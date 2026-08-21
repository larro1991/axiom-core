//! Forge Node - AXIOM Protocol Runtime
//!
//! The main executable for Forge OS. This binary runs the complete AXIOM
//! protocol stack and EMBER coordination system.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod node;
mod network;
mod discovery;
mod control;
// AXIOM Tier 2 Telegram approval channel - see its own module doc comment.
mod telegram_approval;
// AXIOM Phase 3.5: automated regression check for prime directive 2 ("the
// management plane stays outside AXIOM's reach") - see
// capability_isolation.rs's own module doc comment. Test-only: this whole
// module (including the include_str!-embedded source/config it scans)
// compiles out of the production binary entirely.
#[cfg(test)]
mod capability_isolation;

use config::NodeConfig;
use node::ForgeNode;

/// Forge OS Node - Decentralized AI Infrastructure
#[derive(Parser)]
#[command(name = "forge-node")]
#[command(author = "Intuative AI")]
#[command(version)]
#[command(about = "Run a Forge OS node on the AXIOM network", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/forge/config.toml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Forge node
    Start,

    /// Stop a running Forge node
    Stop,

    /// Show node status
    Status,

    /// Generate a new node identity
    Init {
        /// Output directory for config.toml and node.pub. The private key
        /// goes to `--data-dir` instead, which defaults to a different
        /// path (/var/lib/forge) than this flag's own default (/etc/forge)
        /// - see init_node's doc comment for the normal Unix rationale for
        /// that split, and for why `--data-dir` not existing at all used
        /// to make the key's location impossible to override.
        #[arg(short, long, default_value = "/etc/forge")]
        output: PathBuf,

        /// Persistent data directory - node.key is written here, and this
        /// same value is written into the generated config.toml's
        /// `data_dir` field, so a later `start`/`intent`/`wan-ping` using
        /// that config always looks in the same place `init` actually
        /// wrote to (see init_node's doc comment: they used to be two
        /// independently-hardcoded paths that could never be pointed
        /// anywhere else, which is exactly what forced a throwaway
        /// out-of-band key-generation workaround for anything other than
        /// a real deployment - e.g. tests - instead of just using `init`
        /// with a scratch directory). Defaults to /var/lib/forge, matching
        /// `NodeConfig::default()`'s data_dir - leave unset for a normal
        /// deployment; only override it for tests/throwaway identities or
        /// a genuinely non-default layout.
        #[arg(long, default_value = "/var/lib/forge")]
        data_dir: PathBuf,

        /// Overwrite an existing node.key at data_dir. Without this,
        /// init refuses if a key already exists there - identity is this
        /// protocol's whole premise, and Ed25519 key loss is unrecoverable
        /// (2026-07-30: a routine verification `init` run destroyed a live
        /// deployment's key in seconds before this flag existed).
        #[arg(long)]
        force: bool,
    },

    /// Join an existing AXIOM network
    Join {
        /// Bootstrap node address
        #[arg(short, long)]
        bootstrap: String,
    },

    /// Show node information
    Info,

    /// AXIOM-2 Cycle B: connect to one or more peers and request a capability,
    /// printing the Fulfill (or Error) reply. One-shot CLI utility for
    /// exercising/testing `request_intent` directly, independent of the
    /// long-running `start` event loop.
    Intent {
        /// Peer address to connect to. Repeatable (`--bootstrap A --bootstrap
        /// B`) to register multiple providers of the same capability before
        /// requesting - needed to exercise `SemanticRouter::discover()`'s
        /// multi-provider selection at all, since with a single bootstrap
        /// there's only ever one candidate to pick.
        #[arg(long, required = true)]
        bootstrap: Vec<String>,

        /// Capability name to request (must be one the peer has announced)
        #[arg(long, default_value = "echo")]
        capability: String,

        /// Payload to send (UTF-8 text)
        #[arg(long, default_value = "hello axiom")]
        payload: String,

        /// Number of times to call request_intent within this same process.
        /// AXIOM-7: reputation state (`SemanticRouter::update_reputation`)
        /// only lives in memory for the process's lifetime - the default of
        /// 1 matches the original one-shot behavior, but a real test of
        /// reputation-driven routing (does it actually re-route away from a
        /// provider that started failing/died?) needs several calls in the
        /// same process, spaced out with `--interval-ms`, so the score has
        /// somewhere to accumulate.
        #[arg(long, default_value_t = 1)]
        repeat: u32,

        /// Delay between repeated requests, in milliseconds (ignored if
        /// `--repeat` is 1).
        #[arg(long, default_value_t = 2000)]
        interval_ms: u64,
    },

    /// Ask an already-running `start` node (via its control socket) to make
    /// an Intent request through its own long-lived NetworkManager, rather
    /// than spinning up a throwaway one-shot connection like `intent` does.
    /// Requires the target node to have been launched with `start` (which
    /// always opens a control socket at `<data_dir>/control.sock`).
    ControlIntent {
        /// Path to the target node's control socket. Defaults to
        /// `<data_dir>/control.sock` for the config this CLI invocation
        /// itself was given via `--config` (NOT necessarily the target
        /// node's config - pass `--socket` explicitly if they differ).
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Capability name to request
        #[arg(long, default_value = "echo")]
        capability: String,

        /// Payload to send (UTF-8 text, must not itself contain a newline -
        /// the wire protocol is one line in, one line out)
        #[arg(long, default_value = "hello axiom")]
        payload: String,
    },

    /// AXIOM Phase 3.8: admin-only local kill switch - freeze/unfreeze ALL
    /// Tier1+ capability execution, or suspend/unsuspend one specific peer
    /// identity (every tier), on an already-running `start` node, via the
    /// SAME local control socket `ControlIntent` above uses (never over
    /// the network, never as a capability - see
    /// `axiom_gateway::policy`'s own Phase 3.8 doc-comment section and
    /// `control.rs`'s top-of-file doc comment for the full design and wire
    /// protocol). Takes effect on the target node's very next in-flight
    /// request boundary - no restart of that node, and this CLI invocation
    /// itself never touches `node.key`/config/policy files, only the
    /// socket.
    KillSwitch {
        /// Path to the target node's control socket. Same resolution as
        /// `ControlIntent --socket`.
        #[arg(long)]
        socket: Option<PathBuf>,

        #[command(subcommand)]
        action: KillSwitchAction,
    },

    /// WAN transport smoke test (2026-07-29, iroh-backed, see axiom-transport
    /// wan.rs): dial a peer by NodeId over the real internet and perform one
    /// signed ping/pong liveness exchange. Requires the `quic` feature.
    /// This is deliberately a standalone one-shot connect, same rationale as
    /// `intent` above - proves the WAN path end-to-end without needing a
    /// long-running node.
    WanPing {
        /// Target peer's NodeId, as 64 hex chars (32 bytes).
        #[arg(long)]
        peer: String,

        /// Additional NodeId(s) to allow inbound on this endpoint while it
        /// runs, as 64 hex chars each. The target peer is always allowed
        /// automatically. Repeatable.
        #[arg(long)]
        allow: Vec<String>,
    },

    /// Real WAN capability call: dial a peer by NodeId over the internet
    /// and run an actual Intent/Fulfill exchange, not just the liveness-only
    /// ping/pong `wan-ping` does. Closes the gap `wan-ping` deliberately
    /// left open (see its own doc comment) - this is the origination half
    /// of the WAN capability-dispatch path `node.rs::wan_capability_session`
    /// already serves, exercised the same way
    /// `wan_capability_tests::send_intent_request` exercises it against a
    /// loopback pair in tests, just against a real remote peer instead.
    /// Reuses the already-shipped wire-protocol functions as-is
    /// (`build_intent_frame`, `decode_verified_frame`,
    /// `WanEndpoint::bind`/`connect_and_verify_liveness`) - no new frame
    /// types, no new discovery mode, nothing inside the
    /// `v0-transport-frozen` boundary (see ARCHITECTURE.md's freeze
    /// section: client-side CLI tooling calling already-shipped protocol
    /// functions is explicitly not frozen).
    WanIntent {
        /// Target peer's NodeId, as 64 hex chars (32 bytes). Same format as
        /// `wan-ping --peer`.
        #[arg(long)]
        peer: String,

        /// Additional NodeId(s) to allow inbound on this endpoint while it
        /// runs, as 64 hex chars each. The target peer is always allowed
        /// automatically. Repeatable. Same semantics as `wan-ping --allow`.
        #[arg(long)]
        allow: Vec<String>,

        /// Capability name to request (must be one the peer has announced
        /// AND allowlisted in its capability policy). Same default/semantics
        /// as the LAN `intent` subcommand's `--capability`.
        #[arg(long, default_value = "echo")]
        capability: String,

        /// Payload to send (UTF-8 text). Same default/semantics as the LAN
        /// `intent` subcommand's `--payload`.
        #[arg(long, default_value = "hello axiom")]
        payload: String,
    },

    /// AXIOM Phase 3.2: access resolver - a pure, side-effect-free read of
    /// the capability policy file, per the roadmap's own framing ("cheap
    /// because the policy is one file - build it while that's true").
    /// Deliberately does NOT touch node.key, does NOT bind any socket, and
    /// does NOT construct a `ForgeNode`/`NetworkManager` - unlike every
    /// other subcommand above, this one has no network/discovery/WAN
    /// machinery in its dependency path at all, only
    /// `axiom_gateway::CapabilityPolicy::load` plus formatting. Two modes,
    /// exactly one required:
    /// - `axiom access <identity>` - effective capability list for one hex
    ///   NodeId/pubkey (role + direct grants don't exist as separate
    ///   concepts in the current schema, so this resolves to "every
    ///   capability whose `allowed_peers` includes this identity").
    /// - `axiom access --capability <name>` - every identity allowed to
    ///   invoke one capability.
    ///
    /// AXIOM Phase 3.8: per-entry `expires` (unix seconds) now exists in
    /// the policy schema (`axiom_gateway::policy`'s `RawAllowedPeer`) - a
    /// permanent (bare-string) entry reports `permanent`, an entry with an
    /// `expires` reports it as a raw unix-seconds value (no date/time
    /// formatting crate is a dependency of this binary, so this command
    /// doesn't invent one just for cosmetics). Only currently-effective
    /// (non-expired, as of the moment this command runs) peers are
    /// reported at all - see `CapabilityPolicy::capability_summary`'s own
    /// doc comment for why an expired entry is indistinguishable from one
    /// that was never allowlisted.
    Access {
        /// Hex-encoded 32-byte Ed25519 NodeId/pubkey to resolve the
        /// effective capability list for. Required unless --capability is
        /// given instead - exactly one of the two, never both.
        identity: Option<String>,

        /// List every identity allowed to invoke this capability, instead
        /// of resolving by identity. Mutually exclusive with the
        /// positional `identity` argument.
        #[arg(long)]
        capability: Option<String>,

        /// Override the capability policy file to read. Defaults to
        /// `--config`'s `capability_policy_path` (config.toml's own field,
        /// itself defaulting to `/etc/forge/capability_policy.toml` if
        /// `--config` doesn't exist) - same resolution `start`/`intent`
        /// use, just without ever needing a full `NodeConfig`-driven node
        /// to exist.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// AXIOM Phase 3.4: walk a hash-chained audit log
    /// (`axiom_gateway::audit`) end to end and verify every entry's
    /// content hash and chain linkage back to the genesis sentinel.
    /// Deliberately the ONLY way this codebase reads an audit log back out
    /// - see `axiom_gateway::audit`'s own module doc comment, "Prime
    /// directive: not a capability": there is no capability, Tier 0/1/2,
    /// that exposes read access to this file, by design. Like `access`
    /// above, this touches no `node.key`/discovery/WAN machinery - it's a
    /// pure file read plus formatting, so it also does not accept
    /// `--config` at all. AXIOM Phase 3.8: `start_node` now opens an audit
    /// log by default at `axiom_gateway::audit::default_path(data_dir)`
    /// (`<data_dir>/audit.jsonl`) for the kill switch's own admin events -
    /// but that's a `NodeConfig`-derived convention this standalone
    /// command still doesn't consult (no `--config` here, matching Phase
    /// 3.4's original design), so the caller must still say exactly which
    /// file with `--path`; this command deliberately never guesses.
    VerifyAudit {
        /// Path to the JSON-Lines audit log file to verify.
        #[arg(long)]
        path: PathBuf,
    },
}

/// AXIOM Phase 3.8: `KillSwitch`'s own sub-subcommand - one of the four
/// control-socket commands `control.rs`'s top-of-file doc comment defines.
#[derive(Subcommand)]
enum KillSwitchAction {
    /// Freeze ALL Tier1+ capability execution on the target node
    /// immediately. Tier0 (`echo`/`sysinfo`) and the audit log stay live.
    Freeze,
    /// Explicit, primary un-freeze - the freeze does not expire on its own.
    Unfreeze,
    /// Suspend one peer identity - denied for EVERY tier, including
    /// Tier0, until explicitly un-suspended.
    Suspend {
        /// Hex-encoded 32-byte Ed25519 NodeId/pubkey to suspend.
        peer: String,
    },
    /// Explicit un-suspend for one peer identity.
    Unsuspend {
        /// Hex-encoded 32-byte Ed25519 NodeId/pubkey to un-suspend.
        peer: String,
    },
    /// Read-only: report whether the target node is currently frozen and
    /// which peer identities are currently suspended.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    // ASCII banner
    print_banner();

    match cli.command.unwrap_or(Commands::Start) {
        Commands::Start => start_node(&cli.config).await,
        Commands::Stop => stop_node().await,
        Commands::Status => show_status().await,
        Commands::Init { output, data_dir, force } => init_node(&output, &data_dir, force).await,
        Commands::Join { bootstrap } => join_network(&cli.config, &bootstrap).await,
        Commands::Info => show_info(&cli.config).await,
        Commands::Intent { bootstrap, capability, payload, repeat, interval_ms } => {
            request_intent_cmd(&cli.config, &bootstrap, &capability, &payload, repeat, interval_ms).await
        }
        Commands::WanPing { peer, allow } => {
            wan_ping_cmd(&cli.config, &peer, &allow).await
        }
        Commands::WanIntent { peer, allow, capability, payload } => {
            wan_intent_cmd(&cli.config, &peer, &allow, &capability, &payload).await
        }
        Commands::ControlIntent { socket, capability, payload } => {
            let config = if cli.config.exists() {
                NodeConfig::load(&cli.config)?
            } else {
                NodeConfig::default()
            };
            let socket = socket.unwrap_or_else(|| control::default_path(&config.data_dir));
            control_intent_cmd(&socket, &capability, &payload).await
        }
        Commands::KillSwitch { socket, action } => {
            let config = if cli.config.exists() {
                NodeConfig::load(&cli.config)?
            } else {
                NodeConfig::default()
            };
            let socket = socket.unwrap_or_else(|| control::default_path(&config.data_dir));
            kill_switch_cmd(&socket, &action).await
        }
        Commands::Access { identity, capability, policy } => {
            access_cmd(&cli.config, policy.as_ref(), identity.as_deref(), capability.as_deref()).await
        }
        Commands::VerifyAudit { path } => verify_audit_cmd(&path).await,
    }
}

fn print_banner() {
    println!(r#"
    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

    Decentralized AI Infrastructure
    Running on AXIOM Protocol
    "#);
}

async fn start_node(config_path: &PathBuf) -> Result<()> {
    info!("Starting Forge node...");

    // Load configuration
    let config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        warn!("Config file not found, using defaults");
        NodeConfig::default()
    };

    info!("Node ID: {}", hex::encode(&config.node_id[..8]));
    info!("Listen address: {}", config.listen_addr);

    let control_socket_path = control::default_path(&config.data_dir);

    // Create and start the node
    let node = ForgeNode::new(config).await?;
    let node = Arc::new(RwLock::new(node));

    // Start the AXIOM protocol stack (network manager, bootstrap connects -
    // does not run the event loop; that happens below). Grab the
    // NetworkManager handle now, before the event loop task (spawned below)
    // starts holding `node`'s own write lock for its entire lifetime -
    // control.rs needs NetworkManager's own independent lock, not this one.
    let network_handle = {
        let mut n = node.write().await;
        n.start().await?;
        n.network_handle()
    };

    // AXIOM Phase 3.8's audit log used to be opened HERE, independently, via
    // its own `AuditLog::open` call - correct back then (nothing else ever
    // opened one), but wrong now that AXIOM Tier 2's `wg_peer_manage`
    // background task (network.rs) ALSO needs to append to this exact same
    // file: `AuditLog::open` chain-verifies and caches `last_hash`/
    // `next_sequence` in memory at open time (audit.rs's `WriterState`) - a
    // SECOND independent `open()` of the same path would maintain its own,
    // independently-advancing copy of that state, and two writers racing to
    // append with their own stale `prev_hash`/`sequence` would corrupt the
    // hash chain. So there must be exactly ONE `AuditLog` handle per
    // process now - the one `NetworkManager::new` already opens internally
    // (same `axiom_gateway::audit::default_path(&config.data_dir)` path,
    // same best-effort "don't block startup" posture) - fetched back out
    // here via `NetworkManager::audit_log()` (same accessor-after-lock
    // pattern `policy()` already established) so the control socket's
    // kill-switch handlers keep writing to that SAME instance instead of a
    // second, chain-corrupting one.
    let audit_log = if let Some(nh) = &network_handle {
        nh.lock().await.audit_log()
    } else {
        None
    };

    // Lets an external caller drive this node's own long-lived NetworkManager
    // (real peer registrations, real reputation state) instead of the
    // `intent` CLI subcommand's throwaway one-shot connection.
    if let Some(network_handle) = network_handle {
        control::start(control_socket_path, network_handle, audit_log);
    }

    info!("Forge node started successfully");

    // Grab a shutdown handle *before* spawning the event loop task, so
    // Ctrl+C can request a stop without needing the write lock the loop
    // holds for its entire run (see `ForgeNode::shutdown_flag`'s doc
    // comment - taking that lock first here would deadlock).
    let shutdown_flag = {
        let n = node.read().await;
        n.shutdown_signal()
    };

    let node_for_loop = node.clone();
    let mut loop_handle = tokio::spawn(async move {
        let mut n = node_for_loop.write().await;
        n.run_event_loop().await
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
            shutdown_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            // Wait for the loop task to notice the flag and actually exit -
            // otherwise `shutdown()` below would block forever on a write
            // lock the still-running loop task holds.
            if let Err(e) = loop_handle.await {
                warn!("Event loop task panicked: {}", e);
            }
        }
        result = &mut loop_handle => {
            match result {
                Ok(Ok(())) => info!("Event loop exited on its own"),
                Ok(Err(e)) => warn!("Event loop error: {}", e),
                Err(e) => warn!("Event loop task panicked: {}", e),
            }
        }
    }

    info!("Shutting down...");
    {
        let mut n = node.write().await;
        n.shutdown().await?;
    }

    info!("Forge node stopped");
    Ok(())
}

async fn stop_node() -> Result<()> {
    info!("Stopping Forge node...");
    // Send stop signal via Unix socket or similar
    // For now, just print instructions
    println!("To stop the node, send SIGTERM or press Ctrl+C in the running terminal");
    Ok(())
}

async fn show_status() -> Result<()> {
    println!("Forge Node Status");
    println!("=================");

    // TODO: Connect to running node and get status
    println!("Status: Unknown (node may not be running)");
    println!("\nTry: forge-node start");

    Ok(())
}

/// Bug found 2026-07-30 during the first-ever real deployment of this
/// binary (Axiom's WAN work): `node.key` used to be written into
/// `output_dir` (the `--output` arg, defaulted to `/etc/forge`), but
/// `ForgeNode::new()`'s identity-loading logic (main.rs, and duplicated in
/// `request_intent_cmd`/`wan_ping_cmd`) reads it from
/// `config.data_dir.join("node.key")` - a SEPARATE path, hardcoded here to
/// `/var/lib/forge` regardless of `--output`. Since those two directories
/// differ by default, `start` always found "no key file" and silently
/// generated a FRESH random identity on every single run - meaning the
/// NodeId `init` prints/persists to `node.pub`/`config.toml` was never
/// actually the identity the running node used. For a protocol whose
/// entire premise is "identity is the address," a restart silently
/// rotating that address is about as bad a bug as this codebase can have.
/// Fixed by writing `node.key` into the SAME `data_dir` value that goes
/// into the generated config, instead of `output_dir` - config/output can
/// still differ (e.g. `/etc/forge` for config.toml vs `/var/lib/forge` for
/// persistent data, a normal Unix split), but the key's location and
/// `data_dir`'s value can never drift apart again, because they're now
/// the literal same variable instead of two independently-hardcoded paths.
///
/// Fable review (2026-07-30, same cycle): the fix above made a SECOND
/// problem strictly worse - previously a stray `init --output /tmp/x` was
/// sandboxed to that directory; now every `init` run, regardless of
/// `--output`, unconditionally overwrote data_dir/node.key. Proven not
/// hypothetical: the verification run for THIS fix destroyed the real
/// deployment's live key in seconds (caught via sha256sum, restored from a
/// backup that happened to exist). `force` is the guard - without it, an
/// existing key refuses the whole operation instead of being silently
/// destroyed.
///
/// 2026-08-06: closed the actual gap that forced that dangerous
/// verification run in the first place - `data_dir` was ALSO hardcoded,
/// with no CLI flag able to override it at all, so there was never a way
/// to run a real `init` against a scratch directory instead of the live
/// path. That's why identity generation for anything other than a genuine
/// deployment (smoke-testing another feature, in this instance) had been
/// done out-of-band with a throwaway Python script instead of this
/// command. `data_dir` is now `--data-dir`, an explicit parameter with the
/// same `/var/lib/forge` default as before - passing nothing still behaves
/// exactly as it did, but a caller who explicitly wants a different
/// location (tests, throwaway identities) finally has one, without ever
/// touching the real default path.
async fn init_node(output_dir: &PathBuf, data_dir: &PathBuf, force: bool) -> Result<()> {
    use axiom_crypto::identity::Keypair;
    use std::fs;

    info!("Initializing new Forge node identity...");

    // Create output directory (config.toml, node.pub go here)
    fs::create_dir_all(output_dir)?;

    // Persistent data directory - node.key goes HERE, matching where
    // `start` actually looks (config.data_dir.join("node.key")). Comes
    // straight from the caller (CLI `--data-dir`, default /var/lib/forge)
    // and is reused as-is for both the key path and the config value below
    // so they cannot independently drift the way output_dir/data_dir used
    // to.
    fs::create_dir_all(data_dir)?;

    let key_path = data_dir.join("node.key");
    if key_path.exists() && !force {
        let existing_id = fs::read(&key_path)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                hex::encode(Keypair::from_bytes(&arr).node_id().as_bytes())
            });
        anyhow::bail!(
            "refusing to overwrite existing identity at {} (NodeId: {}) - this protocol's whole \
             premise is identity permanence, and key loss is unrecoverable. Pass --force if you \
             really mean to replace it.",
            key_path.display(),
            existing_id.as_deref().unwrap_or("<unreadable - corrupt or wrong size>")
        );
    }

    // Generate new identity
    let identity = Keypair::generate();
    let node_id = identity.node_id();

    info!("Generated Node ID: {}", hex::encode(node_id.as_bytes()));

    // Save private key into data_dir, NOT output_dir - see this fn's doc.
    // (key_path was already computed above, before the identity was even
    // generated, so the overwrite-refusal check could run first.)
    fs::write(&key_path, identity.secret_bytes())?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms)?;
    }

    // Save public key / node ID (informational, output_dir is fine here -
    // nothing reads this file back to load identity, only humans/scripts).
    let pub_path = output_dir.join("node.pub");
    fs::write(&pub_path, hex::encode(node_id.as_bytes()))?;

    // AXIOM Phase 1.1: scaffold a fail-closed capability policy alongside
    // config.toml, in the SAME directory (output_dir, /etc/forge by
    // default) - NOT data_dir, which the running service owns and writes
    // into for node.key/discovery state. This file is meant to end up
    // somewhere the service's own runtime user can't write to (see
    // policy.rs's module doc comment) - `init` just scaffolds the starter
    // copy here for the operator to review/lock down, it never writes to
    // this path again after this point (NodeConfig::load and
    // CapabilityPolicy::load both only ever read it).
    let policy_path = output_dir.join("capability_policy.toml");
    let policy_template = "\
# AXIOM capability access-control policy - see axiom-gateway's policy.rs\n\
# module doc comment for the full fail-closed contract this file\n\
# implements.\n\
#\n\
# Every capability this node might serve needs its OWN [capability.<name>]\n\
# table below, or it serves NO ONE - there is no permissive default. Peers\n\
# are named by their hex-encoded Ed25519 NodeId (never an IP address - IPs\n\
# are unauthenticated on this transport). rate_limit_secs is the minimum\n\
# gap between two served requests from the same allowed peer; concurrency\n\
# bounds how many requests for that capability may be in flight at once,\n\
# across every allowed peer combined. `tier` (schema v2, MANDATORY per\n\
# entry) is \"tier0\"/\"tier1\"/\"tier2\" - see DECISIONS.md's \"Tier model\"\n\
# section: worst-case impact and required controls, not read-vs-write. A\n\
# missing or invalid tier fails that capability closed even if\n\
# allowed_peers is populated.\n\
#\n\
# AXIOM Phase 3.6: any tier1/tier2 capability ALSO requires a\n\
# [[protected_resource]] section to exist somewhere in this file - even an\n\
# empty one - or it fails closed at registration regardless of\n\
# allowed_peers (same fail-closed mechanism as a missing/invalid tier).\n\
# This scaffold ships with `network_clients` (tier1) below but NO\n\
# [[protected_resource]] section yet, since this generator has no way to\n\
# know this device's real network - `network_clients` therefore starts\n\
# unregistered (not merely empty-allowlisted) until you add one, e.g.:\n\
#\n\
#   [[protected_resource]]\n\
#   name = \"router\"\n\
#   mac = \"aa:bb:cc:dd:ee:ff\"\n\
#   ip = \"192.168.1.1\"\n\
#\n\
# Deliberately shipped empty (fail closed) - add peers (and, for any\n\
# tier1+ capability, a protected-resource section) explicitly before any\n\
# capability will serve anyone.\n\
\n\
version = 2\n\
\n\
[capability.echo]\n\
allowed_peers = []\n\
rate_limit_secs = 0\n\
concurrency = 50\n\
tier = \"tier0\"\n\
\n\
[capability.sysinfo]\n\
allowed_peers = []\n\
rate_limit_secs = 0\n\
concurrency = 50\n\
tier = \"tier0\"\n\
\n\
[capability.network_clients]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
[capability.notify_send]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
[capability.proxmox_restart]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
[capability.home_assistant_toggle]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
[capability.docker_restart]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
[capability.wg_peers_list]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier1\"\n\
\n\
# AXIOM Tier 2: wg_peer_manage (create/delete/enable/disable a WireGuard\n\
# VPN peer) - the first REAL Tier 2 (destructive/security-relevant)\n\
# capability. Requires a [[protected_resource]] section to exist (see\n\
# above) and, separately, telegram_bot_token/telegram_chat_id set in\n\
# config.toml, or every request answers \"not configured\" regardless of\n\
# allowed_peers. Every invocation additionally requires a real,\n\
# per-invocation Telegram approval from the configured chat_id - see\n\
# telegram_approval.rs - no allowed_peers entry bypasses that.\n\
[capability.wg_peer_manage]\n\
allowed_peers = []\n\
rate_limit_secs = 30\n\
concurrency = 2\n\
tier = \"tier2\"\n\
";
    fs::write(&policy_path, policy_template)?;

    // Create default config
    let config = NodeConfig {
        node_id: *node_id.as_bytes(),
        listen_addr: "0.0.0.0:7777".parse()?,
        api_addr: "127.0.0.1:7778".parse()?,
        bootstrap_nodes: vec![],
        data_dir: data_dir.clone(),
        max_peers: 50,
        enable_guardian: true,
        enable_watcher: true,
        enable_link_local_discovery: true,
        link_local_trusted_subnets: vec![],
        capabilities: vec!["echo".to_string(), "sysinfo".to_string()],
        uai_base_url: None,
        uai_token: None,
        notify_topic: None,
        capability_policy_path: policy_path.clone(),
        wan_enabled: false,
        wan_allowed_peers: vec![],
        telegram_bot_token: None,
        telegram_chat_id: None,
    };

    let config_path = output_dir.join("config.toml");
    let config_str = toml::to_string_pretty(&config)?;
    fs::write(&config_path, config_str)?;

    println!("\nForge node initialized!");
    println!("  Node ID:    {}", hex::encode(&node_id.as_bytes()[..8]));
    println!("  Config:     {}", config_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  Capability policy: {} (fail-closed, empty - add peers before anything is servable)", policy_path.display());
    println!("\nTo start the node:");
    println!("  forge-node --config {} start", config_path.display());

    Ok(())
}

async fn request_intent_cmd(
    config_path: &PathBuf,
    bootstrap: &[String],
    capability: &str,
    payload: &str,
    repeat: u32,
    interval_ms: u64,
) -> Result<()> {
    use network::NetworkManager;

    let config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        warn!("Config file not found, using defaults");
        NodeConfig::default()
    };

    // See NodeConfig::load_or_generate_identity - this used to carry its own
    // copy of the identity-load logic, same as ForgeNode::new/wan_ping_cmd.
    let identity = config.load_or_generate_identity()?;

    let mut network = NetworkManager::new(&config, identity).await?;

    // Connect to every given bootstrap peer up front - with only one, there's
    // just one candidate and `SemanticRouter::discover()` never actually has
    // to choose between providers.
    for b in bootstrap {
        let addr: SocketAddr = b.parse().context("Invalid bootstrap address")?;
        let peer_id = network.connect(&addr).await
            .with_context(|| format!("Failed to connect to bootstrap peer {}", addr))?;
        info!("Connected to {} as peer {}", addr, hex::encode(peer_id.as_bytes()));
        network.spawn_announce(addr);
    }
    // Give all sides a moment to exchange Announce frames - Announce is
    // fire-and-forget gossip, not part of connect()'s handshake itself, so
    // `request_intent`'s discover() wouldn't find anything yet without this.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut last_result = Ok(());
    for round in 1..=repeat.max(1) {
        // Print BEFORE sending so a reader can see the score that actually
        // drove this round's pick, not the score it produced afterward.
        let snapshot = network.routing_snapshot(capability).await;
        let snapshot_str = snapshot.iter()
            .map(|(id, rep)| format!("{}={:.3}", &hex::encode(id.as_bytes())[..8], rep))
            .collect::<Vec<_>>()
            .join(", ");
        println!("[{}/{}] candidates (ranked): [{}]", round, repeat, snapshot_str);

        match network.request_intent(capability, payload.as_bytes().to_vec()).await {
            Ok((peer_id, result)) => {
                println!("[{}/{}] Fulfill from {}: {}", round, repeat, hex::encode(peer_id.as_bytes()), String::from_utf8_lossy(&result));
                last_result = Ok(());
            }
            Err(e) => {
                println!("[{}/{}] Error: {}", round, repeat, e);
                last_result = Err(e);
            }
        }
        if round < repeat {
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        }
    }
    last_result
}



/// One-shot WAN smoke test: dial `peer` over iroh, do a signed ping/pong,
/// report the result. See axiom-transport::wan module docs for why the
/// signed pong (not "iroh reports connected") is what proves liveness.
async fn wan_ping_cmd(config_path: &PathBuf, peer_hex: &str, allow_hex: &[String]) -> Result<()> {
    use axiom_transport::wan::{WanAllowlist, WanEndpoint};
    use axiom_types::crypto::NodeId;

    fn parse_node_id(hex_str: &str) -> Result<NodeId> {
        let bytes = hex::decode(hex_str).context("peer/allow id must be hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
        Ok(NodeId::from_bytes(arr))
    }

    let config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        warn!("Config file not found, using defaults");
        NodeConfig::default()
    };

    // See NodeConfig::load_or_generate_identity.
    let identity = config.load_or_generate_identity()?;

    let peer = parse_node_id(peer_hex)?;
    let mut allowlist = WanAllowlist::new();
    allowlist.allow(peer);
    for a in allow_hex {
        allowlist.allow(parse_node_id(a)?);
    }

    info!("Binding WAN endpoint, local NodeId = {:?}", identity.node_id());
    let endpoint = WanEndpoint::bind(identity, allowlist).await
        .map_err(|e| anyhow::anyhow!("WAN bind failed: {e}"))?;

    info!("Dialing peer {:?} over iroh...", peer);
    let (_, pong) = endpoint.connect_and_verify_liveness(peer).await
        .map_err(|e| anyhow::anyhow!("WAN connect/liveness failed: {e}"))?;

    println!("WAN liveness OK: peer {:?} signed a fresh pong {}s ago", pong.responder,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(pong.responded_at))
            .unwrap_or(0));

    Ok(())
}

/// Upper bound on this CLI's own wait for a Fulfill/Error reply, once the
/// request stream has actually been opened. Mirrors `node.rs`'s private
/// `WAN_REQUEST_TIMEOUT` (30s) - that constant isn't `pub(crate)` so it
/// can't be imported here, but the client side of one request/reply cycle
/// should wait no longer than the server side is willing to work on it, so
/// the same value is duplicated deliberately rather than picking an
/// unrelated one. If `WAN_REQUEST_TIMEOUT` ever changes, this should move
/// with it.
const WAN_INTENT_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Real WAN capability call: dial `peer` over iroh (same bind/dial path as
/// `wan_ping_cmd` above, unchanged), then - instead of stopping at the
/// liveness pong - open a bidirectional stream, send a real signed Intent
/// frame (`network::build_intent_frame`), and read+verify the reply
/// (`network::decode_verified_frame`). This is exactly the client-side
/// logic `node.rs`'s `wan_capability_tests::send_intent_request` test
/// helper already exercises against a loopback `bind_local_only` pair -
/// same frame-building, same channel-binding/trace_id checks, same
/// Fulfill/Error handling - just wired up as a real CLI command dialing a
/// real remote peer via `WanEndpoint::bind` instead of a test pair.
///
/// Split into a pure `Result`-returning helper (`run`) plus this thin
/// wrapper so the CLI-level argument parsing/output-formatting logic can be
/// integration-tested directly (see `main_tests::wan_intent` below) without
/// needing a real WAN dial for every case - mirrors how `wan_ping_cmd`
/// itself stays a thin wrapper around `WanEndpoint`/`connect_and_verify_liveness`,
/// just carried one level further since this command has more distinct
/// reply outcomes to report than a bare liveness check does.
async fn wan_intent_cmd(
    config_path: &PathBuf,
    peer_hex: &str,
    allow_hex: &[String],
    capability: &str,
    payload: &str,
) -> Result<()> {
    use axiom_transport::wan::{WanAllowlist, WanEndpoint};
    use axiom_types::crypto::NodeId;

    fn parse_node_id(hex_str: &str) -> Result<NodeId> {
        let bytes = hex::decode(hex_str).context("peer/allow id must be hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
        Ok(NodeId::from_bytes(arr))
    }

    let config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        warn!("Config file not found, using defaults");
        NodeConfig::default()
    };

    // See NodeConfig::load_or_generate_identity.
    let identity = config.load_or_generate_identity()?;

    let peer = parse_node_id(peer_hex)?;
    let mut allowlist = WanAllowlist::new();
    allowlist.allow(peer);
    for a in allow_hex {
        allowlist.allow(parse_node_id(a)?);
    }

    info!("Binding WAN endpoint, local NodeId = {:?}", identity.node_id());
    // bind() consumes the keypair (WanEndpoint keeps its own copy for the
    // liveness handshake) - clone first, the Intent frame below still needs
    // to sign with the same identity.
    let endpoint = WanEndpoint::bind(identity.clone(), allowlist).await
        .map_err(|e| anyhow::anyhow!("WAN bind failed: {e}"))?;

    info!("Dialing peer {:?} over iroh...", peer);
    let (conn, pong) = endpoint.connect_and_verify_liveness(peer).await
        .map_err(|e| anyhow::anyhow!("WAN connect/liveness failed: {e}"))?;

    println!("WAN liveness OK: peer {:?} signed a fresh pong {}s ago", pong.responder,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(pong.responded_at))
            .unwrap_or(0));

    let result_payload = send_wan_intent_request(&conn, &identity, peer, capability, payload.as_bytes().to_vec())
        .await
        .with_context(|| format!("wan-intent: request to {} failed", hex::encode(peer.as_bytes())))?;

    println!("Fulfill from {}: {}", hex::encode(peer.as_bytes()), String::from_utf8_lossy(&result_payload));

    Ok(())
}

/// Open one bidi stream on an already liveness-verified WAN connection,
/// send a signed Intent frame, and read+verify the reply - the same
/// request/reply shape `node.rs`'s `wan_capability_session` serves on the
/// other end, and the same client-side checks (channel binding, trace_id
/// echo) `wan_capability_tests::send_intent_request` already proves work
/// against a loopback pair. Kept as its own function (rather than inlined
/// into `wan_intent_cmd`) so `main_tests` below can exercise it directly
/// against a real `connected_pair`-style loopback connection, the same
/// pattern `node.rs`'s own WAN tests use.
async fn send_wan_intent_request(
    conn: &iroh::endpoint::Connection,
    identity: &axiom_crypto::identity::Keypair,
    expected_peer: axiom_types::crypto::NodeId,
    capability: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    use axiom_router::ai::Intent as AiIntent;
    use axiom_types::frame::FrameType;
    use network::{build_intent_frame, decode_verified_frame, next_trace_id};

    // Cap matches node.rs's own WAN_MAX_FRAME_BYTES (65536) - not
    // `pub(crate)` there either, so duplicated for the same reason
    // WAN_INTENT_CLIENT_TIMEOUT is: the client shouldn't accept a reply
    // larger than the server is willing to send.
    const WAN_MAX_FRAME_BYTES: usize = 65536;

    let intent_hash = AiIntent::from_str(capability).hash;
    let trace_id = next_trace_id();
    let request = build_intent_frame(identity, intent_hash, trace_id, payload, None);
    if request.is_empty() {
        anyhow::bail!("wan-intent: failed to build Intent frame (sign/encode error, see logs)");
    }

    let (mut send, mut recv) = conn.open_bi().await
        .context("wan-intent: failed to open request stream")?;
    send.write_all(&request).await
        .context("wan-intent: failed to send Intent frame")?;
    send.finish()
        .context("wan-intent: failed to finish request stream")?;
    let _ = send.stopped().await;

    let reply_bytes = tokio::time::timeout(WAN_INTENT_CLIENT_TIMEOUT, recv.read_to_end(WAN_MAX_FRAME_BYTES))
        .await
        .map_err(|_| anyhow::anyhow!(
            "wan-intent: timed out after {:?} waiting for reply from {}",
            WAN_INTENT_CLIENT_TIMEOUT, hex::encode(expected_peer.as_bytes())
        ))?
        .context("wan-intent: failed to read reply")?;

    let reply = decode_verified_frame(&reply_bytes)
        .ok_or_else(|| anyhow::anyhow!("wan-intent: reply failed signature verification (malformed or unsigned reply)"))?;

    // Channel binding: the reply's claimed sender must be the peer this
    // connection actually authenticated as (see node.rs's own channel-
    // binding check on the request path for the same rationale in reverse -
    // decode_verified_frame alone only proves SOME valid keypair signed it,
    // not that it's the peer we're actually connected to).
    if reply.header.sender_id != expected_peer {
        anyhow::bail!(
            "wan-intent: reply sender {} does not match dialed peer {} (channel-binding mismatch)",
            hex::encode(reply.header.sender_id.as_bytes()), hex::encode(expected_peer.as_bytes())
        );
    }
    if reply.trace_id != Some(trace_id) {
        anyhow::bail!("wan-intent: reply trace_id does not match request (stale or cross-talk reply)");
    }

    match reply.header.frame_type {
        FrameType::Fulfill => Ok(reply.payload),
        FrameType::Error => anyhow::bail!(
            "wan-intent: {} rejected the request: {}",
            hex::encode(expected_peer.as_bytes()), String::from_utf8_lossy(&reply.payload)
        ),
        other => anyhow::bail!("wan-intent: unexpected reply frame type {:?}", other),
    }
}

/// Client side of `control.rs`'s one-line-in, one-line-out Unix socket
/// protocol. Connects, sends a single `INTENT` command, reads a single
/// reply line, prints it, and disconnects.
#[cfg(unix)]
async fn control_intent_cmd(socket_path: &PathBuf, capability: &str, payload: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await
        .with_context(|| format!("Failed to connect to control socket {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    let command = format!("INTENT {} {}\n", capability, payload);
    write_half.write_all(command.as_bytes()).await
        .context("Failed to send command to control socket")?;

    let mut reader = BufReader::new(read_half);
    let mut reply = String::new();
    reader.read_line(&mut reply).await
        .context("Failed to read reply from control socket")?;

    print!("{}", reply);
    if reply.starts_with("ERR") {
        anyhow::bail!("control-intent: {}", reply.trim_end());
    }
    Ok(())
}

/// Client side of `control.rs`'s Windows named-pipe control socket - same
/// wire protocol `control_intent_cmd` above speaks over a Unix socket, just
/// over `\\.\pipe\...` instead. See `connect_control_pipe_with_retry` for
/// why this isn't a single bare `ClientOptions::open` call.
#[cfg(windows)]
async fn control_intent_cmd(socket_path: &PathBuf, capability: &str, payload: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let pipe_name = socket_path.to_string_lossy().into_owned();
    let client = connect_control_pipe_with_retry(&pipe_name).await
        .with_context(|| format!("Failed to connect to control pipe {}", pipe_name))?;
    let (read_half, mut write_half) = tokio::io::split(client);

    let command = format!("INTENT {} {}\n", capability, payload);
    write_half.write_all(command.as_bytes()).await
        .context("Failed to send command to control pipe")?;

    let mut reader = BufReader::new(read_half);
    let mut reply = String::new();
    reader.read_line(&mut reply).await
        .context("Failed to read reply from control pipe")?;

    print!("{}", reply);
    if reply.starts_with("ERR") {
        anyhow::bail!("control-intent: {}", reply.trim_end());
    }
    Ok(())
}

/// Opens a Windows named-pipe client connection, retrying on
/// `ERROR_PIPE_BUSY`. `control.rs`'s server side (`create_pipe_instance`)
/// always keeps one fresh, unconnected instance waiting - but there's a
/// real (if brief) window on every accept where the just-connected instance
/// hasn't been replaced yet, during which a racing client sees
/// ERROR_PIPE_BUSY rather than getting queued the way a Unix listener's
/// backlog would queue it. A short bounded retry (not a single attempt) is
/// the standard pattern Win32's own client-side named-pipe documentation
/// recommends for exactly this race.
#[cfg(windows)]
async fn connect_control_pipe_with_retry(
    pipe_name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    for attempt in 0..10u32 {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1))).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("control pipe {} still busy after repeated retries", pipe_name),
    ))
}

/// Neither Unix domain sockets nor Win32 named pipes exist on whatever this
/// is - see `control.rs`'s own non-fatal-if-unavailable philosophy, applied
/// here to the CLI client side. In practice this binary is only ever built
/// for `unix` or `windows` targets - this arm is a safety net.
#[cfg(not(any(unix, windows)))]
async fn control_intent_cmd(_socket_path: &PathBuf, _capability: &str, _payload: &str) -> Result<()> {
    anyhow::bail!("control-intent: control socket not supported on this platform")
}

/// AXIOM Phase 3.8: client side of `control.rs`'s FREEZE/UNFREEZE/SUSPEND/
/// UNSUSPEND/STATUS commands - same one-line-in, one-line-out protocol
/// `control_intent_cmd` above already speaks, just a different command
/// word per `KillSwitchAction` variant. This CLI invocation itself never
/// touches `node.key`/config/policy files - the socket connection alone
/// carries the whole request, matching `control_intent_cmd`'s own "thin
/// client" shape.
#[cfg(unix)]
async fn kill_switch_cmd(socket_path: &PathBuf, action: &KillSwitchAction) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let command = match action {
        KillSwitchAction::Freeze => "FREEZE\n".to_string(),
        KillSwitchAction::Unfreeze => "UNFREEZE\n".to_string(),
        KillSwitchAction::Suspend { peer } => format!("SUSPEND {peer}\n"),
        KillSwitchAction::Unsuspend { peer } => format!("UNSUSPEND {peer}\n"),
        KillSwitchAction::Status => "STATUS\n".to_string(),
    };

    let stream = UnixStream::connect(socket_path).await
        .with_context(|| format!("Failed to connect to control socket {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    write_half.write_all(command.as_bytes()).await
        .context("Failed to send command to control socket")?;

    let mut reader = BufReader::new(read_half);
    let mut reply = String::new();
    reader.read_line(&mut reply).await
        .context("Failed to read reply from control socket")?;

    print!("{}", reply);
    if reply.starts_with("ERR") {
        anyhow::bail!("kill-switch: {}", reply.trim_end());
    }
    Ok(())
}

/// Windows named-pipe client side of `control.rs`'s FREEZE/UNFREEZE/
/// SUSPEND/UNSUSPEND/STATUS commands - same protocol
/// `control_intent_cmd`'s Windows sibling above speaks, just a different
/// command word per `KillSwitchAction` variant, matching the Unix
/// `kill_switch_cmd`'s own relationship to `control_intent_cmd`.
#[cfg(windows)]
async fn kill_switch_cmd(socket_path: &PathBuf, action: &KillSwitchAction) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let command = match action {
        KillSwitchAction::Freeze => "FREEZE\n".to_string(),
        KillSwitchAction::Unfreeze => "UNFREEZE\n".to_string(),
        KillSwitchAction::Suspend { peer } => format!("SUSPEND {peer}\n"),
        KillSwitchAction::Unsuspend { peer } => format!("UNSUSPEND {peer}\n"),
        KillSwitchAction::Status => "STATUS\n".to_string(),
    };

    let pipe_name = socket_path.to_string_lossy().into_owned();
    let client = connect_control_pipe_with_retry(&pipe_name).await
        .with_context(|| format!("Failed to connect to control pipe {}", pipe_name))?;
    let (read_half, mut write_half) = tokio::io::split(client);

    write_half.write_all(command.as_bytes()).await
        .context("Failed to send command to control pipe")?;

    let mut reader = BufReader::new(read_half);
    let mut reply = String::new();
    reader.read_line(&mut reply).await
        .context("Failed to read reply from control pipe")?;

    print!("{}", reply);
    if reply.starts_with("ERR") {
        anyhow::bail!("kill-switch: {}", reply.trim_end());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
async fn kill_switch_cmd(_socket_path: &PathBuf, _action: &KillSwitchAction) -> Result<()> {
    anyhow::bail!("kill-switch: control socket not supported on this platform")
}

async fn join_network(config_path: &PathBuf, bootstrap: &str) -> Result<()> {
    info!("Joining AXIOM network via {}", bootstrap);

    let mut config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        NodeConfig::default()
    };

    // Add bootstrap node
    let bootstrap_addr: SocketAddr = bootstrap.parse()
        .context("Invalid bootstrap address")?;

    if !config.bootstrap_nodes.contains(&bootstrap_addr) {
        config.bootstrap_nodes.push(bootstrap_addr);
    }

    // Save updated config
    config.save(config_path)?;

    info!("Added bootstrap node: {}", bootstrap);
    info!("Run 'forge-node start' to connect");

    Ok(())
}

async fn show_info(config_path: &PathBuf) -> Result<()> {
    let config = if config_path.exists() {
        NodeConfig::load(config_path)?
    } else {
        println!("No configuration found. Run 'forge-node init' first.");
        return Ok(());
    };

    println!("Forge Node Information");
    println!("======================");
    println!("Node ID:        {}", hex::encode(&config.node_id[..8]));
    println!("Listen Address: {}", config.listen_addr);
    println!("API Address:    {}", config.api_addr);
    println!("Data Directory: {}", config.data_dir.display());
    println!("Max Peers:      {}", config.max_peers);
    println!("Guardian:       {}", if config.enable_guardian { "enabled" } else { "disabled" });
    println!("Watcher:        {}", if config.enable_watcher { "enabled" } else { "disabled" });

    if !config.bootstrap_nodes.is_empty() {
        println!("\nBootstrap Nodes:");
        for node in &config.bootstrap_nodes {
            println!("  - {}", node);
        }
    }

    Ok(())
}

/// AXIOM Phase 3.2 access resolver - see `Commands::Access`'s doc comment
/// for the full contract. Resolves which policy file to read (an explicit
/// `--policy` override, or else `--config`'s `capability_policy_path`),
/// loads it via `axiom_gateway::CapabilityPolicy::load` (the SAME
/// fail-closed loader the running node itself uses - a broken file reports
/// as "no capabilities registered," never a crash or a permissive
/// fallback), and dispatches to exactly one of the two report modes.
/// Deliberately never calls `NodeConfig::load_or_generate_identity` (no
/// `node.key` read or written) and never constructs a `ForgeNode` (no
/// socket bound, no discovery, no WAN) - the entire cost of this command is
/// one TOML file read, matching the roadmap's "cheap because the policy is
/// one file" framing literally.
async fn access_cmd(
    config_path: &PathBuf,
    policy_override: Option<&PathBuf>,
    identity_hex: Option<&str>,
    capability: Option<&str>,
) -> Result<()> {
    use axiom_types::crypto::NodeId;

    let policy_path = match policy_override {
        Some(p) => p.clone(),
        None => {
            let config = if config_path.exists() {
                NodeConfig::load(config_path)?
            } else {
                NodeConfig::default()
            };
            config.capability_policy_path
        }
    };

    let policy = axiom_gateway::CapabilityPolicy::load(&policy_path);

    let output = match (identity_hex, capability) {
        (Some(_), Some(_)) => {
            anyhow::bail!("axiom access: specify either an <identity> or --capability <name>, not both");
        }
        (None, None) => {
            anyhow::bail!("axiom access: specify either an <identity> (hex NodeId) or --capability <name>");
        }
        (Some(id_hex), None) => {
            let bytes = hex::decode(id_hex)
                .with_context(|| format!("axiom access: identity '{}' is not valid hex", id_hex))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!("axiom access: identity must be exactly 32 bytes (64 hex chars), got {}", v.len())
            })?;
            format_access_by_identity(&policy, id_hex, NodeId::from_bytes(arr))
        }
        (None, Some(cap)) => format_access_by_capability(&policy, cap),
    };

    println!("{}", output);
    Ok(())
}

/// `axiom access <identity>` report body - a pure function of the loaded
/// policy plus the already-parsed identity, returning a `String` rather
/// than printing directly so `main_tests` below can assert on exact output
/// without capturing stdout (same "pure formatting helper, thin println!
/// wrapper around it" split `send_wan_intent_request`/`wan_intent_cmd`
/// already use above).
fn format_access_by_identity(
    policy: &axiom_gateway::CapabilityPolicy,
    id_hex: &str,
    identity: axiom_types::crypto::NodeId,
) -> String {
    let mut names = policy.capability_names();
    names.sort();

    let mut lines = vec![
        format!("Access for identity {}", id_hex),
        "=".repeat(24 + id_hex.len()),
    ];

    let mut matched = 0;
    for name in names {
        if !policy.allows(name, identity) {
            continue;
        }
        // `allows` only returns true for a registered entry, so this is
        // always Some - but handled without unwrap() to stay consistent
        // with this module's no-panic-on-policy-data discipline.
        let Some(summary) = policy.capability_summary(name) else { continue };
        matched += 1;
        // AXIOM Phase 3.8: find THIS identity's own entry (already
        // filtered to only currently-effective peers by
        // `capability_summary`) to report its expiry.
        let expiry = summary
            .allowed_peers
            .iter()
            .find(|(hex, _)| hex == id_hex)
            .map(|(_, expires)| match expires {
                Some(ts) => format!("expires_unix={ts}"),
                None => "expiry=permanent".to_string(),
            })
            .unwrap_or_else(|| "expiry=permanent".to_string());
        lines.push(format!(
            "  - {name:<20} tier={tier:<6} rate_limit={rl:>4}s concurrency={conc:<4} {expiry}",
            name = name,
            tier = summary.tier.as_str(),
            rl = summary.rate_limit_secs,
            conc = summary.concurrency,
        ));
    }

    if matched == 0 {
        lines.push("  (none - this identity is not on any capability's allowlist)".to_string());
    }

    lines.join("\n")
}

/// `axiom access --capability <name>` report body - see
/// `format_access_by_identity`'s doc comment for why this returns a
/// `String` instead of printing directly.
fn format_access_by_capability(policy: &axiom_gateway::CapabilityPolicy, capability: &str) -> String {
    let Some(summary) = policy.capability_summary(capability) else {
        return format!(
            "Capability '{capability}' is not present in the policy (no entry, or an entry that failed \
             closed for lacking a valid tier) - denies everyone. This is not necessarily a bug: e.g. \
             network_clients is deliberately absent from the live policy pending a properly-scoped credential."
        );
    };

    let mut lines = vec![
        format!("Capability: {}", capability),
        format!("Tier:        {}", summary.tier.as_str()),
        format!("Rate limit:  {}s", summary.rate_limit_secs),
        format!("Concurrency: {}", summary.concurrency),
        String::new(),
    ];

    if summary.allowed_peers.is_empty() {
        lines.push("Allowed identities: (none - allowlist is empty, denies everyone)".to_string());
    } else {
        lines.push(format!("Allowed identities ({}) - only currently-effective (non-expired) entries shown:", summary.allowed_peers.len()));
        // AXIOM Phase 3.8: each peer's own expiry, if any.
        for (peer, expires) in &summary.allowed_peers {
            match expires {
                Some(ts) => lines.push(format!("  - {peer}  (expires_unix={ts})")),
                None => lines.push(format!("  - {peer}  (permanent)")),
            }
        }
    }

    lines.join("\n")
}

/// AXIOM Phase 3.4: `verify-audit` - reads `path` as a JSON-Lines
/// hash-chained audit log (`axiom_gateway::audit`) and reports whether the
/// whole chain verifies, or exactly where/how it's broken. Thin wrapper
/// around `axiom_gateway::verify_chain` plus `format_verify_report` - see
/// those for the actual walk/formatting logic (split out, same "pure
/// function main_tests can assert on, thin println! wrapper around it"
/// pattern `format_access_by_identity`/`format_access_by_capability` use
/// above).
async fn verify_audit_cmd(path: &PathBuf) -> Result<()> {
    let result = axiom_gateway::verify_chain(path);
    let is_valid = result.is_ok();
    println!("{}", format_verify_report(path, &result));
    if is_valid {
        Ok(())
    } else {
        // Non-zero exit for a broken chain - this command exists to be
        // scripted/alerted on, not just read by a human at a terminal; the
        // detailed WHY is already in the printed report above.
        anyhow::bail!("audit log at {} failed to verify", path.display());
    }
}

/// `verify-audit`'s report body - see `verify_audit_cmd`'s doc comment for
/// why this is split out as a pure function.
fn format_verify_report(
    path: &std::path::Path,
    result: &std::result::Result<axiom_gateway::ChainState, axiom_gateway::AuditChainBreak>,
) -> String {
    match result {
        Ok(state) => format!(
            "chain valid, {n} entr{suffix}\nPath:      {path}\nLast hash: {hash}",
            n = state.entries,
            suffix = if state.entries == 1 { "y" } else { "ies" },
            path = path.display(),
            hash = hex::encode(state.last_hash),
        ),
        Err(broken) => format!("chain INVALID\nPath: {path}\n{broken}", path = path.display()),
    }
}

#[cfg(test)]
mod main_tests {
    //! CLI-level tests for `wan-intent`. The underlying wire-protocol
    //! functions (`build_intent_frame`, `decode_verified_frame`,
    //! `WanEndpoint`/`connect_and_verify_liveness`) and the server-side
    //! dispatch path (`wan_capability_session`, `dispatch_intent`) are
    //! already covered by `node.rs`'s own `wan_capability_tests`. These
    //! tests are about the NEW code this subcommand adds: argument parsing
    //! (pure, no network) and the client-side request/reply/error-path
    //! logic + output (`send_wan_intent_request`, exercised end-to-end over
    //! a real WAN connection using the same `bind_local_only` loopback
    //! pattern `wan_capability_tests` uses, rather than mocking the
    //! transport).
    use super::*;
    use axiom_crypto::identity::Keypair;
    use axiom_transport::wan::{WanAllowlist, WanEndpoint};
    use axiom_types::crypto::NodeId;
    use std::collections::HashSet;
    use crate::network::DispatchContext;
    use crate::node::wan_capability_session;
    use axiom_gateway::CapabilityPolicy;

    // --- Argument parsing ---

    #[test]
    fn wan_intent_cli_parses_with_only_required_peer() {
        let peer_hex = "aa".repeat(32);
        let cli = Cli::try_parse_from(["forge-node", "wan-intent", "--peer", &peer_hex])
            .expect("wan-intent --peer <hex> alone should parse");
        match cli.command {
            Some(Commands::WanIntent { peer, allow, capability, payload }) => {
                assert_eq!(peer, peer_hex);
                assert!(allow.is_empty());
                assert_eq!(capability, "echo", "capability default must match the LAN `intent` subcommand's default");
                assert_eq!(payload, "hello axiom", "payload default must match the LAN `intent` subcommand's default");
            }
            other => panic!("expected Commands::WanIntent, got {}", if other.is_some() { "a different command" } else { "None" }),
        }
    }

    #[test]
    fn wan_intent_cli_parses_full_arg_set_with_repeated_allow() {
        let peer_hex = "bb".repeat(32);
        let allow1 = "cc".repeat(32);
        let allow2 = "dd".repeat(32);
        let cli = Cli::try_parse_from([
            "forge-node", "wan-intent",
            "--peer", &peer_hex,
            "--capability", "sysinfo",
            "--payload", "custom payload",
            "--allow", &allow1,
            "--allow", &allow2,
        ]).expect("full wan-intent arg set should parse");
        match cli.command {
            Some(Commands::WanIntent { peer, allow, capability, payload }) => {
                assert_eq!(peer, peer_hex);
                assert_eq!(capability, "sysinfo");
                assert_eq!(payload, "custom payload");
                assert_eq!(allow, vec![allow1, allow2]);
            }
            _ => panic!("expected Commands::WanIntent"),
        }
    }

    #[test]
    fn wan_intent_cli_requires_peer() {
        let result = Cli::try_parse_from(["forge-node", "wan-intent"]);
        assert!(result.is_err(), "wan-intent with no --peer must fail to parse, same as wan-ping");
    }

    // --- Client-side request/reply/error-path logic, over a real WAN connection ---

    fn test_capabilities() -> Arc<Vec<String>> {
        Arc::new(vec!["echo".to_string(), "sysinfo".to_string()])
    }

    fn test_dispatch_context(identity: Keypair, allowed_peers: HashSet<NodeId>) -> DispatchContext {
        DispatchContext {
            identity,
            local_capabilities: test_capabilities(),
            uai_config: Arc::new(None),
            notify_topic: Arc::new(None),
            policy: Arc::new(CapabilityPolicy::for_test(&["echo", "sysinfo"], allowed_peers)),
            tier2_flow: None,
            audit_log: None,
        }
    }

    /// Same loopback-pair pattern as `node.rs`'s
    /// `wan_capability_tests::connected_pair` - duplicated rather than
    /// imported, since that helper is private to its own test module (same
    /// reasoning as the rest of that module's test scaffolding staying
    /// module-private). Binds two relay-disabled endpoints and connects
    /// A -> B, with B's side already past `handle_incoming`/liveness.
    async fn connected_pair(kp_a: Keypair, kp_b: Keypair) -> (
        Arc<WanEndpoint>,
        Arc<WanEndpoint>,
        iroh::endpoint::Connection,
        iroh::endpoint::Connection,
        NodeId,
    ) {
        let mut allow_a = WanAllowlist::new();
        allow_a.allow(kp_b.node_id());
        let mut allow_b = WanAllowlist::new();
        allow_b.allow(kp_a.node_id());

        let ep_a = Arc::new(WanEndpoint::bind_local_only(kp_a, allow_a).await.expect("bind a"));
        let ep_b = Arc::new(WanEndpoint::bind_local_only(kp_b, allow_b).await.expect("bind b"));
        let b_node_id = ep_b.local_node_id();
        let b_addr_wild = ep_b.local_addrs().first().copied().expect("b bound addr");
        let b_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), b_addr_wild.port());

        let ep_b_for_accept = ep_b.clone();
        let accept_task = tokio::spawn(async move {
            ep_b_for_accept.accept_with_liveness().await.expect("accept+liveness")
        });

        let peer_addr = iroh::EndpointAddr::new(
            iroh::EndpointId::from_bytes(b_node_id.as_bytes()).expect("valid key")
        ).with_ip_addr(b_addr);
        let (conn_a, _pong) = ep_a
            .connect_direct_and_verify_liveness(peer_addr, b_node_id)
            .await
            .expect("connect+liveness");

        let (conn_b, _peer_a_id) = accept_task.await.expect("join");

        (ep_a, ep_b, conn_a, conn_b, b_node_id)
    }

    #[tokio::test]
    async fn wan_intent_fulfills_over_real_wan_connection() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        let mut allowed = HashSet::new();
        allowed.insert(kp_a.node_id());
        let ctx_b = test_dispatch_context(kp_b, allowed);
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        // Exercises the exact function `wan_intent_cmd` calls after
        // dial+liveness - proves the new CLI-level request/reply logic
        // round-trips a real Fulfill over a real (loopback) WAN connection.
        let reply = send_wan_intent_request(&conn_a, &kp_a, b_node_id, "echo", b"hello wan-intent".to_vec())
            .await
            .expect("echo request should be fulfilled");
        assert_eq!(reply, b"hello wan-intent");
    }

    #[tokio::test]
    async fn wan_intent_reports_policy_rejection_distinctly() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        // Deliberately do NOT allowlist kp_a in B's capability policy - the
        // WAN liveness handshake still succeeds (that's transport-level,
        // gated only by WanAllowlist), but dispatch_intent on B's side must
        // return an Error frame, which send_wan_intent_request has to
        // surface as a distinguishable "rejected" error rather than a
        // decode failure or a bare timeout.
        let ctx_b = test_dispatch_context(kp_b, HashSet::new());
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        let err = send_wan_intent_request(&conn_a, &kp_a, b_node_id, "echo", b"hi".to_vec())
            .await
            .expect_err("a peer with no policy allowlist entry must be rejected, not fulfilled");
        let msg = err.to_string();
        assert!(
            msg.contains("rejected the request"),
            "expected wan-intent's distinguishable rejection wording, got: {msg}"
        );
    }

    #[tokio::test]
    async fn wan_intent_reports_unknown_capability_distinctly() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        let mut allowed = HashSet::new();
        allowed.insert(kp_a.node_id());
        let ctx_b = test_dispatch_context(kp_b, allowed);
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        // "not_a_real_capability" isn't in test_capabilities() - B's
        // dispatch_intent returns an "unknown capability" Error frame,
        // which should surface through the same distinguishable rejection
        // path as an authorization denial (both are Error-frame replies,
        // as opposed to a transport/timeout/decode failure).
        let err = send_wan_intent_request(&conn_a, &kp_a, b_node_id, "not_a_real_capability", b"hi".to_vec())
            .await
            .expect_err("unknown capability should error, not fulfill");
        assert!(err.to_string().contains("rejected the request"));
    }

    #[tokio::test]
    async fn wan_intent_parse_node_id_rejects_bad_hex() {
        // wan_intent_cmd's own peer/allow parsing (parse_node_id, a local
        // fn) - not reachable directly since it's nested inside
        // wan_intent_cmd, so exercised the same way a user would hit it:
        // through the full command, which fails fast on the config load /
        // identity step being trivial (no config file => defaults, no disk
        // I/O) and then on the malformed hex, without ever touching the
        // network.
        let bad_hex = "not-valid-hex";
        let result = wan_intent_cmd(
            &PathBuf::from("/nonexistent/forge-node-test-config.toml"),
            bad_hex,
            &[],
            "echo",
            "hi",
        ).await;
        let err = result.expect_err("malformed peer hex must be rejected before any network activity");
        assert!(
            err.to_string().contains("hex") || err.chain().any(|c| c.to_string().contains("hex")),
            "expected a hex-decode error, got: {err}"
        );
    }

    // --- init: --data-dir override (2026-08-06) ---
    //
    // Bug: `init`'s private-key destination (`data_dir`) used to be
    // hardcoded to `/var/lib/forge` with no CLI flag able to override it,
    // even though `--output` looked like it should control this (it only
    // ever controlled config.toml/node.pub/capability_policy.toml). The
    // functional test below proves an explicit `--data-dir` is actually
    // honored end-to-end (key lands there, config.toml's `data_dir` field
    // matches). The parse-level test proves the documented default
    // (/var/lib/forge) is unchanged for a bare `init` with no flags -
    // deliberately NOT exercised by actually running `init_node` with no
    // override, since that would write into the real default path; see
    // this file's own `init_node` doc comment for why a stray write there
    // is not a hypothetical risk in this codebase.

    #[test]
    fn init_cli_defaults_output_and_data_dir_when_unset() {
        let cli = Cli::try_parse_from(["forge-node", "init"])
            .expect("bare `init` with no flags should parse");
        match cli.command {
            Some(Commands::Init { output, data_dir, force }) => {
                assert_eq!(output, PathBuf::from("/etc/forge"));
                assert_eq!(data_dir, PathBuf::from("/var/lib/forge"), "default data_dir must stay /var/lib/forge - this is the documented default, only an explicit --data-dir should change it");
                assert!(!force);
            }
            other => panic!("expected Commands::Init, got {}", if other.is_some() { "a different command" } else { "None" }),
        }
    }

    #[test]
    fn init_cli_parses_explicit_data_dir_and_output() {
        let cli = Cli::try_parse_from([
            "forge-node", "init",
            "--output", "/tmp/axiom-test-init-output",
            "--data-dir", "/tmp/axiom-test-init-data",
            "--force",
        ]).expect("init with explicit --output/--data-dir/--force should parse");
        match cli.command {
            Some(Commands::Init { output, data_dir, force }) => {
                assert_eq!(output, PathBuf::from("/tmp/axiom-test-init-output"));
                assert_eq!(data_dir, PathBuf::from("/tmp/axiom-test-init-data"));
                assert!(force);
            }
            other => panic!("expected Commands::Init, got {}", if other.is_some() { "a different command" } else { "None" }),
        }
    }

    /// Removes a directory tree if present, ignoring "already gone" -
    /// mirrors the `let _ = std::fs::remove_file(...)` cleanup idiom
    /// `policy.rs`'s tests use, just for a directory instead of one file.
    fn cleanup_dir(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn init_with_explicit_data_dir_writes_key_there_not_to_default_path() {
        let unique = format!("{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos());
        let output_dir = std::env::temp_dir().join(format!("axiom-test-init-output-{unique}"));
        let data_dir = std::env::temp_dir().join(format!("axiom-test-init-data-{unique}"));
        cleanup_dir(&output_dir);
        cleanup_dir(&data_dir);

        let result = init_node(&output_dir, &data_dir, false).await;
        assert!(result.is_ok(), "init_node with fresh explicit output/data dirs should succeed: {:?}", result.err());

        // The key must land at the EXPLICIT data_dir, not at the
        // documented default - this is the whole point of the fix.
        let key_path = data_dir.join("node.key");
        assert!(key_path.exists(), "node.key must be written to the explicit --data-dir, got nothing at {}", key_path.display());
        let key_bytes = std::fs::read(&key_path).expect("read node.key");
        assert_eq!(key_bytes.len(), 32, "node.key must be a raw 32-byte Ed25519 secret key");
        assert!(!PathBuf::from("/var/lib/forge/node.key").starts_with(&data_dir), "sanity: test data_dir must not coincide with the real default path");

        // config.toml's own data_dir field must match what was actually
        // used to write the key - this is the invariant the original
        // 2026-07-30 bug violated (two independently-hardcoded paths that
        // could silently drift apart).
        let config_path = output_dir.join("config.toml");
        let loaded = NodeConfig::load(&config_path).expect("load generated config.toml");
        assert_eq!(loaded.data_dir, data_dir, "config.toml's data_dir must match the --data-dir the key was actually written to");

        // node.pub and capability_policy.toml still go to output_dir, same
        // as before this fix - --data-dir only changes where the KEY goes.
        assert!(output_dir.join("node.pub").exists());
        assert!(output_dir.join("capability_policy.toml").exists());

        cleanup_dir(&output_dir);
        cleanup_dir(&data_dir);
    }

    #[tokio::test]
    async fn init_refuses_to_overwrite_existing_key_at_explicit_data_dir_without_force() {
        let unique = format!("{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos());
        let output_dir = std::env::temp_dir().join(format!("axiom-test-init-force-output-{unique}"));
        let data_dir = std::env::temp_dir().join(format!("axiom-test-init-force-data-{unique}"));
        cleanup_dir(&output_dir);
        cleanup_dir(&data_dir);

        init_node(&output_dir, &data_dir, false).await.expect("first init should succeed");
        let key_bytes_before = std::fs::read(data_dir.join("node.key")).expect("read node.key after first init");

        // Second init at the SAME explicit data_dir, no --force: must
        // refuse rather than silently rotate the identity - same
        // fail-closed guarantee `--force`'s own doc comment describes for
        // the default path, now proven to also hold for an explicit
        // --data-dir.
        let result = init_node(&output_dir, &data_dir, false).await;
        assert!(result.is_err(), "init without --force must refuse to overwrite an existing key at an explicit --data-dir");
        let key_bytes_after = std::fs::read(data_dir.join("node.key")).expect("read node.key after refused second init");
        assert_eq!(key_bytes_before, key_bytes_after, "refused init must not have touched the existing key");

        // --force explicitly allows it.
        let result = init_node(&output_dir, &data_dir, true).await;
        assert!(result.is_ok(), "init --force should overwrite an existing key at an explicit --data-dir: {:?}", result.err());

        cleanup_dir(&output_dir);
        cleanup_dir(&data_dir);
    }

    // --- AXIOM Phase 3.2: `axiom access` resolver CLI ---

    // --- CLI argument parsing ---

    #[test]
    fn access_cli_parses_identity_positional() {
        let id_hex = "ab".repeat(32);
        let cli = Cli::try_parse_from(["forge-node", "access", &id_hex])
            .expect("access <identity> should parse");
        match cli.command {
            Some(Commands::Access { identity, capability, policy }) => {
                assert_eq!(identity, Some(id_hex));
                assert_eq!(capability, None);
                assert_eq!(policy, None);
            }
            other => panic!("expected Commands::Access, got {}", if other.is_some() { "a different command" } else { "None" }),
        }
    }

    #[test]
    fn access_cli_parses_capability_flag() {
        let cli = Cli::try_parse_from(["forge-node", "access", "--capability", "echo"])
            .expect("access --capability <name> should parse");
        match cli.command {
            Some(Commands::Access { identity, capability, policy }) => {
                assert_eq!(identity, None);
                assert_eq!(capability, Some("echo".to_string()));
                assert_eq!(policy, None);
            }
            _ => panic!("expected Commands::Access"),
        }
    }

    #[test]
    fn access_cli_parses_policy_override() {
        let cli = Cli::try_parse_from([
            "forge-node", "access", "--capability", "echo", "--policy", "/tmp/custom-policy.toml",
        ]).expect("access with --policy override should parse");
        match cli.command {
            Some(Commands::Access { policy, .. }) => {
                assert_eq!(policy, Some(PathBuf::from("/tmp/custom-policy.toml")));
            }
            _ => panic!("expected Commands::Access"),
        }
    }

    #[test]
    fn access_cli_allows_no_args_at_parse_time() {
        // clap itself doesn't reject "neither identity nor --capability" -
        // both are optional at the argument-parsing layer, since clap has
        // no clean "exactly one of a positional and a flag" primitive.
        // access_cmd's own runtime check is what enforces "exactly one" -
        // see access_cmd_errors_when_neither_given /
        // access_cmd_errors_when_both_identity_and_capability_given below.
        let cli = Cli::try_parse_from(["forge-node", "access"])
            .expect("access with no args parses fine at the clap layer");
        assert!(matches!(cli.command, Some(Commands::Access { identity: None, capability: None, .. })));
    }

    // --- Test policy fixture ---

    /// Three identities (A, B, C) and three capabilities set up so every
    /// case the task calls out is covered in one fixture: overlapping
    /// allowlists (A and B both on `echo`), a capability nobody can call
    /// (`network_clients`, empty allowlist despite being registered), and
    /// an identity nobody grants anything to (C, present in neither
    /// capability's allowlist). Mirrors axiom-gateway's own `write_policy`
    /// test helper (policy.rs), duplicated here rather than imported since
    /// that helper is private to policy.rs's own test module.
    fn write_test_policy(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    struct AccessTestFixture {
        policy_path: PathBuf,
        identity_a: NodeId,
        identity_a_hex: String,
        identity_b: NodeId,
        identity_b_hex: String,
        identity_c: NodeId,
        identity_c_hex: String,
    }

    fn setup_access_test_fixture(policy_file_name: &str) -> AccessTestFixture {
        let identity_a = Keypair::generate().node_id();
        let identity_b = Keypair::generate().node_id();
        let identity_c = Keypair::generate().node_id();
        let identity_a_hex = hex::encode(identity_a.as_bytes());
        let identity_b_hex = hex::encode(identity_b.as_bytes());
        let identity_c_hex = hex::encode(identity_c.as_bytes());

        // AXIOM Phase 3.6: network_clients is Tier1, so it now also needs a
        // [[protected_resource]] section present in the file (even an
        // unrelated one, as here) or it fails closed at registration - see
        // axiom-gateway's policy.rs. Purely additive to this fixture;
        // doesn't change any allowlist/tier assertion below.
        let policy_path = write_test_policy(policy_file_name, &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.echo]\nallowed_peers = [\"{a}\", \"{b}\"]\nrate_limit_secs = 5\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{a}\"]\nrate_limit_secs = 0\nconcurrency = 20\ntier = \"tier0\"\n\n\
             [capability.network_clients]\nallowed_peers = []\nrate_limit_secs = 30\nconcurrency = 2\ntier = \"tier1\"\n",
            a = identity_a_hex, b = identity_b_hex,
        ));

        AccessTestFixture {
            policy_path, identity_a, identity_a_hex, identity_b, identity_b_hex, identity_c, identity_c_hex,
        }
    }

    // --- format_access_by_identity ---

    #[test]
    fn format_access_by_identity_lists_both_capabilities_for_identity_a() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-identity-a.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_identity(&policy, &fx.identity_a_hex, fx.identity_a);
        assert!(out.contains(&fx.identity_a_hex), "header must echo the queried identity");
        assert!(out.contains("echo"), "identity A is on echo's allowlist");
        assert!(out.contains("sysinfo"), "identity A is on sysinfo's allowlist");
        assert!(!out.contains("network_clients"), "network_clients has an empty allowlist, identity A must not be listed under it");
        assert!(out.contains("tier=tier0"));
        // AXIOM Phase 3.8: this fixture's entries are all bare hex strings
        // (no `expires`) - permanent entries, reported as such.
        assert!(out.contains("expiry=permanent"), "a bare-string allowlist entry has no expiry - must report permanent, not fabricate a value");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[test]
    fn format_access_by_identity_lists_only_echo_for_identity_b() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-identity-b.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_identity(&policy, &fx.identity_b_hex, fx.identity_b);
        assert!(out.contains("echo"), "identity B is on echo's allowlist");
        assert!(!out.contains("sysinfo"), "identity B is NOT on sysinfo's allowlist");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[test]
    fn format_access_by_identity_reports_none_clearly_for_zero_capability_identity() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-identity-c.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_identity(&policy, &fx.identity_c_hex, fx.identity_c);
        assert!(!out.contains("echo") || out.contains("not on any capability"),
            "identity C is on no allowlist - must not silently print nothing, must say so");
        assert!(out.to_lowercase().contains("none") || out.contains("not on any"), "must clearly report zero capabilities, not print nothing");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    // --- format_access_by_capability ---

    #[test]
    fn format_access_by_capability_lists_both_identities_for_echo() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-cap-echo.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_capability(&policy, "echo");
        assert!(out.contains(&fx.identity_a_hex));
        assert!(out.contains(&fx.identity_b_hex));
        assert!(!out.contains(&fx.identity_c_hex), "identity C is not allowlisted for echo");
        assert!(out.contains("tier0"));
        assert!(out.contains("5s"), "rate_limit_secs must be reported");
        assert!(out.contains("10"), "concurrency must be reported");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[test]
    fn format_access_by_capability_reports_empty_allowlist_clearly_for_network_clients() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-cap-networkclients.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_capability(&policy, "network_clients");
        // network_clients IS registered (tier1, present in the policy) but
        // its allowed_peers is empty - must be reported as "zero
        // identities," a DIFFERENT message from "capability doesn't exist
        // in the policy at all" (see the next test).
        assert!(out.contains("tier1"), "network_clients is registered with tier1, must still report its metadata");
        assert!(out.to_lowercase().contains("none") || out.contains("(none"), "must clearly report zero allowed identities, not print an empty list silently");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[test]
    fn format_access_by_capability_reports_not_present_for_absent_capability() {
        let fx = setup_access_test_fixture("axiom-access-test-fmt-cap-absent.toml");
        let policy = CapabilityPolicy::load(&fx.policy_path);
        let out = format_access_by_capability(&policy, "some_capability_not_in_the_policy_at_all");
        assert!(out.contains("not present in the policy"), "an absent capability must say so clearly rather than printing nothing or misleading data, got: {out}");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    // --- access_cmd end-to-end (argument validation + full read path) ---

    #[tokio::test]
    async fn access_cmd_errors_when_both_identity_and_capability_given() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-both.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), Some(&fx.identity_a_hex), Some("echo")).await;
        assert!(result.is_err(), "must reject identity AND --capability together");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_errors_when_neither_given() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-neither.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), None, None).await;
        assert!(result.is_err(), "must reject neither identity nor --capability given");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_errors_on_invalid_hex_identity() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-badhex.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), Some("not-valid-hex"), None).await;
        assert!(result.is_err(), "must reject non-hex identity rather than panicking or silently resolving nothing");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_errors_on_wrong_length_identity() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-shorthex.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), Some("aabbcc"), None).await;
        assert!(result.is_err(), "must reject a hex identity that isn't exactly 32 bytes");
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_succeeds_by_identity_with_explicit_policy_override() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-ok-identity.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), Some(&fx.identity_a_hex), None).await;
        assert!(result.is_ok(), "valid identity + explicit --policy must succeed: {:?}", result.err());
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_succeeds_by_capability_with_explicit_policy_override() {
        let fx = setup_access_test_fixture("axiom-access-test-cmd-ok-capability.toml");
        let result = access_cmd(&PathBuf::from("/nonexistent/config.toml"), Some(&fx.policy_path), None, Some("echo")).await;
        assert!(result.is_ok(), "valid --capability + explicit --policy must succeed: {:?}", result.err());
        let _ = std::fs::remove_file(&fx.policy_path);
    }

    #[tokio::test]
    async fn access_cmd_succeeds_against_a_missing_policy_file_reporting_deny_all() {
        // No --policy override AND no --config present: falls back to
        // NodeConfig::default()'s capability_policy_path
        // (/etc/forge/capability_policy.toml), which - on a machine with no
        // real deployment - won't exist. CapabilityPolicy::load's own
        // fail-closed contract means this must still succeed (Ok, "zero
        // capabilities"), never error out or panic, matching every other
        // "missing file" case in axiom-gateway's own tests.
        let result = access_cmd(&PathBuf::from("/nonexistent/config-does-not-exist.toml"), None, None, Some("echo")).await;
        assert!(result.is_ok(), "a missing policy file must resolve to 'not present', not an error: {:?}", result.err());
    }

    // --- AXIOM Phase 3.4: `verify-audit` ---

    #[test]
    fn verify_audit_cli_parses_required_path() {
        let cli = Cli::try_parse_from(["forge-node", "verify-audit", "--path", "/tmp/some-audit.jsonl"])
            .expect("verify-audit --path <p> should parse");
        match cli.command {
            Some(Commands::VerifyAudit { path }) => assert_eq!(path, PathBuf::from("/tmp/some-audit.jsonl")),
            other => panic!("expected Commands::VerifyAudit, got {}", if other.is_some() { "a different command" } else { "None" }),
        }
    }

    #[test]
    fn verify_audit_cli_requires_path() {
        let result = Cli::try_parse_from(["forge-node", "verify-audit"]);
        assert!(result.is_err(), "--path is required, must not silently default to anything");
    }

    #[test]
    fn format_verify_report_valid_chain_matches_expected_wording() {
        let state = axiom_gateway::ChainState { entries: 3, last_hash: [0xAB; 32] };
        let text = format_verify_report(std::path::Path::new("/tmp/audit.jsonl"), &Ok(state));
        assert!(text.starts_with("chain valid, 3 entries"), "got: {text}");
        assert!(text.contains(&hex::encode([0xAB; 32])));
    }

    #[test]
    fn format_verify_report_singular_entry_wording() {
        let state = axiom_gateway::ChainState { entries: 1, last_hash: [0u8; 32] };
        let text = format_verify_report(std::path::Path::new("/tmp/audit.jsonl"), &Ok(state));
        assert!(text.starts_with("chain valid, 1 entry\n"), "got: {text}");
    }

    #[test]
    fn format_verify_report_broken_chain_is_specific_not_generic() {
        let broken = axiom_gateway::AuditChainBreak::ContentTampered { index: 2 };
        let text = format_verify_report(std::path::Path::new("/tmp/audit.jsonl"), &Err(broken));
        assert!(text.starts_with("chain INVALID"));
        assert!(text.contains("index 2"), "must name the exact index, not just say 'invalid': {text}");
        assert!(text.contains("tampered"), "must name the mechanism, not just say 'invalid': {text}");
    }

    /// End-to-end: `verify_audit_cmd` against a real `AuditLog` written via
    /// `axiom_gateway::AuditLog::log_tier1_call`, both for a valid chain
    /// and a tampered one - proves the CLI's own plumbing (not just
    /// `axiom_gateway::verify_chain` in isolation, which axiom-gateway's
    /// own test suite already covers) end to end.
    #[tokio::test]
    async fn verify_audit_cmd_succeeds_on_a_real_valid_log() {
        let path = std::env::temp_dir().join(format!("forge-node-verify-audit-test-valid-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = axiom_gateway::AuditLog::open(&path).expect("open a fresh audit log");
        let caller = Keypair::generate().node_id();
        for i in 0..3 {
            log.log_tier1_call(
                caller,
                "network_clients",
                &[],
                Ok(Some(format!("call {i}"))),
                std::time::Duration::from_millis(1),
            )
            .expect("log_tier1_call should succeed");
        }
        drop(log);

        let result = verify_audit_cmd(&path).await;
        assert!(result.is_ok(), "a valid chain must report success: {:?}", result.err());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn verify_audit_cmd_fails_on_a_tampered_log() {
        let path = std::env::temp_dir().join(format!("forge-node-verify-audit-test-tampered-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = axiom_gateway::AuditLog::open(&path).expect("open a fresh audit log");
        let caller = Keypair::generate().node_id();
        log.log_tier1_call(caller, "network_clients", &[], Ok(None), std::time::Duration::from_millis(1))
            .expect("log_tier1_call should succeed");
        drop(log);

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, contents.replace("network_clients", "tampered_capability")).unwrap();

        let result = verify_audit_cmd(&path).await;
        assert!(result.is_err(), "a tampered chain must report failure via a non-zero exit, not silently succeed");
        let _ = std::fs::remove_file(&path);
    }
}
