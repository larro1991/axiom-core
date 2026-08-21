//! Forge Node - Core node implementation

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tracing::{info, debug, warn};

use axiom_types::NodeId;
use axiom_crypto::identity::Keypair;
use axiom_guardian::{Guardian, GuardianConfig};
use axiom_watcher::{Watcher, WatcherConfig};
use axiom_transport::wan::{WanAllowlist, WanEndpoint};
use axiom_types::frame::FrameType;
use ember::Coordinator;
use crate::network::{decode_verified_frame, dispatch_intent, DispatchContext, DispatchOrigin};
#[cfg(test)]
use axiom_router::ai::Intent as AiIntent;

/// Cap on concurrent in-flight WAN connections (post-handshake, mid-liveness
/// or beyond). Bounds one compromised-or-buggy ALLOWLISTED peer from
/// exhausting resources by opening connections in a tight loop - the
/// allowlist bounds WHO can connect, not HOW MANY connections they can
/// open. `try_acquire_owned`, reject-don't-queue (same pattern as
/// `network.rs`'s `NETWORK_CLIENTS_MAX_CONCURRENT` semaphore) - an
/// over-the-cap connection is closed immediately, not made to wait.
const WAN_MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Upper bound on handshake-completion + allowlist-check + liveness for one
/// spawned inbound connection, wrapping the WHOLE `handle_incoming` call -
/// not just its own internal liveness-exchange timeout. Fable review
/// (Cycle 1): without this, an UNAUTHENTICATED peer (identity, and
/// therefore allowlist membership, isn't known until the handshake itself
/// completes) can hold a semaphore permit for iroh's transport-level idle
/// timeout (~30s) simply by dragging out the handshake - 16 such peers
/// exhaust every permit and deny WAN service to legitimate allowlisted
/// peers, from a position that never had to prove any identity at all.
/// Set comfortably above `axiom_transport::wan::LIVENESS_EXCHANGE_TIMEOUT`
/// (10s) to leave room for the handshake itself.
const WAN_INBOUND_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long a WAN capability session (a liveness-verified connection, now
/// exchanging Intent/Fulfill/Error requests) may sit with no new request
/// stream before it's closed. Fable review (Cycle 2B): allowing multiple
/// requests per connection (rather than dial-per-request) means the
/// connection semaphore permit is held for the WHOLE session, not just one
/// request - without an application-level bound, a peer that keeps the
/// connection alive via QUIC keepalives (which defeat quinn's own idle
/// timeout) could pin a permit indefinitely. This is deliberately NOT the
/// same timeout as WAN_INBOUND_TOTAL_TIMEOUT, and the session loop below
/// does NOT sit inside that 15s wrap - a real session is supposed to
/// outlive 15s.
const WAN_SESSION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Cap on a single WAN Intent request/reply's encoded frame size. Matches
/// the LAN receive loop's implicit cap (its `recv_buffer_size` /
/// `vec![0u8; 65536]`, `network.rs`) - QUIC streams have no equivalent
/// built-in bound, so this needs to be explicit or an allowlisted peer
/// could balloon memory with an arbitrarily large request/reply.
const WAN_MAX_FRAME_BYTES: usize = 65536;

/// Upper bound on ONE request/reply cycle within `wan_capability_session`
/// (from a stream being accepted through the reply's `stopped()` ack) -
/// required, not just recommended (Fable Cycle 2B diff review): before
/// this, only `conn.accept_bi()` itself was covered by
/// `WAN_SESSION_IDLE_TIMEOUT`. A peer could open a stream (which resets
/// the idle timer via QUIC keepalives - client-controlled, defeats the
/// server's own idle timeout regardless of server config), then never
/// finish writing its request, or withhold flow-control credit/acks on
/// the reply - the session task would hang in `read_to_end`/`stopped()`
/// FOREVER, silently, with its connection-semaphore and per-peer-slot
/// permits both pinned indefinitely. Generous relative to real dispatch
/// latency - `network_clients` (the only capability with real external
/// latency) is hard-denied for WAN, so every legitimate WAN dispatch is
/// echo/sysinfo-fast.
const WAN_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Max concurrent WAN connections from any ONE peer, independent of
/// `WAN_MAX_CONCURRENT_CONNECTIONS`'s global pool. Required (Fable Cycle
/// 2B diff review): once sessions became long-lived (multi-request per
/// connection, Gap B) rather than dying within ~15s (Cycle 2A), the global
/// semaphore's own doc comment claim - "bounds ONE compromised-or-buggy
/// allowlisted peer" - stopped being true. A single peer opening
/// `WAN_MAX_CONCURRENT_CONNECTIONS` connections and refreshing each one's
/// idle timer with a trivial request just under the timeout starves every
/// OTHER allowlisted peer indefinitely, using only legitimate-looking
/// traffic. This caps that peer's share of the global pool instead.
const WAN_MAX_CONNECTIONS_PER_PEER: usize = 2;

use crate::config::NodeConfig;

/// How often `run_event_loop` rechecks `shutdown_flag` when the network is
/// otherwise quiet (see the loop body for why this can't just be "whenever
/// `poll_event` returns").
const SHUTDOWN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
use crate::network::NetworkManager;

/// The main Forge node
pub struct ForgeNode {
    /// Node configuration
    config: NodeConfig,

    /// Node identity (keypair)
    identity: Keypair,

    /// Network manager. Wrapped in its own lock, independent of whatever
    /// lock guards `ForgeNode` itself (main.rs's `Arc<RwLock<ForgeNode>>`,
    /// held by `run_event_loop` for the node's ENTIRE running lifetime, per
    /// `shutdown_flag`'s doc comment above) - `control.rs`'s socket handler
    /// needs to reach this directly, without ever contending for that outer
    /// lock, or every control request would deadlock forever waiting for a
    /// lock the event loop never releases. See `network_handle()`.
    network: Option<Arc<tokio::sync::Mutex<NetworkManager>>>,

    /// EMBER coordinator for distributed workloads
    #[allow(dead_code)]
    coordinator: Coordinator,

    /// Security guardian (optional)
    guardian: Option<Guardian>,

    /// Network watcher (optional)
    #[allow(dead_code)]
    watcher: Option<Watcher>,

    /// Running state
    running: bool,

    /// Shutdown signal, checked by `run_event_loop`'s loop condition.
    /// Separate from `running`/the RwLock that guards `self` so a caller can
    /// request shutdown (e.g. from a Ctrl+C handler racing the event loop
    /// via `tokio::select!`) without needing the write lock that the
    /// running event loop task holds for its entire lifetime - taking that
    /// lock first would deadlock waiting for the loop to notice it should
    /// stop.
    shutdown_flag: Arc<AtomicBool>,

    /// Handle to the spawned WAN accept-loop task (AXIOM-11.1), if
    /// `config.wan_enabled`. Aborted on `shutdown()` - a bare `JoinHandle`
    /// dropped without `.abort()` leaves the accept loop itself running
    /// detached. NOTE (Fable review, Cycle 1): `.abort()` does NOT cascade
    /// to the per-connection tasks the loop spawns via `tokio::spawn` -
    /// those are independent runtime-owned tasks and keep running until
    /// `wan_accept_loop`'s own `WAN_INBOUND_TOTAL_TIMEOUT` bound expires for
    /// each of them (worst case ~15s after shutdown, not indefinite - see
    /// that const's doc). Acceptable for now since the process typically
    /// exits shortly after shutdown anyway; Cycle 2 should instead store
    /// the `Arc<WanEndpoint>` here and call `endpoint.close().await` (which
    /// makes `accept()` return `None`, ending the loop on its own) with
    /// `.abort()` kept only as a backstop.
    wan_task: Option<tokio::task::JoinHandle<()>>,
}

impl ForgeNode {
    /// Create a new Forge node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing Forge node...");

        // Load or generate identity - see NodeConfig::load_or_generate_identity
        // for the mismatch-check rationale (this used to be duplicated
        // inline here, in request_intent_cmd, and in wan_ping_cmd).
        let identity = config.load_or_generate_identity()?;
        let node_id = identity.node_id();
        debug!("Node ID: {}", hex::encode(node_id.as_bytes()));

        // Initialize EMBER coordinator
        let coordinator = Coordinator::new(node_id);

        // Initialize guardian if enabled
        let guardian = if config.enable_guardian {
            info!("Initializing Guardian security module");
            Some(Guardian::new(GuardianConfig::default()))
        } else {
            None
        };

        // Initialize watcher if enabled
        let watcher = if config.enable_watcher {
            info!("Initializing Watcher network monitor");
            Some(Watcher::new(WatcherConfig::default()))
        } else {
            None
        };

        Ok(Self {
            config,
            identity,
            network: None,
            coordinator,
            guardian,
            watcher,
            running: false,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            wan_task: None,
        })
    }

    /// Start the node
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            warn!("Node already running");
            return Ok(());
        }

        info!("Starting Forge node services...");

        // Start network manager
        let network = NetworkManager::new(
            &self.config,
            self.identity.clone(),
        ).await?;
        let network = Arc::new(tokio::sync::Mutex::new(network));

        self.network = Some(network.clone());

        // AXIOM-14 Cycle 3: periodic pruning for maps that only grow
        // otherwise (see spawn_maintenance's doc comment). One-shot, not
        // per-peer like spawn_announce/spawn_ping above - runs for the
        // node's whole lifetime, not once per bootstrap connection.
        network.lock().await.spawn_maintenance();

        // Connect to bootstrap nodes
        if !self.config.bootstrap_nodes.is_empty() {
            info!("Connecting to {} bootstrap node(s)...", self.config.bootstrap_nodes.len());
            let mut network = network.lock().await;
            for addr in &self.config.bootstrap_nodes {
                match network.connect(addr).await {
                    Ok(peer_id) => {
                        info!("Connected to bootstrap node: {}", addr);
                        // Same Cycle A liveness demonstration as the
                        // discovery path - confirm the real AXIOM Frame
                        // channel works for explicitly-configured peers
                        // too, not just discovered ones. Non-blocking:
                        // a slow/dead bootstrap peer can't stall startup.
                        network.spawn_ping(peer_id, *addr);
                        // Cycle B: tell them what we can do.
                        network.spawn_announce(*addr);
                    }
                    Err(e) => warn!("Failed to connect to {}: {}", addr, e),
                }
            }
        }

        // AXIOM-11.1: WAN accept loop, off by default (config.wan_enabled).
        // Independent of the LAN NetworkManager above - separate transport,
        // separate allowlist, separate iroh::Endpoint.
        if self.config.wan_enabled {
            // Same log-and-skip-invalid-entries pattern as
            // network.rs's network_clients_allowed_peers parsing - a
            // typo'd entry should degrade to "that one peer can't reach
            // us", not take the whole node down.
            let mut allowlist = WanAllowlist::new();
            let mut parsed_count = 0usize;
            for s in &self.config.wan_allowed_peers {
                match hex::decode(s).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                    Some(arr) => {
                        allowlist.allow(NodeId::from_bytes(arr));
                        parsed_count += 1;
                    }
                    None => warn!("wan_allowed_peers: '{}' is not a valid 32-byte hex NodeId, skipped", s),
                }
            }
            // Fable review (Cycle 1): key this off the PARSED count, not
            // the raw config vec's length - a config with only typo'd
            // entries is just as effectively-empty as an empty list, and
            // deserves the same loud warning, not just per-entry skip logs.
            if parsed_count == 0 {
                warn!(
                    "wan_enabled=true but no valid entries in wan_allowed_peers - the WAN \
                     endpoint will bind and listen but reject every inbound connection \
                     (fail-closed allowlist, not a bug). Add peer NodeIds to \
                     wan_allowed_peers to actually allow WAN traffic."
                );
            }

            // Fable review (Cycle 1): bind() failing here is NOT the same
            // class of thing as a single failed bootstrap-node connect
            // above - that's per-peer degradation of a working subsystem;
            // this is the entire subsystem the operator explicitly opted
            // into (wan_enabled=true) silently not existing. An explicit
            // opt-in that can't be honored fails start() outright, loudly,
            // at the moment the operator is watching - not a background
            // warning they may never see.
            let wan_endpoint = WanEndpoint::bind(self.identity.clone(), allowlist)
                .await
                .map_err(|e| anyhow::anyhow!("wan_enabled=true but WAN endpoint bind failed: {e}"))?;
            let wan_endpoint = Arc::new(wan_endpoint);
            info!(
                "WAN endpoint bound, NodeId = {}",
                hex::encode(wan_endpoint.local_node_id().as_bytes())
            );
            let semaphore = Arc::new(tokio::sync::Semaphore::new(WAN_MAX_CONCURRENT_CONNECTIONS));
            // Gap B (AXIOM-11.2): safe to lock here - the event loop hasn't
            // started yet (nobody else holds this lock at this point in
            // start()), and dispatch_context() only clones Arc'd fields, so
            // the lock is released immediately after. The WAN accept loop
            // never touches this Mutex again after this point - see
            // DispatchContext's doc for why that matters (run_event_loop
            // holds it for up to SHUTDOWN_POLL_INTERVAL per iteration).
            let dispatch_ctx = network.lock().await.dispatch_context();
            let peer_connections = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            let task = tokio::spawn(wan_accept_loop(wan_endpoint, semaphore, dispatch_ctx, peer_connections));
            self.wan_task = Some(task);
        }

        self.running = true;
        info!("Forge node started");

        Ok(())
    }

    /// Get a handle that can request shutdown of a running event loop
    /// without needing `self`'s write lock (see `shutdown_flag`'s doc comment).
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown_flag.clone()
    }

    /// Cloneable handle to this node's live `NetworkManager`, independent of
    /// whatever lock guards `ForgeNode` itself. `control.rs` uses this
    /// directly (not `ForgeNode`'s own lock - see `network`'s doc comment)
    /// so a control request shares the exact same peer/capability/reputation
    /// state the running event loop has been building, without ever waiting
    /// on a lock the event loop holds for its entire lifetime.
    pub fn network_handle(&self) -> Option<Arc<tokio::sync::Mutex<NetworkManager>>> {
        self.network.clone()
    }

    /// Main event loop. Runs until `shutdown()` or `shutdown_signal()` sets
    /// the shutdown flag - callers needing to race this against something
    /// else (Ctrl+C, a supervisor signal) should run it in its own task and
    /// select! against that, using `shutdown_signal()` to stop it instead of
    /// requiring the write lock this method holds for its entire duration.
    pub async fn run_event_loop(&mut self) -> Result<()> {
        info!("Entering main event loop");

        loop {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            // select! between the next network event and a short timeout so
            // the shutdown flag actually gets rechecked. `network.poll_event()`
            // blocks indefinitely on a quiet network - its sender half lives
            // inside NetworkManager for the manager's whole lifetime, so it
            // never yields None - which previously meant Ctrl+C on an
            // otherwise-idle node hung forever waiting for this loop to
            // notice the flag had been set. Locking fresh each iteration
            // (rather than once for the whole loop) means the lock is
            // released at least every `SHUTDOWN_POLL_INTERVAL` even on a
            // quiet network - dropping the losing side of a `select!`
            // cancels that future cleanly (the mpsc receiver inside
            // `poll_event` isn't holding anything that needs graceful
            // unwind), so this never loses an in-flight event. Without this,
            // `control.rs`'s handler - which locks this same mutex to serve
            // one request - would wait for a lock this loop never released.
            let event = if let Some(network) = &self.network {
                let mut network = network.lock().await;
                tokio::select! {
                    event = network.poll_event() => event,
                    _ = tokio::time::sleep(SHUTDOWN_POLL_INTERVAL) => None,
                }
            } else {
                tokio::time::sleep(SHUTDOWN_POLL_INTERVAL).await;
                None
            };

            if let Some(event) = event {
                self.handle_network_event(event).await?;
            }
        }

        Ok(())
    }

    /// Handle a network event
    async fn handle_network_event(&mut self, event: NetworkEvent) -> Result<()> {
        match event {
            NetworkEvent::PeerConnected(peer_id) => {
                info!("Peer connected: {}", hex::encode(peer_id.as_bytes()));
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                info!("Peer disconnected: {}", hex::encode(peer_id.as_bytes()));
            }
            NetworkEvent::PeerDiscovered { node_id, addr, timestamp } => {
                info!("Discovered link-local peer {} at {}", hex::encode(node_id.as_bytes()), addr);
                if let Some(network) = &self.network {
                    let mut network = network.lock().await;
                    network.register_peer(node_id, addr, timestamp);
                    // Cycle A demonstration: confirm real AXIOM Frame traffic
                    // (not just the HELLO liveness layer) works end to end by
                    // pinging every newly-discovered peer once. Non-blocking
                    // (Fable flagged the earlier inline-awaited version as a
                    // real problem once Cycle B adds more Frame traffic on
                    // this loop, not just a style preference) - a slow/dead
                    // peer can't stall processing of other events.
                    network.spawn_ping(node_id, addr);
                    // Cycle B: tell them what we can do too - without this,
                    // only the dialing side of a connect() ever announces
                    // (the answering side only registers/pings the dialer
                    // via this same event, it never told them about its own
                    // capabilities).
                    network.spawn_announce(addr);
                }
            }
            NetworkEvent::MessageReceived { from, data } => {
                debug!("Message from {}: {} bytes", hex::encode(from.as_bytes()), data.len());
                // Process through guardian if enabled
                if let Some(ref mut _guardian) = self.guardian {
                    // guardian.inspect(&data);
                }
                // Handle AXIOM protocol messages
                self.handle_message(from, data).await?;
            }
            NetworkEvent::Error(e) => {
                warn!("Network error: {}", e);
            }
        }
        Ok(())
    }

    /// Handle an incoming AXIOM message
    async fn handle_message(&mut self, from: NodeId, _data: Vec<u8>) -> Result<()> {
        // Decode and process AXIOM frame
        // This is where the protocol logic lives
        debug!("Processing message from {}", hex::encode(from.as_bytes()));
        Ok(())
    }

    /// Shutdown the node
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down Forge node...");
        self.running = false;
        self.shutdown_flag.store(true, Ordering::Relaxed);

        if let Some(network) = &self.network {
            network.lock().await.shutdown().await?;
        }

        if let Some(task) = self.wan_task.take() {
            task.abort();
        }

        info!("Forge node shut down");
        Ok(())
    }

    /// Get the node ID
    #[allow(dead_code)]
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Check if node is running
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running
    }
}

/// RAII guard for one peer's slot in the per-peer WAN connection cap (see
/// `WAN_MAX_CONNECTIONS_PER_PEER`). Decrements on drop regardless of which
/// exit path ends the session - mirrors the connection semaphore's own
/// `_permit` pattern.
struct PeerConnectionGuard {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<NodeId, usize>>>,
    peer: NodeId,
}

impl Drop for PeerConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(count) = counts.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

fn try_acquire_peer_slot(
    counts: &Arc<std::sync::Mutex<std::collections::HashMap<NodeId, usize>>>,
    peer: NodeId,
) -> Option<PeerConnectionGuard> {
    let mut map = counts.lock().unwrap();
    let count = map.entry(peer).or_insert(0);
    if *count >= WAN_MAX_CONNECTIONS_PER_PEER {
        return None;
    }
    *count += 1;
    Some(PeerConnectionGuard { counts: counts.clone(), peer })
}

/// AXIOM-11.1 WAN accept loop. Split accept()/handle_incoming() (see
/// `axiom_transport::wan` docs) is what makes the per-connection spawn
/// below actually work: `accept()` returns as soon as a connection attempt
/// is dequeued, WITHOUT waiting for its handshake, so this loop can spawn
/// that connection's handshake+allowlist+liveness handling onto its own
/// task and immediately go back to accepting the next one - a single
/// slow/wedged peer (bounded to 10s by `handle_incoming`'s own timeout,
/// but still 10s) can no longer stall every other connection behind it.
///
/// `Err` from `handle_incoming` (non-allowlisted peer, failed liveness,
/// timeout) is logged and dropped - it is per-connection, never fatal to
/// this loop. `None` from `accept()` means the endpoint itself closed,
/// which ends the loop.
async fn wan_accept_loop(
    endpoint: Arc<WanEndpoint>,
    semaphore: Arc<tokio::sync::Semaphore>,
    dispatch_ctx: DispatchContext,
    peer_connections: Arc<std::sync::Mutex<std::collections::HashMap<NodeId, usize>>>,
) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            info!("WAN endpoint closed, accept loop exiting");
            return;
        };

        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            // warn!, not debug! - an operator under a connection-flood
            // attempt needs this visible at default log level, not opt-in.
            // remote_addr() is available pre-handshake (Fable review).
            warn!(
                "WAN connection rejected (from {:?}): at concurrent-connection cap ({})",
                incoming.remote_addr(), WAN_MAX_CONCURRENT_CONNECTIONS
            );
            // Explicit refuse(), not a bare drop - sends a clean QUIC
            // CONNECTION_REFUSED rather than relying on Incoming's Drop
            // impl to do the right thing implicitly (Fable review).
            incoming.refuse();
            continue;
        };

        let endpoint = endpoint.clone();
        let dispatch_ctx = dispatch_ctx.clone();
        let peer_connections = peer_connections.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the connection's ENTIRE handling lifetime, including the capability session below - not just handshake+liveness
            // Fable review (Cycle 1): wrap the WHOLE call, not just rely on
            // handle_incoming's own internal liveness-exchange timeout -
            // the handshake step (incoming.await, inside handle_incoming,
            // BEFORE the allowlist check) has no bound of its own, so an
            // unauthenticated peer could otherwise hold this permit for
            // iroh's ~30s transport idle timeout. See
            // WAN_INBOUND_TOTAL_TIMEOUT's doc. Deliberately does NOT wrap
            // the capability session below - a real, ongoing session is
            // supposed to last longer than 15s; wan_capability_session has
            // its own idle timeout instead (WAN_SESSION_IDLE_TIMEOUT).
            match tokio::time::timeout(WAN_INBOUND_TOTAL_TIMEOUT, endpoint.handle_incoming(incoming)).await {
                Ok(Ok((conn, peer))) => {
                    info!("WAN peer liveness verified: {}", hex::encode(peer.as_bytes()));
                    // Fable Cycle 2B diff review, required fix: the global
                    // WAN_MAX_CONCURRENT_CONNECTIONS pool alone no longer
                    // bounds a single peer once sessions are long-lived
                    // (Gap B) rather than dying within ~15s (Cycle 2A) - see
                    // WAN_MAX_CONNECTIONS_PER_PEER's doc.
                    let Some(_peer_slot) = try_acquire_peer_slot(&peer_connections, peer) else {
                        warn!(
                            "WAN connection from {} rejected: at per-peer connection cap ({})",
                            hex::encode(peer.as_bytes()), WAN_MAX_CONNECTIONS_PER_PEER
                        );
                        conn.close(1u32.into(), b"per-peer connection limit");
                        return;
                    };
                    // Gap B (AXIOM-11.2): capability dispatch over this
                    // connection - serialized per-connection (one request
                    // completes before the next accept_bi), matching
                    // dispatch_intent's single-await shape under Fable's
                    // review. Ends on idle timeout, peer disconnect, or a
                    // protocol violation (channel-binding mismatch, wrong
                    // frame type) - all logged, none fatal to the accept
                    // loop, which never sees this task at all. `_peer_slot`
                    // is held for the session's whole lifetime, releasing
                    // this peer's slot on drop regardless of which of
                    // wan_capability_session's several return points ends it.
                    wan_capability_session(conn, peer, dispatch_ctx).await;
                }
                Ok(Err(e)) => {
                    // A non-allowlisted peer is a security-relevant event
                    // (someone with no claim to be here reached the
                    // handshake stage), not routine debug noise - other
                    // failure modes (bad liveness reply, exchange timeout)
                    // stay at debug.
                    if matches!(e, axiom_transport::wan::WanError::NotAllowlisted(_)) {
                        warn!("WAN connection rejected: {e}");
                    } else {
                        debug!("WAN inbound connection did not complete liveness: {e}");
                    }
                }
                Err(_) => {
                    warn!(
                        "WAN inbound connection exceeded {:?} total (handshake+liveness) - dropped",
                        WAN_INBOUND_TOTAL_TIMEOUT
                    );
                }
            }
        });
    }
}

/// Gap B (AXIOM-11.2): serve Intent requests over one liveness-verified WAN
/// connection until it goes idle, the peer disconnects, or it commits a
/// protocol violation. `peer` is the QUIC-authenticated NodeId from
/// `handle_incoming` - the ONLY source of truth for who's on the other end
/// of `conn`, which is why every frame read off it is checked against
/// `peer` before dispatch (see the channel-binding check below). Requests
/// are handled ONE AT A TIME (await each to completion before the next
/// `accept_bi`) - `dispatch_intent` is already a single sequential await
/// under Fable's Cycle 2B review, so this is the natural shape, and it
/// gives free per-peer serialization with no unbounded task growth for a
/// long-lived session.
// pub(crate), not private: the `wan-intent` CLI subcommand's own tests
// (forge-node/src/main.rs's `main_tests` module) need to spin up a real
// server side of this exact exchange against a loopback WAN pair, the same
// way this module's own `wan_capability_tests` does - see main.rs for the
// client-side counterpart this drives (`send_wan_intent_request`, itself
// modeled on `wan_capability_tests::send_intent_request` below).
pub(crate) async fn wan_capability_session(conn: iroh::endpoint::Connection, peer: NodeId, ctx: DispatchContext) {
    loop {
        let (send, recv) = match tokio::time::timeout(WAN_SESSION_IDLE_TIMEOUT, conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                debug!("WAN session with {} ended: {e}", hex::encode(peer.as_bytes()));
                return;
            }
            Err(_) => {
                debug!(
                    "WAN session with {} idle for {:?}, closing",
                    hex::encode(peer.as_bytes()), WAN_SESSION_IDLE_TIMEOUT
                );
                conn.close(0u32.into(), b"idle timeout");
                return;
            }
        };

        // Fable Cycle 2B diff review, required fix: WAN_SESSION_IDLE_TIMEOUT
        // above only covers accept_bi() - everything after a stream is
        // accepted (read, dispatch, write, the reply's stopped() ack) was
        // previously unbounded. A peer could open a stream (which itself
        // resets the idle timer) then simply never finish writing, or
        // withhold flow-control credit on the reply, hanging this task -
        // and its connection-semaphore + per-peer-slot permits - forever,
        // silently. Wrapping the whole per-request span closes that gap.
        match tokio::time::timeout(WAN_REQUEST_TIMEOUT, handle_one_wan_request(send, recv, peer, &ctx)).await {
            Ok(WanRequestOutcome::Continue) => continue,
            Ok(WanRequestOutcome::CloseConnection { code, reason }) => {
                conn.close(code.into(), reason);
                return;
            }
            Err(_) => {
                warn!(
                    "WAN request from {} exceeded {:?} - closing connection",
                    hex::encode(peer.as_bytes()), WAN_REQUEST_TIMEOUT
                );
                conn.close(1u32.into(), b"request timeout");
                return;
            }
        }
    }
}

/// What `handle_one_wan_request` decided should happen next - kept
/// separate from `wan_capability_session`'s loop so the whole per-request
/// body can be wrapped in a single `tokio::time::timeout` (see
/// `WAN_REQUEST_TIMEOUT`) without threading `continue`/`return` control
/// flow through a timeout boundary.
enum WanRequestOutcome {
    Continue,
    CloseConnection { code: u32, reason: &'static [u8] },
}

/// One request/reply cycle on an already-accepted WAN stream: read, decode
/// + verify, channel-bind, dispatch, reply. See `wan_capability_session`
/// for the channel-binding rationale (unchanged, just relocated here so it
/// can be timeout-wrapped as a unit).
async fn handle_one_wan_request(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    peer: NodeId,
    ctx: &DispatchContext,
) -> WanRequestOutcome {
    let bytes = match recv.read_to_end(WAN_MAX_FRAME_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            debug!("WAN request read failed from {}: {e}", hex::encode(peer.as_bytes()));
            return WanRequestOutcome::Continue; // this stream's dead; the connection/session isn't
        }
    };

    let Some(frame) = decode_verified_frame(&bytes) else {
        // A frame that fails signature verification on an already-
        // liveness-verified, allowlisted connection is not routine
        // noise - close the whole connection, not just this stream.
        warn!(
            "WAN request from {} failed signature verification - closing connection",
            hex::encode(peer.as_bytes())
        );
        return WanRequestOutcome::CloseConnection { code: 1, reason: b"bad frame signature" };
    };

    // CHANNEL BINDING (Fable Cycle 2B review, the blocker-class
    // requirement): decode_verified_frame only proves the frame was
    // signed by WHOEVER frame.header.sender_id claims to be - it does
    // NOT prove that's who's actually connected on `conn`. Without
    // this check, any allowlisted peer could relay a frame signed by a
    // completely different (possibly non-allowlisted) keypair and have
    // it dispatched under that third identity - bypassing the WAN
    // allowlist for the effective requester. Checked structurally,
    // before ANY frame_type-specific handling, so no future frame type
    // added here can accidentally skip it. A mismatch closes the
    // CONNECTION (not just the stream) and logs at warn! - this is
    // only ever reachable by a buggy or malicious already-allowlisted
    // peer attempting relay, a security event, not per-request noise.
    if frame.header.sender_id != peer {
        warn!(
            "WAN channel-binding mismatch: connection authenticated as {} but frame claims sender {} - closing connection (relay attempt?)",
            hex::encode(peer.as_bytes()), hex::encode(frame.header.sender_id.as_bytes())
        );
        return WanRequestOutcome::CloseConnection { code: 1, reason: b"sender/channel mismatch" };
    }

    // WAN request streams only ever carry Intent - routing a Ping/
    // Announce/Fulfill/Error frame through dispatch_intent would be a
    // protocol violation, not something to guess at. Never falls
    // through to handle_axiom_frame (LAN-only: UDP addr, known_peers,
    // socket.send_to - none of it applies here).
    if frame.header.frame_type != FrameType::Intent {
        warn!(
            "WAN stream from {} carried non-Intent frame type {:?} - closing connection",
            hex::encode(peer.as_bytes()), frame.header.frame_type
        );
        return WanRequestOutcome::CloseConnection { code: 1, reason: b"unexpected frame type" };
    }

    let Some(trace_id) = frame.trace_id else {
        debug!("Dropping WAN Intent with no trace_id from {}", hex::encode(peer.as_bytes()));
        return WanRequestOutcome::Continue;
    };

    let reply = dispatch_intent(ctx, frame.header.intent_hash, trace_id, frame.payload.clone(), frame.header.sender_id, DispatchOrigin::Wan, None).await;
    if reply.is_empty() {
        warn!("Failed to build WAN Intent reply for {} (sign/encode error, see logs)", hex::encode(peer.as_bytes()));
        return WanRequestOutcome::Continue;
    }
    if reply.len() > WAN_MAX_FRAME_BYTES {
        warn!("WAN Intent reply for {} exceeds {} bytes, not sending", hex::encode(peer.as_bytes()), WAN_MAX_FRAME_BYTES);
        return WanRequestOutcome::Continue;
    }
    if let Err(e) = send.write_all(&reply).await {
        debug!("WAN reply write failed to {}: {e}", hex::encode(peer.as_bytes()));
        return WanRequestOutcome::Continue;
    }
    if let Err(e) = send.finish() {
        debug!("WAN reply stream finish failed for {}: {e}", hex::encode(peer.as_bytes()));
        return WanRequestOutcome::Continue;
    }
    // Same reasoning as the liveness pong path (axiom_transport::wan) -
    // wait for the peer to actually ack the reply before moving on to
    // the next request, rather than racing a `finish()`-then-forget
    // against whatever the caller does next.
    let _ = send.stopped().await;
    WanRequestOutcome::Continue
}

/// Network events
#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnected(NodeId),
    PeerDisconnected(NodeId),
    /// Peer found via IPv6 link-local multicast, not yet in the peer map.
    /// `timestamp` is the HELLO's signed unix-seconds field, used by
    /// `register_peer` to reject replayed/stale frames.
    PeerDiscovered { node_id: NodeId, addr: SocketAddr, timestamp: u64 },
    MessageReceived { from: NodeId, data: Vec<u8> },
    Error(String),
}

#[cfg(test)]
mod wan_capability_tests {
    use super::*;
    use axiom_transport::wan::{WanAllowlist, WanEndpoint};
    use crate::network::{build_intent_frame, decode_verified_frame, next_trace_id};
    use axiom_gateway::CapabilityPolicy;
    use std::collections::HashSet;

    fn test_capabilities() -> Arc<Vec<String>> {
        Arc::new(vec!["echo".to_string(), "sysinfo".to_string(), "network_clients".to_string()])
    }

    /// AXIOM Phase 1.1: `allowed_peers` is applied uniformly across all
    /// three test capabilities (echo/sysinfo/network_clients) via
    /// `CapabilityPolicy::for_test` - the policy is now the SOLE
    /// authorization mechanism `dispatch_intent` consults (see
    /// `axiom_gateway::policy`'s module doc comment), so a WAN test that wants
    /// e.g. an `echo` request to actually succeed must list the requesting
    /// peer here now, not rely on a completed liveness exchange alone.
    fn test_dispatch_context(identity: Keypair, allowed_peers: HashSet<NodeId>) -> DispatchContext {
        DispatchContext {
            identity,
            local_capabilities: test_capabilities(),
            uai_config: Arc::new(None),
            notify_topic: Arc::new(None),
            policy: Arc::new(CapabilityPolicy::for_test(&["echo", "sysinfo", "network_clients"], allowed_peers)),
            tier2_flow: None,
            audit_log: None,
        }
    }

    /// Bind two relay-disabled endpoints and connect A -> B, returning B's
    /// side already through handle_incoming (liveness verified) so tests
    /// can go straight to exercising `wan_capability_session`/dispatch.
    ///
    /// Returns the `WanEndpoint`s too, not just the `Connection`s - a
    /// `Connection` needs its parent endpoint's driver task alive to
    /// process any FURTHER stream activity (the endpoint owns the socket
    /// and the background task that actually pumps QUIC state forward).
    /// Dropping `ep_a`/`ep_b` at the end of this function (as an earlier
    /// version of this helper did, returning only the Connections) let the
    /// liveness exchange complete fine but killed the connection before a
    /// SECOND round of streams (the capability request/reply) could ever
    /// happen - same bug class as AXIOM-11's original premature-endpoint-
    /// drop bug, one level up. Callers must hold the returned endpoints for
    /// the test's whole duration, not just destructure and discard them.
    async fn connected_pair(kp_a: Keypair, kp_b: Keypair) -> (
        Arc<WanEndpoint>, // A's endpoint - keep alive for the whole test
        Arc<WanEndpoint>, // B's endpoint - keep alive for the whole test
        iroh::endpoint::Connection, // A's view of the connection
        iroh::endpoint::Connection, // B's view of the connection
        NodeId, // B's NodeId (what A dialed)
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

    /// Client-side counterpart to `wan_capability_session` - open a bidi
    /// stream, send a signed Intent frame, read+verify the reply. Mirrors
    /// the server's channel-binding check (Fable Cycle 2B review, point 3):
    /// the reply's sender_id must be the peer actually connected to, and
    /// its trace_id must echo the request.
    async fn send_intent_request(
        conn: &iroh::endpoint::Connection,
        identity: &Keypair,
        expected_peer: NodeId,
        capability: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let intent_hash = AiIntent::from_str(capability).hash;
        let trace_id = next_trace_id();
        let request = build_intent_frame(identity, intent_hash, trace_id, payload, None);

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        send.write_all(&request).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let _ = send.stopped().await;

        let reply_bytes = recv.read_to_end(WAN_MAX_FRAME_BYTES).await.map_err(|e| e.to_string())?;
        let reply = decode_verified_frame(&reply_bytes).ok_or("reply signature verification failed")?;
        if reply.header.sender_id != expected_peer {
            return Err(format!(
                "reply sender {} != expected peer {}",
                hex::encode(reply.header.sender_id.as_bytes()),
                hex::encode(expected_peer.as_bytes())
            ));
        }
        if reply.trace_id != Some(trace_id) {
            return Err("reply trace_id does not match request".into());
        }
        match reply.header.frame_type {
            FrameType::Fulfill => Ok(reply.payload),
            FrameType::Error => Err(format!("Error reply: {}", String::from_utf8_lossy(&reply.payload))),
            other => Err(format!("unexpected reply frame type: {other:?}")),
        }
    }

    #[tokio::test]
    async fn echo_round_trip_over_wan() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        // AXIOM Phase 1.1: echo now requires an explicit policy allowlist
        // entry too, not just a liveness-verified WAN connection - A must
        // be named here for the request below to succeed.
        let mut allowed = HashSet::new();
        allowed.insert(kp_a.node_id());
        let ctx_b = test_dispatch_context(kp_b, allowed);
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        let reply = send_intent_request(&conn_a, &kp_a, b_node_id, "echo", b"hello wan".to_vec())
            .await
            .expect("echo request");
        assert_eq!(reply, b"hello wan");
    }

    /// THE test proving the blocker-class channel-binding requirement:
    /// a frame signed by a keypair that is NOT the connection's
    /// QUIC-authenticated peer must be rejected, even though the frame's
    /// OWN signature is perfectly valid (it really was signed by kp_c) -
    /// decode_verified_frame alone would accept it; only the explicit
    /// sender_id == peer check in wan_capability_session catches this.
    #[tokio::test]
    async fn channel_binding_rejects_frame_signed_by_third_party() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate(); // not on B's allowlist, not connected to B at all
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        // A is allowed (policy-wise) so the legitimate follow-up request at
        // the end of this test would succeed if the connection were still
        // alive - its failure is then unambiguously attributable to the
        // channel-binding mismatch tearing down the connection, not to A
        // simply not being on the allowlist.
        let mut allowed = HashSet::new();
        allowed.insert(kp_a.node_id());
        let ctx_b = test_dispatch_context(kp_b, allowed);
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        // Deliberately bypass send_intent_request's identity == connection-
        // owner assumption: build a validly-signed Intent frame as kp_c,
        // send it over A's (allowlisted, liveness-verified) connection to B.
        let intent_hash = AiIntent::from_str("echo").hash;
        let trace_id = next_trace_id();
        let forged_request = build_intent_frame(&kp_c, intent_hash, trace_id, b"relayed".to_vec(), None);

        let (mut send, mut recv) = conn_a.open_bi().await.expect("open stream");
        send.write_all(&forged_request).await.expect("write forged frame");
        let _ = send.finish();

        // B must close the connection without ever sending a Fulfill/Error
        // reply for this - a bare read error/EOF is the expected outcome,
        // not a successfully decoded reply of any kind.
        let result = recv.read_to_end(WAN_MAX_FRAME_BYTES).await;
        match result {
            Ok(bytes) => {
                let decoded = decode_verified_frame(&bytes);
                assert!(
                    decoded.is_none() || decoded.unwrap().header.frame_type != FrameType::Fulfill,
                    "channel-binding bypass: relayed third-party frame got dispatched and Fulfilled"
                );
            }
            Err(_) => {} // expected: connection closed before any reply
        }

        // Fable Cycle 2B diff review (recommended tightening): the read
        // failure/decode-mismatch above alone would ALSO happen on any
        // unrelated infrastructure failure (task panic, connection drop
        // bug) - it would pass vacuously if the channel-binding check were
        // silently deleted from the source and something else coincidentally
        // also caused a read error. Prove the CONNECTION (not just the
        // forged stream) was actually torn down BECAUSE of the mismatch, by
        // attempting a legitimate follow-up request on the same connection
        // and confirming it fails too - a connection deleted the check
        // would still be alive and would answer this one normally.
        let followup = send_intent_request(&conn_a, &kp_a, b_node_id, "echo", b"still alive?".to_vec()).await;
        assert!(
            followup.is_err(),
            "channel-binding mismatch should have closed the whole connection, but a legitimate follow-up request on it still succeeded"
        );
    }

    /// `network_clients` must be denied for WAN origin even when the
    /// requester IS on the capability policy's `network_clients` allowlist
    /// - proves the origin gate is a hard deny, not something the policy
    /// allowlist can override for a WAN requester.
    ///
    /// AXIOM Phase 1.4: as of the credential-scope finding in SECURITY.md,
    /// `network_clients` is hard-denied unconditionally (every origin, not
    /// just WAN) - so this test's assertion now checks for that broader
    /// Phase 1.4 message rather than the origin-specific "not authorized
    /// for this capability" text a plain policy/origin miss produces. The
    /// test's own intent (WAN can't reach this capability via the policy
    /// allowlist) still holds; it's just no longer the ONLY reason a WAN
    /// requester is denied. See `network::policy_dispatch_tests::network_clients_hard_denied_even_when_allowlisted_and_uai_configured`
    /// for the dedicated Phase 1.4 gate test (LAN origin, since that's the
    /// stronger claim: even a LAN peer that would pass every other check
    /// still gets denied).
    #[tokio::test]
    async fn network_clients_denied_over_wan_even_if_allowlisted() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let (_ep_a, _ep_b, conn_a, conn_b, b_node_id) = connected_pair(kp_a.clone(), kp_b.clone()).await;

        let mut nc_allowed = HashSet::new();
        nc_allowed.insert(kp_a.node_id()); // would be allowed on LAN
        let ctx_b = test_dispatch_context(kp_b, nc_allowed);
        tokio::spawn(wan_capability_session(conn_b, kp_a.node_id(), ctx_b));

        let result = send_intent_request(&conn_a, &kp_a, b_node_id, "network_clients", vec![]).await;
        let err = result.expect_err("network_clients over WAN must be denied, not fulfilled");
        assert!(
            err.contains("network_clients disabled pending a properly-scoped UAI credential"),
            "unexpected denial reason: {err}"
        );
    }
}

/// AXIOM Phase 1.2 (AXIOM-15): regression guard for the control-socket
/// deadlock class described in `ForgeNode::network`'s and
/// `control.rs::start`'s doc comments - an early control-socket
/// implementation routed requests through `ForgeNode`'s own outer lock,
/// which `run_event_loop` holds for the node's entire running lifetime by
/// design, so any control request hung forever. The fix gave
/// `NetworkManager` its own independent lock, re-acquired fresh every loop
/// iteration (see `run_event_loop`'s own comment on why it locks fresh each
/// iteration rather than once for the whole loop). This is a REAL
/// concurrency test, not a comment/structural proxy: it runs the actual
/// `run_event_loop` in its own task and races real lock acquisitions
/// against it, the same way `control.rs`'s handler does, each bounded by a
/// timeout well under what an actual deadlock would look like.
#[cfg(test)]
mod lock_discipline_tests {
    use super::*;

    #[tokio::test]
    async fn control_socket_style_lock_never_hangs_while_event_loop_runs() {
        let mut config = NodeConfig::default();
        config.listen_addr = "127.0.0.1:19901".parse().unwrap();
        config.api_addr = "127.0.0.1:19902".parse().unwrap();
        // No business binding real fe80 interfaces or an iroh WAN endpoint
        // for a test that's purely about lock discipline - same reasoning
        // `network.rs`'s `multihop_tests` module doc comment gives for
        // disabling link-local discovery in its own fixtures.
        config.enable_link_local_discovery = false;
        config.wan_enabled = false;
        config.bootstrap_nodes = Vec::new();

        let mut node = ForgeNode::new(config).await.expect("ForgeNode::new");
        node.start().await.expect("ForgeNode::start");
        let network = node.network_handle().expect("network handle must exist after start()");
        let shutdown = node.shutdown_signal();

        let loop_task = tokio::spawn(async move {
            let _ = node.run_event_loop().await;
        });

        // Same access pattern control.rs's handle_intent uses - lock the
        // SAME NetworkManager handle the running event loop holds each
        // iteration. If this ever regressed to the old outer-lock-for-the-
        // whole-lifetime shape, every one of these would hang until the
        // timeout, not just the first (which could pass by luck if it
        // happened to race a single iteration boundary).
        for attempt in 0..10 {
            let result = tokio::time::timeout(std::time::Duration::from_secs(2), network.lock()).await;
            assert!(
                result.is_ok(),
                "attempt {attempt}: control-socket-style lock acquisition hung while the event \
                 loop was running - the control-socket deadlock class has regressed"
            );
            drop(result.unwrap());
        }

        shutdown.store(true, Ordering::Relaxed);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), loop_task).await;
    }
}
