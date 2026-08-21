//! Local control socket for a running `start`-mode node.
//!
//! AXIOM-7's `intent` CLI subcommand is one-shot: it stands up its own
//! throwaway `NetworkManager`, connects, requests, and exits - reputation
//! state and peer registrations never persist across calls, and it can't
//! reach a real long-running node's own registry at all. There was no way
//! to ask an already-running `start` node to make a request on its own
//! behalf. This is deliberately NOT an HTTP API (no framework dependency
//! pulled in for one text command) - a Unix domain socket with a single
//! line-in, line-out request matches how the rest of this codebase favors
//! small hand-rolled protocols over frameworks (see the frame codec, the
//! base64/hex decoders in axiom-hal).
//!
//! Protocol: one line in, one line out, connection closes.
//!   `INTENT <capability> <payload>\n`  ->  `OK <peer_id_hex> <payload>\n` or `ERR <message>\n`
//! `payload` is the remainder of the line verbatim (may itself contain
//! spaces) - only `capability` is a bare whitespace-delimited token.
//!
//! AXIOM Phase 3.8: four more commands, all local-admin-only (this socket
//! is already restricted to 0600/0700-owning-user-only - see `start`'s own
//! doc comment below), none of them capability dispatch, none of them
//! reachable from `INTENT`:
//!   `FREEZE\n`             -> `OK frozen\n`
//!   `UNFREEZE\n`           -> `OK unfrozen\n`
//!   `SUSPEND <peer_hex>\n`   -> `OK suspended <peer_hex>\n` or `ERR <message>\n`
//!   `UNSUSPEND <peer_hex>\n` -> `OK unsuspended <peer_hex>\n` or `ERR <message>\n`
//!   `STATUS\n`             -> `OK frozen=<bool> suspended=<comma-separated hex, possibly empty>\n`
//! These mutate `axiom_gateway::CapabilityPolicy`'s kill-switch state via
//! `NetworkManager::policy()` - the SAME `Arc` `dispatch_intent` already
//! checks on every capability call, so the effect is immediate on the next
//! in-flight request boundary, no restart. See `axiom-gateway::policy`'s
//! own Phase 3.8 doc-comment section for the full design (why `SUSPEND`
//! denies every tier but `FREEZE` only Tier1+) and
//! `forge-node/src/capability_isolation.rs`'s
//! `capability_dispatch_has_zero_references_to_kill_switch_mutators_today`
//! test for the enforced proof these four commands are the ONLY way to
//! reach the kill switch's mutating methods - `network.rs`'s
//! `dispatch_intent` never calls them.
//!
//! Each kill-switch command also appends one entry to `AuditLog`, if this
//! node has one open (`start_node` in `main.rs` opens it best-effort at
//! `axiom_gateway::audit::default_path(data_dir)` and passes it through
//! here - see that function's doc comment for why a failure to open it is
//! non-fatal to node startup, matching this module's own "a node should
//! still run its core AXIOM duties without a control-plane convenience
//! feature" philosophy). If no audit log is open, the kill-switch action
//! still takes effect - a missing/corrupt audit log must never make the
//! kill switch itself inoperable - but a warning is logged locally
//! (`tracing::warn!`, not the audit log) so the gap is visible to whoever
//! is watching this node's own logs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::network::NetworkManager;

/// Default control socket path for a node's `data_dir` (Unix). See the
/// `#[cfg(windows)]` sibling below for the named-pipe equivalent - Windows
/// has no filesystem-rooted socket to place under `data_dir` at all, so
/// that version derives a pipe name instead of returning a real path.
#[cfg(unix)]
pub fn default_path(data_dir: &Path) -> PathBuf {
    data_dir.join("control.sock")
}

/// Windows analog of the Unix `default_path` above. Named pipes live in a
/// flat `\\.\pipe\` namespace, not the filesystem - there is no real "path
/// under data_dir" to return - so this derives a pipe name deterministic in
/// `data_dir` instead (every non-alphanumeric byte replaced with `_`), so
/// two nodes on the same machine with different `data_dir`s still get
/// distinct pipes, matching the Unix version's per-data-dir uniqueness.
/// The `PathBuf` return type is kept identical to the Unix signature purely
/// so `main.rs`'s `--socket` CLI flag and its default-resolution call site
/// don't need platform-specific plumbing - the string it holds is a pipe
/// name, not a filesystem path, on this platform.
#[cfg(windows)]
pub fn default_path(data_dir: &Path) -> PathBuf {
    let sanitized: String = data_dir
        .display()
        .to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    PathBuf::from(format!(r"\\.\pipe\forge-node-control-{sanitized}"))
}

/// Neither Unix domain sockets nor (obviously) Win32 named pipes exist on
/// whatever this is. Matches this module's own non-fatal philosophy for the
/// real implementations below (see this module's top-of-file doc comment) -
/// a node should still run its core AXIOM duties without a control surface
/// rather than fail startup over a convenience feature this platform can't
/// offer at all. In practice this crate is only ever built for `unix` or
/// `windows` targets - this arm is a safety net, not a real deployment
/// target.
#[cfg(not(any(unix, windows)))]
pub fn start(
    socket_path: PathBuf,
    _network: Arc<Mutex<NetworkManager>>,
    _audit_log: Option<Arc<axiom_gateway::AuditLog>>,
) {
    tracing::warn!(
        "Control socket ({}) not supported on this platform - skipping",
        socket_path.display()
    );
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
// Shared by both platform `start()` implementations and by `handle_connection`
// (and its own helpers) below - the wire protocol is identical on both
// platforms, so it's implemented ONCE, generic over any `AsyncRead + AsyncWrite`
// stream, rather than duplicated per-platform. `UnixStream` and `NamedPipeServer`
// both satisfy that bound.
#[cfg(any(unix, windows))]
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(any(unix, windows))]
use tracing::{info, warn, debug};

/// Start the control socket, spawned as its own task. Non-fatal if the
/// socket can't be bound (stale file, permissions) - a node should still run
/// its core AXIOM duties without a control surface rather than fail startup
/// over a convenience feature.
///
/// Takes `NetworkManager`'s own handle directly (`ForgeNode::network_handle`),
/// NOT `ForgeNode`'s outer lock - `run_event_loop` holds that outer lock for
/// the node's entire running lifetime (see `ForgeNode`'s own doc comments),
/// so a handler that needed it would deadlock forever the moment the node
/// started running. This handle is `NetworkManager`'s own independent lock,
/// released briefly between operations by both the event loop and this
/// socket, so a control request only ever waits a bounded amount, never
/// permanently.
#[cfg(unix)]
pub fn start(
    socket_path: PathBuf,
    network: Arc<Mutex<NetworkManager>>,
    audit_log: Option<Arc<axiom_gateway::AuditLog>>,
) {
    tokio::spawn(async move {
        // AXIOM-14 Cycle 4 (Fable full-repo review finding #5): any local
        // user could otherwise drive this node's identity through the
        // control socket - unlike `node.key` (explicitly chmod'd 0600),
        // nothing here ever restricted who could connect, so a local user
        // could make signed requests under this node's own identity,
        // including `network_clients` if this node happens to be
        // allowlisted for it elsewhere - defeating that allowlist entirely.
        // Restricting the PARENT directory first, before `bind()` ever
        // creates the socket file, closes the race a plain post-bind
        // `chmod` on the socket alone would leave open (a window where the
        // file exists with default/umask permissions before its own
        // chmod runs) - directory permissions gate every path underneath
        // them from the moment they're set, regardless of ordering.
        if let Some(parent) = socket_path.parent() {
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)) {
                warn!("Control socket: failed to restrict {} to 0700: {}", parent.display(), e);
            }
        }

        // A stale socket file from an unclean previous shutdown makes bind()
        // fail with AddrInUse even though nothing is actually listening -
        // remove it first. Only ever a leftover file, never a live socket
        // another process still owns (this node's own data_dir).
        let _ = std::fs::remove_file(&socket_path);

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                warn!("Control socket: failed to bind {}: {}", socket_path.display(), e);
                return;
            }
        };
        // Defense in depth alongside the directory restriction above - the
        // socket's own mode should reflect its actual sensitivity too, the
        // same reasoning `node.key` already gets 0600 for.
        if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
            warn!("Control socket: failed to restrict {} to 0600: {}", socket_path.display(), e);
        }
        info!("Control socket listening on {}", socket_path.display());

        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Control socket: accept failed: {}", e);
                    continue;
                }
            };

            let network = network.clone();
            let audit_log = audit_log.clone();
            tokio::spawn(async move {
                handle_connection(stream, network, audit_log).await;
            });
        }
    });
}

/// Windows named-pipe implementation of the control socket - see this
/// module's top-of-file doc comment for the wire protocol, which is
/// IDENTICAL on both platforms (`handle_connection` below is the SAME
/// function the Unix `start()` above calls - only how a connection is
/// accepted differs here, never what happens once one is).
///
/// Structurally different from the Unix `UnixListener` accept loop above
/// because Win32 named pipes have no equivalent of `accept()` handing back
/// a fresh, independent socket - instead each pipe "instance" IS the
/// connection, and a new instance must be created and listening BEFORE the
/// current one is handed off to its handler, or a client racing to connect
/// while this instance is being served gets `ERROR_PIPE_BUSY` instead of
/// queuing. This is tokio's own documented pattern for `NamedPipeServer`
/// (see its module docs' server-loop example), not invented here.
#[cfg(windows)]
pub fn start(
    socket_path: PathBuf,
    network: Arc<Mutex<NetworkManager>>,
    audit_log: Option<Arc<axiom_gateway::AuditLog>>,
) {
    let pipe_name = socket_path.to_string_lossy().into_owned();

    tokio::spawn(async move {
        // AXIOM-14 Cycle 4's restriction (see this module's top-of-file doc
        // comment) applies just as much to this pipe as it does to the Unix
        // socket above - an unrestricted named pipe is reachable by every
        // local user, not just this one, and would let any of them drive
        // this node's identity the same way an unrestricted Unix socket
        // would. `sd` grants access to the pipe's creator/owner, Local
        // System, and built-in Administrators only - see
        // `build_restrictive_security_descriptor`'s own doc comment.
        let sd = match build_restrictive_security_descriptor() {
            Ok(sd) => sd,
            Err(e) => {
                warn!(
                    "Control pipe: failed to build a restrictive security descriptor: {} - refusing to start an unrestricted control pipe",
                    e
                );
                return;
            }
        };

        let mut server = match create_pipe_instance(&pipe_name, &sd, true) {
            Ok(s) => s,
            Err(e) => {
                warn!("Control pipe: failed to create {}: {}", pipe_name, e);
                return;
            }
        };
        info!("Control pipe listening on {}", pipe_name);

        loop {
            if let Err(e) = server.connect().await {
                warn!("Control pipe: connect (accept) failed: {}", e);
                continue;
            }

            // Swap in a fresh instance BEFORE handing the connected one off
            // to its own task - see this fn's own doc comment for why the
            // ordering matters (a client connecting in the gap would
            // otherwise see ERROR_PIPE_BUSY for no real reason).
            let connected = server;
            server = match create_pipe_instance(&pipe_name, &sd, false) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Control pipe: failed to create the next instance of {}: {} - still serving the in-flight connection, but this pipe will stop accepting new ones until this node restarts",
                        pipe_name, e
                    );
                    handle_connection(connected, network.clone(), audit_log.clone()).await;
                    return;
                }
            };

            let network = network.clone();
            let audit_log = audit_log.clone();
            tokio::spawn(async move {
                handle_connection(connected, network, audit_log).await;
            });
        }
    });
}

/// Creates one named-pipe instance (`first` selects
/// `ServerOptions::first_pipe_instance`, required exactly once - the very
/// first instance of a given pipe name - and forbidden on every instance
/// after it, per `ServerOptions`'s own docs) with `sd`'s restrictive DACL
/// applied. Pulled out of `start` above since it's called twice: once for
/// the pipe's first instance, then again every time a connected instance is
/// handed off to its own task.
#[cfg(windows)]
fn create_pipe_instance(
    pipe_name: &str,
    sd: &SecurityDescriptorGuard,
    first: bool,
) -> std::io::Result<NamedPipeServer> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };

    // SAFETY: `sa` is a validly-initialized SECURITY_ATTRIBUTES pointing at
    // a real security descriptor built by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
    // (see `build_restrictive_security_descriptor`) and kept alive by the
    // caller (`sd` lives for this whole node's process lifetime, sitting in
    // `start`'s own async block above) - Win32's `CreateNamedPipeW`, which
    // tokio calls internally here, only reads through this pointer during
    // the call itself and never retains it afterward.
    unsafe {
        ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(pipe_name, &mut sa as *mut _ as *mut _)
    }
}

/// Owns the security-descriptor buffer `ConvertStringSecurityDescriptorToSecurityDescriptorW`
/// allocates (via `LocalAlloc` internally - that's the API's own documented
/// contract), freeing it with the matching `LocalFree` on drop. A raw
/// pointer to OS-owned memory isn't `Send` by default; this type is - it's
/// never mutated or read from Rust after construction, only handed back to
/// Win32 APIs by value, so sending it across the `tokio::spawn` boundary
/// (this node's control-pipe task) carries none of the real risks `Send`
/// normally guards against.
#[cfg(windows)]
struct SecurityDescriptorGuard(*mut core::ffi::c_void);

#[cfg(windows)]
unsafe impl Send for SecurityDescriptorGuard {}

#[cfg(windows)]
impl SecurityDescriptorGuard {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
            // (documented as `LocalAlloc`-backed) and is freed at most once -
            // `Drop` runs at most once per value, and `self.0` is only ever
            // set in `build_restrictive_security_descriptor` below.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0);
            }
        }
    }
}

/// Builds a Windows security descriptor restricting the control pipe to
/// this pipe's creator/owner, Local System, and built-in Administrators -
/// no ACE for any other trustee, so the DACL denies everyone else by
/// default (absence of an ACE for a trustee means no access, the same
/// "explicit allowlist, deny by omission" shape the Unix implementation's
/// 0700/0600 permissions above already have). Same underlying goal as
/// those permissions - see this module's top-of-file doc comment, AXIOM-14
/// Cycle 4 - a Windows named pipe just has no filesystem permission bits to
/// `chmod`, so the equivalent protection has to be expressed as an explicit
/// DACL at creation time instead.
///
/// SDDL: `D:` (a discretionary ACL follows) `(A;;GA;;;OW)` allow
/// GENERIC_ALL to OWNER (the identity that creates the pipe - this
/// process's own token, i.e. whichever user/service account forge-node
/// itself runs as), `(A;;GA;;;SY)` to LOCAL_SYSTEM, `(A;;GA;;;BA)` to
/// BUILTIN\Administrators (covers an elevated admin driving `control-intent`
/// over SSH, this project's actual deployment shape - see this file's
/// module doc comment's real-world context). Parsed via
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, the standard
/// Win32 way to build a security descriptor from SDDL rather than
/// hand-assembling ACL/ACE structs byte by byte.
#[cfg(windows)]
fn build_restrictive_security_descriptor() -> std::io::Result<SecurityDescriptorGuard> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    const SDDL: &str = "D:(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)";
    let wide: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();

    let mut psd: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the
    // duration of this call; `psd`/`null_mut()` are valid out-pointers per
    // this API's documented signature.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1 as u32,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SecurityDescriptorGuard(psd))
}

/// Shared connection handler for both platforms - see this module's
/// top-of-file doc comment for the exact wire protocol. Generic over any
/// `AsyncRead + AsyncWrite` stream (`UnixStream` on Unix, `NamedPipeServer`
/// on Windows) rather than duplicated per-platform, since the protocol
/// itself doesn't know or care which transport carried it. Uses the
/// generic `tokio::io::split` (a `Mutex`-guarded shared half-pair) rather
/// than `UnixStream`'s own zero-cost `into_split`, since `NamedPipeServer`
/// has no equivalent specialized split - one connection's one-line-in/
/// one-line-out exchange is far too short-lived for that difference to
/// matter.
#[cfg(any(unix, windows))]
async fn handle_connection<S>(
    stream: S,
    network: Arc<Mutex<NetworkManager>>,
    audit_log: Option<Arc<axiom_gateway::AuditLog>>,
) where
    S: AsyncRead + AsyncWrite,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let line = line.trim_end();

    // AXIOM Phase 3.8: `cmd`/`rest` split once, up front, so FREEZE/
    // UNFREEZE/STATUS (no argument) and SUSPEND/UNSUSPEND/INTENT (an
    // argument) can be matched uniformly - `line.split_once(' ')` alone
    // (the pre-3.8 shape) can't express "this command takes NO argument"
    // at all, only "this command's argument is everything after the first
    // space."
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next();

    let reply = match (cmd, rest) {
        ("INTENT", Some(rest)) => match rest.split_once(' ') {
            Some((capability, payload)) => handle_intent(&network, capability, payload).await,
            None => "ERR malformed INTENT command - expected: INTENT <capability> <payload>\n".to_string(),
        },
        ("INTENT", None) => "ERR malformed INTENT command - expected: INTENT <capability> <payload>\n".to_string(),
        ("FREEZE", None) => handle_freeze(&network, &audit_log, true).await,
        ("UNFREEZE", None) => handle_freeze(&network, &audit_log, false).await,
        ("SUSPEND", Some(peer_hex)) => handle_suspend(&network, &audit_log, peer_hex.trim(), true).await,
        ("UNSUSPEND", Some(peer_hex)) => handle_suspend(&network, &audit_log, peer_hex.trim(), false).await,
        ("STATUS", None) => handle_status(&network).await,
        _ => "ERR unknown command\n".to_string(),
    };

    let _ = write_half.write_all(reply.as_bytes()).await;
}

#[cfg(any(unix, windows))]
async fn handle_intent(network: &Arc<Mutex<NetworkManager>>, capability: &str, payload: &str) -> String {
    debug!("Control socket: INTENT {} {}", capability, payload);
    let mut network = network.lock().await;
    match network.request_intent(capability, payload.as_bytes().to_vec()).await {
        Ok((peer_id, result)) => format!(
            "OK {} {}\n",
            hex::encode(peer_id.as_bytes()),
            String::from_utf8_lossy(&result)
        ),
        Err(e) => format!("ERR {}\n", e),
    }
}

/// AXIOM Phase 3.8: best-effort audit-log append for one kill-switch
/// action. The kill-switch mutation itself has ALREADY happened by the
/// time this is called - a failure to log never unwinds or blocks it (see
/// this module's own top-of-file doc comment for why) - so this only ever
/// warns locally, never returns an error to the caller.
#[cfg(any(unix, windows))]
async fn log_kill_switch_event(audit_log: &Option<Arc<axiom_gateway::AuditLog>>, action: &str, detail: Option<String>) {
    match audit_log {
        Some(log) => {
            if let Err(e) = log.log_admin_event(action, detail, std::time::Duration::ZERO) {
                warn!("Control socket: failed to audit-log kill-switch event '{}': {}", action, e);
            }
        }
        None => warn!(
            "Control socket: kill-switch event '{}' NOT audit-logged - no audit log is open for this node",
            action
        ),
    }
}

/// AXIOM Phase 3.8: `FREEZE`/`UNFREEZE` - see this module's top-of-file
/// doc comment for the wire protocol and `axiom_gateway::policy`'s own
/// Phase 3.8 doc-comment section for what freezing actually does
/// (Tier1+ only, Tier0 and the audit log stay live).
#[cfg(any(unix, windows))]
async fn handle_freeze(network: &Arc<Mutex<NetworkManager>>, audit_log: &Option<Arc<axiom_gateway::AuditLog>>, freeze: bool) -> String {
    let policy = network.lock().await.policy();
    if freeze {
        policy.freeze();
        info!("Control socket: kill switch FREEZE issued - all Tier1+ capability execution suspended, Tier0 and the audit log are unaffected");
        log_kill_switch_event(audit_log, "kill_switch_freeze", Some("all Tier1+ capability execution frozen; Tier0 and audit log unaffected".to_string())).await;
        "OK frozen\n".to_string()
    } else {
        policy.unfreeze();
        info!("Control socket: kill switch UNFREEZE issued - Tier1+ capability execution resumed");
        log_kill_switch_event(audit_log, "kill_switch_unfreeze", Some("Tier1+ capability execution resumed".to_string())).await;
        "OK unfrozen\n".to_string()
    }
}

/// AXIOM Phase 3.8: `SUSPEND <peer_hex>`/`UNSUSPEND <peer_hex>` - see this
/// module's top-of-file doc comment for the wire protocol.
#[cfg(any(unix, windows))]
async fn handle_suspend(
    network: &Arc<Mutex<NetworkManager>>,
    audit_log: &Option<Arc<axiom_gateway::AuditLog>>,
    peer_hex: &str,
    suspend: bool,
) -> String {
    let bytes = match hex::decode(peer_hex) {
        Ok(b) => b,
        Err(_) => return format!("ERR '{}' is not valid hex\n", peer_hex),
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(v) => {
            let v: Vec<u8> = v;
            return format!("ERR peer id must be exactly 32 bytes (64 hex chars), got {}\n", v.len());
        }
    };
    let peer = axiom_types::crypto::NodeId::from_bytes(arr);

    let policy = network.lock().await.policy();
    if suspend {
        policy.suspend_peer(peer);
        info!("Control socket: kill switch SUSPEND issued for peer {}", peer_hex);
        log_kill_switch_event(audit_log, "kill_switch_suspend", Some(format!("peer {peer_hex}"))).await;
        format!("OK suspended {}\n", peer_hex)
    } else {
        let was_suspended = policy.unsuspend_peer(peer);
        info!("Control socket: kill switch UNSUSPEND issued for peer {} (was suspended: {})", peer_hex, was_suspended);
        log_kill_switch_event(audit_log, "kill_switch_unsuspend", Some(format!("peer {peer_hex}"))).await;
        format!("OK unsuspended {}\n", peer_hex)
    }
}

/// AXIOM Phase 3.8: `STATUS` - read-only kill-switch introspection, not
/// itself an "action" (nothing changes), so it is deliberately NOT
/// audit-logged - matches `axiom-gateway::audit`'s own "what gets logged"
/// contract of recording actions/decisions, not every read.
#[cfg(any(unix, windows))]
async fn handle_status(network: &Arc<Mutex<NetworkManager>>) -> String {
    let policy = network.lock().await.policy();
    let suspended = policy.suspended_peers().join(",");
    format!("OK frozen={} suspended={}\n", policy.is_frozen(), suspended)
}
