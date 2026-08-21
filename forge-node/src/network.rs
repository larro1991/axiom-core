//! Network management for Forge node

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::Duration;
use tracing::{info, debug, warn, error};

use axiom_types::NodeId;
use axiom_types::clock::HybridClock;
use axiom_types::intent::Constraint;
use axiom_types::crypto::{IntentHash, Signature, TraceId};
use axiom_types::frame::{Frame, FrameHeader, FrameType, RoutingExt};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;
use axiom_codec::{Decoder, Encoder};
use axiom_crypto::identity::{Keypair, Signer, Verifier};
use axiom_crypto::frame_sign::{FrameSigner, FrameVerifier};
use axiom_router::ai::Intent as AiIntent;
use axiom_router::announce::{AnnouncedCapability, AnnouncementManager, AnnouncePayload, MAX_ANNOUNCE_CLOCK_SKEW, MAX_ROUTE_INDIRECTION};
use axiom_router::semantic::{SemanticCapability, SemanticRouter};
use zeroize::Zeroizing;

use crate::config::NodeConfig;
use crate::discovery;
use crate::node::NetworkEvent;
use crate::telegram_approval::{TelegramApprovalChannel, TelegramApprovalState};

/// AXIOM Tier 2: the real (non-mock) `Tier2ApprovalFlow`, fixed to the
/// Telegram channel - see `telegram_approval`'s own module doc comment for
/// why that's a `forge-node`-local `ApprovalChannel` impl rather than
/// something added to `axiom-gateway` itself. A type alias, not a newtype -
/// nothing here needs to hide `Tier2ApprovalFlow<TelegramApprovalChannel>`'s
/// own API, this just saves repeating the generic parameter at every use
/// site (`DispatchContext`, `NetworkManager`, `dispatch_wg_peer_manage`).
pub(crate) type Tier2Flow = axiom_gateway::Tier2ApprovalFlow<TelegramApprovalChannel>;

/// Manages network connections and AXIOM protocol transport
pub struct NetworkManager {
    /// Our node identity
    identity: Keypair,

    /// UDP transport layer (bound to `config.listen_addr`, typically IPv4)
    socket: Arc<UdpSocket>,

    /// IPv6 link-local discovery socket, if any link-local interfaces were
    /// found at startup. Kept separate from `socket` because a socket bound
    /// to an IPv4 address cannot send/receive AF_INET6 traffic - discovered
    /// fe80 peers must be reached through this socket instead.
    discovery_socket: Option<Arc<UdpSocket>>,

    /// Connected peers
    peers: HashMap<NodeId, PeerConnection>,

    /// Outstanding `connect()` calls awaiting a HELLO_ACK from the addr they
    /// dialed, keyed by that addr. Shared with the background receive loop
    /// task (which fulfills these when a matching reply arrives) since only
    /// one task can ever be reading `socket.recv_from` at a time - `connect()`
    /// can't just read the reply itself without racing that loop for every
    /// other incoming datagram.
    pending_connects: Arc<Mutex<HashMap<SocketAddr, oneshot::Sender<(NodeId, u64)>>>>,

    /// Outstanding `ping()` calls awaiting a `Pong`, keyed by the `Ping`
    /// frame's `trace_id`. See `PendingPing` for why `sender_id` is checked
    /// too, not just the trace_id.
    pending_pings: Arc<Mutex<HashMap<TraceId, PendingPing>>>,

    /// NodeIds we've actually handshaken with (via `connect()` or discovery's
    /// `register_peer()`), shared with the background receive loop so it can
    /// answer a `Ping` only from a peer we actually know - a signature alone
    /// proves the sender holds *some* real keypair, not that we've agreed to
    /// talk to them. Without this check, any signed Ping (from literally
    /// anyone who can run this binary) gets a Pong reply for free - a small
    /// but real one-shot reflection surface with no cost to gate on.
    ///
    /// A plain `std::sync::Mutex`, not the tokio one `pending_connects`/
    /// `pending_pings` use - every access here is a quick insert/contains
    /// check, never held across an `.await`, so `register_peer` (called
    /// synchronously from the event loop) doesn't need to become `async`
    /// just to touch this.
    known_peers: Arc<std::sync::Mutex<HashSet<NodeId>>>,

    /// AXIOM-14 Cycle 1b: address of each direct peer, shared with the
    /// background receive loop for the SAME reason `known_peers` is - the
    /// full `peers: HashMap<NodeId, PeerConnection>` map below is main-
    /// event-loop-owned only, not reachable from the spawned receive task,
    /// and multi-hop forwarding needs to answer "is `destination` a direct
    /// peer of mine, and if so where do I send to it" from inside that task.
    /// Kept in sync with `known_peers` at the exact same call sites
    /// (`connect()`, `register_peer()`) rather than merging the two maps -
    /// a bigger refactor than this cycle's scope, noted as a possible
    /// future cleanup, not done here.
    peer_addrs: Arc<std::sync::Mutex<HashMap<NodeId, SocketAddr>>>,

    /// AXIOM-14 Cycle 1b: bounded dedup so the same frame arriving twice
    /// (e.g. a retransmit) isn't forwarded twice by this node. See
    /// `ForwardedFrameCache`.
    forwarded_frames: Arc<std::sync::Mutex<ForwardedFrameCache>>,

    /// Last time we *processed* an `Announce` naming each (immediate
    /// sender, origin) pair - AXIOM-4 (Cycle C), rekeyed for AXIOM-14
    /// Cycle 2b's gossip forwarding. Keying on sender ALONE would drop
    /// legitimate gossip fan-out (one relay forwarding many distinct
    /// origins' announcements back-to-back all count against the same
    /// bucket); keying on origin ALONE would let a relay bypass the limit
    /// by claiming a different origin each time while it's really the same
    /// relay hammering us. Bounded the same way as before: only ever
    /// grows from `known_peers`-gated traffic (bounded by `max_peers`)
    /// times however many distinct origins that peer legitimately relays,
    /// no separate size cap needed.
    last_announce_from: Arc<std::sync::Mutex<HashMap<(NodeId, NodeId), std::time::Instant>>>,

    /// Outstanding `request_intent()` calls awaiting a `Fulfill` (success) or
    /// `Error` (clean failure) reply, keyed by `trace_id`. Same sender_id-
    /// checked, consume-not-restore-on-mismatch design as `pending_pings`.
    pending_intents: Arc<Mutex<HashMap<TraceId, PendingIntent>>>,

    /// Capability name -> providing peer(s), populated from verified
    /// `Announce` frames after a handshake completes. Real, tested
    /// `axiom_router` component - this is the first thing in forge-node to
    /// actually use it. In-memory only, no persistence (AXIOM-2 Cycle B
    /// scope cut - see the plan doc).
    semantic_router: Arc<Mutex<SemanticRouter>>,

    /// Builds/dedupes our own capability announcements. Also real/tested
    /// `axiom_router` infrastructure - `create_announcement` already
    /// produces a ready-to-sign `Frame`.
    announcement_mgr: Arc<Mutex<AnnouncementManager>>,

    /// AXIOM-14 Cycle 2b: origin NodeId -> the direct peer that gossiped us
    /// its announcement, for origins that AREN'T themselves direct peers.
    /// Deliberately separate from `SemanticRouter` (which has no concept of
    /// "direct" vs "via relay" and shouldn't grow one just for this) and
    /// from `peer_addrs` (which is direct-peer-only by definition).
    /// `request_intent`'s fallback consults this when the winning
    /// `SemanticRouter` candidate isn't in `self.peers`. One relay per
    /// origin is sufficient at Cycle 2's one-hop-of-indirection scope -
    /// last-writer-wins on refresh. Purged whenever the relay itself stops
    /// being a known peer (see `register_peer`'s eviction path) - but
    /// that's a peer-churn trigger, not a staleness one, so as of Cycle 4
    /// the value also carries the `Instant` of the last accepted announce
    /// that touched this origin (refreshed on every touch, not just the
    /// first), and `run_announcement_maintenance` separately ages out
    /// entries nothing has refreshed in `ANNOUNCEMENT_MAX_AGE` - the
    /// second, previously-missing half of Cycle 3's "bound every growing
    /// map" pass (Fable's full-repo review, finding #3: this map and the
    /// `SemanticRouter` registrations it implies were the two Cycle 3
    /// missed - the LRU-eviction purge alone never fires on a small mesh,
    /// since nothing here ever detects a peer disconnect independent of
    /// `max_peers` pressure).
    reachable_via: Arc<std::sync::Mutex<HashMap<NodeId, (NodeId, std::time::Instant)>>>,

    /// AXIOM-14 Cycle 6: per-in-flight-request reverse-path breadcrumb -
    /// `trace_id -> (upstream_addr, last_touched)`, where `upstream_addr` is
    /// the address THIS node received a routed `Intent` FROM, recorded at
    /// the moment this node forwards that Intent onward (see
    /// `try_forward_routed_frame`). Lets a `Fulfill`/`Error` reply retrace
    /// the exact relay chain an Intent traveled, hop by hop, even when the
    /// ORIGINAL REQUESTER never appears in anyone's `reachable_via` at all -
    /// the normal case for a pure-consumer node (zero registered
    /// capabilities): `process_announcement` drops an announce with no
    /// capabilities outright (nothing ever marks `any_fresh`), so such a
    /// node is NEVER gossiped and NEVER earns a `reachable_via` entry
    /// anywhere, no matter how deep gossip's reach becomes. Without this,
    /// every multi-hop request from a pure-consumer node would time out
    /// looking exactly like a provider failure, and `request_intent`'s
    /// reputation feedback would then wrongly punish the innocent
    /// provider's score for it (Fable's plan review: the regression that
    /// would have shipped if `MAX_ROUTE_INDIRECTION`'s routing-reach
    /// increase and `reachable_via` consultation landed without this).
    /// Deliberately a time-bounded map, NOT a capacity-FIFO cache like
    /// `ForwardedFrameCache` - a capacity eviction under load could drop an
    /// in-flight route out from under a legitimately slow (but still within
    /// `INTENT_TIMEOUT`) round trip; `REVERSE_ROUTE_TTL` bounds it by time
    /// instead, pruned by `run_announcement_maintenance` the same way
    /// `reachable_via` is.
    reverse_routes: Arc<std::sync::Mutex<HashMap<TraceId, (SocketAddr, std::time::Instant)>>>,

    /// AXIOM-14 Cycle 3: per-sender window tracking how many DISTINCT
    /// origins that sender has introduced recently - see
    /// `MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW`'s doc comment for why
    /// this exists (the sender/origin pair-level rate limit above does
    /// nothing against a sender rotating fresh fabricated origins). Only
    /// ever grows to at most `known_peers`'s size (the gate on this arm
    /// already restricts it to that), purged on peer eviction the same as
    /// `reachable_via`.
    origin_admission: Arc<std::sync::Mutex<HashMap<NodeId, (std::time::Instant, HashSet<NodeId>)>>>,

    /// Capabilities this node offers (from `NodeConfig::capabilities`).
    /// `Arc` because it's read-only after construction and needs to reach
    /// the spawned receive loop for `Intent` dispatch.
    local_capabilities: Arc<Vec<String>>,

    /// AXIOM-10: UAI broker bridge for the `"network_clients"` capability.
    /// `None` if `NodeConfig::uai_base_url`/`uai_token` weren't both set -
    /// the capability then answers with a clear "not configured" Error
    /// instead of a confusing timeout or being silently unservable.
    ///
    /// Also the bridge `"notify_send"` uses (AXIOM notify_send) - the same
    /// `X-UAI-Token`/base URL, just a different `tool_name` on the same
    /// `/registry/dispatch` endpoint. Not split into a second config
    /// struct: both capabilities reach the same broker with the same
    /// credential, and `NodeConfig::notify_topic` (below) is the only
    /// piece that's notify_send-specific.
    uai_config: Arc<Option<UaiConfig>>,

    /// AXIOM notify_send: the ntfy topic this node's `"notify_send"`
    /// capability posts to. `None` (alongside `uai_config` being `None`,
    /// or independently of it) means notify_send answers "not configured"
    /// - see `dispatch_notify_send`. `Arc` for the same reason `uai_config`
    /// is: read-only after construction, needs to reach `DispatchContext`
    /// for both the LAN receive loop and WAN per-connection tasks.
    notify_topic: Arc<Option<String>>,

    /// AXIOM Phase 1.1: fail-closed, per-capability allowlist + rate limit
    /// + concurrency policy covering EVERY capability (`echo`, `sysinfo`,
    /// `network_clients`, and any future one), loaded once at startup from
    /// `NodeConfig::capability_policy_path`. Replaces the old
    /// `NetworkClientsGuard`/`network_clients_semaphore` pair (which only
    /// ever covered `network_clients`) and the `known_peers`-gates-
    /// `echo`/`sysinfo` model entirely - see `axiom_gateway::policy`'s
    /// module doc comment for the full contract.
    policy: Arc<axiom_gateway::CapabilityPolicy>,

    /// AXIOM Tier 2: the real propose/approve/execute flow, fixed to the
    /// Telegram approval channel - `None` unless BOTH
    /// `NodeConfig::telegram_bot_token`/`telegram_chat_id` are set (same
    /// "don't announce something that can't actually be served" rule
    /// `uai_config` follows). `wg_peer_manage` is the only capability that
    /// reads this today, but it's a `DispatchContext` field (not
    /// `wg_peer_manage`-specific plumbing) so any FUTURE real Tier 2
    /// capability gets the same machinery for free - see `DECISIONS.md`'s
    /// "Tier-2 approval channel" section on why that reuse is exactly the
    /// point of `ApprovalChannel` being a trait.
    tier2_flow: Option<Arc<Tier2Flow>>,

    /// AXIOM Tier 2: this node's hash-chained audit log (Phase 3.4),
    /// opened here (not passed in) so there is exactly ONE `AuditLog`
    /// handle per process for a given `data_dir` - see `main.rs::start_node`'s
    /// own doc comment on why a second independent `open()` of the same
    /// file would corrupt the hash chain. `None` if opening it failed (a
    /// node still runs its core AXIOM duties without this - same
    /// best-effort posture Phase 3.8's control-socket audit logging
    /// already established); `wg_peer_manage`'s background task logs a
    /// warning and proceeds WITHOUT an audit entry in that case, rather
    /// than blocking the underlying WireGuard action on logging succeeding.
    audit_log: Option<Arc<axiom_gateway::AuditLog>>,

    /// Event channel
    event_tx: mpsc::Sender<NetworkEvent>,
    event_rx: mpsc::Receiver<NetworkEvent>,

    /// Configuration
    #[allow(dead_code)]
    config: NetworkConfig,
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_addr: SocketAddr,
    pub max_peers: usize,
    pub mtu: usize,
}

/// AXIOM-10: how to reach the UAI broker that backs the `"network_clients"`
/// capability. Built once from `NodeConfig::uai_base_url`/`uai_token` (both
/// required, config.toml only - see their doc comments in config.rs for why
/// neither is ever a compiled-in default).
#[derive(Debug, Clone)]
pub(crate) struct UaiConfig {
    pub base_url: String,
    pub token: String,
}

/// An outstanding `ping()` call. Keyed by `trace_id` in `pending_pings`, but
/// a matching trace_id alone isn't authorization to fulfill it - `expected_sender`
/// is checked against the `Pong`'s verified `sender_id` too, so a different
/// peer that happens to guess/reuse a trace_id can't falsely resolve someone
/// else's ping. On a mismatch the entry is still consumed (removed) rather
/// than left for the real reply - the original `ping()` then times out
/// normally instead of either falsely succeeding or hanging on a lock. Real
/// RTT is measured by the caller (`ping()`), not stored here - the oneshot
/// just signals "a verified Pong from the right peer arrived."
pub(crate) struct PendingPing {
    expected_sender: NodeId,
    tx: oneshot::Sender<()>,
}

/// An outstanding `request_intent()` call. Same `expected_sender`-checked,
/// consume-not-restore-on-mismatch design as `PendingPing` - see its doc
/// comment for the reasoning. `Ok(payload)` on a verified `Fulfill`,
/// `Err(reason)` on a verified `Error` reply (from `frame.payload` as UTF-8,
/// lossy) - an `Error` reply wakes this waiter too, so "capability not
/// found" fails fast instead of degrading into the full timeout.
pub(crate) struct PendingIntent {
    expected_sender: NodeId,
    tx: oneshot::Sender<Result<Vec<u8>, String>>,
}

/// A connection to a peer
struct PeerConnection {
    node_id: NodeId,
    addr: SocketAddr,
    #[allow(dead_code)]
    established_at: std::time::Instant,
    #[allow(dead_code)]
    bytes_sent: u64,
    #[allow(dead_code)]
    bytes_received: u64,
    /// True for peers that arrived via link-local discovery rather than an
    /// explicit `connect()`/bootstrap call - only these are ever LRU-evicted
    /// under `max_peers` pressure, so a flood of disposable-keypair discovery
    /// spam can never push out a peer the human actually configured.
    discovered: bool,
    /// Signed timestamp (unix secs) from the last HELLO accepted for this
    /// peer. A new HELLO with a timestamp <= this is rejected as a replay -
    /// signature verification alone only proves the bytes were once signed
    /// by that key, not that they're fresh.
    last_hello_ts: u64,
    /// Wall-clock time this peer was last confirmed reachable - the LRU key
    /// for discovery-peer eviction (oldest last_seen goes first).
    last_seen: std::time::Instant,
}

impl NetworkManager {
    /// Create a new network manager
    pub async fn new(config: &NodeConfig, identity: Keypair) -> Result<Self> {
        info!("Binding to {}", config.listen_addr);

        let socket = UdpSocket::bind(config.listen_addr)
            .await
            .context("Failed to bind UDP socket")?;

        let socket = Arc::new(socket);

        let (event_tx, event_rx) = mpsc::channel(1000);

        let net_config = NetworkConfig {
            listen_addr: config.listen_addr,
            max_peers: config.max_peers,
            mtu: 1400,
        };

        let local_id = identity.node_id();

        // Built here (not inline in the `Self` literal below) so they can
        // also be handed to `discovery::start` - see the comment there for
        // why that matters.
        let pending_pings = Arc::new(Mutex::new(HashMap::new()));
        let known_peers = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let peer_addrs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let forwarded_frames = Arc::new(std::sync::Mutex::new(ForwardedFrameCache::new()));
        let last_announce_from = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let pending_intents = Arc::new(Mutex::new(HashMap::new()));
        let semantic_router = Arc::new(Mutex::new(SemanticRouter::new(local_id)));
        // AXIOM-14 Cycle 4: holds the full identity now, not just its
        // NodeId - see AnnouncementManager's `identity` field doc comment.
        let announcement_mgr = Arc::new(Mutex::new(AnnouncementManager::new(identity.clone())));
        let reachable_via = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let reverse_routes = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let origin_admission = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let local_capabilities = Arc::new(config.capabilities.clone());
        let uai_config = Arc::new(match (&config.uai_base_url, &config.uai_token) {
            (Some(base_url), Some(token)) => Some(UaiConfig { base_url: base_url.clone(), token: token.clone() }),
            _ => None,
        });
        // AXIOM notify_send: independent of uai_config's own presence -
        // `dispatch_notify_send` requires BOTH to be set (see its doc
        // comment) rather than folding this into UaiConfig itself, since
        // network_clients has no equivalent per-capability destination and
        // widening UaiConfig for one capability's sake would be a shared
        // struct carrying a field only half its users need.
        let notify_topic = Arc::new(config.notify_topic.clone());
        // AXIOM Phase 1.1: fail-closed for every capability, not just
        // network_clients - see axiom_gateway::policy's module doc comment for the
        // full contract. `load` never fails startup itself (a broken
        // policy file logs loudly and denies everything instead).
        let policy = Arc::new(axiom_gateway::CapabilityPolicy::load(&config.capability_policy_path));

        // AXIOM Tier 2: the Telegram approval channel + real Tier2ApprovalFlow,
        // built here (once, per node) exactly like uai_config above - `None`
        // unless BOTH telegram_bot_token/telegram_chat_id are configured, so
        // wg_peer_manage answers a clear "not configured" rather than a
        // confusing hang or panic. `telegram_chat_id` is validated as a real
        // i64 HERE, at startup, rather than deferred to the first request -
        // a malformed chat_id is a config error the operator should see
        // immediately in the startup logs, not silently on first use.
        let tier2_flow: Option<Arc<Tier2Flow>> = match (&config.telegram_bot_token, &config.telegram_chat_id) {
            (Some(token), Some(chat_id_str)) => match chat_id_str.trim().parse::<i64>() {
                Ok(chat_id) => match TelegramApprovalState::new(token.clone(), chat_id) {
                    Ok(state) => {
                        crate::telegram_approval::spawn_poller(state.clone());
                        let channel = TelegramApprovalChannel::new(state, tokio::runtime::Handle::current());
                        Some(Arc::new(axiom_gateway::Tier2ApprovalFlow::new(channel, policy.clone())))
                    }
                    Err(e) => {
                        warn!("Failed to build Telegram approval channel: {} - wg_peer_manage (and any future Tier 2 capability) will answer 'not configured'", e);
                        None
                    }
                },
                Err(e) => {
                    warn!(
                        "NodeConfig::telegram_chat_id ({:?}) is not a valid integer: {} - wg_peer_manage (and any future Tier 2 capability) will answer 'not configured'",
                        chat_id_str, e
                    );
                    None
                }
            },
            _ => None,
        };

        // AXIOM Tier 2: the audit log - see NetworkManager::audit_log's own
        // field doc comment for why this is opened HERE (exactly once per
        // process) rather than by main.rs independently.
        let audit_log_path = axiom_gateway::audit::default_path(&config.data_dir);
        let audit_log = match axiom_gateway::AuditLog::open(&audit_log_path) {
            Ok(log) => Some(Arc::new(log)),
            Err(e) => {
                warn!(
                    "Failed to open audit log at {}: {} - kill-switch admin actions and Tier 2 wg_peer_manage \
                     calls will still function, but will NOT be audit-logged until this is fixed",
                    audit_log_path.display(), e
                );
                None
            }
        };

        // Link-local discovery works alongside the configured listen_addr,
        // not instead of it - explicitly configured/bootstrap peers still go
        // through `connect()` below unchanged. Shares the same pending-
        // request maps/registry as the main receive loop below: a link-local
        // peer's Ping/Pong/Announce/Intent/Fulfill/Error traffic can ONLY
        // ever arrive on THIS socket (a socket bound to an IPv4 address
        // can't receive AF_INET6 traffic at all) - without threading these
        // through, `discovery::start`'s receive loop would keep doing
        // exactly what it used to: try to parse everything as a HELLO,
        // silently drop anything else, and every Ping/Announce to a
        // discovered peer would time out forever. This was the real,
        // previously-undiscovered gap every Cycle A/B/C test missed, because
        // all of that testing used `127.0.0.1` peers - never a link-local
        // address, so `is_link_local_v6` was always false and traffic
        // always went through the main socket's dispatch instead.
        let discovery_socket = if config.enable_link_local_discovery {
            discovery::start(
                identity.clone(),
                socket.clone(),
                event_tx.clone(),
                config.link_local_trusted_subnets.clone(),
                pending_pings.clone(),
                known_peers.clone(),
                peer_addrs.clone(),
                forwarded_frames.clone(),
                pending_intents.clone(),
                semantic_router.clone(),
                announcement_mgr.clone(),
                reachable_via.clone(),
                reverse_routes.clone(),
                origin_admission.clone(),
                local_capabilities.clone(),
                last_announce_from.clone(),
                uai_config.clone(),
                notify_topic.clone(),
                policy.clone(),
                tier2_flow.clone(),
                audit_log.clone(),
            ).await
        } else {
            None
        };

        let mut manager = Self {
            identity,
            socket,
            discovery_socket,
            peers: HashMap::new(),
            pending_connects: Arc::new(Mutex::new(HashMap::new())),
            pending_pings,
            known_peers,
            peer_addrs,
            forwarded_frames,
            last_announce_from,
            pending_intents,
            semantic_router,
            announcement_mgr,
            reachable_via,
            reverse_routes,
            origin_admission,
            local_capabilities,
            uai_config,
            notify_topic,
            policy,
            tier2_flow,
            audit_log,
            event_tx,
            event_rx,
            config: net_config,
        };

        // Register our own capabilities so `create_announcement` has
        // something to advertise. `category` is a placeholder (`*b"capa"`) -
        // Cycle B only matches capabilities by `intent_hash`, never by this
        // field; it exists on the wire format for a hierarchical-category
        // scheme this pass doesn't use.
        {
            let mut mgr = manager.announcement_mgr.lock().await;
            for cap in manager.local_capabilities.iter() {
                let intent_hash = AiIntent::from_str(cap).hash;
                mgr.register_capability(AnnouncedCapability::new(intent_hash, *b"capa"));
            }
        }

        // Start receive loop
        manager.start_receive_loop();

        Ok(manager)
    }

    /// Start the background receive loop
    fn start_receive_loop(&self) {
        let socket = self.socket.clone();
        let discovery_socket = self.discovery_socket.clone();
        let event_tx = self.event_tx.clone();
        let identity = self.identity.clone();
        let pending_connects = self.pending_connects.clone();
        let pending_pings = self.pending_pings.clone();
        let known_peers = self.known_peers.clone();
        let peer_addrs = self.peer_addrs.clone();
        let forwarded_frames = self.forwarded_frames.clone();
        let pending_intents = self.pending_intents.clone();
        let semantic_router = self.semantic_router.clone();
        let announcement_mgr = self.announcement_mgr.clone();
        let reachable_via = self.reachable_via.clone();
        let reverse_routes = self.reverse_routes.clone();
        let origin_admission = self.origin_admission.clone();
        let local_capabilities = self.local_capabilities.clone();
        let last_announce_from = self.last_announce_from.clone();
        let uai_config = self.uai_config.clone();
        let notify_topic = self.notify_topic.clone();
        let policy = self.policy.clone();
        let tier2_flow = self.tier2_flow.clone();
        let audit_log = self.audit_log.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let data = buf[..len].to_vec();
                        debug!("Received {} bytes from {}", len, addr);

                        if let Some((node_id, hello_ts)) = extract_sender_with_timestamp(&data) {
                            // Gated on the frame's actual message type, not just
                            // "any verified frame from an addr we're dialing" -
                            // otherwise some unrelated frame arriving from that
                            // addr before the real HELLO_ACK would wrongly
                            // resolve the pending connect(), and a genuine HELLO
                            // from that same addr (a real, separate greeting)
                            // could get silently swallowed as if it were the
                            // reply instead of being answered below.
                            match frame_msg_type(&data) {
                                Some(HELLO_ACK_MSG_TYPE) => {
                                    if let Some(tx) = pending_connects.lock().await.remove(&addr) {
                                        let _ = tx.send((node_id, hello_ts));
                                    }
                                }
                                Some(HELLO_MSG_TYPE) => {
                                    // Unsolicited HELLO from someone we didn't
                                    // dial - answer it with our own identity so
                                    // *their* connect() call resolves. Never done
                                    // for a HELLO_ACK (separate match arm above),
                                    // so a reply never triggers a reply-to-the-reply.
                                    let ack = build_hello_reply_frame(&identity);
                                    if let Err(e) = socket.send_to(&ack, addr).await {
                                        warn!("Failed to send HELLO_ACK to {}: {}", addr, e);
                                    }
                                    // Also register them via the same event
                                    // path `discovery` uses (this task can't
                                    // touch `self.peers`/`known_peers`
                                    // directly - the main event loop owns
                                    // that). Without this, the answering
                                    // side of a connect() handshake never
                                    // actually tracks the dialer as a known
                                    // peer, which would silently break the
                                    // `known_peers`-gated Ping reply below
                                    // for anyone who connected TO us rather
                                    // than peers we dialed or discovered.
                                    let _ = event_tx.send(NetworkEvent::PeerDiscovered {
                                        node_id,
                                        addr,
                                        timestamp: hello_ts,
                                    }).await;
                                }
                                _ => {}
                            }

                            let _ = event_tx.send(NetworkEvent::MessageReceived {
                                from: node_id,
                                data,
                            }).await;
                        } else if let Some(frame) = decode_verified_frame(&data) {
                            // Provably disjoint from the HELLO family by wire
                            // format (HELLO magic byte 0 is 0x41; codec frames
                            // always pack 0b10 into byte 0's top 2 bits, landing
                            // in 0x80-0xBF) - no ambiguity between the branches.
                            handle_axiom_frame(
                                frame, addr, &socket, &discovery_socket, &pending_pings, &known_peers,
                                &peer_addrs, &forwarded_frames,
                                &pending_intents, &semantic_router, &announcement_mgr,
                                &reachable_via, &reverse_routes, &origin_admission, &local_capabilities,
                                &last_announce_from, &identity, &uai_config, &notify_topic,
                                &policy, &tier2_flow, &audit_log,
                            ).await;
                        }
                        // Neither a verified HELLO/HELLO_ACK nor a signature-
                        // verified AXIOM Frame - drop silently, same as today.
                    }
                    Err(e) => {
                        error!("Receive error: {}", e);
                        let _ = event_tx.send(NetworkEvent::Error(e.to_string())).await;
                    }
                }
            }
        });
    }

    /// Fire off a `ping()` in its own task and log the result instead of
    /// returning it - for call sites (the event loop, on `PeerDiscovered`/
    /// bootstrap `connect()`) that want a liveness check but can't afford to
    /// block on up to `PING_TIMEOUT` waiting for a slow/dead peer. Takes
    /// `&self`: everything it touches (`pending_pings`, `socket`,
    /// `discovery_socket`, `identity`) is already `Arc`-shared or cheaply
    /// cloneable, so the spawned task doesn't need to borrow `self` at all.
    pub fn spawn_ping(&self, peer_id: NodeId, addr: SocketAddr) {
        let identity = self.identity.clone();
        let pending_pings = self.pending_pings.clone();
        let socket = self.socket.clone();
        let discovery_socket = self.discovery_socket.clone();

        tokio::spawn(async move {
            let trace_id = next_trace_id();
            let (tx, rx) = oneshot::channel();
            pending_pings.lock().await.insert(trace_id, PendingPing {
                expected_sender: peer_id,
                tx,
            });

            let ping_frame = build_ping_frame(&identity, trace_id);
            if ping_frame.is_empty() {
                pending_pings.lock().await.remove(&trace_id);
                warn!("spawn_ping: failed to build Ping frame (sign/encode error, see logs)");
                return;
            }

            let send_result = if is_link_local_v6(&addr) {
                match &discovery_socket {
                    Some(disc) => disc.send_to(&ping_frame, addr).await,
                    None => socket.send_to(&ping_frame, addr).await,
                }
            } else {
                socket.send_to(&ping_frame, addr).await
            };
            if let Err(e) = send_result {
                pending_pings.lock().await.remove(&trace_id);
                warn!("Ping to {}: send failed: {}", hex::encode(peer_id.as_bytes()), e);
                return;
            }

            let start = std::time::Instant::now();
            match tokio::time::timeout(PING_TIMEOUT, rx).await {
                Ok(Ok(())) => info!("Ping to {} succeeded: {:?} RTT", hex::encode(peer_id.as_bytes()), start.elapsed()),
                Ok(Err(_)) => warn!("Ping to {} failed: reply channel closed", hex::encode(peer_id.as_bytes())),
                Err(_) => {
                    pending_pings.lock().await.remove(&trace_id);
                    warn!("Ping to {} timed out waiting for Pong", hex::encode(peer_id.as_bytes()));
                }
            }
        });
    }

    /// Fire off our capability `Announce` to `addr`, once, fire-and-forget -
    /// no reply is expected or waited on (`Announce` is one-way gossip, not
    /// a request/reply pair like `Ping`/`Intent`). Called from the same
    /// points `spawn_ping` is (both `connect()`'s success path and
    /// discovery's `PeerDiscovered`), so both sides of a handshake
    /// independently announce to each other - nothing here is triggered BY
    /// receiving an Announce, so there's no reply-triggers-a-reply loop to
    /// worry about in the first place.
    pub fn spawn_announce(&self, addr: SocketAddr) {
        let identity = self.identity.clone();
        let announcement_mgr = self.announcement_mgr.clone();
        let socket = self.socket.clone();
        let discovery_socket = self.discovery_socket.clone();

        tokio::spawn(async move {
            // AXIOM-14 Cycle 2b (Fable diff review, required) / Cycle 6
            // (extended, not removed - see `MAX_ROUTE_INDIRECTION`'s doc
            // comment in axiom-router/src/announce.rs): TTL here must match
            // how far request routing can actually REACH, not just how far
            // gossip can propagate. Cycle 2b's routing table was
            // one-hop-of-indirection only, so a hardcoded TTL=1 was correct
            // then. Cycle 6 taught `try_forward_routed_frame` to also
            // consult `reachable_via` for a next hop, extending routing
            // reach to `MAX_ROUTE_INDIRECTION` hops of indirection - this
            // must use that same constant, not a separately-maintained
            // number, or the exact regression Cycle 2b fixed reappears: a
            // node learning about (and registering as a provider) an origin
            // further away than routing can actually forward to,
            // guaranteeing a 25s timeout on every attempt.
            let frame = announcement_mgr.lock().await.create_announcement(MAX_ROUTE_INDIRECTION);
            let bytes = sign_and_encode_frame(&identity, frame, FrameType::Announce);
            if bytes.is_empty() {
                warn!("spawn_announce: failed to build Announce frame (sign/encode error, see logs)");
                return;
            }

            let send_result = if is_link_local_v6(&addr) {
                match &discovery_socket {
                    Some(disc) => disc.send_to(&bytes, addr).await,
                    None => socket.send_to(&bytes, addr).await,
                }
            } else {
                socket.send_to(&bytes, addr).await
            };
            if let Err(e) = send_result {
                warn!("Failed to send Announce to {}: {}", addr, e);
            }
        });
    }

    /// Send a signed `Ping` frame to an already-connected peer and wait for
    /// its `Pong`, returning measured round-trip time. Errors (not a silent
    /// placeholder) on an unknown peer, send failure, or timeout. Blocks for
    /// up to `PING_TIMEOUT` - callers that can't afford that (the event
    /// loop) should use `spawn_ping` instead.
    pub async fn ping(&mut self, peer_id: &NodeId) -> Result<Duration> {
        let addr = self.peers.get(peer_id)
            .map(|p| p.addr)
            .ok_or_else(|| anyhow::anyhow!("ping: unknown peer {}", hex::encode(peer_id.as_bytes())))?;

        let trace_id = next_trace_id();
        let (tx, rx) = oneshot::channel();
        self.pending_pings.lock().await.insert(trace_id, PendingPing {
            expected_sender: *peer_id,
            tx,
        });

        let ping_frame = build_ping_frame(&self.identity, trace_id);
        if ping_frame.is_empty() {
            self.pending_pings.lock().await.remove(&trace_id);
            anyhow::bail!("ping: failed to build Ping frame (sign/encode error, see logs)");
        }
        let start = std::time::Instant::now();
        if let Err(e) = self.send_raw(&addr, &ping_frame).await {
            self.pending_pings.lock().await.remove(&trace_id);
            return Err(e);
        }

        match tokio::time::timeout(PING_TIMEOUT, rx).await {
            Ok(Ok(())) => Ok(start.elapsed()),
            Ok(Err(_)) => {
                self.pending_pings.lock().await.remove(&trace_id);
                anyhow::bail!("ping to {} failed: reply channel closed", hex::encode(peer_id.as_bytes()));
            }
            Err(_) => {
                self.pending_pings.lock().await.remove(&trace_id);
                anyhow::bail!("ping to {} timed out waiting for Pong", hex::encode(peer_id.as_bytes()));
            }
        }
    }

    /// Ask a peer that's announced `capability` to fulfill it with `payload`,
    /// returning the result payload (for the built-in `"echo"` capability,
    /// byte-for-byte identical to what was sent). Picks the top-scored
    /// provider via `SemanticRouter::discover` (populated by verified
    /// `Announce` frames - see `spawn_announce`/`handle_axiom_frame`'s
    /// `Announce` arm) - no multi-hop forwarding, direct send only (AXIOM-2
    /// scope cut, see the plan doc). Fails fast, before sending anything, if
    /// no peer has announced the capability or the top candidate has no
    /// known address (an Announce can in principle arrive relayed from a
    /// peer we haven't ourselves handshaken with - `self.peers` wouldn't
    /// have an address for them).
    ///
    /// Returns the responding peer's `NodeId` alongside the payload so a
    /// caller doing repeated requests (see `routing_snapshot` and the CLI's
    /// `intent --repeat`) can observe which provider actually got picked each
    /// round, not just infer it from side effects.
    pub async fn request_intent(&mut self, capability: &str, payload: Vec<u8>) -> Result<(NodeId, Vec<u8>)> {
        let intent = AiIntent::from_str(capability);

        let candidate = {
            let router = self.semantic_router.lock().await;
            router.discover(&intent).into_iter().next()
        };
        let Some(candidate) = candidate else {
            anyhow::bail!("request_intent: no provider found for capability '{}'", capability);
        };
        let peer_id = *candidate.agent.node_id();

        let direct_addr = self.peers.get(&peer_id).map(|p| p.addr);
        let addr = match direct_addr {
            Some(addr) => addr,
            None => {
                // AXIOM-14 Cycle 2b: not a direct peer - but do we know a
                // relay for it, learned via a gossip-forwarded Announce
                // (see the live `Announce` arm in `handle_axiom_frame`)?
                // Fall back to `request_intent_via` automatically instead
                // of failing outright, so discovery "just works" without
                // the caller ever needing to know a relay exists.
                let relay = self.reachable_via.lock().unwrap().get(&peer_id).map(|(relay, _)| *relay);
                let Some(relay) = relay else {
                    anyhow::bail!(
                        "request_intent: provider {} for '{}' has no known address and no known relay",
                        hex::encode(peer_id.as_bytes()), capability
                    );
                };
                let result = self.request_intent_via(relay, peer_id, capability, payload).await?;
                return Ok((peer_id, result));
            }
        };

        let trace_id = next_trace_id();
        let (tx, rx) = oneshot::channel();
        self.pending_intents.lock().await.insert(trace_id, PendingIntent {
            expected_sender: peer_id,
            tx,
        });

        let frame_bytes = build_intent_frame(&self.identity, intent.hash, trace_id, payload, None);
        if frame_bytes.is_empty() {
            self.pending_intents.lock().await.remove(&trace_id);
            anyhow::bail!("request_intent: failed to build Intent frame (sign/encode error, see logs)");
        }
        let start = std::time::Instant::now();
        if let Err(e) = self.send_raw(&addr, &frame_bytes).await {
            self.pending_intents.lock().await.remove(&trace_id);
            return Err(e);
        }

        // Feed the real outcome back into the same reputation score `discover()`
        // used to pick this provider - without this, `discover()`'s reputation
        // term is permanently pinned at the 0.5 default and multi-provider
        // selection never actually adapts to which peers are healthy.
        let elapsed_ms = || start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        match tokio::time::timeout(INTENT_TIMEOUT, rx).await {
            Ok(Ok(Ok(result_payload))) => {
                self.semantic_router.lock().await.update_reputation(&peer_id, true, elapsed_ms());
                Ok((peer_id, result_payload))
            }
            Ok(Ok(Err(reason))) => {
                self.semantic_router.lock().await.update_reputation(&peer_id, false, elapsed_ms());
                anyhow::bail!("request_intent: {} returned error: {}", hex::encode(peer_id.as_bytes()), reason)
            }
            Ok(Err(_)) => {
                self.pending_intents.lock().await.remove(&trace_id);
                self.semantic_router.lock().await.update_reputation(&peer_id, false, elapsed_ms());
                anyhow::bail!("request_intent: reply channel closed");
            }
            Err(_) => {
                self.pending_intents.lock().await.remove(&trace_id);
                self.semantic_router.lock().await.update_reputation(&peer_id, false, elapsed_ms());
                anyhow::bail!("request_intent to {} timed out waiting for Fulfill", hex::encode(peer_id.as_bytes()));
            }
        }
    }

    /// AXIOM-14 Cycle 1b: like `request_intent`, but explicitly routed
    /// through `relay` toward `destination` - a peer we're NOT directly
    /// connected to, unlike `request_intent`'s `semantic_router.discover()`
    /// (which only ever finds direct-neighbor providers). `relay` MUST be a
    /// direct peer (checked via `self.peers`, same as `request_intent`'s
    /// address lookup) - `destination` does not need to be, that's the
    /// whole point.
    ///
    /// Cycle 1b scope: `destination` and the capability it should serve are
    /// known out-of-band by the caller (a CLI flag, a test fixture) rather
    /// than discovered - see `try_forward_routed_frame`'s doc comment for
    /// why. Automatic discovery of peers-of-peers is Cycle 2 territory.
    pub async fn request_intent_via(
        &mut self,
        relay: NodeId,
        destination: NodeId,
        capability: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let intent = AiIntent::from_str(capability);

        let relay_addr = self.peers.get(&relay)
            .map(|p| p.addr)
            .ok_or_else(|| anyhow::anyhow!(
                "request_intent_via: relay {} has no known address - relay must be a direct peer",
                hex::encode(relay.as_bytes())
            ))?;

        let trace_id = next_trace_id();
        let (tx, rx) = oneshot::channel();
        // expected_sender is `destination`, NOT `relay` - the Fulfill we get
        // back is signed by `destination` itself (relaying never touches
        // the header/signature, only routing.destination/ttl), even though
        // it physically arrives via `relay`'s address.
        self.pending_intents.lock().await.insert(trace_id, PendingIntent {
            expected_sender: destination,
            tx,
        });

        let routing = RoutingExt::new(destination, DEFAULT_ROUTING_TTL);
        let frame_bytes = build_intent_frame(&self.identity, intent.hash, trace_id, payload, Some(routing));
        if frame_bytes.is_empty() {
            self.pending_intents.lock().await.remove(&trace_id);
            anyhow::bail!("request_intent_via: failed to build Intent frame (sign/encode error, see logs)");
        }
        let start = std::time::Instant::now();
        if let Err(e) = self.send_raw(&relay_addr, &frame_bytes).await {
            self.pending_intents.lock().await.remove(&trace_id);
            return Err(e);
        }

        // AXIOM-14 Cycle 3: same reputation feedback `request_intent` gives
        // direct providers - without this, a relayed provider's score stays
        // pinned at the 0.5 default forever, since `request_intent`'s
        // automatic fallback (see above) hands off to this function and
        // returns its result directly, never touching `update_reputation`
        // itself. Scored on `destination` (the actual provider), never
        // `relay` - the relay just carried the frame, it didn't answer it.
        let elapsed_ms = || start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        match tokio::time::timeout(INTENT_TIMEOUT, rx).await {
            Ok(Ok(Ok(result_payload))) => {
                self.semantic_router.lock().await.update_reputation(&destination, true, elapsed_ms());
                Ok(result_payload)
            }
            Ok(Ok(Err(reason))) => {
                self.semantic_router.lock().await.update_reputation(&destination, false, elapsed_ms());
                anyhow::bail!("request_intent_via: {} returned error: {}", hex::encode(destination.as_bytes()), reason)
            }
            Ok(Err(_)) => {
                self.pending_intents.lock().await.remove(&trace_id);
                self.semantic_router.lock().await.update_reputation(&destination, false, elapsed_ms());
                anyhow::bail!("request_intent_via: reply channel closed");
            }
            Err(_) => {
                self.pending_intents.lock().await.remove(&trace_id);
                self.semantic_router.lock().await.update_reputation(&destination, false, elapsed_ms());
                anyhow::bail!(
                    "request_intent_via to {} (via {}) timed out waiting for Fulfill",
                    hex::encode(destination.as_bytes()), hex::encode(relay.as_bytes())
                );
            }
        }
    }

    /// AXIOM-14 Cycle 3: `last_announce_from`, `origin_admission`, and the
    /// `AnnouncementManager`'s own `seen` dedup map all grow one entry per
    /// distinct (sender, origin) / sender / (origin, intent) they've ever
    /// observed, and NONE of them had a way to shrink again - LRU peer
    /// eviction purges `reachable_via` (see that branch's comment) but was
    /// never wired to these three, so a long-lived node facing a slow trickle
    /// of distinct peers/origins over days or weeks would grow all three
    /// unboundedly even though most entries are long past being useful for
    /// rate-limiting or dedup. Cycle 4 (Fable full-repo review finding #3)
    /// adds `reachable_via` and its implied `SemanticRouter` registrations -
    /// the two maps Cycle 3 missed, since the LRU-eviction purge alone
    /// never fires on a small mesh. Cycle 6 adds `reverse_routes` - see its
    /// own field doc comment for why it needs a time-based sweep rather
    /// than `ForwardedFrameCache`'s capacity-FIFO approach. Run
    /// periodically for the lifetime of the node - not one-shot - so it
    /// keeps these bounded for as long as the process runs, not just once
    /// at startup.
    pub fn spawn_maintenance(&self) {
        let announcement_mgr = self.announcement_mgr.clone();
        let last_announce_from = self.last_announce_from.clone();
        let origin_admission = self.origin_admission.clone();
        let reachable_via = self.reachable_via.clone();
        let reverse_routes = self.reverse_routes.clone();
        let known_peers = self.known_peers.clone();
        let semantic_router = self.semantic_router.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ANNOUNCEMENT_MAINTENANCE_INTERVAL);
            // First tick fires immediately; the interval only matters once
            // we're actually running long enough to accumulate anything.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                run_announcement_maintenance(
                    &announcement_mgr, &last_announce_from, &origin_admission,
                    &reachable_via, &reverse_routes, &known_peers, &semantic_router,
                ).await;
            }
        });
    }

    /// AXIOM-7 diagnostic: every current provider of `capability`, in the
    /// same rank order `request_intent` would pick from, alongside each
    /// one's live reputation score. Exists to make a multi-provider routing
    /// test legible - without this, an external observer can only see WHICH
    /// peer answered each round, not WHY: distinguishing "the loser's score
    /// actually dropped" from "the loser silently vanished from the registry
    /// for an unrelated reason" (LRU eviction, a re-Announce race) requires
    /// seeing both peers' scores and continued presence together, every
    /// round, not reconstructing it after the fact from side effects.
    pub async fn routing_snapshot(&self, capability: &str) -> Vec<(NodeId, f32)> {
        let intent = AiIntent::from_str(capability);
        let router = self.semantic_router.lock().await;
        router.discover(&intent).into_iter()
            .map(|c| {
                let id = *c.agent.node_id();
                (id, router.get_reputation(&id))
            })
            .collect()
    }

    /// Connect to a peer whose address is already known (config/bootstrap
    /// path). Sends a HELLO and waits for the peer's HELLO_ACK to learn its
    /// real NodeId (verified by `start_receive_loop` before this ever sees
    /// it) - errors out on timeout rather than guessing. Link-local
    /// discovery is additive to this, not a replacement.
    pub async fn connect(&mut self, addr: &SocketAddr) -> Result<NodeId> {
        info!("Connecting to {}", addr);

        let (tx, rx) = oneshot::channel();
        self.pending_connects.lock().await.insert(*addr, tx);

        let hello = self.create_hello_message();
        if let Err(e) = self.send_raw(addr, &hello).await {
            self.pending_connects.lock().await.remove(addr);
            return Err(e);
        }

        let (peer_id, hello_ts) = match tokio::time::timeout(CONNECT_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => {
                self.pending_connects.lock().await.remove(addr);
                anyhow::bail!("connect to {} failed: reply channel closed", addr);
            }
            Err(_) => {
                self.pending_connects.lock().await.remove(addr);
                anyhow::bail!("connect to {} timed out waiting for HELLO_ACK", addr);
            }
        };

        let conn = PeerConnection {
            node_id: peer_id,
            addr: *addr,
            established_at: std::time::Instant::now(),
            bytes_sent: hello.len() as u64,
            bytes_received: 0,
            discovered: false,
            // Real timestamp from the verified HELLO_ACK, not a placeholder -
            // without this, a connect()-established peer's replay/rebind
            // protection in `register_peer` would be weaker than a
            // discovery-established one's (any later timestamp at all would
            // clear the `0` bar).
            last_hello_ts: hello_ts,
            last_seen: std::time::Instant::now(),
        };

        self.peers.insert(peer_id, conn);
        self.known_peers.lock().unwrap().insert(peer_id);
        self.peer_addrs.lock().unwrap().insert(peer_id, *addr);

        Ok(peer_id)
    }

    /// Register a peer discovered outside the explicit `connect()` path
    /// (currently: link-local multicast). Unlike `connect()`, the real
    /// NodeId is already known here (`discovery::start` already verified the
    /// HELLO signature against it), so no placeholder ID is needed.
    ///
    /// `hello_ts` is the HELLO frame's signed timestamp - rejecting
    /// non-increasing values per NodeId stops a captured HELLO from being
    /// replayed later to rebind this peer's address to an attacker's.
    ///
    /// Bounded by `max_peers`: a flood of disposable-keypair discovery spam
    /// can fill every slot, so once full this evicts the least-recently-seen
    /// *discovered* peer (never an explicit/`connect()`-established one) to
    /// make room, rather than permanently locking out legitimate peers.
    pub fn register_peer(&mut self, node_id: NodeId, addr: SocketAddr, hello_ts: u64) {
        if let Some(existing) = self.peers.get_mut(&node_id) {
            if hello_ts <= existing.last_hello_ts {
                debug!(
                    "Rejecting stale/replayed HELLO for {} at {} (ts {} <= last {})",
                    hex::encode(node_id.as_bytes()), addr, hello_ts, existing.last_hello_ts
                );
                return;
            }
            // Refresh the address in case the peer's interface/scope_id
            // changed since it was first seen (link flap, renumbering).
            existing.addr = addr;
            existing.last_hello_ts = hello_ts;
            existing.last_seen = std::time::Instant::now();
            self.peer_addrs.lock().unwrap().insert(node_id, addr);
            return;
        }

        if self.peers.len() >= self.config.max_peers {
            let evictable = self.peers.iter()
                .filter(|(_, p)| p.discovered)
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(id, _)| *id);

            match evictable {
                Some(id) => {
                    debug!("Evicting LRU discovered peer {} to admit {}", hex::encode(id.as_bytes()), hex::encode(node_id.as_bytes()));
                    self.peers.remove(&id);
                    self.known_peers.lock().unwrap().remove(&id);
                    self.peer_addrs.lock().unwrap().remove(&id);
                    // AXIOM-14 Cycle 3: drop the evicted peer's own
                    // origin-admission window too - else a peer's slot
                    // frees up but a NEW peer that later reuses the same
                    // NodeId (or the peer reconnecting) inherits a stale,
                    // possibly-already-exhausted admission window.
                    self.origin_admission.lock().unwrap().remove(&id);
                    // AXIOM-14 Cycle 2b: any origin we only knew how to
                    // reach THROUGH this now-evicted peer is unreachable
                    // too - purge those `reachable_via` entries, or
                    // `request_intent`'s automatic fallback would keep
                    // retrying a dead route forever (announcements are
                    // currently one-shot per handshake, no periodic
                    // re-announce wired yet, so disconnect-purge is the
                    // ONLY staleness mechanism that exists right now).
                    let orphaned_origins: Vec<NodeId> = {
                        let mut via = self.reachable_via.lock().unwrap();
                        let orphaned: Vec<NodeId> = via.iter()
                            .filter(|(_, (relay, _))| *relay == id)
                            .map(|(origin, _)| *origin)
                            .collect();
                        for origin in &orphaned {
                            via.remove(origin);
                        }
                        orphaned
                    };
                    // AXIOM-4 (Cycle C): also drop the evicted peer's OWN
                    // capability registrations, plus every orphaned
                    // relayed-origin's - otherwise `request_intent` could
                    // keep picking a now-unreachable "provider" long after
                    // we've stopped tracking how to reach them (already
                    // fails clean via the `self.peers`/`reachable_via`
                    // checks, but there's no reason to let the registry
                    // stay stale). Spawned since `semantic_router` needs an
                    // async lock and this method is sync (called from the
                    // event loop).
                    let router = self.semantic_router.clone();
                    // AXIOM-14 Cycle 2b (Fable diff review): re-checked
                    // under its own lock inside the spawned task, not
                    // trusted from the synchronous collection above - a
                    // concurrent Announce for the same origin, arriving via
                    // a DIFFERENT relay in the gap between collecting
                    // `orphaned_origins` and this task actually running,
                    // could have already re-populated `reachable_via` (and
                    // re-registered the origin) with fresh, valid
                    // information. Unregistering it anyway here would
                    // silently destroy that fresh registration - and since
                    // announces are one-shot per handshake (no periodic
                    // re-announce), that corruption would be permanent, not
                    // self-healing.
                    let reachable_via = self.reachable_via.clone();
                    tokio::spawn(async move {
                        let mut router = router.lock().await;
                        router.unregister_node(&id);
                        for origin in orphaned_origins {
                            if reachable_via.lock().unwrap().contains_key(&origin) {
                                // Re-populated since collection - a fresh,
                                // still-valid route exists now, don't
                                // destroy it.
                                continue;
                            }
                            router.unregister_node(&origin);
                        }
                    });
                }
                None => {
                    warn!(
                        "Dropping discovered peer {} at {}: max_peers ({}) reached, no discovered peer to evict",
                        hex::encode(node_id.as_bytes()), addr, self.config.max_peers
                    );
                    return;
                }
            }
        }

        debug!("Registered discovered peer {} at {}", hex::encode(node_id.as_bytes()), addr);
        self.known_peers.lock().unwrap().insert(node_id);
        self.peer_addrs.lock().unwrap().insert(node_id, addr);
        self.peers.insert(node_id, PeerConnection {
            node_id,
            addr,
            established_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            discovered: true,
            last_hello_ts: hello_ts,
            last_seen: std::time::Instant::now(),
        });
    }

    /// Send `data` to `addr`, routing link-local IPv6 destinations through
    /// the discovery socket since `self.socket` (typically IPv4) can't reach
    /// them.
    async fn send_raw(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        if is_link_local_v6(addr) {
            if let Some(disc) = &self.discovery_socket {
                disc.send_to(data, addr).await?;
                return Ok(());
            }
        }
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    /// Create a HELLO message for handshake
    fn create_hello_message(&self) -> Vec<u8> {
        build_hello_frame(&self.identity)
    }

    /// Send a message to a peer
    #[allow(dead_code)]
    pub async fn send(&self, peer_id: &NodeId, data: &[u8]) -> Result<()> {
        if let Some(peer) = self.peers.get(peer_id) {
            self.send_raw(&peer.addr, data).await?;
            debug!("Sent {} bytes to {}", data.len(), hex::encode(peer_id.as_bytes()));
        } else {
            warn!("Unknown peer: {}", hex::encode(peer_id.as_bytes()));
        }
        Ok(())
    }

    /// Broadcast a message to all peers
    #[allow(dead_code)]
    pub async fn broadcast(&self, data: &[u8]) -> Result<()> {
        for peer in self.peers.values() {
            if let Err(e) = self.send_raw(&peer.addr, data).await {
                warn!("Failed to send to {}: {}", peer.addr, e);
            }
        }
        Ok(())
    }

    /// Poll for network events
    pub async fn poll_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    /// Shutdown the network manager
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down network manager");
        self.peers.clear();
        Ok(())
    }

    /// Get the number of connected peers
    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get list of connected peer IDs
    #[allow(dead_code)]
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.keys().copied().collect()
    }

    /// AXIOM Phase 3.8: exposes this node's live, shared `CapabilityPolicy`
    /// handle - the SAME `Arc` every real capability dispatch call already
    /// checks via `check_and_acquire` (`DispatchContext::policy`) - to
    /// `forge-node`'s local admin control socket (`control.rs`), so a
    /// kill-switch mutation made through that socket (freeze/unfreeze/
    /// suspend/unsuspend) takes effect on the very next in-flight request
    /// boundary: no restart, no second copy of policy state to keep in
    /// sync. Read-only from this accessor's own point of view (it just
    /// clones the `Arc`); the mutating methods live on
    /// `axiom_gateway::CapabilityPolicy` itself.
    pub fn policy(&self) -> Arc<axiom_gateway::CapabilityPolicy> {
        self.policy.clone()
    }

    /// AXIOM Tier 2: the SAME `AuditLog` handle `NetworkManager::new` opened
    /// internally - see that field's own doc comment. `main.rs::start_node`
    /// calls this (after `ForgeNode::start`/`NetworkManager::new` has
    /// already run) to hand the control socket's kill-switch handlers this
    /// exact instance, instead of opening a second, chain-corrupting one.
    pub fn audit_log(&self) -> Option<Arc<axiom_gateway::AuditLog>> {
        self.audit_log.clone()
    }

    /// Gap B (AXIOM-11.2): a `DispatchContext` bundle for `dispatch_intent`,
    /// independent of `self` after this call returns - every field is
    /// `Arc`/cheap-`Clone`, so this is a handful of refcount bumps, not a
    /// deep copy. Deliberately does NOT hand out anything requiring the
    /// `Arc<tokio::sync::Mutex<NetworkManager>>` `ForgeNode` wraps `self`
    /// in - see `DispatchContext`'s own doc for why that lock must never be
    /// on the WAN request path. Safe to call from `ForgeNode::start()`
    /// before the event loop begins (nobody else holds the manager's lock
    /// at that point) and pass the resulting bundle into the independently-
    /// spawned WAN accept loop.
    pub(crate) fn dispatch_context(&self) -> DispatchContext {
        DispatchContext {
            identity: self.identity.clone(),
            local_capabilities: self.local_capabilities.clone(),
            uai_config: self.uai_config.clone(),
            notify_topic: self.notify_topic.clone(),
            policy: self.policy.clone(),
            tier2_flow: self.tier2_flow.clone(),
            audit_log: self.audit_log.clone(),
        }
    }
}

/// Message type byte: an initiating greeting - sent by `connect()` and by
/// `discovery`'s periodic announce. Answered with [`HELLO_ACK_MSG_TYPE`].
const HELLO_MSG_TYPE: u8 = 0x01;

/// Message type byte: a reply to a [`HELLO_MSG_TYPE`] frame. Never itself
/// answered - `start_receive_loop` only sends a HELLO_ACK for an incoming
/// HELLO, never for an incoming HELLO_ACK, which is what stops a reply from
/// triggering a reply-to-the-reply forever.
const HELLO_ACK_MSG_TYPE: u8 = 0x02;

/// How long `connect()` waits for a HELLO_ACK before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `ping()` waits for a `Pong` before giving up.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `request_intent()` waits for a `Fulfill`/`Error` before giving up.
/// Was 5s until AXIOM-10's "network_clients" (bridges to UAI, which itself
/// calls out to real hardware) proved a real round trip can legitimately
/// take ~15s even on a FAILURE path (Omada's own timeout inside the UAI
/// driver) - confirmed live: a real request completed in 15.03s end to end,
/// but AXIOM's own 5s timeout gave up and discarded it before the reply
/// ever arrived. 25s covers that with margin; fast capabilities (echo,
/// sysinfo) return in microseconds regardless and never wait anywhere near
/// this long in practice - a shared ceiling only costs a caller time when a
/// capability is genuinely slow to fail, not when everything's healthy.
const INTENT_TIMEOUT: Duration = Duration::from_secs(25);

/// AXIOM-14 Cycle 6: how long a `reverse_routes` breadcrumb survives with no
/// matching reply. Bounded by TIME, not capacity (see that field's own doc
/// comment for why a capacity-FIFO cache like `ForwardedFrameCache` would be
/// wrong here) - must comfortably exceed `INTENT_TIMEOUT` (the longest a
/// legitimate round trip can still be in flight) or a slow-but-healthy
/// reply's breadcrumb could be evicted before it ever arrives. Double
/// `INTENT_TIMEOUT` for margin, same reasoning `MAX_ANNOUNCE_CLOCK_SKEW`
/// used relative to `ANNOUNCEMENT_MAX_AGE` (Cycle 5) - comfortably above
/// real relay latency, while a breadcrumb old enough to actually be evicted
/// is always well past the point where its Intent could still be legitimately
/// in flight anyway.
const REVERSE_ROUTE_TTL: Duration = Duration::from_secs(INTENT_TIMEOUT.as_secs() * 2);

/// AXIOM-7: every capability name this build understands how to resolve an
/// Announce's hash back to, independent of what any single node offers via
/// its own `local_capabilities`. Recognizing a capability's name and being
/// able to serve it are different questions - only the `Intent` handler's
/// `capability_known` check (does *this* node actually implement it) should
/// stay scoped to `local_capabilities`; resolving an Announce's hash to a
/// name is a property of the software build, not any one node's config, so a
/// pure-consumer node (nothing in `local_capabilities`) can still recognize
/// and route to capabilities it wants but doesn't itself provide.
const KNOWN_CAPABILITY_NAMES: &[&str] = &["echo", "sysinfo", "network_clients", "notify_send", "proxmox_restart", "home_assistant_toggle", "docker_restart", "wg_peers_list", "wg_peer_manage"];

/// AXIOM-4 (Cycle C): minimum gap between processing two `Announce` frames
/// from the same already-known sender.
const ANNOUNCE_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

/// AXIOM-14 Cycle 3: how many DISTINCT origins a single sender may
/// introduce per `ORIGIN_ADMISSION_WINDOW`. The `(sender, origin)` rate
/// limit above only bounds re-announcing the SAME origin too fast - it
/// does nothing against a sender rotating a fresh fabricated origin on
/// every frame, which bypasses it entirely and grows SemanticRouter/
/// reachable_via/AnnouncementManager.seen/last_announce_from unboundedly.
/// Must scale with expected network size - a legitimate relay can validly
/// introduce up to (network size - 1) distinct origins. Any value works
/// for the current 2-real-node deployment; the MECHANISM (bounding
/// admission rate, not the tracker's own memory - a bounded-FIFO tracker
/// wouldn't help here, since the resources under attack live downstream
/// of this check, not in the tracker itself) is what matters.
///
/// AXIOM-14 Cycle 6 (Fable plan review, required): with `MAX_ROUTE_INDIRECTION`
/// raising routing/gossip reach beyond one hop, "expected network size"
/// above is no longer the right thing to size this against - a single
/// relay now legitimately fronts its ENTIRE multi-hop subtree of origins
/// (everyone reachable through it within `MAX_ROUTE_INDIRECTION` hops), not
/// just its own direct neighbors. Any relay whose subtree exceeds 16
/// distinct origins within one `ORIGIN_ADMISSION_WINDOW` will now silently
/// drop HONEST origins beyond the cap every window, indistinguishable from
/// an attacker being correctly rate-limited - a real tradeoff this cycle
/// introduces, not merely inherits from Cycle 3. Deliberately left at 16
/// rather than raised speculatively: the current real deployment is 2
/// nodes, several orders of magnitude below this cap either way, so there
/// is no live data yet on real subtree sizes to size a new value against -
/// guessing a bigger number now only weakens the anti-flood protection for
/// a scale that doesn't exist yet, in exchange for a benefit this
/// deployment can't presently observe either way. Revisit with real
/// numbers once the deployment actually grows past a handful of nodes - a
/// future, deployment-scale-driven cycle, not this one.
const MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW: usize = 16;
const ORIGIN_ADMISSION_WINDOW: Duration = Duration::from_secs(60);

/// AXIOM-14 Cycle 3: how often the periodic maintenance tick runs
/// (evicts stale AnnouncementManager.seen entries and last_announce_from
/// entries - neither had any eviction path before this cycle, so both
/// grew monotonically).
const ANNOUNCEMENT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Entries older than this get evicted by the maintenance tick. Gossip
/// loops resolve in seconds, so this only needs to comfortably
/// exceed real in-flight time - announces are one-shot per handshake
/// (no periodic re-announce), so there's no legitimate re-announce
/// cadence this needs to stay under either.
const ANNOUNCEMENT_MAX_AGE: Duration = Duration::from_secs(30 * 60);

/// Generate a probably-unique `TraceId` for correlating a request with its
/// reply. Not cryptographically random - doesn't need to be, since a
/// forged/guessed trace_id alone can't forge a valid reply (the payload
/// still has to carry a real signature over `sender_id`) and a collision
/// just costs a `ping()`/request timeout, not a security failure. Avoids
/// pulling in `rand` as a dependency for this alone.
pub(crate) fn next_trace_id() -> TraceId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    TraceId::from_u64(nanos ^ counter)
}

/// Decode `data` as an `axiom_codec`-encoded `Frame` and verify its Ed25519
/// signature against the sender_id it claims - returns `None` on any decode
/// failure OR a failed/inapplicable verification. Unlike the HELLO layer's
/// `extract_sender_with_timestamp`, which does this in one step, codec's
/// `Decoder` itself verifies nothing - skipping this check would mean the
/// entire Frame channel is unauthenticated (anyone on the LAN segment could
/// inject a `Ping`/future `Announce`/etc as anyone).
pub(crate) fn decode_verified_frame(data: &[u8]) -> Option<Frame> {
    let decoded = Decoder::decode(data).ok()?;
    let frame = Frame {
        header: decoded.header,
        trace_id: decoded.trace_id,
        routing: decoded.routing,
        fragment_info: decoded.fragment_info,
        payload_header: decoded.payload_header,
        payload: decoded.payload,
        auth: decoded.auth,
    };
    match FrameVerifier::verify(&frame) {
        Ok(true) => Some(frame),
        Ok(false) => {
            debug!(
                "Dropping Frame from claimed sender {}: signature verification failed",
                hex::encode(frame.header.sender_id.as_bytes())
            );
            None
        }
        // TrustLevel::Compress (session-token auth) or ::Raw (no auth) - this
        // codepath only ever builds Sig-level frames, so anything else here
        // isn't a frame we know how to trust; drop rather than guess.
        Err(_) => None,
    }
}

/// Whether an Announce's claimed `origin_clock` (HLC physical seconds) is
/// fresh enough to trust as non-replayed data, relative to `now_physical`
/// (real wall-clock, also HLC physical seconds) - at most
/// `MAX_ANNOUNCE_CLOCK_SKEW` away in EITHER direction. Pulled out of the
/// live `Announce` arm's own pre-check below (itself a duplicate of
/// `axiom_router::announce::process_announcement`'s authoritative check -
/// see the call site's doc comment for why the duplication is required) as
/// its own pure function (AXIOM Phase 1.2/AXIOM-15) so the exact boundary is
/// directly unit-testable, without needing a real signed frame timed to
/// land on it via a live socket round trip.
fn origin_clock_is_fresh(origin_clock_physical: u64, now_physical: u64) -> bool {
    now_physical.abs_diff(origin_clock_physical) <= MAX_ANNOUNCE_CLOCK_SKEW.as_secs()
}

/// Which transport a capability request arrived over - controls trust-tier
/// gating that must NOT be uniform across transports. See `dispatch_intent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchOrigin {
    Lan,
    Wan,
}

/// Bundle of everything `dispatch_intent` needs, independent of which
/// transport (LAN UDP receive loop, WAN per-connection task) is calling it.
/// Built once via `NetworkManager::dispatch_context()` and cloned per
/// request/connection - every field is already `Arc`/cheap-`Clone` (see
/// their own doc comments on `NetworkManager`), so cloning this bundle is
/// just a handful of refcount bumps, not a deep copy.
///
/// Deliberately does NOT hold `Arc<tokio::sync::Mutex<NetworkManager>>` or
/// anything reachable through it - `run_event_loop` holds that lock for up
/// to `SHUTDOWN_POLL_INTERVAL` per iteration, and a WAN request touching it
/// would stall behind the LAN event loop for no reason. Every field here is
/// independently `Arc`-shared specifically so WAN never needs that lock.
#[derive(Clone)]
pub(crate) struct DispatchContext {
    pub(crate) identity: Keypair,
    pub(crate) local_capabilities: Arc<Vec<String>>,
    pub(crate) uai_config: Arc<Option<UaiConfig>>,
    /// AXIOM notify_send: see `NetworkManager::notify_topic`'s own doc
    /// comment. `None` means the `"notify_send"` capability answers "not
    /// configured" regardless of what `uai_config` is.
    pub(crate) notify_topic: Arc<Option<String>>,
    /// AXIOM Phase 1.1: the sole authority on whether `sender_id` may call
    /// a given capability - see `axiom_gateway::policy`'s module doc comment.
    /// Replaces the old `network_clients_guard`/`network_clients_semaphore`
    /// pair (network_clients-only) and the known_peers-gates-echo/sysinfo
    /// model this struct's callers used to rely on for everything else.
    pub(crate) policy: Arc<axiom_gateway::CapabilityPolicy>,
    /// AXIOM Tier 2: see `NetworkManager::tier2_flow`'s own field doc
    /// comment.
    pub(crate) tier2_flow: Option<Arc<Tier2Flow>>,
    /// AXIOM Tier 2: see `NetworkManager::audit_log`'s own field doc
    /// comment.
    pub(crate) audit_log: Option<Arc<axiom_gateway::AuditLog>>,
}

/// Transport-agnostic capability dispatch - the reusable core of what used
/// to be inline in `handle_axiom_frame`'s `FrameType::Intent` arm (LAN
/// only, before AXIOM-11.2/Gap B). Resolves `intent_hash` to a capability
/// name, runs it, and returns an encoded `Fulfill`/`Error` Frame ready to
/// write to whatever transport the caller has (UDP `send_to` for LAN, a
/// QUIC stream for WAN - see `axiom_transport::wan` /
/// `forge-node/src/node.rs`'s WAN accept loop).
///
/// Callers MUST spawn this rather than awaiting it inline on a shared
/// receive loop - the `network_clients` path can take a real HTTP round
/// trip and must not block that loop from processing other peers' frames
/// meanwhile (this used to be a spawn INSIDE the network_clients branch
/// specifically; Fable's Cycle 2B review pointed out that only works if
/// the caller already knows in advance which capability was requested -
/// simpler and strictly safer to make spawning the caller's job for every
/// capability, not just the slow one). WAN's per-connection task already
/// runs independently of the LAN receive loop, so this requirement is
/// satisfied there for free by construction.
///
/// `origin` is NOT a suggestion - `network_clients` hard-denies
/// `DispatchOrigin::Wan` regardless of the policy allowlist, because it
/// discloses full network topology to a peer that, unlike a LAN peer, is
/// internet-reachable and has no revocation path if its key is later
/// compromised (see project-axiom.md's WAN gap notes). `echo`/`sysinfo` are
/// fine for both origins.
///
/// AXIOM Phase 1.4 [OWNER GATE]: `network_clients` is ALSO hard-denied for
/// every origin right now (see the unconditional check below, which runs
/// before the WAN-specific one and makes it unreachable for this
/// capability until the gate is lifted). This is deliberate and temporary:
/// AXIOM-10's `fetch_network_clients` authenticates to the UAI broker with
/// a single `X-UAI-Token` that, per `uai_broker.py`'s own
/// `/registry/dispatch` route, is NOT scoped to the two read-only
/// `omada_*` tools this capability actually calls - any caller holding a
/// valid token for ANY registered UAI caller can invoke any of the
/// broker's ~2000 registered tools across ~200 drivers (`uai_callers`
/// entries in `uai_secrets.json` even carry `allowed_drivers`/`allow_all`
/// fields that LOOK like a scoping mechanism, but nothing in
/// `uai_broker.py` ever reads them - dead config, not enforced). A
/// per-capability AXIOM-side allowlist/tier/audit control cannot
/// compensate for an over-scoped credential on the other side of that
/// wire - see SECURITY.md's "AXIOM -> UAI credential scope" section for
/// the full writeup. Do not remove this block until Larry has provisioned
/// a UAI token actually scoped (UAI-side) to read-only Omada queries, and
/// SECURITY.md has been updated to describe that new, narrower scope.
///
/// AXIOM Phase 1.1: authorization for EVERY capability here (not just
/// `network_clients`, which used to be the only one) now comes from
/// `ctx.policy` alone - see `axiom_gateway::policy`'s module doc comment. A
/// completed HELLO handshake (`known_peers`, LAN) or a fresh signed
/// liveness exchange (WAN) still proves the caller holds the private key
/// for `sender_id`, but neither one grants access to anything by itself
/// anymore; only an explicit per-capability allowlist entry does.
/// `reply_routing`: AXIOM-14 Cycle 1b - `Some(RoutingExt{destination: <the
/// original requester>, ttl})` when `sender_id` is a relay forwarding this
/// Intent on someone else's behalf, so the Fulfill/Error built here routes
/// back through that relay instead of vanishing as an unmatched local
/// frame at the relay. `None` for a direct request (today's existing
/// behavior, unchanged) - see `handle_axiom_frame`'s `Intent` arm for how
/// this gets computed.
pub(crate) async fn dispatch_intent(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    sender_id: NodeId,
    // AXIOM Phase 1.4: unused now that `network_clients` (the only
    // capability that ever consulted this) is hard-denied unconditionally
    // regardless of origin - see the [OWNER GATE] block below. Kept in
    // the signature (both call sites, LAN and WAN, still pass a real
    // value) rather than removed, since it's needed again the moment
    // that gate is narrowed back to WAN-only.
    _origin: DispatchOrigin,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    let Some(name) = ctx.local_capabilities.iter()
        .find(|name| AiIntent::from_str(name).hash == intent_hash)
        .map(|s| s.as_str())
    else {
        return build_error_frame(&ctx.identity, intent_hash, trace_id, "unknown capability", reply_routing);
    };

    // AXIOM Phase 1.4 [OWNER GATE] - see this function's doc comment above
    // for the full writeup and SECURITY.md for the finding. Unconditional,
    // build-level, no policy escape hatch (same reasoning the old
    // WAN-only version of this check used, and which this one now
    // subsumes: a requester - LAN or WAN - learns nothing about whether
    // it would otherwise have been on the allowlist). The UAI credential
    // this capability holds is not scoped to what it actually needs, so
    // the capability does not run for real, for anyone, on any origin,
    // until that's fixed. Restore the narrower (`origin == DispatchOrigin::Wan`-only)
    // form of this check, rather than deleting it outright, once a
    // properly-scoped token exists and SECURITY.md is updated.
    if name == "network_clients" {
        debug!(
            "Rejecting network_clients from {} - capability disabled pending a properly-scoped UAI credential (see SECURITY.md)",
            hex::encode(sender_id.as_bytes())
        );
        return build_error_frame(&ctx.identity, intent_hash, trace_id, "network_clients disabled pending a properly-scoped UAI credential", reply_routing);
    }

    // AXIOM Phase 1.1: the SOLE authorization check for every capability -
    // see axiom_gateway::policy's module doc comment. A peer with a perfectly
    // valid signature (decode_verified_frame already proved that, upstream
    // of this function) but no allowlist entry gets a DISTINCT, explicit
    // "not authorized" Error reply here - never silently conflated with a
    // bad-signature drop, which produces no reply at all and happens
    // before this function is ever called.
    let permit = match ctx.policy.check_and_acquire(name, sender_id) {
        axiom_gateway::PolicyOutcome::NotAuthorized => {
            debug!(
                "Rejecting {} from {} - not authorized by capability policy",
                name, hex::encode(sender_id.as_bytes())
            );
            return build_error_frame(&ctx.identity, intent_hash, trace_id, "not authorized for this capability", reply_routing);
        }
        axiom_gateway::PolicyOutcome::RateLimited => {
            debug!("Rate-limiting {} from {} (too soon since last)", name, hex::encode(sender_id.as_bytes()));
            return build_error_frame(&ctx.identity, intent_hash, trace_id, "rate limited, try again later", reply_routing);
        }
        axiom_gateway::PolicyOutcome::AtConcurrencyLimit => {
            debug!("{}: at max concurrency, rejecting {}", name, hex::encode(sender_id.as_bytes()));
            return build_error_frame(&ctx.identity, intent_hash, trace_id, "too many concurrent requests for this capability, try again shortly", reply_routing);
        }
        // AXIOM Phase 3.8: kill switch outcomes, DISTINCT from
        // NotAuthorized (see axiom_gateway::policy::PolicyOutcome's own
        // doc comment) so an operator/log can tell "revoked/frozen at the
        // switch" apart from "was never granted." This match arm is the
        // ONLY place forge-node ever sees these outcomes - the kill
        // switch's own mutating methods (freeze/unfreeze/suspend_peer/
        // unsuspend_peer) are never called from this file at all; see
        // control.rs for the local admin channel that calls them, and
        // capability_isolation.rs's
        // capability_dispatch_has_zero_references_to_kill_switch_mutators_today
        // test for the enforced proof.
        axiom_gateway::PolicyOutcome::Suspended => {
            debug!(
                "Rejecting {} from {} - this identity is suspended by the local kill switch",
                name, hex::encode(sender_id.as_bytes())
            );
            return build_error_frame(&ctx.identity, intent_hash, trace_id, "suspended by kill switch", reply_routing);
        }
        axiom_gateway::PolicyOutcome::Frozen => {
            debug!(
                "Rejecting {} from {} - Tier1+ execution is frozen by the local kill switch",
                name, hex::encode(sender_id.as_bytes())
            );
            return build_error_frame(&ctx.identity, intent_hash, trace_id, "tier1+ execution frozen by kill switch", reply_routing);
        }
        axiom_gateway::PolicyOutcome::Allowed(permit) => permit,
    };
    let _permit = permit; // held until this fn returns, released on drop

    match name {
        // Fulfill by returning the payload unchanged.
        "echo" => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, payload, reply_routing),
        // Real system facts, no payload input needed - proves a second
        // genuine (non-echo) capability end to end: any peer can ask THIS
        // node "what are you" without needing direct network/SSH access to
        // it, authenticated by its signed identity rather than by IP/
        // network position.
        "sysinfo" => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, collect_sysinfo(), reply_routing),
        "network_clients" => dispatch_network_clients(ctx, intent_hash, trace_id, reply_routing).await,
        "notify_send" => dispatch_notify_send(ctx, intent_hash, trace_id, payload, reply_routing).await,
        "proxmox_restart" => dispatch_proxmox_restart(ctx, intent_hash, trace_id, payload, reply_routing).await,
        "home_assistant_toggle" => dispatch_home_assistant_toggle(ctx, intent_hash, trace_id, payload, reply_routing).await,
        "docker_restart" => dispatch_docker_restart(ctx, intent_hash, trace_id, payload, reply_routing).await,
        "wg_peers_list" => dispatch_wg_peers_list(ctx, intent_hash, trace_id, reply_routing).await,
        "wg_peer_manage" => dispatch_wg_peer_manage(ctx, intent_hash, trace_id, payload, sender_id, reply_routing).await,
        _ => build_error_frame(&ctx.identity, intent_hash, trace_id, "capability recognized but has no handler", reply_routing),
    }
}

/// The `"network_clients"` sub-path of `dispatch_intent` - kept as its own
/// function since it's the only capability with real async work (the UAI
/// HTTP round trip) beyond a plain name match. Allowlist/rate-limit/
/// concurrency gating and the WAN hard-deny both happen in `dispatch_intent`
/// itself now (AXIOM Phase 1.1, uniform across every capability) - by the
/// time this runs, `ctx.policy` has already granted (and is holding a
/// permit for) this exact request.
async fn dispatch_network_clients(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    match ctx.uai_config.as_ref() {
        None => build_error_frame(&ctx.identity, intent_hash, trace_id, "network_clients not configured on this node", reply_routing),
        Some(uai) => match fetch_network_clients(uai).await {
            Ok(json) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, json.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    }
}

/// The `"notify_send"` sub-path of `dispatch_intent` - sends the Intent's
/// payload as a push notification via UAI's `ntfy` driver
/// (`ntfy_send` tool). Tier1 (see `DECISIONS.md`'s "Tier model" section):
/// reaches an external system and exercises a UAI credential, same as
/// `network_clients`, but is neither destructive nor security-relevant
/// (worst case an allowlisted peer causes an unwanted notification -
/// bounded by this capability's own rate limit/concurrency in
/// `capability_policy.toml`), so it's Tier1, not Tier2.
///
/// Requires BOTH `ctx.uai_config` and `ctx.notify_topic` to be set - see
/// `NodeConfig::notify_topic`'s doc comment for why this is a second,
/// independent "not configured" knob rather than folding into
/// `uai_config` alone the way `network_clients` gets away with a single
/// knob (network_clients has no per-capability destination to configure;
/// notify_send does - the topic).
///
/// Unlike `network_clients`, whose only inputs come from node config (see
/// `axiom_gateway::policy`'s module doc comment on that distinction),
/// `notify_send`'s payload IS caller-supplied - it's the message text a
/// peer wants delivered. See `prepare_notify_message`'s doc comment for
/// how that untrusted input is bounded before it ever reaches UAI.
async fn dispatch_notify_send(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    match (ctx.uai_config.as_ref(), ctx.notify_topic.as_ref()) {
        (Some(uai), Some(topic)) => match send_notification(uai, topic, &payload).await {
            Ok(reply) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, reply.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
        _ => build_error_frame(&ctx.identity, intent_hash, trace_id, "notify_send not configured on this node", reply_routing),
    }
}

/// AXIOM proxmox_restart: which class of Proxmox guest a
/// `"proxmox_restart"` Intent targets - an LXC container (`pct`, UAI's
/// `proxmox_lxc` driver, `lxc_restart` tool) or a QEMU/KVM VM (`qm`, UAI's
/// `proxmox_vms` driver, `vm_reset` tool). There is no single Proxmox CLI
/// verb that restarts either kind uniformly - `pct`/`qm` are separate
/// tools with separate ID namespaces that happen to overlap numerically
/// (a VMID like `120` could in principle name either an LXC or a VM), so
/// the caller must say which one it means rather than AXIOM guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxmoxResourceKind {
    Lxc,
    Vm,
}

impl ProxmoxResourceKind {
    fn as_str(&self) -> &'static str {
        match self {
            ProxmoxResourceKind::Lxc => "lxc",
            ProxmoxResourceKind::Vm => "vm",
        }
    }

    /// The UAI tool this kind's restart maps to. `Vm` maps to `vm_reset`
    /// (a hard reset, UAI's `proxmox_vms` driver has no separate graceful
    /// "restart" tool - only `vm_shutdown`+`vm_start` as two steps, or
    /// `vm_reset` as one) - see `restart_proxmox_resource`'s own doc
    /// comment for why one UAI call, not two, is what this capability
    /// deliberately offers.
    fn uai_tool_name(&self) -> &'static str {
        match self {
            ProxmoxResourceKind::Lxc => "lxc_restart",
            ProxmoxResourceKind::Vm => "vm_reset",
        }
    }
}

/// A parsed, validated `"proxmox_restart"` target - never holds `vmid ==
/// 0` (Proxmox's own reserved/invalid sentinel; no real guest is ever
/// assigned it) because `parse_proxmox_restart_target` refuses to
/// construct one that does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxmoxRestartTarget {
    kind: ProxmoxResourceKind,
    vmid: u32,
}

impl ProxmoxRestartTarget {
    /// Canonical `"<kind>:<vmid>"` form - what actually gets checked
    /// against `capability_policy.toml`'s `denied_param_substrings` for
    /// this capability (see `dispatch_proxmox_restart`), and what's
    /// embedded in this capability's own log/Fulfill text. Deterministic
    /// (always `kind.as_str()` then `:` then the plain decimal VMID) so a
    /// denylist entry like `"120"` reliably matches regardless of how the
    /// caller originally formatted their request.
    fn canonical(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.vmid)
    }
}

/// Parse a `"proxmox_restart"` Intent payload - UTF-8 text of the form
/// `"lxc:<vmid>"` or `"vm:<vmid>"` (e.g. `"lxc:120"`), the same
/// plain-text-payload convention `notify_send`'s message established
/// (this capability has no reason to invent a JSON/binary shape neither
/// existing capability uses - see this build's own final report for why
/// that convention, not a new one, was followed here). Pure/sync, no
/// network - directly unit-testable, same precedent as
/// `prepare_notify_message`.
///
/// Deliberately rejects, as basic input validation rather than a policy
/// concern (see `dispatch_proxmox_restart`'s own doc comment for where the
/// POLICY-level protected-VMID check happens instead):
/// - an empty or whitespace-only payload ("no target specified" is never a
///   valid restart request - there is no such thing as a default/wildcard
///   target for a destructive-adjacent action like this);
/// - a `kind` that isn't exactly `"lxc"` or `"vm"`;
/// - a `vmid` that doesn't parse as a plain non-negative decimal integer;
/// - `vmid == 0` - Proxmox's own reserved sentinel value, never a real
///   guest's ID (`pct`/`qm` both refuse to create a guest with this ID),
///   so accepting it here could only ever be a caller error or a
///   deliberate probe, never a legitimate request.
fn parse_proxmox_restart_target(payload: &[u8]) -> Result<ProxmoxRestartTarget, String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("proxmox_restart: payload is empty - expected 'lxc:<vmid>' or 'vm:<vmid>'".to_string());
    }
    let Some((kind_str, vmid_str)) = trimmed.split_once(':') else {
        return Err(format!(
            "proxmox_restart: '{trimmed}' is not in the expected 'lxc:<vmid>' or 'vm:<vmid>' form"
        ));
    };
    let kind = match kind_str.trim().to_ascii_lowercase().as_str() {
        "lxc" => ProxmoxResourceKind::Lxc,
        "vm" => ProxmoxResourceKind::Vm,
        other => return Err(format!("proxmox_restart: unknown resource kind '{other}' - expected 'lxc' or 'vm'")),
    };
    let vmid: u32 = vmid_str.trim().parse().map_err(|_| {
        format!("proxmox_restart: '{}' is not a valid VMID (expected a positive integer)", vmid_str.trim())
    })?;
    if vmid == 0 {
        return Err("proxmox_restart: VMID 0 is never a real guest - refusing".to_string());
    }
    Ok(ProxmoxRestartTarget { kind, vmid })
}

/// AXIOM proxmox_restart: bridge for the `"proxmox_restart"` capability -
/// restarts a Proxmox LXC container (`pct reboot`, via UAI's `proxmox_lxc`
/// driver's `lxc_restart` tool) or hard-resets a QEMU/KVM VM (`qm reset`,
/// via `proxmox_vms`'s `vm_reset` tool), through the SAME `uai_dispatch`
/// helper `fetch_network_clients`/`send_notification` already use - one
/// more backend, same shared HTTP-POST shape, not a second hand-rolled
/// client.
///
/// Deliberately a single UAI call, not `lxc_shutdown`+`lxc_start` (or
/// `vm_shutdown`+`vm_start`) as two steps: `lxc_restart`/`vm_reset` are
/// each already one atomic Proxmox-side operation (`pct reboot`/`qm
/// reset`), and splitting it into two AXIOM-orchestrated UAI calls would
/// only add a window where the guest is confirmed stopped but not yet
/// restarted if AXIOM's own process were killed between the two calls -
/// strictly worse, for zero benefit, than letting Proxmox's own already-
/// atomic verb do it.
///
/// No `keepass_lookup` call anywhere in this path (same reason
/// `send_notification` doesn't call it either - see that function's own
/// doc comment): both `proxmox_lxc`/`proxmox_vms` UAI drivers authenticate
/// to the Proxmox host using a private key file UAI holds in ITS OWN
/// configuration, resolved entirely on UAI's side and never supplied by
/// AXIOM's request, not a credential AXIOM fetches and forwards - this
/// capability's request body carries only `{vmid}`, nothing
/// credential-shaped, same narrower-usage property `send_notification`
/// has relative to `fetch_network_clients`.
/// See this build's own final report for the fuller trust-calculus
/// writeup (this specific UAI deployment happens to run ON the same
/// Proxmox host this capability targets, which changes what "the
/// credential is exfiltrated" would even mean here relative to
/// `network_clients`'s Omada case).
async fn restart_proxmox_resource(uai: &UaiConfig, target: &ProxmoxRestartTarget) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let resp = uai_dispatch(&client, uai, target.kind.uai_tool_name(), serde_json::json!({
        "vmid": target.vmid,
    })).await?;

    Ok(format!(
        "restarted {} (uai ok={})",
        target.canonical(),
        resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
    ))
}

/// The `"proxmox_restart"` sub-path of `dispatch_intent` - restarts a
/// Proxmox LXC container or hard-resets a VM by ID, via UAI's
/// `proxmox_lxc`/`proxmox_vms` drivers. Tier1 (see `DECISIONS.md`'s "Tier
/// model" section): reaches an external system (UAI, which in turn talks
/// to the Proxmox host over SSH) and exercises a UAI credential, and -
/// unlike `notify_send` - performs a real, if reversible, write against
/// live infrastructure (a container/VM reboot). Reversible and
/// no-data-loss by construction (a restart is exactly what
/// fleet-watchdog/ai_fixer already do routinely against these same guests
/// today via the same UAI tools - this capability makes that existing,
/// already-trusted operation reachable over AXIOM's peer-authenticated
/// transport instead of only from scripts with direct UAI access), which
/// is why this is Tier1, not Tier2 - see this build's final report for the
/// full tier-assignment reasoning.
///
/// Requires `ctx.uai_config` (same single-knob shape `network_clients`
/// uses, not `notify_send`'s two-knob uai_config+notify_topic - this
/// capability has no per-node destination to configure beyond "which UAI
/// broker").
///
/// AXIOM Phase 3.6: the protected-resource / argument-constraint check
/// happens HERE, via `ctx.policy.check_denied_param_substrings` - the
/// SAME mechanism (and the same `CapabilityPolicy` instance) Phase 3.6
/// built for exactly this purpose, reused rather than reimplemented (see
/// `axiom_gateway::policy`'s module doc comment, "Also lands here" /
/// `denied_param_substrings`). This is the first LIVE Tier1 call site to
/// actually invoke it: `network_clients`/`notify_send` never take a
/// caller-supplied identifier worth denylisting this way (`network_clients`
/// takes no caller input at all; `notify_send`'s payload is free-text, not
/// a resource identifier). `capability_policy.toml`'s
/// `[capability.proxmox_restart].denied_param_substrings` carries the
/// VMID of `claude-host` (CT120) - the LXC container this host's own
/// Claude Code control-plane sessions run in (see this build's final
/// report for why this is the closest real analog to "AXIOM's own
/// container" available on THIS deployment, where forge-node itself runs
/// directly on Proxmox bare metal rather than inside a guest). VMID `0`
/// and an empty/malformed target are refused unconditionally in
/// `parse_proxmox_restart_target` instead (a data-validation concern, not
/// a per-deployment policy choice - see that function's own doc comment).
async fn dispatch_proxmox_restart(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    let target = match parse_proxmox_restart_target(&payload) {
        Ok(t) => t,
        Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
    };

    if let Some(reason) = ctx.policy.check_denied_param_substrings(
        "proxmox_restart",
        &[Constraint::string("target", target.canonical())],
    ) {
        warn!("Rejecting proxmox_restart targeting {}: {}", target.canonical(), reason);
        return build_error_frame(&ctx.identity, intent_hash, trace_id, &reason, reply_routing);
    }

    match ctx.uai_config.as_ref() {
        None => build_error_frame(&ctx.identity, intent_hash, trace_id, "proxmox_restart not configured on this node", reply_routing),
        Some(uai) => match restart_proxmox_resource(uai, &target).await {
            Ok(reply) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, reply.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    }
}

/// AXIOM home_assistant_toggle: which action a `"home_assistant_toggle"`
/// Intent requests against an entity - maps 1:1 to UAI's `homeassistant`
/// driver's own `ha_turn_on`/`ha_turn_off`/`ha_toggle` tools (each a thin
/// wrapper over HA's `<domain>.turn_on`/`turn_off`/`toggle` service call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HaAction {
    On,
    Off,
    Toggle,
}

impl HaAction {
    fn as_str(&self) -> &'static str {
        match self {
            HaAction::On => "on",
            HaAction::Off => "off",
            HaAction::Toggle => "toggle",
        }
    }

    fn uai_tool_name(&self) -> &'static str {
        match self {
            HaAction::On => "ha_turn_on",
            HaAction::Off => "ha_turn_off",
            HaAction::Toggle => "ha_toggle",
        }
    }
}

/// AXIOM home_assistant_toggle: the small, explicitly-allowlisted set of
/// Home Assistant entity DOMAINS this capability may act on. This is a
/// HARD ALLOWLIST enforced here in code, not a policy-file concern - see
/// this build's own final report and DECISIONS.md's Tier model for the
/// full reasoning. UAI's `homeassistant` driver
/// (`/mnt/Main/appdata/uai/drivers/homeassistant.py`) exposes a generic
/// `ha_turn_on`/`ha_turn_off`/`ha_toggle`/`ha_call_service` surface with NO
/// entity-domain restriction of its own - it will happily call
/// `lock.turn_off` (unlocks a door), `cover.turn_off`/`toggle` (garage
/// doors - HA models these as `cover` entities, same domain as blinds/
/// curtains), or `alarm_control_panel.turn_off`/`toggle` if asked, because
/// Home Assistant's own REST API has no concept of "safe" vs
/// "security-relevant" domains. That judgment call has to be made here, in
/// AXIOM, before the request ever reaches UAI - `parse_ha_toggle_target`
/// is the one and only place it's made, and it fails closed (rejects) for
/// anything not on this list, rather than trying to enumerate every unsafe
/// domain and hoping the list is complete.
///
/// Deliberately EXCLUDED, even though technically reachable through the
/// SAME UAI driver/tools this capability calls under the hood:
/// - `lock` - could unlock a physical door.
/// - `cover` - garage doors, gates, but also blinds/curtains/awnings; HA
///   does not distinguish "cover that's a garage door" from "cover that's
///   window blinds" at the domain level, so there is no clean way to allow
///   the safe subset without also allowing the unsafe one - excluding the
///   whole domain is the conservative call this task's own instructions
///   asked for on exactly this kind of ambiguity.
/// - `alarm_control_panel` - could disarm a security system.
/// - `valve` - physical water/gas shutoff.
/// - `siren` - a physical security/safety alerting device.
/// - `camera` - not itself a physical-security actuator, but privacy/
///   recording-relevant; out of scope for a first "lights and switches"
///   capability.
/// - `climate` / `water_heater` / `humidifier` - can affect real physical
///   conditions (heat/cold, humidity) unattended over a long period;
///   plausibly safe but not "obviously low-blast-radius" the way a light
///   is, so deliberately left for a dedicated follow-up decision rather
///   than bundled in here.
///
/// ALLOWED: `light`, `switch`, `fan`, `input_boolean` (all support
/// on/off/toggle symmetrically), and `scene` (activate-only - see
/// `parse_ha_toggle_target`'s own check for why `scene` rejects off/
/// toggle: Home Assistant has no `scene.turn_off`/`scene.toggle` service).
const ALLOWED_HA_DOMAINS: &[&str] = &["light", "switch", "fan", "input_boolean", "scene"];

/// A parsed, validated `"home_assistant_toggle"` target - never holds a
/// domain outside `ALLOWED_HA_DOMAINS` and never holds `action == Off` or
/// `Toggle` paired with the `scene` domain, because
/// `parse_ha_toggle_target` refuses to construct one that does.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HaToggleTarget {
    action: HaAction,
    entity_id: String,
}

impl HaToggleTarget {
    /// Canonical `"<action>:<entity_id>"` form - what actually gets
    /// checked against `capability_policy.toml`'s `denied_param_substrings`
    /// for this capability (see `dispatch_home_assistant_toggle`), and
    /// what's embedded in this capability's own log/Fulfill text.
    /// Deterministic, same convention `ProxmoxRestartTarget::canonical`
    /// established.
    fn canonical(&self) -> String {
        format!("{}:{}", self.action.as_str(), self.entity_id)
    }
}

/// Parse a `"home_assistant_toggle"` Intent payload - UTF-8 text of the
/// form `"<on|off|toggle>:<entity_id>"` (e.g. `"on:light.living_room"`,
/// `"toggle:switch.desk_fan"`), the same plain-text-payload convention
/// `notify_send`/`proxmox_restart` established. Pure/sync, no network -
/// directly unit-testable.
///
/// Deliberately rejects, as basic input validation:
/// - an empty or whitespace-only payload, or a missing `:` separator;
/// - an `action` that isn't exactly `"on"`, `"off"`, or `"toggle"`;
/// - an `entity_id` that's empty or not in Home Assistant's own
///   `domain.object_id` form;
/// - **a `domain` outside `ALLOWED_HA_DOMAINS`** - the hard-deny that
///   matters most here; see that constant's own doc comment for the full
///   list of what's excluded and why;
/// - a `scene` entity paired with `off`/`toggle` - Home Assistant has no
///   such service for scenes (only `scene.turn_on` exists).
fn parse_ha_toggle_target(payload: &[u8]) -> Result<HaToggleTarget, String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("home_assistant_toggle: payload is empty - expected '<on|off|toggle>:<entity_id>'".to_string());
    }
    let Some((action_str, entity_id_str)) = trimmed.split_once(':') else {
        return Err(format!(
            "home_assistant_toggle: '{trimmed}' is not in the expected '<on|off|toggle>:<entity_id>' form"
        ));
    };
    let action = match action_str.trim().to_ascii_lowercase().as_str() {
        "on" => HaAction::On,
        "off" => HaAction::Off,
        "toggle" => HaAction::Toggle,
        other => return Err(format!("home_assistant_toggle: unknown action '{other}' - expected 'on', 'off', or 'toggle'")),
    };
    let entity_id = entity_id_str.trim();
    if entity_id.is_empty() {
        return Err("home_assistant_toggle: entity_id is empty".to_string());
    }
    let Some((domain, object_id)) = entity_id.split_once('.') else {
        return Err(format!("home_assistant_toggle: '{entity_id}' is not a valid entity_id (expected 'domain.object_id')"));
    };
    if domain.is_empty() || object_id.is_empty() {
        return Err(format!("home_assistant_toggle: '{entity_id}' is not a valid entity_id (expected 'domain.object_id')"));
    }
    if !ALLOWED_HA_DOMAINS.contains(&domain) {
        return Err(format!(
            "home_assistant_toggle: domain '{domain}' is not permitted - only {ALLOWED_HA_DOMAINS:?} are allowed \
             (locks, covers/garage doors, alarm panels, valves, sirens, cameras, and climate devices are \
             deliberately excluded - see parse_ha_toggle_target's doc comment)"
        ));
    }
    if domain == "scene" && action != HaAction::On {
        return Err(format!(
            "home_assistant_toggle: 'scene' entities only support 'on' (activation) - Home Assistant has no \
             scene off/toggle service, got action '{}'", action.as_str()
        ));
    }
    Ok(HaToggleTarget { action, entity_id: entity_id.to_string() })
}

/// AXIOM home_assistant_toggle: bridge for the `"home_assistant_toggle"`
/// capability - calls UAI's `homeassistant` driver's `ha_turn_on`/
/// `ha_turn_off`/`ha_toggle` tool (per `target.action`) with `{entity_id}`,
/// through the SAME `uai_dispatch` helper every other UAI-backed
/// capability uses - one more backend, same shared HTTP-POST shape, not a
/// second hand-rolled client.
///
/// No `keepass_lookup` call anywhere in this path, same reasoning
/// `send_notification`/`restart_proxmox_resource` already give: UAI's
/// `homeassistant` driver resolves its own long-lived HA access token from
/// its own config (`uai_secrets.json`'s `tokens.ha_token` / env, see the
/// driver's own module doc comment), never a credential AXIOM fetches and
/// forwards - this capability's request body carries only `{entity_id}`,
/// nothing credential-shaped.
async fn call_ha_action(uai: &UaiConfig, target: &HaToggleTarget) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let resp = uai_dispatch(&client, uai, target.action.uai_tool_name(), serde_json::json!({
        "entity_id": target.entity_id,
    })).await?;

    Ok(format!(
        "home_assistant_toggle {} (uai ok={})",
        target.canonical(),
        resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
    ))
}

/// The `"home_assistant_toggle"` sub-path of `dispatch_intent` - turns on,
/// turns off, or toggles a Home Assistant entity (light/switch/fan/
/// input_boolean/scene only - see `ALLOWED_HA_DOMAINS`) via UAI's
/// `homeassistant` driver. Tier1 (see `DECISIONS.md`'s "Tier model"
/// section): reaches an external system (UAI, which in turn talks to HA's
/// own REST API) and exercises a UAI credential, and performs a real, but
/// reversible and low-blast-radius, write (a light/switch/fan/scene state
/// change) - NOT Tier2, since the domain allowlist above already excludes
/// everything DECISIONS.md's Tier model would call destructive/
/// security-relevant (locks, garage doors/covers, alarm panels). Same
/// "reversible, bounded, narrow" reasoning `proxmox_restart` and
/// `notify_send` were assigned Tier1 under.
///
/// Requires `ctx.uai_config` (same single-knob shape `network_clients`/
/// `proxmox_restart` use - this capability has no per-node destination to
/// configure beyond "which UAI broker").
///
/// AXIOM Phase 3.6: the protected-resource / argument-constraint check
/// happens HERE, via `ctx.policy.check_denied_param_substrings` - same
/// mechanism `proxmox_restart` wired live first, reused rather than
/// reimplemented. This gives Larry a way to additionally denylist a
/// SPECIFIC entity_id (e.g. one that's domain-allowed in general but
/// happens to control something he doesn't want AXIOM touching) without
/// a code change - on top of, never instead of, the code-level domain
/// allowlist above, which cannot be loosened by policy at all.
async fn dispatch_home_assistant_toggle(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    let target = match parse_ha_toggle_target(&payload) {
        Ok(t) => t,
        Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
    };

    if let Some(reason) = ctx.policy.check_denied_param_substrings(
        "home_assistant_toggle",
        &[Constraint::string("target", target.canonical())],
    ) {
        warn!("Rejecting home_assistant_toggle targeting {}: {}", target.canonical(), reason);
        return build_error_frame(&ctx.identity, intent_hash, trace_id, &reason, reply_routing);
    }

    match ctx.uai_config.as_ref() {
        None => build_error_frame(&ctx.identity, intent_hash, trace_id, "home_assistant_toggle not configured on this node", reply_routing),
        Some(uai) => match call_ha_action(uai, &target).await {
            Ok(reply) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, reply.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    }
}

/// AXIOM docker_restart: the small, explicitly-allowlisted set of Docker
/// container NAMES this capability may ever restart on this Proxmox host.
/// This is a HARD ALLOWLIST enforced here in code, not a policy-file
/// concern - same posture `ALLOWED_HA_DOMAINS` established for
/// `home_assistant_toggle`, chosen over a denylist because this single
/// Proxmox host runs dozens of production containers (media pipeline,
/// pm-agent, this very UAI broker, Conduit, databases, VPN egress, ...) -
/// enumerating every DANGEROUS container would require the list to stay
/// perfectly in sync with an ever-changing fleet, where a single missed
/// entry is a real incident. An allowlist of specifically-vetted, low-risk
/// containers degrades safely instead: anything not named here is
/// refused, including every container stood up after this list was
/// written.
///
/// Each entry below was chosen because it is standalone (its own isolated
/// docker-compose project, confirmed via `docker inspect`'s
/// `com.docker.compose.project.config_files` label - no OTHER compose
/// file's `depends_on` references it), non-critical (nothing else breaks
/// or degrades if it's offline for the ~1-5 seconds a restart takes), and
/// NOT a dependency of AXIOM's own path to fulfilling this exact request
/// (UAI, forge-node) or of the coordination/management plane (pm-agent,
/// mystro, ops-monitor):
/// - `infra-watchtower` (`containrrr/watchtower`) - a stateless
///   container-image-update checker. It has no state of its own and
///   nothing depends on it being continuously up; a restart at worst
///   delays its next periodic update-check cycle.
/// - `lib-calibre-web` - a standalone ebook-library reading web UI. No
///   other service's compose file depends on it; a restart is a few
///   seconds of unavailability for anyone actively browsing it.
/// - `dl-bazarr` - a subtitle-fetching helper for the *arr media stack.
///   It shares a docker network with sonarr/radarr/qbittorrent but
///   nothing depends on IT being up - subtitle fetches simply resume on
///   their own next cycle, and it holds no data those other services
///   need to keep running.
/// - `ntl-snmpsim` - an SNMP simulator in the isolated `net-test-lab`
///   compose project, used for network-device-audit testing. An entirely
///   synthetic test fixture with zero production dependency by
///   construction.
///
/// Deliberately EXCLUDED even though "just a docker container" like the
/// above: `ai-uai` (AXIOM's own path to fulfilling ANY `docker_restart`
/// request runs through this container - restarting the thing this
/// capability depends on to work at all is the textbook footgun this
/// capability exists to avoid), `forge-node` itself, `pm-agent` and every
/// other coordination-plane container (`infra-mystro`, `infra-ops-monitor`,
/// `infra-notify`), every database container (`*-postgres-*`, `*-redis-*`,
/// `postgres-shared`, `paperless-pg`, `paperless-redis`), and any VPN/
/// egress container (`dl-vpn` (gluetun), `wg-easy`) - none of those were
/// close calls, so none are individually re-litigated here; see this
/// build's own final report for the full reasoning trail. `ai-uai` and
/// `forge-node`'s own name are additionally HARD-DENIED below
/// (`HARD_DENIED_DOCKER_CONTAINERS`), not merely left off this list - see
/// that constant's own doc comment for why omission alone isn't enough.
const ALLOWED_DOCKER_CONTAINERS: &[&str] = &["infra-watchtower", "lib-calibre-web", "dl-bazarr", "ntl-snmpsim"];

/// AXIOM docker_restart: names that can NEVER be targeted, checked BEFORE
/// `ALLOWED_DOCKER_CONTAINERS` and regardless of what that allowlist (or
/// any policy-file `denied_param_substrings` configuration) says - the
/// same "hard-deny in code, not just by omission" posture
/// `proxmox_restart`'s CT120 protection uses. `ai-uai` is the UAI broker
/// this exact capability's request travels through to reach Docker at
/// all - restarting it while fulfilling a request that depends on it
/// being up is an obvious footgun. `forge-node` is this Rust process
/// itself; on this deployment it runs directly on Proxmox bare metal, not
/// inside a container (see `ARCHITECTURE.md`), so no real container
/// should ever legitimately carry this name, but the check costs nothing
/// and closes the door if that ever changes. Compared case-insensitively -
/// deliberately broader than an exact match, mirroring `proxmox_restart`'s
/// own reasoning for denying `"vm:120"` as well as `"lxc:120"` even though
/// CT120 is only ever an LXC.
const HARD_DENIED_DOCKER_CONTAINERS: &[&str] = &["ai-uai", "forge-node"];

/// A parsed, validated `"docker_restart"` target - never holds a name
/// that fails basic shape validation, appears in
/// `HARD_DENIED_DOCKER_CONTAINERS`, or is absent from
/// `ALLOWED_DOCKER_CONTAINERS`, because `parse_docker_restart_target`
/// refuses to construct one that does.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerRestartTarget {
    name: String,
}

impl DockerRestartTarget {
    /// Canonical form - just the container name itself (there is only one
    /// kind of target here, unlike `proxmox_restart`'s lxc/vm split), used
    /// both for `capability_policy.toml`'s `denied_param_substrings` check
    /// and this capability's own log/Fulfill text.
    fn canonical(&self) -> &str {
        &self.name
    }
}

/// Parse a `"docker_restart"` Intent payload - UTF-8 text that is just the
/// target container's name (e.g. `"infra-watchtower"`), the same
/// plain-text-payload convention `notify_send`/`proxmox_restart`/
/// `home_assistant_toggle` established. Pure/sync, no network - directly
/// unit-testable.
///
/// Deliberately rejects, as basic input validation:
/// - an empty or whitespace-only payload, or one longer than 128
///   characters (real docker container names top out at 253 bytes per
///   the Docker Engine API, but every name on `ALLOWED_DOCKER_CONTAINERS`
///   is far shorter than 128 - this is generous headroom, not a tight
///   fit, and exists to give a clear error rather than let a pathological
///   input fall through to a definite allowlist-miss for a less obvious
///   reason);
/// - a name containing anything outside Docker's own legal
///   container-name charset (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`);
/// - **a name in `HARD_DENIED_DOCKER_CONTAINERS`** - checked before the
///   allowlist below, unconditionally;
/// - **a name not in `ALLOWED_DOCKER_CONTAINERS`** - the hard allowlist
///   that matters most here; see that constant's own doc comment for the
///   full list and reasoning.
fn parse_docker_restart_target(payload: &[u8]) -> Result<DockerRestartTarget, String> {
    let raw = String::from_utf8_lossy(payload);
    let name = raw.trim();
    if name.is_empty() {
        return Err("docker_restart: payload is empty - expected a container name".to_string());
    }
    if name.len() > 128 {
        return Err(format!("docker_restart: container name is too long ({} chars, max 128)", name.len()));
    }
    let mut chars = name.chars();
    let first_ok = chars.next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false);
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
    if !first_ok || !rest_ok {
        return Err(format!(
            "docker_restart: '{name}' is not a valid Docker container name (expected [a-zA-Z0-9][a-zA-Z0-9_.-]*)"
        ));
    }
    if HARD_DENIED_DOCKER_CONTAINERS.iter().any(|denied| denied.eq_ignore_ascii_case(name)) {
        return Err(format!(
            "docker_restart: '{name}' is hard-denied in code and can never be targeted, regardless of policy \
             (it is either AXIOM's own UAI broker path or forge-node itself)"
        ));
    }
    if !ALLOWED_DOCKER_CONTAINERS.contains(&name) {
        return Err(format!(
            "docker_restart: '{name}' is not on the allowlist - only {ALLOWED_DOCKER_CONTAINERS:?} may be \
             restarted via this capability (see parse_docker_restart_target's doc comment for why)"
        ));
    }
    Ok(DockerRestartTarget { name: name.to_string() })
}

/// AXIOM docker_restart: bridge for the `"docker_restart"` capability -
/// restarts a Docker container by name via UAI's `docker_desktop` driver's
/// `docker_restart` tool (`docker restart <name>`), through the SAME
/// `uai_dispatch` helper every other UAI-backed capability uses.
///
/// No `keepass_lookup` call anywhere in this path, same reasoning
/// `restart_proxmox_resource`/`call_ha_action` already give: the UAI
/// driver reaches Docker using access it holds in its own container
/// configuration (see this build's own final report for exactly what
/// that access is and how it was provisioned) - this capability's
/// request body carries only `{name}`, nothing credential-shaped.
async fn restart_docker_container(uai: &UaiConfig, target: &DockerRestartTarget) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let resp = uai_dispatch(&client, uai, "docker_restart", serde_json::json!({
        "name": target.canonical(),
    })).await?;

    Ok(format!(
        "docker_restart {} (uai ok={})",
        target.canonical(),
        resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
    ))
}

/// The `"docker_restart"` sub-path of `dispatch_intent` - restarts ONE
/// specific, hard-coded-safe Docker container on this Proxmox host (see
/// `ALLOWED_DOCKER_CONTAINERS`) via UAI's `docker_desktop` driver. Tier1
/// per DECISIONS.md's tier model: reaches an external system (UAI, which
/// in turn talks to the Docker daemon on this host) and exercises a UAI
/// credential, and performs a real, reversible write - NOT Tier2, because
/// the code-level allowlist keeps the actual blast radius bounded to four
/// specifically-vetted, non-critical containers, the same "reversible,
/// bounded, narrow" reasoning `proxmox_restart`/`home_assistant_toggle`
/// were assigned Tier1 under. This IS a higher blast-radius surface than
/// either of those, purely because of WHERE it points (this exact host
/// runs dozens of production containers) - see this build's own final
/// report for why the allowlist, not the tier, is what carries that extra
/// weight here.
///
/// Requires `ctx.uai_config` (same single-knob shape every other
/// UAI-backed capability uses).
///
/// AXIOM Phase 3.6: `ctx.policy.check_denied_param_substrings` is wired
/// the same way `proxmox_restart`/`home_assistant_toggle` wired it - an
/// ADDITIONAL, policy-file-editable layer on top of (never instead of)
/// the code-level allowlist/hard-deny above, so Larry can deny a specific
/// currently-allowlisted container later without a rebuild.
async fn dispatch_docker_restart(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    let target = match parse_docker_restart_target(&payload) {
        Ok(t) => t,
        Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
    };

    if let Some(reason) = ctx.policy.check_denied_param_substrings(
        "docker_restart",
        &[Constraint::string("target", target.canonical().to_string())],
    ) {
        warn!("Rejecting docker_restart targeting {}: {}", target.canonical(), reason);
        return build_error_frame(&ctx.identity, intent_hash, trace_id, &reason, reply_routing);
    }

    match ctx.uai_config.as_ref() {
        None => build_error_frame(&ctx.identity, intent_hash, trace_id, "docker_restart not configured on this node", reply_routing),
        Some(uai) => match restart_docker_container(uai, &target).await {
            Ok(reply) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, reply.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    }
}

/// AXIOM wg_peers_list: the read-only counterpart to notify_send/
/// proxmox_restart/home_assistant_toggle/docker_restart above - lists the
/// WireGuard VPN peers configured on this Proxmox host's wg-easy instance
/// via UAI's `wg_easy` driver's `wg_clients` tool, through the SAME
/// `uai_dispatch` helper every other UAI-backed capability uses.
///
/// # Why this ships as a narrow read-only slice, not full peer management
///
/// UAI's `wg_easy` driver (`/mnt/Main/appdata/uai/drivers/wg_easy.py`,
/// read in full before writing this) exposes 9 tools: `wg_clients` (list),
/// `wg_client` (get one), `wg_create_client`, `wg_delete_client`,
/// `wg_enable_client`, `wg_disable_client`, `wg_client_qr`,
/// `wg_client_config`, and `wg_rename_client`. Creating, deleting, or
/// enabling/disabling a VPN peer is an access-control decision - per
/// `DECISIONS.md`'s ratified Tier model ("Tier 2: destructive/
/// security-relevant... anything touching connectivity or auth"), that
/// class of action is Tier2, not Tier1 - the same bucket as a firewall
/// rule or a VLAN change. That would make it the FIRST real (non-mock)
/// capability ever wired through `axiom-gateway`'s Phase 3.3
/// `Tier2ApprovalFlow`/`ApprovalChannel` machinery, which today has
/// exactly one implementation (`CliApprovalChannel`, `approval.rs`) and is
/// fundamentally an INTERACTIVE stdin-prompt/stdout-write primitive -
/// see that module's own doc comment: "Primary, now: CLI prompt on the
/// management box" (`DECISIONS.md`'s "Tier-2 approval channel" section;
/// v2 phone-push is explicitly future work, "required before Tier 2
/// actions become *routine*... not required before the mock rehearsal or
/// before Phase 3 starts" - i.e. never asserted sufficient for a real,
/// network-reachable capability). `Tier2ApprovalFlow::decide_and_execute`
/// calls `ApprovalChannel::request_approval` SYNCHRONOUSLY and blocks on
/// it; for `CliApprovalChannel::stdio()` that is a blocking `read_line`
/// against real stdin.
///
/// This node's production instance is `forge-node.service`, a headless
/// systemd unit (`Type=simple`, `StandardOutput=journal`,
/// `StandardError=journal`, no `TTYPath`/`StandardInput=tty` configured -
/// confirmed by reading the real deployed unit file before writing this
/// comment) reacting asynchronously to signed Intent frames arriving over
/// the network from remote peers, with no guarantee anyone is sitting at
/// its console the moment a request arrives. Nothing anywhere in this
/// codebase (or in UAI, or in the ntfy-backed `notify_send` capability,
/// which only ever SENDS a one-way message and cannot receive a reply)
/// delivers a `CliApprovalChannel`-shaped prompt to a human and gets a
/// synchronous decision back, out-of-band, while a real network dispatch
/// is in flight. Wiring a genuinely destructive wg-easy action through the
/// CLI-only channel as it exists today would mean either the dispatch
/// task hangs forever waiting on a stdin nobody is attached to, or (the
/// likelier outcome - systemd's normal default for a service with no
/// configured `StandardInput` is `/dev/null`) `read_line` returns
/// immediate EOF and `CliApprovalChannel` auto-DENIES every single real
/// Tier 2 request, silently and permanently, with no observable
/// difference from "working as designed" until someone specifically goes
/// looking.
///
/// Per this task's own instruction ("if anything feels like it needs a
/// human call beyond what's scoped here, STOP and flag it clearly rather
/// than guessing"), building an ad hoc bridge between real network
/// dispatch and an interactive CLI prompt (a background thread blocking
/// on stdin, some new IPC channel to a separate approval-typing process,
/// etc.) was judged to be exactly that kind of guess: it would mean
/// inventing new security-relevant plumbing without an owner decision on
/// what "the management box" and "authenticated" even mean for a headless
/// daemon reacting to remote peers - a question `DECISIONS.md`'s "Tier-2
/// approval channel" section does not yet answer (it commits only to "CLI
/// prompt on the management box" as what Phase 3.3's MOCK rehearsal runs
/// against, never to that being sufficient for a real, network-reachable
/// capability). So: peer creation/deletion/enable/disable is NOT built in
/// this task - see this build's own final report for the full write-up of
/// that judgment call. This capability ships only `wg_clients` (list):
/// genuinely Tier1 (reaches an external system, exercises a UAI
/// credential - same reasoning `network_clients` is Tier1 despite being
/// read-only, per `DECISIONS.md`'s Tier model), carries no
/// access-control consequence of its own, and returns no key material -
/// see `fetch_wg_peers_list`'s own doc comment for why `wg_client_config`/
/// `wg_client_qr` (which DO return private-key-bearing data) are not
/// wired to anything here at all.
async fn dispatch_wg_peers_list(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    match ctx.uai_config.as_ref() {
        None => build_error_frame(&ctx.identity, intent_hash, trace_id, "wg_peers_list not configured on this node", reply_routing),
        Some(uai) => match fetch_wg_peers_list(uai).await {
            Ok(json) => build_fulfill_frame(&ctx.identity, intent_hash, trace_id, json.into_bytes(), reply_routing),
            Err(e) => build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    }
}

/// AXIOM wg_peers_list: single UAI call (wg-easy's `wg_clients` tool -
/// `GET /api/clients` against wg-easy). No `keepass_lookup` first - same
/// reasoning `send_notification`/`call_ha_action` already give: UAI's
/// `wg_easy` driver resolves its own wg-easy session password from its
/// own config (`uai_secrets.json`'s `tokens.wg_easy_pass` / env), never a
/// credential AXIOM fetches and forwards.
///
/// Deliberately calls ONLY `wg_clients` (`WGEasyDriver.list_clients`, read
/// straight from the driver's own source before writing this function):
/// it returns `{id, name, address, enabled, connected, transfer_rx,
/// transfer_tx, last_handshake}` per peer - no `privateKey`/`publicKey`
/// field at all. `wg_client_config`/`wg_client_qr` (the driver's other two
/// read-shaped tools) hit wg-easy's `/clients/{id}/configuration` endpoint
/// instead, which returns the actual `.conf` file content - that DOES
/// embed the peer's WireGuard private key in cleartext. Neither of those
/// two tools is called anywhere in this function, or reachable from this
/// capability at all - not an oversight, but the entire reason this
/// capability's safety argument (see `dispatch_wg_peers_list`'s own doc
/// comment) holds: it never calls a tool that CAN return key material, so
/// there is no code path here for a future bug to accidentally leak one
/// through.
///
/// AXIOM Phase 3.7: like `fetch_network_clients`'s Omada reply, a wg-easy
/// peer's `name` field is attacker-influenceable content - whoever creates
/// a WireGuard peer (today: manual wg-easy admin access only; nothing in
/// this codebase can create one - see `dispatch_wg_peers_list`'s doc
/// comment) chooses that peer's name freely, the same "attacker-chosen
/// string that flows into an AI's context" threat model `SECURITY.md`'s
/// "Untrusted-content handling" section describes for device hostnames/
/// SSIDs. Passed through `axiom_gateway::sanitize::sanitize_and_wrap_
/// untrusted_json` before this function returns, same as
/// `fetch_network_clients` - the raw backend reply itself never leaves
/// this function.
async fn fetch_wg_peers_list(uai: &UaiConfig) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let clients = uai_dispatch(&client, uai, "wg_clients", serde_json::json!({})).await?;

    let sanitized = axiom_gateway::sanitize::sanitize_and_wrap_untrusted_json(
        "wg_peers_list (WireGuard peer records via UAI/wg-easy)",
        clients,
    );
    Ok(sanitized.to_string())
}

// =====================================================================
// AXIOM Tier 2: wg_peer_manage - the first REAL (non-mock) Tier 2
// capability wired through axiom-gateway's Phase 3.3 Tier2ApprovalFlow.
// =====================================================================
//
// `wg_peers_list`'s own commit (399508b) shipped ONLY the read-only
// `wg_clients` (list) tool and explicitly declined to build create/delete/
// enable/disable, because the only ApprovalChannel implementation that
// existed then (`CliApprovalChannel`) needs an interactive TTY forge-node's
// production systemd service doesn't have - see that commit's own "THE
// JUDGMENT CALL" writeup. `telegram_approval.rs` (this build) is that
// missing piece: a second, headless-friendly `ApprovalChannel` impl. This
// capability is what it exists to unblock.
//
// # Wire-timing judgment call (read before touching this function)
//
// A real Tier 2 approval can legitimately take up to `DEFAULT_EXPIRY` (15
// minutes) - Larry needs to see the Telegram message and tap a button.
// This node's EXISTING request/reply timing constants were sized for a
// completely different scale: `INTENT_TIMEOUT` (25s) is how long a peer's
// own `request_intent()` call waits for a Fulfill/Error before giving up,
// and `REVERSE_ROUTE_TTL` (2x that, 50s) is how long a multi-hop relay's
// reverse-path breadcrumb survives - both are part of
// `ARCHITECTURE.md`'s frozen Phase 1 transport surface ("the multi-hop
// relay / reverse-path-breadcrumb ... behavior it plugs into via the
// shared dispatch layer" is explicitly named as frozen). Widening either
// one for this one capability was judged out of scope - a transport-layer
// change requiring its own owner decision per that freeze, not a decision
// this task should make unilaterally for a single capability.
//
// So: this function does NOT block the wire-level reply on the full
// propose -> Telegram -> approve/deny -> execute cycle. It runs the
// PROTECTED-RESOURCE / policy-denylist / target-exists checks
// SYNCHRONOUSLY (fast, so a request that was never going to be allowed
// gets a real Error reply, and - critically - Larry never sees a Telegram
// prompt for it at all, matching Phase 3.6's own "the owner never even
// sees an approval request for it" guarantee), then PROPOSES the Tier 2
// intent (fast - `Tier2ApprovalFlow::propose` does not itself contact
// Telegram), then hands the actual approve/deny/execute cycle to a
// detached `tokio::spawn` that is NOT on this request's reply path, and
// immediately returns a Fulfill ACKNOWLEDGING the proposal (intent id,
// action, target, expiry) - not the eventual create/delete/enable/disable
// OUTCOME, which is not yet known when this function returns. A caller
// that needs the real outcome checks `wg_peers_list` afterward, or (once a
// capability exists to read it - not built by this task) the audit log.
// This is documented here as explicitly as `wg_peers_list`'s own judgment
// call was, per this task's own instruction to flag rather than silently
// guess - see this build's own final report for the full write-up.

/// Peer names Larry is actually, currently relying on for real remote
/// access - confirmed live against UAI's `wg_clients` tool before writing
/// this list, not guessed (`larry-laptop` = 10.8.0.2, `phone` = 10.8.0.3,
/// both `enabled=true` at the time of this build). `DECISIONS.md`'s
/// protected-resource list already calls out `wg0`/the laptop's WireGuard
/// client by name as "management-plane-adjacent (remote access into the
/// network) even though it can't fit the MAC-based enforcement model" -
/// this is that same concern, enforced the only way it CAN be for a
/// WireGuard peer (by its wg-easy display name, not a MAC/IP): a HARD
/// DENY in code, checked before the allowlist/policy/Tier2-approval layers
/// even run, same "hard-deny in code, not just by omission" posture
/// `docker_restart`'s `HARD_DENIED_DOCKER_CONTAINERS` and
/// `proxmox_restart`'s CT120 protection both already use. Applies ONLY to
/// `delete`/`disable` (the two actions that REDUCE access) - `create`
/// (any name, even a duplicate of one of these) and `enable` are lower-risk,
/// additive/restorative actions with no footgun to guard against here.
/// Compared case-insensitively, same reasoning those two precedents give.
const HARD_DENIED_WG_PEER_TARGETS: &[&str] = &["larry-laptop", "phone"];

const MAX_WG_PEER_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WgPeerAction {
    Create,
    Delete,
    Enable,
    Disable,
}

impl WgPeerAction {
    fn as_str(&self) -> &'static str {
        match self {
            WgPeerAction::Create => "create",
            WgPeerAction::Delete => "delete",
            WgPeerAction::Enable => "enable",
            WgPeerAction::Disable => "disable",
        }
    }

    /// `true` for the two actions `HARD_DENIED_WG_PEER_TARGETS` gates -
    /// see that constant's own doc comment.
    fn reduces_access(&self) -> bool {
        matches!(self, WgPeerAction::Delete | WgPeerAction::Disable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WgPeerManageTarget {
    action: WgPeerAction,
    name: String,
}

/// Parse a `"wg_peer_manage"` Intent payload - `"<create|delete|enable|
/// disable>:<peer name>"`, the same `"<action>:<target>"` plain-text
/// convention `home_assistant_toggle`'s `parse_ha_toggle_target` already
/// established for a multi-field capability payload (see that function).
/// `name` is wg-easy's human-readable peer NAME (what `wg_peers_list`
/// itself returns, and what a caller would have seen from that capability),
/// never wg-easy's internal client UUID - resolving name -> id is
/// `dispatch_wg_peer_manage`'s own job (a live UAI call, so it can't happen
/// in this pure/sync parse step). Pure/sync, no network - directly
/// unit-testable.
fn parse_wg_peer_manage_target(payload: &[u8]) -> Result<WgPeerManageTarget, String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("wg_peer_manage: payload is empty - expected '<create|delete|enable|disable>:<peer name>'".to_string());
    }
    let Some((action_str, name_str)) = trimmed.split_once(':') else {
        return Err(format!(
            "wg_peer_manage: '{trimmed}' is not in the expected '<create|delete|enable|disable>:<peer name>' form"
        ));
    };
    let action = match action_str.trim().to_ascii_lowercase().as_str() {
        "create" => WgPeerAction::Create,
        "delete" => WgPeerAction::Delete,
        "enable" => WgPeerAction::Enable,
        "disable" => WgPeerAction::Disable,
        other => return Err(format!("wg_peer_manage: unknown action '{other}' - expected 'create', 'delete', 'enable', or 'disable'")),
    };
    let name = name_str.trim();
    if name.is_empty() {
        return Err("wg_peer_manage: peer name is empty".to_string());
    }
    if name.len() > MAX_WG_PEER_NAME_LEN {
        return Err(format!("wg_peer_manage: peer name is too long ({} chars, max {})", name.len(), MAX_WG_PEER_NAME_LEN));
    }
    let mut chars = name.chars();
    let first_ok = chars.next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false);
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == ' ');
    if !first_ok || !rest_ok {
        return Err(format!(
            "wg_peer_manage: '{name}' is not a valid peer name (expected to start with a letter/digit, and contain only \
             letters, digits, spaces, '_', '.', '-')"
        ));
    }
    if action.reduces_access() && HARD_DENIED_WG_PEER_TARGETS.iter().any(|denied| denied.eq_ignore_ascii_case(name)) {
        return Err(format!(
            "wg_peer_manage: '{name}' is hard-denied in code for '{}' and can never be targeted by it, regardless of \
             policy - it is one of Larry's own currently-relied-upon WireGuard peers (see \
             HARD_DENIED_WG_PEER_TARGETS's own doc comment)",
            action.as_str()
        ));
    }
    Ok(WgPeerManageTarget { action, name: name.to_string() })
}

/// Look up a WireGuard peer by its wg-easy display NAME via UAI's
/// `wg_clients` (list) tool - the exact same read-only tool
/// `fetch_wg_peers_list` uses, reused here rather than inventing a second
/// lookup. Returns `Ok(None)` if no peer with this exact name exists (a
/// clean, expected outcome for e.g. `create` colliding-check or a stale
/// `delete` target - NOT an error). `(client_id, enabled, connected)` -
/// enough for `WgPeerManageCapability::dry_run` to show a real
/// current-state diff without a second network call.
async fn resolve_wg_peer_by_name(uai: &UaiConfig, name: &str) -> Result<Option<(String, bool, bool)>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;
    let resp = uai_dispatch(&client, uai, "wg_clients", serde_json::json!({})).await?;
    let clients = resp.get("clients").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for c in &clients {
        if c.get("name").and_then(|v| v.as_str()) == Some(name) {
            let id = c.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = c.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let connected = c.get("connected").and_then(|v| v.as_bool()).unwrap_or(false);
            return Ok(Some((id, enabled, connected)));
        }
    }
    Ok(None)
}

/// The `Tier2Capability` this capability proposes/executes against - see
/// `axiom_gateway::approval::Tier2Capability`'s own doc comment for the
/// contract. Holds everything `execute` needs to actually perform the
/// action WITHOUT another network round trip to re-derive it (the target
/// was already resolved once, in `dispatch_wg_peer_manage`, before
/// proposing - re-resolving at execute time would be redundant and would
/// reopen a target-vanished race that resolving up front already
/// minimizes, though not eliminates - see `execute`'s own doc comment).
struct WgPeerManageCapability {
    uai: UaiConfig,
    /// Bridges this trait's synchronous `execute`/`dry_run` methods to the
    /// real async UAI HTTP call - see `telegram_approval.rs`'s own
    /// top-of-file doc comment, "Bridging a synchronous trait method to
    /// async I/O", for why this is safe ONLY when `execute` is reached
    /// from inside `tokio::task::spawn_blocking` (which
    /// `dispatch_wg_peer_manage` guarantees - see its own doc comment).
    runtime: tokio::runtime::Handle,
    action: WgPeerAction,
    name: String,
    /// wg-easy's internal client UUID - `None` for `create` (doesn't exist
    /// yet), `Some(id)` for delete/enable/disable (resolved by
    /// `resolve_wg_peer_by_name` before this was constructed).
    resolved_id: Option<String>,
    prior_enabled: bool,
}

impl WgPeerManageCapability {
    /// The actual UAI call - split out from `execute` purely so
    /// `execute`'s own body can stay a one-line `self.runtime.block_on(...)`
    /// bridge, matching this codebase's existing style of keeping the
    /// sync/async boundary itself trivially readable.
    ///
    /// Calls ONLY `wg_create_client`/`wg_delete_client`/`wg_enable_client`/
    /// `wg_disable_client` - never `wg_client_config`/`wg_client_qr` (which
    /// return the peer's WireGuard PRIVATE KEY in cleartext), the exact
    /// same exclusion `fetch_wg_peers_list` already established for the
    /// read side (see that function's own doc comment) extended to the
    /// write side here. `wg_create_client`'s own real response DOES embed
    /// the newly-created peer's private key (that is simply how wg-easy's
    /// client-provisioning flow works) - this function extracts ONLY the
    /// new peer's `id` field out of that response and discards everything
    /// else; the full response is never logged, never included in the
    /// `Ok(String)` returned to `Tier2ApprovalFlow` (which becomes this
    /// intent's audit-log entry AND the dry-run/decision text a human
    /// reads), and never forwarded anywhere. See
    /// `capability_isolation.rs`'s `wg_peer_manage`-specific regression
    /// tests for the enforced proof.
    async fn perform(&self) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| format!("building HTTP client: {e}"))?;
        match self.action {
            WgPeerAction::Create => {
                let resp = uai_dispatch(&client, &self.uai, "wg_create_client", serde_json::json!({"name": self.name})).await?;
                let new_id = resp.get("data").and_then(|d| d.get("id")).and_then(|v| v.as_str()).unwrap_or("(unknown id)");
                Ok(format!("wg_peer_manage create '{}' succeeded (new id={})", self.name, new_id))
            }
            WgPeerAction::Delete => {
                let id = self.resolved_id.as_deref().ok_or_else(|| "internal error: no resolved client id for delete".to_string())?;
                uai_dispatch(&client, &self.uai, "wg_delete_client", serde_json::json!({"client_id": id})).await?;
                Ok(format!("wg_peer_manage delete '{}' succeeded (id={})", self.name, id))
            }
            WgPeerAction::Enable | WgPeerAction::Disable => {
                let id = self.resolved_id.as_deref().ok_or_else(|| "internal error: no resolved client id".to_string())?;
                let tool = if self.action == WgPeerAction::Enable { "wg_enable_client" } else { "wg_disable_client" };
                uai_dispatch(&client, &self.uai, tool, serde_json::json!({"client_id": id})).await?;
                Ok(format!("wg_peer_manage {} '{}' succeeded (id={})", self.action.as_str(), self.name, id))
            }
        }
    }
}

impl axiom_gateway::Tier2Capability for WgPeerManageCapability {
    fn capability_name(&self) -> &str {
        "wg_peer_manage"
    }

    fn dry_run(&self, _parameters: &[axiom_types::intent::Constraint]) -> Option<Vec<axiom_gateway::DryRunDiffEntry>> {
        Some(match self.action {
            WgPeerAction::Create => vec![axiom_gateway::DryRunDiffEntry::new("peer", "(does not exist)", format!("created, name='{}'", self.name))],
            WgPeerAction::Delete => {
                vec![axiom_gateway::DryRunDiffEntry::new("peer", format!("exists, enabled={}", self.prior_enabled), "permanently deleted")]
            }
            WgPeerAction::Enable => vec![axiom_gateway::DryRunDiffEntry::new("enabled", self.prior_enabled.to_string(), "true")],
            WgPeerAction::Disable => vec![axiom_gateway::DryRunDiffEntry::new("enabled", self.prior_enabled.to_string(), "false")],
        })
    }

    /// Only ever called by `Tier2ApprovalFlow::decide_and_execute`, after
    /// an explicit Telegram approval AND a final expiry/parameter-hash
    /// re-check - see `approval.rs`'s own doc comment. `self.runtime.
    /// block_on` is safe here ONLY because `dispatch_wg_peer_manage`
    /// always calls `decide_and_execute` (and therefore this) from inside
    /// `tokio::task::spawn_blocking` - see this struct's own `runtime`
    /// field doc comment.
    fn execute(&self, _parameters: &[axiom_types::intent::Constraint]) -> Result<String, String> {
        self.runtime.clone().block_on(self.perform())
    }
}

/// The `"wg_peer_manage"` sub-path of `dispatch_intent` - AXIOM's first
/// real (non-mock) Tier 2 capability. See this section's own top-of-file
/// doc comment for the wire-timing judgment call this function's shape
/// depends on, and `HARD_DENIED_WG_PEER_TARGETS`'s doc comment for the
/// delete/disable hard-deny.
///
/// Defense layers, in the order they run (matching `docker_restart`'s own
/// "at least this level of defense in depth" precedent, extended since
/// this is Tier 2):
/// 1. `parse_wg_peer_manage_target` - payload shape, charset, length, and
///    the code-level `HARD_DENIED_WG_PEER_TARGETS` hard-deny (delete/
///    disable only).
/// 2. `ctx.policy.check_denied_param_substrings` - the policy-file-editable
///    layer, same as every prior UAI-backed capability's own belt-and-
///    suspenders wiring.
/// 3. Target-existence resolution (delete/enable/disable only) - a request
///    naming a peer that doesn't exist is rejected here, BEFORE a Tier 2
///    proposal is ever created and BEFORE Larry ever sees a Telegram
///    prompt for it.
/// 4. `Tier2ApprovalFlow::propose` - Phase 3.6's protected-resource +
///    argument-denylist check, AGAIN (independently) at the flow's own
///    mandatory gate - see `approval.rs`'s own doc comment on why this
///    layering is correct, not redundant-for-redundancy's-sake.
/// 5. The real Telegram approval, in a detached background task - see
///    this section's wire-timing doc comment for why this is NOT awaited
///    inline here.
async fn dispatch_wg_peer_manage(
    ctx: &DispatchContext,
    intent_hash: IntentHash,
    trace_id: TraceId,
    payload: Vec<u8>,
    sender_id: NodeId,
    reply_routing: Option<RoutingExt>,
) -> Vec<u8> {
    let target = match parse_wg_peer_manage_target(&payload) {
        Ok(t) => t,
        Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
    };

    if let Some(reason) = ctx.policy.check_denied_param_substrings(
        "wg_peer_manage",
        &[Constraint::string("action", target.action.as_str().to_string()), Constraint::string("target", target.name.clone())],
    ) {
        warn!("Rejecting wg_peer_manage {} targeting {}: {}", target.action.as_str(), target.name, reason);
        return build_error_frame(&ctx.identity, intent_hash, trace_id, &reason, reply_routing);
    }

    let Some(uai) = ctx.uai_config.as_ref() else {
        return build_error_frame(&ctx.identity, intent_hash, trace_id, "wg_peer_manage not configured on this node (no UAI backend)", reply_routing);
    };
    let Some(tier2) = ctx.tier2_flow.as_ref() else {
        return build_error_frame(
            &ctx.identity, intent_hash, trace_id,
            "wg_peer_manage not configured on this node (no Tier 2 approval channel - see telegram_bot_token/telegram_chat_id in config.toml)",
            reply_routing,
        );
    };

    let (resolved_id, prior_enabled) = match target.action {
        WgPeerAction::Create => (None, false),
        _ => match resolve_wg_peer_by_name(uai, &target.name).await {
            Ok(Some((id, enabled, _connected))) => (Some(id), enabled),
            Ok(None) => {
                return build_error_frame(
                    &ctx.identity, intent_hash, trace_id,
                    &format!("wg_peer_manage: no WireGuard peer named '{}' exists - nothing to {}", target.name, target.action.as_str()),
                    reply_routing,
                );
            }
            Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e, reply_routing),
        },
    };

    let capability = WgPeerManageCapability {
        uai: uai.clone(),
        runtime: tokio::runtime::Handle::current(),
        action: target.action,
        name: target.name.clone(),
        resolved_id,
        prior_enabled,
    };
    let params = vec![
        Constraint::string("action", target.action.as_str().to_string()),
        Constraint::string("target", target.name.clone()),
    ];

    let intent_id = match tier2.propose(sender_id, &capability, params) {
        Ok(id) => id,
        Err(e) => return build_error_frame(&ctx.identity, intent_hash, trace_id, &e.to_string(), reply_routing),
    };

    // See this section's own top-of-file "Wire-timing judgment call" doc
    // comment: the real approve/deny/execute cycle runs detached, off this
    // request's reply path.
    let flow = Arc::clone(tier2);
    let audit_log = ctx.audit_log.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            let status = flow.decide_and_execute(intent_id, &capability);
            (status, flow)
        }).await;
        let (status, flow) = match result {
            Ok(v) => v,
            Err(join_err) => {
                warn!("wg_peer_manage background task for intent {} panicked: {}", intent_id.to_hex(), join_err);
                return;
            }
        };
        match &status {
            Ok(s) => info!("wg_peer_manage intent {} reached terminal status {:?}", intent_id.to_hex(), s),
            Err(e) => warn!("wg_peer_manage intent {} ended in a flow error: {}", intent_id.to_hex(), e),
        }
        if let Some(record) = flow.record(intent_id) {
            if let Some(log) = audit_log.as_ref() {
                if let Err(e) = log.log_tier2_linked_record(&record) {
                    warn!("failed to write Tier 2 audit record for wg_peer_manage intent {}: {}", intent_id.to_hex(), e);
                }
            }
        }
    });

    build_fulfill_frame(
        &ctx.identity, intent_hash, trace_id,
        format!(
            "wg_peer_manage: Tier 2 approval requested (intent {}) for action='{}' target='{}'. A Telegram approval \
             request has been sent to the configured chat; this request expires {} minutes from now if not answered. \
             Check wg_peers_list (or the audit log) afterward for the actual outcome - this reply only confirms the \
             request was proposed, not that it was approved or executed.",
            intent_id.to_hex(), target.action.as_str(), target.name,
            axiom_gateway::DEFAULT_EXPIRY.as_secs() / 60,
        ).into_bytes(),
        reply_routing,
    )
}

/// Dispatch a verified incoming AXIOM Frame: `Ping`/`Pong` (Cycle A) and
/// `Announce`/`Intent`/`Fulfill`/`Error` (Cycle B) are handled; anything else
/// is logged and dropped.
pub(crate) async fn handle_axiom_frame(
    frame: Frame,
    addr: SocketAddr,
    socket: &Arc<UdpSocket>,
    discovery_socket: &Option<Arc<UdpSocket>>,
    pending_pings: &Arc<Mutex<HashMap<TraceId, PendingPing>>>,
    known_peers: &Arc<std::sync::Mutex<HashSet<NodeId>>>,
    peer_addrs: &Arc<std::sync::Mutex<HashMap<NodeId, SocketAddr>>>,
    forwarded_frames: &Arc<std::sync::Mutex<ForwardedFrameCache>>,
    pending_intents: &Arc<Mutex<HashMap<TraceId, PendingIntent>>>,
    semantic_router: &Arc<Mutex<SemanticRouter>>,
    announcement_mgr: &Arc<Mutex<AnnouncementManager>>,
    reachable_via: &Arc<std::sync::Mutex<HashMap<NodeId, (NodeId, std::time::Instant)>>>,
    reverse_routes: &Arc<std::sync::Mutex<HashMap<TraceId, (SocketAddr, std::time::Instant)>>>,
    origin_admission: &Arc<std::sync::Mutex<HashMap<NodeId, (std::time::Instant, HashSet<NodeId>)>>>,
    local_capabilities: &Arc<Vec<String>>,
    last_announce_from: &Arc<std::sync::Mutex<HashMap<(NodeId, NodeId), std::time::Instant>>>,
    identity: &Keypair,
    uai_config: &Arc<Option<UaiConfig>>,
    notify_topic: &Arc<Option<String>>,
    policy: &Arc<axiom_gateway::CapabilityPolicy>,
    tier2_flow: &Option<Arc<Tier2Flow>>,
    audit_log: &Option<Arc<axiom_gateway::AuditLog>>,
) {
    let local_node_id = identity.node_id();

    // AXIOM-14 Cycle 1b: any frame type carrying a routing extension whose
    // destination isn't us gets forwarded (or dropped - TTL exhausted, no
    // known route, already forwarded once) here, before it ever reaches the
    // frame-type-specific handling below. This is what makes Fulfill
    // forwarding "for free" once Intent forwarding works - a Fulfill
    // destined for the original requester, arriving at a relay, is caught
    // by this same generic check rather than needing its own copy of the
    // forwarding logic in the Fulfill arm.
    if try_forward_routed_frame(&frame, addr, local_node_id, socket, discovery_socket, peer_addrs, forwarded_frames, reachable_via, reverse_routes).await {
        return;
    }

    match frame.header.frame_type {
        FrameType::Ping => {
            // A valid signature only proves the sender holds *some* real
            // keypair, not that we've agreed to talk to them - answering
            // any signed Ping unconditionally is a free one-shot reflection
            // surface (reply to an arbitrary claimed source address) with
            // zero cost to close: only reply to peers we've actually
            // handshaken with.
            if !known_peers.lock().unwrap().contains(&frame.header.sender_id) {
                debug!(
                    "Dropping Ping from unknown peer {} at {}",
                    hex::encode(frame.header.sender_id.as_bytes()), addr
                );
                return;
            }
            let Some(trace_id) = frame.trace_id else {
                debug!("Dropping Ping with no trace_id from {}", addr);
                return;
            };
            let pong = build_pong_frame(identity, trace_id);
            if pong.is_empty() {
                warn!("Failed to build Pong frame for {} (sign/encode error, see logs)", addr);
                return;
            }
            // AXIOM-14 Cycle 4: every send in this function goes through
            // `send_via` uniformly now, not a raw send on whichever
            // `socket` param happens to be passed - both call sites
            // (`network.rs`'s own receive loop and `discovery.rs`'s) now
            // pass `socket`/`discovery_socket` in the same fixed
            // (main, discovery) order regardless of which socket a given
            // frame actually arrived on, so a plain `socket.send_to(addr)`
            // would be wrong exactly when this arm runs from
            // `discovery.rs`'s loop and `addr` is link-local.
            if let Err(e) = send_via(socket, discovery_socket, &addr, &pong).await {
                warn!("Failed to send Pong to {}: {}", addr, e);
            }
        }
        FrameType::Pong => {
            let Some(trace_id) = frame.trace_id else {
                return;
            };
            let sender = frame.header.sender_id;
            if let Some(pending) = pending_pings.lock().await.remove(&trace_id) {
                if pending.expected_sender == sender {
                    let _ = pending.tx.send(());
                } else {
                    // Consuming (not restoring) the entry on a mismatch is
                    // deliberate: the real reply, if it arrives later, will
                    // find nothing and the original ping() times out
                    // normally - failing safe, rather than either falsely
                    // succeeding on a spoofed/misdirected Pong or leaving
                    // the entry racing with a legitimate late reply.
                    warn!(
                        "Dropping Pong for trace_id: expected sender {}, got {}",
                        hex::encode(pending.expected_sender.as_bytes()),
                        hex::encode(sender.as_bytes())
                    );
                }
            }
        }
        FrameType::Announce => {
            // Same reasoning as the Ping gate above: a verified signature
            // proves a real keypair, not a peer we've agreed to talk to.
            // Unlike the Intent gate (Cycle 1b), this stays STRICT - not
            // relaxed for gossip-forwarded copies. Announce needs no reply
            // routed back the way Intent/Fulfill do, so there's no
            // legitimate reason to accept one from anyone but an
            // authenticated direct hop; every relay in a gossip chain must
            // itself be a known peer of the next hop, same invariant
            // Cycle 1b's relay-source-authentication fix established for
            // routed frames.
            if !known_peers.lock().unwrap().contains(&frame.header.sender_id) {
                debug!(
                    "Dropping Announce from unknown peer {} at {}",
                    hex::encode(frame.header.sender_id.as_bytes()), addr
                );
                return;
            }

            let Some(payload) = AnnouncePayload::decode(&frame.payload) else {
                debug!("Dropping malformed Announce from {}", addr);
                return;
            };

            // AXIOM-14 Cycle 4 (Fable full-repo review finding #1, the
            // highest-severity finding of the whole review): before this
            // cycle, `origin`/`origin_clock` inside the payload were
            // trusted from ANY known peer with no proof they actually came
            // from the claimed origin - only the relaying hop's frame-level
            // signature was ever checked. A relay could claim an arbitrary
            // `origin` and this arm would act on it with full authority:
            // `unregister_node(&origin)` below would wipe the real origin's
            // entire registry, and a fabricated max-value `origin_clock`
            // would permanently poison `AnnouncementManager`'s dedup entry
            // so the real origin's future legitimate announces were
            // silently suppressed forever. Verified here, BEFORE any other
            // processing - including the admission/rate-limit bookkeeping
            // below (Fable's plan review, required: an unverifiable claim
            // must not even burn an admission slot or a
            // `last_announce_from` entry, or Cycle 3's anti-flood machinery
            // itself becomes a denial vector against the legitimate origins
            // a malicious relay also happens to carry). This duplicates
            // `process_announcement`'s own (authoritative) verification
            // below - required because this arm decodes its own local copy
            // of the payload independently, and `process_announcement`
            // re-decodes `frame.payload` itself from scratch, so verifying
            // only there would let a forged claim consume admission/
            // rate-limit state first; verifying only here would leave
            // `process_announcement` trusting an unverified claim if ever
            // called from anywhere else. Uniform rule, not a fallback
            // ladder: the pre-Cycle-4 shape (origin+clock, no signature -
            // what both live nodes emitted before this cycle) and the
            // pre-Cycle-2a shape (no origin at all) are BOTH rejected now,
            // never silently re-attributed to `sender_id`.
            let (Some(origin), Some(origin_clock), Some(origin_signature)) =
                (payload.origin, payload.origin_clock, payload.origin_signature)
            else {
                debug!(
                    "Dropping Announce from {} at {} with no signed origin claim (missing origin, origin_clock, or origin_signature)",
                    hex::encode(frame.header.sender_id.as_bytes()), addr
                );
                return;
            };
            let origin_signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin, &origin_clock, &payload.capabilities);
            if !origin.verify(&origin_signing_bytes, &origin_signature) {
                debug!(
                    "Dropping Announce from {} at {} claiming origin {} - signature does not verify",
                    hex::encode(frame.header.sender_id.as_bytes()), addr, hex::encode(origin.as_bytes())
                );
                return;
            }

            // AXIOM-14 Cycle 5: a genuinely signed origin claim whose clock
            // is too far from real wall-clock (either direction) is a
            // stale-data replay, not spoofing - Cycle 4's signature check
            // above proves authenticity, not freshness. This mirrors
            // `process_announcement`'s own (authoritative) check below,
            // same reasoning as why the signature verification itself is
            // duplicated here: this arm does its own local decode and must
            // not let an unverifiable-for-freshness claim burn admission/
            // rate-limit state before `process_announcement` gets a chance
            // to reject it. Concretely, without this check here, an
            // attacker could replay one captured old-but-signed frame at
            // ~1Hz and starve the relay's OWN genuine fresh announces via
            // the (sender, origin) rate limit below, even though
            // `process_announcement` would reject every replayed copy -
            // the damage (burned rate-limit state) happens before that
            // rejection ever occurs. Computed against `HybridClock::now()`
            // (real wall-clock), not this node's own `ClockManager`, which
            // has the same frozen-physical problem `create_announcement`
            // fixes for the sender side via `sync_physical()`.
            let now = HybridClock::now();
            if !origin_clock_is_fresh(origin_clock.physical, now.physical) {
                debug!(
                    "Dropping Announce from {} at {} claiming origin {} - origin_clock too far from wall-clock (skew {}s, max {}s)",
                    hex::encode(frame.header.sender_id.as_bytes()), addr, hex::encode(origin.as_bytes()),
                    now.physical.abs_diff(origin_clock.physical), MAX_ANNOUNCE_CLOCK_SKEW.as_secs()
                );
                return;
            }

            // AXIOM-14 Cycle 3: bound how many DISTINCT origins a single
            // sender can introduce per window - the (sender, origin)
            // rate limit below only bounds re-announcing the SAME origin
            // too fast, which does nothing against a sender rotating a
            // fresh fabricated origin on every frame to bypass it
            // entirely. Checked (and any rejection applied) BEFORE the
            // pair-level rate limit's own bookkeeping below, so a
            // rejected origin never grows last_announce_from either.
            {
                let mut admission = origin_admission.lock().unwrap();
                let now = std::time::Instant::now();
                let entry = admission.entry(frame.header.sender_id)
                    .or_insert_with(|| (now, HashSet::new()));
                if now.duration_since(entry.0) >= ORIGIN_ADMISSION_WINDOW {
                    // Window rolled over - start fresh.
                    *entry = (now, HashSet::new());
                }
                if !entry.1.contains(&origin) {
                    if entry.1.len() >= MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW {
                        debug!(
                            "Dropping Announce: sender {} exceeded {} distinct origins this window (origin {})",
                            hex::encode(frame.header.sender_id.as_bytes()),
                            MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW,
                            hex::encode(origin.as_bytes())
                        );
                        return;
                    }
                    entry.1.insert(origin);
                }
                // else: already admitted this window - pass through
                // uncounted, governed by the pair-level rate limit below.
            }

            // AXIOM-4 (Cycle C), rekeyed for Cycle 2b: bound how often a
            // single known peer can force a registry unregister+re-register
            // cycle for a given origin. Keyed on (immediate sender, origin)
            // - sender alone would drop legitimate gossip fan-out (one
            // relay forwarding many distinct origins back-to-back all
            // sharing one bucket); origin alone would let a relay bypass
            // the limit by claiming a different origin each time while
            // it's really the same relay hammering us.
            {
                let mut last_seen = last_announce_from.lock().unwrap();
                let now = std::time::Instant::now();
                let key = (frame.header.sender_id, origin);
                if let Some(last) = last_seen.get(&key) {
                    if now.duration_since(*last) < ANNOUNCE_RATE_LIMIT_INTERVAL {
                        debug!(
                            "Rate-limiting Announce (sender {}, origin {}) - too soon since last",
                            hex::encode(frame.header.sender_id.as_bytes()), hex::encode(origin.as_bytes())
                        );
                        return;
                    }
                }
                last_seen.insert(key, now);
            }

            // process_announcement handles: dropping our own announcement
            // echoed back to us, dedup on (origin, intent_hash) vs
            // origin_clock (NOT sender_id/header.clock - see its own doc
            // comment for why that would make dedup vacuous against gossip
            // loops), and building a re-forwardable frame with TTL
            // decremented and origin/origin_clock preserved unmodified.
            let Some((new_caps, forward_frame)) =
                announcement_mgr.lock().await.process_announcement(&frame)
            else {
                return; // stale, duplicate, self-origin, or malformed
            };

            // AXIOM-14 Cycle 2b: if origin isn't itself a direct peer,
            // remember which direct peer (whoever relayed this to us) can
            // reach it - request_intent's fallback consults this instead
            // of failing "no known address" the way it always has for a
            // non-direct candidate. AXIOM-14 Cycle 4 (Fable diff review,
            // optional but applied): this insert now happens BEFORE the
            // router registration block below, not after - if
            // `run_announcement_maintenance` interleaves between the two
            // (this origin was stale and this is its self-healing
            // re-announce racing the maintenance pass), the old ordering
            // left a window where `reachable_via` could be pruned as
            // "still stale" a moment after the router had already
            // re-registered the origin's capabilities, orphaning them
            // until the next re-announce. Inserting first means
            // maintenance always sees the fresh touch.
            if !known_peers.lock().unwrap().contains(&origin) {
                // Refresh-on-touch, not first-write-only - this same
                // insert already runs on every accepted announce for this
                // origin, so timestamping it here for free is what lets
                // `run_announcement_maintenance` age out entries by "no
                // legitimate re-announce in ANNOUNCEMENT_MAX_AGE" rather
                // than "first learned more than 30 minutes ago," which
                // would prune a still-alive, periodically re-gossiped
                // route out from under itself.
                reachable_via.lock().unwrap().insert(origin, (frame.header.sender_id, std::time::Instant::now()));
            }

            {
                let mut router = semantic_router.lock().await;
                // AXIOM-4 (Cycle C), rekeyed for Cycle 2b: full-set
                // replacement keyed on ORIGIN, not the immediate sender - a
                // gossip-forwarded announcement is about the origin, and a
                // relay forwarding it must never wipe/replace ITS OWN
                // registrations (which is what unregister_node(sender_id)
                // would do here, since sender_id is now the relay for a
                // forwarded copy, not the origin).
                router.unregister_node(&origin);
                for cap in &new_caps {
                    // The wire format only carries a hash, not the
                    // capability's name (see the plan doc) - match against
                    // KNOWN_CAPABILITY_NAMES (every name this build
                    // understands) rather than trying to register an
                    // unnamed capability. AXIOM-7 found and fixed a bug
                    // here: this used to match against `local_capabilities`
                    // (what WE offer), so a pure-consumer node with nothing
                    // to offer could never recognize ANY announced
                    // capability, no matter who provided it - recognizing a
                    // name and offering it are two different things, and
                    // only the Intent handler (do we actually SERVE this)
                    // should stay gated on `local_capabilities`.
                    for name in KNOWN_CAPABILITY_NAMES {
                        if AiIntent::from_str(name).hash == cap.intent_hash {
                            router.register(origin, SemanticCapability::new(name));
                            info!(
                                "Registered capability '{}' from {} (via {})",
                                name, hex::encode(origin.as_bytes()), hex::encode(frame.header.sender_id.as_bytes())
                            );
                        }
                    }
                }
            }

            // Re-gossip to every OTHER direct peer - never back to
            // whoever sent us this copy, they already have it.
            if let Some(mut fwd) = forward_frame {
                // process_announcement's output frame carries a zero
                // signature - it's OUR job as the physical relay for this
                // hop to actually sign it before it goes out.
                let signer = FrameSigner::new(identity.clone());
                if signer.sign(&mut fwd).is_err() {
                    warn!("Failed to sign forwarded Announce for {}, dropping", hex::encode(origin.as_bytes()));
                    return;
                }
                let wire_size = fwd.wire_size();
                let mut buffer = vec![0u8; wire_size + 32];
                match Encoder::encode(&fwd, &mut buffer) {
                    Ok(size) => {
                        buffer.truncate(size);
                        let targets: Vec<SocketAddr> = peer_addrs.lock().unwrap().iter()
                            .filter(|(id, _)| **id != frame.header.sender_id)
                            .map(|(_, a)| *a)
                            .collect();
                        for target in targets {
                            if let Err(e) = send_via(socket, discovery_socket, &target, &buffer).await {
                                warn!("Failed to re-gossip Announce for {} to {}: {}", hex::encode(origin.as_bytes()), target, e);
                            }
                        }
                    }
                    Err(e) => warn!("Failed to encode forwarded Announce: {:?}", e),
                }
            }
        }
        FrameType::Intent => {
            // AXIOM Phase 1.1: capability AUTHORIZATION no longer depends
            // on known_peers (a completed HELLO handshake) at all - that
            // was the old model (any known peer could call echo/sysinfo
            // for free); it's gone, replaced entirely by
            // `dispatch_intent`'s policy check below, uniformly for every
            // capability. `decode_verified_frame` (upstream of this whole
            // function) already proved `frame.header.sender_id` is
            // authentic - a handshake proves nothing dispatch_intent's
            // policy check doesn't already re-derive from the signature
            // itself, so requiring one here too would just be a second,
            // redundant gate with no security benefit.
            //
            // What's still checked here is a DIFFERENT, narrower thing:
            // for a RELAYED Intent (routing.destination == us, arrived via
            // some other node forwarding it - already established by
            // `try_forward_routed_frame`'s fallthrough above), the
            // physical relay delivering it must itself be a peer we've
            // directly handshaken with. This is transport-level anti-
            // spoofing (don't accept a frame claiming to be relayed from
            // an arbitrary/spoofed UDP source), not a capability-
            // authorization decision - a direct (non-relayed) Intent has
            // no such physical-relay concept to check at all. Replies
            // still go to `addr` (the relay, for a relayed Intent), never
            // to `frame.header.sender_id` directly - no reflection to an
            // attacker-chosen address either way.
            let relayed_for_us = frame.routing.is_some(); // destination==us, guaranteed above
            if relayed_for_us {
                let relay_is_known = peer_addrs.lock().unwrap().values().any(|a| *a == addr);
                if !relay_is_known {
                    debug!(
                        "Dropping relayed Intent toward us: relay source {} is not a known peer",
                        addr
                    );
                    return;
                }
            }
            let Some(trace_id) = frame.trace_id else {
                debug!("Dropping Intent with no trace_id from {}", addr);
                return;
            };

            // Route the Fulfill/Error back toward the original requester
            // (frame.header.sender_id - preserved through relaying, since
            // forwarding only touches routing.destination/ttl, not the
            // signed header) if this Intent itself arrived relayed;
            // unchanged direct-reply-to-addr behavior otherwise.
            let reply_routing = relayed_for_us
                .then(|| RoutingExt::new(frame.header.sender_id, DEFAULT_ROUTING_TTL));

            // Gap B (AXIOM-11.2): dispatch itself is now transport-agnostic
            // (see dispatch_intent's doc) - this LAN call site just builds
            // the context bundle, spawns (dispatch_intent must never be
            // awaited inline here - network_clients can be a real HTTP
            // round trip), and sends the reply over this frame's own UDP
            // socket/addr once it's back.
            let ctx = DispatchContext {
                identity: identity.clone(),
                local_capabilities: local_capabilities.clone(),
                uai_config: uai_config.clone(),
                notify_topic: notify_topic.clone(),
                policy: policy.clone(),
                tier2_flow: tier2_flow.clone(),
                audit_log: audit_log.clone(),
            };
            let intent_hash = frame.header.intent_hash;
            let sender_id = frame.header.sender_id;
            let payload = frame.payload.clone();
            let socket = socket.clone();
            let discovery_socket = discovery_socket.clone();
            tokio::spawn(async move {
                let reply = dispatch_intent(&ctx, intent_hash, trace_id, payload, sender_id, DispatchOrigin::Lan, reply_routing).await;
                if reply.is_empty() {
                    warn!("Failed to build Intent reply for {} (sign/encode error, see logs)", addr);
                    return;
                }
                // AXIOM-14 Cycle 4: see the Ping/Pong arm's comment on why
                // this must be family-aware, not a raw send on `socket`.
                if let Err(e) = send_via(&socket, &discovery_socket, &addr, &reply).await {
                    warn!("Failed to send Intent reply to {}: {}", addr, e);
                }
            });
        }
        FrameType::Fulfill => {
            let Some(trace_id) = frame.trace_id else {
                return;
            };
            let sender = frame.header.sender_id;
            if let Some(pending) = pending_intents.lock().await.remove(&trace_id) {
                if pending.expected_sender == sender {
                    let _ = pending.tx.send(Ok(frame.payload));
                } else {
                    // Same fail-safe consume-not-restore reasoning as Pong's
                    // mismatch handling.
                    warn!(
                        "Dropping Fulfill for trace_id: expected sender {}, got {}",
                        hex::encode(pending.expected_sender.as_bytes()),
                        hex::encode(sender.as_bytes())
                    );
                }
            }
        }
        FrameType::Error => {
            let Some(trace_id) = frame.trace_id else {
                return;
            };
            let sender = frame.header.sender_id;
            if let Some(pending) = pending_intents.lock().await.remove(&trace_id) {
                if pending.expected_sender == sender {
                    let reason = String::from_utf8_lossy(&frame.payload).into_owned();
                    let _ = pending.tx.send(Err(reason));
                } else {
                    warn!(
                        "Dropping Error for trace_id: expected sender {}, got {}",
                        hex::encode(pending.expected_sender.as_bytes()),
                        hex::encode(sender.as_bytes())
                    );
                }
            }
        }
        other => {
            debug!("Dropping unhandled frame type {:?} from {} (not built yet)", other, addr);
        }
    }
}

/// AXIOM-14 Cycle 1b's degenerate "routing table": we forward toward
/// `destination` only if it's itself a direct peer of ours - no discovery,
/// no multi-hop route tables yet (Cycle 2 territory). A hop budget larger
/// than this is pointless with only one relay level currently reachable,
/// but the field allows a larger mesh later without a wire change.
const DEFAULT_ROUTING_TTL: u8 = 8;

/// Bound on `ForwardedFrameCache`'s size - oldest entries evicted first once
/// exceeded. This is loop *mitigation* for duplicate-frame delivery (e.g. a
/// retransmit), not the TTL mechanism's job: TTL bounds how many hops a
/// frame can travel in total; this bounds how many times THIS node
/// re-forwards the identical frame.
const FORWARD_DEDUP_CAPACITY: usize = 4096;

/// AXIOM-14 Cycle 6 (Fable diff review, required): backstop cap on
/// `reverse_routes`. Its own eviction (`run_announcement_maintenance`,
/// every `ANNOUNCEMENT_MAINTENANCE_INTERVAL` = 5 minutes) bounds entry
/// LIFETIME, not entry COUNT between sweeps - and nothing on the
/// Intent-forwarding path rate-limits how many distinct trace_ids one
/// relay can be asked to remember in that window. A known peer (or a
/// spoofed UDP source, since forwarded frames aren't re-verified against
/// transport) blasting routed Intents with distinct trace_ids could grow
/// this map by one ~100-byte entry per packet, unbounded until the next
/// sweep - at any real packet rate that's a lot of memory in under 5
/// minutes. This ceiling is orders of magnitude above realistic legitimate
/// in-flight request count, so it doesn't reintroduce the "small
/// capacity-FIFO cache evicts an in-flight route" hazard the time-bounded
/// design was chosen to avoid - it only stops truly unbounded growth.
const REVERSE_ROUTES_CAPACITY: usize = 65536;

/// See `FORWARD_DEDUP_CAPACITY`. Keyed on `(TraceId, FrameType)`, not
/// `TraceId` alone - an Intent and its own Fulfill share a `TraceId` by
/// design (that's how `pending_intents` correlates them), so `TraceId`
/// alone would treat a request and its reply as the same dedup entry.
pub(crate) struct ForwardedFrameCache {
    seen: HashSet<(TraceId, FrameType)>,
    order: std::collections::VecDeque<(TraceId, FrameType)>,
}

impl ForwardedFrameCache {
    pub(crate) fn new() -> Self {
        Self { seen: HashSet::new(), order: std::collections::VecDeque::new() }
    }

    fn contains(&self, key: &(TraceId, FrameType)) -> bool {
        self.seen.contains(key)
    }

    fn insert(&mut self, key: (TraceId, FrameType)) {
        if self.seen.insert(key) {
            self.order.push_back(key);
            if self.order.len() > FORWARD_DEDUP_CAPACITY {
                if let Some(oldest) = self.order.pop_front() {
                    self.seen.remove(&oldest);
                }
            }
        }
    }
}

/// If `frame` carries a routing extension addressed to someone other than
/// `local_node_id`, either forward it toward that peer or drop it (relay
/// source not a known peer, TTL exhausted, no known route, or a duplicate
/// already forwarded) - see `ForwardedFrameCache` and `DEFAULT_ROUTING_TTL`.
/// Returns `true` if the frame was consumed here (forwarded or dropped): the
/// caller must NOT also process it as a local frame. Returns `false` for a
/// frame with no routing extension (today's existing direct-only behavior,
/// unchanged) or one addressed to us - the caller's normal frame-type
/// handling applies.
///
/// AXIOM-14 Cycle 6 (pieces 2/3 of the plan Fable reviewed): the next-hop
/// resolution below now goes beyond "is `destination` a direct peer" -
/// see the inline comments at the resolution site for the fallback order
/// (direct peer, then a `reverse_routes` breadcrumb for Fulfill/Error, then
/// `reachable_via`) and the arrival-source loop guard. This is purely an
/// additional next-hop-resolution fallback - the existing gate/dedup/TTL-
/// decrement ordering above it is untouched.
async fn try_forward_routed_frame(
    frame: &Frame,
    addr: SocketAddr,
    local_node_id: NodeId,
    socket: &Arc<UdpSocket>,
    discovery_socket: &Option<Arc<UdpSocket>>,
    peer_addrs: &Arc<std::sync::Mutex<HashMap<NodeId, SocketAddr>>>,
    forwarded_frames: &Arc<std::sync::Mutex<ForwardedFrameCache>>,
    reachable_via: &Arc<std::sync::Mutex<HashMap<NodeId, (NodeId, std::time::Instant)>>>,
    reverse_routes: &Arc<std::sync::Mutex<HashMap<TraceId, (SocketAddr, std::time::Instant)>>>,
) -> bool {
    let Some(routing) = &frame.routing else {
        return false;
    };
    if routing.destination == local_node_id {
        return false;
    }

    // Fable's Cycle 1b diff review: without this, we'd relay for ANYONE who
    // can reach our socket with a self-generated keypair (a valid signature
    // proves a real keypair, not a peer we've agreed to talk to - same
    // reasoning as every other known_peers gate in this file), which makes
    // the destination's "immediate UDP source is a known peer" check
    // vacuous - it's checking that the frame arrived via a relay whose OWN
    // upstream source was never itself authenticated. Checked first, before
    // spending any dedup-cache slot on an unauthorized attempt.
    let source_is_known_peer = peer_addrs.lock().unwrap().values().any(|a| *a == addr);
    if !source_is_known_peer {
        debug!(
            "Dropping routed {:?} toward {}: relay source {} is not a known peer",
            frame.header.frame_type, hex::encode(routing.destination.as_bytes()), addr
        );
        return true;
    }

    let Some(trace_id) = frame.trace_id else {
        debug!(
            "Dropping routed {:?} toward {} with no trace_id - can't dedup safely",
            frame.header.frame_type, hex::encode(routing.destination.as_bytes())
        );
        return true;
    };

    let dedup_key = (trace_id, frame.header.frame_type);
    {
        let mut cache = forwarded_frames.lock().unwrap();
        if cache.contains(&dedup_key) {
            debug!("Dropping duplicate routed {:?} (already forwarded once)", frame.header.frame_type);
            return true;
        }
        cache.insert(dedup_key);
    }

    if routing.ttl == 0 {
        debug!(
            "Dropping routed {:?} toward {}: TTL exhausted",
            frame.header.frame_type, hex::encode(routing.destination.as_bytes())
        );
        return true;
    }

    // AXIOM-14 Cycle 6 (piece 2): destination isn't a direct peer - consult
    // `reachable_via`, the gossip-populated "origin X is reachable via
    // direct peer Y" table (already populated since Cycle 2b, never
    // previously consulted by routing - see `MAX_ROUTE_INDIRECTION`'s doc
    // comment in axiom-router/src/announce.rs). Each hop's `reachable_via`
    // naturally points one hop closer to the destination along whatever
    // path gossip took, so consulting it here composes a full route
    // hop-by-hop with no single node needing end-to-end path knowledge.
    //
    // Piece 3: for a Fulfill/Error specifically, a `reverse_routes`
    // breadcrumb (recorded below when the matching Intent transited this
    // node) is tried BEFORE falling back to `reachable_via` - it's the
    // exact address this trace's Intent actually arrived from at this hop,
    // which correctly reaches even a pure-consumer requester that
    // `reachable_via` can never know about (see that field's doc comment).
    let direct_hit = peer_addrs.lock().unwrap().get(&routing.destination).copied();
    let next_hop_addr = direct_hit.or_else(|| {
        let breadcrumb = if matches!(frame.header.frame_type, FrameType::Fulfill | FrameType::Error) {
            reverse_routes.lock().unwrap().get(&trace_id).map(|(upstream_addr, _)| *upstream_addr)
        } else {
            None
        };
        breadcrumb.or_else(|| {
            reachable_via.lock().unwrap().get(&routing.destination)
                .and_then(|(relay, _)| peer_addrs.lock().unwrap().get(relay).copied())
        })
    });
    let Some(next_hop_addr) = next_hop_addr else {
        debug!(
            "Dropping routed {:?}: no known route to {} (not a direct peer, no reverse-path breadcrumb, no reachable_via relay)",
            frame.header.frame_type, hex::encode(routing.destination.as_bytes())
        );
        return true;
    };

    // Fable's plan review: never forward back toward exactly where this
    // frame just arrived from - a degenerate blackhole/loop case a stale or
    // malformed route (direct, breadcrumb, or reachable_via-derived) could
    // otherwise produce. `ForwardedFrameCache`'s dedup (checked above)
    // stops THIS node from re-forwarding an identical frame twice, but does
    // nothing to stop a single bad hop from bouncing a frame straight back
    // the way it came.
    if next_hop_addr == addr {
        debug!(
            "Dropping routed {:?} toward {}: resolved next hop {} is the frame's own arrival source - refusing to bounce it back",
            frame.header.frame_type, hex::encode(routing.destination.as_bytes()), next_hop_addr
        );
        return true;
    }

    // Piece 3: record the reverse-path breadcrumb for an Intent we're about
    // to forward, before actually sending it - `addr` is the upstream
    // address THIS Intent arrived from at this hop (already proven a known
    // peer by the `source_is_known_peer` check above), so a later
    // Fulfill/Error for the same trace_id can retrace this exact hop back.
    //
    // Fable diff review (required): first-write-wins (`or_insert`), NOT an
    // unconditional overwrite. An unconditional insert lets an on-path
    // attacker who is (or spoofs) a known peer flush this exact trace_id
    // out of the (TraceId, FrameType) dedup cache (FORWARD_DEDUP_CAPACITY
    // is only 4096 - a burst of unrelated routed frames evicts it), then
    // replay an Intent with the sniffed trace_id from an address THEY
    // control - overwriting the real breadcrumb and hijacking the eventual
    // Fulfill's reverse path to themselves, while the real requester times
    // out and the innocent provider's reputation gets punished for it
    // (exactly the harm this whole mechanism exists to prevent). An honest
    // duplicate Intent never reaches this line at all - the dedup check
    // above already dropped it - so first-write-wins changes nothing for
    // legitimate traffic.
    if frame.header.frame_type == FrameType::Intent {
        let mut routes = reverse_routes.lock().unwrap();
        // Fable diff review (required): backstop capacity cap - see
        // REVERSE_ROUTES_CAPACITY's doc comment. Only refuses genuinely
        // NEW breadcrumbs once at capacity; an existing trace_id's entry
        // (the common case - this same relay re-forwarding, or the
        // first-write-wins check above) is untouched either way.
        if routes.len() < REVERSE_ROUTES_CAPACITY || routes.contains_key(&trace_id) {
            routes.entry(trace_id).or_insert_with(|| (addr, std::time::Instant::now()));
        } else {
            debug!(
                "Dropping reverse-route breadcrumb for trace_id {:?}: reverse_routes at capacity ({})",
                trace_id, REVERSE_ROUTES_CAPACITY
            );
        }
    }

    // Re-encode with a decremented TTL, but the ORIGINAL signature bytes
    // untouched - TTL is deliberately excluded from what's signed (see
    // Encoder::signature_data), so this doesn't invalidate anything the
    // eventual recipient will verify.
    let mut forwarded = frame.clone();
    let new_ttl = routing.ttl - 1;
    forwarded.routing.as_mut().unwrap().ttl = new_ttl;

    let wire_size = forwarded.wire_size();
    let mut buffer = vec![0u8; wire_size + 32];
    match Encoder::encode(&forwarded, &mut buffer) {
        Ok(size) => {
            buffer.truncate(size);
            if let Err(e) = send_via(socket, discovery_socket, &next_hop_addr, &buffer).await {
                warn!("Failed to forward {:?} to {}: {}", frame.header.frame_type, next_hop_addr, e);
            } else {
                debug!(
                    "Forwarded {:?} toward {} via {} (ttl now {})",
                    frame.header.frame_type, hex::encode(routing.destination.as_bytes()),
                    next_hop_addr, new_ttl
                );
            }
        }
        Err(e) => {
            warn!("Failed to re-encode frame for forwarding: {:?}", e);
        }
    }
    true
}

fn build_ping_frame(identity: &Keypair, trace_id: TraceId) -> Vec<u8> {
    build_simple_frame(identity, FrameType::Ping, trace_id, IntentHash::zero(), Vec::new(), None)
}

fn build_pong_frame(identity: &Keypair, trace_id: TraceId) -> Vec<u8> {
    build_simple_frame(identity, FrameType::Pong, trace_id, IntentHash::zero(), Vec::new(), None)
}

/// `routing`: AXIOM-14 Cycle 1b - `Some(RoutingExt{destination, ttl})` to
/// send this Intent toward a peer we're not directly connected to via a
/// relay (see `NetworkManager::request_intent_via`); `None` for today's
/// existing direct-only behavior, unchanged.
pub(crate) fn build_intent_frame(identity: &Keypair, intent_hash: IntentHash, trace_id: TraceId, payload: Vec<u8>, routing: Option<RoutingExt>) -> Vec<u8> {
    build_simple_frame(identity, FrameType::Intent, trace_id, intent_hash, payload, routing)
}

/// `routing`: `Some(RoutingExt{destination: <original requester>, ttl})`
/// when replying to a relayed Intent, so the relay forwards this Fulfill
/// back rather than it vanishing as an unmatched local frame - see
/// `dispatch_intent`'s `reply_routing` param, which is where this comes
/// from.
fn build_fulfill_frame(identity: &Keypair, intent_hash: IntentHash, trace_id: TraceId, payload: Vec<u8>, routing: Option<RoutingExt>) -> Vec<u8> {
    build_simple_frame(identity, FrameType::Fulfill, trace_id, intent_hash, payload, routing)
}

fn build_error_frame(identity: &Keypair, intent_hash: IntentHash, trace_id: TraceId, reason: &str, routing: Option<RoutingExt>) -> Vec<u8> {
    build_simple_frame(identity, FrameType::Error, trace_id, intent_hash, reason.as_bytes().to_vec(), routing)
}

/// Real local facts for the built-in `"sysinfo"` capability - reads
/// `/proc/sys/kernel/hostname` and `/proc/uptime` directly rather than
/// pulling in a `hostname`/`sysinfo` crate, matching how the rest of this
/// codebase favors small hand-rolled reads over new dependencies (discovery.rs
/// already reads `/proc/net/if_inet6` and `/sys/class/net/*/flags` the same
/// way). Ignores any payload the requester sent - this capability answers
/// "what are you", not "do X with this input".
#[cfg(target_os = "linux")]
fn collect_sysinfo() -> Vec<u8> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime_secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| secs as u64);

    match uptime_secs {
        Some(secs) => format!("hostname={} uptime_secs={}", hostname, secs).into_bytes(),
        None => format!("hostname={} uptime_secs=unknown", hostname).into_bytes(),
    }
}

/// Windows port (2026-08-15) of `collect_sysinfo` above. No procfs here, so
/// hostname comes from the `COMPUTERNAME` environment variable Windows
/// always sets (no new dependency needed for that one). Uptime has no
/// equally cheap source without an FFI call (`GetTickCount64`) this crate
/// doesn't otherwise need - `sysinfo`'s own consumers only ever cared about
/// hostname reachability in practice so far (see AXIOM-8's original design
/// notes), and `uptime_secs=unknown` is an honest, already-handled value on
/// this path (the Linux implementation reports the same string whenever
/// `/proc/uptime` is unreadable), not a silent stub - matching this port's
/// overall rule of never faking data it doesn't actually have.
#[cfg(windows)]
fn collect_sysinfo() -> Vec<u8> {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    format!("hostname={} uptime_secs=unknown", hostname).into_bytes()
}

/// AXIOM-10: bridge for the `"network_clients"` capability - fetches the
/// live client list from the TP-Link Omada SDN controller managing the
/// network, via the UAI broker's existing `omada` driver. AXIOM never
/// PERSISTS the Omada password anywhere (config, disk, logs): it asks
/// UAI's `keepass_lookup` for the stored "omada controller (Local)"
/// credential fresh on every call, uses it for exactly one call to UAI's
/// `omada_clients`, then zeroes it out of memory (AXIOM Phase 1.4, see
/// SECURITY.md) rather than letting it linger for the allocator to reuse
/// on its own schedule - the same pattern any other UAI caller (a human,
/// a script) already uses, just made reachable over AXIOM's own
/// peer-authenticated transport instead of a direct HTTP call. (Note:
/// AXIOM's own request DOES ask `keepass_lookup` to include the password
/// - `{"password": true}` below - so unlike the tool's one-line registry
/// description ("returns username, URL, notes -- NOT password") suggests,
/// AXIOM's process does briefly hold the real plaintext value; the
/// "never persisted" property above is what's actually guaranteed, not
/// "never seen".) Errors are returned as `Err(String)` - the caller turns
/// that into a signed AXIOM `Error` frame rather than ever panicking or
/// hanging the connection open.
///
/// AXIOM Phase 3.7: the `omada_clients` reply is UNTRUSTED external data -
/// its string fields (hostnames, SSIDs, ...) are self-reported by whatever
/// device is on the LAN, including devices the owner doesn't control (see
/// `SECURITY.md`'s "Untrusted-content handling" section and
/// `axiom_gateway::sanitize`'s module doc comment for the full threat
/// model). Before this function returns, the reply is passed through
/// `axiom_gateway::sanitize::sanitize_and_wrap_untrusted_json` - every
/// string field gets length-capped and control-character/terminal-escape-
/// stripped (oversized/mangled fields flagged, never silently hidden), and
/// the whole thing is wrapped in a structural "this is data, not
/// instructions" envelope - so the raw backend reply itself never leaves
/// this function, let alone this node.
async fn fetch_network_clients(uai: &UaiConfig) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let mut kp = uai_dispatch(&client, uai, "keepass_lookup", serde_json::json!({
        "title": "omada controller (Local)",
        "password": true,
    })).await?;
    let entry = kp.get_mut("entry").ok_or("keepass_lookup: reply missing entry")?;

    // AXIOM Phase 1.4: pull the credential fields OUT of `entry` (via
    // `mem::take`, which leaves an empty string behind in the JSON value
    // rather than cloning) and into `Zeroizing` wrappers, so this
    // function holds exactly one copy of the plaintext Omada password at
    // any point, and that copy is wiped (not just deallocated) when it
    // drops at the end of this function - see the doc comment above and
    // SECURITY.md's "AXIOM -> UAI credential scope" section for why this
    // was flagged as worth doing even though the value's lifetime here is
    // already short (single call, never persisted to disk/logs).
    let username: Zeroizing<String> = match entry.get_mut("username") {
        Some(serde_json::Value::String(s)) => Zeroizing::new(std::mem::take(s)),
        _ => return Err("keepass_lookup: entry missing username".to_string()),
    };
    let password: Zeroizing<String> = match entry.get_mut("password") {
        Some(serde_json::Value::String(s)) => Zeroizing::new(std::mem::take(s)),
        _ => return Err("keepass_lookup: entry missing password".to_string()),
    };

    let clients = uai_dispatch(&client, uai, "omada_clients", serde_json::json!({
        "host": "192.168.1.14",
        "port": 8043,
        "username": username.as_str(),
        "password": password.as_str(),
    })).await?;

    // `username`/`password` go out of scope (and get zeroized by
    // `Zeroizing`'s `Drop` impl) here, before this function returns.
    //
    // AXIOM Phase 3.7: `clients` is the raw, untrusted backend reply -
    // sanitize (length-cap + control-char/escape-sequence strip, flagged
    // not silent) and wrap it in the structural untrusted-data envelope
    // BEFORE it's turned into the string this function returns. Nothing
    // downstream of this line - the Fulfill frame payload
    // `dispatch_network_clients` builds, and (per this phase's own audit
    // review) any future audit-log wiring - ever sees `clients` itself.
    let sanitized = axiom_gateway::sanitize::sanitize_and_wrap_untrusted_json(
        "network_clients (Omada client records via UAI)",
        clients,
    );
    Ok(sanitized.to_string())
}

/// Shared UAI broker HTTP-POST helper - `POST {base_url}/registry/dispatch`
/// with `{tool_name, input_args}`, `X-UAI-Token` auth, treating any
/// non-`ok: true` reply as an error. Extracted (AXIOM notify_send) out of
/// what used to be a closure private to `fetch_network_clients` so
/// `send_notification` (below) can call the exact same request shape
/// rather than hand-rolling a second copy - both capabilities that ever
/// talk to UAI go through this one function, so a wire-format fix (auth
/// header, error-shape handling) only has one place to land. Mechanical
/// extraction, not a behavior change - `fetch_network_clients`'s own two
/// call sites (`keepass_lookup`, `omada_clients`) are unchanged in
/// substance, just calling this by its new top-level name.
async fn uai_dispatch(client: &reqwest::Client, uai: &UaiConfig, tool_name: &str, input_args: serde_json::Value) -> Result<serde_json::Value, String> {
    let resp = client.post(format!("{}/registry/dispatch", uai.base_url))
        .header("X-UAI-Token", &uai.token)
        .json(&serde_json::json!({"tool_name": tool_name, "input_args": input_args}))
        .send().await
        .map_err(|e| format!("UAI unreachable: {e}"))?
        .json::<serde_json::Value>().await
        .map_err(|e| format!("bad UAI reply: {e}"))?;
    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let reason = resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
        return Err(format!("{tool_name}: {reason}"));
    }
    Ok(resp)
}

/// AXIOM notify_send: turn a raw Intent payload into a message string
/// that's safe to hand to an external notification service and, from
/// there, straight onto a human's phone lock screen. Pure/sync (no
/// network) so it's directly unit-testable without a live UAI broker -
/// see this module's `notify_send_tests`.
///
/// This is caller-supplied, untrusted content - unlike `network_clients`,
/// whose only inputs come from node config (see `axiom_gateway::policy`'s
/// module doc comment on that distinction). But it's untrusted in the
/// OPPOSITE direction from Phase 3.7's `network_clients` concern: that
/// phase defended against a hostile backend's data flowing INTO an AI's
/// context (device hostnames/SSIDs an AI would later read). Here, a
/// possibly-hostile ALLOWLISTED PEER's message text flows OUT to an
/// external service and then a human's screen. The concrete risks this
/// guards against are the same low-level ones sanitize.rs already
/// documents (ANSI/terminal-escape and control-character injection into
/// whatever renders the message - a notification client, or a log line if
/// this ever gets echoed there) plus an unbounded-length payload padding
/// out or abusing the notification backend.
///
/// Reuses `axiom_gateway::sanitize::sanitize_str` directly - the same
/// tested primitive Phase 3.7 built for exactly this class of problem -
/// rather than inventing a second one. Deliberately does NOT use
/// `sanitize_and_wrap_untrusted_json`/`wrap_untrusted_json`: that
/// machinery's whole point is a JSON object boundary that keeps an
/// attacker-controlled STRING from being mistaken for a sibling of a
/// structured multi-field reply being handed back to a peer (see
/// `sanitize.rs`'s own doc comment, "Structural envelope, not a text
/// prefix"). notify_send has no such reply shape to protect - its output
/// isn't JSON returned to a peer at all, it's a single plain-text HTTP
/// body sent to ntfy - so wrapping it in a JSON envelope would just be
/// dead structure ntfy would never parse as anything but noise; the
/// per-string cleaning (`sanitize_str`) is the part of Phase 3.7 that
/// actually applies here, so that's the part reused.
///
/// `sanitize_str`'s existing 256-character cap
/// (`axiom_gateway::sanitize::MAX_UNTRUSTED_STRING_CHARS`) is reused as-is
/// rather than defining a second, notify_send-specific limit - a judgment
/// call: 256 characters is on the short side for a detailed status
/// message but is already a normal single-push-notification length (most
/// phone lock screens truncate previews well below this), and reusing the
/// one already-reviewed constant is preferable to inventing a second
/// magic number this task was told not to. If Larry wants longer
/// notification bodies later, that's a one-line follow-up (a dedicated
/// constant), not a design change. Unlike `network_clients`'s silent-per-
/// field truncation flag (consumed structurally, by code), a human is the
/// only consumer of notify_send's output, so a truncated message gets a
/// visible `" [truncated]"` suffix appended here instead of a JSON
/// sibling field nothing would ever render.
fn prepare_notify_message(payload: &[u8]) -> Result<String, String> {
    let raw = String::from_utf8_lossy(payload);
    if raw.trim().is_empty() {
        return Err("notify_send: payload is empty".to_string());
    }
    let sanitized = axiom_gateway::sanitize::sanitize_str(&raw);
    let mut message = sanitized.value;
    if sanitized.truncated {
        message.push_str(" [truncated]");
    }
    Ok(message)
}

/// AXIOM notify_send: bridge for the `"notify_send"` capability - posts a
/// sanitized message (see `prepare_notify_message`) to UAI's `ntfy` driver
/// (`ntfy_send` tool) on `topic`. Deliberately does NOT call
/// `keepass_lookup` first, unlike `fetch_network_clients` - the ntfy UAI
/// driver resolves its own auth token (if any) from UAI's own
/// config (`uai_secrets.json`'s `tokens.ntfy_token` / env), never from a
/// value the caller supplies, so AXIOM's request body carries only
/// `{message, topic}`, nothing credential-shaped. This is a real,
/// deliberate difference from `network_clients`'s pattern, not a
/// shortcut: it means this capability's UAI token is exercised for
/// exactly one tool (`ntfy_send`) in normal operation, never
/// `keepass_lookup` - a narrower actual usage than network_clients ever
/// had, even though (see this repo's SECURITY.md "AXIOM -> UAI credential
/// scope" section) the TOKEN itself is not narrower: UAI's
/// `/registry/dispatch` still does not restrict which registered tool a
/// valid caller may invoke, so this capability's blast radius if the
/// token itself were ever exfiltrated is exactly as wide as
/// network_clients's would have been. See this function's own call site
/// (`dispatch_notify_send`) and this build's final report for why that
/// residual risk was accepted here rather than hard-denied the way
/// `network_clients` was.
async fn send_notification(uai: &UaiConfig, topic: &str, payload: &[u8]) -> Result<String, String> {
    let message = prepare_notify_message(payload)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let resp = uai_dispatch(&client, uai, "ntfy_send", serde_json::json!({
        "message": message,
        "topic": topic,
    })).await?;

    Ok(resp.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "sent".to_string()))
}

/// Build, sign, and encode a small AXIOM frame (`TrustLevel::Sig`,
/// `PayloadType::Raw`) - the shared shape behind `Ping`/`Pong`/`Intent`/
/// `Fulfill`/`Error`. `intent_hash` is `IntentHash::zero()` for the
/// non-capability frame types (Ping/Pong); `Intent`/`Fulfill`/`Error` use it
/// to identify which capability the exchange is about.
fn build_simple_frame(identity: &Keypair, frame_type: FrameType, trace_id: TraceId, intent_hash: IntentHash, payload: Vec<u8>, routing: Option<RoutingExt>) -> Vec<u8> {
    let header = FrameHeader::new(frame_type, identity.node_id())
        .with_trust_level(TrustLevel::Sig)
        .with_intent(intent_hash);
    let mut frame = Frame::new(header, PayloadType::Raw, payload);
    frame.trace_id = Some(trace_id);
    frame.routing = routing;
    sign_and_encode_frame(identity, frame, frame_type)
}

/// AXIOM-14 Cycle 3: the actual pruning pass behind `spawn_maintenance`,
/// pulled out to a free function taking bare refs (same shape as
/// `handle_axiom_frame`) so tests can call it directly on a real
/// `NetworkManager`'s state without waiting on `ANNOUNCEMENT_MAINTENANCE_INTERVAL`
/// (5 minutes) or racing a real background tokio task.
async fn run_announcement_maintenance(
    announcement_mgr: &Mutex<AnnouncementManager>,
    last_announce_from: &std::sync::Mutex<HashMap<(NodeId, NodeId), std::time::Instant>>,
    origin_admission: &std::sync::Mutex<HashMap<NodeId, (std::time::Instant, HashSet<NodeId>)>>,
    reachable_via: &std::sync::Mutex<HashMap<NodeId, (NodeId, std::time::Instant)>>,
    reverse_routes: &std::sync::Mutex<HashMap<TraceId, (SocketAddr, std::time::Instant)>>,
    known_peers: &std::sync::Mutex<HashSet<NodeId>>,
    semantic_router: &Mutex<SemanticRouter>,
) {
    announcement_mgr.lock().await.cleanup_stale(ANNOUNCEMENT_MAX_AGE);

    let now = std::time::Instant::now();
    last_announce_from.lock().unwrap()
        .retain(|_, last| now.duration_since(*last) < ANNOUNCEMENT_MAX_AGE);
    origin_admission.lock().unwrap()
        .retain(|_, (window_start, _)| now.duration_since(*window_start) < ANNOUNCEMENT_MAX_AGE);

    // AXIOM-14 Cycle 4 (Fable full-repo review finding #3): reachable_via
    // and the SemanticRouter registrations it implies were the two maps
    // Cycle 3's pass missed - both grew forever, with the only purge
    // trigger being LRU peer-eviction pressure, which never fires on a
    // small mesh. The Announce arm's insert already refreshes an origin's
    // timestamp on every accepted touch (not just its first - see
    // `reachable_via`'s field doc comment), so aging out here means "no
    // legitimate re-announce for ANNOUNCEMENT_MAX_AGE," not "first learned
    // more than 30 minutes ago" - a still-alive, periodically re-gossiped
    // route is never pruned out from under itself.
    let stale_origins: Vec<NodeId> = {
        let mut via = reachable_via.lock().unwrap();
        let stale: Vec<NodeId> = via.iter()
            .filter(|(_, (_, touched))| now.duration_since(*touched) >= ANNOUNCEMENT_MAX_AGE)
            .map(|(origin, _)| *origin)
            .collect();
        for origin in &stale {
            via.remove(origin);
        }
        stale
    };
    if !stale_origins.is_empty() {
        let mut router = semantic_router.lock().await;
        for origin in stale_origins {
            // Fable's plan review (Cycle 4): re-check under lock
            // immediately before acting, same reasoning as the LRU
            // eviction branch's existing race guard - a concurrent
            // Announce could have already re-touched `reachable_via` for
            // this exact origin in the gap between collection above and
            // this loop running, and an origin that's since become a
            // direct known peer must never have ITS OWN registrations
            // wiped by a stale-relay-route cleanup.
            if known_peers.lock().unwrap().contains(&origin) {
                continue;
            }
            if reachable_via.lock().unwrap().contains_key(&origin) {
                continue;
            }
            router.unregister_node(&origin);
        }
    }

    // AXIOM-14 Cycle 6: `reverse_routes` breadcrumbs are time-bounded, not
    // capacity-bounded (see that field's doc comment) - this is their only
    // eviction path, piggybacked on the same periodic pass as every other
    // map here rather than a separate mechanism.
    reverse_routes.lock().unwrap()
        .retain(|_, (_, touched)| now.duration_since(*touched) < REVERSE_ROUTE_TTL);
}

/// Sign `frame` (in place) and encode it to wire bytes. Shared tail for
/// every frame builder in this file, including `spawn_announce`'s (whose
/// unsigned `Frame` comes from `AnnouncementManager::create_announcement`
/// instead of being built here).
fn sign_and_encode_frame(identity: &Keypair, mut frame: Frame, frame_type: FrameType) -> Vec<u8> {
    let signer = FrameSigner::new(identity.clone());
    if let Err(e) = signer.sign(&mut frame) {
        warn!("Failed to sign {:?} frame: {:?}", frame_type, e);
        return Vec::new();
    }

    let wire_size = frame.wire_size();
    let mut buffer = vec![0u8; wire_size + 32];
    match Encoder::encode(&frame, &mut buffer) {
        Ok(size) => {
            buffer.truncate(size);
            buffer
        }
        Err(e) => {
            warn!("Failed to encode {:?} frame: {:?}", frame_type, e);
            Vec::new()
        }
    }
}

/// Build a signed AXIOM HELLO frame for `identity`. Shared by
/// `NetworkManager::create_hello_message` and the discovery module, which
/// announces the same frame over link-local multicast.
pub(crate) fn build_hello_frame(identity: &Keypair) -> Vec<u8> {
    build_frame(identity, HELLO_MSG_TYPE)
}

/// Build a signed AXIOM HELLO_ACK frame - what `start_receive_loop` sends
/// back in response to an unsolicited HELLO, so the dialing side's
/// `connect()` learns the real NodeId instead of guessing one.
fn build_hello_reply_frame(identity: &Keypair) -> Vec<u8> {
    build_frame(identity, HELLO_ACK_MSG_TYPE)
}

fn build_frame(identity: &Keypair, msg_type: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // AXIOM magic + version
    buf.extend_from_slice(&[0x41, 0x58, 0x49, 0x4F]); // "AXIO"
    buf.push(0x01); // Version 1

    buf.push(msg_type);

    // Our node ID
    buf.extend_from_slice(identity.node_id().as_bytes());

    // Timestamp. A clock set before 1970 would fail `duration_since` - fall
    // back to 0 rather than panic the whole node; a HELLO timestamped 0
    // simply gets rejected downstream as stale, which is the correct
    // behavior for a node with a broken clock anyway.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    buf.extend_from_slice(&timestamp.to_be_bytes());

    // Sign the message
    let signature = identity.sign(&buf);
    buf.extend_from_slice(signature.as_bytes());

    buf
}

/// Peek an AXIOM frame's message-type byte without fully decoding it.
/// Returns `None` if the frame is too short to contain one.
fn frame_msg_type(data: &[u8]) -> Option<u8> {
    data.get(5).copied()
}

/// Extract sender node ID from AXIOM frame, verifying the signature against
/// the *claimed* node ID first. Without this check, anyone can put an
/// arbitrary NodeId in the frame and have it trusted as-is - harmless when
/// this only fed a passive log line, but `discovery::start` now uses this to
/// auto-register peers from unauthenticated multicast, so an unverified
/// claim would let anyone on the LAN segment impersonate any NodeId.
pub(crate) fn extract_sender(data: &[u8]) -> Option<NodeId> {
    extract_sender_with_timestamp(data).map(|(node_id, _)| node_id)
}

/// Same as `extract_sender`, plus the frame's signed timestamp (unix secs).
/// `discovery::start` uses the timestamp for replay/freshness rejection -
/// the signature alone only proves someone who once held the key produced
/// these bytes, not that the bytes are fresh, so a captured HELLO could
/// otherwise be replayed later to rebind a peer's address in `register_peer`.
pub(crate) fn extract_sender_with_timestamp(data: &[u8]) -> Option<(NodeId, u64)> {
    // magic(4) + version(1) + type(1) + node_id(32) + timestamp(8) + signature(64)
    if data.len() < 110 {
        return None;
    }

    if &data[0..4] != b"AXIO" {
        return None;
    }

    let mut node_id_bytes = [0u8; 32];
    node_id_bytes.copy_from_slice(&data[6..38]);
    let node_id = NodeId::from_bytes(node_id_bytes);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&data[38..46]);
    let timestamp = u64::from_be_bytes(ts_bytes);

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&data[46..110]);
    let signature = Signature::from_bytes(sig_bytes);

    // Signed payload is everything before the signature (magic..timestamp).
    if !node_id.verify(&data[0..46], &signature) {
        return None;
    }

    Some((node_id, timestamp))
}

/// True if `addr` is an IPv6 link-local (fe80::/10) address - these require
/// `discovery_socket` since `socket` is usually bound to an IPv4 address.
fn is_link_local_v6(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V6(v6) => (v6.ip().segments()[0] & 0xffc0) == 0xfe80,
        SocketAddr::V4(_) => false,
    }
}

/// AXIOM-14 Cycle 4 (Fable full-repo review finding #4): the same
/// family-aware socket selection `send_raw`/`spawn_ping`/`spawn_announce`
/// already use, pulled out to a free function so `handle_axiom_frame`'s
/// re-gossip and forward send sites can share it too. Before this cycle,
/// both of those blindly reused whichever socket the triggering frame
/// happened to arrive on - a frame arriving on the IPv4 loop that needed
/// re-gossiping/forwarding to an `fe80::` peer would fail `send_to`
/// (wrong address family for that socket), and vice versa, silently
/// losing exactly the multi-hop and gossip paths in any deployment with a
/// mixed peer set (this deployment has one, since link-local discovery is
/// enabled).
async fn send_via(
    socket: &Arc<UdpSocket>,
    discovery_socket: &Option<Arc<UdpSocket>>,
    addr: &SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    if is_link_local_v6(addr) {
        if let Some(disc) = discovery_socket {
            return disc.send_to(data, addr).await;
        }
    }
    socket.send_to(data, addr).await
}

/// AXIOM Phase 1.1: writes a permissive capability policy TOML file
/// allowing every `NodeId` in `allowed_peers` to call every one of `echo`/
/// `sysinfo`/`network_clients` on the node this config belongs to, no rate
/// limit, generous concurrency. Used by the routing/forwarding/gossip test
/// modules below (`multihop_tests`, `gossip_tests`, `deep_indirection_tests`)
/// - those tests exist to prove routing/forwarding/discovery mechanics, not
/// authorization, so their fixtures just need policy to get out of the way
/// for whichever peers they name, the same way `known_peers`-gates-
/// echo/sysinfo used to before AXIOM Phase 1.1 replaced it. Tests that
/// specifically exercise `CapabilityPolicy`'s own fail-closed/allowlist/
/// rate-limit/concurrency behavior live in axiom-gateway's `policy.rs` and this file's
/// `policy_dispatch_tests` module instead, and build policy files with
/// deliberately narrow/empty allowlists.
#[cfg(test)]
fn write_permissive_test_policy(port: u16, allowed_peers: &[NodeId]) -> std::path::PathBuf {
    let allowed_toml = allowed_peers.iter()
        .map(|p| format!("\"{}\"", hex::encode(p.as_bytes())))
        .collect::<Vec<_>>()
        .join(", ");
    // AXIOM Phase 3.1/3.2: schema v2 - every [capability.*] table needs a
    // `tier` now (axiom_gateway::policy's module doc comment / Tier), or
    // it fails closed regardless of allowed_peers. Tiers here match the
    // real ratified assignments (DECISIONS.md's "Tier model" section):
    // echo/sysinfo = tier0, network_clients = tier1 (despite being
    // read-only - it exercises real UAI credentials).
    // AXIOM Phase 3.6: network_clients (tier1) also needs a
    // [[protected_resource]] section present or it fails closed at
    // registration regardless of allowed_peers - see axiom-gateway's
    // policy.rs. Functionally inert either way for THESE tests specifically
    // (network_clients is hard-denied unconditionally in dispatch_intent
    // before the policy check ever runs, per AXIOM Phase 1.4 - see that
    // function's own doc comment), but added anyway so this fixture
    // doesn't silently rely on that separate, unrelated gate to avoid a
    // "failing closed" warning log on every test run.
    // AXIOM notify_send: tier1, same shape as network_clients above, but
    // (unlike network_clients) NOT hard-denied in dispatch_intent - so
    // this entry is functionally live for these tests, not inert.
    let contents = format!(
        "version = 2\n\n\
         [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
         [capability.echo]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier0\"\n\n\
         [capability.sysinfo]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier0\"\n\n\
         [capability.network_clients]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.notify_send]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.proxmox_restart]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.home_assistant_toggle]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.docker_restart]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.wg_peers_list]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\n\n\
         [capability.wg_peer_manage]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier2\"\n",
    );
    // Unique per (port, pid) - test ports are already unique per test
    // function in this file, and pid guards against two full test-binary
    // runs racing on the same shared temp dir.
    let path = std::env::temp_dir().join(format!("axiom-test-policy-{}-{}.toml", port, std::process::id()));
    std::fs::write(&path, contents).expect("write permissive test policy file");
    path
}

#[cfg(test)]
mod multihop_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    /// AXIOM-14 Cycle 1b's first-ever 3-node test: A, B, D, where A and D
    /// NEVER directly handshake - the only reason A can reach D's capability
    /// at all is that B forwards for both of them. Real UDP sockets, real
    /// signed frames, real HELLO handshakes for A<->B and B<->D - the only
    /// thing bypassed is the full `ForgeNode` event loop that would
    /// normally drive `register_peer()` on the answering side of a
    /// handshake in production (nothing in this test suite constructs a
    /// full `ForgeNode`, just bare `NetworkManager`s) - so the answering
    /// side's registration is done directly here instead, which is exactly
    /// what that event loop would have done in response to the same
    /// `PeerDiscovered` event `connect()`'s HELLO already triggered.
    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            // Deliberately off - real interface link-local discovery has no
            // business running inside a unit test and would be
            // non-deterministic across CI/dev machines.
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    #[tokio::test]
    async fn test_multihop_intent_via_relay() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19301);
        let config_b = test_config(19302);
        // AXIOM Phase 1.1: A (the requester) must be on D's echo policy
        // allowlist now - a completed handshake alone no longer grants
        // capability access.
        let mut config_d = test_config(19303);
        config_d.capability_policy_path = write_permissive_test_policy(19303, &[kp_a.node_id()]);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        // A <-> B: real HELLO/HELLO_ACK handshake, both directions.
        let b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        assert_eq!(b_id, kp_b.node_id());
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        // B <-> D: same. A never talks to D directly - not even once.
        let d_id = mgr_b.connect(&config_d.listen_addr).await.unwrap();
        assert_eq!(d_id, kp_d.node_id());
        mgr_d.register_peer(kp_b.node_id(), config_b.listen_addr, 1);

        // D serves "echo" by default (NodeConfig::default()'s capabilities).
        // A asks for it explicitly via B as the relay - the actual point of
        // this whole cycle: reaching a capability on a node A has no direct
        // connection to at all.
        let result = mgr_a
            .request_intent_via(b_id, d_id, "echo", b"hello multihop".to_vec())
            .await
            .expect("request_intent_via should succeed through the relay");

        assert_eq!(result, b"hello multihop".to_vec());
    }

    /// TTL=0 must drop at the very first relay, even though a valid route
    /// exists (D IS a direct peer of B) - isolates the TTL-exhaustion drop
    /// path specifically from the separate "no known route" path (see the
    /// next test), by using a topology where forwarding would otherwise
    /// succeed if not for the TTL.
    #[tokio::test]
    async fn test_multihop_ttl_zero_drops_frame() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19311);
        let config_b = test_config(19312);
        let config_d = test_config(19313);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        let _b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        let d_id = mgr_b.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_b.node_id(), config_b.listen_addr, 1);

        // Hand-built with ttl=0 - request_intent_via always uses
        // DEFAULT_ROUTING_TTL, so this bypasses it deliberately to exercise
        // the drop path a real multi-hop chain would eventually hit.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(
            &kp_a,
            AiIntent::from_str("echo").hash,
            trace_id,
            b"should not arrive".to_vec(),
            Some(RoutingExt::new(d_id, 0)),
        );
        mgr_a.send_raw(&config_b.listen_addr, &frame_bytes).await.unwrap();

        // B has a real route to D (they're direct peers) - if TTL weren't
        // checked first, this would forward successfully. Confirm D never
        // receives anything within a short, generous window.
        let mut probe_buf = [0u8; 16];
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            mgr_d.socket.recv_from(&mut probe_buf),
        ).await;
        assert!(recv_result.is_err(), "D should never receive a ttl=0 frame, even with a valid route through B");
    }

    /// A chain (A-B-C-D) where B has no direct route to D (only C does) -
    /// the frame dies at B's very first forwarding decision, regardless of
    /// TTL. Distinct failure mode from TTL exhaustion above: Cycle 1b's
    /// routing table is degenerate (direct peers only, no multi-hop route
    /// propagation - that's Cycle 2), so B genuinely has no way to know D
    /// is reachable via C at all.
    #[tokio::test]
    async fn test_multihop_no_known_route_drops_frame() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19321);
        let config_b = test_config(19322);
        let config_c = test_config(19323);
        let config_d = test_config(19324);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        let _b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        let c_id = mgr_b.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_b.node_id(), config_b.listen_addr, 1);
        let d_id = mgr_c.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_c.node_id(), config_c.listen_addr, 1);

        // Sent to B, addressed to D, with plenty of TTL - B simply has no
        // route to D (only C does), so this must drop at B regardless.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(
            &kp_a,
            AiIntent::from_str("echo").hash,
            trace_id,
            b"should not arrive".to_vec(),
            Some(RoutingExt::new(d_id, DEFAULT_ROUTING_TTL)),
        );
        mgr_a.send_raw(&config_b.listen_addr, &frame_bytes).await.unwrap();

        let mut probe_buf = [0u8; 16];
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            mgr_d.socket.recv_from(&mut probe_buf),
        ).await;
        assert!(recv_result.is_err(), "D should never receive a frame B has no route for, even via a real chain through C");

        let _ = c_id;
    }

    /// Fable's Cycle 1b diff review finding: a relay must not forward for a
    /// UDP source it hasn't itself handshaken with, or the destination's
    /// "immediate UDP source is a known peer" gate becomes vacuous - it'd be
    /// checking that a frame arrived via a relay whose OWN upstream source
    /// was never authenticated. `kp_e` here is a real, validly-signed
    /// keypair (a signature alone proves *a* real keypair, not a peer B has
    /// agreed to talk to) that never handshakes with B at all - B must
    /// refuse to relay for it even though B->D is a perfectly good route.
    #[tokio::test]
    async fn test_multihop_stranger_relay_source_rejected() {
        let kp_b = Keypair::generate();
        let kp_d = Keypair::generate();
        let kp_e = Keypair::generate(); // never connects to B - a stranger

        let config_b = test_config(19331);
        let config_d = test_config(19332);
        let config_e = test_config(19333);

        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();
        let mgr_e = NetworkManager::new(&config_e, kp_e.clone()).await.unwrap();

        // B<->D is a real, valid route - if B relayed indiscriminately by
        // UDP source, this frame WOULD reach D. It must not.
        let d_id = mgr_b.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_b.node_id(), config_b.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(
            &kp_e,
            AiIntent::from_str("echo").hash,
            trace_id,
            b"should not arrive".to_vec(),
            Some(RoutingExt::new(d_id, DEFAULT_ROUTING_TTL)),
        );
        // Sent directly from E's own socket, not via mgr_b - B never dialed
        // E and never received a HELLO from E, so B's peer_addrs has no
        // entry for E's address at all.
        mgr_e.socket.send_to(&frame_bytes, config_b.listen_addr).await.unwrap();

        let mut probe_buf = [0u8; 16];
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            mgr_d.socket.recv_from(&mut probe_buf),
        ).await;
        assert!(recv_result.is_err(), "D should never receive a frame relayed from an unauthenticated stranger, even via a real B->D route");
    }

    /// AXIOM-14 Cycle 6 (piece 2's `reachable_via` fallback, regression
    /// coverage for a stale/blackhole entry): B's `reachable_via` claims D
    /// is reachable via some relay R, but R was never actually a peer of
    /// B's at all (simulating a stale entry surviving after R disconnected,
    /// or simply a corrupt/bogus one) - distinct from
    /// `test_multihop_no_known_route_drops_frame` above, which covers "no
    /// `reachable_via` entry at all." This proves the NEW fallback path
    /// itself fails closed on a bad entry (peer_addrs lookup for the
    /// claimed relay comes up empty) rather than panicking, looping, or
    /// misdelivering the frame anywhere - D (a real, running node) must
    /// never receive anything, and this test completing at all (not
    /// hanging) is itself part of the proof.
    #[tokio::test]
    async fn test_multihop_stale_reachable_via_entry_drops_cleanly() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_d = Keypair::generate();
        let kp_stale_relay = Keypair::generate(); // never a peer of B at all

        let config_a = test_config(19341);
        let config_b = test_config(19342);
        let config_d = test_config(19343);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        let _b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        let d_id = kp_d.node_id();

        // Manually seed a blackhole entry - B "knows" D is reachable via
        // kp_stale_relay, but kp_stale_relay was never actually connected to
        // B, so B has no address to send to even after consulting it.
        mgr_b.reachable_via.lock().unwrap().insert(d_id, (kp_stale_relay.node_id(), std::time::Instant::now()));

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(
            &kp_a,
            AiIntent::from_str("echo").hash,
            trace_id,
            b"should not arrive".to_vec(),
            Some(RoutingExt::new(d_id, DEFAULT_ROUTING_TTL)),
        );
        mgr_a.send_raw(&config_b.listen_addr, &frame_bytes).await.unwrap();

        let mut probe_buf = [0u8; 16];
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            mgr_d.socket.recv_from(&mut probe_buf),
        ).await;
        assert!(recv_result.is_err(), "D must never receive a frame routed via a stale reachable_via entry pointing at a relay B was never actually connected to");
    }
}

#[cfg(test)]
mod gossip_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    /// AXIOM-14 Cycle 2b's actual point, end to end over real sockets: A
    /// learns about D's capability - and can successfully USE it via
    /// `request_intent`'s automatic fallback - having never directly
    /// handshaken D at all. The only thing A ever did was handshake B;
    /// discovery of D happened entirely through B's live gossip-forward of
    /// D's Announce, wired through the real `handle_axiom_frame` receive
    /// path (not manually constructed frames the way the announce.rs unit
    /// tests exercise the dedup logic in isolation).
    #[tokio::test]
    async fn test_gossip_discovery_via_relay() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19351);
        let config_b = test_config(19352);
        // AXIOM Phase 1.1: A (the requester, reached indirectly via gossip)
        // must be on D's echo policy allowlist.
        let mut config_d = test_config(19353);
        config_d.capability_policy_path = write_permissive_test_policy(19353, &[kp_a.node_id()]);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        let b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let d_id = mgr_b.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_b.node_id(), config_b.listen_addr, 1);

        // D announces to B - a real signed Announce frame over a real UDP
        // socket. B's live receive loop should: accept it (D is a known
        // peer of B), register D's capability under D's own NodeId (not
        // B's), record reachable_via[D] = B, and re-gossip to every OTHER
        // direct peer of B's - which is A.
        mgr_d.spawn_announce(config_b.listen_addr);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // A never handshook D. This must still work, with zero out-of-band
        // knowledge of D's NodeId - request_intent's fallback through
        // reachable_via is what makes it possible.
        let (responder, result) = mgr_a
            .request_intent("echo", b"gossip discovery works".to_vec())
            .await
            .expect("request_intent should succeed via the automatically-learned relay");
        assert_eq!(responder, d_id, "the capability must be attributed to D (the real origin), not B (the relay)");
        assert_eq!(result, b"gossip discovery works".to_vec());

        let _ = b_id;
    }

    /// A real cyclic topology (A-B-C all pairwise directly connected, not
    /// a tree/chain) - the shape that actually creates the amplification
    /// risk Fable's plan review caught (a linear chain can't loop). This
    /// proves the LIVE wiring correctly routes into the dedup logic in a
    /// topology where naive flooding would matter; it does NOT re-prove
    /// the dedup logic itself is correct in isolation - that's already
    /// empirically proven at the unit level in `announce.rs`
    /// (`test_gossip_dedup_keys_on_stable_origin_not_relay`, verified to
    /// genuinely fail against the pre-fix code by temporarily reverting
    /// it). What this test adds: real sockets, real re-gossip fan-out,
    /// and confirms discovery still converges correctly (A's capability
    /// registered under A's own NodeId at both B and C) when every node
    /// has more than one neighbor to potentially re-forward to.
    #[tokio::test]
    async fn test_gossip_cycle_topology_converges() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let config_a = test_config(19361);
        let config_b = test_config(19362);
        let config_c = test_config(19363);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();

        // A real triangle: every pair directly connected, each pair via
        // one side's connect() + the other side's manual register_peer()
        // (matching the established pattern in `multihop_tests` - no full
        // ForgeNode event loop exists in this test to drive answering-side
        // registration automatically).
        mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        mgr_a.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_a.node_id(), config_a.listen_addr, 2);

        mgr_b.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_b.node_id(), config_b.listen_addr, 3);

        mgr_c.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_c.node_id(), config_c.listen_addr, 4);

        // A announces directly to BOTH B and C (both are its direct
        // peers) - this alone, in a naive implementation, could set off
        // B forwarding to C and C forwarding to B in an endless loop,
        // since B and C are also directly connected to each other.
        mgr_a.spawn_announce(config_b.listen_addr);
        mgr_a.spawn_announce(config_c.listen_addr);

        // Generous window - long enough that an actual unbounded loop
        // would have produced many rounds of re-gossip by now, but the
        // test still completes in bounded time either way (tokio::test
        // has its own runtime, this doesn't hang forever regardless).
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        // Both B and C must have A's capability correctly registered
        // under A's own NodeId - discovery converges correctly even
        // though every node had multiple neighbors to potentially
        // re-forward through.
        let b_router = mgr_b.semantic_router.lock().await;
        let c_router = mgr_c.semantic_router.lock().await;
        let intent = AiIntent::from_str("echo");
        assert!(
            b_router.discover(&intent).into_iter().any(|c| *c.agent.node_id() == kp_a.node_id()),
            "B must have A's capability registered"
        );
        assert!(
            c_router.discover(&intent).into_iter().any(|c| *c.agent.node_id() == kp_a.node_id()),
            "C must have A's capability registered"
        );
        drop(b_router);
        drop(c_router);

        // Fable's diff review: A is a direct peer of both B and C, so the
        // `!known_peers.contains(&origin)` branch that populates
        // `reachable_via` must never have fired for A at either - catches
        // a class of ordering bug where the gossiped copy (arriving via
        // the other node) races the direct copy and mis-populates the
        // relay map for a peer that was never actually indirect.
        assert!(mgr_b.reachable_via.lock().unwrap().is_empty(), "B must not record a relay for A - A is B's direct peer");
        assert!(mgr_c.reachable_via.lock().unwrap().is_empty(), "C must not record a relay for A - A is C's direct peer");
    }

    /// AXIOM-14 Cycle 6 (piece 5, test 3): the triangle A-B-C from
    /// `test_gossip_cycle_topology_converges` above, PLUS a spur node D
    /// hanging off C only (C<->D direct, D not connected to A or B at
    /// all) - a real cycle (A-B-C) feeding a real multi-hop routing target
    /// (D), combining this cycle's new pieces (the `reachable_via`
    /// consultation in `try_forward_routed_frame` and the `reverse_routes`
    /// breadcrumb) with the exact cyclic-gossip shape Fable's Cycle 2 plan
    /// review flagged as the amplification risk. Proves both: gossip still
    /// converges without an unbounded forwarding loop in a topology with a
    /// real cycle (not just a chain), AND a routed Intent/Fulfill round
    /// trip through it actually completes rather than looping or hanging -
    /// bounded by an outer timeout well under `INTENT_TIMEOUT` so a
    /// regression to an actual stuck loop fails this test promptly instead
    /// of burning 25s per run.
    #[tokio::test]
    async fn test_gossip_cycle_topology_routes_to_spur_node() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19371);
        let config_b = test_config(19372);
        let config_c = test_config(19373);
        // AXIOM Phase 1.1: A (the requester) must be on D's echo policy
        // allowlist.
        let mut config_d = test_config(19374);
        config_d.capability_policy_path = write_permissive_test_policy(19374, &[kp_a.node_id()]);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        // The triangle: A, B, C all pairwise directly connected.
        mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        mgr_a.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_a.node_id(), config_a.listen_addr, 2);
        mgr_b.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_b.node_id(), config_b.listen_addr, 3);
        mgr_c.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_c.node_id(), config_c.listen_addr, 4);

        // The spur: D is directly connected to C only.
        let d_id = mgr_c.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_c.node_id(), config_c.listen_addr, 1);

        // D announces to C. C gossip-forwards to both A and B (its other
        // two direct peers); A and B may each attempt to further forward
        // to each other/back toward C, but strictly-newer-only dedup on
        // (origin, origin_clock) must suppress every one of those without
        // an unbounded loop, exactly as the sibling triangle test above
        // already proves for a direct announce - this test adds a real
        // multi-hop routing target behind the cycle, not just gossip.
        mgr_d.spawn_announce(config_c.listen_addr);
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        // A never touched D directly - only through the cyclic gossip above.
        // Bounded well under INTENT_TIMEOUT (25s): if a regression turns
        // this into a stuck forwarding loop instead of a clean multi-hop
        // delivery, this test fails promptly rather than burning a full
        // timeout per run.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mgr_a.request_intent("echo", b"cycle plus spur".to_vec()),
        ).await;
        let (responder, payload) = result
            .expect("request_intent must not hang/loop - it must resolve well within 5s")
            .expect("request_intent should succeed via the cyclic-gossip-learned route to the spur node D");
        assert_eq!(responder, d_id, "the capability must be attributed to D, not to any relay along the way");
        assert_eq!(payload, b"cycle plus spur".to_vec());
    }
}

#[cfg(test)]
mod origin_admission_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;
    use axiom_types::clock::HybridClock;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    /// Build a real signed Announce frame relayed by `sender` but claiming
    /// `origin` (which is NOT `sender`'s own identity - that's the whole
    /// point, a relay legitimately forwards announcements about OTHER
    /// origins). Carries one real capability, not zero -
    /// `process_announcement` returns `None` for an empty capability list
    /// (nothing to mark "fresh"), which would make the admission gate's
    /// effect unobservable via `reachable_via` even when it correctly let
    /// the frame through. AXIOM-14 Cycle 4: `origin` is now a full
    /// `Keypair`, not just a `NodeId` - the payload-level origin claim
    /// must be genuinely signed by it (`AnnouncePayload::origin_signing_bytes_for`),
    /// or the live Announce arm's Cycle 4 verification drops it before it
    /// ever reaches the admission gate this test module exists to exercise.
    fn build_announce_bytes(sender: &Keypair, origin: &Keypair) -> Vec<u8> {
        let origin_clock = HybridClock::now();
        let capabilities = [AnnouncedCapability::new(AiIntent::from_str("echo").hash, *b"echo")];
        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin.node_id(), &origin_clock, &capabilities);
        let origin_signature = origin.sign(&signing_bytes);

        let mut payload = AnnouncePayload::new(1)
            .with_origin(origin.node_id(), origin_clock)
            .with_origin_signature(origin_signature);
        payload.add_capability(capabilities[0].clone());
        let header = FrameHeader::new(FrameType::Announce, sender.node_id()).with_trust_level(TrustLevel::Sig);
        let frame = Frame::new(header, PayloadType::Raw, payload.encode());
        sign_and_encode_frame(sender, frame, FrameType::Announce)
    }

    /// AXIOM-14 Cycle 3's actual point: a single relay claiming a fresh
    /// fabricated origin on every Announce bypasses the pre-existing
    /// (sender, origin) pair-level rate limit entirely, since a NEW origin
    /// never collides with the previous key. Without the distinct-origins
    /// cap this test would see all 17 origins registered in
    /// `reachable_via`; with it, only the first
    /// `MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW` should land.
    #[tokio::test]
    async fn test_origin_admission_caps_distinct_origins_per_sender() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19381);
        let config_b = test_config(19382);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();

        // B's Announce arm gates on `known_peers.contains(&sender_id)`
        // before it ever looks at admission - A must be a known peer of B.
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let mut admitted_origins = Vec::new();
        for _ in 0..MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW {
            let origin = Keypair::generate();
            let bytes = build_announce_bytes(&kp_a, &origin);
            mgr_a.socket.send_to(&bytes, config_b.listen_addr).await.unwrap();
            admitted_origins.push(origin.node_id());
        }
        let rejected_origin = Keypair::generate();
        let bytes = build_announce_bytes(&kp_a, &rejected_origin);
        mgr_a.socket.send_to(&bytes, config_b.listen_addr).await.unwrap();
        let rejected_origin = rejected_origin.node_id();

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        for origin in &admitted_origins {
            assert!(
                mgr_b.reachable_via.lock().unwrap().contains_key(origin),
                "the first {} distinct origins from A within one window must be admitted",
                MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW
            );
        }
        assert!(
            !mgr_b.reachable_via.lock().unwrap().contains_key(&rejected_origin),
            "the {}th distinct origin from the SAME sender within one window must be dropped by the admission cap",
            MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW + 1
        );
        // Fable diff review, adjustment 1: the over-cap drop must happen
        // BEFORE last_announce_from's own bookkeeping, so a rejected
        // origin grows nothing there either - not just reachable_via.
        assert!(
            !mgr_b.last_announce_from.lock().unwrap().contains_key(&(kp_a.node_id(), rejected_origin)),
            "a rejected over-cap origin must never be inserted into last_announce_from"
        );
    }

    /// Proves the window actually rolls over rather than permanently
    /// capping a sender at `MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW`
    /// origins for the life of the connection. Seeds B's admission state
    /// directly as if a full window had already elapsed (real time, not
    /// mocked - `ORIGIN_ADMISSION_WINDOW` is 60s, too slow to actually
    /// sleep through in a test) and confirms a fresh origin from the same
    /// sender is admitted once the stale window is backdated far enough
    /// to trigger the same `now.duration_since(entry.0) >=
    /// ORIGIN_ADMISSION_WINDOW` rollover the live code path uses.
    #[tokio::test]
    async fn test_origin_admission_window_resets_after_expiry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19383);
        let config_b = test_config(19384);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        // Simulate A having already exhausted its window with
        // MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW fabricated origins,
        // long enough ago that the window has expired.
        let stale_window_start = std::time::Instant::now()
            .checked_sub(ORIGIN_ADMISSION_WINDOW + std::time::Duration::from_secs(1))
            .expect("test host clock must support subtracting ~61s from now");
        let mut exhausted = HashSet::new();
        for _ in 0..MAX_DISTINCT_ORIGINS_PER_SENDER_PER_WINDOW {
            exhausted.insert(Keypair::generate().node_id());
        }
        mgr_b.origin_admission.lock().unwrap().insert(kp_a.node_id(), (stale_window_start, exhausted));

        let fresh_origin = Keypair::generate();
        let bytes = build_announce_bytes(&kp_a, &fresh_origin);
        mgr_a.socket.send_to(&bytes, config_b.listen_addr).await.unwrap();
        let fresh_origin = fresh_origin.node_id();

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        assert!(
            mgr_b.reachable_via.lock().unwrap().contains_key(&fresh_origin),
            "a fresh origin must be admitted once the sender's prior window has expired, not permanently capped"
        );
        let admission = mgr_b.origin_admission.lock().unwrap();
        let (window_start, set) = admission.get(&kp_a.node_id()).expect("A must have an admission entry after the reset");
        assert!(*window_start > stale_window_start, "the window must have actually rolled over, not just accumulated onto the stale one");
        assert_eq!(set.len(), 1, "the rolled-over window must start counting fresh, not carry over the expired window's 16 entries");
    }

    /// `run_announcement_maintenance` (the pruning pass `spawn_maintenance`
    /// runs every `ANNOUNCEMENT_MAINTENANCE_INTERVAL`) must actually shrink
    /// `last_announce_from` and `origin_admission` once their entries are
    /// older than `ANNOUNCEMENT_MAX_AGE` - otherwise a long-lived node
    /// facing a slow trickle of distinct peers/origins over days grows both
    /// unboundedly despite the maps existing specifically to bound memory.
    /// Calls the free function directly rather than `spawn_maintenance`
    /// itself, since the latter's real interval (5 minutes) makes it
    /// impractical to observe in a test.
    #[tokio::test]
    async fn test_maintenance_prunes_stale_entries() {
        let config = test_config(19385);
        let kp = Keypair::generate();
        let mgr = NetworkManager::new(&config, kp.clone()).await.unwrap();

        let stale = std::time::Instant::now()
            .checked_sub(ANNOUNCEMENT_MAX_AGE + std::time::Duration::from_secs(1))
            .expect("test host clock must support subtracting past ANNOUNCEMENT_MAX_AGE from now");
        let fresh = std::time::Instant::now();

        let stale_pair = (Keypair::generate().node_id(), Keypair::generate().node_id());
        let fresh_pair = (Keypair::generate().node_id(), Keypair::generate().node_id());
        mgr.last_announce_from.lock().unwrap().insert(stale_pair, stale);
        mgr.last_announce_from.lock().unwrap().insert(fresh_pair, fresh);

        let stale_sender = Keypair::generate().node_id();
        let fresh_sender = Keypair::generate().node_id();
        mgr.origin_admission.lock().unwrap().insert(stale_sender, (stale, HashSet::new()));
        mgr.origin_admission.lock().unwrap().insert(fresh_sender, (fresh, HashSet::new()));

        // AXIOM-14 Cycle 4 (Fable full-repo review finding #3): reachable_via
        // and the SemanticRouter registration it implies. Three cases:
        // stale + not a direct peer (must be pruned AND unregistered),
        // fresh (must survive untouched), stale but now a direct known
        // peer (the relay-route entry is stale and gets removed either
        // way, but the router registration must NOT be touched - that's
        // the race-guard Fable's plan review required).
        let stale_via_origin = Keypair::generate().node_id();
        let fresh_via_origin = Keypair::generate().node_id();
        let stale_but_known_origin = Keypair::generate().node_id();
        let relay = Keypair::generate().node_id();
        mgr.reachable_via.lock().unwrap().insert(stale_via_origin, (relay, stale));
        mgr.reachable_via.lock().unwrap().insert(fresh_via_origin, (relay, fresh));
        mgr.reachable_via.lock().unwrap().insert(stale_but_known_origin, (relay, stale));
        mgr.known_peers.lock().unwrap().insert(stale_but_known_origin);

        {
            let mut router = mgr.semantic_router.lock().await;
            router.register(stale_via_origin, SemanticCapability::new("echo"));
            router.register(fresh_via_origin, SemanticCapability::new("echo"));
            router.register(stale_but_known_origin, SemanticCapability::new("echo"));
        }

        run_announcement_maintenance(
            &mgr.announcement_mgr, &mgr.last_announce_from, &mgr.origin_admission,
            &mgr.reachable_via, &mgr.reverse_routes, &mgr.known_peers, &mgr.semantic_router,
        ).await;

        let last_announce = mgr.last_announce_from.lock().unwrap();
        assert!(!last_announce.contains_key(&stale_pair), "an entry older than ANNOUNCEMENT_MAX_AGE must be pruned");
        assert!(last_announce.contains_key(&fresh_pair), "an entry younger than ANNOUNCEMENT_MAX_AGE must survive");
        drop(last_announce);

        let admission = mgr.origin_admission.lock().unwrap();
        assert!(!admission.contains_key(&stale_sender), "a stale admission window must be pruned");
        assert!(admission.contains_key(&fresh_sender), "a fresh admission window must survive");
        drop(admission);

        let via = mgr.reachable_via.lock().unwrap();
        assert!(!via.contains_key(&stale_via_origin), "a stale reachable_via entry must be pruned");
        assert!(via.contains_key(&fresh_via_origin), "a fresh reachable_via entry must survive");
        assert!(!via.contains_key(&stale_but_known_origin), "a stale reachable_via entry is removed regardless of known-peer status - it's vestigial relay-routing info either way");
        drop(via);

        let intent = AiIntent::from_str("echo");
        let router = mgr.semantic_router.lock().await;
        let registered: Vec<NodeId> = router.discover(&intent).into_iter().map(|c| *c.agent.node_id()).collect();
        assert!(!registered.contains(&stale_via_origin), "a stale, not-a-direct-peer origin's SemanticRouter registration must be unregistered");
        assert!(registered.contains(&fresh_via_origin), "a fresh origin's registration must survive untouched");
        assert!(registered.contains(&stale_but_known_origin), "an origin that's since become a direct known peer must NOT have its registration wiped by stale-relay-route cleanup, even though its reachable_via entry was stale");
    }
}

#[cfg(test)]
mod deep_indirection_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    /// AXIOM-14 Cycle 6 (piece 5, test 1): the actual multi-hop routing
    /// proof for this cycle - a real 4-node chain (A-B-C-D, each link a
    /// real HELLO/HELLO_ACK handshake, D's Announce a real signed frame
    /// gossiped hop by hop) where A has ZERO prior knowledge of D: no
    /// direct connection, no out-of-band NodeId, nothing. D is exactly
    /// `MAX_ROUTE_INDIRECTION` (2) hops of indirection away from A (A-B,
    /// B-C, C-D - 2 relay hops beyond A's own direct peer B) - the edge of
    /// what this cycle's routing-reach increase is supposed to cover, not
    /// comfortably inside it. `request_intent`'s fully automatic discovery
    /// fallback (learn D via gossip-populated `reachable_via`, then
    /// `request_intent_via`) must succeed end to end, including the
    /// Fulfill actually finding its way back through C and B to A.
    #[tokio::test]
    async fn test_deep_chain_intent_via_automatic_discovery() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        let config_a = test_config(19401);
        let config_b = test_config(19402);
        let config_c = test_config(19403);
        // AXIOM Phase 1.1: A (the requester) must be on D's echo policy
        // allowlist.
        let mut config_d = test_config(19404);
        config_d.capability_policy_path = write_permissive_test_policy(19404, &[kp_a.node_id()]);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        mgr_b.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_b.node_id(), config_b.listen_addr, 1);
        let d_id = mgr_c.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_c.node_id(), config_c.listen_addr, 1);

        // D announces to C; gossip must survive 2 forward hops (C->B,
        // B->A) for A to ever learn about D at all - exactly
        // MAX_ROUTE_INDIRECTION's budget, not a margin inside it.
        mgr_d.spawn_announce(config_c.listen_addr);
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mgr_a.request_intent("echo", b"deep chain".to_vec()),
        ).await;
        let (responder, payload) = result
            .expect("request_intent must not hang - full 2-hop-indirection discovery+routing must resolve well within 5s")
            .expect("request_intent should succeed through the full A-B-C-D chain with zero prior knowledge of D");
        assert_eq!(responder, d_id, "must be attributed to D, the real origin/provider");
        assert_eq!(payload, b"deep chain".to_vec());
    }

    /// AXIOM-14 Cycle 6 (piece 5, test 2): THE regression test Fable's plan
    /// review specifically flagged as the one that would have caught the
    /// missing reverse-path-breadcrumb piece. Identical A-B-C-D chain to
    /// the test above, except A is a PURE CONSUMER - zero registered
    /// capabilities. A's own `Announce` (if it ever sent one) would carry
    /// zero capabilities and be dropped outright by `process_announcement`
    /// (`any_fresh` never gets set - see that function's doc comment), so A
    /// can NEVER appear in anyone's `reachable_via`, at any hop, no matter
    /// how far gossip's reach becomes. Piece 2's `reachable_via` fallback
    /// ALONE cannot route D's Fulfill back to A through C (C has no
    /// `reachable_via` entry for A, and A is not C's direct peer either) -
    /// only piece 3's `reverse_routes` breadcrumb, recorded at each relay
    /// when the original Intent transited it, can. Without piece 3 this
    /// hangs for the full `INTENT_TIMEOUT` (25s) looking exactly like D
    /// failed to answer, and would then wrongly tank D's reputation score
    /// via `request_intent`'s `update_reputation(peer_id, false, ...)`
    /// fallback path - an innocent provider punished for a routing gap, not
    /// its own failure. Bounded to 5s here specifically so a regression
    /// back to that behavior fails this test fast instead of passing-but-slow.
    #[tokio::test]
    async fn test_deep_chain_pure_consumer_requester_gets_reply() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        let mut config_a = test_config(19411);
        config_a.capabilities = Vec::new(); // pure consumer - offers nothing
        let config_b = test_config(19412);
        let config_c = test_config(19413);
        // AXIOM Phase 1.1: A (the requester) must be on D's echo policy
        // allowlist.
        let mut config_d = test_config(19414);
        config_d.capability_policy_path = write_permissive_test_policy(19414, &[kp_a.node_id()]);

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        let mut mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();
        let mut mgr_d = NetworkManager::new(&config_d, kp_d.clone()).await.unwrap();

        mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        mgr_b.connect(&config_c.listen_addr).await.unwrap();
        mgr_c.register_peer(kp_b.node_id(), config_b.listen_addr, 1);
        let d_id = mgr_c.connect(&config_d.listen_addr).await.unwrap();
        mgr_d.register_peer(kp_c.node_id(), config_c.listen_addr, 1);

        // A deliberately never announces anything - it has nothing to
        // announce (zero capabilities), and even if it tried,
        // process_announcement would drop it outright everywhere along the
        // chain. D still announces normally so A can discover D itself -
        // the FORWARD direction never depended on A's own capabilities.
        mgr_d.spawn_announce(config_c.listen_addr);
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;

        // Confirm the setup actually exercises the regression: A must be
        // registered nowhere as a reachable_via target at B or C - proving
        // the eventual success below can only be the reverse_routes
        // breadcrumb, not a lucky reachable_via hit.
        assert!(!mgr_b.reachable_via.lock().unwrap().contains_key(&kp_a.node_id()), "A (pure consumer) must never appear in B's reachable_via");
        assert!(!mgr_c.reachable_via.lock().unwrap().contains_key(&kp_a.node_id()), "A (pure consumer) must never appear in C's reachable_via");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mgr_a.request_intent("echo", b"pure consumer".to_vec()),
        ).await;
        let (responder, payload) = result
            .expect("request_intent must not time out - the reverse-path breadcrumb, not reachable_via, must route D's Fulfill back to the pure-consumer requester A")
            .expect("request_intent should succeed even though A never appears in anyone's reachable_via");
        assert_eq!(responder, d_id, "must be attributed to D, the real provider - not misdelivered or dropped");
        assert_eq!(payload, b"pure consumer".to_vec());
    }
}

/// AXIOM Phase 1.1: tests for the `CapabilityPolicy`-based authorization
/// path itself (not routing/forwarding/gossip, which the other test
/// modules above already cover). `CapabilityPolicy`'s own unit tests
/// (fail-closed loading, empty-allowlist, rate limit, concurrency) live in
/// axiom-gateway's `policy.rs`; these are end-to-end over real UDP sockets and real
/// `NetworkManager`s, proving the wiring in `dispatch_intent`/
/// `handle_axiom_frame` actually enforces what `policy.rs` promises.
#[cfg(test)]
mod policy_dispatch_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    /// Send `frame_bytes` to `to_addr` from `from_socket`, then wait up to
    /// `wait` for a reply datagram back on that SAME socket - `None` on
    /// timeout (no reply arrived at all), `Some(bytes)` otherwise. Used
    /// directly (rather than `request_intent`/`request_intent_via`, both
    /// of which need the target registered in the semantic router or
    /// passed as explicit relay/destination arguments this module's tests
    /// don't need) so each test can build exactly the frame it wants -
    /// including a deliberately corrupted one, which neither convenience
    /// method could ever produce.
    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn allowlisted_peer_can_call_echo() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19521);
        let mut config_b = test_config(19522);
        config_b.capability_policy_path = write_permissive_test_policy(19522, &[kp_a.node_id()]);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted peer's echo request must get a reply");
        let reply = decode_verified_frame(&reply_bytes).expect("reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Fulfill, "allowlisted peer's echo request must be Fulfilled, not denied");
        assert_eq!(reply.payload, b"hi".to_vec());
    }

    /// The exact distinction this whole task cares about: "not authorized"
    /// (a validly-signed, correctly-identified peer simply isn't on the
    /// capability's allowlist) must never be conflated with "bad
    /// signature" (the frame isn't even provably from who it claims to
    /// be). Same principle as the earlier axiom-hal::secure_parser bug
    /// this project fixed (AXIOM-1 follow-up, commit 41fe434) - conflating
    /// "unsigned"/"corrupt" with a different failure class silently hid a
    /// real gap there; this test locks in that the two classes stay
    /// observably different here too. A validly-signed-but-denied request
    /// gets an explicit, distinct Error reply; a corrupted-signature frame
    /// gets NO reply at all - `decode_verified_frame` drops it upstream of
    /// `dispatch_intent`, before authorization is ever even considered.
    #[tokio::test]
    async fn not_authorized_is_distinct_from_bad_signature() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19531);
        // Empty allowlist for echo - A is deliberately NOT on it.
        let mut config_b = test_config(19532);
        config_b.capability_policy_path = write_permissive_test_policy(19532, &[]);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        // Case 1: validly signed, but not on the allowlist - B must reply
        // with an explicit, distinct denial, not silence.
        let trace_id = next_trace_id();
        let valid_frame = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &valid_frame, Duration::from_millis(500))
            .await
            .expect("an unauthorized-but-validly-signed request must still get an explicit reply, not silence");
        let reply = decode_verified_frame(&reply_bytes).expect("B's denial reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Error, "must be an explicit Error reply, not Fulfill");
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");

        // Case 2: an otherwise-identical frame with a corrupted signature -
        // must produce NO reply at all. Flipping any byte of the encoded
        // frame either breaks decoding outright or leaves the signature
        // mismatched against the (now-different) signed content - either
        // way `decode_verified_frame` returns `None` and `handle_axiom_frame`
        // is never even called for it, so there is structurally no way for
        // this to produce the SAME reply as case 1 above.
        let mut corrupted_frame = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, next_trace_id(), b"hi".to_vec(), None);
        let last = corrupted_frame.len() - 1;
        corrupted_frame[last] ^= 0xFF;
        let reply = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &corrupted_frame, Duration::from_millis(500)).await;
        assert!(
            reply.is_none(),
            "a corrupted-signature frame must produce NO reply at all - conflating it with an explicit 'not authorized' denial would leak whether the claimed sender_id was ever real"
        );
    }

    /// An empty allowlist for a capability must deny EVERY requester,
    /// including one that reached this node via a real, explicit
    /// `connect()` handshake - the same mechanism `ForgeNode::start()` uses
    /// for every address in `NodeConfig::bootstrap_nodes` (this test suite
    /// builds bare `NetworkManager`s with no full `ForgeNode` event loop,
    /// so calling `.connect()` directly here IS the bootstrap_nodes flow,
    /// not a stand-in for it - see `multihop_tests`' module doc comment for
    /// the same pattern). Proves the fail-closed empty-allowlist behavior
    /// isn't accidentally scoped to link-local discovery peers only.
    #[tokio::test]
    async fn empty_allowlist_denies_peer_reached_via_bootstrap_style_connect() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19541);
        let mut config_b = test_config(19542);
        config_b.capability_policy_path = write_permissive_test_policy(19542, &[]); // empty - denies everyone

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();

        // A real bidirectional HELLO/HELLO_ACK handshake - exactly what a
        // configured bootstrap_nodes entry drives in production.
        let b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        // Liveness works fine - the handshake and Ping/Pong are entirely
        // unaffected by capability policy.
        mgr_a.ping(&b_id).await.expect("Ping/Pong liveness must be unaffected by capability policy");

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("even a bootstrap-connected, fully-handshaken peer must get an explicit denial, not a hang");
        let reply = decode_verified_frame(&reply_bytes).expect("denial reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// Requirement: a missing/malformed policy file at startup must leave
    /// the node running (constructor succeeds), discovery/handshake/
    /// liveness fully functional, and zero capability calls succeeding.
    /// Fully unit-testable in this codebase's existing style (real
    /// `NetworkManager`, real UDP sockets, no process-level harness
    /// needed) - `NetworkManager::new` never fails just because
    /// `CapabilityPolicy::load` hit a bad file, and nothing about
    /// connect()/register_peer()/ping() touches the policy at all.
    #[tokio::test]
    async fn malformed_policy_file_denies_capabilities_but_node_stays_up() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19551);
        let mut config_b = test_config(19552);
        // Points at a file that will never exist - CapabilityPolicy::load
        // logs loudly and falls back to "deny everything" rather than
        // erroring NetworkManager::new/failing node startup.
        config_b.capability_policy_path = std::env::temp_dir().join("axiom-test-policy-does-not-exist-19552.toml");

        let mut mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone())
            .await
            .expect("NetworkManager::new must succeed even with a missing/unreadable policy file");

        // Discovery/handshake still fully functional.
        let b_id = mgr_a.connect(&config_b.listen_addr).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        mgr_a.ping(&b_id).await.expect("liveness must be unaffected by a missing policy file");

        // But zero capability calls succeed.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a missing policy file must still produce an explicit denial reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).expect("denial reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// AXIOM Phase 1.4 [OWNER GATE]: `network_clients` must refuse to run
    /// even when EVERYTHING an operator controls says it should - the
    /// requester is on the capability's allowlist, and `uai_base_url`/
    /// `uai_token` are both set (so `dispatch_network_clients` would
    /// otherwise happily try the UAI round trip). This is deliberately
    /// stronger than `not_authorized_is_distinct_from_bad_signature`
    /// above: that test proves policy denial and bad-signature silence
    /// stay distinct; this one proves the Phase 1.4 hard-deny is a THIRD,
    /// separate outcome, reachable by neither of the other two knobs -
    /// see `dispatch_intent`'s doc comment and SECURITY.md's "AXIOM ->
    /// UAI credential scope" section for why: the UAI token this
    /// capability would use is not scoped to what it actually needs, so
    /// AXIOM-side allowlisting can't make calling it safe. The reply text
    /// itself is the assertion that matters here - it must be the Phase
    /// 1.4 gate's specific message, not the generic "not authorized for
    /// this capability" a plain allowlist-miss produces (proving the gate
    /// fired first) and not "network_clients not configured on this
    /// node" (proving it fired before `dispatch_network_clients` ever
    /// looked at `uai_config`).
    #[tokio::test]
    async fn network_clients_hard_denied_even_when_allowlisted_and_uai_configured() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19561);
        let mut config_b = test_config(19562);
        // Allowlisted for every capability, including network_clients -
        // policy alone would authorize this request.
        config_b.capability_policy_path = write_permissive_test_policy(19562, &[kp_a.node_id()]);
        // "Fully configured" from an operator's perspective - a real base
        // URL/token would make `dispatch_network_clients` attempt the UAI
        // HTTP round trip if the Phase 1.4 gate didn't return first.
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "network_clients".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("network_clients").hash, trace_id, Vec::new(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("the Phase 1.4 gate must produce an explicit denial reply, not a hang or silent drop");
        let reply = decode_verified_frame(&reply_bytes).expect("denial reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Error, "must be an explicit Error reply, not Fulfill");
        assert_eq!(
            String::from_utf8_lossy(&reply.payload),
            "network_clients disabled pending a properly-scoped UAI credential",
            "must be the Phase 1.4 hard-deny's own message - a plain allowlist-miss or an unconfigured-UAI error would both read differently, and either one appearing here would mean the gate didn't actually fire first"
        );
    }

    /// AXIOM Phase 3.8: kill switch, end to end over real UDP sockets and
    /// real `dispatch_intent` - not just `axiom-gateway::policy`'s own
    /// `CapabilityPolicy` unit tests. Uses `echo` (Tier0), not
    /// `network_clients` (this codebase's only Tier1 capability) -
    /// `network_clients` is unconditionally hard-denied before
    /// `check_and_acquire` ever runs (see the Phase 1.4 [OWNER GATE] test
    /// just above), so it cannot exercise a live freeze/suspend path over
    /// the wire; suspend (unlike freeze) applies to EVERY tier including
    /// Tier0, so `echo` is the correct, and only, real capability that can
    /// prove this end to end today. `NetworkManager::policy()` is the same
    /// accessor `control.rs`'s local admin socket uses on a live node -
    /// calling it directly here is this test suite's equivalent of driving
    /// the control socket, without needing a real Unix socket connection
    /// for a unit test.
    #[tokio::test]
    async fn suspended_peer_denied_over_the_wire_while_a_second_peer_is_unaffected() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let config_a = test_config(19561);
        let config_c = test_config(19563);
        let mut config_b = test_config(19562);
        config_b.capability_policy_path = write_permissive_test_policy(19562, &[kp_a.node_id(), kp_c.node_id()]);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mgr_c = NetworkManager::new(&config_c, kp_c.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);
        mgr_b.register_peer(kp_c.node_id(), config_c.listen_addr, 1);

        // Baseline: both A and C are allowlisted and get Fulfill.
        let trace_id = next_trace_id();
        let frame_a = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi from a".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_a, Duration::from_millis(500)).await.unwrap();
        assert_eq!(decode_verified_frame(&reply_bytes).unwrap().header.frame_type, FrameType::Fulfill);

        // B's operator suspends A via the SAME accessor control.rs's local
        // admin socket uses on a live node.
        mgr_b.policy().suspend_peer(kp_a.node_id());

        // A is now denied, with a DISTINCT error from a plain allowlist-miss.
        let trace_id = next_trace_id();
        let frame_a = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi from a again".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_a, Duration::from_millis(500))
            .await
            .expect("a suspended-but-validly-signed request must still get an explicit reply, not silence");
        let reply = decode_verified_frame(&reply_bytes).expect("denial reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "suspended by kill switch");

        // C, never suspended, proceeds completely normally on the SAME
        // node at the SAME time - proves suspend is scoped to A's
        // identity alone, not a global freeze.
        let trace_id = next_trace_id();
        let frame_c = build_intent_frame(&kp_c, AiIntent::from_str("echo").hash, trace_id, b"hi from c".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_c.socket, config_b.listen_addr, &frame_c, Duration::from_millis(500))
            .await
            .expect("a non-suspended peer must be completely unaffected by another peer's suspension");
        let reply = decode_verified_frame(&reply_bytes).expect("reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Fulfill, "C must still be Fulfilled, not denied");

        // Explicit un-suspend restores A.
        assert!(mgr_b.policy().unsuspend_peer(kp_a.node_id()));
        let trace_id = next_trace_id();
        let frame_a = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"hi from a once more".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_a, Duration::from_millis(500)).await.unwrap();
        assert_eq!(decode_verified_frame(&reply_bytes).unwrap().header.frame_type, FrameType::Fulfill, "A must be able to call echo again after an explicit unsuspend");
    }

    /// AXIOM Phase 3.8: `Frozen`, over the wire - `echo`/`sysinfo` (Tier0)
    /// stay live during a freeze, an Error reply distinct from a plain
    /// allowlist-miss is returned for what WOULD be a live Tier1+ call, and
    /// an explicit unfreeze restores it. See the test just above for why
    /// this codebase's real dispatch has no live Tier1 capability to
    /// freeze against directly (`network_clients` is independently hard-
    /// denied) - this test instead proves the two halves the roadmap
    /// actually requires can be proven live: (a) Tier0 is unaffected by a
    /// freeze, over real UDP dispatch, and (b) the SAME `CapabilityPolicy`
    /// instance `dispatch_intent` checks on every call reports `Frozen`
    /// for a Tier1+ capability the instant `freeze()` is called - no
    /// restart, no reload. `axiom-gateway::policy`'s own
    /// `freeze_denies_tier1_but_not_tier0_and_unfreeze_restores_tier1` test
    /// covers the Tier1-denial half directly against `check_and_acquire`.
    #[tokio::test]
    async fn freeze_leaves_tier0_live_over_the_wire_and_is_visible_on_the_shared_policy_instantly() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19571);
        let mut config_b = test_config(19572);
        config_b.capability_policy_path = write_permissive_test_policy(19572, &[kp_a.node_id()]);

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        assert!(!mgr_b.policy().is_frozen());
        mgr_b.policy().freeze();
        // Visible instantly on the SAME Arc<CapabilityPolicy>
        // dispatch_intent checks - no restart, no reload.
        assert!(mgr_b.policy().is_frozen());
        assert!(
            matches!(mgr_b.policy().check_and_acquire("network_clients", kp_a.node_id()), axiom_gateway::PolicyOutcome::Frozen),
            "a Tier1 capability must report Frozen the instant freeze() is called, on the exact policy instance dispatch_intent uses"
        );

        // Tier0 (echo) stays live over the real wire, during the freeze.
        let trace_id = next_trace_id();
        let frame_a = build_intent_frame(&kp_a, AiIntent::from_str("echo").hash, trace_id, b"still alive".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_a, Duration::from_millis(500))
            .await
            .expect("Tier0 must stay live during a freeze");
        let reply = decode_verified_frame(&reply_bytes).expect("reply must itself be validly signed");
        assert_eq!(reply.header.frame_type, FrameType::Fulfill, "Tier0 (echo) must be unaffected by a Tier1+ freeze");
        assert_eq!(reply.payload, b"still alive".to_vec());

        mgr_b.policy().unfreeze();
        assert!(!mgr_b.policy().is_frozen());
        assert!(matches!(mgr_b.policy().check_and_acquire("network_clients", kp_a.node_id()), axiom_gateway::PolicyOutcome::Allowed(_)));
    }
}

/// AXIOM notify_send: unit coverage for the new capability - the
/// message-sanitization boundary (`prepare_notify_message`, pure/sync, no
/// network needed) plus end-to-end `dispatch_intent` coverage for both
/// "not configured" combinations, following the same real-UDP-socket,
/// real-signed-frame pattern `policy_dispatch_tests` already established.
/// Deliberately does NOT attempt a real UAI HTTP round trip here (neither
/// does any existing `network_clients` test - see this module's own
/// `network_clients_hard_denied_even_when_allowlisted_and_uai_configured`,
/// which stops at a fake `127.0.0.1:1` URL specifically to avoid needing
/// one) - the real broker/ntfy round trip is covered by this capability's
/// live verification instead (see the build's own final report).
#[cfg(test)]
mod notify_send_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    // Local copies of `policy_dispatch_tests`'s `test_config`/
    // `send_and_await_reply` helpers - each test module in this file
    // defines its own rather than sharing across sibling `mod` blocks
    // (see e.g. `multihop_tests`'s and `policy_dispatch_tests`'s own
    // identically-named-but-separately-defined copies); same convention
    // followed here rather than introducing a new cross-module sharing
    // pattern for two trivial helpers.
    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    #[test]
    fn prepare_notify_message_passes_a_benign_message_through_unmangled() {
        let out = prepare_notify_message(b"Backup completed: 4.2TB, 0 errors").unwrap();
        assert_eq!(out, "Backup completed: 4.2TB, 0 errors");
    }

    #[test]
    fn prepare_notify_message_rejects_empty_payload() {
        assert!(prepare_notify_message(b"").is_err());
        assert!(prepare_notify_message(b"   \n\t  ").is_err(), "whitespace-only payload must also be rejected");
    }

    #[test]
    fn prepare_notify_message_strips_ansi_escapes_and_control_chars() {
        // Same threat class Phase 3.7's sanitize.rs targets: a message
        // trying to manipulate whatever renders it (terminal, log line,
        // notification client) via a color escape and a carriage return.
        let hostile = b"\x1b[31mFAKE ALERT\x1b[0m\rreal message";
        let out = prepare_notify_message(hostile).unwrap();
        assert!(!out.contains('\x1b'), "ANSI escape must be stripped: {out:?}");
        assert!(!out.contains('\r'), "control character must be stripped: {out:?}");
        assert!(out.contains("real message"));
    }

    #[test]
    fn prepare_notify_message_flags_truncation_visibly() {
        let long = "a".repeat(1000);
        let out = prepare_notify_message(long.as_bytes()).unwrap();
        assert!(out.ends_with(" [truncated]"), "a truncated message must say so, not look like an ordinary short one: {out:?}");
        assert!(out.len() < long.len(), "must actually be shorter than the input");
    }

    /// Neither `uai_config` nor `notify_topic` set - the common case for a
    /// node that's never had notify_send configured at all.
    #[tokio::test]
    async fn notify_send_reports_not_configured_when_neither_uai_nor_topic_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19571);
        let mut config_b = test_config(19572);
        config_b.capability_policy_path = write_permissive_test_policy(19572, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "notify_send".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("notify_send").hash, trace_id, b"test message".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured notify_send request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "notify_send not configured on this node");
    }

    /// `uai_base_url`/`uai_token` ARE set, but `notify_topic` is not -
    /// proves BOTH knobs are required (see `dispatch_notify_send`'s doc
    /// comment on why this is two independent knobs, unlike
    /// `network_clients`'s single `uai_config`), and proves this fails
    /// before any real HTTP attempt (the configured `uai_base_url` here,
    /// `http://127.0.0.1:1`, refuses TCP connections outright - if this
    /// test hung or timed out instead of returning promptly, that would
    /// mean the topic check isn't actually short-circuiting first).
    #[tokio::test]
    async fn notify_send_reports_not_configured_when_uai_set_but_topic_missing() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19573);
        let mut config_b = test_config(19574);
        config_b.capability_policy_path = write_permissive_test_policy(19574, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "notify_send".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());
        // notify_topic deliberately left unset.

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("notify_send").hash, trace_id, b"test message".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly - a hang here would mean this fell through to a real HTTP attempt instead of the topic-missing short-circuit")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "notify_send not configured on this node");
    }

    /// A peer with no allowlist entry for notify_send gets the same
    /// generic "not authorized" denial every other capability's
    /// allowlist-miss produces - proves notify_send didn't accidentally
    /// wire up its own bespoke authorization path instead of going
    /// through `ctx.policy` like everything else.
    #[tokio::test]
    async fn notify_send_denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19575);
        let mut config_b = test_config(19576);
        // Allowlist a DIFFERENT peer, not kp_a - kp_a must still be denied.
        config_b.capability_policy_path = write_permissive_test_policy(19576, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "notify_send".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("notify_send").hash, trace_id, b"test message".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied notify_send request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }
}

/// AXIOM proxmox_restart: unit coverage for the new capability - the
/// target-parsing boundary (`parse_proxmox_restart_target`, pure/sync, no
/// network needed), the Phase 3.6 protected-VMID denylist wired live for
/// the first time into a real Tier1 dispatch path, and the "not
/// configured" / "no allowlist entry" cases every prior capability's test
/// module also covers - same real-UDP-socket, real-signed-frame pattern
/// `notify_send_tests`/`policy_dispatch_tests` already established.
/// Deliberately does NOT attempt a real UAI HTTP round trip here (same
/// reasoning `notify_send_tests`' own doc comment gives) - the real
/// broker/`proxmox_lxc` round trip against a genuinely disposable test LXC
/// container is covered by this capability's live verification instead
/// (see this build's own final report).
#[cfg(test)]
mod proxmox_restart_tests {
    use super::*;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    // Same private per-module copy `policy_dispatch_tests`/`notify_send_tests`
    // each already carry (not a shared helper either of those reused, so this
    // module follows the same precedent rather than introducing the first
    // cross-module refactor as a drive-by of this capability's own change).
    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    #[test]
    fn parse_accepts_a_well_formed_lxc_target() {
        let target = parse_proxmox_restart_target(b"lxc:120").unwrap();
        assert_eq!(target.kind, ProxmoxResourceKind::Lxc);
        assert_eq!(target.vmid, 120);
        assert_eq!(target.canonical(), "lxc:120");
    }

    #[test]
    fn parse_accepts_a_well_formed_vm_target_case_insensitive_kind() {
        let target = parse_proxmox_restart_target(b"VM:100").unwrap();
        assert_eq!(target.kind, ProxmoxResourceKind::Vm);
        assert_eq!(target.vmid, 100);
        assert_eq!(target.canonical(), "vm:100");
    }

    #[test]
    fn parse_rejects_empty_or_whitespace_only_payload() {
        assert!(parse_proxmox_restart_target(b"").is_err());
        assert!(parse_proxmox_restart_target(b"   \n\t  ").is_err());
    }

    #[test]
    fn parse_rejects_vmid_zero() {
        let err = parse_proxmox_restart_target(b"lxc:0").unwrap_err();
        assert!(err.contains("VMID 0"), "error should name the VMID-0 rejection: {err}");
    }

    #[test]
    fn parse_rejects_unknown_kind() {
        let err = parse_proxmox_restart_target(b"docker:120").unwrap_err();
        assert!(err.contains("unknown resource kind"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_numeric_vmid() {
        assert!(parse_proxmox_restart_target(b"lxc:not-a-number").is_err());
        assert!(parse_proxmox_restart_target(b"lxc:-5").is_err(), "a negative number must not parse as a u32 VMID");
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = parse_proxmox_restart_target(b"lxc120").unwrap_err();
        assert!(err.contains("expected"), "got: {err}");
    }

    /// `ctx.uai_config` unset - the common case for a node that's never
    /// had proxmox_restart configured at all. Uses a harmless "vm:9999"
    /// target (no protected-VMID collision) so this test proves the
    /// "not configured" short-circuit specifically, not the denylist.
    #[tokio::test]
    async fn reports_not_configured_when_uai_not_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19581);
        let mut config_b = test_config(19582);
        config_b.capability_policy_path = write_permissive_test_policy(19582, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "proxmox_restart".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("proxmox_restart").hash, trace_id, b"vm:9999".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured proxmox_restart request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "proxmox_restart not configured on this node");
    }

    /// A peer with no allowlist entry gets the same generic "not
    /// authorized" denial every other capability's allowlist-miss
    /// produces - proves proxmox_restart didn't wire up a bespoke
    /// authorization path instead of going through `ctx.policy`.
    #[tokio::test]
    async fn denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19583);
        let mut config_b = test_config(19584);
        config_b.capability_policy_path = write_permissive_test_policy(19584, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "proxmox_restart".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("proxmox_restart").hash, trace_id, b"vm:9999".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied proxmox_restart request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// AXIOM Phase 3.6's `denied_param_substrings`, wired live for the
    /// first time: a policy file carrying
    /// `[capability.proxmox_restart].denied_param_substrings = ["120"]`
    /// (the same shape this build's real `capability_policy.toml` entry
    /// uses to protect CT120/claude-host) must reject a request targeting
    /// VMID 120 with a distinct, real-check reply - and BEFORE any UAI
    /// call is attempted (`uai_base_url` here is `http://127.0.0.1:1`,
    /// which refuses TCP outright - if this test hung or timed out instead
    /// of returning promptly, the denylist check would not actually be
    /// short-circuiting first).
    #[tokio::test]
    async fn denies_a_request_targeting_a_denylisted_vmid_before_any_uai_call() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19585);
        let mut config_b = test_config(19586);
        let allowed_toml = format!("\"{}\"", hex::encode(kp_a.node_id().as_bytes()));
        let policy_contents = format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.proxmox_restart]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\ndenied_param_substrings = [\"120\"]\n",
        );
        let policy_path = std::env::temp_dir().join(format!("axiom-test-policy-proxmox-restart-denylist-{}.toml", std::process::id()));
        std::fs::write(&policy_path, policy_contents).unwrap();
        config_b.capability_policy_path = policy_path;
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "proxmox_restart".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("proxmox_restart").hash, trace_id, b"lxc:120".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly - a hang here would mean this fell through to a real HTTP attempt instead of the denylist short-circuit")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "expected the check_denied_param_substrings reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );

        // An unrelated, non-denylisted VMID on the SAME node/policy is
        // NOT blocked by the denylist check - proves this is a targeted
        // per-value match, not an accidental full-capability freeze. It
        // still fails, but for the DIFFERENT reason of hitting the fake
        // unreachable UAI URL - proving the denylist check specifically
        // let it past.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("proxmox_restart").hash, trace_id, b"lxc:999".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(5),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(4000)),
        )
            .await
            .expect("must not hang indefinitely")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            !String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "a non-denylisted VMID must not be rejected by the denylist check: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }
}

/// AXIOM home_assistant_toggle: unit coverage for the new capability - the
/// target-parsing boundary (`parse_ha_toggle_target`, pure/sync, no
/// network needed - including the code-level domain hard-deny, the single
/// most important thing this capability's own tests need to prove), the
/// Phase 3.6 protected-param denylist wired the same way `proxmox_restart`
/// wired it, and the "not configured" / "no allowlist entry" cases every
/// prior capability's test module also covers. Deliberately does NOT
/// attempt a real UAI HTTP round trip here (same reasoning every sibling
/// test module gives) - the real broker/`homeassistant` driver round trip
/// against a genuinely real HA entity is covered by this capability's live
/// verification instead (see this build's own final report).
#[cfg(test)]
mod home_assistant_toggle_tests {
    use super::*;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    #[test]
    fn parse_accepts_a_well_formed_light_on_target() {
        let target = parse_ha_toggle_target(b"on:light.living_room").unwrap();
        assert_eq!(target.action, HaAction::On);
        assert_eq!(target.entity_id, "light.living_room");
        assert_eq!(target.canonical(), "on:light.living_room");
    }

    #[test]
    fn parse_accepts_switch_off_and_fan_toggle_case_insensitive_action() {
        let t1 = parse_ha_toggle_target(b"OFF:switch.desk_lamp").unwrap();
        assert_eq!(t1.action, HaAction::Off);
        let t2 = parse_ha_toggle_target(b"Toggle:fan.bedroom").unwrap();
        assert_eq!(t2.action, HaAction::Toggle);
    }

    #[test]
    fn parse_accepts_scene_activation() {
        let target = parse_ha_toggle_target(b"on:scene.movie_night").unwrap();
        assert_eq!(target.action, HaAction::On);
        assert_eq!(target.entity_id, "scene.movie_night");
    }

    #[test]
    fn parse_rejects_scene_off_and_toggle() {
        let off = parse_ha_toggle_target(b"off:scene.movie_night").unwrap_err();
        assert!(off.contains("only support 'on'"), "got: {off}");
        let toggle = parse_ha_toggle_target(b"toggle:scene.movie_night").unwrap_err();
        assert!(toggle.contains("only support 'on'"), "got: {toggle}");
    }

    #[test]
    fn parse_rejects_empty_or_whitespace_only_payload() {
        assert!(parse_ha_toggle_target(b"").is_err());
        assert!(parse_ha_toggle_target(b"   \n\t  ").is_err());
    }

    #[test]
    fn parse_rejects_unknown_action() {
        let err = parse_ha_toggle_target(b"unlock:light.foyer").unwrap_err();
        assert!(err.contains("unknown action"), "got: {err}");
    }

    #[test]
    fn parse_rejects_malformed_entity_id() {
        assert!(parse_ha_toggle_target(b"on:notadomainobject").is_err(), "missing '.' must be rejected");
        assert!(parse_ha_toggle_target(b"on:.foo").is_err(), "empty domain must be rejected");
        assert!(parse_ha_toggle_target(b"on:light.").is_err(), "empty object_id must be rejected");
        assert!(parse_ha_toggle_target(b"on:").is_err(), "empty entity_id must be rejected");
    }

    /// The single most important test in this module: every
    /// security-relevant domain named in `ALLOWED_HA_DOMAINS`'s own doc
    /// comment must actually be rejected by the parser itself - not merely
    /// documented as excluded. This is the "hard-deny in code" property
    /// the build's final report describes; if this test regresses, the
    /// capability has silently widened past its approved scope.
    #[test]
    fn parse_hard_denies_every_security_relevant_domain() {
        for (payload, domain) in [
            (b"off:lock.front_door" as &[u8], "lock"),
            (b"on:cover.garage_door", "cover"),
            (b"off:alarm_control_panel.home", "alarm_control_panel"),
            (b"toggle:valve.main_water", "valve"),
            (b"on:siren.backyard", "siren"),
            (b"toggle:camera.driveway", "camera"),
            (b"on:climate.thermostat", "climate"),
            (b"on:water_heater.tank", "water_heater"),
            (b"toggle:humidifier.bedroom", "humidifier"),
        ] {
            let err = parse_ha_toggle_target(payload).unwrap_err();
            assert!(
                err.contains("is not permitted"),
                "domain '{domain}' must be hard-denied, got: {err}"
            );
        }
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED:
    /// `ALLOWED_HA_DOMAINS.contains(&domain)` is a case-SENSITIVE exact
    /// match with no lowercasing anywhere in `parse_ha_toggle_target` - a
    /// case-varied spelling of even a genuinely allowed domain
    /// (`"Light"`/`"LIGHT"` instead of `"light"`) is rejected, not
    /// fuzzy-matched. This closes the theoretical direction a naive
    /// case-insensitive allowlist check could have opened; since this is an
    /// ALLOWlist (not a denylist), a case-varied forbidden domain
    /// (`"LOCK"`) was never actually at risk of being let through either -
    /// both directions land on "reject," which is the correct fail-closed
    /// shape for an allowlist either way.
    #[test]
    fn parse_rejects_case_varied_domain_even_for_an_otherwise_allowed_domain_name() {
        for payload in [b"on:Light.living_room" as &[u8], b"on:LIGHT.living_room", b"off:Lock.front_door", b"off:LOCK.front_door"] {
            let err = parse_ha_toggle_target(payload).unwrap_err();
            assert!(err.contains("is not permitted"), "case-varied domain must be rejected, got: {err}");
        }
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED:
    /// a Unicode homoglyph domain - Cyrillic "і" (U+0456) in place of Latin
    /// "i" (U+0069), visually indistinguishable from `"light"` in most
    /// fonts/terminals - must not be treated as the real `"light"` domain.
    /// Rust string equality (what `&[&str]::contains` uses here) compares
    /// exact Unicode scalar values, not visual rendering, so this was
    /// always structurally safe - this test proves it directly rather than
    /// trusting that by inference.
    #[test]
    fn parse_rejects_unicode_homoglyph_domain_that_visually_resembles_an_allowed_domain() {
        let homoglyph_domain = "l\u{0456}ght"; // "light" with Cyrillic U+0456 standing in for Latin 'i'
        let payload = format!("on:{homoglyph_domain}.living_room");
        let err = parse_ha_toggle_target(payload.as_bytes()).unwrap_err();
        assert!(err.contains("is not permitted"), "a Unicode homoglyph domain must not be treated as the real allowed domain, got: {err}");
    }

    #[test]
    fn parse_accepts_every_allowed_domain() {
        for entity in ["light.x", "switch.x", "fan.x", "input_boolean.x"] {
            assert!(parse_ha_toggle_target(format!("on:{entity}").as_bytes()).is_ok(), "domain in {entity} should be allowed");
            assert!(parse_ha_toggle_target(format!("off:{entity}").as_bytes()).is_ok());
            assert!(parse_ha_toggle_target(format!("toggle:{entity}").as_bytes()).is_ok());
        }
    }

    /// `ctx.uai_config` unset - the common case for a node that's never
    /// had home_assistant_toggle configured at all. Uses an allowed domain
    /// so this test proves the "not configured" short-circuit
    /// specifically, not the domain hard-deny.
    #[tokio::test]
    async fn reports_not_configured_when_uai_not_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19591);
        let mut config_b = test_config(19592);
        config_b.capability_policy_path = write_permissive_test_policy(19592, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "home_assistant_toggle".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("home_assistant_toggle").hash, trace_id, b"on:light.test".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured home_assistant_toggle request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "home_assistant_toggle not configured on this node");
    }

    /// A peer with no allowlist entry gets the same generic "not
    /// authorized" denial every other capability's allowlist-miss
    /// produces.
    #[tokio::test]
    async fn denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19593);
        let mut config_b = test_config(19594);
        config_b.capability_policy_path = write_permissive_test_policy(19594, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "home_assistant_toggle".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("home_assistant_toggle").hash, trace_id, b"on:light.test".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied home_assistant_toggle request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// A request targeting a domain hard-denied in
    /// `parse_ha_toggle_target` never even reaches the allowlist/UAI
    /// check - proves the domain hard-deny fires first, unconditionally,
    /// even for an allowlisted peer with UAI fully configured (the
    /// `uai_base_url` here, `http://127.0.0.1:1`, refuses TCP outright -
    /// if this test hung or timed out instead of returning promptly, the
    /// parse-level hard-deny would not actually be short-circuiting
    /// first).
    #[tokio::test]
    async fn denies_a_hard_denied_domain_before_any_uai_call_even_when_allowlisted_and_configured() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19595);
        let mut config_b = test_config(19596);
        config_b.capability_policy_path = write_permissive_test_policy(19596, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "home_assistant_toggle".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("home_assistant_toggle").hash, trace_id, b"off:lock.front_door".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly - a hang here would mean this fell through to a real HTTP attempt instead of the domain hard-deny short-circuit")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("is not permitted"),
            "expected the domain hard-deny reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }

    /// AXIOM Phase 3.6's `denied_param_substrings`, wired the same way
    /// `proxmox_restart` wired it: a specific entity_id can be additionally
    /// denylisted by policy on top of (never instead of) the code-level
    /// domain allowlist above.
    #[tokio::test]
    async fn denies_a_request_targeting_a_policy_denylisted_entity_before_any_uai_call() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19597);
        let mut config_b = test_config(19598);
        let allowed_toml = format!("\"{}\"", hex::encode(kp_a.node_id().as_bytes()));
        let policy_contents = format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.home_assistant_toggle]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\ndenied_param_substrings = [\"light.nursery\"]\n",
        );
        let policy_path = std::env::temp_dir().join(format!("axiom-test-policy-ha-toggle-denylist-{}.toml", std::process::id()));
        std::fs::write(&policy_path, policy_contents).unwrap();
        config_b.capability_policy_path = policy_path;
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "home_assistant_toggle".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("home_assistant_toggle").hash, trace_id, b"on:light.nursery".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "expected the check_denied_param_substrings reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );

        // A different, non-denylisted light on the SAME node/policy is NOT
        // blocked by the denylist check - proves this is a targeted
        // per-value match, not an accidental full-capability freeze.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("home_assistant_toggle").hash, trace_id, b"on:light.kitchen".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(5),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(4000)),
        )
            .await
            .expect("must not hang indefinitely")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            !String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "a non-denylisted entity_id must not be rejected by the denylist check: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }
}

/// AXIOM docker_restart: unit coverage for the new capability - the
/// target-parsing boundary (`parse_docker_restart_target`, pure/sync, no
/// network needed - including the code-level allowlist AND the separate
/// hard-deny for `ai-uai`/`forge-node`, the single most important thing
/// this capability's own tests need to prove), the Phase 3.6
/// protected-param denylist wired the same way `proxmox_restart`/
/// `home_assistant_toggle` wired it, and the "not configured" / "no
/// allowlist entry" cases every prior capability's test module also
/// covers. Deliberately does NOT attempt a real UAI HTTP round trip here
/// (same reasoning every sibling test module gives) - the real broker/
/// `docker_desktop` driver round trip against a genuinely real,
/// disposable-restart container is covered by this capability's live
/// verification instead (see this build's own final report).
#[cfg(test)]
mod docker_restart_tests {
    use super::*;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    #[test]
    fn parse_accepts_every_allowlisted_container() {
        for name in ALLOWED_DOCKER_CONTAINERS {
            let target = parse_docker_restart_target(name.as_bytes()).unwrap();
            assert_eq!(target.canonical(), *name);
        }
    }

    #[test]
    fn parse_rejects_empty_or_whitespace_only_payload() {
        assert!(parse_docker_restart_target(b"").is_err());
        assert!(parse_docker_restart_target(b"   \n\t  ").is_err());
    }

    #[test]
    fn parse_rejects_a_name_not_on_the_allowlist() {
        let err = parse_docker_restart_target(b"pm-agent").unwrap_err();
        assert!(err.contains("not on the allowlist"), "got: {err}");
    }

    #[test]
    fn parse_rejects_invalid_characters() {
        assert!(parse_docker_restart_target(b"infra-watchtower; rm -rf /").is_err());
        assert!(parse_docker_restart_target(b"../etc/passwd").is_err());
        assert!(parse_docker_restart_target(b" -leading-space-then-dash").is_err());
    }

    #[test]
    fn parse_rejects_an_overlong_name() {
        let long = "a".repeat(200);
        let err = parse_docker_restart_target(long.as_bytes()).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    /// The single most important test in this module: `ai-uai` and
    /// `forge-node` must be rejected with the DISTINCT hard-deny message,
    /// not the generic "not on the allowlist" one - proving this is a
    /// separate, unconditional code path (defense in depth), not merely
    /// an accident of both names being absent from
    /// `ALLOWED_DOCKER_CONTAINERS`. If this regresses to the generic
    /// allowlist-miss message, the hard-deny check has silently been
    /// removed or reordered after the allowlist check.
    #[test]
    fn parse_hard_denies_ai_uai_and_forge_node_regardless_of_allowlist() {
        for name in HARD_DENIED_DOCKER_CONTAINERS {
            let err = parse_docker_restart_target(name.as_bytes()).unwrap_err();
            assert!(err.contains("hard-denied"), "'{name}' must be hard-denied, got: {err}");
        }
        // Case-insensitivity, mirroring proxmox_restart's own paranoia
        // about denying "vm:120" as well as "lxc:120".
        let err = parse_docker_restart_target(b"AI-UAI").unwrap_err();
        assert!(err.contains("hard-denied"), "got: {err}");
        let err2 = parse_docker_restart_target(b"Forge-Node").unwrap_err();
        assert!(err2.contains("hard-denied"), "got: {err2}");
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED:
    /// the INVERSE risk from the hard-deny's own deliberate case-
    /// insensitivity above - `ALLOWED_DOCKER_CONTAINERS.contains(&name)` is
    /// a plain `&str` equality check, which IS case-sensitive. Confirms a
    /// case-varied spelling of a genuinely allowlisted container name
    /// (`"Infra-Watchtower"`, `"INFRA-WATCHTOWER"`) is correctly REJECTED,
    /// not silently treated as a match for `"infra-watchtower"` - a naive
    /// case-insensitive allowlist check would have been a real bypass
    /// (attacker-controlled casing reaching a container the allowlist
    /// wasn't written to name).
    #[test]
    fn parse_rejects_case_varied_spelling_of_an_allowlisted_name() {
        for variant in ["Infra-Watchtower", "INFRA-WATCHTOWER", "iNFRA-wATCHTOWER"] {
            let err = parse_docker_restart_target(variant.as_bytes())
                .expect_err(&format!("'{variant}' must NOT be accepted as a case-insensitive match for an allowlisted name"));
            assert!(err.contains("not on the allowlist"), "got: {err}");
        }
        // Sanity: the canonical, correctly-cased spelling still works -
        // proves the rejection above is really about case, not a broken parser.
        assert!(parse_docker_restart_target(b"infra-watchtower").is_ok());
    }

    /// `ctx.uai_config` unset - the common case for a node that's never
    /// had docker_restart configured at all. Uses an allowlisted name so
    /// this test proves the "not configured" short-circuit specifically,
    /// not the allowlist.
    #[tokio::test]
    async fn reports_not_configured_when_uai_not_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19601);
        let mut config_b = test_config(19602);
        config_b.capability_policy_path = write_permissive_test_policy(19602, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "docker_restart".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("docker_restart").hash, trace_id, b"infra-watchtower".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured docker_restart request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "docker_restart not configured on this node");
    }

    /// A peer with no allowlist entry gets the same generic "not
    /// authorized" denial every other capability's allowlist-miss
    /// produces.
    #[tokio::test]
    async fn denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19603);
        let mut config_b = test_config(19604);
        config_b.capability_policy_path = write_permissive_test_policy(19604, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "docker_restart".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("docker_restart").hash, trace_id, b"infra-watchtower".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied docker_restart request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// A request targeting `ai-uai` never even reaches the allowlist/UAI
    /// check - proves the hard-deny fires first, unconditionally, even
    /// for an allowlisted peer with UAI fully configured (the
    /// `uai_base_url` here, `http://127.0.0.1:1`, refuses TCP outright -
    /// if this test hung or timed out instead of returning promptly, the
    /// hard-deny check would not actually be short-circuiting first).
    #[tokio::test]
    async fn denies_ai_uai_before_any_uai_call_even_when_allowlisted_and_configured() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19605);
        let mut config_b = test_config(19606);
        config_b.capability_policy_path = write_permissive_test_policy(19606, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "docker_restart".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("docker_restart").hash, trace_id, b"ai-uai".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly - a hang here would mean this fell through to a real HTTP attempt instead of the hard-deny short-circuit")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("hard-denied"),
            "expected the hard-deny reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }

    /// AXIOM Phase 3.6's `denied_param_substrings`, wired the same way
    /// `proxmox_restart`/`home_assistant_toggle` wired it: a specific
    /// already-allowlisted container name can be additionally denylisted
    /// by policy on top of (never instead of) the code-level allowlist.
    #[tokio::test]
    async fn denies_a_request_targeting_a_policy_denylisted_container_before_any_uai_call() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19607);
        let mut config_b = test_config(19608);
        let allowed_toml = format!("\"{}\"", hex::encode(kp_a.node_id().as_bytes()));
        let policy_contents = format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.docker_restart]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier1\"\ndenied_param_substrings = [\"dl-bazarr\"]\n",
        );
        let policy_path = std::env::temp_dir().join(format!("axiom-test-policy-docker-restart-denylist-{}.toml", std::process::id()));
        std::fs::write(&policy_path, policy_contents).unwrap();
        config_b.capability_policy_path = policy_path;
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "docker_restart".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("docker_restart").hash, trace_id, b"dl-bazarr".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "expected the check_denied_param_substrings reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );

        // A different, non-denylisted allowed container on the SAME
        // node/policy is NOT blocked by the denylist check - proves this
        // is a targeted per-value match, not an accidental
        // full-capability freeze.
        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("docker_restart").hash, trace_id, b"infra-watchtower".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(5),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(4000)),
        )
            .await
            .expect("must not hang indefinitely")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            !String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "a non-denylisted container must not be rejected by the denylist check: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }
}

/// AXIOM wg_peers_list: unit coverage for the new capability. Payload-less
/// (like `network_clients`/`sysinfo`) - there is no target-parsing
/// boundary to test here, so this module only covers the same "not
/// configured" / "no allowlist entry" cases every other UAI-backed
/// capability's test module also covers. The real broker/`wg_easy` driver
/// round trip against a genuine, disposable wg-easy test peer is covered
/// by this capability's live verification instead (see this build's own
/// final report) - deliberately not attempted here, same reasoning every
/// sibling test module gives for skipping a real UAI HTTP round trip in
/// unit tests.
#[cfg(test)]
mod wg_peers_list_tests {
    use super::*;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    /// `ctx.uai_config` unset - the common case for a node that's never
    /// had wg_peers_list configured at all.
    #[tokio::test]
    async fn reports_not_configured_when_uai_not_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19609);
        let mut config_b = test_config(19610);
        config_b.capability_policy_path = write_permissive_test_policy(19610, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peers_list".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peers_list").hash, trace_id, Vec::new(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured wg_peers_list request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "wg_peers_list not configured on this node");
    }

    /// A peer with no allowlist entry gets the same generic "not
    /// authorized" denial every other capability's allowlist-miss
    /// produces.
    #[tokio::test]
    async fn denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19611);
        let mut config_b = test_config(19612);
        config_b.capability_policy_path = write_permissive_test_policy(19612, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peers_list".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peers_list").hash, trace_id, Vec::new(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied wg_peers_list request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }
}

/// AXIOM Tier 2: unit coverage for `wg_peer_manage` - the target-parsing
/// boundary (`parse_wg_peer_manage_target`, pure/sync, no network,
/// including the code-level `HARD_DENIED_WG_PEER_TARGETS` hard-deny for
/// delete/disable) and the dispatch-level "not configured" / "no allowlist
/// entry" cases every prior capability's test module also covers.
/// Deliberately does NOT attempt a real Telegram round trip or a real UAI
/// HTTP round trip here - same reasoning every sibling test module gives.
/// The full propose -> approve/deny -> execute state machine itself
/// (happy path, deny path, expiry path, tampered-parameters path,
/// protected-resource path) already has extensive, real, non-mock coverage
/// in `axiom-gateway::approval`'s own test suite - channel-agnostically, by
/// design (that's the whole point of `ApprovalChannel` being a trait) - so
/// this module does not re-prove those; `telegram_approval.rs`'s own test
/// module covers the parts SPECIFIC to the Telegram channel (chat-id auth,
/// concurrent-waiter isolation, callback_data matching). The real
/// end-to-end wire path (a real signed Intent producing a real Telegram
/// message with real buttons, gating a real WireGuard peer create/delete)
/// is covered by this build's own live verification instead - see the
/// final report for exactly how that was validated.
#[cfg(test)]
mod wg_peer_manage_tests {
    use super::*;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    async fn send_and_await_reply(
        from_socket: &Arc<UdpSocket>,
        to_addr: SocketAddr,
        frame_bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        from_socket.send_to(frame_bytes, to_addr).await.unwrap();
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, from_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }

    // --- parse_wg_peer_manage_target ---

    #[test]
    fn parse_accepts_every_action_with_a_valid_name() {
        for action in ["create", "delete", "enable", "disable"] {
            let target = parse_wg_peer_manage_target(format!("{action}:new-test-peer").as_bytes()).unwrap();
            assert_eq!(target.name, "new-test-peer");
        }
    }

    #[test]
    fn parse_is_case_insensitive_on_the_action_word() {
        let target = parse_wg_peer_manage_target(b"CREATE:some-peer").unwrap();
        assert_eq!(target.action, WgPeerAction::Create);
    }

    #[test]
    fn parse_rejects_empty_or_whitespace_only_payload() {
        assert!(parse_wg_peer_manage_target(b"").is_err());
        assert!(parse_wg_peer_manage_target(b"   \n\t  ").is_err());
    }

    #[test]
    fn parse_rejects_missing_colon_separator() {
        let err = parse_wg_peer_manage_target(b"create-newpeer").unwrap_err();
        assert!(err.contains("expected"), "got: {err}");
    }

    #[test]
    fn parse_rejects_unknown_action() {
        let err = parse_wg_peer_manage_target(b"reboot:some-peer").unwrap_err();
        assert!(err.contains("unknown action"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_name() {
        assert!(parse_wg_peer_manage_target(b"create:").is_err());
        assert!(parse_wg_peer_manage_target(b"create:   ").is_err());
    }

    #[test]
    fn parse_rejects_an_overlong_name() {
        let long = "a".repeat(200);
        let err = parse_wg_peer_manage_target(format!("create:{long}").as_bytes()).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn parse_rejects_invalid_characters() {
        assert!(parse_wg_peer_manage_target(b"create:new-peer; rm -rf /").is_err());
        assert!(parse_wg_peer_manage_target(b"create:../etc/passwd").is_err());
        assert!(parse_wg_peer_manage_target(b"create: -leading-space-then-dash").is_err());
    }

    /// The single most important test in this module: `larry-laptop` and
    /// `phone` must be rejected for delete/disable with the DISTINCT
    /// hard-deny message - proving this is a separate, unconditional code
    /// path (defense in depth), same discipline
    /// `docker_restart`'s own `parse_hard_denies_ai_uai_and_forge_node_
    /// regardless_of_allowlist` test proves for its own hard-deny list.
    #[test]
    fn parse_hard_denies_larry_laptop_and_phone_for_delete_and_disable() {
        for name in HARD_DENIED_WG_PEER_TARGETS {
            for action in ["delete", "disable"] {
                let err = parse_wg_peer_manage_target(format!("{action}:{name}").as_bytes()).unwrap_err();
                assert!(err.contains("hard-denied"), "'{action}:{name}' must be hard-denied, got: {err}");
            }
        }
        // Case-insensitivity.
        let err = parse_wg_peer_manage_target(b"delete:LARRY-LAPTOP").unwrap_err();
        assert!(err.contains("hard-denied"), "got: {err}");
    }

    /// The hard-deny must NOT apply to create/enable - additive/restorative
    /// actions on these same names are not the footgun this list exists to
    /// prevent (see `HARD_DENIED_WG_PEER_TARGETS`'s own doc comment).
    #[test]
    fn hard_denied_names_are_still_permitted_for_create_and_enable() {
        for name in HARD_DENIED_WG_PEER_TARGETS {
            assert!(parse_wg_peer_manage_target(format!("create:{name}").as_bytes()).is_ok());
            assert!(parse_wg_peer_manage_target(format!("enable:{name}").as_bytes()).is_ok());
        }
    }

    // --- dispatch-level configuration gating ---

    /// `ctx.uai_config` unset - the common case for a node that's never had
    /// wg_peer_manage configured at all. Uses a non-hard-denied name so
    /// this test proves the "not configured" short-circuit specifically.
    #[tokio::test]
    async fn reports_not_configured_when_uai_not_set() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19701);
        let mut config_b = test_config(19702);
        config_b.capability_policy_path = write_permissive_test_policy(19702, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peer_manage".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peer_manage").hash, trace_id, b"create:test-peer".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("an allowlisted-but-unconfigured wg_peer_manage request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "wg_peer_manage not configured on this node (no UAI backend)");
    }

    /// A peer with no allowlist entry gets the same generic "not
    /// authorized" denial every other capability's allowlist-miss
    /// produces - proving the Tier 2 nature of this capability doesn't
    /// bypass the same Phase 1.1 gate every other tier already passes
    /// through first.
    #[tokio::test]
    async fn denies_a_peer_with_no_allowlist_entry() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19703);
        let mut config_b = test_config(19704);
        config_b.capability_policy_path = write_permissive_test_policy(19704, &[Keypair::generate().node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peer_manage".to_string()];

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peer_manage").hash, trace_id, b"create:test-peer".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("a denied wg_peer_manage request must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert_eq!(String::from_utf8_lossy(&reply.payload), "not authorized for this capability");
    }

    /// AXIOM Phase 3.6's `denied_param_substrings`, wired the same way
    /// `docker_restart`/`proxmox_restart`/`home_assistant_toggle` wired it -
    /// an additional, policy-file-editable layer on top of (never instead
    /// of) the code-level hard-deny.
    #[tokio::test]
    async fn denies_a_request_targeting_a_policy_denylisted_value_before_any_uai_call() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19705);
        let mut config_b = test_config(19706);
        let allowed_toml = format!("\"{}\"", hex::encode(kp_a.node_id().as_bytes()));
        let policy_contents = format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.wg_peer_manage]\nallowed_peers = [{allowed_toml}]\nrate_limit_secs = 0\nconcurrency = 1000\ntier = \"tier2\"\ndenied_param_substrings = [\"blocked-peer\"]\n",
        );
        let policy_path = std::env::temp_dir().join(format!("axiom-test-policy-wg-peer-manage-denylist-{}.toml", std::process::id()));
        std::fs::write(&policy_path, policy_contents).unwrap();
        config_b.capability_policy_path = policy_path;
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peer_manage".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peer_manage").hash, trace_id, b"create:blocked-peer".to_vec(), None);
        let reply_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(1500)),
        )
            .await
            .expect("must return promptly")
            .expect("must get an explicit reply, not a silent drop");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("denied pattern"),
            "expected the check_denied_param_substrings reason text, got: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }

    /// Even a fully-allowlisted, fully-configured (UAI base_url set)
    /// request must still answer "not configured" for the Tier 2 approval
    /// channel specifically when telegram_bot_token/telegram_chat_id are
    /// absent - the UAI backend being configured must never be sufficient
    /// on its own for a Tier 2 capability to serve a real request.
    #[tokio::test]
    async fn reports_not_configured_when_uai_is_set_but_telegram_is_not() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let config_a = test_config(19707);
        let mut config_b = test_config(19708);
        config_b.capability_policy_path = write_permissive_test_policy(19708, &[kp_a.node_id()]);
        config_b.capabilities = vec!["echo".to_string(), "sysinfo".to_string(), "wg_peer_manage".to_string()];
        config_b.uai_base_url = Some("http://127.0.0.1:1".to_string());
        config_b.uai_token = Some("test-only-not-a-real-uai-token".to_string());
        // telegram_bot_token/telegram_chat_id deliberately left unset.

        let mgr_a = NetworkManager::new(&config_a, kp_a.clone()).await.unwrap();
        let mut mgr_b = NetworkManager::new(&config_b, kp_b.clone()).await.unwrap();
        mgr_b.register_peer(kp_a.node_id(), config_a.listen_addr, 1);

        let trace_id = next_trace_id();
        let frame_bytes = build_intent_frame(&kp_a, AiIntent::from_str("wg_peer_manage").hash, trace_id, b"create:test-peer".to_vec(), None);
        let reply_bytes = send_and_await_reply(&mgr_a.socket, config_b.listen_addr, &frame_bytes, Duration::from_millis(500))
            .await
            .expect("must get an explicit reply, not a hang");
        let reply = decode_verified_frame(&reply_bytes).unwrap();
        assert_eq!(reply.header.frame_type, FrameType::Error);
        assert!(
            String::from_utf8_lossy(&reply.payload).contains("no Tier 2 approval channel"),
            "got: {}",
            String::from_utf8_lossy(&reply.payload),
        );
    }
}

/// AXIOM Phase 3.7: regression coverage for the roadmap's point 3 -
/// "never let backend-returned strings be interpolated into anything AXIOM
/// itself executes, logs-as-structure, or uses for routing decisions."
/// This phase's own build notes: `fetch_network_clients`/
/// `dispatch_network_clients` were read in full and found to contain NO
/// instance of this bug class - the backend-returned `clients` value
/// passes through exactly one transformation
/// (`axiom_gateway::sanitize::sanitize_and_wrap_untrusted_json`) and then
/// straight into the Fulfill frame payload; neither function builds a
/// shell command, a file path, a log-format string, or a routing/dispatch
/// decision from it. `reply_routing`/`RoutingExt` (the only "routing
/// decision" either function touches at all) is threaded through from the
/// ORIGINAL Intent frame's own routing extension, never derived from the
/// fetched client data.
///
/// This module turns that one-time reading into a standing check: a
/// small, self-contained (deliberately NOT reusing
/// `capability_isolation.rs`'s private extractor - that module already
/// separately proves these two functions contain no process-spawn/
/// filesystem-write primitive at all via its own per-capability forbidden-
/// pattern scan, see `every_known_capability_has_no_forbidden_pattern_in_
/// its_implementation`) brace-matching extractor pulls each function's
/// CURRENT real source out of this very file (`include_str!` on itself,
/// same "embed real source, not a paraphrase" precedent
/// `capability_isolation.rs` already established for sibling files) and
/// asserts neither contains a logging-macro call, and that the sanitize
/// call this phase added is still actually present.
#[cfg(test)]
mod network_clients_output_safety_tests {
    const NETWORK_RS_SELF: &str = include_str!("network.rs");

    /// Brace-matching extraction of one function's full body (from its
    /// opening `{` through the matching closing `}`), skipping over `//`
    /// line comments, `/* */` block comments, and string/char literal
    /// contents so a stray brace inside any of those doesn't desync the
    /// depth count - same class of robustness
    /// `capability_isolation.rs::extract_braced_block` proves for its own
    /// (separate, private) implementation.
    fn extract_fn_body(fn_name: &str) -> String {
        let marker = format!("fn {fn_name}(");
        let start = NETWORK_RS_SELF
            .find(&marker)
            .unwrap_or_else(|| panic!("could not find `{marker}` in network.rs - has it been renamed or removed?"));
        let open_brace = NETWORK_RS_SELF[start..]
            .find('{')
            .map(|i| start + i)
            .expect("function signature must be followed by an opening brace");

        let bytes = NETWORK_RS_SELF.as_bytes();
        let mut depth: i32 = 0;
        let mut i = open_brace;
        let (mut in_string, mut in_char, mut escape) = (false, false, false);

        loop {
            if i >= bytes.len() {
                panic!("ran off the end of network.rs looking for `{fn_name}`'s closing brace");
            }
            let c = bytes[i] as char;

            if in_string {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_string = false;
                }
                i += 1;
                continue;
            }
            if in_char {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '\'' {
                    in_char = false;
                }
                i += 1;
                continue;
            }
            // Line comment: skip to (not including) the newline.
            if c == '/' && bytes.get(i + 1) == Some(&b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Block comment: skip past the matching `*/`.
            if c == '/' && bytes.get(i + 1) == Some(&b'*') {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            match c {
                '"' => in_string = true,
                '\'' => in_char = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return NETWORK_RS_SELF[open_brace..=i].to_string();
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    const LOGGING_MACROS: &[&str] = &["debug!(", "warn!(", "error!(", "info!(", "trace!("];

    #[test]
    fn fetch_network_clients_contains_no_logging_macro_call() {
        let body = extract_fn_body("fetch_network_clients");
        for macro_name in LOGGING_MACROS {
            assert!(
                !body.contains(macro_name),
                "fetch_network_clients must never log the raw or sanitized client payload via a \
                 format-string macro - found `{macro_name}`. A future legitimate need to log here \
                 must only ever log the SANITIZED value, and this test updated deliberately, not \
                 silently"
            );
        }
    }

    #[test]
    fn dispatch_network_clients_contains_no_logging_macro_call() {
        let body = extract_fn_body("dispatch_network_clients");
        for macro_name in LOGGING_MACROS {
            assert!(
                !body.contains(macro_name),
                "dispatch_network_clients must never log capability output via `{macro_name}`"
            );
        }
    }

    #[test]
    fn fetch_network_clients_still_sanitizes_the_backend_reply_before_returning() {
        let body = extract_fn_body("fetch_network_clients");
        assert!(
            body.contains("sanitize_and_wrap_untrusted_json"),
            "fetch_network_clients must pass the backend reply through the untrusted-data sanitizer \
             before returning - this is a regression guard against that call being silently removed"
        );
        assert!(
            !body.contains("Ok(clients.to_string())"),
            "must not revert to returning the raw, unsanitized backend reply directly"
        );
    }

    /// AXIOM wg_peers_list: same two regression guards as
    /// `fetch_network_clients` above, reusing this module's own
    /// capability-agnostic `extract_fn_body` helper - wg-easy peer `name`
    /// fields are attacker-influenceable the same way Omada hostnames/
    /// SSIDs are (see `fetch_wg_peers_list`'s own doc comment).
    #[test]
    fn fetch_wg_peers_list_contains_no_logging_macro_call() {
        let body = extract_fn_body("fetch_wg_peers_list");
        for macro_name in LOGGING_MACROS {
            assert!(
                !body.contains(macro_name),
                "fetch_wg_peers_list must never log the raw or sanitized peer list payload via a \
                 format-string macro - found `{macro_name}`"
            );
        }
    }

    #[test]
    fn dispatch_wg_peers_list_contains_no_logging_macro_call() {
        let body = extract_fn_body("dispatch_wg_peers_list");
        for macro_name in LOGGING_MACROS {
            assert!(
                !body.contains(macro_name),
                "dispatch_wg_peers_list must never log capability output via `{macro_name}`"
            );
        }
    }

    #[test]
    fn fetch_wg_peers_list_still_sanitizes_the_backend_reply_before_returning() {
        let body = extract_fn_body("fetch_wg_peers_list");
        assert!(
            body.contains("sanitize_and_wrap_untrusted_json"),
            "fetch_wg_peers_list must pass the backend reply through the untrusted-data sanitizer \
             before returning - this is a regression guard against that call being silently removed"
        );
        assert!(
            !body.contains("Ok(clients.to_string())"),
            "must not revert to returning the raw, unsanitized backend reply directly"
        );
    }

    /// The single most important regression guard for THIS capability
    /// specifically (see `fetch_wg_peers_list`'s own doc comment on why):
    /// it must never call any wg-easy tool that can return WireGuard
    /// private-key-bearing data (`wg_client_config`/`wg_client_qr`), and
    /// must never call the create/delete/enable/disable tools that would
    /// make this capability Tier2 rather than Tier1.
    #[test]
    fn fetch_wg_peers_list_never_calls_a_key_bearing_or_mutating_wg_easy_tool() {
        let body = extract_fn_body("fetch_wg_peers_list");
        for forbidden_tool in ["wg_client_config", "wg_client_qr", "wg_create_client", "wg_delete_client", "wg_enable_client", "wg_disable_client", "wg_rename_client"] {
            assert!(
                !body.contains(forbidden_tool),
                "fetch_wg_peers_list must never call `{forbidden_tool}` - this capability is scoped \
                 to the read-only `wg_clients` (list) tool only, see its own doc comment for why"
            );
        }
        assert!(body.contains("\"wg_clients\""), "fetch_wg_peers_list must call the wg_clients (list) tool");
    }

    /// AXIOM Tier 2: `wg_peer_manage`'s own regression guard - unlike
    /// `wg_peers_list`, this capability DOES legitimately call
    /// `wg_create_client`/`wg_delete_client`/`wg_enable_client`/
    /// `wg_disable_client` (that is its whole purpose), so the check here
    /// is narrower and different: it must never call the two tools that
    /// return WireGuard PRIVATE KEY material
    /// (`wg_client_config`/`wg_client_qr`), and it must never log or
    /// forward the raw `wg_create_client` response body wholesale (which
    /// DOES embed the newly-created peer's private key - see `perform`'s
    /// own doc comment) - only ever extracting its `data.id` field.
    #[test]
    fn wg_peer_manage_perform_never_calls_a_key_bearing_wg_easy_tool() {
        let body = extract_fn_body("perform");
        for forbidden_tool in ["wg_client_config", "wg_client_qr", "wg_rename_client"] {
            assert!(
                !body.contains(forbidden_tool),
                "wg_peer_manage's perform() must never call `{forbidden_tool}` - it would return \
                 WireGuard private key material over the wire"
            );
        }
        for required_tool in ["wg_create_client", "wg_delete_client", "wg_enable_client", "wg_disable_client"] {
            assert!(body.contains(required_tool), "wg_peer_manage's perform() must still call `{required_tool}`");
        }
    }

    #[test]
    fn wg_peer_manage_perform_never_forwards_the_raw_create_response_wholesale() {
        let body = extract_fn_body("perform");
        for macro_name in LOGGING_MACROS {
            assert!(
                !body.contains(macro_name),
                "wg_peer_manage's perform() must never log its UAI response via a format-string macro \
                 (the wg_create_client response embeds the new peer's private key) - found `{macro_name}`"
            );
        }
        // The ONLY field ever pulled out of the create response - a
        // regression guard against a future edit accidentally returning
        // `resp`/`resp.get("data")` wholesale (e.g. via `{:?}` Debug
        // formatting) instead of just its `id`.
        assert!(body.contains("d.get(\"id\")") || body.contains(".get(\"id\")"), "perform() must extract only the id field from the create response");
        assert!(!body.contains("{:?}\", resp"), "perform() must never Debug-format the raw UAI response");
        assert!(!body.contains("{resp:?}"), "perform() must never Debug-format the raw UAI response");
    }

    #[test]
    fn extractor_is_not_confused_by_a_synthetic_function_with_braces_in_comments_and_strings() {
        // Negative-test proof this extractor's comment/string handling
        // actually works, same "prove the mechanism can fail correctly"
        // discipline capability_isolation.rs's own scanner tests use -
        // not exercised against real source, a local synthetic fixture.
        const FIXTURE: &str = r#"
fn helper() {
    // a comment with a stray brace }
    /* another one { in a block comment */
    let s = "a string with a brace {";
    let c = '{';
    if true {
        let _ = 1;
    }
}
fn next_fn() {}
"#;
        let marker = "fn helper(";
        let start = FIXTURE.find(marker).unwrap();
        let open_brace = FIXTURE[start..].find('{').map(|i| start + i).unwrap();

        // Reuse the same algorithm inline against the fixture rather than
        // NETWORK_RS_SELF, by temporarily shadowing - simplest is to
        // duplicate the tiny walk here since `extract_fn_body` is hardwired
        // to NETWORK_RS_SELF; this stays a faithful proof of the same
        // string/comment-skipping logic since it's copied verbatim below.
        let bytes = FIXTURE.as_bytes();
        let mut depth: i32 = 0;
        let mut i = open_brace;
        let (mut in_string, mut in_char, mut escape) = (false, false, false);
        let end = loop {
            let c = bytes[i] as char;
            if in_string {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_string = false;
                }
                i += 1;
                continue;
            }
            if in_char {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '\'' {
                    in_char = false;
                }
                i += 1;
                continue;
            }
            if c == '/' && bytes.get(i + 1) == Some(&b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if c == '/' && bytes.get(i + 1) == Some(&b'*') {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            match c {
                '"' => in_string = true,
                '\'' => in_char = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break i;
                    }
                }
                _ => {}
            }
            i += 1;
        };
        let extracted = &FIXTURE[open_brace..=end];
        assert!(extracted.contains("let _ = 1;"), "must have found the real body content");
        assert!(!extracted.contains("next_fn"), "must not have run past helper()'s real closing brace");
    }
}

/// AXIOM Phase 1.2 (AXIOM-15): `extract_sender_with_timestamp`'s own
/// signature check, isolated from the timestamp-freshness and rate-limiting
/// concerns tested elsewhere (`discovery.rs`'s own test module covers
/// those - see its module doc comment for why they live there instead).
/// `CapabilityPolicy`'s allowlist gating (AXIOM Phase 1.1) already has
/// adequate dedicated coverage - 9 unit tests in axiom-gateway's `policy.rs` plus 4
/// end-to-end tests in this file's `policy_dispatch_tests` module above -
/// not duplicated here.
#[cfg(test)]
mod hello_validation_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    #[test]
    fn hello_signature_check_accepts_a_genuine_hello() {
        let identity = Keypair::generate();
        let hello_bytes = build_hello_frame(&identity);
        let (sender_id, _ts) = extract_sender_with_timestamp(&hello_bytes)
            .expect("a genuinely signed HELLO must verify");
        assert_eq!(sender_id, identity.node_id());
    }

    #[test]
    fn hello_signature_check_rejects_corrupted_signature() {
        let identity = Keypair::generate();
        let mut hello_bytes = build_hello_frame(&identity);
        let last = hello_bytes.len() - 1;
        hello_bytes[last] ^= 0xFF; // flip a bit inside the signature
        assert!(
            extract_sender_with_timestamp(&hello_bytes).is_none(),
            "a HELLO with a corrupted signature must not verify"
        );
    }

    #[test]
    fn hello_signature_check_rejects_claimed_node_id_not_matching_signer() {
        let identity = Keypair::generate();
        let impostor = Keypair::generate();
        let mut tampered = build_hello_frame(&identity);
        // Splice a different claimed node_id over the real signer's - the
        // signature was computed over the ORIGINAL node_id bytes, so this
        // must fail verification, not silently authenticate as the impostor.
        tampered[6..38].copy_from_slice(impostor.node_id().as_bytes());
        assert!(
            extract_sender_with_timestamp(&tampered).is_none(),
            "a HELLO whose claimed node_id doesn't match the actual signer must be rejected"
        );
    }

    #[test]
    fn hello_signature_check_rejects_truncated_buffer() {
        let identity = Keypair::generate();
        let hello_bytes = build_hello_frame(&identity);
        let truncated = &hello_bytes[..hello_bytes.len() - 20];
        assert!(
            extract_sender_with_timestamp(truncated).is_none(),
            "a truncated HELLO (too short to contain a full signature) must be rejected, not panic"
        );
    }
}

/// AXIOM Phase 1.2 (AXIOM-15): the regression guard for the historical bug
/// class described in `discovery.rs`'s receive loop comment - an incoming
/// packet used to only ever be tried as a HELLO frame; every other frame
/// type silently failed that one decode attempt and was dropped, logged
/// misleadingly as "signature verification failed" (a HELLO-specific
/// failure mode, not what actually happened to a Ping/Pong/Announce/Intent/
/// Fulfill/Error). `extract_sender_with_timestamp` and `decode_verified_frame`
/// are the exact two functions both this file's own receive loop
/// (`start_receive_loop`) and `discovery.rs`'s use, in the same fallback
/// order (HELLO first, then the Frame codec) - proving their disjointness
/// here at the unit level covers both call sites without needing a live
/// socket. `discovery.rs`'s own socket requires real link-local interfaces
/// to bind at all, deliberately excluded from this codebase's unit tests -
/// see `multihop_tests`' module doc comment for why real-interface-dependent
/// behavior doesn't belong in a unit test.
#[cfg(test)]
mod frame_family_dispatch_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    /// Every Frame-codec type this build dispatches - not a stand-in
    /// subset. If any one of these silently fell back to being tried as a
    /// HELLO (or failed to decode at all), the historical bug class would
    /// be back for that specific frame type.
    #[test]
    fn every_non_hello_frame_type_decodes_via_frame_path_not_hello_path() {
        let identity = Keypair::generate();
        let trace_id = next_trace_id();
        let intent_hash = AiIntent::from_str("echo").hash;

        let mut announce_mgr = AnnouncementManager::new(identity.clone());
        announce_mgr.register_capability(AnnouncedCapability::new(intent_hash, *b"capa"));
        let announce_frame = announce_mgr.create_announcement(MAX_ROUTE_INDIRECTION);
        let announce_bytes = sign_and_encode_frame(&identity, announce_frame, FrameType::Announce);

        let cases: Vec<(FrameType, Vec<u8>)> = vec![
            (FrameType::Ping, build_ping_frame(&identity, trace_id)),
            (FrameType::Pong, build_pong_frame(&identity, trace_id)),
            (FrameType::Announce, announce_bytes),
            (FrameType::Intent, build_intent_frame(&identity, intent_hash, trace_id, b"hi".to_vec(), None)),
            (FrameType::Fulfill, build_fulfill_frame(&identity, intent_hash, trace_id, b"hi".to_vec(), None)),
            (FrameType::Error, build_error_frame(&identity, intent_hash, trace_id, "nope", None)),
        ];

        for (expected_type, bytes) in cases {
            assert!(
                extract_sender_with_timestamp(&bytes).is_none(),
                "{:?} frame bytes must NOT parse as a HELLO - if they did, the historical \
                 'everything tried as HELLO first' bug could silently misroute it",
                expected_type
            );
            let frame = decode_verified_frame(&bytes).unwrap_or_else(|| {
                panic!("{:?} frame must decode+verify via the Frame codec fallback path", expected_type)
            });
            assert_eq!(
                frame.header.frame_type, expected_type,
                "decoded frame_type must match what was actually built and sent"
            );
        }
    }

    /// The mirror image of the test above: a real HELLO must decode via
    /// `extract_sender_with_timestamp` and must NOT also be mistaken for a
    /// codec Frame - confirms the two decode paths are genuinely disjoint in
    /// both directions, not just "Frame bytes never look like HELLO."
    #[test]
    fn hello_frame_decodes_only_via_hello_path_not_frame_path() {
        let identity = Keypair::generate();
        let hello_bytes = build_hello_frame(&identity);

        let (sender_id, _ts) = extract_sender_with_timestamp(&hello_bytes)
            .expect("a real HELLO must decode via extract_sender_with_timestamp");
        assert_eq!(sender_id, identity.node_id());

        assert!(
            decode_verified_frame(&hello_bytes).is_none(),
            "a HELLO frame must not also decode as a codec Frame - the two families must stay disjoint"
        );
    }
}

/// AXIOM Phase 1.2 (AXIOM-15): boundary tests for `origin_clock_is_fresh`,
/// the Announce arm's own freshness check - the second place (besides
/// HELLO's `MAX_HELLO_AGE_SECS`/`MAX_CLOCK_SKEW_SECS` in `discovery.rs`)
/// this codebase rejects a signed-but-stale timestamp. `MAX_ANNOUNCE_CLOCK_SKEW`
/// (5 minutes) is symmetric - unlike HELLO's separate past/future bounds -
/// so both directions are covered here.
#[cfg(test)]
mod announce_clock_freshness_tests {
    use super::*;

    #[test]
    fn fresh_at_zero_skew() {
        assert!(origin_clock_is_fresh(1_000_000, 1_000_000));
    }

    #[test]
    fn fresh_at_exact_past_boundary() {
        // origin_clock exactly MAX_ANNOUNCE_CLOCK_SKEW seconds in the past -
        // one tick INSIDE the window, must still pass (`>`, not `>=`).
        let skew = MAX_ANNOUNCE_CLOCK_SKEW.as_secs();
        assert!(origin_clock_is_fresh(1_000_000 - skew, 1_000_000));
    }

    #[test]
    fn stale_one_second_past_the_past_boundary() {
        let skew = MAX_ANNOUNCE_CLOCK_SKEW.as_secs();
        assert!(!origin_clock_is_fresh(1_000_000 - skew - 1, 1_000_000));
    }

    #[test]
    fn fresh_at_exact_future_boundary() {
        // origin_clock exactly MAX_ANNOUNCE_CLOCK_SKEW seconds in the
        // future relative to now - one tick INSIDE the window, must pass.
        let skew = MAX_ANNOUNCE_CLOCK_SKEW.as_secs();
        assert!(origin_clock_is_fresh(1_000_000 + skew, 1_000_000));
    }

    #[test]
    fn stale_one_second_past_the_future_boundary() {
        let skew = MAX_ANNOUNCE_CLOCK_SKEW.as_secs();
        assert!(!origin_clock_is_fresh(1_000_000 + skew + 1, 1_000_000));
    }
}

/// AXIOM Phase 1.2 (AXIOM-15): `register_peer`'s own replay/monotonicity and
/// LRU-eviction behavior, isolated from the routing/forwarding/gossip
/// concerns the other test modules above exercise. `register_peer` is a
/// synchronous, purely in-memory operation - these tests call it directly
/// with synthetic addresses, no real peer on the other end needed, the same
/// way `multihop_tests`/etc. use bare `NetworkManager`s without a full
/// `ForgeNode` event loop.
#[cfg(test)]
mod peer_registration_tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    fn test_config(port: u16) -> NodeConfig {
        NodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            enable_link_local_discovery: false,
            ..NodeConfig::default()
        }
    }

    /// A new HELLO timestamp <= the peer's last-accepted one must be
    /// rejected outright (address left unchanged) - this is what stops a
    /// captured HELLO from being replayed later to rebind a peer's address
    /// to an attacker's. Exercises both an exact replay (same timestamp)
    /// and a genuinely older one (out-of-order delivery), then confirms a
    /// strictly newer timestamp is still accepted afterward.
    #[tokio::test]
    async fn register_peer_rejects_replayed_and_out_of_order_timestamps() {
        let config = test_config(19611);
        let mgr_identity = Keypair::generate();
        let mut mgr = NetworkManager::new(&config, mgr_identity).await.unwrap();

        let peer_id = Keypair::generate().node_id();
        let addr1: SocketAddr = "127.0.0.1:19612".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:19613".parse().unwrap();

        mgr.register_peer(peer_id, addr1, 100);
        assert_eq!(mgr.peers.get(&peer_id).unwrap().addr, addr1);

        // Exact replay: same timestamp again - must be rejected, address
        // must not move to addr2.
        mgr.register_peer(peer_id, addr2, 100);
        assert_eq!(
            mgr.peers.get(&peer_id).unwrap().addr, addr1,
            "a replayed (equal) HELLO timestamp must not update the peer's address"
        );

        // Out-of-order: an OLDER timestamp than what's on record - also
        // rejected, same as an exact replay.
        mgr.register_peer(peer_id, addr2, 50);
        assert_eq!(
            mgr.peers.get(&peer_id).unwrap().addr, addr1,
            "an out-of-order (older) HELLO timestamp must be rejected as stale/replayed"
        );

        // A genuinely newer timestamp must still be accepted afterward -
        // proves the peer isn't permanently stuck, only non-monotonic
        // updates are rejected.
        mgr.register_peer(peer_id, addr2, 101);
        assert_eq!(
            mgr.peers.get(&peer_id).unwrap().addr, addr2,
            "a strictly newer HELLO timestamp must be accepted and update the peer's address"
        );
    }

    /// A peer reached via explicit `connect()` (the `bootstrap_nodes` path)
    /// must never be LRU-evicted under `max_peers` pressure - only
    /// discovery-sourced peers are ever evictable. Fills every slot with
    /// discovered peers and confirms the bootstrap connection survives.
    #[tokio::test]
    async fn lru_eviction_never_evicts_an_explicit_connect_peer() {
        let kp_local = Keypair::generate();
        let kp_bootstrap = Keypair::generate();
        let mut config_local = test_config(19621);
        config_local.max_peers = 2;
        let config_bootstrap = test_config(19622);

        let mut mgr_bootstrap = NetworkManager::new(&config_bootstrap, kp_bootstrap.clone()).await.unwrap();
        let mut mgr_local = NetworkManager::new(&config_local, kp_local.clone()).await.unwrap();

        let bootstrap_id = mgr_local.connect(&config_bootstrap.listen_addr).await.unwrap();
        mgr_bootstrap.register_peer(kp_local.node_id(), config_local.listen_addr, 1);
        assert_eq!(bootstrap_id, kp_bootstrap.node_id());
        assert_eq!(mgr_local.peers.len(), 1);

        // Fill the remaining slot with one discovered peer.
        let kp_disc_1 = Keypair::generate();
        let addr_disc_1: SocketAddr = "127.0.0.1:19700".parse().unwrap();
        mgr_local.register_peer(kp_disc_1.node_id(), addr_disc_1, 1);
        assert_eq!(mgr_local.peers.len(), 2, "max_peers (2) should now be reached");

        // A second discovered peer arriving now must evict the LRU
        // discovered peer (kp_disc_1) - never the bootstrap connection.
        let kp_disc_2 = Keypair::generate();
        let addr_disc_2: SocketAddr = "127.0.0.1:19701".parse().unwrap();
        mgr_local.register_peer(kp_disc_2.node_id(), addr_disc_2, 1);

        assert_eq!(mgr_local.peers.len(), 2, "max_peers must still be respected");
        assert!(
            mgr_local.peers.contains_key(&bootstrap_id),
            "the explicit connect()-established peer must never be evicted"
        );
        assert!(
            !mgr_local.peers.contains_key(&kp_disc_1.node_id()),
            "the older discovered peer must be the one evicted, not the bootstrap peer"
        );
        assert!(
            mgr_local.peers.contains_key(&kp_disc_2.node_id()),
            "the newly registered discovered peer must be admitted"
        );
    }

    /// When `max_peers` is entirely full of never-evictable (explicit-
    /// connect) peers, a new discovered peer must be dropped outright - it
    /// must NOT evict a bootstrap connection just to make room.
    #[tokio::test]
    async fn lru_eviction_drops_new_discovered_peer_when_nothing_is_evictable() {
        let kp_local = Keypair::generate();
        let kp_b1 = Keypair::generate();
        let kp_b2 = Keypair::generate();
        let mut config_local = test_config(19631);
        config_local.max_peers = 2;
        let config_b1 = test_config(19632);
        let config_b2 = test_config(19633);

        let mut mgr_b1 = NetworkManager::new(&config_b1, kp_b1.clone()).await.unwrap();
        let mut mgr_b2 = NetworkManager::new(&config_b2, kp_b2.clone()).await.unwrap();
        let mut mgr_local = NetworkManager::new(&config_local, kp_local.clone()).await.unwrap();

        let b1_id = mgr_local.connect(&config_b1.listen_addr).await.unwrap();
        mgr_b1.register_peer(kp_local.node_id(), config_local.listen_addr, 1);
        let b2_id = mgr_local.connect(&config_b2.listen_addr).await.unwrap();
        mgr_b2.register_peer(kp_local.node_id(), config_local.listen_addr, 1);
        assert_eq!(mgr_local.peers.len(), 2, "max_peers (2) reached with two explicit-connect peers");

        let kp_disc = Keypair::generate();
        let addr_disc: SocketAddr = "127.0.0.1:19702".parse().unwrap();
        mgr_local.register_peer(kp_disc.node_id(), addr_disc, 1);

        assert_eq!(mgr_local.peers.len(), 2, "max_peers must still be respected");
        assert!(mgr_local.peers.contains_key(&b1_id), "an explicit-connect peer must survive");
        assert!(mgr_local.peers.contains_key(&b2_id), "the other explicit-connect peer must survive too");
        assert!(
            !mgr_local.peers.contains_key(&kp_disc.node_id()),
            "the new discovered peer must be dropped outright, not admitted by evicting a bootstrap peer"
        );
    }

    /// With several discovered peers competing for eviction, the LRU
    /// (oldest `last_seen`) one must be chosen - not insertion order into
    /// the underlying `HashMap` (which is unspecified) and not `NodeId`
    /// ordering.
    #[tokio::test]
    async fn lru_eviction_picks_the_oldest_last_seen_discovered_peer() {
        let mut config = test_config(19641);
        // Room for exactly 3 discovered peers before eviction pressure starts.
        config.max_peers = 3;
        let mgr_identity = Keypair::generate();
        let mut mgr = NetworkManager::new(&config, mgr_identity).await.unwrap();

        let kp_oldest = Keypair::generate();
        let kp_middle = Keypair::generate();
        let kp_newest = Keypair::generate();
        let addr_oldest: SocketAddr = "127.0.0.1:19710".parse().unwrap();
        let addr_middle: SocketAddr = "127.0.0.1:19711".parse().unwrap();
        let addr_newest: SocketAddr = "127.0.0.1:19712".parse().unwrap();

        // Registered in order, with a real (small) gap between each so
        // `last_seen` orders identically to registration order regardless
        // of clock resolution.
        mgr.register_peer(kp_oldest.node_id(), addr_oldest, 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
        mgr.register_peer(kp_middle.node_id(), addr_middle, 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
        mgr.register_peer(kp_newest.node_id(), addr_newest, 1);
        assert_eq!(mgr.peers.len(), 3, "max_peers (3) reached");

        // A 4th discovered peer must evict kp_oldest specifically, not
        // kp_middle or kp_newest.
        let kp_fourth = Keypair::generate();
        let addr_fourth: SocketAddr = "127.0.0.1:19713".parse().unwrap();
        mgr.register_peer(kp_fourth.node_id(), addr_fourth, 1);

        assert_eq!(mgr.peers.len(), 3, "max_peers must still be respected");
        assert!(!mgr.peers.contains_key(&kp_oldest.node_id()), "the oldest last_seen peer must be evicted first");
        assert!(mgr.peers.contains_key(&kp_middle.node_id()), "a more-recently-seen peer must survive");
        assert!(mgr.peers.contains_key(&kp_newest.node_id()), "the most-recently-seen peer must survive");
        assert!(mgr.peers.contains_key(&kp_fourth.node_id()), "the newly registered peer must be admitted");
    }
}
