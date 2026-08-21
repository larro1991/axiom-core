//! Capability announcement and discovery for AXIOM mesh
//!
//! Provides ANNOUNCE frame handling for advertising capabilities
//! to the mesh network.

use alloc::vec::Vec;
use axiom_types::clock::HybridClock;
use axiom_types::crypto::{IntentHash, NodeId, Signature};
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;
use axiom_types::{CLOCK_SIZE, NODE_ID_SIZE, SIGNATURE_SIZE};

#[cfg(feature = "std")]
use axiom_crypto::identity::{Keypair, Signer, Verifier};

/// Maximum TTL for announcements - the protocol's raw ceiling, not what
/// this deployment's routing can actually serve (see
/// `MAX_ACCEPTED_ANNOUNCE_TTL` for that).
pub const MAX_ANNOUNCE_TTL: u8 = 16;

/// AXIOM-14 Cycle 6 (Fable plan review, required): how many hops of
/// GOSSIP-RELAY indirection routing can actually forward through, beyond a
/// node's own direct peers - the single source of truth both
/// `MAX_ACCEPTED_ANNOUNCE_TTL` below (how far gossip propagates) and
/// `forge-node/src/network.rs`'s `try_forward_routed_frame` (how far a
/// routed Intent/Fulfill/Error can actually be forwarded, via its
/// `reachable_via` consultation) are derived from/must agree with. Before
/// this cycle these were TWO independently hardcoded magic-1s (this
/// constant's predecessor, and `spawn_announce`'s `create_announcement(1)`
/// call) that had to be kept in sync by comment discipline alone - now
/// there is exactly one number to change, and both call sites derive from
/// it by construction. A node `N` hops from an origin needs gossip to have
/// survived `N-1` relay-forwards to have ANY `reachable_via` entry for that
/// origin at all, so `MAX_ROUTE_INDIRECTION` hops of indirection beyond an
/// origin's own direct announce means a total reachable radius of
/// `MAX_ROUTE_INDIRECTION + 1` hops end to end.
pub const MAX_ROUTE_INDIRECTION: u8 = 2;

/// AXIOM-14 Cycle 4 (Fable plan review, required) / Cycle 6 (now DERIVED
/// from `MAX_ROUTE_INDIRECTION`, not an independent hardcoded number - see
/// that constant's doc comment): the TTL an INCOMING announce is clamped
/// to, deliberately distinct from `MAX_ANNOUNCE_TTL`. Cycle 2b established
/// that routing could only ever forward to a direct peer (one-hop-of-
/// indirection only) and fixed the SEND side accordingly (`spawn_announce`
/// used TTL=1, not the protocol max). That fix never touched the RECEIVE
/// side: `process_announcement` clamped only to `MAX_ANNOUNCE_TTL` (16) and
/// forwarded whenever `ttl > 0`, so a peer claiming ttl=16 reintroduced the
/// exact bug Cycle 2b fixed - registering providers further away than
/// routing could ever reach (guaranteed 25s timeout), and turning every
/// accepted announce into up to a 16-hop mesh-wide flood. Cycle 6 taught
/// routing to forward `MAX_ROUTE_INDIRECTION` hops of indirection (see
/// `try_forward_routed_frame`'s `reachable_via` consultation in
/// `forge-node/src/network.rs`), so this clamp now matches that reach
/// exactly rather than the old fixed 1 - the two invariants (how far
/// gossip reaches vs. how far routing can actually forward) can never
/// silently drift apart again, by construction rather than by comment.
/// Clamped here, on receipt, so it applies no matter what the sender
/// claims.
pub const MAX_ACCEPTED_ANNOUNCE_TTL: u8 = MAX_ROUTE_INDIRECTION;

/// AXIOM-14 Cycle 5: bounds how far an origin's claimed
/// `origin_clock.physical` may diverge from real wall-clock time, in
/// EITHER direction, before an Announce is rejected outright. Closes a
/// replay hazard Cycle 4's origin-signature check does NOT cover: that
/// check proves an Announce was genuinely signed by the claimed origin,
/// but has no bound on how OLD the signed claim is. `AnnouncementManager`'s
/// dedup map (`seen`) is pruned after `ANNOUNCEMENT_MAX_AGE` (30 minutes,
/// in `forge-node/src/network.rs`) of no touches; once an origin's entry
/// is pruned, a captured OLD-but-genuinely-signed Announce (recorded
/// earlier, replayed later) lands on a Vacant dedup entry, reads as
/// "fresh," and full-set-replaces that origin's capability registry with
/// stale data - the signature is real, so Cycle 4's check alone can't
/// catch this, it isn't spoofing, it's a stale-data replay. 300s gives 6x
/// margin below `ANNOUNCEMENT_MAX_AGE` - comfortably above real relay
/// latency, while a replay old enough to actually exploit dedup eviction
/// is always well outside this bound too. Also rejects clock values too
/// far in the FUTURE, which protects against gaming the strictly-newer-
/// only dedup polarity (see `process_announcement`) by pre-dating a
/// forged-but-signed claim so it always reads as newer than whatever's
/// currently in `seen`. Only meaningful because `create_announcement` now
/// calls `ClockManager::sync_physical()` before ticking (AXIOM-14 Cycle 5)
/// - without that fix, a long-uptime node's own genuine announces would
/// drift outside this bound and start rejecting themselves.
#[cfg(feature = "std")]
pub const MAX_ANNOUNCE_CLOCK_SKEW: std::time::Duration = std::time::Duration::from_secs(300);

/// Default announcement refresh interval (milliseconds)
pub const DEFAULT_REFRESH_INTERVAL_MS: u64 = 30000;

/// AXIOM-14 Cycle 4: domain-separation prefix for the origin-signature
/// canonical bytes (see `AnnouncePayload::origin_signing_bytes`). Without
/// this, the exact same Ed25519 key signs two different kinds of message
/// under two different schemes with no way to tell them apart - the outer
/// frame signature (`axiom_codec::Encoder::signature_data`, which covers
/// the whole encoded frame including this payload) and the origin-claim
/// signature over a bare `origin || origin_clock || cap_count || caps`
/// tuple. A domain tag makes the two unambiguously distinct messages, so a
/// valid signature for one can never be replayed as a valid signature for
/// the other.
const ORIGIN_SIG_DOMAIN: &[u8] = b"AXIOM/announce-origin/v1";

/// Announcement payload structure
/// Layout: [ttl: 1][num_caps: 2][capabilities: variable][origin+origin_clock(+origin_signature): 0, 39, or 103]
#[derive(Debug, Clone)]
pub struct AnnouncePayload {
    /// Time-to-live (hop count)
    pub ttl: u8,
    /// Capabilities being announced
    pub capabilities: Vec<AnnouncedCapability>,
    /// AXIOM-14 Cycle 2a: the ORIGINAL announcer's NodeId, preserved
    /// unmodified through every forward - distinct from
    /// `frame.header.sender_id`, which is whoever physically relayed this
    /// specific copy to you. `None` only for the raw wire shape predating
    /// Cycle 2a; as of Cycle 4, `process_announcement` requires this
    /// AND `origin_signature` to be present and to verify, or the frame is
    /// dropped outright - see that function's doc comment.
    pub origin: Option<NodeId>,
    /// The origin's own causal clock at the moment it created this
    /// announcement, likewise preserved unmodified through every forward.
    /// `frame.header.clock` CANNOT be reused for this - it gets re-stamped
    /// by each relay's own `ClockManager` on every forward, so a forwarded
    /// copy always looks "newer" than the last one seen, forever, in any
    /// topology with a cycle (the exact amplification hazard Fable's
    /// Cycle 2 plan review caught before this ever went live).
    pub origin_clock: Option<HybridClock>,
    /// AXIOM-14 Cycle 4: the origin's own Ed25519 signature over
    /// `origin_signing_bytes()` - proves the claimed `origin` actually
    /// created this announcement, not merely that SOME known peer relayed
    /// a frame claiming to be about it. Before this field existed, any
    /// known peer could claim an arbitrary `origin` and have
    /// `process_announcement` act on that claim with full authority:
    /// `unregister_node(&origin)` would wipe the real origin's entire
    /// registry, and a fabricated max-value `origin_clock` would
    /// permanently poison the dedup entry so the real origin's future
    /// legitimate announces were silently suppressed forever. Preserved
    /// byte-for-byte through every forward (opaque to relays - they don't
    /// have the origin's private key and must never try to re-sign it);
    /// only ever computed at the origin, in `AnnouncementManager::create_announcement`.
    pub origin_signature: Option<Signature>,
}

/// A single announced capability
#[derive(Debug, Clone)]
pub struct AnnouncedCapability {
    /// Hash of the intent this capability fulfills
    pub intent_hash: IntentHash,
    /// Capability category (from intent)
    pub category: [u8; 4],
    /// Current load (0-255, lower = more available)
    pub load: u8,
    /// Self-reported latency in milliseconds
    pub latency_ms: u16,
}

impl AnnouncedCapability {
    pub fn new(intent_hash: IntentHash, category: [u8; 4]) -> Self {
        Self {
            intent_hash,
            category,
            load: 128, // Default to mid-range load
            latency_ms: 0,
        }
    }

    pub fn with_load(mut self, load: u8) -> Self {
        self.load = load;
        self
    }

    pub fn with_latency(mut self, latency_ms: u16) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Encode a single capability (23 bytes)
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(23);
        data.extend_from_slice(self.intent_hash.as_bytes()); // 16 bytes
        data.extend_from_slice(&self.category); // 4 bytes
        data.push(self.load); // 1 byte
        data.extend_from_slice(&self.latency_ms.to_be_bytes()); // 2 bytes
        data
    }

    /// Decode a capability from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 23 {
            return None;
        }

        let mut intent_bytes = [0u8; 16];
        intent_bytes.copy_from_slice(&data[0..16]);
        let intent_hash = IntentHash::from_bytes(intent_bytes);

        let mut category = [0u8; 4];
        category.copy_from_slice(&data[16..20]);

        let load = data[20];
        let latency_ms = u16::from_be_bytes([data[21], data[22]]);

        Some(Self {
            intent_hash,
            category,
            load,
            latency_ms,
        })
    }
}

impl AnnouncePayload {
    pub fn new(ttl: u8) -> Self {
        Self {
            ttl,
            capabilities: Vec::new(),
            origin: None,
            origin_clock: None,
            origin_signature: None,
        }
    }

    /// Add a capability to announce
    pub fn add_capability(&mut self, cap: AnnouncedCapability) {
        self.capabilities.push(cap);
    }

    /// Attach the stable origin identity/clock - see `AnnouncePayload::origin`'s
    /// doc comment. Always set together; there's no valid state with one
    /// present and the other absent. Does NOT set `origin_signature` -
    /// use `with_origin_signature` for that (kept separate because a
    /// relay forwarding someone else's announcement calls this to carry
    /// origin/origin_clock through, but must never fabricate a signature -
    /// it copies the origin's existing one across unmodified instead, via
    /// `with_origin_signature`).
    pub fn with_origin(mut self, origin: NodeId, origin_clock: HybridClock) -> Self {
        self.origin = Some(origin);
        self.origin_clock = Some(origin_clock);
        self
    }

    /// Attach a (previously computed or forwarded-through) origin
    /// signature. See `origin_signature`'s doc comment.
    pub fn with_origin_signature(mut self, origin_signature: Signature) -> Self {
        self.origin_signature = Some(origin_signature);
        self
    }

    /// AXIOM-14 Cycle 4: the canonical bytes the origin signs (and a
    /// verifier re-derives) to prove authorship of `origin`/`origin_clock`
    /// plus the exact capability set being claimed. Deliberately excludes
    /// `ttl` - it decrements on every hop, same precedent as
    /// `RoutingExt.ttl` being excluded from the outer frame's
    /// `signature_data` since Cycle 1a - a field that legitimately mutates
    /// in transit can't be part of what a signature proves unchanged.
    /// `None` if `origin`/`origin_clock` aren't both set yet (nothing
    /// meaningful to sign).
    pub fn origin_signing_bytes(&self) -> Option<Vec<u8>> {
        let (origin, origin_clock) = match (&self.origin, &self.origin_clock) {
            (Some(o), Some(c)) => (o, c),
            _ => return None,
        };
        Some(Self::origin_signing_bytes_for(origin, origin_clock, &self.capabilities))
    }

    /// Free-standing version of `origin_signing_bytes` for callers that
    /// already have the three pieces separately (verification, where they
    /// come from a just-decoded payload rather than `self`) - both signer
    /// and verifier MUST go through this single implementation, or a
    /// mismatch between two independent re-encodings becomes a signature
    /// that verifies on one path and silently fails on the other (the same
    /// hazard `axiom_codec::Encoder::signature_data` was written to avoid
    /// for the outer frame signature).
    pub fn origin_signing_bytes_for(origin: &NodeId, origin_clock: &HybridClock, capabilities: &[AnnouncedCapability]) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            ORIGIN_SIG_DOMAIN.len() + NODE_ID_SIZE + CLOCK_SIZE + 2 + capabilities.len() * 23,
        );
        data.extend_from_slice(ORIGIN_SIG_DOMAIN);
        data.extend_from_slice(origin.as_bytes());
        data.extend_from_slice(&origin_clock.to_bytes());
        data.extend_from_slice(&(capabilities.len() as u16).to_be_bytes());
        for cap in capabilities {
            data.extend_from_slice(&cap.encode());
        }
        data
    }

    /// Encode the payload
    pub fn encode(&self) -> Vec<u8> {
        let cap_count = self.capabilities.len() as u16;
        let mut data = Vec::with_capacity(3 + self.capabilities.len() * 23 + NODE_ID_SIZE + CLOCK_SIZE + SIGNATURE_SIZE);

        data.push(self.ttl);
        data.extend_from_slice(&cap_count.to_be_bytes());

        for cap in &self.capabilities {
            data.extend_from_slice(&cap.encode());
        }

        // AXIOM-14 Cycle 2a/4: origin/origin_clock(/origin_signature) trail
        // the capabilities block if present. No flag bit - this payload has
        // no header of its own to carry one - so back-compat decode is
        // exact-length based instead (see `decode` below): `encode()` only
        // ever emits exactly 0, 39, or 103 extra bytes, never a partial tail.
        if let (Some(origin), Some(origin_clock)) = (&self.origin, &self.origin_clock) {
            data.extend_from_slice(origin.as_bytes());
            data.extend_from_slice(&origin_clock.to_bytes());
            if let Some(sig) = &self.origin_signature {
                data.extend_from_slice(sig.as_bytes());
            }
        }

        data
    }

    /// Decode from bytes. Purely structural - does NOT enforce the
    /// signed-origin security policy (that lives in `process_announcement`,
    /// the actual trust boundary). A payload with `origin`/`origin_clock`
    /// set but `origin_signature` absent decodes successfully here (it's a
    /// real, parseable wire shape - the pre-Cycle-4 one) precisely so the
    /// caller can distinguish "no origin claimed at all" from "origin
    /// claimed but unverifiable" and log accordingly, rather than both
    /// collapsing into the same `None` from a decode failure.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }

        let ttl = data[0];
        let cap_count = u16::from_be_bytes([data[1], data[2]]) as usize;
        let caps_end = 3 + cap_count * 23;

        if data.len() < caps_end {
            return None;
        }

        let mut capabilities = Vec::with_capacity(cap_count);
        for i in 0..cap_count {
            let offset = 3 + i * 23;
            if let Some(cap) = AnnouncedCapability::decode(&data[offset..offset + 23]) {
                capabilities.push(cap);
            }
        }

        // Exact-length check, not "at least" - each of the three trailer
        // shapes (0 / 39 / 103 bytes) is a distinct, fully-determined
        // length once `caps_end` is known, so at most one arm can ever
        // match a given byte string - no ambiguity between a corrupt/
        // truncated newer payload and a genuinely older one.
        let (origin, origin_clock, origin_signature) = if data.len() == caps_end + NODE_ID_SIZE + CLOCK_SIZE + SIGNATURE_SIZE {
            let mut node_bytes = [0u8; NODE_ID_SIZE];
            node_bytes.copy_from_slice(&data[caps_end..caps_end + NODE_ID_SIZE]);
            let mut clock_bytes = [0u8; CLOCK_SIZE];
            clock_bytes.copy_from_slice(&data[caps_end + NODE_ID_SIZE..caps_end + NODE_ID_SIZE + CLOCK_SIZE]);
            let mut sig_bytes = [0u8; SIGNATURE_SIZE];
            sig_bytes.copy_from_slice(&data[caps_end + NODE_ID_SIZE + CLOCK_SIZE..caps_end + NODE_ID_SIZE + CLOCK_SIZE + SIGNATURE_SIZE]);
            (
                Some(NodeId::from_bytes(node_bytes)),
                Some(HybridClock::from_bytes(&clock_bytes)),
                Some(Signature::from_bytes(sig_bytes)),
            )
        } else if data.len() == caps_end + NODE_ID_SIZE + CLOCK_SIZE {
            let mut node_bytes = [0u8; NODE_ID_SIZE];
            node_bytes.copy_from_slice(&data[caps_end..caps_end + NODE_ID_SIZE]);
            let mut clock_bytes = [0u8; CLOCK_SIZE];
            clock_bytes.copy_from_slice(&data[caps_end + NODE_ID_SIZE..caps_end + NODE_ID_SIZE + CLOCK_SIZE]);
            (Some(NodeId::from_bytes(node_bytes)), Some(HybridClock::from_bytes(&clock_bytes)), None)
        } else {
            (None, None, None)
        };

        Some(Self { ttl, capabilities, origin, origin_clock, origin_signature })
    }

    /// Decrement TTL for forwarding
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }
}

/// Manages announcement generation and tracking
#[cfg(feature = "std")]
pub struct AnnouncementManager {
    /// Our identity. AXIOM-14 Cycle 4 (Fable plan review, required R6):
    /// holds the full `Keypair`, not just a `NodeId`, and every announced
    /// `node_id` is derived from it on demand (`self.identity.node_id()`)
    /// rather than cached separately - this repo has already been bitten
    /// once by an announced identity and a signing key silently
    /// disagreeing (see `NodeConfig::load_or_generate_identity`'s
    /// identity-mismatch check, added after that exact incident), and a
    /// single source of truth makes the equivalent bug structurally
    /// impossible here.
    identity: Keypair,
    /// Our local capabilities
    local_capabilities: Vec<AnnouncedCapability>,
    /// Announcements we've seen (for dedup)
    seen: hashbrown::HashMap<(NodeId, IntentHash), SeenAnnouncement>,
    /// Clock for announcements
    clock: axiom_clock::ClockManager,
}

/// Tracks a seen announcement
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct SeenAnnouncement {
    /// When we first saw this
    pub first_seen: std::time::Instant,
    /// The clock value from the announcement
    pub clock: HybridClock,
    /// How many times we've seen this
    pub count: u32,
}

#[cfg(feature = "std")]
impl AnnouncementManager {
    pub fn new(identity: Keypair) -> Self {
        Self {
            identity,
            local_capabilities: Vec::new(),
            seen: hashbrown::HashMap::new(),
            clock: axiom_clock::ClockManager::new(),
        }
    }

    /// Our node ID, derived from `identity` - see that field's doc comment
    /// for why this is never cached separately.
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Register a local capability
    pub fn register_capability(&mut self, cap: AnnouncedCapability) {
        self.local_capabilities.push(cap);
    }

    /// Unregister a capability
    pub fn unregister_capability(&mut self, intent_hash: &IntentHash) {
        self.local_capabilities.retain(|c| &c.intent_hash != intent_hash);
    }

    /// Create an announcement frame for our capabilities, signed both at
    /// the frame level (by whoever calls `sign_and_encode_frame` on the
    /// returned `Frame` - unchanged from before) AND, as of Cycle 4, at
    /// the payload level: `origin_signature` proves WE (the origin)
    /// actually created this specific origin/clock/capability claim, so a
    /// relay can carry it forward but never forge or tamper with it.
    pub fn create_announcement(&mut self, ttl: u8) -> Frame {
        // AXIOM-14 Cycle 5: re-sync `physical` to real wall-clock before
        // ticking. `ClockManager::new()` seeds `physical` ONCE, at
        // construction, via `HybridClock::now()`; `tick()` only bumps the
        // logical counter, it never re-reads wall-clock. Without this
        // call, a long-uptime node's `origin_clock.physical` stays frozen
        // at whatever it was when this `AnnouncementManager` was first
        // constructed - hours stale on a real deployment - which would
        // make the receive-side `MAX_ANNOUNCE_CLOCK_SKEW` check below
        // reject the node's own genuine announces. `sync_physical()` is
        // forward-only and resets `logical` to 0 on advance, preserving
        // HLC monotonicity.
        self.clock.sync_physical();
        let clock = self.clock.tick();
        let node_id = self.identity.node_id();

        let header = FrameHeader::new(FrameType::Announce, node_id.clone())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(clock.clone());

        let mut payload = AnnouncePayload::new(ttl.min(MAX_ANNOUNCE_TTL))
            .with_origin(node_id, clock);
        for cap in &self.local_capabilities {
            payload.add_capability(cap.clone());
        }

        let signing_bytes = payload.origin_signing_bytes()
            .expect("origin/origin_clock were just set above by with_origin");
        let origin_signature = self.identity.sign(&signing_bytes);
        payload = payload.with_origin_signature(origin_signature);

        Frame::new(header, PayloadType::Raw, payload.encode())
    }

    /// Process an incoming announcement - handles both a direct announce
    /// (from a peer announcing its own capabilities) and a gossip-forwarded
    /// one (a relay passing along someone else's announcement, AXIOM-14
    /// Cycle 2) via the same code path, since `origin`/`origin_clock`
    /// collapse to the announcer's own identity/clock for a direct
    /// announce anyway. Returns `Some((capabilities, forward_frame))` -
    /// `capabilities` is the announcement's FULL current set (for
    /// full-replacement registration - see `network.rs`'s `Announce` arm),
    /// `forward_frame` is `Some` iff there's anything worth re-gossiping to
    /// other peers.
    ///
    /// AXIOM-14 Cycle 4 (Fable full-repo review, the highest-severity
    /// finding of the whole review): before this cycle, `origin`/
    /// `origin_clock` were trusted from ANY known peer with no proof they
    /// actually came from the claimed origin. A relay could claim an
    /// arbitrary `origin` and this function would act on it with full
    /// authority - `unregister_node(&origin)` (in `network.rs`'s caller)
    /// would wipe the real origin's entire registry, and a fabricated
    /// max-value `origin_clock` would permanently poison the dedup entry
    /// below so the real origin's future legitimate announces were
    /// silently suppressed forever. Now: an announce is REJECTED OUTRIGHT,
    /// before any other processing (admission bookkeeping in the caller,
    /// TTL clamping, dedup, all of it), unless `origin`, `origin_clock`,
    /// AND a valid `origin_signature` are all present and the signature
    /// verifies against `origin`'s own public key. This is a uniform rule,
    /// not a fallback ladder: the pre-Cycle-4 "39-byte, no signature" wire
    /// shape and the pre-Cycle-2a "0-byte, no origin at all" shape are
    /// BOTH rejected now, even though the 0-byte shape was arguably always
    /// safe (it implicitly claims sender_id as origin, which the outer
    /// frame signature already authenticates) - `create_announcement`
    /// hasn't emitted either shape since Cycle 2a/4 respectively, so one
    /// uniform rule costs nothing in practice and removes the entire
    /// origin-ambiguity class from this function.
    pub fn process_announcement(
        &mut self,
        frame: &Frame,
    ) -> Option<(Vec<AnnouncedCapability>, Option<Frame>)> {
        let payload = AnnouncePayload::decode(&frame.payload)?;

        let (Some(origin), Some(origin_clock), Some(origin_signature)) =
            (payload.origin.clone(), payload.origin_clock.clone(), payload.origin_signature.clone())
        else {
            return None;
        };

        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin, &origin_clock, &payload.capabilities);
        if !origin.verify(&signing_bytes, &origin_signature) {
            return None;
        }

        // AXIOM-14 Cycle 5: bound how far the origin's claimed clock may
        // diverge from real wall-clock time, in EITHER direction - see
        // `MAX_ANNOUNCE_CLOCK_SKEW`'s doc comment for the replay hazard
        // this closes. Computed against `HybridClock::now()` (real
        // wall-clock), deliberately NOT `self.clock.current()` - the
        // receiver's own `ClockManager` has the exact same frozen-physical
        // problem `create_announcement` fixes for the sender side via
        // `sync_physical()`, and using it here would just move the bug
        // rather than close it. `abs_diff` handles the unsigned
        // subtraction safely in either direction (no underflow panic).
        let now = HybridClock::now();
        if now.physical.abs_diff(origin_clock.physical) > MAX_ANNOUNCE_CLOCK_SKEW.as_secs() {
            return None;
        }

        // Clamp to what routing can actually reach, not the protocol's raw
        // ceiling - see `MAX_ACCEPTED_ANNOUNCE_TTL`'s doc comment. Done
        // AFTER verification (nothing about a rejected frame's TTL
        // matters) but before everything else (an accepted frame's TTL
        // must be clamped before it's used to decide whether/how far to
        // forward).
        let mut payload = payload;
        payload.ttl = payload.ttl.min(MAX_ACCEPTED_ANNOUNCE_TTL);

        // Our own announcement, gossiped back to us through some path -
        // never register or re-forward it.
        if origin == self.identity.node_id() {
            return None;
        }

        // Dedup keyed on the STABLE origin+clock, not sender_id/header.clock
        // (which get rebound to the relay's own identity/clock on every
        // hop - see the doc comments above for why that made dedup vacuous
        // in any topology with a cycle). Strictly-newer-only: an EQUAL
        // clock (the same announcement arriving again via a second path)
        // must NOT count as fresh, or dedup only slows a loop by one clock
        // tick per lap instead of actually stopping it.
        let mut any_fresh = false;
        for cap in &payload.capabilities {
            let key = (origin.clone(), cap.intent_hash);
            match self.seen.entry(key) {
                hashbrown::hash_map::Entry::Occupied(mut e) => {
                    // AXIOM-14 Cycle 3 (Fable diff review, required):
                    // refresh on EVERY touch, not just a strictly-newer
                    // one - `cleanup_stale` now actually evicts entries
                    // past ANNOUNCEMENT_MAX_AGE (previously nothing ever
                    // pruned `seen`, so this field's age was moot). An
                    // actively-alive route that keeps getting legitimately
                    // re-announced (repeat handshakes, same origin/intent)
                    // must stay "recently seen" so it never goes stale
                    // mid-use - if it did, a captured OLD signed frame
                    // (stale clock) replayed into that gap would land on a
                    // Vacant entry with nothing to compare against and get
                    // treated as fresh again. A duplicate/stale touch still
                    // proves the route is alive even though its clock
                    // didn't advance, so it refreshes too, not just the
                    // strictly-newer branch. Cycle 4: this refresh is now
                    // only ever reachable with a VERIFIED origin, so the
                    // "poison via forged max-clock" version of this hazard
                    // is closed at the door above, not by this refresh.
                    e.get_mut().first_seen = std::time::Instant::now();
                    if e.get().clock.happens_before(&origin_clock) {
                        e.get_mut().clock = origin_clock.clone();
                        e.get_mut().count += 1;
                        any_fresh = true;
                    }
                    // else: not strictly newer - stale or exact duplicate,
                    // suppress (this IS the loop-suppression case).
                }
                hashbrown::hash_map::Entry::Vacant(e) => {
                    e.insert(SeenAnnouncement {
                        first_seen: std::time::Instant::now(),
                        clock: origin_clock.clone(),
                        count: 1,
                    });
                    any_fresh = true;
                }
            }
        }

        if !any_fresh {
            return None;
        }

        // Create forwarded frame if TTL > 0. Forwards the FULL capability
        // list from this frame (not just the subset that happened to be
        // "new" from this node's own dedup-state perspective) - a partial
        // forward would corrupt the full-set-replacement registration
        // semantics downstream (`unregister_node(origin)` then re-register
        // everything in the frame - see `network.rs`'s `Announce` arm),
        // silently dropping capabilities the downstream node should still
        // know the origin has. `origin_signature` is carried through
        // BYTE-FOR-BYTE, unmodified - this relay does not have the
        // origin's private key and must never attempt to re-sign; the
        // whole point of Cycle 4 is that only the origin's own signature
        // ever proves this claim.
        let forward_frame = if payload.ttl > 0 {
            let mut fwd_payload = AnnouncePayload::new(payload.ttl - 1)
                .with_origin(origin.clone(), origin_clock.clone())
                .with_origin_signature(origin_signature.clone());
            for cap in &payload.capabilities {
                fwd_payload.add_capability(cap.clone());
            }

            // Update OUR OWN clock from the incoming frame's header clock
            // (standard causal-clock hygiene, keeps our future ticks
            // ordered after anything we've observed) - unrelated to the
            // origin_clock dedup logic above, which never touches
            // self.clock at all.
            //
            // AXIOM-14 Cycle 5 (Fable diff review, required): bounded by
            // the same skew window as origin_clock above, NOT fed
            // unconditionally. header.clock is relay-controlled and was
            // never bounded before this cycle - harmless while nothing
            // read self.clock.physical for a security decision, but the
            // new skew check above changed that: HLC update() takes the
            // max of the two clocks, so ONE Announce with a far-future
            // header.clock would permanently jump this node's own
            // ClockManager.physical forward - sync_physical() is
            // forward-only and can never recover it. Every announce THIS
            // node creates afterward would then fail every OTHER node's
            // skew check forever, and the poisoned value keeps
            // propagating hop to hop through this same update() call on
            // every node downstream. Skipping the update on an
            // out-of-skew header.clock is safe - it only affects causal
            // ordering hygiene, never the dedup/replay logic above.
            if now.physical.abs_diff(frame.header.clock.physical) <= MAX_ANNOUNCE_CLOCK_SKEW.as_secs() {
                self.clock.update(&frame.header.clock);
            }
            let clock = self.clock.tick();

            // header.sender_id/header.clock here are OUR identity/clock as
            // the physical relay of this specific copy - meaningful for
            // the receiving peer's known_peers/channel-binding checks at
            // that hop, NOT the announcement's logical identity (that's
            // origin/origin_clock/origin_signature inside the payload,
            // preserved above).
            let header = FrameHeader::new(FrameType::Announce, self.identity.node_id())
                .with_trust_level(frame.header.trust_level)
                .with_clock(clock);

            Some(Frame::new(header, PayloadType::Raw, fwd_payload.encode()))
        } else {
            None
        };

        Some((payload.capabilities.clone(), forward_frame))
    }

    /// Clean up old seen entries
    pub fn cleanup_stale(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.seen.retain(|_, v| now.duration_since(v.first_seen) < max_age);
    }

    /// Get our local capabilities
    pub fn local_capabilities(&self) -> &[AnnouncedCapability] {
        &self.local_capabilities
    }

    /// Update metrics for a local capability
    pub fn update_capability_metrics(&mut self, intent_hash: &IntentHash, load: u8, latency_ms: u16) {
        if let Some(cap) = self.local_capabilities.iter_mut().find(|c| &c.intent_hash == intent_hash) {
            cap.load = load;
            cap.latency_ms = latency_ms;
        }
    }

    /// Get number of seen announcements
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }
}

/// Scheduler for periodic announcements
#[cfg(feature = "std")]
pub struct AnnouncementScheduler {
    /// Interval between announcements (milliseconds)
    announce_interval_ms: u64,
    /// Last announcement time
    last_announce: Option<std::time::Instant>,
    /// Jitter range (milliseconds) to prevent thundering herd
    jitter_ms: u64,
    /// RNG state for jitter
    rng_state: u64,
}

#[cfg(feature = "std")]
impl AnnouncementScheduler {
    pub fn new(interval_ms: u64, jitter_ms: u64) -> Self {
        Self {
            announce_interval_ms: interval_ms,
            last_announce: None,
            jitter_ms,
            rng_state: 0xDEADBEEF,
        }
    }

    /// Check if it's time to announce
    pub fn should_announce(&self) -> bool {
        match self.last_announce {
            None => true,
            Some(last) => {
                let elapsed = last.elapsed().as_millis() as u64;
                elapsed >= self.announce_interval_ms
            }
        }
    }

    /// Record that we announced
    pub fn record_announce(&mut self) {
        self.last_announce = Some(std::time::Instant::now());
    }

    /// Get time until next announce (milliseconds)
    pub fn time_until_next(&self) -> u64 {
        match self.last_announce {
            None => 0,
            Some(last) => {
                let elapsed = last.elapsed().as_millis() as u64;
                if elapsed >= self.announce_interval_ms {
                    0
                } else {
                    self.announce_interval_ms - elapsed
                }
            }
        }
    }

    /// Get interval with jitter for next announcement
    pub fn next_interval_with_jitter(&mut self) -> u64 {
        if self.jitter_ms == 0 {
            return self.announce_interval_ms;
        }

        // Simple xorshift for jitter
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;

        let jitter = (self.rng_state % (self.jitter_ms * 2)) as i64 - self.jitter_ms as i64;
        (self.announce_interval_ms as i64 + jitter).max(100) as u64
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct AnnouncementManager;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    #[test]
    fn test_announced_capability_roundtrip() {
        let cap = AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0")
            .with_load(64)
            .with_latency(25);

        let encoded = cap.encode();
        assert_eq!(encoded.len(), 23);

        let decoded = AnnouncedCapability::decode(&encoded).unwrap();
        assert_eq!(decoded.intent_hash, test_intent_hash(0xAB));
        assert_eq!(decoded.category, *b"llm\0");
        assert_eq!(decoded.load, 64);
        assert_eq!(decoded.latency_ms, 25);
    }

    #[test]
    fn test_announce_payload_roundtrip() {
        let mut payload = AnnouncePayload::new(8);
        payload.add_capability(
            AnnouncedCapability::new(test_intent_hash(1), *b"llm\0")
                .with_load(50),
        );
        payload.add_capability(
            AnnouncedCapability::new(test_intent_hash(2), *b"embd")
                .with_load(100),
        );

        let encoded = payload.encode();
        let decoded = AnnouncePayload::decode(&encoded).unwrap();

        assert_eq!(decoded.ttl, 8);
        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.capabilities[0].intent_hash, test_intent_hash(1));
        assert_eq!(decoded.capabilities[1].intent_hash, test_intent_hash(2));
        // No origin attached - decode must not synthesize one out of thin
        // air, and must not produce a partial/corrupt trailing field.
        assert!(decoded.origin.is_none());
        assert!(decoded.origin_clock.is_none());
        assert!(decoded.origin_signature.is_none());
    }

    /// AXIOM-14 Cycle 2a/4: origin/origin_clock/origin_signature survive
    /// the wire round-trip unmodified.
    #[test]
    fn test_announce_payload_origin_roundtrip() {
        let origin = axiom_types::crypto::NodeId::from_bytes([0x77; 32]);
        let origin_clock = HybridClock::new(1_700_000_000, 42);
        let sig = Signature::from_bytes([0x99; SIGNATURE_SIZE]);

        let mut payload = AnnouncePayload::new(5)
            .with_origin(origin.clone(), origin_clock.clone())
            .with_origin_signature(sig);
        payload.add_capability(AnnouncedCapability::new(test_intent_hash(9), *b"llm\0"));

        let encoded = payload.encode();
        let decoded = AnnouncePayload::decode(&encoded).unwrap();

        assert_eq!(decoded.origin.unwrap().as_bytes(), origin.as_bytes());
        let decoded_clock = decoded.origin_clock.unwrap();
        assert_eq!(decoded_clock.physical, origin_clock.physical);
        assert_eq!(decoded_clock.logical, origin_clock.logical);
        assert_eq!(decoded.origin_signature.unwrap().as_bytes(), &[0x99; SIGNATURE_SIZE]);
    }

    /// Deployment-history proof, same rigor as Cycle 1a's frame-header
    /// byte-compat test: a payload encoded the OLDEST way (no origin field
    /// at all - simulating a payload from a node that predates Cycle 2a)
    /// still decodes cleanly at the PARSER level, with all three fields
    /// `None`. `decode()` itself stays a pure structural parser - it does
    /// NOT enforce the Cycle 4 signed-origin security policy; that lives
    /// in `process_announcement`, which (per its own tests below) now
    /// rejects this exact shape outright rather than falling back to
    /// `sender_id`.
    #[test]
    fn test_announce_payload_decodes_pre_cycle2a_bytes() {
        // Hand-built exactly as the OLDEST encode() would have produced:
        // [ttl][cap_count: 2][capabilities...], nothing more.
        let cap = AnnouncedCapability::new(test_intent_hash(3), *b"embd").with_load(10);
        let mut old_format = Vec::new();
        old_format.push(6u8); // ttl
        old_format.extend_from_slice(&1u16.to_be_bytes()); // cap_count
        old_format.extend_from_slice(&cap.encode());

        let decoded = AnnouncePayload::decode(&old_format).unwrap();
        assert_eq!(decoded.ttl, 6);
        assert_eq!(decoded.capabilities.len(), 1);
        assert!(decoded.origin.is_none());
        assert!(decoded.origin_clock.is_none());
        assert!(decoded.origin_signature.is_none());
    }

    /// The Cycle 2a/2b/3 wire shape (origin + origin_clock, no signature -
    /// what every already-deployed node emitted before Cycle 4) also still
    /// decodes cleanly at the PARSER level. Cycle 4's `process_announcement`
    /// test below (`test_process_announcement_rejects_unsigned_origin`)
    /// proves the SECURITY layer rejects it; this test proves the parser
    /// layer doesn't conflate it with either the 0-byte or 103-byte shape.
    #[test]
    fn test_announce_payload_decodes_cycle2a_unsigned_origin_bytes() {
        let cap = AnnouncedCapability::new(test_intent_hash(4), *b"embd").with_load(20);
        let origin = axiom_types::crypto::NodeId::from_bytes([0x55; 32]);
        let origin_clock = HybridClock::new(1_700_000_001, 7);

        let mut old_format = Vec::new();
        old_format.push(3u8); // ttl
        old_format.extend_from_slice(&1u16.to_be_bytes()); // cap_count
        old_format.extend_from_slice(&cap.encode());
        old_format.extend_from_slice(origin.as_bytes());
        old_format.extend_from_slice(&origin_clock.to_bytes());

        let decoded = AnnouncePayload::decode(&old_format).unwrap();
        assert_eq!(decoded.ttl, 3);
        assert_eq!(decoded.capabilities.len(), 1);
        assert_eq!(decoded.origin.unwrap().as_bytes(), origin.as_bytes());
        assert!(decoded.origin_clock.is_some());
        assert!(decoded.origin_signature.is_none(), "the pre-Cycle-4 wire shape has no signature to decode");
    }

    #[test]
    fn test_ttl_decrement() {
        let mut payload = AnnouncePayload::new(3);

        assert!(payload.decrement_ttl());
        assert_eq!(payload.ttl, 2);

        assert!(payload.decrement_ttl());
        assert!(payload.decrement_ttl());
        assert_eq!(payload.ttl, 0);

        // Can't decrement below 0
        assert!(!payload.decrement_ttl());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_announcement_manager() {
        let identity = Keypair::generate();
        let mut manager = AnnouncementManager::new(identity.clone());

        // Register capability
        let cap = AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0");
        manager.register_capability(cap);

        assert_eq!(manager.local_capabilities().len(), 1);

        // Create announcement
        let frame = manager.create_announcement(8);
        assert_eq!(frame.header.frame_type, FrameType::Announce);

        let payload = AnnouncePayload::decode(&frame.payload).unwrap();
        assert_eq!(payload.ttl, 8);
        assert_eq!(payload.capabilities.len(), 1);
        assert_eq!(payload.origin.unwrap().as_bytes(), identity.node_id().as_bytes());
        assert!(payload.origin_signature.is_some(), "create_announcement must sign the origin claim");
    }

    /// AXIOM-14 Cycle 4's actual point: `create_announcement`'s own output
    /// must verify against the origin it claims - proves the signing
    /// bytes/signature/verify triangle is internally consistent, not just
    /// that a signature exists.
    #[cfg(feature = "std")]
    #[test]
    fn test_created_announcement_origin_signature_verifies() {
        let identity = Keypair::generate();
        let node_id = identity.node_id();
        let mut manager = AnnouncementManager::new(identity);
        manager.register_capability(AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0"));

        let frame = manager.create_announcement(1);
        let payload = AnnouncePayload::decode(&frame.payload).unwrap();

        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(
            &payload.origin.clone().unwrap(),
            &payload.origin_clock.clone().unwrap(),
            &payload.capabilities,
        );
        assert!(node_id.verify(&signing_bytes, &payload.origin_signature.unwrap()));
    }

    #[cfg(feature = "std")]
    fn build_gossip_frame(
        sender: axiom_types::crypto::NodeId,
        origin: axiom_types::crypto::NodeId,
        origin_clock: HybridClock,
        origin_signature: Option<Signature>,
    ) -> Frame {
        // Simulates a frame as it would arrive at a relay/destination:
        // header.sender_id is the PHYSICAL immediate sender (may differ
        // from origin, e.g. a relay forwarding someone else's
        // announcement), origin/origin_clock/origin_signature inside the
        // payload are the announcement's stable logical identity/proof.
        let header = FrameHeader::new(FrameType::Announce, sender)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(999, 1)); // relay's own clock - must NOT affect dedup
        let mut payload = AnnouncePayload::new(8).with_origin(origin, origin_clock);
        if let Some(sig) = origin_signature {
            payload = payload.with_origin_signature(sig);
        }
        payload.add_capability(AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0"));
        Frame::new(header, PayloadType::Raw, payload.encode())
    }

    /// Builds a REAL origin keypair and signs a gossip frame the way
    /// `create_announcement` would, but via `build_gossip_frame` so the
    /// test can control `sender`/relay independently of `origin` (exactly
    /// the relayed-through-a-third-party shape gossip needs to exercise).
    #[cfg(feature = "std")]
    fn build_signed_gossip_frame(
        sender: axiom_types::crypto::NodeId,
        origin_identity: &Keypair,
        origin_clock: HybridClock,
        capabilities: &[AnnouncedCapability],
    ) -> Frame {
        let origin = origin_identity.node_id();
        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin, &origin_clock, capabilities);
        let sig = origin_identity.sign(&signing_bytes);

        let header = FrameHeader::new(FrameType::Announce, sender)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(999, 1));
        let mut payload = AnnouncePayload::new(8)
            .with_origin(origin, origin_clock)
            .with_origin_signature(sig);
        for cap in capabilities {
            payload.add_capability(cap.clone());
        }
        Frame::new(header, PayloadType::Raw, payload.encode())
    }

    /// AXIOM-14 Cycle 4's regression test for the actual vulnerability:
    /// a forged origin claim (no signature at all) must be rejected
    /// outright, and critically must NOT poison the dedup entry for that
    /// (origin, intent_hash) - proven by confirming the REAL origin's
    /// subsequent genuine announcement still succeeds afterward.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_and_does_not_poison_forged_origin() {
        let relay_m = axiom_types::crypto::NodeId::from_bytes([0xAA; 32]);
        let real_origin_identity = Keypair::generate();
        let real_origin = real_origin_identity.node_id();

        let mut manager = AnnouncementManager::new(Keypair::generate());

        // Attacker M, a known peer, sends an unsigned forged claim: origin
        // = the real origin, with a maxed-out clock designed to poison the
        // dedup entry so the real origin's future announces are
        // suppressed.
        let poison_clock = HybridClock::new(u64::MAX >> 24, u16::MAX); // max representable 40-bit physical
        let forged = build_gossip_frame(relay_m.clone(), real_origin.clone(), poison_clock, None);
        assert!(
            manager.process_announcement(&forged).is_none(),
            "an origin claim with no signature at all must be rejected outright"
        );
        assert_eq!(manager.seen_count(), 0, "a rejected forged announce must not create ANY dedup entry");

        // The real origin now sends its own genuine, properly signed
        // announcement (a lower, honest clock value) via the same relay.
        // If the forged claim above had poisoned the dedup entry, this
        // would be spuriously suppressed as "not strictly newer." Uses a
        // wall-clock-relative timestamp (AXIOM-14 Cycle 5's clock-skew
        // check rejects a hardcoded stale timestamp outright, which would
        // mask this test's actual point - poison-resistance, not clock
        // freshness).
        let genuine_clock = HybridClock::new(HybridClock::now().physical, 1);
        let real_caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];
        let genuine = build_signed_gossip_frame(relay_m, &real_origin_identity, genuine_clock, &real_caps);
        let result = manager.process_announcement(&genuine);
        assert!(result.is_some(), "the real origin's genuine, signed announcement must succeed - it must not have been poisoned by the earlier forged/unsigned one");
    }

    /// The pre-Cycle-4 wire shape (origin + origin_clock, no signature -
    /// exactly what both live nodes emitted before this cycle) must also
    /// be rejected now, not silently trusted as before.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_unsigned_origin() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let origin = axiom_types::crypto::NodeId::from_bytes([0xDD; 32]);

        let unsigned = build_gossip_frame(relay, origin, HybridClock::new(1_700_000_000, 1), None);
        assert!(manager.process_announcement(&unsigned).is_none());
    }

    /// A signature that doesn't actually verify against the claimed origin
    /// (wrong key signed it, or the payload was tampered with after
    /// signing) must be rejected - proves verification is a real check,
    /// not just "is this field present."
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_invalid_signature() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let real_origin_identity = Keypair::generate();
        let wrong_identity = Keypair::generate(); // signs, but isn't the claimed origin

        let origin_clock = HybridClock::new(1_700_000_000, 1);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];
        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&real_origin_identity.node_id(), &origin_clock, &caps);
        let wrong_sig = wrong_identity.sign(&signing_bytes); // valid signature, WRONG key

        let header = FrameHeader::new(FrameType::Announce, relay)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(999, 1));
        let mut payload = AnnouncePayload::new(8)
            .with_origin(real_origin_identity.node_id(), origin_clock)
            .with_origin_signature(wrong_sig);
        payload.add_capability(caps[0].clone());
        let frame = Frame::new(header, PayloadType::Raw, payload.encode());

        assert!(manager.process_announcement(&frame).is_none());
    }

    /// A relay tampering with a capability after the origin signed it
    /// (e.g. inflating its own load/latency claim, or swapping in a
    /// different intent_hash) must be caught - the signature covers the
    /// exact capability set, not just the origin/clock.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_tampered_capability() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let origin_identity = Keypair::generate();
        let origin_clock = HybridClock::new(1_700_000_000, 1);
        let original_caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0").with_load(10)];

        let mut frame = build_signed_gossip_frame(relay, &origin_identity, origin_clock, &original_caps);

        // Relay tampers: re-decode, change the load, re-encode - simulates
        // a compromised or buggy relay mutating the payload in flight
        // without access to the origin's private key.
        let mut payload = AnnouncePayload::decode(&frame.payload).unwrap();
        payload.capabilities[0].load = 255;
        frame.payload = payload.encode();

        assert!(manager.process_announcement(&frame).is_none(), "a tampered capability must invalidate the origin signature");
    }

    /// Two-hop forward: the origin_signature set by the ORIGIN must
    /// survive a relay's forward unmodified (not re-derived, not dropped),
    /// and the second hop's `process_announcement` must still verify it
    /// successfully against the same signing bytes.
    #[cfg(feature = "std")]
    #[test]
    fn test_origin_signature_survives_two_hop_forward() {
        let origin_identity = Keypair::generate();
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];
        // Wall-clock-relative (AXIOM-14 Cycle 5): a hardcoded stale
        // timestamp would now be rejected by the clock-skew check before
        // this test ever reaches the two-hop-forward behavior it exists
        // to exercise.
        let origin_clock = HybridClock::new(HybridClock::now().physical, 1);

        // Hop 1: B receives directly from the origin.
        let mut mgr_b = AnnouncementManager::new(Keypair::generate());
        let frame_to_b = build_signed_gossip_frame(origin_identity.node_id(), &origin_identity, origin_clock.clone(), &caps);
        let (_, forward) = mgr_b.process_announcement(&frame_to_b).expect("B must accept the origin's genuine announcement");
        let frame_from_b = forward.expect("TTL was 8, must still be forwardable");

        // Hop 2: C receives the frame B forwarded, physically sent by B
        // (not the origin) - this is the actual relayed shape.
        let mut mgr_c = AnnouncementManager::new(Keypair::generate());
        let result_c = mgr_c.process_announcement(&frame_from_b);
        assert!(result_c.is_some(), "C must accept B's forward - the origin_signature must have survived the hop unmodified and still verify");
        let (caps_at_c, _) = result_c.unwrap();
        assert_eq!(caps_at_c.len(), 1);
        assert_eq!(caps_at_c[0].intent_hash, test_intent_hash(0xCD));
    }

    /// AXIOM-14 Cycle 4 (Fable plan review, required): a peer claiming
    /// ttl=16 (the raw protocol ceiling) must still only ever be
    /// forwarded ONE hop, matching what routing can actually serve -
    /// proves the receive-side clamp works, not just the send-side one
    /// Cycle 2b already fixed.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_clamps_received_ttl() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let origin_identity = Keypair::generate();
        // Wall-clock-relative (AXIOM-14 Cycle 5): this test's point is the
        // receive-side TTL clamp, not clock freshness - a hardcoded stale
        // timestamp would be rejected by the clock-skew check first.
        let origin_clock = HybridClock::new(HybridClock::now().physical, 1);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin_identity.node_id(), &origin_clock, &caps);
        let sig = origin_identity.sign(&signing_bytes);
        let header = FrameHeader::new(FrameType::Announce, relay)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(999, 1));
        let mut payload = AnnouncePayload::new(MAX_ANNOUNCE_TTL) // claims the raw ceiling, not 1
            .with_origin(origin_identity.node_id(), origin_clock)
            .with_origin_signature(sig);
        payload.add_capability(caps[0].clone());
        let frame = Frame::new(header, PayloadType::Raw, payload.encode());

        let (_, forward) = manager.process_announcement(&frame).unwrap();
        let forwarded_frame = forward.expect("TTL was well above 0 before clamping, must still forward once");
        let forwarded_payload = AnnouncePayload::decode(&forwarded_frame.payload).unwrap();
        assert_eq!(
            forwarded_payload.ttl, MAX_ACCEPTED_ANNOUNCE_TTL - 1,
            "receive-side clamp must cap accepted TTL to MAX_ACCEPTED_ANNOUNCE_TTL ({}), decremented once for this forward, regardless of the 16 the sender claimed",
            MAX_ACCEPTED_ANNOUNCE_TTL
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_gossip_dedup_keys_on_stable_origin_not_relay() {
        let origin_identity = Keypair::generate();
        let relay_b = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let relay_e = axiom_types::crypto::NodeId::from_bytes([0xE0; 32]);
        // Wall-clock-relative (AXIOM-14 Cycle 5): this test's point is
        // dedup keying on stable origin, not clock freshness.
        let origin_clock = HybridClock::new(HybridClock::now().physical, 5);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let mut manager = AnnouncementManager::new(Keypair::generate());

        // First arrival, via relay B - genuinely new, must forward.
        let frame_via_b = build_signed_gossip_frame(relay_b, &origin_identity, origin_clock.clone(), &caps);
        let result_b = manager.process_announcement(&frame_via_b);
        assert!(result_b.is_some(), "first arrival of a real announcement must be accepted");
        let (_, forward_b) = result_b.unwrap();
        assert!(forward_b.is_some(), "genuinely new announcement must be forwarded");

        // Fable's Cycle 2a diff review: decode the actual forward frame's
        // payload, don't just check Some/None - a regression to
        // filtered-subset forwarding, or to re-deriving origin from the
        // relay's own header instead of carrying it through unmodified,
        // would pass every other test in this file.
        let fwd_frame = forward_b.unwrap();
        let fwd_payload = AnnouncePayload::decode(&fwd_frame.payload).unwrap();
        assert_eq!(fwd_payload.origin.unwrap().as_bytes(), origin_identity.node_id().as_bytes(), "origin must survive the forward unmodified, not become the relay's own ID");
        let fwd_clock = fwd_payload.origin_clock.unwrap();
        assert_eq!(fwd_clock.physical, origin_clock.physical, "origin_clock must survive the forward unmodified");
        assert_eq!(fwd_clock.logical, origin_clock.logical);
        assert_eq!(fwd_payload.capabilities.len(), 1, "forward must carry the FULL received capability set");
        assert_eq!(fwd_payload.capabilities[0].intent_hash, test_intent_hash(0xCD));
        assert_eq!(
            fwd_payload.ttl, MAX_ACCEPTED_ANNOUNCE_TTL - 1,
            "Cycle 4/6 receive-side clamp: accepted TTL is capped to MAX_ACCEPTED_ANNOUNCE_TTL ({}) regardless of what the sender's build_signed_gossip_frame claimed (8), then decremented once for this forward",
            MAX_ACCEPTED_ANNOUNCE_TTL
        );

        // SAME origin, SAME origin_clock, arriving again via a DIFFERENT
        // relay (E, not B) - this is the loop/duplicate-delivery case.
        // Different sender_id, different header.clock (build_signed_gossip_frame
        // always stamps a fresh relay clock) - if dedup were still keyed
        // on those, this would look brand new. It must not.
        let frame_via_e = build_signed_gossip_frame(relay_e, &origin_identity, origin_clock, &caps);
        let result_e = manager.process_announcement(&frame_via_e);
        assert!(result_e.is_none(), "identical origin+origin_clock via a second path must be suppressed, not re-forwarded");
    }

    /// A STRICTLY NEWER origin_clock for the same origin (the origin
    /// re-announced, e.g. after a new handshake) must still propagate -
    /// the fix must not overcorrect into suppressing genuine updates.
    #[cfg(feature = "std")]
    #[test]
    fn test_gossip_dedup_allows_strictly_newer_origin_clock() {
        let origin_identity = Keypair::generate();
        let relay_b = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let mut manager = AnnouncementManager::new(Keypair::generate());

        // Wall-clock-relative (AXIOM-14 Cycle 5): same physical second for
        // both, so the clock-skew check treats them identically - only
        // the logical counter differs, which is exactly the
        // strictly-newer comparison this test exercises.
        let now_physical = HybridClock::now().physical;
        let older = HybridClock::new(now_physical, 1);
        let newer = HybridClock::new(now_physical, 2);

        let first = build_signed_gossip_frame(relay_b.clone(), &origin_identity, older, &caps);
        assert!(manager.process_announcement(&first).is_some());

        let second = build_signed_gossip_frame(relay_b, &origin_identity, newer, &caps);
        let result = manager.process_announcement(&second);
        assert!(result.is_some(), "a strictly newer origin_clock for the same origin must still be accepted");
        assert!(result.unwrap().1.is_some(), "and still forwarded");
    }

    /// Our own announcement, gossiped back to us through some relay chain,
    /// must never be re-registered or re-forwarded.
    #[cfg(feature = "std")]
    #[test]
    fn test_gossip_rejects_own_announcement_echoed_back() {
        let my_identity = Keypair::generate();
        let relay_b = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let mut manager = AnnouncementManager::new(my_identity.clone());
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        // Wall-clock-relative (AXIOM-14 Cycle 5): this test's point is the
        // self-origin echo rejection specifically - a hardcoded stale
        // timestamp would make this pass for the wrong reason (clock-skew
        // rejection) even if the self-origin check itself regressed.
        let echoed = build_signed_gossip_frame(relay_b, &my_identity, HybridClock::new(HybridClock::now().physical, 1), &caps);
        assert!(manager.process_announcement(&echoed).is_none(), "must never process our own announcement echoed back to us");
    }

    /// AXIOM-14 Cycle 5: a genuinely signed origin claim whose
    /// `origin_clock.physical` is far in the PAST (simulating a captured
    /// frame recorded long ago and replayed now, after the original
    /// dedup entry would have aged out of `seen` via `cleanup_stale`)
    /// must be rejected outright, even though the signature itself is
    /// perfectly valid - this is the actual vulnerability the clock-skew
    /// check closes: stale-data replay, not spoofing.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_clock_far_in_past() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let origin_identity = Keypair::generate();
        let now = HybridClock::now();
        let stale_clock = HybridClock::new(now.physical.saturating_sub(3600), 0);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let frame = build_signed_gossip_frame(relay, &origin_identity, stale_clock, &caps);
        assert!(
            manager.process_announcement(&frame).is_none(),
            "an origin_clock over an hour in the past must be rejected as a stale-data replay"
        );
    }

    /// Same hazard, opposite direction: a claimed clock far in the FUTURE
    /// must also be rejected - otherwise an attacker could pre-date a
    /// forged-but-signed claim to always win the strictly-newer-only
    /// dedup polarity in `process_announcement`.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_rejects_clock_far_in_future() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xB0; 32]);
        let origin_identity = Keypair::generate();
        let now = HybridClock::now();
        let future_clock = HybridClock::new(now.physical + 3600, 0);
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let frame = build_signed_gossip_frame(relay, &origin_identity, future_clock, &caps);
        assert!(
            manager.process_announcement(&frame).is_none(),
            "an origin_clock over an hour in the future must be rejected"
        );
    }

    /// Regression guard: a normal, freshly-built Announce (via the real
    /// `create_announcement`/`AnnouncementManager::new()` path, not
    /// hand-built) must still succeed - the clock-skew check must not
    /// reject genuine, current traffic.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_accepts_freshly_created_announcement() {
        let origin_identity = Keypair::generate();
        let mut origin_mgr = AnnouncementManager::new(origin_identity);
        origin_mgr.register_capability(AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0"));
        let frame = origin_mgr.create_announcement(1);

        let mut receiver = AnnouncementManager::new(Keypair::generate());
        assert!(
            receiver.process_announcement(&frame).is_some(),
            "a normal freshly-built announcement must still be accepted"
        );
    }

    /// AXIOM-14 Cycle 5's regression test for the frozen-clock bug fix
    /// specifically: `test_process_announcement_accepts_freshly_created_announcement`
    /// above would NOT catch a regression here, since a freshly-constructed
    /// `AnnouncementManager::new()` has a just-seeded clock either way.
    /// Instead, build the manager via a direct struct literal (its fields
    /// are private, but this test module is inside the same module tree
    /// and can construct it directly) with `clock` pre-seeded to a
    /// deliberately OLD `HybridClock` - simulating a real long-uptime node
    /// whose `ClockManager` was constructed hours ago and never re-synced.
    /// If `create_announcement` didn't call `sync_physical()` (Step 1),
    /// the emitted `origin_clock.physical` would still reflect that old
    /// seed value, not real wall-clock-now.
    #[cfg(feature = "std")]
    #[test]
    fn test_create_announcement_resyncs_frozen_clock() {
        let identity = Keypair::generate();
        let now = HybridClock::now();
        let frozen_at_construction = now.physical.saturating_sub(7200); // 2 hours stale
        let mut manager = AnnouncementManager {
            identity,
            local_capabilities: Vec::new(),
            seen: hashbrown::HashMap::new(),
            clock: axiom_clock::ClockManager::with_clock(HybridClock::new(frozen_at_construction, 0)),
        };
        manager.register_capability(AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0"));

        let frame = manager.create_announcement(1);
        let payload = AnnouncePayload::decode(&frame.payload).unwrap();
        let origin_clock = payload.origin_clock.expect("create_announcement always sets origin_clock");

        let now_after = HybridClock::now();
        let skew = now_after.physical.abs_diff(origin_clock.physical);
        assert!(
            skew <= MAX_ANNOUNCE_CLOCK_SKEW.as_secs(),
            "create_announcement must call sync_physical() so origin_clock.physical reflects real wall-clock, not the frozen construction-time value 2 hours in the past (observed skew: {}s)",
            skew
        );
    }

    /// AXIOM-14 Cycle 5 (Fable diff review, required): the skew check on
    /// origin_clock alone isn't enough - process_announcement's forward
    /// path also feeds `frame.header.clock` (the RELAY's clock, not the
    /// origin's) into this node's own ClockManager via `update()`. HLC
    /// update() takes the max of the two clocks, so before this fix a
    /// single Announce with a far-future header.clock would permanently
    /// jump this node's own physical clock forward - `sync_physical()`
    /// is forward-only and can never recover it, so every announce THIS
    /// node creates afterward would fail every OTHER node's skew check
    /// forever (and the poisoned value keeps propagating hop to hop
    /// through the same mechanism on every downstream node). Proves the
    /// fix: a malicious header.clock is silently ignored for causal-clock
    /// purposes (the frame itself is still accepted normally - header.clock
    /// never gated acceptance, only origin_clock does), and this node's
    /// own subsequent create_announcement output stays within skew of
    /// real wall-clock.
    #[cfg(feature = "std")]
    #[test]
    fn test_process_announcement_ignores_poisoned_header_clock() {
        let mut manager = AnnouncementManager::new(Keypair::generate());
        let relay = axiom_types::crypto::NodeId::from_bytes([0xBB; 32]);
        let origin_identity = Keypair::generate();
        let fresh_origin_clock = HybridClock::now();
        let caps = [AnnouncedCapability::new(test_intent_hash(0xCD), *b"llm\0")];

        let signing_bytes = AnnouncePayload::origin_signing_bytes_for(&origin_identity.node_id(), &fresh_origin_clock, &caps);
        let sig = origin_identity.sign(&signing_bytes);

        // Malicious header.clock: far in the future. origin_clock itself is
        // fresh and correctly signed, so this frame passes every other
        // check - only header.clock is poisoned.
        let poisoned_header_clock = HybridClock::new(HybridClock::now().physical + 1_000_000, 0);
        let header = FrameHeader::new(FrameType::Announce, relay)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(poisoned_header_clock);
        let mut payload = AnnouncePayload::new(1)
            .with_origin(origin_identity.node_id(), fresh_origin_clock)
            .with_origin_signature(sig);
        payload.add_capability(caps[0].clone());
        let frame = Frame::new(header, PayloadType::Raw, payload.encode());

        let result = manager.process_announcement(&frame);
        assert!(result.is_some(), "a fresh, validly-signed origin claim must still be accepted regardless of the relay's own header.clock");

        // The actual regression proof: the manager's OWN clock must not
        // have been poisoned by the malicious header.clock - if it had,
        // create_announcement would now emit a far-future origin_clock
        // that fails every other node's skew check, forever (sync_physical
        // is forward-only and can't undo a future-poisoned value).
        manager.register_capability(AnnouncedCapability::new(test_intent_hash(0xEF), *b"llm\0"));
        let own_frame = manager.create_announcement(1);
        let own_payload = AnnouncePayload::decode(&own_frame.payload).unwrap();
        let own_clock = own_payload.origin_clock.expect("create_announcement always sets origin_clock");
        let skew = HybridClock::now().physical.abs_diff(own_clock.physical);
        assert!(
            skew <= MAX_ANNOUNCE_CLOCK_SKEW.as_secs(),
            "this node's own clock must not be poisoned by a relay's out-of-skew header.clock - observed skew after processing a poisoned frame: {}s",
            skew
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_update_capability_metrics() {
        let identity = Keypair::generate();
        let mut manager = AnnouncementManager::new(identity);

        let cap = AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0")
            .with_load(50)
            .with_latency(100);
        manager.register_capability(cap);

        // Update metrics
        manager.update_capability_metrics(&test_intent_hash(0xAB), 75, 150);

        let caps = manager.local_capabilities();
        assert_eq!(caps[0].load, 75);
        assert_eq!(caps[0].latency_ms, 150);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_announcement_scheduler() {
        let mut scheduler = AnnouncementScheduler::new(1000, 0); // 1 second, no jitter

        // Should announce immediately on first call
        assert!(scheduler.should_announce());
        assert_eq!(scheduler.time_until_next(), 0);

        // Record the announce
        scheduler.record_announce();

        // Should not announce immediately after
        assert!(!scheduler.should_announce());

        // Time until next should be approximately 1000ms
        let time_until = scheduler.time_until_next();
        assert!(time_until > 900 && time_until <= 1000);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_announcement_scheduler_jitter() {
        let mut scheduler = AnnouncementScheduler::new(1000, 100); // 1 second, 100ms jitter

        // Get several intervals with jitter
        let mut intervals = Vec::new();
        for _ in 0..10 {
            intervals.push(scheduler.next_interval_with_jitter());
        }

        // Should have some variation
        let min = *intervals.iter().min().unwrap();
        let max = *intervals.iter().max().unwrap();

        // All should be within jitter range
        for interval in &intervals {
            assert!(*interval >= 900 && *interval <= 1100);
        }

        // Should have some variation (not all the same)
        assert!(max > min, "Jitter should create variation");
    }
}
