//! WAN transport binding — connects Axiom nodes over the real internet via iroh
//! (dial-by-public-key QUIC with built-in NAT traversal + relay fallback).
//!
//! Design decision (2026-07-29, validated by Fable review): iroh was chosen over
//! a Cloudflare WARP-to-WARP approach because it requires no third-party account
//! for anyone else who runs this node, and its EndpointId IS an Ed25519 public
//! key — identical to Axiom's own NodeId — so there is no second identity system
//! to reconcile, unlike a hand-rolled QUIC+TLS integration would need.
//!
//! Per Fable's review, Cloudflare/tunnel "reachability" signals (or iroh's own
//! connection-established event) are NEVER treated as a trust/liveness signal by
//! themselves — only a freshly verified SignedPong flips a peer to "live" in any
//! trust-relevant logic. A transport-layer connection proves a QUIC handshake
//! succeeded; it does not prove the expected private key is still on the other
//! end right now.
//!
//! Second Fable pass (2026-07-29, against this actual code) found two blockers,
//! both fixed here: (1) the signed pong bytes had no domain-separation tag, so
//! a signature over some other Axiom message could in principle be replayed as
//! a pong, or vice versa, now or in a future protocol addition sharing this same
//! node key — fixed via PONG_SIGNING_CONTEXT; (2) every await in the liveness
//! exchange was unbounded, so an allowlisted-but-wedged peer could hang the
//! whole exchange forever — fixed via LIVENESS_EXCHANGE_TIMEOUT wrapping the
//! full post-handshake exchange on both sides.

use axiom_crypto::identity::{Keypair, PublicKey, Signer};
use axiom_types::crypto::{NodeId, Signature};
use hashbrown::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// How old a ping is allowed to be (by the verifier's OWN clock, not the
/// responder's - see verify_signed_pong) before a pong answering it is
/// rejected as stale. Bounds total exchange latency; the nonce (not this
/// window) is what actually carries the anti-replay guarantee.
const LIVENESS_FRESHNESS_WINDOW_SECS: u64 = 30;

/// Upper bound on the whole post-handshake ping/pong exchange (open stream,
/// write, wait-for-ack, read reply) on both the connect and accept sides.
/// Comfortably above any real RTT, well below the freshness window above -
/// without this, a peer that completes the QUIC handshake (so passes the
/// allowlist check) and then simply never writes/reads/acks hangs the
/// caller indefinitely. Required once anything (like a future accept loop)
/// serially processes more than one peer.
const LIVENESS_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Domain-separation tag mixed into every signed ping/pong. This node key is
/// Axiom's only identity key (also used for HELLO handshakes, frames,
/// cross_tier_auth tokens, and now iroh's own TLS identity) - without a
/// context tag, nothing stops a signature minted for one purpose being
/// replayed as valid for another. Bump alongside AXIOM_WAN_ALPN on any
/// wire-incompatible change.
const PONG_SIGNING_CONTEXT: &[u8] = b"axiom-wan-pong-v1";

#[derive(Debug, Error)]
pub enum WanError {
    #[error("peer {0:?} is not on the WAN allowlist")]
    NotAllowlisted(NodeId),
    #[error("pong responder {actual:?} does not match dialed peer {expected:?} (relay/substitution attempt?)")]
    ResponderMismatch { expected: NodeId, actual: NodeId },
    #[error("liveness pong signature invalid")]
    BadSignature,
    #[error("liveness pong nonce mismatch")]
    NonceMismatch,
    #[error("liveness ping stale: {0}s old (max {LIVENESS_FRESHNESS_WINDOW_SECS}s)")]
    Stale(u64),
    #[error("liveness exchange timed out after {LIVENESS_EXCHANGE_TIMEOUT:?}")]
    ExchangeTimeout,
    #[error("iroh transport error: {0}")]
    Transport(String),
}

/// Converts an Axiom Ed25519 keypair into the equivalent iroh identity.
/// Both wrap ed25519-dalek directly, so this is a pure byte reinterpretation —
/// no new key material, no translation loss. Axiom's NodeId and iroh's
/// EndpointId are the same 32 bytes.
#[cfg(feature = "quic")]
pub fn axiom_keypair_to_iroh_secret(keypair: &Keypair) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&keypair.secret_bytes())
}

#[cfg(feature = "quic")]
pub fn iroh_endpoint_id_to_node_id(id: iroh::EndpointId) -> NodeId {
    NodeId::from_bytes(*id.as_bytes())
}

/// Static allowlist of NodeIds permitted to reach this node over the WAN.
/// Required because the WAN path has no gossip/revocation system yet (see
/// project-axiom.md "spec-only" gaps) — this substitutes for it at current
/// scale. Grows this into something dynamic only once there's an actual
/// second WAN peer that isn't hand-configured — at that point this needs to
/// become e.g. Arc<RwLock<HashSet<NodeId>>> plus a re-check at capability
/// dispatch time, since right now it's captured immutably at bind() and
/// revoking a peer requires rebinding the whole endpoint.
#[derive(Debug, Clone, Default)]
pub struct WanAllowlist {
    allowed: HashSet<NodeId>,
}

impl WanAllowlist {
    pub fn new() -> Self {
        Self { allowed: HashSet::new() }
    }

    pub fn from_node_ids(ids: impl IntoIterator<Item = NodeId>) -> Self {
        Self { allowed: ids.into_iter().collect() }
    }

    pub fn allow(&mut self, id: NodeId) {
        self.allowed.insert(id);
    }

    pub fn is_allowed(&self, id: &NodeId) -> bool {
        self.allowed.contains(id)
    }

    pub fn check(&self, id: &NodeId) -> Result<(), WanError> {
        if self.is_allowed(id) {
            Ok(())
        } else {
            Err(WanError::NotAllowlisted(*id))
        }
    }
}

/// A liveness challenge. NOT itself signed - the challenger's identity is
/// already proven by iroh's own QUIC/TLS handshake (dial-by-public-key), so
/// signing the challenge would add nothing. `nonce` is what prevents replay
/// of a captured pong against a different challenge; `sent_at` is the
/// verifier's own clock, checked in verify_signed_pong against ITS OWN
/// current time (not the responder's clock) so the freshness check can't be
/// defeated or falsely tripped by responder clock skew.
#[derive(Debug, Clone, Copy)]
pub struct SignedPing {
    pub nonce: [u8; 16],
    pub sent_at: u64,
}

impl SignedPing {
    pub fn new() -> Self {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        Self {
            nonce,
            sent_at: now_unix(),
        }
    }

    fn signing_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[..16].copy_from_slice(&self.nonce);
        buf[16..].copy_from_slice(&self.sent_at.to_be_bytes());
        buf
    }

    pub fn to_wire(&self) -> [u8; 24] {
        self.signing_bytes()
    }

    pub fn from_wire(bytes: &[u8; 24]) -> Self {
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[..16]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[16..]);
        Self { nonce, sent_at: u64::from_be_bytes(ts) }
    }
}

/// The signed reply to a SignedPing — proves the private key for `responder`
/// is live on the other end of the connection RIGHT NOW, not just that some
/// transport-layer session (iroh/Cloudflare/whatever) reports as connected.
#[derive(Debug, Clone, Copy)]
pub struct SignedPong {
    pub responder: NodeId,
    pub echoed_nonce: [u8; 16],
    pub responded_at: u64,
    pub signature: Signature,
}

fn pong_signing_bytes(echoed_nonce: &[u8; 16], responded_at: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PONG_SIGNING_CONTEXT.len() + 16 + 8);
    msg.extend_from_slice(PONG_SIGNING_CONTEXT);
    msg.extend_from_slice(echoed_nonce);
    msg.extend_from_slice(&responded_at.to_be_bytes());
    msg
}

/// Build a signed pong replying to `ping`, as the node owning `keypair`.
pub fn build_signed_pong(keypair: &Keypair, ping: &SignedPing) -> SignedPong {
    let responded_at = now_unix();
    let signature = keypair.sign(&pong_signing_bytes(&ping.nonce, responded_at));
    SignedPong {
        responder: keypair.node_id(),
        echoed_nonce: ping.nonce,
        responded_at,
        signature,
    }
}

/// Verify a pong actually answers `ping` and was signed by the claimed
/// responder's key. This is the ONLY thing allowed to mark a WAN peer
/// "live" in trust-relevant logic — see module docs. Freshness is checked
/// against the VERIFIER's own clock and the ORIGINAL ping's send time
/// (`ping.sent_at`), not the responder-supplied `pong.responded_at` - using
/// the responder's timestamp for this check would let a responder with a
/// fast clock trivially pass and unfairly reject a responder whose clock
/// merely runs slow.
pub fn verify_signed_pong(ping: &SignedPing, pong: &SignedPong) -> Result<(), WanError> {
    if pong.echoed_nonce != ping.nonce {
        return Err(WanError::NonceMismatch);
    }

    let age = now_unix().saturating_sub(ping.sent_at);
    if age > LIVENESS_FRESHNESS_WINDOW_SECS {
        return Err(WanError::Stale(age));
    }

    let pubkey = PublicKey::from_bytes(pong.responder.as_bytes())
        .map_err(|_| WanError::BadSignature)?;
    let msg = pong_signing_bytes(&pong.echoed_nonce, pong.responded_at);
    if !pubkey.verify(&msg, &pong.signature) {
        return Err(WanError::BadSignature);
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}

/// ALPN identifying Axiom traffic over iroh's QUIC transport. Bump the
/// version suffix on any wire-incompatible change to the liveness/frame
/// format so mismatched peers fail the handshake cleanly instead of
/// desyncing on garbled bytes. Bumped 1->2 alongside PONG_SIGNING_CONTEXT
/// being added (2026-07-29 Fable pass) - nothing was deployed yet so this
/// cost nothing, but the same discipline applies to any future change.
#[cfg(feature = "quic")]
pub const AXIOM_WAN_ALPN: &[u8] = b"axiom/wan/2";

#[cfg(feature = "quic")]
pub struct WanEndpoint {
    endpoint: iroh::Endpoint,
    keypair: Keypair,
    allowlist: WanAllowlist,
}

#[cfg(feature = "quic")]
impl WanEndpoint {
    /// Shared builder setup for both the production and test-only bind
    /// paths, so a future change (new ALPN, transport tuning, etc.) can't
    /// silently apply to one and not the other.
    fn base_builder(keypair: &Keypair) -> iroh::endpoint::Builder {
        let secret_key = axiom_keypair_to_iroh_secret(keypair);
        iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![AXIOM_WAN_ALPN.to_vec()])
    }

    /// Bind a new WAN-reachable endpoint using the node's existing Axiom
    /// identity (no separate key material, no separate cert/CA — see module
    /// docs). Uses iroh's default (n0-hosted) relay set for hole-punching
    /// assistance; self-hosting a relay is a config change here later, not
    /// a code change.
    pub async fn bind(keypair: Keypair, allowlist: WanAllowlist) -> Result<Self, WanError> {
        let endpoint = Self::base_builder(&keypair)
            .bind()
            .await
            .map_err(|e| WanError::Transport(e.to_string()))?;
        Ok(Self { endpoint, keypair, allowlist })
    }

    /// Relay/discovery-disabled bind, for direct-address-only connections
    /// (same-host/cross-crate tests - see `forge-node`'s WAN capability
    /// tests - or a peer whose address is already known out of band, e.g.
    /// a genuinely air-gapped/local-only deployment). NOT for the real
    /// roaming-laptop WAN case - that needs the default `bind()`'s relay/
    /// discovery for NAT traversal. Gated behind the `test-utils` feature
    /// (plus this crate's own `test` cfg) rather than left unconditionally
    /// `pub` - forge-node's tests, in a different crate, need to reach it,
    /// which `#[cfg(test)]` alone can't provide since it doesn't cross
    /// crate boundaries, but that's no reason to ship it in every
    /// consumer's default public API surface. Still document the "not for
    /// real WAN" caveat loudly at every call site, this isn't an invitation
    /// to use it for the roaming case.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn bind_local_only(keypair: Keypair, allowlist: WanAllowlist) -> Result<Self, WanError> {
        let endpoint = Self::base_builder(&keypair)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await
            .map_err(|e| WanError::Transport(e.to_string()))?;
        Ok(Self { endpoint, keypair, allowlist })
    }

    pub fn local_node_id(&self) -> NodeId {
        self.keypair.node_id()
    }

    /// This endpoint's own bound local socket addresses - a wildcard bind
    /// (`0.0.0.0:PORT`) unless a specific address was requested. Needed
    /// alongside `bind_local_only` for direct-address dialing (same-host/
    /// cross-crate tests, or a peer whose address is already known out of
    /// band) - without this, `connect_direct_and_verify_liveness` has no
    /// way to learn what to dial. Same `test-utils` gating as
    /// `bind_local_only` and for the same reason - has no production
    /// caller, only test callers across crates.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn local_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Dial a peer by NodeId, relying on iroh discovery/relay to resolve
    /// how to reach them. The normal production path for the real WAN case.
    /// Allowlist is checked before dialing outbound too, not just on
    /// accept — a compromised local config shouldn't be able to silently
    /// talk to an unapproved peer either.
    pub async fn connect_and_verify_liveness(
        &self,
        peer: NodeId,
    ) -> Result<(iroh::endpoint::Connection, SignedPong), WanError> {
        self.allowlist.check(&peer)?;
        let peer_key = iroh::EndpointId::from_bytes(peer.as_bytes())
            .map_err(|e| WanError::Transport(e.to_string()))?;
        let addr = iroh::EndpointAddr::new(peer_key);
        self.connect_direct_and_verify_liveness(addr, peer).await
    }

    /// Dial a peer using an explicitly-supplied EndpointAddr (e.g. a known
    /// direct socket address, bypassing discovery) instead of relying on
    /// iroh's discovery/relay resolution. Useful for a statically-reachable
    /// peer (like a home node behind a static IP — see project-axiom.md,
    /// this is the canonical relay-free deployment) or for tests that
    /// should not depend on external relay reachability.
    pub async fn connect_direct_and_verify_liveness(
        &self,
        addr: iroh::EndpointAddr,
        peer: NodeId,
    ) -> Result<(iroh::endpoint::Connection, SignedPong), WanError> {
        self.allowlist.check(&peer)?;

        let conn = self
            .endpoint
            .connect(addr, AXIOM_WAN_ALPN)
            .await
            .map_err(|e| WanError::Transport(e.to_string()))?;

        let (conn, pong, ping) = tokio::time::timeout(LIVENESS_EXCHANGE_TIMEOUT, async {
            let (mut send, mut recv) = conn.open_bi().await
                .map_err(|e| WanError::Transport(e.to_string()))?;

            let ping = SignedPing::new();
            send.write_all(&ping.to_wire()).await
                .map_err(|e| WanError::Transport(e.to_string()))?;
            send.finish().map_err(|e| WanError::Transport(e.to_string()))?;
            // finish() only means "no more data queued" - stopped() waits for
            // the peer to actually ack it. Without this, dropping the
            // WanEndpoint shortly after this fn returns (as any short-lived
            // caller might) can sever the connection before the bytes land.
            if let Ok(Some(code)) = send.stopped().await {
                tracing::debug!(?code, "peer rejected ping stream (STOP_SENDING)");
            }

            let reply = recv.read_to_end(1024).await
                .map_err(|e| WanError::Transport(e.to_string()))?;
            let pong = decode_pong(&reply)?;
            Ok::<_, WanError>((conn, pong, ping))
        })
        .await
        .map_err(|_| WanError::ExchangeTimeout)??;

        verify_signed_pong(&ping, &pong)?;
        if pong.responder != peer {
            return Err(WanError::ResponderMismatch { expected: peer, actual: pong.responder });
        }

        Ok((conn, pong))
    }

    /// Cheaply dequeue the next inbound connection attempt WITHOUT waiting
    /// for its QUIC handshake to complete. Deliberately split from the
    /// handshake+allowlist+liveness work (handle_incoming) so an accept
    /// loop can immediately go back to accepting the next connection while
    /// spawning this one's handling onto its own task — otherwise one
    /// slow/malicious peer (allowlisted or not: identity isn't known until
    /// the handshake completes, so this can't be allowlist-gated any
    /// earlier than it already is) stalls every other pending connection
    /// behind it. Returns None when the endpoint itself has closed.
    pub async fn accept(&self) -> Option<iroh::endpoint::Incoming> {
        self.endpoint.accept().await
    }

    /// Complete the handshake for one already-dequeued inbound connection,
    /// allowlist-check the resulting peer identity, then answer exactly one
    /// signed ping/pong liveness exchange before handing the connection
    /// back to the caller for real capability traffic (not yet wired — see
    /// project-axiom.md Gap B).
    ///
    /// IMPORTANT for whoever calls this from a real accept loop: a
    /// non-allowlisted or misbehaving peer returns `Err` from a single call
    /// to this fn — that is a per-connection event, not a fatal endpoint
    /// error. The loop must `continue` past an `Err` here, not tear down
    /// the whole endpoint. Run this per-connection future on its own
    /// spawned task (see accept()'s doc) — do NOT `.await` it inline in the
    /// accept loop itself, or you've reintroduced the exact serialization
    /// this split exists to avoid.
    pub async fn handle_incoming(
        &self,
        incoming: iroh::endpoint::Incoming,
    ) -> Result<(iroh::endpoint::Connection, NodeId), WanError> {
        let conn = incoming
            .await
            .map_err(|e| WanError::Transport(e.to_string()))?;

        let remote_id = conn.remote_id();
        let peer = iroh_endpoint_id_to_node_id(remote_id);
        self.allowlist.check(&peer)?;

        tokio::time::timeout(LIVENESS_EXCHANGE_TIMEOUT, async {
            let (mut send, mut recv) = conn.accept_bi().await
                .map_err(|e| WanError::Transport(e.to_string()))?;
            let bytes = recv.read_to_end(1024).await
                .map_err(|e| WanError::Transport(e.to_string()))?;
            let wire: [u8; 24] = bytes.as_slice().try_into()
                .map_err(|_| WanError::Transport("malformed ping".into()))?;
            let ping = SignedPing::from_wire(&wire);

            let pong = build_signed_pong(&self.keypair, &ping);
            send.write_all(&encode_pong(&pong)).await
                .map_err(|e| WanError::Transport(e.to_string()))?;
            send.finish().map_err(|e| WanError::Transport(e.to_string()))?;
            if let Ok(Some(code)) = send.stopped().await {
                tracing::debug!(?code, "peer rejected pong stream (STOP_SENDING)");
            }
            Ok::<_, WanError>(())
        })
        .await
        .map_err(|_| WanError::ExchangeTimeout)??;

        Ok((conn, peer))
    }

    /// Thin composition of accept() + handle_incoming() for callers that
    /// don't need per-connection spawning (the existing one-shot CLI, the
    /// e2e test). A real long-running accept loop should call the two
    /// separately — see both fns' docs.
    pub async fn accept_with_liveness(
        &self,
    ) -> Result<(iroh::endpoint::Connection, NodeId), WanError> {
        let incoming = self
            .accept()
            .await
            .ok_or_else(|| WanError::Transport("endpoint closed".into()))?;
        self.handle_incoming(incoming).await
    }
}

#[cfg(feature = "quic")]
fn encode_pong(pong: &SignedPong) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 16 + 8 + 64);
    buf.extend_from_slice(pong.responder.as_bytes());
    buf.extend_from_slice(&pong.echoed_nonce);
    buf.extend_from_slice(&pong.responded_at.to_be_bytes());
    buf.extend_from_slice(pong.signature.as_bytes());
    buf
}

#[cfg(feature = "quic")]
fn decode_pong(bytes: &[u8]) -> Result<SignedPong, WanError> {
    if bytes.len() != 32 + 16 + 8 + 64 {
        return Err(WanError::Transport(format!(
            "malformed pong: {} bytes",
            bytes.len()
        )));
    }
    let mut responder = [0u8; 32];
    responder.copy_from_slice(&bytes[0..32]);
    let mut echoed_nonce = [0u8; 16];
    echoed_nonce.copy_from_slice(&bytes[32..48]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&bytes[48..56]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[56..120]);
    Ok(SignedPong {
        responder: NodeId::from_bytes(responder),
        echoed_nonce,
        responded_at: u64::from_be_bytes(ts),
        signature: Signature::from_bytes(sig),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pong_round_trips_and_verifies() {
        let kp = Keypair::generate();
        let ping = SignedPing::new();
        let pong = build_signed_pong(&kp, &ping);
        assert!(verify_signed_pong(&ping, &pong).is_ok());
        assert_eq!(pong.responder, kp.node_id());
    }

    #[test]
    fn pong_rejects_nonce_mismatch() {
        let kp = Keypair::generate();
        let ping_a = SignedPing::new();
        let ping_b = SignedPing::new();
        let pong = build_signed_pong(&kp, &ping_a);
        assert!(matches!(
            verify_signed_pong(&ping_b, &pong),
            Err(WanError::NonceMismatch)
        ));
    }

    #[test]
    fn pong_rejects_wrong_signer() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let ping = SignedPing::new();
        let mut pong = build_signed_pong(&kp_a, &ping);
        // Splice in a different responder identity than who actually signed.
        pong.responder = kp_b.node_id();
        assert!(matches!(
            verify_signed_pong(&ping, &pong),
            Err(WanError::BadSignature)
        ));
    }

    #[test]
    fn pong_signature_not_valid_for_different_context() {
        // A signature over the same nonce+timestamp bytes but WITHOUT the
        // domain-separation prefix must not verify - this is what would
        // have let a signature minted for a different Axiom purpose (or a
        // future protocol reusing this node key) be replayed as a pong.
        let kp = Keypair::generate();
        let ping = SignedPing::new();
        let responded_at = now_unix();
        let mut bare_msg = Vec::new();
        bare_msg.extend_from_slice(&ping.nonce);
        bare_msg.extend_from_slice(&responded_at.to_be_bytes());
        let bare_signature = kp.sign(&bare_msg);
        let forged_pong = SignedPong {
            responder: kp.node_id(),
            echoed_nonce: ping.nonce,
            responded_at,
            signature: bare_signature,
        };
        assert!(matches!(
            verify_signed_pong(&ping, &forged_pong),
            Err(WanError::BadSignature)
        ));
    }

    #[test]
    fn allowlist_blocks_unknown_peer() {
        let kp = Keypair::generate();
        let list = WanAllowlist::new();
        assert!(list.check(&kp.node_id()).is_err());
    }

    #[test]
    fn allowlist_allows_added_peer() {
        let kp = Keypair::generate();
        let mut list = WanAllowlist::new();
        list.allow(kp.node_id());
        assert!(list.check(&kp.node_id()).is_ok());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn end_to_end_wan_liveness_over_real_iroh() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "axiom_transport=debug".into()),
            )
            .try_init();
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let mut allow_a = WanAllowlist::new();
        allow_a.allow(kp_b.node_id());
        let mut allow_b = WanAllowlist::new();
        allow_b.allow(kp_a.node_id());

        let ep_a = WanEndpoint::bind_local_only(kp_a.clone(), allow_a).await.expect("bind a");
        let ep_b = WanEndpoint::bind_local_only(kp_b.clone(), allow_b).await.expect("bind b");
        let b_node_id = ep_b.local_node_id();
        // Bypass discovery/relay for this local test - supply B's directly
        // bound socket address so the test does not depend on external relay
        // reachability. Production connect_and_verify_liveness still relies
        // on iroh's discovery for the real (non-local) WAN case.
        let b_addr_wild = ep_b.endpoint.bound_sockets().first().copied().expect("b bound addr");
        // bound_sockets() reports the wildcard bind (0.0.0.0:PORT) - not directly
        // dialable. For this same-host test, redirect to loopback on that port.
        let b_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), b_addr_wild.port());

        let accept_task = tokio::spawn(async move {
            ep_b.accept_with_liveness().await.expect("accept")
        });

        let peer_addr = iroh::EndpointAddr::new(
            iroh::EndpointId::from_bytes(b_node_id.as_bytes()).expect("valid key")
        ).with_ip_addr(b_addr);
        let (_, pong) = ep_a
            .connect_direct_and_verify_liveness(peer_addr, b_node_id)
            .await
            .expect("connect + liveness");

        assert_eq!(pong.responder, b_node_id);

        let (_, accepted_peer) = accept_task.await.expect("join");
        assert_eq!(accepted_peer, kp_a.node_id());
    }

    /// Real-world reachability check for iroh's default (n0-hosted) relay
    /// and discovery infrastructure - NOT run in normal `cargo test` or CI
    /// (external network dependency), only on demand via
    /// `cargo test -- --ignored`. Unlike the always-run e2e test above,
    /// this uses production `bind()` (relay/discovery ENABLED, matching
    /// what a real deployment uses) and dials by NodeId ALONE - no direct
    /// address is ever supplied - so a pass genuinely proves the n0
    /// discovery-publish/resolve and relay-assist path is reachable from
    /// wherever this runs. It does NOT prove real cross-NAT hole-punching
    /// (both endpoints are the same process/host here); that remains a
    /// manual test from an actual separately-NATed device. See
    /// project-axiom.md Gap C.
    #[cfg(feature = "quic")]
    #[tokio::test]
    #[ignore]
    async fn relay_and_discovery_are_reachable() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "axiom_transport=debug".into()),
            )
            .try_init();
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let mut allow_a = WanAllowlist::new();
        allow_a.allow(kp_b.node_id());
        let mut allow_b = WanAllowlist::new();
        allow_b.allow(kp_a.node_id());

        let ep_a = WanEndpoint::bind(kp_a.clone(), allow_a).await.expect("bind a");
        let ep_b = WanEndpoint::bind(kp_b.clone(), allow_b).await.expect("bind b");
        let b_node_id = ep_b.local_node_id();

        let accept_task = tokio::spawn(async move {
            ep_b.accept_with_liveness().await.expect("accept")
        });

        // Deliberately NO direct address - this is the whole point of the
        // test. If discovery/relay aren't reachable, this hangs until the
        // outer timeout below fails it, rather than succeeding for the
        // wrong reason via some fallback direct path.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            ep_a.connect_and_verify_liveness(b_node_id),
        )
        .await
        .expect("discovery/relay unreachable within 60s")
        .expect("connect + liveness");

        assert_eq!(result.1.responder, b_node_id);
        accept_task.await.expect("join");
    }

    #[test]
    fn wire_round_trip_for_ping() {
        let ping = SignedPing::new();
        let wire = ping.to_wire();
        let back = SignedPing::from_wire(&wire);
        assert_eq!(ping.nonce, back.nonce);
        assert_eq!(ping.sent_at, back.sent_at);
    }
}
