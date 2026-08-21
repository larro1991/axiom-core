//! Trust negotiation state machine
//!
//! Implements the trust negotiation protocol between AXIOM peers:
//! - Challenge-response authentication
//! - Trust level upgrades/downgrades
//! - Session establishment
//!
//! # Trust Levels
//!
//! - `Full`: Challenge-response with signature (first contact)
//! - `Sig`: Signature-only authentication (known peer)
//! - `Compress`: Session token authentication (trusted peer)
//! - `Raw`: No per-frame authentication (mesh-internal)
//!
//! # Security Notes
//!
//! `Ack` verification (see `TrustNegotiator::process_frame`'s `Ack` branch)
//! checks a transcript signature covering both nonces and the negotiated
//! `trust_level`, verified against the public key carried IN the `Ack`
//! itself. This proves proof-of-possession of that key and binds the `Ack`
//! to this specific session (replay- and downgrade-resistant within the
//! session). It is deliberately **not** a claim of MITM-proof first-contact
//! authentication: nothing here pins the peer's key to an out-of-band
//! identity, so a full on-path attacker present from the very first `Hello`
//! can still run its own keypair through the whole protocol and be
//! accepted as "the peer". Solving that requires key pinning / an
//! out-of-band trust anchor, which is out of scope for this layer.

use alloc::vec::Vec;
use axiom_types::crypto::{NodeId, SessionToken, Signature};
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;

#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(feature = "std")]
use hashbrown::HashMap;

use crate::identity::{Keypair, Signer};

/// Trust negotiation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationState {
    /// Initial state, no negotiation started
    Initial,
    /// Challenge sent, waiting for response
    ChallengeSent,
    /// Challenge received, preparing response
    ChallengeReceived,
    /// Response sent, waiting for verification
    ResponseSent,
    /// Negotiation complete, trust established
    Established,
    /// Negotiation failed
    Failed,
}

/// Trust negotiation message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustMessageType {
    /// Initial hello with capabilities
    Hello = 0x01,
    /// Challenge for authentication
    Challenge = 0x02,
    /// Response to challenge
    Response = 0x03,
    /// Acknowledgment of successful negotiation
    Ack = 0x04,
    /// Request to upgrade trust level
    UpgradeRequest = 0x05,
    /// Response to upgrade request
    UpgradeResponse = 0x06,
    /// Request to downgrade trust level
    DowngradeNotify = 0x07,
    /// Error in negotiation
    Error = 0x08,
}

impl TrustMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Challenge),
            0x03 => Some(Self::Response),
            0x04 => Some(Self::Ack),
            0x05 => Some(Self::UpgradeRequest),
            0x06 => Some(Self::UpgradeResponse),
            0x07 => Some(Self::DowngradeNotify),
            0x08 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Hello message payload
#[derive(Debug, Clone)]
pub struct HelloPayload {
    /// Protocol version
    pub version: u16,
    /// Sender's public key (32 bytes)
    pub public_key: [u8; 32],
    /// Requested trust level
    pub requested_trust: TrustLevel,
    /// Supported capabilities (bitmap)
    pub capabilities: u32,
    /// Initiator's own nonce, generated fresh per Hello. Carried through to
    /// the eventual Ack so the initiator can verify a transcript signature
    /// over it - this is what makes Ack verification session-bound instead
    /// of a bare "some signature exists" check. See the module doc comment.
    pub initiator_nonce: [u8; 32],
}

impl HelloPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(71);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.push(self.requested_trust as u8);
        buf.extend_from_slice(&self.capabilities.to_be_bytes());
        buf.extend_from_slice(&self.initiator_nonce);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 71 {
            return None;
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[2..34]);
        let requested_trust = match data[34] {
            0 => TrustLevel::Full,
            1 => TrustLevel::Sig,
            2 => TrustLevel::Compress,
            3 => TrustLevel::Raw,
            _ => return None,
        };
        let capabilities = u32::from_be_bytes([data[35], data[36], data[37], data[38]]);
        let mut initiator_nonce = [0u8; 32];
        initiator_nonce.copy_from_slice(&data[39..71]);

        Some(Self {
            version,
            public_key,
            requested_trust,
            capabilities,
            initiator_nonce,
        })
    }
}

/// Challenge payload
#[derive(Debug, Clone)]
pub struct ChallengePayload {
    /// Random nonce (32 bytes)
    pub nonce: [u8; 32],
    /// Timestamp for replay protection
    pub timestamp: u64,
    /// Challenge expiry (seconds from timestamp)
    pub expiry_secs: u32,
}

impl ChallengePayload {
    pub fn new(nonce: [u8; 32], timestamp: u64) -> Self {
        Self {
            nonce,
            timestamp,
            expiry_secs: 30, // 30 second default expiry
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(44);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.expiry_secs.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 44 {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[0..32]);
        let timestamp = u64::from_be_bytes(data[32..40].try_into().ok()?);
        let expiry_secs = u32::from_be_bytes(data[40..44].try_into().ok()?);

        Some(Self {
            nonce,
            timestamp,
            expiry_secs,
        })
    }

    /// Check if challenge is still valid
    pub fn is_valid(&self, current_timestamp: u64) -> bool {
        current_timestamp <= self.timestamp + self.expiry_secs as u64
    }
}

/// Response payload (signed challenge)
#[derive(Debug, Clone)]
pub struct ResponsePayload {
    /// Original nonce from challenge
    pub nonce: [u8; 32],
    /// Signature over nonce + peer's public key
    pub signature: Signature,
}

impl ResponsePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(self.signature.as_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 96 {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[0..32]);
        let signature = Signature::from_bytes(data[32..96].try_into().ok()?);

        Some(Self { nonce, signature })
    }
}

/// Trust negotiation error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NegotiationError {
    /// Version mismatch
    VersionMismatch = 0x01,
    /// Invalid signature
    InvalidSignature = 0x02,
    /// Challenge expired
    ChallengeExpired = 0x03,
    /// Trust level not supported
    TrustNotSupported = 0x04,
    /// Rate limited
    RateLimited = 0x05,
    /// Internal error
    Internal = 0xFF,
}

/// Session established through trust negotiation
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct EstablishedSession {
    /// Peer's node ID
    pub peer_id: NodeId,
    /// Peer's public key
    pub peer_public_key: [u8; 32],
    /// Negotiated trust level
    pub trust_level: TrustLevel,
    /// Session token (for Compress level)
    pub session_token: Option<SessionToken>,
    /// When session was established
    pub established_at: Instant,
    /// Session expiry duration
    pub expires_in: Duration,
}

#[cfg(feature = "std")]
impl EstablishedSession {
    /// Check if session is still valid
    pub fn is_valid(&self) -> bool {
        self.established_at.elapsed() < self.expires_in
    }

    /// Get remaining validity duration
    pub fn remaining(&self) -> Duration {
        self.expires_in.saturating_sub(self.established_at.elapsed())
    }
}

/// Trust negotiation context for a single peer
#[cfg(feature = "std")]
pub struct NegotiationContext {
    /// Current state
    state: NegotiationState,
    /// Our keypair
    keypair: Keypair,
    /// Our node ID
    local_id: NodeId,
    /// Peer's node ID (once known)
    peer_id: Option<NodeId>,
    /// Peer's public key (once known)
    peer_public_key: Option<[u8; 32]>,
    /// Pending challenge (if we sent one)
    pending_challenge: Option<ChallengePayload>,
    /// Received challenge (if we need to respond)
    received_challenge: Option<ChallengePayload>,
    /// The initiator's nonce for this negotiation - either generated by us
    /// (if we're the initiator, via `create_hello`) or received from the
    /// peer's Hello (if we're the responder, via `process_hello`). Used to
    /// build/verify the Ack transcript signature.
    initiator_nonce: Option<[u8; 32]>,
    /// Negotiation started at
    started_at: Instant,
    /// Timeout duration
    timeout: Duration,
}

/// Domain tag for the Response transcript signature - see `create_response`
/// / `verify_response`. A domain tag makes this message unambiguously
/// distinct from any other transcript signed in this protocol (or
/// elsewhere in AXIOM), so a valid signature for one can never be replayed
/// as a valid signature for another. Matches the domain-separation pattern
/// established in `axiom-router/src/announce.rs`'s `ORIGIN_SIG_DOMAIN`.
#[cfg(feature = "std")]
const NEGOTIATE_RESPONSE_DOMAIN: &[u8] = b"AXIOM/negotiate-response/v1";

/// Domain tag for the Ack transcript signature - see `create_ack` /
/// `verify_ack_transcript`.
#[cfg(feature = "std")]
const NEGOTIATE_ACK_DOMAIN: &[u8] = b"AXIOM/negotiate-ack/v1";

/// Canonical bytes for the Response transcript: binds the signature to
/// WHO is challenging and WHO is responding, not just to a bare nonce that
/// (on its own) says nothing about which two parties the exchange is
/// between.
#[cfg(feature = "std")]
fn response_transcript(challenger_id: &NodeId, responder_id: &NodeId, nonce: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(NEGOTIATE_RESPONSE_DOMAIN.len() + 32 + 32 + 32);
    data.extend_from_slice(NEGOTIATE_RESPONSE_DOMAIN);
    data.extend_from_slice(challenger_id.as_bytes());
    data.extend_from_slice(responder_id.as_bytes());
    data.extend_from_slice(nonce);
    data
}

/// Canonical bytes for the Ack transcript. Including both nonces makes this
/// replay-resistant; including `trust_level` prevents an Ack from claiming a
/// different (e.g. downgraded) trust level than what was actually signed.
#[cfg(feature = "std")]
fn ack_transcript(
    initiator_pubkey: &[u8; 32],
    responder_pubkey: &[u8; 32],
    initiator_nonce: &[u8; 32],
    challenge_nonce: &[u8; 32],
    trust_level: TrustLevel,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(NEGOTIATE_ACK_DOMAIN.len() + 32 * 4 + 1);
    data.extend_from_slice(NEGOTIATE_ACK_DOMAIN);
    data.extend_from_slice(initiator_pubkey);
    data.extend_from_slice(responder_pubkey);
    data.extend_from_slice(initiator_nonce);
    data.extend_from_slice(challenge_nonce);
    data.push(trust_level.to_u8());
    data
}

/// Verify an incoming Ack's transcript signature against the public key it
/// claims, proving whoever sent it actually possesses that key's private
/// half (not just that SOME valid signature exists somewhere). See the
/// module doc comment for what this does and doesn't prove.
#[cfg(feature = "std")]
fn verify_ack_transcript(
    ctx: &NegotiationContext,
    claimed_responder_pubkey: &[u8; 32],
    trust_level: TrustLevel,
    signature: &Signature,
) -> bool {
    let Some(initiator_nonce) = ctx.initiator_nonce else {
        return false;
    };
    let Some(challenge_nonce) = ctx.received_challenge.as_ref().map(|c| c.nonce) else {
        return false;
    };
    let initiator_pubkey = *ctx.local_id.as_bytes();

    let transcript = ack_transcript(
        &initiator_pubkey,
        claimed_responder_pubkey,
        &initiator_nonce,
        &challenge_nonce,
        trust_level,
    );

    let Ok(verifier) = crate::identity::PublicKey::from_bytes(claimed_responder_pubkey) else {
        return false;
    };

    verifier.verify(&transcript, signature)
}

#[cfg(feature = "std")]
impl NegotiationContext {
    pub fn new(keypair: Keypair, local_id: NodeId, timeout: Duration) -> Self {
        Self {
            state: NegotiationState::Initial,
            keypair,
            local_id,
            peer_id: None,
            peer_public_key: None,
            pending_challenge: None,
            received_challenge: None,
            initiator_nonce: None,
            started_at: Instant::now(),
            timeout,
        }
    }

    /// Get current state
    pub fn state(&self) -> NegotiationState {
        self.state
    }

    /// Check if negotiation has timed out
    pub fn is_timed_out(&self) -> bool {
        self.started_at.elapsed() > self.timeout
    }

    /// Create a Hello message to initiate negotiation
    pub fn create_hello(&mut self, requested_trust: TrustLevel) -> Frame {
        // Fresh entropy per Hello - remembered so we can later verify the
        // responder's Ack transcript signature, which binds to this nonce.
        let mut initiator_nonce = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut initiator_nonce);
        self.initiator_nonce = Some(initiator_nonce);

        let payload = HelloPayload {
            version: 1,
            public_key: self.keypair.public_key_bytes(),
            requested_trust,
            capabilities: 0xFFFFFFFF, // All capabilities
            initiator_nonce,
        };

        let header = FrameHeader::new(FrameType::Trust, self.local_id.clone())
            .with_trust_level(TrustLevel::Full);

        let mut data = vec![TrustMessageType::Hello as u8];
        data.extend(payload.encode());

        Frame::new(header, PayloadType::Raw, data)
    }

    /// Create a Challenge message
    pub fn create_challenge(&mut self, timestamp: u64) -> Frame {
        // Real entropy, not a timestamp-derived transform - the previous
        // `timestamp ^ 0xDEADBEEF` PRNG made the nonce fully predictable
        // (and identical across challenges issued at the same timestamp),
        // which defeats its purpose as a replay/forgery guard.
        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let challenge = ChallengePayload::new(nonce, timestamp);
        self.pending_challenge = Some(challenge.clone());
        self.state = NegotiationState::ChallengeSent;

        let header = FrameHeader::new(FrameType::Trust, self.local_id.clone())
            .with_trust_level(TrustLevel::Full);

        let mut data = vec![TrustMessageType::Challenge as u8];
        data.extend(challenge.encode());

        Frame::new(header, PayloadType::Raw, data)
    }

    /// Create a Response to a challenge
    pub fn create_response(&mut self, challenge: &ChallengePayload, challenger_id: &NodeId) -> Frame {
        self.received_challenge = Some(challenge.clone());
        self.peer_id = Some(challenger_id.clone());

        // Sign a domain-separated, identity-bound transcript rather than
        // the bare nonce - binds the signature to WHO is challenging and
        // WHO is responding.
        let transcript = response_transcript(challenger_id, &self.local_id, &challenge.nonce);
        let signature = self.keypair.sign(&transcript);

        let response = ResponsePayload {
            nonce: challenge.nonce,
            signature,
        };

        self.state = NegotiationState::ResponseSent;

        let header = FrameHeader::new(FrameType::Trust, self.local_id.clone())
            .with_trust_level(TrustLevel::Full);

        let mut data = vec![TrustMessageType::Response as u8];
        data.extend(response.encode());

        Frame::new(header, PayloadType::Raw, data)
    }

    /// Verify a response to our challenge
    pub fn verify_response(&mut self, response: &ResponsePayload) -> Result<(), NegotiationError> {
        let challenge = self.pending_challenge.as_ref()
            .ok_or(NegotiationError::Internal)?;

        // Check nonce matches
        if response.nonce != challenge.nonce {
            return Err(NegotiationError::InvalidSignature);
        }

        // Get peer's public key and identity
        let peer_key = self.peer_public_key
            .ok_or(NegotiationError::Internal)?;
        let peer_node_id = self.peer_id.clone()
            .ok_or(NegotiationError::Internal)?;

        // We (self) were the challenger; the peer is the responder -
        // recompute the same transcript `create_response` signed.
        let transcript = response_transcript(&self.local_id, &peer_node_id, &challenge.nonce);

        // Verify signature
        let verifier = crate::identity::PublicKey::from_bytes(&peer_key)
            .map_err(|_| NegotiationError::InvalidSignature)?;

        if !verifier.verify(&transcript, &response.signature) {
            return Err(NegotiationError::InvalidSignature);
        }

        self.state = NegotiationState::Established;
        Ok(())
    }

    /// Create an Ack message (includes our public key for the initiator).
    ///
    /// Also carries a transcript signature so the initiator can verify
    /// proof-of-possession of the carried public key before installing
    /// anything - see `TrustNegotiator::process_frame`'s Ack branch and the
    /// module doc comment.
    pub fn create_ack(&self, trust_level: TrustLevel) -> Result<Frame, NegotiationError> {
        let initiator_pubkey = self.peer_public_key
            .ok_or(NegotiationError::Internal)?;
        let initiator_nonce = self.initiator_nonce
            .ok_or(NegotiationError::Internal)?;
        let challenge_nonce = self.pending_challenge.as_ref()
            .ok_or(NegotiationError::Internal)?
            .nonce;
        let responder_pubkey = self.keypair.public_key_bytes();

        let transcript = ack_transcript(
            &initiator_pubkey,
            &responder_pubkey,
            &initiator_nonce,
            &challenge_nonce,
            trust_level,
        );
        let signature = self.keypair.sign(&transcript);

        let header = FrameHeader::new(FrameType::Trust, self.local_id.clone())
            .with_trust_level(trust_level);

        let mut data = vec![TrustMessageType::Ack as u8, trust_level as u8];
        data.extend_from_slice(&responder_pubkey);
        data.extend_from_slice(signature.as_bytes());

        Ok(Frame::new(header, PayloadType::Raw, data))
    }

    /// Process incoming Hello
    pub fn process_hello(&mut self, hello: &HelloPayload) -> Result<(), NegotiationError> {
        if hello.version != 1 {
            return Err(NegotiationError::VersionMismatch);
        }

        self.peer_public_key = Some(hello.public_key);
        // Derive NodeId from public key
        let peer_id = NodeId::from_bytes(hello.public_key);
        self.peer_id = Some(peer_id);
        self.initiator_nonce = Some(hello.initiator_nonce);

        self.state = NegotiationState::ChallengeReceived;
        Ok(())
    }

    /// Get established session (if negotiation complete)
    pub fn get_session(&self, trust_level: TrustLevel) -> Option<EstablishedSession> {
        if self.state != NegotiationState::Established {
            return None;
        }

        Some(EstablishedSession {
            peer_id: self.peer_id.clone()?,
            peer_public_key: self.peer_public_key?,
            trust_level,
            session_token: None, // Generated separately for Compress level
            established_at: Instant::now(),
            expires_in: Duration::from_secs(3600), // 1 hour default
        })
    }
}

/// Trust negotiation manager for multiple peers
#[cfg(feature = "std")]
pub struct TrustNegotiator {
    /// Our keypair
    keypair: Keypair,
    /// Our node ID
    local_id: NodeId,
    /// Active negotiations
    negotiations: HashMap<NodeId, NegotiationContext>,
    /// Established sessions
    sessions: HashMap<NodeId, EstablishedSession>,
    /// Default negotiation timeout
    negotiation_timeout: Duration,
    /// Default session duration
    session_duration: Duration,
}

#[cfg(feature = "std")]
impl TrustNegotiator {
    pub fn new(keypair: Keypair, local_id: NodeId) -> Self {
        Self {
            keypair,
            local_id,
            negotiations: HashMap::new(),
            sessions: HashMap::new(),
            negotiation_timeout: Duration::from_secs(30),
            session_duration: Duration::from_secs(3600),
        }
    }

    /// Start negotiation with a peer
    pub fn start_negotiation(&mut self, peer_id: NodeId, requested_trust: TrustLevel) -> Frame {
        let mut ctx = NegotiationContext::new(
            self.keypair.clone(),
            self.local_id.clone(),
            self.negotiation_timeout,
        );
        let hello = ctx.create_hello(requested_trust);
        self.negotiations.insert(peer_id, ctx);
        hello
    }

    /// Process incoming Trust frame
    pub fn process_frame(&mut self, frame: &Frame, timestamp: u64) -> Result<Option<Frame>, NegotiationError> {
        if frame.payload.is_empty() {
            return Err(NegotiationError::Internal);
        }

        let msg_type = TrustMessageType::from_u8(frame.payload[0])
            .ok_or(NegotiationError::Internal)?;
        let payload_data = &frame.payload[1..];

        let peer_id = frame.header.sender_id.clone();

        match msg_type {
            TrustMessageType::Hello => {
                let hello = HelloPayload::decode(payload_data)
                    .ok_or(NegotiationError::Internal)?;

                // Create new context for this peer
                let mut ctx = NegotiationContext::new(
                    self.keypair.clone(),
                    self.local_id.clone(),
                    self.negotiation_timeout,
                );
                ctx.process_hello(&hello)?;

                // Send challenge
                let challenge_frame = ctx.create_challenge(timestamp);
                self.negotiations.insert(peer_id, ctx);

                Ok(Some(challenge_frame))
            }

            TrustMessageType::Challenge => {
                let challenge = ChallengePayload::decode(payload_data)
                    .ok_or(NegotiationError::Internal)?;

                if !challenge.is_valid(timestamp) {
                    return Err(NegotiationError::ChallengeExpired);
                }

                let ctx = self.negotiations.get_mut(&peer_id)
                    .ok_or(NegotiationError::Internal)?;

                let response_frame = ctx.create_response(&challenge, &peer_id);
                Ok(Some(response_frame))
            }

            TrustMessageType::Response => {
                let response = ResponsePayload::decode(payload_data)
                    .ok_or(NegotiationError::Internal)?;

                let ctx = self.negotiations.get_mut(&peer_id)
                    .ok_or(NegotiationError::Internal)?;

                ctx.verify_response(&response)?;

                // Send ack
                let ack_frame = ctx.create_ack(TrustLevel::Sig)?;

                // Create session
                if let Some(session) = ctx.get_session(TrustLevel::Sig) {
                    self.sessions.insert(peer_id.clone(), session);
                }

                self.negotiations.remove(&peer_id);
                Ok(Some(ack_frame))
            }

            TrustMessageType::Ack => {
                // Negotiation complete - extract the CLAIMED public key,
                // trust level, and transcript signature from the ack, then
                // verify the signature against that claimed key BEFORE
                // installing anything. Previously this branch installed
                // whatever public key/trust level the payload contained
                // with zero verification - an attacker (on-path, or simply
                // spoofing `peer_id`) could hand the initiator any key and
                // any trust level, cert-free. See the module doc comment
                // for what this verification does and doesn't buy.
                if payload_data.len() >= 1 + 32 + 64 {
                    let trust_level = match payload_data[0] {
                        0 => TrustLevel::Full,
                        1 => TrustLevel::Sig,
                        2 => TrustLevel::Compress,
                        _ => TrustLevel::Raw,
                    };
                    let mut claimed_responder_pubkey = [0u8; 32];
                    claimed_responder_pubkey.copy_from_slice(&payload_data[1..33]);
                    let mut signature_bytes = [0u8; 64];
                    signature_bytes.copy_from_slice(&payload_data[33..97]);
                    let signature = Signature::from_bytes(signature_bytes);

                    if let Some(mut ctx) = self.negotiations.remove(&peer_id) {
                        if verify_ack_transcript(&ctx, &claimed_responder_pubkey, trust_level, &signature) {
                            // Set peer info from ack - only now that we've
                            // proven the sender actually holds the private
                            // key for the identity it's claiming.
                            ctx.peer_public_key = Some(claimed_responder_pubkey);
                            ctx.peer_id = Some(peer_id.clone());
                            ctx.state = NegotiationState::Established;

                            if let Some(session) = ctx.get_session(trust_level) {
                                self.sessions.insert(peer_id, session);
                            }
                        }
                        // If verification fails, the negotiation is simply
                        // dropped (already removed from `self.negotiations`
                        // above) rather than silently installed.
                    }
                }
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    /// Get session for a peer
    pub fn get_session(&self, peer_id: &NodeId) -> Option<&EstablishedSession> {
        self.sessions.get(peer_id).filter(|s| s.is_valid())
    }

    /// Check if we have a valid session with a peer
    pub fn has_session(&self, peer_id: &NodeId) -> bool {
        self.get_session(peer_id).is_some()
    }

    /// Get trust level with a peer
    pub fn trust_level(&self, peer_id: &NodeId) -> TrustLevel {
        self.get_session(peer_id)
            .map(|s| s.trust_level)
            .unwrap_or(TrustLevel::Raw)
    }

    /// Cleanup expired negotiations and sessions
    pub fn cleanup(&mut self) {
        self.negotiations.retain(|_, ctx| !ctx.is_timed_out());
        self.sessions.retain(|_, session| session.is_valid());
    }

    /// Get number of active negotiations
    pub fn active_negotiations(&self) -> usize {
        self.negotiations.len()
    }

    /// Get number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct NegotiationContext;

#[cfg(not(feature = "std"))]
pub struct TrustNegotiator;

#[cfg(not(feature = "std"))]
pub struct EstablishedSession;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_hello_payload_roundtrip() {
        let payload = HelloPayload {
            version: 1,
            public_key: [0xAB; 32],
            requested_trust: TrustLevel::Sig,
            capabilities: 0xDEADBEEF,
            initiator_nonce: [0xEF; 32],
        };

        let encoded = payload.encode();
        let decoded = HelloPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.public_key, [0xAB; 32]);
        assert_eq!(decoded.requested_trust, TrustLevel::Sig);
        assert_eq!(decoded.capabilities, 0xDEADBEEF);
        assert_eq!(decoded.initiator_nonce, [0xEF; 32]);
    }

    #[test]
    fn test_challenge_payload_roundtrip() {
        let payload = ChallengePayload::new([0xCD; 32], 1700000000);

        let encoded = payload.encode();
        let decoded = ChallengePayload::decode(&encoded).unwrap();

        assert_eq!(decoded.nonce, [0xCD; 32]);
        assert_eq!(decoded.timestamp, 1700000000);
        assert!(decoded.is_valid(1700000000));
        assert!(!decoded.is_valid(1700000100)); // Expired
    }

    #[test]
    fn test_negotiation_flow() {
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();

        let node1_id = NodeId::from_bytes(keypair1.public_key_bytes());
        let node2_id = NodeId::from_bytes(keypair2.public_key_bytes());

        let mut negotiator1 = TrustNegotiator::new(keypair1, node1_id.clone());
        let mut negotiator2 = TrustNegotiator::new(keypair2, node2_id.clone());

        let timestamp = 1700000000u64;

        // Node 1 sends Hello
        let hello_frame = negotiator1.start_negotiation(node2_id.clone(), TrustLevel::Sig);
        assert_eq!(negotiator1.active_negotiations(), 1);

        // Node 2 receives Hello, sends Challenge
        let challenge_frame = negotiator2.process_frame(&hello_frame, timestamp)
            .unwrap()
            .unwrap();
        assert_eq!(negotiator2.active_negotiations(), 1);

        // Node 1 receives Challenge, sends Response
        let response_frame = negotiator1.process_frame(&challenge_frame, timestamp)
            .unwrap()
            .unwrap();

        // Node 2 receives Response, sends Ack
        let ack_frame = negotiator2.process_frame(&response_frame, timestamp)
            .unwrap()
            .unwrap();
        assert!(negotiator2.has_session(&node1_id));

        // Node 1 receives Ack
        negotiator1.process_frame(&ack_frame, timestamp).unwrap();
        assert!(negotiator1.has_session(&node2_id));

        // Both should have established sessions
        assert_eq!(negotiator1.active_sessions(), 1);
        assert_eq!(negotiator2.active_sessions(), 1);
    }

    #[test]
    fn test_challenge_nonce_not_derived_from_timestamp() {
        let keypair1 = test_keypair();
        let node1_id = NodeId::from_bytes(keypair1.public_key_bytes());
        let mut ctx = NegotiationContext::new(keypair1, node1_id, Duration::from_secs(30));

        let _frame_a = ctx.create_challenge(1700000000);
        let nonce_a = ctx.pending_challenge.clone().unwrap().nonce;

        // Same timestamp again.
        let _frame_b = ctx.create_challenge(1700000000);
        let nonce_b = ctx.pending_challenge.clone().unwrap().nonce;

        // Pre-fix, the nonce was `timestamp ^ 0xDEADBEEF` transformed
        // byte-by-byte - fully deterministic from the timestamp, so the
        // SAME timestamp always produced the SAME (predictable, replayable)
        // nonce. With real entropy, two challenges at the same timestamp
        // must differ.
        assert_ne!(nonce_a, nonce_b);
    }

    #[test]
    fn test_ack_with_mismatched_claimed_pubkey_rejected() {
        // Full negotiation up through a genuine Response/Ack, but the Ack
        // payload's claimed public key is swapped for an unrelated
        // attacker key after the fact (signature bytes left untouched) -
        // simulating an attacker tampering the claimed-key field in
        // transit, or fabricating their own Ack around a stolen signature.
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();
        let attacker_keypair = test_keypair();

        let node1_id = NodeId::from_bytes(keypair1.public_key_bytes());
        let node2_id = NodeId::from_bytes(keypair2.public_key_bytes());

        let mut negotiator1 = TrustNegotiator::new(keypair1, node1_id.clone());
        let mut negotiator2 = TrustNegotiator::new(keypair2, node2_id.clone());

        let timestamp = 1700000000u64;

        let hello_frame = negotiator1.start_negotiation(node2_id.clone(), TrustLevel::Sig);
        let challenge_frame = negotiator2.process_frame(&hello_frame, timestamp).unwrap().unwrap();
        let response_frame = negotiator1.process_frame(&challenge_frame, timestamp).unwrap().unwrap();
        let ack_frame = negotiator2.process_frame(&response_frame, timestamp).unwrap().unwrap();

        // Ack payload layout: [Ack][trust_level][pubkey(32)][signature(64)]
        let mut tampered = ack_frame.clone();
        let attacker_pub = attacker_keypair.public_key_bytes();
        tampered.payload[2..34].copy_from_slice(&attacker_pub);

        negotiator1.process_frame(&tampered, timestamp).unwrap();

        // Must NOT establish a session with the attacker's key installed.
        assert!(!negotiator1.has_session(&node2_id));
        assert_eq!(negotiator1.active_sessions(), 0);
    }

    #[test]
    fn test_ack_trust_level_downgrade_tampering_rejected() {
        // Tamper the trust_level byte in an otherwise-genuine Ack to a
        // different value than what was actually negotiated/signed. Since
        // the transcript signature covers trust_level, this must invalidate
        // the signature and the ack must be rejected.
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();

        let node1_id = NodeId::from_bytes(keypair1.public_key_bytes());
        let node2_id = NodeId::from_bytes(keypair2.public_key_bytes());

        let mut negotiator1 = TrustNegotiator::new(keypair1, node1_id.clone());
        let mut negotiator2 = TrustNegotiator::new(keypair2, node2_id.clone());

        let timestamp = 1700000000u64;

        let hello_frame = negotiator1.start_negotiation(node2_id.clone(), TrustLevel::Sig);
        let challenge_frame = negotiator2.process_frame(&hello_frame, timestamp).unwrap().unwrap();
        let response_frame = negotiator1.process_frame(&challenge_frame, timestamp).unwrap().unwrap();
        let ack_frame = negotiator2.process_frame(&response_frame, timestamp).unwrap().unwrap();

        let mut tampered = ack_frame.clone();
        // trust_level byte is payload[1]; this flow always negotiates
        // TrustLevel::Sig (== 1), so anything else is a forged
        // downgrade/upgrade attempt.
        tampered.payload[1] = TrustLevel::Raw as u8;

        negotiator1.process_frame(&tampered, timestamp).unwrap();

        assert!(!negotiator1.has_session(&node2_id));
        assert_eq!(negotiator1.active_sessions(), 0);
    }

    #[test]
    fn test_challenge_expiry() {
        let challenge = ChallengePayload::new([0; 32], 1700000000);

        assert!(challenge.is_valid(1700000000));
        assert!(challenge.is_valid(1700000029)); // Just before expiry
        assert!(!challenge.is_valid(1700000031)); // After expiry
    }

    #[test]
    fn test_session_validity() {
        let session = EstablishedSession {
            peer_id: test_node_id(1),
            peer_public_key: [0; 32],
            trust_level: TrustLevel::Sig,
            session_token: None,
            established_at: Instant::now(),
            expires_in: Duration::from_secs(3600),
        };

        assert!(session.is_valid());
        assert!(session.remaining() > Duration::from_secs(3599));
    }
}
