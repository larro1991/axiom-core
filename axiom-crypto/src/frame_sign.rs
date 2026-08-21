//! Frame signing and verification
//!
//! Provides cryptographic signing and verification for AXIOM frames.

use crate::identity::{Keypair, Signer, Verifier};
use alloc::vec::Vec;
use axiom_codec::Encoder;
use axiom_types::crypto::SessionToken;
use axiom_types::frame::{Authentication, Frame};
use axiom_types::trust::TrustLevel;

/// Error types for frame signing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// Frame requires no signature at this trust level
    NoSignatureRequired,
    /// Failed to encode frame for signing
    EncodingFailed,
    /// Invalid trust level for operation
    InvalidTrustLevel,
}

/// Result type for sign operations
pub type SignResult<T> = Result<T, SignError>;

/// Signs AXIOM frames according to trust level
pub struct FrameSigner {
    keypair: Keypair,
}

impl FrameSigner {
    /// Create a new frame signer with the given keypair
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Get the node ID for this signer
    pub fn node_id(&self) -> axiom_types::crypto::NodeId {
        self.keypair.node_id()
    }

    /// Sign a frame, updating its authentication field
    ///
    /// For TrustLevel::Full and TrustLevel::Sig, this computes an Ed25519 signature
    /// over the frame data (excluding the signature field itself).
    pub fn sign(&self, frame: &mut Frame) -> SignResult<()> {
        match frame.header.trust_level {
            TrustLevel::Full | TrustLevel::Sig => {
                // Compute signature data (frame without auth)
                let sig_data = self.signature_data(frame)?;
                let signature = self.keypair.sign(&sig_data);
                frame.auth = Authentication::Signature(signature);
                Ok(())
            }
            TrustLevel::Compress => {
                // Compress level uses session tokens, not signatures
                // The token should already be set by the session layer
                Err(SignError::InvalidTrustLevel)
            }
            TrustLevel::Raw => {
                // Raw level has no authentication
                frame.auth = Authentication::None;
                Err(SignError::NoSignatureRequired)
            }
        }
    }

    /// Compute the data that should be signed. Delegates to
    /// `axiom_codec::Encoder::signature_data` - the single canonical
    /// implementation (previously duplicated here and in `FrameVerifier`,
    /// a hazard: a mismatch between copies means a signature that verifies
    /// on one path and fails on another).
    fn signature_data(&self, frame: &Frame) -> SignResult<Vec<u8>> {
        Ok(Encoder::signature_data(frame))
    }
}

/// Verifies AXIOM frame signatures
pub struct FrameVerifier;

impl FrameVerifier {
    /// Verify a frame's signature
    ///
    /// Returns Ok(true) if signature is valid, Ok(false) if invalid,
    /// or Err if verification is not applicable (e.g., Raw trust level).
    pub fn verify(frame: &Frame) -> SignResult<bool> {
        match frame.header.trust_level {
            TrustLevel::Full | TrustLevel::Sig => {
                let Authentication::Signature(sig) = &frame.auth else {
                    return Ok(false);
                };

                // Compute signature data
                let sig_data = Self::signature_data(frame)?;

                // Verify using sender's node ID
                let valid = frame.header.sender_id.verify(&sig_data, sig);
                Ok(valid)
            }
            TrustLevel::Compress => {
                // Session token verification is handled by the session layer
                Err(SignError::InvalidTrustLevel)
            }
            TrustLevel::Raw => {
                // Raw level has no authentication to verify
                Err(SignError::NoSignatureRequired)
            }
        }
    }

    /// Compute the data that was signed. Delegates to
    /// `axiom_codec::Encoder::signature_data` - see `FrameSigner`'s copy of
    /// this doc comment for why this is a delegation, not its own copy.
    fn signature_data(frame: &Frame) -> SignResult<Vec<u8>> {
        Ok(Encoder::signature_data(frame))
    }
}

/// Session token manager for TrustLevel::Compress
///
/// Session tokens are derived from a shared secret established during
/// trust negotiation. They provide lightweight authentication without
/// requiring full signature verification on every frame.
pub struct SessionManager {
    /// Active session tokens indexed by peer NodeId
    #[cfg(feature = "std")]
    sessions: std::collections::HashMap<axiom_types::crypto::NodeId, SessionInfo>,
}

/// Information about an active session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// The session token used for authentication
    pub token: SessionToken,
    /// Peer's node ID
    pub peer_id: axiom_types::crypto::NodeId,
    /// Session creation timestamp (unix millis)
    pub created_at: u64,
    /// Session expiration timestamp (unix millis)
    pub expires_at: u64,
    /// Number of frames authenticated with this session
    pub frame_count: u64,
}

impl SessionInfo {
    pub fn new(
        token: SessionToken,
        peer_id: axiom_types::crypto::NodeId,
        ttl_ms: u64,
    ) -> Self {
        let now = current_time_ms();
        Self {
            token,
            peer_id,
            created_at: now,
            expires_at: now + ttl_ms,
            frame_count: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        current_time_ms() > self.expires_at
    }
}

#[cfg(feature = "std")]
impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Create a session with a peer
    ///
    /// The token is derived from a shared secret (e.g., from X25519 key exchange)
    pub fn create_session(
        &mut self,
        peer_id: axiom_types::crypto::NodeId,
        shared_secret: &[u8; 32],
        ttl_ms: u64,
    ) -> SessionToken {
        use blake3::Hasher;

        // Derive session token from shared secret
        let mut hasher = Hasher::new();
        hasher.update(b"AXIOM-SESSION-TOKEN-V1");
        hasher.update(shared_secret);
        hasher.update(peer_id.as_bytes());

        let hash = hasher.finalize();
        let mut token_bytes = [0u8; 16];
        token_bytes.copy_from_slice(&hash.as_bytes()[0..16]);
        let token = SessionToken::from_bytes(token_bytes);

        let info = SessionInfo::new(token.clone(), peer_id.clone(), ttl_ms);
        self.sessions.insert(peer_id, info);

        token
    }

    /// Get session token for a peer
    pub fn get_token(&self, peer_id: &axiom_types::crypto::NodeId) -> Option<&SessionToken> {
        self.sessions
            .get(peer_id)
            .filter(|info| !info.is_expired())
            .map(|info| &info.token)
    }

    /// Verify a session token from a peer
    pub fn verify_token(
        &mut self,
        peer_id: &axiom_types::crypto::NodeId,
        token: &SessionToken,
    ) -> bool {
        if let Some(info) = self.sessions.get_mut(peer_id) {
            if info.is_expired() {
                self.sessions.remove(peer_id);
                return false;
            }

            if &info.token == token {
                info.frame_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove expired sessions
    pub fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, info| !info.is_expired());
    }

    /// Get session info for a peer
    pub fn get_session(&self, peer_id: &axiom_types::crypto::NodeId) -> Option<&SessionInfo> {
        self.sessions.get(peer_id).filter(|info| !info.is_expired())
    }

    /// Remove a session
    pub fn remove_session(&mut self, peer_id: &axiom_types::crypto::NodeId) {
        self.sessions.remove(peer_id);
    }
}

#[cfg(feature = "std")]
impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    #[cfg(not(feature = "std"))]
    {
        0 // In no_std environments, time must be provided externally
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct SessionManager;

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::clock::HybridClock;
    use axiom_types::frame::{FrameHeader, FrameType};
    use axiom_types::payload::PayloadType;

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate();
        let signer = FrameSigner::new(keypair);

        // Create frame with signer's node ID
        let header = FrameHeader::new(FrameType::Intent, signer.node_id())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1));

        let mut frame = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3]);

        // Sign the frame
        signer.sign(&mut frame).unwrap();

        // Verify the frame
        let valid = FrameVerifier::verify(&frame).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_tampered_frame_fails_verification() {
        let keypair = Keypair::generate();
        let signer = FrameSigner::new(keypair);

        let header = FrameHeader::new(FrameType::Intent, signer.node_id())
            .with_trust_level(TrustLevel::Sig);

        let mut frame = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3]);

        // Sign the frame
        signer.sign(&mut frame).unwrap();

        // Tamper with the payload
        frame.payload[0] = 0xFF;

        // Verification should fail
        let valid = FrameVerifier::verify(&frame).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_signer_fails_verification() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();

        let signer1 = FrameSigner::new(keypair1);
        let signer2 = FrameSigner::new(keypair2);

        // Create frame with signer2's node ID
        let header = FrameHeader::new(FrameType::Intent, signer2.node_id())
            .with_trust_level(TrustLevel::Sig);

        let mut frame = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3]);

        // Sign with signer1 (wrong key)
        signer1.sign(&mut frame).unwrap();

        // Verification should fail (signature doesn't match sender_id)
        let valid = FrameVerifier::verify(&frame).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_raw_trust_level_no_signature() {
        let keypair = Keypair::generate();
        let signer = FrameSigner::new(keypair);

        let header = FrameHeader::new(FrameType::Intent, signer.node_id())
            .with_trust_level(TrustLevel::Raw);

        let mut frame = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3]);

        // Signing Raw frames should return error
        let result = signer.sign(&mut frame);
        assert_eq!(result, Err(SignError::NoSignatureRequired));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();
        let peer_id = axiom_types::crypto::NodeId::from_bytes([0x42; 32]);
        let shared_secret = [0x11; 32];

        // Create session
        let token = manager.create_session(peer_id.clone(), &shared_secret, 60000);

        // Verify token
        assert!(manager.verify_token(&peer_id, &token));

        // Wrong token should fail
        let wrong_token = SessionToken::from_bytes([0xFF; 16]);
        assert!(!manager.verify_token(&peer_id, &wrong_token));

        // Unknown peer should fail
        let unknown_peer = axiom_types::crypto::NodeId::from_bytes([0x99; 32]);
        assert!(!manager.verify_token(&unknown_peer, &token));
    }
}
