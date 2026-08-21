//! Ed25519 identity management

use axiom_types::crypto::{NodeId, Signature};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Ed25519 keypair for node identity
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from existing secret key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the node ID (public key)
    pub fn node_id(&self) -> NodeId {
        let verifying_key = self.signing_key.verifying_key();
        NodeId::from_bytes(verifying_key.to_bytes())
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the secret key bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Ed25519 public key for verification
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self { verifying_key })
    }

    /// Verify a signature. Uses `verify_strict`, NOT the `Verifier` trait's
    /// plain `verify` - the latter accepts non-canonical (s > L/8, or
    /// small-order) signature encodings that RFC 8032 rejects, which can
    /// let two different byte strings both verify as "the same" signature
    /// for a message. Since `NodeId` (below) IS the identity in this
    /// protocol, a malleable verify here is a malleable identity check.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        self.verifying_key.verify_strict(message, &sig).is_ok()
    }
}

/// Signing operations
pub trait Signer {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Signature;
}

impl Signer for Keypair {
    fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer as DalekSigner;
        let sig = self.signing_key.sign(message);
        Signature::from_bytes(sig.to_bytes())
    }
}

/// Verification operations
pub trait Verifier {
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Signature) -> bool;
}

impl Verifier for NodeId {
    // Fable full-repo review (2026-07-31): strict verification, same
    // reasoning as `PublicKey::verify` above - this is the actual
    // signature check on the live path (every AXIOM frame, via
    // `FrameVerifier::verify` -> `NodeId::verify`), not a dormant module.
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(self.as_bytes()) else {
            return false;
        };

        let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());

        verifying_key.verify_strict(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = Keypair::generate();
        let secret = keypair.secret_bytes();
        let restored = Keypair::from_bytes(&secret);

        assert_eq!(keypair.node_id(), restored.node_id());
    }

    #[test]
    fn test_sign_verify() {
        let keypair = Keypair::generate();
        let message = b"Hello, AXIOM!";

        let signature = keypair.sign(message);
        let node_id = keypair.node_id();

        assert!(node_id.verify(message, &signature));
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = Keypair::generate();
        let message = b"Hello, AXIOM!";

        let signature = keypair.sign(message);
        let node_id = keypair.node_id();

        // Tamper with message
        let tampered = b"Hello, AXIOM?";
        assert!(!node_id.verify(tampered, &signature));
    }

    #[test]
    fn test_wrong_key() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let message = b"Hello, AXIOM!";

        let signature = keypair1.sign(message);
        let wrong_node_id = keypair2.node_id();

        assert!(!wrong_node_id.verify(message, &signature));
    }
}
