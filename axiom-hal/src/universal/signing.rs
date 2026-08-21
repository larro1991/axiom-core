//! HDL Signature Verification
//!
//! Implements Ed25519 signing and verification for HDL files.
//! **CRITICAL SECURITY**: No unsigned HDL should ever execute.
//!
//! # Format
//!
//! Signed HDL files have a header:
//! ```text
//! # HDL-SIGNATURE: <base64-encoded-signature>
//! # HDL-SIGNER: <hex-encoded-public-key>
//! # HDL-TIMESTAMP: <unix-timestamp>
//! <actual HDL content>
//! ```
//!
//! # Trust Model
//!
//! - HDL files MUST be signed by a trusted key
//! - Trusted keys are stored in a TrustStore
//! - The TrustStore can be bootstrapped from a root key
//! - Signatures cover the entire HDL content (excluding signature header)

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

/// HDL signature verification result
#[derive(Debug, Clone)]
pub enum SignatureVerification {
    /// Signature is valid, signed by trusted key
    Valid {
        signer: [u8; 32],
        timestamp: u64,
    },
    /// Signature is invalid
    Invalid(SignatureError),
    /// No signature present
    Unsigned,
}

/// Signature verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// No `# HDL-` signature header lines present at all - distinct from
    /// `MalformedHeader` (lines present but incomplete/corrupt) so `verify()`
    /// can tell "genuinely unsigned content" from "someone attempted to sign
    /// this and got it wrong" - the former is `SignatureVerification::Unsigned`
    /// regardless of trust store policy (each caller decides whether to
    /// accept that), the latter always stays a hard `Invalid` error.
    NoHeader,
    /// Malformed signature header
    MalformedHeader,
    /// Signature doesn't match content
    SignatureMismatch,
    /// Signer is not in trust store
    UntrustedSigner,
    /// Signature has expired
    Expired,
    /// Timestamp is in the future (clock skew attack)
    FutureTimestamp,
    /// Invalid base64 encoding
    InvalidEncoding,
    /// Invalid public key format
    InvalidPublicKey,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoHeader => write!(f, "No signature header present"),
            Self::MalformedHeader => write!(f, "Malformed signature header"),
            Self::SignatureMismatch => write!(f, "Signature does not match content"),
            Self::UntrustedSigner => write!(f, "Signer is not trusted"),
            Self::Expired => write!(f, "Signature has expired"),
            Self::FutureTimestamp => write!(f, "Timestamp is in the future"),
            Self::InvalidEncoding => write!(f, "Invalid base64 encoding"),
            Self::InvalidPublicKey => write!(f, "Invalid public key format"),
        }
    }
}

/// Parsed signature header
#[derive(Debug, Clone)]
pub struct SignatureHeader {
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
    /// Signer's public key (32 bytes)
    pub signer: [u8; 32],
    /// Unix timestamp when signed
    pub timestamp: u64,
    /// Byte offset where actual HDL content starts
    pub content_offset: usize,
}

/// Trust store for HDL signers
#[derive(Debug, Clone)]
pub struct HdlTrustStore {
    /// Trusted public keys with metadata
    trusted_keys: Vec<TrustedKey>,
    /// Root key for bootstrapping (optional)
    root_key: Option<[u8; 32]>,
    /// Maximum signature age in seconds (0 = no expiry)
    max_signature_age_secs: u64,
    /// Allow unsigned HDL (DANGEROUS - only for development)
    allow_unsigned: bool,
}

/// A trusted signing key with metadata
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Ed25519 public key
    pub public_key: [u8; 32],
    /// Human-readable name/identifier
    pub name: String,
    /// Key purpose constraints
    pub purpose: KeyPurpose,
    /// When this key was added to trust store
    pub added_at: u64,
    /// Expiration timestamp (0 = never expires)
    pub expires_at: u64,
    /// Is this key revoked?
    pub revoked: bool,
}

/// What types of HDL a key can sign
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Can sign any HDL
    Any,
    /// Can only sign network device HDL
    NetworkOnly,
    /// Can only sign storage device HDL
    StorageOnly,
    /// Development/testing only (should not be in production)
    Development,
}

impl HdlTrustStore {
    /// Create a new empty trust store
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            root_key: None,
            max_signature_age_secs: 0, // No expiry by default
            allow_unsigned: false,
        }
    }

    /// Create trust store with a root key
    pub fn with_root_key(root_key: [u8; 32]) -> Self {
        let mut store = Self::new();
        store.root_key = Some(root_key);
        // Root key is implicitly trusted
        store.trusted_keys.push(TrustedKey {
            public_key: root_key,
            name: "ROOT".to_string(),
            purpose: KeyPurpose::Any,
            added_at: 0,
            expires_at: 0,
            revoked: false,
        });
        store
    }

    /// DANGEROUS: Allow unsigned HDL (development only)
    pub fn allow_unsigned_dev_only(mut self) -> Self {
        self.allow_unsigned = true;
        self
    }

    /// Set maximum signature age
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_signature_age_secs = seconds;
        self
    }

    /// Add a trusted key
    pub fn add_trusted_key(&mut self, key: TrustedKey) {
        // Don't add duplicates
        if !self.trusted_keys.iter().any(|k| k.public_key == key.public_key) {
            self.trusted_keys.push(key);
        }
    }

    /// Revoke a key
    pub fn revoke_key(&mut self, public_key: &[u8; 32]) {
        for key in &mut self.trusted_keys {
            if &key.public_key == public_key {
                key.revoked = true;
            }
        }
    }

    /// Check if a key is trusted
    pub fn is_trusted(&self, public_key: &[u8; 32], current_time: u64) -> bool {
        self.trusted_keys.iter().any(|k| {
            k.public_key == *public_key
                && !k.revoked
                && (k.expires_at == 0 || k.expires_at > current_time)
        })
    }

    /// Check if unsigned HDL is allowed
    pub fn allows_unsigned(&self) -> bool {
        self.allow_unsigned
    }

    /// Get all trusted keys
    pub fn trusted_keys(&self) -> &[TrustedKey] {
        &self.trusted_keys
    }
}

impl Default for HdlTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/// HDL Signature Verifier
pub struct HdlVerifier {
    trust_store: HdlTrustStore,
}

impl HdlVerifier {
    /// Create verifier with trust store
    pub fn new(trust_store: HdlTrustStore) -> Self {
        Self { trust_store }
    }

    /// Whether this verifier's trust store accepts unsigned content
    /// (`HdlTrustStore::allow_unsigned_dev_only`). `verify()` itself no
    /// longer applies this policy - it always classifies genuinely-unsigned
    /// content as `Unsigned` regardless, so the CALLER decides what to do
    /// with that. `SecureHdlParser::parse_verified` uses this to decide
    /// whether its own dev-mode passthrough is actually allowed.
    pub fn allows_unsigned(&self) -> bool {
        self.trust_store.allows_unsigned()
    }

    /// Parse signature header from HDL content
    pub fn parse_header(&self, hdl: &str) -> Result<SignatureHeader, SignatureError> {
        let mut signature: Option<[u8; 64]> = None;
        let mut signer: Option<[u8; 32]> = None;
        let mut timestamp: Option<u64> = None;
        let mut content_offset = 0;

        for line in hdl.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("# HDL-SIGNATURE:") {
                let sig_b64 = trimmed.strip_prefix("# HDL-SIGNATURE:").unwrap().trim();
                let sig_bytes = Self::decode_base64(sig_b64)?;
                if sig_bytes.len() != 64 {
                    return Err(SignatureError::MalformedHeader);
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&sig_bytes);
                signature = Some(sig);
                content_offset = hdl.find(line).unwrap_or(0) + line.len() + 1;
            } else if trimmed.starts_with("# HDL-SIGNER:") {
                let key_hex = trimmed.strip_prefix("# HDL-SIGNER:").unwrap().trim();
                let key_bytes = Self::decode_hex(key_hex)?;
                if key_bytes.len() != 32 {
                    return Err(SignatureError::InvalidPublicKey);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                signer = Some(key);
                content_offset = hdl.find(line).unwrap_or(0) + line.len() + 1;
            } else if trimmed.starts_with("# HDL-TIMESTAMP:") {
                let ts_str = trimmed.strip_prefix("# HDL-TIMESTAMP:").unwrap().trim();
                timestamp = ts_str.parse().ok();
                content_offset = hdl.find(line).unwrap_or(0) + line.len() + 1;
            } else if !trimmed.starts_with('#') && !trimmed.is_empty() {
                // First non-comment, non-empty line - this is where content starts
                break;
            }
        }

        // Find actual content start (skip all header lines)
        let mut actual_offset = 0;
        for line in hdl.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("# HDL-") {
                actual_offset += line.len() + 1; // +1 for newline
            } else {
                break;
            }
        }

        match (signature, signer, timestamp) {
            (Some(sig), Some(key), Some(ts)) => Ok(SignatureHeader {
                signature: sig,
                signer: key,
                timestamp: ts,
                content_offset: actual_offset,
            }),
            (None, None, None) => Err(SignatureError::NoHeader),
            _ => Err(SignatureError::MalformedHeader),
        }
    }

    /// Verify HDL content
    pub fn verify(&self, hdl: &str, current_time: u64) -> SignatureVerification {
        // Try to parse header
        let header = match self.parse_header(hdl) {
            Ok(h) => h,
            // Genuinely no signature attempted - always classify as
            // Unsigned, regardless of trust store policy. Whether Unsigned
            // is ACCEPTABLE is a decision for the caller (parse_strict
            // rejects it, parse_verified allows it in dev mode) - it's not
            // this function's call to make by silently reclassifying
            // "nothing to verify" as a failed verification.
            Err(SignatureError::NoHeader) => return SignatureVerification::Unsigned,
            // Header lines were present but incomplete/corrupt - a real
            // attempt at signing that failed, never silently treated as
            // unsigned even in dev mode.
            Err(e) => return SignatureVerification::Invalid(e),
        };

        // Check timestamp
        if header.timestamp > current_time + 300 {
            // More than 5 min in future = clock skew attack
            return SignatureVerification::Invalid(SignatureError::FutureTimestamp);
        }

        if self.trust_store.max_signature_age_secs > 0 {
            let age = current_time.saturating_sub(header.timestamp);
            if age > self.trust_store.max_signature_age_secs {
                return SignatureVerification::Invalid(SignatureError::Expired);
            }
        }

        // Check if signer is trusted
        if !self.trust_store.is_trusted(&header.signer, current_time) {
            return SignatureVerification::Invalid(SignatureError::UntrustedSigner);
        }

        // Get content to verify (everything after header)
        let content = if header.content_offset < hdl.len() {
            &hdl[header.content_offset..]
        } else {
            ""
        };

        // Verify signature using Ed25519
        if self.verify_ed25519(&header.signer, content.as_bytes(), &header.signature) {
            SignatureVerification::Valid {
                signer: header.signer,
                timestamp: header.timestamp,
            }
        } else {
            SignatureVerification::Invalid(SignatureError::SignatureMismatch)
        }
    }

    /// Verify Ed25519 signature
    /// In production, this would use ed25519-dalek
    fn verify_ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        // This is a placeholder - real implementation uses ed25519-dalek
        // For now, we compute expected signature and compare

        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signature, VerifyingKey, Verifier};

            let verifying_key = match VerifyingKey::from_bytes(public_key) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let sig = match Signature::from_slice(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };

            verifying_key.verify(message, &sig).is_ok()
        }

        #[cfg(not(feature = "std"))]
        {
            // In no_std, we need a different approach
            // For safety, reject all signatures in no_std without proper crypto
            let _ = (public_key, message, signature);
            false
        }
    }

    /// Decode base64 (simplified)
    fn decode_base64(input: &str) -> Result<Vec<u8>, SignatureError> {
        // Simple base64 decoder
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let input = input.trim().trim_end_matches('=');
        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        let mut buffer = 0u32;
        let mut bits = 0;

        for c in input.bytes() {
            let value = ALPHABET.iter().position(|&x| x == c)
                .ok_or(SignatureError::InvalidEncoding)? as u32;
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                output.push((buffer >> bits) as u8);
            }
        }

        Ok(output)
    }

    /// Decode hex string
    fn decode_hex(input: &str) -> Result<Vec<u8>, SignatureError> {
        let input = input.trim();
        if input.len() % 2 != 0 {
            return Err(SignatureError::InvalidEncoding);
        }

        let mut output = Vec::with_capacity(input.len() / 2);
        for chunk in input.as_bytes().chunks(2) {
            let high = Self::hex_digit(chunk[0])?;
            let low = Self::hex_digit(chunk[1])?;
            output.push((high << 4) | low);
        }
        Ok(output)
    }

    fn hex_digit(c: u8) -> Result<u8, SignatureError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(SignatureError::InvalidEncoding),
        }
    }
}

/// Sign HDL content (for tooling)
#[cfg(feature = "std")]
pub struct HdlSigner {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

#[cfg(feature = "std")]
impl HdlSigner {
    /// Create signer from private key bytes
    pub fn from_bytes(private_key: [u8; 32]) -> Result<Self, SignatureError> {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = signing_key.verifying_key().to_bytes();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Sign HDL content and return signed HDL with header
    pub fn sign(&self, hdl: &str, timestamp: u64) -> String {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.private_key);
        let signature = signing_key.sign(hdl.as_bytes());

        let sig_b64 = Self::encode_base64(signature.to_bytes().as_slice());
        let key_hex = Self::encode_hex(&self.public_key);

        format!(
            "# HDL-SIGNATURE: {}\n# HDL-SIGNER: {}\n# HDL-TIMESTAMP: {}\n{}",
            sig_b64, key_hex, timestamp, hdl
        )
    }

    fn encode_base64(input: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = String::new();
        for chunk in input.chunks(3) {
            let mut buffer = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                buffer |= (byte as u32) << (16 - i * 8);
            }

            let chars = match chunk.len() {
                3 => 4,
                2 => 3,
                1 => 2,
                _ => 0,
            };

            for i in 0..chars {
                let idx = ((buffer >> (18 - i * 6)) & 0x3F) as usize;
                output.push(ALPHABET[idx] as char);
            }

            for _ in chars..4 {
                output.push('=');
            }
        }
        output
    }

    fn encode_hex(input: &[u8]) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut output = String::with_capacity(input.len() * 2);
        for &byte in input {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0F) as usize] as char);
        }
        output
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_trust_store() -> HdlTrustStore {
        let mut store = HdlTrustStore::new();
        store.add_trusted_key(TrustedKey {
            public_key: [0xAB; 32],
            name: "test-key".to_string(),
            purpose: KeyPurpose::Any,
            added_at: 1000,
            expires_at: 0,
            revoked: false,
        });
        store
    }

    #[test]
    fn test_trust_store_creation() {
        let store = test_trust_store();
        assert!(store.is_trusted(&[0xAB; 32], 2000));
        assert!(!store.is_trusted(&[0xCD; 32], 2000));
    }

    #[test]
    fn test_key_revocation() {
        let mut store = test_trust_store();
        assert!(store.is_trusted(&[0xAB; 32], 2000));

        store.revoke_key(&[0xAB; 32]);
        assert!(!store.is_trusted(&[0xAB; 32], 2000));
    }

    #[test]
    fn test_key_expiration() {
        let mut store = HdlTrustStore::new();
        store.add_trusted_key(TrustedKey {
            public_key: [0xAB; 32],
            name: "expiring-key".to_string(),
            purpose: KeyPurpose::Any,
            added_at: 1000,
            expires_at: 2000, // Expires at time 2000
            revoked: false,
        });

        assert!(store.is_trusted(&[0xAB; 32], 1500)); // Before expiry
        assert!(!store.is_trusted(&[0xAB; 32], 2500)); // After expiry
    }

    #[test]
    fn test_verifier_unsigned_rejected() {
        let store = test_trust_store();
        let verifier = HdlVerifier::new(store);

        let hdl = r#"
device:
  name: "Test"
  class: network
"#;

        // Genuinely no signature attempted - `verify()` classifies this as
        // Unsigned regardless of trust store policy; a strict trust store
        // doesn't change what the content IS, only what a caller (like
        // `SecureHdlParser::parse_strict`) chooses to do with an Unsigned
        // result. Previously this asserted `Invalid(MalformedHeader)`, which
        // was the actual bug this test happened to codify: headerless HDL
        // and a corrupted-header attempt were indistinguishable, which also
        // broke `secure_parser`'s `test_unsigned_rejected_strict`.
        match verifier.verify(hdl, 1000) {
            SignatureVerification::Unsigned => {}
            other => panic!("Expected Unsigned, got {:?}", other),
        }
    }

    #[test]
    fn test_verifier_unsigned_allowed_dev() {
        let store = HdlTrustStore::new().allow_unsigned_dev_only();
        let verifier = HdlVerifier::new(store);

        let hdl = r#"
device:
  name: "Test"
  class: network
"#;

        match verifier.verify(hdl, 1000) {
            SignatureVerification::Unsigned => {}
            other => panic!("Expected Unsigned, got {:?}", other),
        }
    }

    #[test]
    fn test_hex_decode() {
        let verifier = HdlVerifier::new(HdlTrustStore::new());

        let decoded = HdlVerifier::decode_hex("48454c4c4f").unwrap();
        assert_eq!(decoded, b"HELLO");

        let decoded = HdlVerifier::decode_hex("ABCD").unwrap();
        assert_eq!(decoded, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_base64_decode() {
        let decoded = HdlVerifier::decode_base64("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_sign_and_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        // Generate keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create trust store with this key
        let mut store = HdlTrustStore::new();
        store.add_trusted_key(TrustedKey {
            public_key,
            name: "test".to_string(),
            purpose: KeyPurpose::Any,
            added_at: 0,
            expires_at: 0,
            revoked: false,
        });

        // Create signer and verifier
        let signer = HdlSigner::from_bytes(signing_key.to_bytes()).unwrap();
        let verifier = HdlVerifier::new(store);

        // Sign HDL
        let hdl = r#"device:
  name: "Test"
  class: network"#;

        let signed = signer.sign(hdl, 1000);

        // Verify
        match verifier.verify(&signed, 1000) {
            SignatureVerification::Valid { signer: s, timestamp } => {
                assert_eq!(s, public_key);
                assert_eq!(timestamp, 1000);
            }
            other => panic!("Expected Valid, got {:?}", other),
        }
    }
}
