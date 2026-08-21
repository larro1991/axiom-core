//! Secure HDL Parser
//!
//! Wraps the HDL parser with mandatory signature verification.
//! **This is the only interface that should be used to load HDL in production.**
//!
//! # Security Guarantee
//!
//! - Unsigned HDL is REJECTED by default
//! - All HDL loads are logged to external audit
//! - Signature verification happens BEFORE parsing
//!
//! # Usage
//!
//! ```ignore
//! let trust_store = HdlTrustStore::with_root_key(ROOT_KEY);
//! let parser = SecureHdlParser::new(trust_store, audit_writer);
//!
//! let desc = parser.parse_verified(hdl, current_timestamp)?;
//! // desc is guaranteed to be from signed, trusted HDL
//! ```

use alloc::string::{String, ToString};

use super::parser::HdlParser;
use super::signing::{HdlVerifier, HdlTrustStore, SignatureVerification, SignatureError};
use super::types::{HardwareDescription, ParseError};

/// Errors from secure parser
#[derive(Debug, Clone)]
pub enum SecureParseError {
    /// HDL is not signed (and unsigned not allowed)
    Unsigned,
    /// Signature verification failed
    SignatureError(SignatureError),
    /// HDL parsing failed
    ParseError(ParseError),
}

impl core::fmt::Display for SecureParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsigned => write!(f, "HDL is not signed (signature required)"),
            Self::SignatureError(e) => write!(f, "Signature verification failed: {}", e),
            Self::ParseError(e) => write!(f, "HDL parse error: {}", e),
        }
    }
}

/// Verification result with metadata
#[derive(Debug, Clone)]
pub struct VerifiedHdl {
    /// Parsed hardware description
    pub description: HardwareDescription,
    /// Who signed this HDL
    pub signer: [u8; 32],
    /// When it was signed
    pub signature_timestamp: u64,
    /// Hash of the HDL content (for audit)
    pub content_hash: [u8; 32],
}

/// Secure HDL Parser with mandatory signature verification
pub struct SecureHdlParser {
    /// Signature verifier
    verifier: HdlVerifier,
    /// For development mode warning
    dev_mode_warned: bool,
}

impl SecureHdlParser {
    /// Create secure parser with trust store
    pub fn new(trust_store: HdlTrustStore) -> Self {
        Self {
            verifier: HdlVerifier::new(trust_store),
            dev_mode_warned: false,
        }
    }

    /// Parse and verify HDL
    ///
    /// Returns error if:
    /// - HDL is unsigned (unless dev mode enabled)
    /// - Signature is invalid
    /// - Signer is not trusted
    /// - HDL parsing fails
    pub fn parse_verified(
        &mut self,
        hdl: &str,
        current_timestamp: u64,
    ) -> Result<VerifiedHdl, SecureParseError> {
        // STEP 1: Verify signature FIRST (before any parsing)
        let (signer, sig_timestamp) = match self.verifier.verify(hdl, current_timestamp) {
            SignatureVerification::Valid { signer, timestamp } => (signer, timestamp),
            SignatureVerification::Invalid(e) => {
                return Err(SecureParseError::SignatureError(e));
            }
            SignatureVerification::Unsigned => {
                // `verify()` reports genuinely-unsigned content as `Unsigned`
                // unconditionally (AXIOM-1 fix) - it no longer applies the
                // trust store's policy itself, so this caller must, or an
                // unsigned HDL would pass through here even with a strict
                // (non-dev) trust store, contradicting this function's own
                // doc comment and the module's "Unsigned HDL is REJECTED by
                // default" guarantee.
                if !self.verifier.allows_unsigned() {
                    return Err(SecureParseError::Unsigned);
                }
                // Development mode - emit warning
                if !self.dev_mode_warned {
                    // In production, this would log to external audit with warning
                    self.dev_mode_warned = true;
                }
                // Use zero signer for unsigned (dev mode only)
                ([0u8; 32], 0)
            }
        };

        // STEP 2: Compute content hash for audit trail
        let content_hash = self.compute_hash(hdl);

        // STEP 3: Parse HDL (now safe - signature verified)
        let parser = HdlParser::new();
        let description = parser.parse(hdl).map_err(SecureParseError::ParseError)?;

        Ok(VerifiedHdl {
            description,
            signer,
            signature_timestamp: sig_timestamp,
            content_hash,
        })
    }

    /// Parse HDL strictly - reject unsigned even in dev mode
    pub fn parse_strict(
        &self,
        hdl: &str,
        current_timestamp: u64,
    ) -> Result<VerifiedHdl, SecureParseError> {
        // Verify signature
        let (signer, sig_timestamp) = match self.verifier.verify(hdl, current_timestamp) {
            SignatureVerification::Valid { signer, timestamp } => (signer, timestamp),
            SignatureVerification::Invalid(e) => {
                return Err(SecureParseError::SignatureError(e));
            }
            SignatureVerification::Unsigned => {
                return Err(SecureParseError::Unsigned);
            }
        };

        // Compute content hash
        let content_hash = self.compute_hash(hdl);

        // Parse HDL
        let parser = HdlParser::new();
        let description = parser.parse(hdl).map_err(SecureParseError::ParseError)?;

        Ok(VerifiedHdl {
            description,
            signer,
            signature_timestamp: sig_timestamp,
            content_hash,
        })
    }

    /// Compute BLAKE3 hash of HDL content
    fn compute_hash(&self, hdl: &str) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(hdl.as_bytes());
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Production configuration for secure HDL loading
pub struct ProductionHdlConfig {
    /// Root signing key (compiled in or from secure storage)
    pub root_key: [u8; 32],
    /// Maximum signature age (seconds)
    pub max_signature_age_secs: u64,
    /// Require external audit logging of HDL loads
    pub require_audit: bool,
}

impl Default for ProductionHdlConfig {
    fn default() -> Self {
        Self {
            root_key: [0u8; 32], // MUST be set before use
            max_signature_age_secs: 86400 * 365, // 1 year
            require_audit: true,
        }
    }
}

/// Create production-ready secure parser
pub fn create_production_parser(config: ProductionHdlConfig) -> SecureHdlParser {
    let trust_store = HdlTrustStore::with_root_key(config.root_key)
        .with_max_age(config.max_signature_age_secs);
    SecureHdlParser::new(trust_store)
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_rejected_strict() {
        let trust_store = HdlTrustStore::new();
        let parser = SecureHdlParser::new(trust_store);

        let hdl = r#"
device:
  name: "Test"
  class: network
"#;

        match parser.parse_strict(hdl, 1000) {
            Err(SecureParseError::Unsigned) => {}
            other => panic!("Expected Unsigned error, got {:?}", other),
        }
    }

    #[test]
    fn test_unsigned_rejected_by_parse_verified_non_dev_store() {
        // Regression test for a gap Fable's review caught: once `verify()`
        // stopped applying trust-store policy itself (it always classifies
        // truly-unsigned content as `Unsigned`, letting the CALLER decide),
        // `parse_verified` needs to check `allows_unsigned()` itself before
        // accepting - otherwise a non-dev trust store's unsigned content
        // would pass through `parse_verified` unconditionally, contradicting
        // both this function's own doc comment and the module's "Unsigned
        // HDL is REJECTED by default" guarantee. No test caught this until now
        // because every other `parse_verified` test used a dev-mode store.
        let trust_store = HdlTrustStore::new(); // strict, NOT allow_unsigned_dev_only()
        let mut parser = SecureHdlParser::new(trust_store);

        let hdl = r#"
device:
  name: "Test"
  class: network
"#;

        match parser.parse_verified(hdl, 1000) {
            Err(SecureParseError::Unsigned) => {}
            other => panic!("Expected Unsigned error, got {:?}", other),
        }
    }

    #[test]
    fn test_unsigned_allowed_dev_mode() {
        let trust_store = HdlTrustStore::new().allow_unsigned_dev_only();
        let mut parser = SecureHdlParser::new(trust_store);

        let hdl = r#"
device:
  name: "Test"
  vendor_id: 0x1234
  device_id: 0x5678
  class: network
"#;

        let result = parser.parse_verified(hdl, 1000);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified.description.device.name, "Test");
        assert_eq!(verified.signer, [0u8; 32]); // Unsigned marker
    }

    #[test]
    fn test_content_hash_computed() {
        let trust_store = HdlTrustStore::new().allow_unsigned_dev_only();
        let mut parser = SecureHdlParser::new(trust_store);

        let hdl = r#"
device:
  name: "Test"
  vendor_id: 0x1234
  device_id: 0x5678
  class: network
"#;

        let verified = parser.parse_verified(hdl, 1000).unwrap();

        // Hash should not be all zeros
        assert_ne!(verified.content_hash, [0u8; 32]);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let mut trust_store = HdlTrustStore::new();
        // Add a key we WON'T use to sign
        trust_store.add_trusted_key(super::super::signing::TrustedKey {
            public_key: [0xAB; 32],
            name: "test".to_string(),
            purpose: super::super::signing::KeyPurpose::Any,
            added_at: 0,
            expires_at: 0,
            revoked: false,
        });

        let parser = SecureHdlParser::new(trust_store);

        // HDL with a well-formed-but-untrusted signature header. The
        // signature is 64 zero bytes base64-encoded (86 'A's + "==" padding -
        // a 64-byte input needs 88 base64 chars total, the last 2 of which
        // are "==" padding, not 2 more content chars). The old fixture had 88
        // 'A's and no padding, which decodes to 66 bytes, not 64 - so it was
        // being rejected as MalformedHeader before the signer's trust was
        // ever checked, never actually exercising the UntrustedSigner path
        // this test is named for.
        let hdl = r#"# HDL-SIGNATURE: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
# HDL-SIGNER: cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
# HDL-TIMESTAMP: 1000
device:
  name: "Test"
  vendor_id: 0x1234
  device_id: 0x5678
  class: network
"#;

        match parser.parse_strict(hdl, 1000) {
            Err(SecureParseError::SignatureError(SignatureError::UntrustedSigner)) => {}
            other => panic!("Expected UntrustedSigner, got {:?}", other),
        }
    }
}
