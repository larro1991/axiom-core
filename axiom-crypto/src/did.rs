//! Decentralized Identifiers (DID) - W3C compatible identity
//!
//! Implements DID support for AXIOM agents, compatible with:
//! - W3C DID Core specification
//! - did:web method (web-hosted DID documents)
//! - did:axiom method (AXIOM-native identifiers)

use alloc::string::String;
use alloc::vec::Vec;
use crate::Keypair;

/// DID method type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidMethod {
    /// AXIOM-native DID method
    Axiom,
    /// Web-based DID (did:web)
    Web,
    /// Key-based DID (did:key)
    Key,
}

impl DidMethod {
    pub fn as_str(&self) -> &str {
        match self {
            DidMethod::Axiom => "axiom",
            DidMethod::Web => "web",
            DidMethod::Key => "key",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "axiom" => Some(DidMethod::Axiom),
            "web" => Some(DidMethod::Web),
            "key" => Some(DidMethod::Key),
            _ => None,
        }
    }
}

/// A Decentralized Identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did {
    /// The DID method
    pub method: DidMethod,
    /// Method-specific identifier
    pub identifier: String,
    /// Optional path
    pub path: Option<String>,
    /// Optional query
    pub query: Option<String>,
    /// Optional fragment
    pub fragment: Option<String>,
}

impl Did {
    /// Create a new did:axiom identifier from a public key
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self {
            method: DidMethod::Axiom,
            identifier: base58_encode(public_key),
            path: None,
            query: None,
            fragment: None,
        }
    }

    /// Create from a keypair
    pub fn from_keypair(keypair: &Keypair) -> Self {
        Self::from_public_key(&keypair.public_key_bytes())
    }

    /// Create a did:web identifier
    pub fn web(domain: impl Into<String>) -> Self {
        Self {
            method: DidMethod::Web,
            identifier: domain.into().replace('/', ":").replace("https://", ""),
            path: None,
            query: None,
            fragment: None,
        }
    }

    /// Parse a DID string
    pub fn parse(s: &str) -> Result<Self, DidError> {
        if !s.starts_with("did:") {
            return Err(DidError::InvalidFormat);
        }

        let rest = &s[4..];
        let (method_str, rest) = rest.split_once(':')
            .ok_or(DidError::InvalidFormat)?;

        let method = DidMethod::from_str(method_str)
            .ok_or(DidError::UnsupportedMethod)?;

        // Parse identifier and optional components
        let (identifier, rest) = if let Some(idx) = rest.find(['/', '?', '#']) {
            (&rest[..idx], Some(&rest[idx..]))
        } else {
            (rest, None)
        };

        let mut did = Self {
            method,
            identifier: String::from(identifier),
            path: None,
            query: None,
            fragment: None,
        };

        if let Some(rest) = rest {
            // Parse path: everything up to (not including) the first '?'
            // or '#', if what's left starts with '/'.
            let mut cursor = rest;
            if cursor.starts_with('/') {
                let end = cursor.find(['?', '#']).unwrap_or(cursor.len());
                did.path = Some(String::from(&cursor[..end]));
                cursor = &cursor[end..];
            }

            // Fragment/query precedence: per URL semantics, a '#' absorbs
            // EVERYTHING after it as the fragment, full stop - nothing
            // after a '#' is ever query syntax, even if it contains a '?'.
            // So the query can only come from a '?' that appears BEFORE any
            // '#' in what's left after the path. Computing the query's end
            // boundary via a bare `rest.find('#')` (as this used to) is
            // wrong whenever '#' precedes '?' - e.g. `#f?x` - because the
            // resulting end index then falls BEFORE the query start index,
            // and slicing `[q_idx + 1..end]` panics (start > end). This
            // fires two ways: at the top level (`did:web:example.com#f?x`)
            // and via this same path-then-fragment-then-query branch
            // (`/p#f?x`) - both are valid, unusual-but-legal DID URLs, not
            // malformed input, so both must parse rather than error.
            let frag_idx = cursor.find('#');
            let query_scan_end = frag_idx.unwrap_or(cursor.len());

            // Parse query (only from before any fragment)
            if let Some(q_idx) = cursor[..query_scan_end].find('?') {
                did.query = Some(String::from(&cursor[q_idx + 1..query_scan_end]));
            }

            // Parse fragment: everything after the first '#', if any.
            if let Some(f_idx) = frag_idx {
                did.fragment = Some(String::from(&cursor[f_idx + 1..]));
            }
        }

        Ok(did)
    }

    /// Convert to DID string
    pub fn to_string(&self) -> String {
        let mut s = format!("did:{}:{}", self.method.as_str(), self.identifier);
        if let Some(ref path) = self.path {
            s.push_str(path);
        }
        if let Some(ref query) = self.query {
            s.push('?');
            s.push_str(query);
        }
        if let Some(ref fragment) = self.fragment {
            s.push('#');
            s.push_str(fragment);
        }
        s
    }

    /// Get public key bytes (for did:axiom and did:key)
    pub fn public_key_bytes(&self) -> Option<[u8; 32]> {
        match self.method {
            DidMethod::Axiom | DidMethod::Key => {
                base58_decode(&self.identifier)
            }
            DidMethod::Web => None,
        }
    }

    /// Get the URL to resolve this DID document
    pub fn document_url(&self) -> Option<String> {
        match self.method {
            DidMethod::Web => {
                let domain = self.identifier.replace(':', "/");
                Some(format!("https://{}/.well-known/did.json", domain))
            }
            DidMethod::Axiom => {
                // For AXIOM, the DID document is retrieved via the AXIOM network
                None
            }
            DidMethod::Key => None,
        }
    }
}

/// DID Document - describes an entity and its verification methods
#[derive(Debug, Clone)]
pub struct DidDocument {
    /// The DID this document describes
    pub id: Did,
    /// Alternative identifiers
    pub also_known_as: Vec<String>,
    /// Controller(s) of this DID
    pub controller: Vec<Did>,
    /// Verification methods (keys)
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication methods (subset of verification_method)
    pub authentication: Vec<String>,
    /// Assertion methods
    pub assertion_method: Vec<String>,
    /// Key agreement methods
    pub key_agreement: Vec<String>,
    /// Service endpoints
    pub service: Vec<ServiceEndpoint>,
}

impl DidDocument {
    /// Create a new DID document
    pub fn new(id: Did) -> Self {
        Self {
            id,
            also_known_as: Vec::new(),
            controller: Vec::new(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            service: Vec::new(),
        }
    }

    /// Create from a keypair
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let did = Did::from_keypair(keypair);
        let vm_id = format!("{}#key-1", did.to_string());

        let mut doc = Self::new(did.clone());

        doc.verification_method.push(VerificationMethod {
            id: vm_id.clone(),
            method_type: VerificationMethodType::Ed25519VerificationKey2020,
            controller: did.to_string(),
            public_key: PublicKeyFormat::Multibase(base58_encode(&keypair.public_key_bytes())),
        });

        doc.authentication.push(vm_id.clone());
        doc.assertion_method.push(vm_id);

        doc
    }

    /// Add a service endpoint
    pub fn add_service(&mut self, id: &str, service_type: &str, endpoint: &str) {
        self.service.push(ServiceEndpoint {
            id: format!("{}#{}", self.id.to_string(), id),
            service_type: String::from(service_type),
            service_endpoint: String::from(endpoint),
        });
    }

    /// Get primary verification method
    pub fn primary_verification_method(&self) -> Option<&VerificationMethod> {
        self.verification_method.first()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        let vms: Vec<String> = self.verification_method.iter()
            .map(|vm| format!(
                r#"{{"id":"{}","type":"{}","controller":"{}"}}"#,
                vm.id, vm.method_type.as_str(), vm.controller
            ))
            .collect();

        let services: Vec<String> = self.service.iter()
            .map(|s| format!(
                r#"{{"id":"{}","type":"{}","serviceEndpoint":"{}"}}"#,
                s.id, s.service_type, s.service_endpoint
            ))
            .collect();

        format!(
            r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{}","verificationMethod":[{}],"service":[{}]}}"#,
            self.id.to_string(),
            vms.join(","),
            services.join(",")
        )
    }
}

/// Verification method in a DID document
#[derive(Debug, Clone)]
pub struct VerificationMethod {
    /// Identifier for this verification method
    pub id: String,
    /// Type of verification method
    pub method_type: VerificationMethodType,
    /// Controller of this key
    pub controller: String,
    /// The public key
    pub public_key: PublicKeyFormat,
}

/// Types of verification methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationMethodType {
    Ed25519VerificationKey2020,
    X25519KeyAgreementKey2020,
    JsonWebKey2020,
}

impl VerificationMethodType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ed25519VerificationKey2020 => "Ed25519VerificationKey2020",
            Self::X25519KeyAgreementKey2020 => "X25519KeyAgreementKey2020",
            Self::JsonWebKey2020 => "JsonWebKey2020",
        }
    }
}

/// Public key format
#[derive(Debug, Clone)]
pub enum PublicKeyFormat {
    /// Multibase encoded
    Multibase(String),
    /// Base58 encoded
    Base58(String),
    /// JWK format
    Jwk(String),
}

/// Service endpoint in a DID document
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    /// Identifier
    pub id: String,
    /// Type of service
    pub service_type: String,
    /// Endpoint URL or object
    pub service_endpoint: String,
}

/// DID resolution errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    /// Invalid DID format
    InvalidFormat,
    /// Unsupported DID method
    UnsupportedMethod,
    /// Resolution failed
    ResolutionFailed,
    /// Document not found
    NotFound,
    /// Deactivated DID
    Deactivated,
}

/// Simple base58 encoding (Bitcoin alphabet)
fn base58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if bytes.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();

    // Convert to base58
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in &mut digits {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Add leading '1's for zeros
    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }

    // Reverse and convert to chars
    for digit in digits.into_iter().rev() {
        result.push(ALPHABET[digit as usize] as char);
    }

    result
}

/// Simple base58 decoding
fn base58_decode(s: &str) -> Option<[u8; 32]> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if s.is_empty() {
        return None;
    }

    let mut bytes: Vec<u8> = Vec::new();

    for c in s.chars() {
        let idx = ALPHABET.iter().position(|&a| a as char == c)?;
        let mut carry = idx as u32;

        for byte in &mut bytes {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }

        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Count leading '1's
    let zeros = s.chars().take_while(|&c| c == '1').count();
    for _ in 0..zeros {
        bytes.push(0);
    }

    bytes.reverse();

    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_from_public_key() {
        let key = [0xAB; 32];
        let did = Did::from_public_key(&key);

        assert_eq!(did.method, DidMethod::Axiom);
        assert!(did.to_string().starts_with("did:axiom:"));
    }

    #[test]
    fn test_did_parse() {
        let did = Did::parse("did:axiom:abc123").unwrap();
        assert_eq!(did.method, DidMethod::Axiom);
        assert_eq!(did.identifier, "abc123");

        let did = Did::parse("did:web:example.com").unwrap();
        assert_eq!(did.method, DidMethod::Web);
    }

    #[test]
    fn test_did_parse_with_path() {
        let did = Did::parse("did:web:example.com/path/to?query=1#frag").unwrap();
        assert_eq!(did.identifier, "example.com");
        assert_eq!(did.path, Some(String::from("/path/to")));
        assert_eq!(did.query, Some(String::from("query=1")));
        assert_eq!(did.fragment, Some(String::from("frag")));
    }

    #[test]
    fn test_did_web() {
        let did = Did::web("example.com");
        assert_eq!(did.document_url(), Some(String::from("https://example.com/.well-known/did.json")));
    }

    #[test]
    fn test_did_fragment_before_query_in_top_level() {
        // `#` before `?`: everything from the first '#' onward is the
        // fragment, full stop - `f?x` is NOT query syntax here, it's part
        // of the fragment. Must parse without panicking or erroring.
        let did = Did::parse("did:web:example.com#f?x").unwrap();
        assert_eq!(did.identifier, "example.com");
        assert_eq!(did.fragment, Some(String::from("f?x")));
        assert_eq!(did.query, None);
    }

    #[test]
    fn test_did_fragment_before_query_after_path() {
        // Same precedence bug, but reached via the path-then-fragment-then-
        // query branch instead of the top-level one.
        let did = Did::parse("did:web:example.com/p#f?x").unwrap();
        assert_eq!(did.identifier, "example.com");
        assert_eq!(did.path, Some(String::from("/p")));
        assert_eq!(did.fragment, Some(String::from("f?x")));
        assert_eq!(did.query, None);
    }

    #[test]
    fn test_did_roundtrip() {
        let key = [0x12; 32];
        let did1 = Did::from_public_key(&key);
        let s = did1.to_string();
        let did2 = Did::parse(&s).unwrap();

        assert_eq!(did1, did2);
        assert_eq!(did2.public_key_bytes(), Some(key));
    }

    #[test]
    fn test_did_document() {
        let keypair = Keypair::generate();
        let doc = DidDocument::from_keypair(&keypair);

        assert!(!doc.verification_method.is_empty());
        assert!(!doc.authentication.is_empty());
    }

    #[test]
    fn test_did_document_service() {
        let keypair = Keypair::generate();
        let mut doc = DidDocument::from_keypair(&keypair);

        doc.add_service("agent", "AxiomAgent", "https://agent.example.com");

        assert_eq!(doc.service.len(), 1);
        assert!(doc.service[0].id.contains("#agent"));
    }

    #[test]
    fn test_did_document_json() {
        let keypair = Keypair::generate();
        let doc = DidDocument::from_keypair(&keypair);
        let json = doc.to_json();

        assert!(json.contains("@context"));
        assert!(json.contains("verificationMethod"));
    }

    #[test]
    fn test_base58_roundtrip() {
        let original = [0x42; 32];
        let encoded = base58_encode(&original);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
