//! External Attestation Mesh
//!
//! Implements distributed attestation for verifying node integrity.
//! Nodes attest to each other's state, forming a mesh of mutual verification.
//!
//! # Security Model
//!
//! - Nodes cannot self-attest (requires external verification)
//! - Attestation covers: HDL state, trust level, configuration
//! - Mesh consensus: multiple attesters must agree
//! - Compromised node detection via attestation mismatch
//!
//! # Protocol
//!
//! ```text
//! Attestation Request:
//!   Requester → Target: "Attest your state"
//!   Target → Requester: AttestationReport(signed)
//!
//! Third-Party Attestation:
//!   Verifier → Target: "Attest your state for Requester"
//!   Target → Verifier: AttestationReport
//!   Verifier → Requester: AttestationCertificate(countersigned)
//! ```

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

/// Attestation report from a node
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// Node being attested
    pub subject_id: [u8; 32],
    /// Timestamp of attestation
    pub timestamp_ms: u64,
    /// Nonce from requester (prevents replay)
    pub nonce: [u8; 32],
    /// Attested state
    pub state: AttestedState,
    /// Subject's signature over entire report
    pub signature: [u8; 64],
}

/// State being attested
#[derive(Debug, Clone)]
pub struct AttestedState {
    /// Hash of loaded HDL files
    pub hdl_manifest_hash: [u8; 32],
    /// Current trust level
    pub trust_level: u8,
    /// Hash of current configuration
    pub config_hash: [u8; 32],
    /// Firmware/software version
    pub version: [u8; 8],
    /// TPM PCR values (if available)
    pub pcr_values: Option<PcrValues>,
    /// Active security alerts
    pub active_alerts: u16,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// TPM PCR values for hardware attestation
#[derive(Debug, Clone)]
pub struct PcrValues {
    /// PCR 0: Firmware
    pub pcr0: [u8; 32],
    /// PCR 1: Firmware config
    pub pcr1: [u8; 32],
    /// PCR 7: Secure boot state
    pub pcr7: [u8; 32],
    /// PCR 10: Boot measurements (IMA)
    pub pcr10: [u8; 32],
}

/// Attestation certificate (third-party verified)
#[derive(Debug, Clone)]
pub struct AttestationCertificate {
    /// Original attestation report
    pub report: AttestationReport,
    /// Verifier who countersigned
    pub verifier_id: [u8; 32],
    /// When verifier checked the report
    pub verified_at_ms: u64,
    /// Verifier's signature over report + verified_at
    pub verifier_signature: [u8; 64],
    /// Verification result
    pub result: AttestationResult,
}

/// Attestation verification result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationResult {
    /// Attestation verified successfully
    Valid,
    /// Signature invalid
    InvalidSignature,
    /// State doesn't match expected
    StateMismatch,
    /// Node is on revocation list
    NodeRevoked,
    /// Attestation expired
    Expired,
    /// Unknown/untrusted subject
    UntrustedSubject,
}

/// Attestation request
#[derive(Debug, Clone)]
pub struct AttestationRequest {
    /// Requester node ID
    pub requester_id: [u8; 32],
    /// Target node to attest
    pub target_id: [u8; 32],
    /// Unique nonce
    pub nonce: [u8; 32],
    /// Timestamp
    pub timestamp_ms: u64,
    /// Request signature
    pub signature: [u8; 64],
}

/// Attestation challenge for target
#[derive(Debug, Clone)]
pub struct AttestationChallenge {
    /// Challenge nonce
    pub nonce: [u8; 32],
    /// Expected to complete within this time
    pub deadline_ms: u64,
    /// Who requested (may be third party)
    pub requester_id: [u8; 32],
    /// Node this challenge was issued for. `verify_report` checks this
    /// against the report's `subject_id` so a report can't be verified
    /// against a challenge that was actually issued for someone else.
    pub target_id: [u8; 32],
}

/// Attestation mesh node
pub struct AttestationNode {
    /// Our node ID
    node_id: [u8; 32],
    /// Our signing key
    signing_key: [u8; 32],
    /// Known good state hashes (for comparison)
    known_good_states: BTreeMap<[u8; 32], ExpectedState>,
    /// Revoked nodes
    revoked_nodes: Vec<[u8; 32]>,
    /// Pending attestation requests
    pending_requests: BTreeMap<[u8; 32], AttestationChallenge>,
    /// Cached attestation results
    attestation_cache: BTreeMap<[u8; 32], CachedAttestation>,
    /// Configuration
    config: AttestationConfig,
}

/// Expected state for a node type/version
#[derive(Debug, Clone)]
pub struct ExpectedState {
    /// Expected HDL manifest hash
    pub hdl_manifest_hash: [u8; 32],
    /// Expected config hash
    pub config_hash: [u8; 32],
    /// Expected version
    pub version: [u8; 8],
    /// Expected PCR values (if TPM required)
    pub pcr_values: Option<PcrValues>,
}

/// Cached attestation result
#[derive(Debug, Clone)]
struct CachedAttestation {
    certificate: AttestationCertificate,
    cached_at_ms: u64,
}

/// Attestation configuration
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// How long attestations are valid
    pub attestation_validity_ms: u64,
    /// How long to cache attestation results
    pub cache_duration_ms: u64,
    /// Require multiple attesters for high-trust
    pub require_mesh_consensus: bool,
    /// Minimum attesters for consensus
    pub min_attesters: u32,
    /// Require TPM attestation
    pub require_tpm: bool,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            attestation_validity_ms: 60000,     // 1 minute
            cache_duration_ms: 300000,          // 5 minutes
            require_mesh_consensus: true,
            min_attesters: 2,
            require_tpm: false,                 // TPM optional by default
        }
    }
}

/// Attestation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// Request signature invalid
    InvalidRequest,
    /// Target node unknown
    UnknownTarget,
    /// Target node revoked
    TargetRevoked,
    /// Attestation timeout
    Timeout,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// State mismatch detected
    StateMismatch(String),
    /// Not enough attesters for consensus
    InsufficientConsensus,
    /// TPM attestation required but not provided
    TpmRequired,
    /// Report's nonce doesn't match any outstanding (unconsumed) challenge -
    /// either a replay of an already-verified report, or a nonce we never
    /// issued
    UnknownNonce,
    /// Report's subject doesn't match who the matching challenge was
    /// actually issued for
    TargetMismatch,
}

impl core::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "Invalid attestation request"),
            Self::UnknownTarget => write!(f, "Unknown target node"),
            Self::TargetRevoked => write!(f, "Target node is revoked"),
            Self::Timeout => write!(f, "Attestation timeout"),
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::StateMismatch(s) => write!(f, "State mismatch: {}", s),
            Self::InsufficientConsensus => write!(f, "Not enough attesters for consensus"),
            Self::TpmRequired => write!(f, "TPM attestation required"),
            Self::UnknownNonce => write!(f, "Report nonce does not match any outstanding challenge"),
            Self::TargetMismatch => write!(f, "Report subject does not match the challenge's target"),
        }
    }
}

impl AttestationNode {
    /// Create new attestation node
    pub fn new(node_id: [u8; 32], signing_key: [u8; 32], config: AttestationConfig) -> Self {
        Self {
            node_id,
            signing_key,
            known_good_states: BTreeMap::new(),
            revoked_nodes: Vec::new(),
            pending_requests: BTreeMap::new(),
            attestation_cache: BTreeMap::new(),
            config,
        }
    }

    /// Register expected state for a node type
    pub fn register_expected_state(&mut self, node_id: [u8; 32], state: ExpectedState) {
        self.known_good_states.insert(node_id, state);
    }

    /// Revoke a node
    pub fn revoke_node(&mut self, node_id: [u8; 32]) {
        if !self.revoked_nodes.contains(&node_id) {
            self.revoked_nodes.push(node_id);
        }
        // Clear any cached attestations
        self.attestation_cache.remove(&node_id);
    }

    /// Check if node is revoked
    pub fn is_revoked(&self, node_id: &[u8; 32]) -> bool {
        self.revoked_nodes.contains(node_id)
    }

    /// Create attestation request for a target
    pub fn create_request(
        &mut self,
        target_id: [u8; 32],
        current_time_ms: u64,
    ) -> AttestationRequest {
        // Generate nonce
        let nonce = self.generate_nonce(current_time_ms);

        // Store pending request
        self.pending_requests.insert(nonce, AttestationChallenge {
            nonce,
            deadline_ms: current_time_ms + self.config.attestation_validity_ms,
            requester_id: self.node_id,
            target_id,
        });

        let request = AttestationRequest {
            requester_id: self.node_id,
            target_id,
            nonce,
            timestamp_ms: current_time_ms,
            signature: [0u8; 64], // Will be signed
        };

        // Sign request
        self.sign_request(request)
    }

    /// Create our attestation report in response to challenge
    pub fn create_report(
        &self,
        challenge: &AttestationChallenge,
        our_state: AttestedState,
        current_time_ms: u64,
    ) -> AttestationReport {
        let mut report = AttestationReport {
            subject_id: self.node_id,
            timestamp_ms: current_time_ms,
            nonce: challenge.nonce,
            state: our_state,
            signature: [0u8; 64],
        };

        // Sign the report
        report.signature = self.sign_report(&report);
        report
    }

    /// Verify received attestation report
    ///
    /// Takes `&mut self` because a successful nonce/target check consumes
    /// the matching `pending_requests` entry (anti-replay) - this forces
    /// any caller to route verification through the node that actually
    /// issued the challenge being answered, which is the correct shape:
    /// verification is stateful, not a pure function of the report.
    pub fn verify_report(
        &mut self,
        report: &AttestationReport,
        current_time_ms: u64,
    ) -> Result<AttestationResult, AttestationError> {
        // Check if node is revoked
        if self.is_revoked(&report.subject_id) {
            return Ok(AttestationResult::NodeRevoked);
        }

        // Check timestamp. The check just above only rejects timestamps
        // MORE than 60s ahead of us, so a timestamp 1-60s in the future
        // still reaches the subtraction below - `saturating_sub` avoids an
        // underflow-panic there (this workspace builds with
        // `panic = "abort"`, so an unchecked underflow here is a
        // peer-triggerable process kill in debug/overflow-checked builds,
        // and a silent wraparound-to-huge-number producing a wrong
        // `Expired` verdict in a plain release build).
        if report.timestamp_ms > current_time_ms + 60000 {
            return Ok(AttestationResult::Expired); // Future timestamp
        }
        if current_time_ms.saturating_sub(report.timestamp_ms) > self.config.attestation_validity_ms {
            return Ok(AttestationResult::Expired);
        }

        // Verify signature
        if !self.verify_report_signature(report) {
            return Ok(AttestationResult::InvalidSignature);
        }

        // Replay check: the nonce must correspond to a challenge WE issued
        // and haven't already consumed (same lifecycle as the timeout-based
        // expiry in `clean_cache`), and it must have been issued for this
        // exact subject - otherwise even a validly-signed report could be
        // replayed against a stale or mismatched challenge. Consuming the
        // entry here (rather than merely peeking) is what makes this an
        // actual anti-replay check instead of a one-time-bypassable one.
        match self.pending_requests.remove(&report.nonce) {
            None => return Err(AttestationError::UnknownNonce),
            Some(challenge) => {
                if challenge.target_id != report.subject_id {
                    return Err(AttestationError::TargetMismatch);
                }
            }
        }

        // Check against known good state (if we have it)
        if let Some(expected) = self.known_good_states.get(&report.subject_id) {
            if report.state.hdl_manifest_hash != expected.hdl_manifest_hash {
                return Err(AttestationError::StateMismatch(
                    "HDL manifest hash mismatch".to_string()
                ));
            }
            if report.state.config_hash != expected.config_hash {
                return Err(AttestationError::StateMismatch(
                    "Config hash mismatch".to_string()
                ));
            }
            if self.config.require_tpm && report.state.pcr_values.is_none() {
                return Err(AttestationError::TpmRequired);
            }
        }

        Ok(AttestationResult::Valid)
    }

    /// Create attestation certificate (as verifier)
    pub fn create_certificate(
        &self,
        report: AttestationReport,
        result: AttestationResult,
        current_time_ms: u64,
    ) -> AttestationCertificate {
        let mut cert = AttestationCertificate {
            report,
            verifier_id: self.node_id,
            verified_at_ms: current_time_ms,
            verifier_signature: [0u8; 64],
            result,
        };

        cert.verifier_signature = self.sign_certificate(&cert);
        cert
    }

    /// Verify attestation certificate
    pub fn verify_certificate(
        &self,
        cert: &AttestationCertificate,
        current_time_ms: u64,
    ) -> Result<(), AttestationError> {
        // Check certificate age. AXIOM-14 Cycle 7 (Fable diff review,
        // required): saturating_sub, not a bare subtraction -
        // verified_at_ms arrives inside a PEER-SUPPLIED certificate, so a
        // future-dated cert underflows this u64 subtraction and panics -
        // this workspace has panic=abort, so that's a peer-triggerable
        // process kill. Identical bug class to the timestamp underflow
        // already fixed in verify_report above; held to the same standard.
        if current_time_ms.saturating_sub(cert.verified_at_ms) > self.config.cache_duration_ms {
            return Err(AttestationError::Timeout);
        }

        // Verify verifier signature
        if !self.verify_certificate_signature(cert) {
            return Err(AttestationError::SignatureVerificationFailed);
        }

        // Verify original report signature
        if !self.verify_report_signature(&cert.report) {
            return Err(AttestationError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Get cached attestation for node
    pub fn get_cached_attestation(
        &self,
        node_id: &[u8; 32],
        current_time_ms: u64,
    ) -> Option<&AttestationCertificate> {
        self.attestation_cache.get(node_id).and_then(|cached| {
            if current_time_ms.saturating_sub(cached.cached_at_ms) <= self.config.cache_duration_ms {
                Some(&cached.certificate)
            } else {
                None
            }
        })
    }

    /// Cache attestation result
    pub fn cache_attestation(&mut self, cert: AttestationCertificate, current_time_ms: u64) {
        self.attestation_cache.insert(
            cert.report.subject_id,
            CachedAttestation {
                certificate: cert,
                cached_at_ms: current_time_ms,
            },
        );
    }

    /// Clean expired cache entries
    pub fn clean_cache(&mut self, current_time_ms: u64) {
        self.attestation_cache.retain(|_, cached| {
            current_time_ms.saturating_sub(cached.cached_at_ms) <= self.config.cache_duration_ms
        });

        self.pending_requests.retain(|_, challenge| {
            challenge.deadline_ms > current_time_ms
        });
    }

    // =========================================================================
    // Cryptographic Operations
    // =========================================================================

    fn generate_nonce(&self, timestamp: u64) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&self.node_id);
        hasher.update(&timestamp.to_le_bytes());

        #[cfg(feature = "std")]
        {
            use rand::RngCore;
            let mut random = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut random);
            hasher.update(&random);
        }

        let hash = hasher.finalize();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(hash.as_bytes());
        nonce
    }

    fn sign_request(&self, mut request: AttestationRequest) -> AttestationRequest {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signer, SigningKey};
            use blake3::Hasher;

            let mut hasher = Hasher::new();
            hasher.update(&request.requester_id);
            hasher.update(&request.target_id);
            hasher.update(&request.nonce);
            hasher.update(&request.timestamp_ms.to_le_bytes());
            let hash = hasher.finalize();

            let signing_key = SigningKey::from_bytes(&self.signing_key);
            let sig = signing_key.sign(hash.as_bytes());
            request.signature = sig.to_bytes();
        }
        request
    }

    fn sign_report(&self, report: &AttestationReport) -> [u8; 64] {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signer, SigningKey};

            let hash = self.hash_report(report);
            let signing_key = SigningKey::from_bytes(&self.signing_key);
            let sig = signing_key.sign(&hash);
            return sig.to_bytes();
        }

        #[cfg(not(feature = "std"))]
        [0u8; 64]
    }

    fn verify_report_signature(&self, report: &AttestationReport) -> bool {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let hash = self.hash_report(report);

            let verifying_key = match VerifyingKey::from_bytes(&report.subject_id) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let signature = match Signature::from_slice(&report.signature) {
                Ok(s) => s,
                Err(_) => return false,
            };

            return verifying_key.verify(&hash, &signature).is_ok();
        }

        #[cfg(not(feature = "std"))]
        false
    }

    fn hash_report(&self, report: &AttestationReport) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&report.subject_id);
        hasher.update(&report.timestamp_ms.to_le_bytes());
        hasher.update(&report.nonce);
        hasher.update(&report.state.hdl_manifest_hash);
        hasher.update(&[report.state.trust_level]);
        hasher.update(&report.state.config_hash);
        hasher.update(&report.state.version);
        // PCR values (TPM measurements) were previously NOT part of the
        // signed digest at all, so a tampered `pcr_values` still verified
        // against a genuine outer signature. Bind them in: a presence tag
        // byte plus the values when present, so "absent" and "all-zero
        // values" hash differently.
        match &report.state.pcr_values {
            Some(pcr) => {
                hasher.update(&[1u8]);
                hasher.update(&pcr.pcr0);
                hasher.update(&pcr.pcr1);
                hasher.update(&pcr.pcr7);
                hasher.update(&pcr.pcr10);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
        hasher.update(&report.state.active_alerts.to_le_bytes());
        hasher.update(&report.state.uptime_secs.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    fn sign_certificate(&self, cert: &AttestationCertificate) -> [u8; 64] {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signer, SigningKey};
            use blake3::Hasher;

            let mut hasher = Hasher::new();
            hasher.update(&self.hash_report(&cert.report));
            hasher.update(&cert.verifier_id);
            hasher.update(&cert.verified_at_ms.to_le_bytes());
            hasher.update(&[cert.result as u8]);
            let hash = hasher.finalize();

            let signing_key = SigningKey::from_bytes(&self.signing_key);
            let sig = signing_key.sign(hash.as_bytes());
            return sig.to_bytes();
        }

        #[cfg(not(feature = "std"))]
        [0u8; 64]
    }

    fn verify_certificate_signature(&self, cert: &AttestationCertificate) -> bool {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            use blake3::Hasher;

            let mut hasher = Hasher::new();
            hasher.update(&self.hash_report(&cert.report));
            hasher.update(&cert.verifier_id);
            hasher.update(&cert.verified_at_ms.to_le_bytes());
            hasher.update(&[cert.result as u8]);
            let hash = hasher.finalize();

            let verifying_key = match VerifyingKey::from_bytes(&cert.verifier_id) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let signature = match Signature::from_slice(&cert.verifier_signature) {
                Ok(s) => s,
                Err(_) => return false,
            };

            return verifying_key.verify(hash.as_bytes(), &signature).is_ok();
        }

        #[cfg(not(feature = "std"))]
        false
    }
}

/// Attestation mesh - coordinates multiple attesters
pub struct AttestationMesh {
    /// Our attestation node
    node: AttestationNode,
    /// Known attesters in the mesh
    attesters: Vec<[u8; 32]>,
    /// Pending mesh attestations
    pending_mesh: BTreeMap<[u8; 32], MeshAttestation>,
}

/// Mesh attestation (multiple attesters)
#[derive(Debug, Clone)]
struct MeshAttestation {
    target_id: [u8; 32],
    certificates: Vec<AttestationCertificate>,
    started_at_ms: u64,
}

impl AttestationMesh {
    /// Create new attestation mesh
    pub fn new(node: AttestationNode) -> Self {
        Self {
            node,
            attesters: Vec::new(),
            pending_mesh: BTreeMap::new(),
        }
    }

    /// Add attester to mesh
    pub fn add_attester(&mut self, attester_id: [u8; 32]) {
        if !self.attesters.contains(&attester_id) {
            self.attesters.push(attester_id);
        }
    }

    /// Request mesh attestation for target
    pub fn request_mesh_attestation(
        &mut self,
        target_id: [u8; 32],
        current_time_ms: u64,
    ) -> Vec<AttestationRequest> {
        let mut requests = Vec::new();

        // Create request for each attester
        for attester_id in &self.attesters {
            let request = self.node.create_request(target_id, current_time_ms);
            requests.push(request);
        }

        // Track pending mesh attestation
        self.pending_mesh.insert(target_id, MeshAttestation {
            target_id,
            certificates: Vec::new(),
            started_at_ms: current_time_ms,
        });

        requests
    }

    /// Process attestation certificate from mesh
    pub fn process_mesh_certificate(
        &mut self,
        cert: AttestationCertificate,
        current_time_ms: u64,
    ) -> Result<Option<MeshConsensus>, AttestationError> {
        let target_id = cert.report.subject_id;

        // Verify certificate
        self.node.verify_certificate(&cert, current_time_ms)?;

        // Add to pending mesh attestation
        if let Some(pending) = self.pending_mesh.get_mut(&target_id) {
            pending.certificates.push(cert);

            // Check if we have consensus
            let valid_count = pending.certificates.iter()
                .filter(|c| c.result == AttestationResult::Valid)
                .count() as u32;

            if valid_count >= self.node.config.min_attesters {
                let consensus = MeshConsensus {
                    target_id,
                    result: AttestationResult::Valid,
                    attester_count: pending.certificates.len() as u32,
                    valid_count,
                    certificates: pending.certificates.clone(),
                };

                self.pending_mesh.remove(&target_id);
                return Ok(Some(consensus));
            }
        }

        Ok(None)
    }

    /// Get attestation node
    pub fn node(&self) -> &AttestationNode {
        &self.node
    }

    /// Get mutable attestation node
    pub fn node_mut(&mut self) -> &mut AttestationNode {
        &mut self.node
    }
}

/// Mesh consensus result
#[derive(Debug, Clone)]
pub struct MeshConsensus {
    /// Target that was attested
    pub target_id: [u8; 32],
    /// Overall result
    pub result: AttestationResult,
    /// Number of attesters that responded
    pub attester_count: u32,
    /// Number of valid attestations
    pub valid_count: u32,
    /// Individual certificates
    pub certificates: Vec<AttestationCertificate>,
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public = signing_key.verifying_key().to_bytes();
        let secret = signing_key.to_bytes();

        (public, secret)
    }

    fn test_state() -> AttestedState {
        AttestedState {
            hdl_manifest_hash: [0xAA; 32],
            trust_level: 2,
            config_hash: [0xBB; 32],
            version: [1, 0, 0, 0, 0, 0, 0, 0],
            pcr_values: None,
            active_alerts: 0,
            uptime_secs: 3600,
        }
    }

    #[test]
    fn test_attestation_node_creation() {
        let node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        assert!(!node.is_revoked(&[0x33; 32]));
    }

    #[test]
    fn test_node_revocation() {
        let mut node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        let target = [0x33; 32];
        assert!(!node.is_revoked(&target));

        node.revoke_node(target);
        assert!(node.is_revoked(&target));
    }

    #[test]
    fn test_attestation_request_creation() {
        let mut node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        let request = node.create_request([0x33; 32], 1000);
        assert_eq!(request.requester_id, [0x11; 32]);
        assert_eq!(request.target_id, [0x33; 32]);
        assert_ne!(request.nonce, [0u8; 32]); // Nonce should be non-zero
    }

    #[test]
    fn test_report_creation() {
        let node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        let challenge = AttestationChallenge {
            nonce: [0xAB; 32],
            deadline_ms: 2000,
            requester_id: [0x33; 32],
            target_id: [0x11; 32],
        };

        let report = node.create_report(&challenge, test_state(), 1000);
        assert_eq!(report.subject_id, [0x11; 32]);
        assert_eq!(report.nonce, [0xAB; 32]);
        assert_ne!(report.signature, [0u8; 64]); // Should be signed
    }

    #[test]
    fn test_revoked_node_attestation_fails() {
        let mut node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        let target = [0x33; 32];
        node.revoke_node(target);

        let report = AttestationReport {
            subject_id: target,
            timestamp_ms: 1000,
            nonce: [0xAB; 32],
            state: test_state(),
            signature: [0u8; 64],
        };

        let result = node.verify_report(&report, 1000).unwrap();
        assert_eq!(result, AttestationResult::NodeRevoked);
    }

    #[test]
    fn test_pcr_tampering_detected() {
        let (node_id, signing_key) = generate_keypair();
        let mut node = AttestationNode::new(
            node_id,
            signing_key,
            AttestationConfig::default(),
        );

        let request = node.create_request(node_id, 1000);
        let challenge = AttestationChallenge {
            nonce: request.nonce,
            deadline_ms: 61000,
            requester_id: node_id,
            target_id: node_id,
        };

        let mut state = test_state();
        state.pcr_values = Some(PcrValues {
            pcr0: [1; 32],
            pcr1: [2; 32],
            pcr7: [3; 32],
            pcr10: [4; 32],
        });

        let mut report = node.create_report(&challenge, state, 1000);

        // Tamper with a PCR value after signing - the outer signature bytes
        // are untouched, only the (previously-unhashed) PCR payload changes.
        if let Some(ref mut pcr) = report.state.pcr_values {
            pcr.pcr0 = [0xFF; 32];
        }

        let result = node.verify_report(&report, 1000).unwrap();
        assert_eq!(result, AttestationResult::InvalidSignature);
    }

    #[test]
    fn test_report_nonce_replay_rejected() {
        let (node_id, signing_key) = generate_keypair();
        let mut node = AttestationNode::new(
            node_id,
            signing_key,
            AttestationConfig::default(),
        );

        let request = node.create_request(node_id, 1000);
        let challenge = AttestationChallenge {
            nonce: request.nonce,
            deadline_ms: 61000,
            requester_id: node_id,
            target_id: node_id,
        };

        let report = node.create_report(&challenge, test_state(), 1000);

        let first = node.verify_report(&report, 1000).unwrap();
        assert_eq!(first, AttestationResult::Valid);

        // Replaying the exact same (validly-signed) report a second time
        // must fail - the nonce has already been consumed.
        let second = node.verify_report(&report, 1000);
        assert!(matches!(second, Err(AttestationError::UnknownNonce)));
    }

    #[test]
    fn test_report_target_mismatch_rejected() {
        let (node_id, signing_key) = generate_keypair();
        let mut node = AttestationNode::new(
            node_id,
            signing_key,
            AttestationConfig::default(),
        );

        // Challenge was issued for a DIFFERENT target than the report's
        // subject - the nonce matches (attacker replay/confusion scenario),
        // but the target binding must still catch the mismatch.
        let other_id = [0x55; 32];
        let request = node.create_request(other_id, 1000);
        let challenge = AttestationChallenge {
            nonce: request.nonce,
            deadline_ms: 61000,
            requester_id: node_id,
            target_id: other_id,
        };

        // Report claims to be from `node_id` (self), not `other_id`.
        let report = node.create_report(&challenge, test_state(), 1000);

        let result = node.verify_report(&report, 1000);
        assert!(matches!(result, Err(AttestationError::TargetMismatch)));
    }

    #[test]
    fn test_future_timestamp_within_skew_does_not_underflow() {
        let (node_id, signing_key) = generate_keypair();
        let mut node = AttestationNode::new(
            node_id,
            signing_key,
            AttestationConfig::default(),
        );

        let request = node.create_request(node_id, 1000);
        let challenge = AttestationChallenge {
            nonce: request.nonce,
            deadline_ms: 61000,
            requester_id: node_id,
            target_id: node_id,
        };

        // Report timestamped 30s ahead of "now" - within the 60s
        // future-skew allowance, but still greater than current_time_ms,
        // which used to underflow `current_time_ms - report.timestamp_ms`
        // (panic in debug/overflow-checked builds, silent wraparound to a
        // huge number - and thus a wrong `Expired` verdict - in plain
        // release).
        let report = node.create_report(&challenge, test_state(), 1030);

        let result = node.verify_report(&report, 1000);
        assert_eq!(result, Ok(AttestationResult::Valid));
    }

    #[test]
    fn test_expired_attestation() {
        let mut node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig {
                attestation_validity_ms: 1000,
                ..Default::default()
            },
        );

        let report = AttestationReport {
            subject_id: [0x33; 32],
            timestamp_ms: 1000,
            nonce: [0xAB; 32],
            state: test_state(),
            signature: [0u8; 64],
        };

        // Report is 10 seconds old, validity is 1 second
        let result = node.verify_report(&report, 11000).unwrap();
        assert_eq!(result, AttestationResult::Expired);
    }

    #[test]
    fn test_mesh_creation() {
        let node = AttestationNode::new(
            [0x11; 32],
            [0x22; 32],
            AttestationConfig::default(),
        );

        let mut mesh = AttestationMesh::new(node);
        mesh.add_attester([0x33; 32]);
        mesh.add_attester([0x44; 32]);

        assert_eq!(mesh.attesters.len(), 2);
    }
}
