//! Key Revocation with Web-of-Trust Propagation
//!
//! Implements a distributed key revocation system where revocations propagate
//! through a web-of-trust network, preventing use of compromised keys.
//!
//! # Security Model
//!
//! - Revocations require cryptographic proof (signature from key holder or
//!   threshold of trusted witnesses)
//! - Revocations are timestamped and sequenced to prevent replay
//! - Revocations propagate through trust relationships
//! - Revocation cannot be undone (keys must be re-issued)
//!
//! # Revocation Types
//!
//! 1. **Self-Revocation**: Key holder revokes their own key
//! 2. **Authority Revocation**: Root/CA revokes a subordinate key
//! 3. **Threshold Revocation**: N-of-M trusted witnesses revoke a key
//! 4. **Emergency Revocation**: Automatic revocation on security event

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Revocation reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    /// Key holder voluntarily revoked
    KeyHolderRevoked = 0x01,
    /// Key was compromised
    KeyCompromised = 0x02,
    /// Key superseded by new key
    KeySuperseded = 0x03,
    /// Affiliation changed (left organization)
    AffiliationChanged = 0x04,
    /// Certificate authority revoked
    CaRevoked = 0x05,
    /// Threshold of witnesses agreed to revoke
    ThresholdRevoked = 0x06,
    /// Automatic security event trigger
    SecurityEvent = 0x07,
    /// Unspecified reason
    Unspecified = 0xFF,
}

/// A signed revocation certificate
#[derive(Debug, Clone)]
pub struct RevocationCertificate {
    /// The key being revoked (public key hash)
    pub revoked_key_id: [u8; 32],
    /// When the revocation was issued
    pub timestamp_ms: u64,
    /// Monotonic sequence number for this revoker
    pub sequence: u64,
    /// Why the key is being revoked
    pub reason: RevocationReason,
    /// Who issued the revocation
    pub revoker_id: [u8; 32],
    /// Signature over revocation data
    pub signature: [u8; 64],
    /// Optional: hash of superseding key
    pub superseded_by: Option<[u8; 32]>,
}

impl RevocationCertificate {
    /// Create canonical bytes for signing/verification
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);

        // Magic header
        bytes.extend_from_slice(b"AXIOM-REVOKE\x00\x01");

        // Revoked key
        bytes.extend_from_slice(&self.revoked_key_id);

        // Timestamp
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());

        // Sequence
        bytes.extend_from_slice(&self.sequence.to_le_bytes());

        // Reason
        bytes.push(self.reason as u8);

        // Revoker
        bytes.extend_from_slice(&self.revoker_id);

        // Superseded by (optional)
        if let Some(ref new_key) = self.superseded_by {
            bytes.push(0x01);
            bytes.extend_from_slice(new_key);
        } else {
            bytes.push(0x00);
        }

        bytes
    }

    /// Verify the signature on this certificate
    pub fn verify(&self, revoker_public_key: &[u8; 32]) -> bool {
        let message = self.canonical_bytes();

        // Ed25519 verification
        use ed25519_dalek::{Signature, VerifyingKey};

        let Ok(verifying_key) = VerifyingKey::from_bytes(revoker_public_key) else {
            return false;
        };

        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };

        use ed25519_dalek::Verifier;
        verifying_key.verify(&message, &signature).is_ok()
    }
}

/// Witness vote for threshold revocation
#[derive(Debug, Clone)]
pub struct RevocationWitness {
    /// The key being revoked
    pub revoked_key_id: [u8; 32],
    /// Witness public key
    pub witness_id: [u8; 32],
    /// When the witness voted
    pub timestamp_ms: u64,
    /// Reason provided by witness
    pub reason: RevocationReason,
    /// Signature from witness
    pub signature: [u8; 64],
}

impl RevocationWitness {
    /// Create canonical bytes for signing/verification
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);

        bytes.extend_from_slice(b"AXIOM-WITNESS\x00\x01");
        bytes.extend_from_slice(&self.revoked_key_id);
        bytes.extend_from_slice(&self.witness_id);
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.push(self.reason as u8);

        bytes
    }

    /// Verify witness signature
    pub fn verify(&self, witness_public_key: &[u8; 32]) -> bool {
        let message = self.canonical_bytes();

        use ed25519_dalek::{Signature, VerifyingKey, Verifier};

        let Ok(verifying_key) = VerifyingKey::from_bytes(witness_public_key) else {
            return false;
        };

        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };

        verifying_key.verify(&message, &signature).is_ok()
    }
}

/// Entry in the revocation database
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    /// The revocation certificate
    pub certificate: RevocationCertificate,
    /// When we received this revocation
    pub received_at_ms: u64,
    /// How we learned of this revocation
    pub source: RevocationSource,
    /// Witness votes (for threshold revocations)
    pub witnesses: Vec<RevocationWitness>,
}

/// How a revocation was received
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationSource {
    /// Direct from key holder
    Direct,
    /// From certificate authority
    Authority,
    /// Propagated through web of trust
    WebOfTrust { from_peer: [u8; 32] },
    /// From revocation broadcast
    Broadcast,
    /// From CRL (Certificate Revocation List)
    Crl,
}

/// Configuration for web-of-trust propagation
#[derive(Debug, Clone)]
pub struct WebOfTrustConfig {
    /// Minimum trust level to accept propagated revocations
    pub min_trust_level: u8,
    /// Maximum hops for revocation propagation
    pub max_propagation_hops: u8,
    /// Threshold for witness-based revocation (N of M)
    pub witness_threshold: (u8, u8),
    /// Maximum age for revocation certificates (ms)
    pub max_certificate_age_ms: u64,
    /// Whether to accept self-revocations
    pub allow_self_revocation: bool,
}

impl Default for WebOfTrustConfig {
    fn default() -> Self {
        Self {
            min_trust_level: 3,
            max_propagation_hops: 5,
            witness_threshold: (3, 5), // 3 of 5 witnesses
            max_certificate_age_ms: 365 * 24 * 60 * 60 * 1000, // 1 year
            allow_self_revocation: true,
        }
    }
}

/// Trust relationship for web-of-trust
#[derive(Debug, Clone)]
pub struct TrustRelationship {
    /// The trusted peer's public key
    pub peer_id: [u8; 32],
    /// Trust level (0-255, higher = more trusted)
    pub trust_level: u8,
    /// Can this peer propagate revocations?
    pub can_propagate_revocations: bool,
    /// Can this peer act as a witness?
    pub can_witness: bool,
    /// When this relationship was established
    pub established_at_ms: u64,
}

/// Session invalidation callback type
pub type SessionInvalidator = alloc::boxed::Box<dyn Fn(&[u8; 32]) + Send + Sync>;

/// Key Revocation Manager
pub struct RevocationManager {
    /// Our identity
    node_id: [u8; 32],
    /// Configuration
    config: WebOfTrustConfig,
    /// Revoked keys database
    revoked_keys: BTreeMap<[u8; 32], RevocationEntry>,
    /// Pending threshold revocations (accumulating witnesses)
    pending_threshold: BTreeMap<[u8; 32], Vec<RevocationWitness>>,
    /// Trust relationships
    trust_relationships: BTreeMap<[u8; 32], TrustRelationship>,
    /// Sequence numbers for our revocations
    our_sequence: u64,
    /// Keys we've issued (for authority revocation) - i.e. keys THIS node
    /// is the authority for. Gates `create_authority_revocation` (the send
    /// path for our own authority).
    issued_keys: Vec<[u8; 32]>,
    /// Authorized revokers for a given key, keyed by the revoked key's ID.
    /// This is the receive-path counterpart to `issued_keys`: it records
    /// which REMOTE authorities are trusted to revoke a given key, so
    /// `process_revocation` can verify that an incoming Authority/
    /// Broadcast/Crl-sourced revocation's `revoker_id` actually had
    /// authority over the key it claims to revoke - not just that the
    /// certificate is self-consistently signed by whoever `revoker_id`
    /// claims to be.
    key_issuers: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    /// Session invalidation callbacks - called when a key is revoked
    session_invalidators: Vec<SessionInvalidator>,
}

impl RevocationManager {
    /// Create new revocation manager
    pub fn new(node_id: [u8; 32], config: WebOfTrustConfig) -> Self {
        Self {
            node_id,
            config,
            revoked_keys: BTreeMap::new(),
            pending_threshold: BTreeMap::new(),
            trust_relationships: BTreeMap::new(),
            our_sequence: 0,
            issued_keys: Vec::new(),
            key_issuers: BTreeMap::new(),
            session_invalidators: Vec::new(),
        }
    }

    /// Register a session invalidation callback
    ///
    /// This callback will be invoked whenever a key is revoked,
    /// allowing active sessions using that key to be terminated.
    pub fn register_session_invalidator<F>(&mut self, callback: F)
    where
        F: Fn(&[u8; 32]) + Send + Sync + 'static,
    {
        self.session_invalidators.push(alloc::boxed::Box::new(callback));
    }

    /// Invoke session invalidators for a revoked key
    fn invalidate_sessions(&self, key_id: &[u8; 32]) {
        for invalidator in &self.session_invalidators {
            invalidator(key_id);
        }
    }

    /// Check if a key is revoked
    pub fn is_revoked(&self, key_id: &[u8; 32]) -> bool {
        self.revoked_keys.contains_key(key_id)
    }

    /// Get revocation details if key is revoked
    pub fn get_revocation(&self, key_id: &[u8; 32]) -> Option<&RevocationEntry> {
        self.revoked_keys.get(key_id)
    }

    /// Add a trust relationship
    pub fn add_trust(&mut self, relationship: TrustRelationship) {
        self.trust_relationships.insert(relationship.peer_id, relationship);
    }

    /// Remove a trust relationship
    pub fn remove_trust(&mut self, peer_id: &[u8; 32]) {
        self.trust_relationships.remove(peer_id);
    }

    /// Register a key we've issued (for authority revocation)
    pub fn register_issued_key(&mut self, key_id: [u8; 32]) {
        if !self.issued_keys.contains(&key_id) {
            self.issued_keys.push(key_id);
        }
    }

    /// Register `issuer_id` as an authority permitted to revoke `key_id`.
    ///
    /// Receive-path counterpart to `register_issued_key`: this is what lets
    /// `process_revocation` accept an Authority/Broadcast/Crl-sourced
    /// revocation for `key_id` from a REMOTE node, without accepting one
    /// from just anyone who can self-consistently sign a certificate.
    pub fn register_key_issuer(&mut self, key_id: [u8; 32], issuer_id: [u8; 32]) {
        let issuers = self.key_issuers.entry(key_id).or_insert_with(Vec::new);
        if !issuers.contains(&issuer_id) {
            issuers.push(issuer_id);
        }
    }

    /// Whether `revoker_id` is a registered authority for `key_id` (i.e.
    /// was registered via `register_key_issuer`).
    fn is_registered_authority(&self, key_id: &[u8; 32], revoker_id: &[u8; 32]) -> bool {
        self.key_issuers
            .get(key_id)
            .is_some_and(|issuers| issuers.contains(revoker_id))
    }

    /// Process incoming revocation certificate
    pub fn process_revocation(
        &mut self,
        certificate: RevocationCertificate,
        source: RevocationSource,
        current_time_ms: u64,
    ) -> Result<RevocationAction, RevocationError> {
        // Check if already revoked
        if self.revoked_keys.contains_key(&certificate.revoked_key_id) {
            return Ok(RevocationAction::AlreadyRevoked);
        }

        // Validate certificate age
        if current_time_ms.saturating_sub(certificate.timestamp_ms) > self.config.max_certificate_age_ms {
            return Err(RevocationError::CertificateExpired);
        }

        // Validate based on source
        match &source {
            RevocationSource::Direct => {
                // Self-revocation: revoker must be the key being revoked
                if !self.config.allow_self_revocation {
                    return Err(RevocationError::SelfRevocationDisabled);
                }
                if certificate.revoker_id != certificate.revoked_key_id {
                    return Err(RevocationError::InvalidRevoker);
                }
                // Verify signature with the key being revoked
                if !certificate.verify(&certificate.revoked_key_id) {
                    return Err(RevocationError::InvalidSignature);
                }
            }
            RevocationSource::Authority => {
                // Authority revocation: the revoker must be a registered
                // authority for the key it claims to revoke - a
                // self-consistent signature alone only proves the cert
                // wasn't tampered with, not that the signer was ever
                // entitled to revoke this particular key.
                if !certificate.verify(&certificate.revoker_id) {
                    return Err(RevocationError::InvalidSignature);
                }
                if !self.is_registered_authority(&certificate.revoked_key_id, &certificate.revoker_id) {
                    return Err(RevocationError::NotAuthorized);
                }
            }
            RevocationSource::WebOfTrust { from_peer } => {
                // Check trust relationship - this gates the TRANSPORT
                // (is from_peer allowed to relay revocations to us at
                // all), same role as the Broadcast/Crl arm's own
                // transport check below. It does NOT gate the inner
                // certificate's own authority to revoke the key it names.
                let Some(trust) = self.trust_relationships.get(from_peer) else {
                    return Err(RevocationError::UntrustedSource);
                };

                if trust.trust_level < self.config.min_trust_level {
                    return Err(RevocationError::InsufficientTrust);
                }

                if !trust.can_propagate_revocations {
                    return Err(RevocationError::PropagationNotAllowed);
                }

                // AXIOM-14 Cycle 7 (Fable diff review, required): the inner
                // certificate must still validate under Direct-or-Authority
                // semantics, same as Broadcast/Crl below - a trusted peer
                // being ALLOWED TO RELAY revocations is not the same thing
                // as every revocation it relays being LEGITIMATE. Before
                // this fix the certificate was only checked for bare
                // self-consistency (a signature from whoever `revoker_id`
                // claims to be, unconstrained) - any single peer with
                // `can_propagate_revocations` could mint a throwaway
                // keypair and revoke ANY key by relaying a self-consistent
                // cert through itself. That's origination, not
                // propagation, and it silently defeated the Authority-arm
                // fix above for anything routed through WebOfTrust instead.
                let is_self_revocation = certificate.revoker_id == certificate.revoked_key_id;

                if is_self_revocation {
                    if !self.config.allow_self_revocation {
                        return Err(RevocationError::SelfRevocationDisabled);
                    }
                    if !certificate.verify(&certificate.revoked_key_id) {
                        return Err(RevocationError::InvalidSignature);
                    }
                } else {
                    if !certificate.verify(&certificate.revoker_id) {
                        return Err(RevocationError::InvalidSignature);
                    }
                    if !self.is_registered_authority(&certificate.revoked_key_id, &certificate.revoker_id) {
                        return Err(RevocationError::NotAuthorized);
                    }
                }
            }
            RevocationSource::Broadcast | RevocationSource::Crl => {
                // Broadcast/CRL are TRANSPORTS, not separate authority
                // classes - a certificate arriving via either must still
                // validate under either Direct semantics (self-revocation:
                // revoker == the revoked key's own owner) or Authority
                // semantics (revoker is a registered authority for this
                // key). Never bare self-consistency alone.
                let is_self_revocation = certificate.revoker_id == certificate.revoked_key_id;

                if is_self_revocation {
                    if !self.config.allow_self_revocation {
                        return Err(RevocationError::SelfRevocationDisabled);
                    }
                    if !certificate.verify(&certificate.revoked_key_id) {
                        return Err(RevocationError::InvalidSignature);
                    }
                } else {
                    if !certificate.verify(&certificate.revoker_id) {
                        return Err(RevocationError::InvalidSignature);
                    }
                    if !self.is_registered_authority(&certificate.revoked_key_id, &certificate.revoker_id) {
                        return Err(RevocationError::NotAuthorized);
                    }
                }
            }
        }

        // Store revocation
        let entry = RevocationEntry {
            certificate,
            received_at_ms: current_time_ms,
            source,
            witnesses: Vec::new(),
        };

        let key_id = entry.certificate.revoked_key_id;
        self.revoked_keys.insert(key_id, entry);

        // Invalidate any active sessions using this key
        self.invalidate_sessions(&key_id);

        Ok(RevocationAction::Revoked { key_id })
    }

    /// Process witness vote for threshold revocation
    pub fn process_witness_vote(
        &mut self,
        witness: RevocationWitness,
        witness_public_key: &[u8; 32],
        current_time_ms: u64,
    ) -> Result<RevocationAction, RevocationError> {
        // Check if already revoked
        if self.revoked_keys.contains_key(&witness.revoked_key_id) {
            return Ok(RevocationAction::AlreadyRevoked);
        }

        // Verify witness is trusted
        let Some(trust) = self.trust_relationships.get(witness_public_key) else {
            return Err(RevocationError::UntrustedSource);
        };

        if !trust.can_witness {
            return Err(RevocationError::WitnessNotAllowed);
        }

        // Verify witness signature
        if !witness.verify(witness_public_key) {
            return Err(RevocationError::InvalidSignature);
        }

        // The signed `witness_id` field must match the key that actually
        // produced the signature. Without this, an attacker who controls
        // `witness_public_key` can still forge a witness record that CLAIMS
        // a different (e.g. victim's) `witness_id` - the signature alone
        // only proves whoever holds `witness_public_key` signed a message
        // that happens to embed some `witness_id` value, not that the two
        // are the same key. Left unchecked, this would poison any
        // downstream reader that trusts stored `witness_id` fields (dedup
        // below is keyed on the verified `witness_public_key`, not on this
        // field, so dedup itself was already safe - but nothing else that
        // reads `RevocationWitness.witness_id` was).
        if witness.witness_id != *witness_public_key {
            return Err(RevocationError::WitnessIdMismatch);
        }

        // Add to pending threshold revocations
        let pending = self.pending_threshold
            .entry(witness.revoked_key_id)
            .or_insert_with(Vec::new);

        // Check for duplicate witness
        if pending.iter().any(|w| w.witness_id == witness.witness_id) {
            return Err(RevocationError::DuplicateWitness);
        }

        let key_id = witness.revoked_key_id;
        pending.push(witness);

        // Check if threshold reached
        let (required, _total) = self.config.witness_threshold;
        if pending.len() >= required as usize {
            // Threshold reached - create revocation
            let key_id = pending[0].revoked_key_id;
            let witnesses = self.pending_threshold.remove(&key_id).unwrap();

            // Create threshold revocation certificate
            // (In production, this would be signed by the threshold witnesses)
            //
            // KNOWN LIMITATION (flagged, not fixed, this cycle - proportionate
            // to this being dormant code with zero production callers today):
            // this cert has `revoker_id = [0; 32]` and an all-zero
            // `signature`. `RevocationCertificate::verify()` will return
            // `false` for it, like for any cert with a placeholder
            // signature - it is NOT a validly-signed certificate and must
            // never be re-verified as if it were one. The only safe
            // discriminator available today is
            // `reason == RevocationReason::ThresholdRevoked`; any future
            // code path that re-verifies stored `RevocationEntry`
            // certificates (e.g. on rehydration from persistent storage,
            // export/import, or re-propagation to a peer) MUST special-case
            // `ThresholdRevoked` entries rather than calling `.verify()` on
            // them. A proper fix would give threshold-derived entries a
            // distinct type (or an aggregate-signature variant) instead of
            // a synthetic zeroed single-signer cert - left for a future
            // cycle since it would ripple into serialize/deserialize and
            // every other `.verify()` call site.
            let certificate = RevocationCertificate {
                revoked_key_id: key_id,
                timestamp_ms: current_time_ms,
                sequence: 0,
                reason: RevocationReason::ThresholdRevoked,
                revoker_id: [0u8; 32], // Threshold revocation has no single revoker
                signature: [0u8; 64],  // Would be aggregate signature
                superseded_by: None,
            };

            let entry = RevocationEntry {
                certificate,
                received_at_ms: current_time_ms,
                source: RevocationSource::Direct,
                witnesses,
            };

            self.revoked_keys.insert(key_id, entry);

            // Invalidate any active sessions using this key
            self.invalidate_sessions(&key_id);

            return Ok(RevocationAction::ThresholdReached { key_id });
        }

        Ok(RevocationAction::WitnessRecorded {
            key_id,
            current_witnesses: pending.len(),
            required: required as usize,
        })
    }

    /// Create self-revocation for our own key
    pub fn create_self_revocation(
        &mut self,
        signing_key: &[u8; 32],
        reason: RevocationReason,
        superseded_by: Option<[u8; 32]>,
        current_time_ms: u64,
    ) -> RevocationCertificate {
        self.our_sequence += 1;

        let mut cert = RevocationCertificate {
            revoked_key_id: self.node_id,
            timestamp_ms: current_time_ms,
            sequence: self.our_sequence,
            reason,
            revoker_id: self.node_id,
            signature: [0u8; 64],
            superseded_by,
        };

        // Sign the certificate
        let message = cert.canonical_bytes();

        use ed25519_dalek::{SigningKey, Signer};
        let signing = SigningKey::from_bytes(signing_key);
        let signature = signing.sign(&message);
        cert.signature = signature.to_bytes();

        cert
    }

    /// Create authority revocation for a key we issued
    pub fn create_authority_revocation(
        &mut self,
        key_to_revoke: [u8; 32],
        signing_key: &[u8; 32],
        reason: RevocationReason,
        current_time_ms: u64,
    ) -> Result<RevocationCertificate, RevocationError> {
        // Check we issued this key
        if !self.issued_keys.contains(&key_to_revoke) {
            return Err(RevocationError::NotAuthorized);
        }

        self.our_sequence += 1;

        let mut cert = RevocationCertificate {
            revoked_key_id: key_to_revoke,
            timestamp_ms: current_time_ms,
            sequence: self.our_sequence,
            reason,
            revoker_id: self.node_id,
            signature: [0u8; 64],
            superseded_by: None,
        };

        // Sign the certificate
        let message = cert.canonical_bytes();

        use ed25519_dalek::{SigningKey, Signer};
        let signing = SigningKey::from_bytes(signing_key);
        let signature = signing.sign(&message);
        cert.signature = signature.to_bytes();

        Ok(cert)
    }

    /// Get revocations to propagate to peers
    pub fn get_propagatable_revocations(&self, since_ms: u64) -> Vec<&RevocationEntry> {
        self.revoked_keys
            .values()
            .filter(|entry| entry.received_at_ms >= since_ms)
            .collect()
    }

    /// Serialize revocation for network transmission
    pub fn serialize_revocation(cert: &RevocationCertificate) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);

        // Header
        bytes.extend_from_slice(b"AXIOM-REV\x00\x01");

        // Certificate data
        bytes.extend_from_slice(&cert.revoked_key_id);
        bytes.extend_from_slice(&cert.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&cert.sequence.to_le_bytes());
        bytes.push(cert.reason as u8);
        bytes.extend_from_slice(&cert.revoker_id);
        bytes.extend_from_slice(&cert.signature);

        // Superseded by
        if let Some(ref new_key) = cert.superseded_by {
            bytes.push(0x01);
            bytes.extend_from_slice(new_key);
        } else {
            bytes.push(0x00);
        }

        bytes
    }

    /// Deserialize revocation from network
    pub fn deserialize_revocation(data: &[u8]) -> Result<RevocationCertificate, RevocationError> {
        // Minimum size check. Header is 11 bytes ("AXIOM-REV" is 9 ASCII
        // bytes + 2 version bytes, \x00\x01) - this used to say 10 and read
        // one byte short everywhere below, so the header comparison could
        // never match its own serializer's output and every field after it
        // was read one byte out of alignment.
        if data.len() < 11 + 32 + 8 + 8 + 1 + 32 + 64 + 1 {
            return Err(RevocationError::MalformedData);
        }

        // Verify header
        if &data[0..11] != b"AXIOM-REV\x00\x01" {
            return Err(RevocationError::InvalidHeader);
        }

        let mut offset = 11;

        // Revoked key ID
        let mut revoked_key_id = [0u8; 32];
        revoked_key_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Timestamp
        let timestamp_ms = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Sequence
        let sequence = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Reason
        let reason = match data[offset] {
            0x01 => RevocationReason::KeyHolderRevoked,
            0x02 => RevocationReason::KeyCompromised,
            0x03 => RevocationReason::KeySuperseded,
            0x04 => RevocationReason::AffiliationChanged,
            0x05 => RevocationReason::CaRevoked,
            0x06 => RevocationReason::ThresholdRevoked,
            0x07 => RevocationReason::SecurityEvent,
            _ => RevocationReason::Unspecified,
        };
        offset += 1;

        // Revoker ID
        let mut revoker_id = [0u8; 32];
        revoker_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Signature
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;

        // Superseded by
        let superseded_by = if data[offset] == 0x01 {
            if data.len() < offset + 1 + 32 {
                return Err(RevocationError::MalformedData);
            }
            let mut new_key = [0u8; 32];
            new_key.copy_from_slice(&data[offset + 1..offset + 33]);
            Some(new_key)
        } else {
            None
        };

        Ok(RevocationCertificate {
            revoked_key_id,
            timestamp_ms,
            sequence,
            reason,
            revoker_id,
            signature,
            superseded_by,
        })
    }
}

/// Result of processing a revocation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationAction {
    /// Key was successfully revoked
    Revoked { key_id: [u8; 32] },
    /// Key was already revoked
    AlreadyRevoked,
    /// Witness vote recorded, threshold not yet reached
    WitnessRecorded {
        key_id: [u8; 32],
        current_witnesses: usize,
        required: usize,
    },
    /// Threshold reached, key revoked
    ThresholdReached { key_id: [u8; 32] },
}

/// Revocation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    /// Certificate has expired
    CertificateExpired,
    /// Self-revocation is disabled
    SelfRevocationDisabled,
    /// Revoker is not authorized
    InvalidRevoker,
    /// Signature verification failed
    InvalidSignature,
    /// Source is not trusted
    UntrustedSource,
    /// Trust level is too low
    InsufficientTrust,
    /// Peer cannot propagate revocations
    PropagationNotAllowed,
    /// Peer cannot act as witness
    WitnessNotAllowed,
    /// Duplicate witness vote
    DuplicateWitness,
    /// Witness's signed `witness_id` field doesn't match the key that
    /// actually produced the signature
    WitnessIdMismatch,
    /// Not authorized to revoke this key
    NotAuthorized,
    /// Data is malformed
    MalformedData,
    /// Invalid header
    InvalidHeader,
}

impl core::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CertificateExpired => write!(f, "Revocation certificate has expired"),
            Self::SelfRevocationDisabled => write!(f, "Self-revocation is disabled"),
            Self::InvalidRevoker => write!(f, "Revoker is not authorized for this key"),
            Self::InvalidSignature => write!(f, "Revocation signature verification failed"),
            Self::UntrustedSource => write!(f, "Revocation source is not trusted"),
            Self::InsufficientTrust => write!(f, "Source trust level is too low"),
            Self::PropagationNotAllowed => write!(f, "Peer cannot propagate revocations"),
            Self::WitnessNotAllowed => write!(f, "Peer cannot act as witness"),
            Self::DuplicateWitness => write!(f, "Duplicate witness vote"),
            Self::WitnessIdMismatch => write!(f, "Witness id does not match the signing key"),
            Self::NotAuthorized => write!(f, "Not authorized to revoke this key"),
            Self::MalformedData => write!(f, "Revocation data is malformed"),
            Self::InvalidHeader => write!(f, "Invalid revocation header"),
        }
    }
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
        let private = signing_key.to_bytes();
        let public = signing_key.verifying_key().to_bytes();

        (private, public)
    }

    #[test]
    fn test_self_revocation() {
        let (private_key, public_key) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new(public_key, config);

        // Create self-revocation
        let cert = manager.create_self_revocation(
            &private_key,
            RevocationReason::KeySuperseded,
            None,
            1000,
        );

        // Verify signature
        assert!(cert.verify(&public_key));

        // Process the revocation
        let result = manager.process_revocation(
            cert,
            RevocationSource::Direct,
            1000,
        );

        assert!(matches!(result, Ok(RevocationAction::Revoked { .. })));
        assert!(manager.is_revoked(&public_key));
    }

    #[test]
    fn test_already_revoked() {
        let (private_key, public_key) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new(public_key, config);

        let cert = manager.create_self_revocation(
            &private_key,
            RevocationReason::KeyCompromised,
            None,
            1000,
        );

        // First revocation succeeds
        manager.process_revocation(cert.clone(), RevocationSource::Direct, 1000).unwrap();

        // Second revocation returns AlreadyRevoked
        let result = manager.process_revocation(cert, RevocationSource::Direct, 1001);
        assert!(matches!(result, Ok(RevocationAction::AlreadyRevoked)));
    }

    #[test]
    fn test_expired_certificate() {
        let (private_key, public_key) = generate_keypair();

        let config = WebOfTrustConfig {
            max_certificate_age_ms: 1000,
            ..Default::default()
        };
        let mut manager = RevocationManager::new(public_key, config);

        let cert = manager.create_self_revocation(
            &private_key,
            RevocationReason::KeyCompromised,
            None,
            1000, // Old timestamp
        );

        // Try to process at much later time
        let result = manager.process_revocation(
            cert,
            RevocationSource::Direct,
            10000, // 9 seconds later, but max age is 1 second
        );

        assert!(matches!(result, Err(RevocationError::CertificateExpired)));
    }

    #[test]
    fn test_authority_revocation() {
        let (authority_private, authority_public) = generate_keypair();
        let (_subordinate_private, subordinate_public) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new(authority_public, config);

        // Register the subordinate key as issued by us (send-path gate for
        // `create_authority_revocation`)
        manager.register_issued_key(subordinate_public);
        // Also register ourselves as a recognized authority for that key on
        // the RECEIVE path - `issued_keys` alone no longer gates
        // `process_revocation`'s Authority branch, by design (see
        // `register_key_issuer` doc comment).
        manager.register_key_issuer(subordinate_public, authority_public);

        // Create authority revocation
        let cert = manager.create_authority_revocation(
            subordinate_public,
            &authority_private,
            RevocationReason::CaRevoked,
            1000,
        ).unwrap();

        // Verify signature
        assert!(cert.verify(&authority_public));

        // Process the revocation
        let result = manager.process_revocation(
            cert,
            RevocationSource::Authority,
            1000,
        );

        assert!(matches!(result, Ok(RevocationAction::Revoked { .. })));
        assert!(manager.is_revoked(&subordinate_public));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (private_key, public_key) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new(public_key, config);

        let original = manager.create_self_revocation(
            &private_key,
            RevocationReason::KeyCompromised,
            Some([0xAB; 32]),
            1000,
        );

        let serialized = RevocationManager::serialize_revocation(&original);
        let deserialized = RevocationManager::deserialize_revocation(&serialized).unwrap();

        assert_eq!(original.revoked_key_id, deserialized.revoked_key_id);
        assert_eq!(original.timestamp_ms, deserialized.timestamp_ms);
        assert_eq!(original.sequence, deserialized.sequence);
        assert_eq!(original.revoker_id, deserialized.revoker_id);
        assert_eq!(original.signature, deserialized.signature);
        assert_eq!(original.superseded_by, deserialized.superseded_by);
    }

    #[test]
    fn test_threshold_revocation() {
        let (_, node_public) = generate_keypair();
        let target_key = [0xAA; 32];

        let config = WebOfTrustConfig {
            witness_threshold: (2, 3), // 2 of 3 required
            ..Default::default()
        };
        let mut manager = RevocationManager::new(node_public, config);

        // Add trusted witnesses
        let (witness1_private, witness1_public) = generate_keypair();
        let (witness2_private, witness2_public) = generate_keypair();

        manager.add_trust(TrustRelationship {
            peer_id: witness1_public,
            trust_level: 10,
            can_propagate_revocations: true,
            can_witness: true,
            established_at_ms: 0,
        });

        manager.add_trust(TrustRelationship {
            peer_id: witness2_public,
            trust_level: 10,
            can_propagate_revocations: true,
            can_witness: true,
            established_at_ms: 0,
        });

        // Create witness votes
        let create_witness = |private: &[u8; 32], public: [u8; 32], timestamp: u64| {
            use ed25519_dalek::{SigningKey, Signer};

            let mut witness = RevocationWitness {
                revoked_key_id: target_key,
                witness_id: public,
                timestamp_ms: timestamp,
                reason: RevocationReason::KeyCompromised,
                signature: [0u8; 64],
            };

            let message = witness.canonical_bytes();
            let signing = SigningKey::from_bytes(private);
            witness.signature = signing.sign(&message).to_bytes();

            witness
        };

        let witness1_vote = create_witness(&witness1_private, witness1_public, 1000);
        let witness2_vote = create_witness(&witness2_private, witness2_public, 1001);

        // First witness - threshold not reached
        let result = manager.process_witness_vote(witness1_vote, &witness1_public, 1000).unwrap();
        assert!(matches!(result, RevocationAction::WitnessRecorded { current_witnesses: 1, required: 2, .. }));
        assert!(!manager.is_revoked(&target_key));

        // Second witness - threshold reached
        let result = manager.process_witness_vote(witness2_vote, &witness2_public, 1001).unwrap();
        assert!(matches!(result, RevocationAction::ThresholdReached { .. }));
        assert!(manager.is_revoked(&target_key));
    }

    #[test]
    fn test_authority_revocation_rejected_without_registration() {
        // Attacker controls a keypair and self-consistently signs a
        // revocation certificate CLAIMING to be an authority for someone
        // else's key. No `register_key_issuer` call has ever happened for
        // that key/attacker pair. This must be rejected - a self-consistent
        // signature alone is not proof of authority.
        let (_victim_private, victim_public) = generate_keypair();
        let (attacker_private, attacker_public) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new([0x99; 32], config);

        use ed25519_dalek::{SigningKey, Signer};
        let mut cert = RevocationCertificate {
            revoked_key_id: victim_public,
            timestamp_ms: 1000,
            sequence: 1,
            reason: RevocationReason::KeyCompromised,
            revoker_id: attacker_public,
            signature: [0u8; 64],
            superseded_by: None,
        };
        let message = cert.canonical_bytes();
        let signing = SigningKey::from_bytes(&attacker_private);
        cert.signature = signing.sign(&message).to_bytes();

        // Sanity: the certificate IS validly self-consistently signed.
        assert!(cert.verify(&attacker_public));

        let result = manager.process_revocation(cert, RevocationSource::Authority, 1000);
        assert!(matches!(result, Err(RevocationError::NotAuthorized)));
        assert!(!manager.is_revoked(&victim_public));
        let _ = attacker_private;
    }

    #[test]
    fn test_authority_revocation_accepted_with_registration() {
        // Same shape as above, but the revoker WAS registered as an
        // authority for this key via `register_key_issuer` - must be
        // accepted.
        let (victim_private, victim_public) = generate_keypair();
        let (authority_private, authority_public) = generate_keypair();
        let _ = victim_private;

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new([0x99; 32], config);
        manager.register_key_issuer(victim_public, authority_public);

        use ed25519_dalek::{SigningKey, Signer};
        let mut cert = RevocationCertificate {
            revoked_key_id: victim_public,
            timestamp_ms: 1000,
            sequence: 1,
            reason: RevocationReason::CaRevoked,
            revoker_id: authority_public,
            signature: [0u8; 64],
            superseded_by: None,
        };
        let message = cert.canonical_bytes();
        let signing = SigningKey::from_bytes(&authority_private);
        cert.signature = signing.sign(&message).to_bytes();

        let result = manager.process_revocation(cert, RevocationSource::Authority, 1000);
        assert!(matches!(result, Ok(RevocationAction::Revoked { .. })));
        assert!(manager.is_revoked(&victim_public));
    }

    #[test]
    fn test_web_of_trust_relay_rejects_unauthorized_revoker() {
        // AXIOM-14 Cycle 7 (Fable diff review, required): a trusted
        // relay peer being ALLOWED TO PROPAGATE revocations is not the
        // same as every revocation it relays being LEGITIMATE. The
        // relay (from_peer) here is genuinely trusted and genuinely
        // allowed to propagate - but the INNER certificate it relays
        // claims a throwaway attacker keypair as the revoker for
        // someone else's key, with no registered authority. Before this
        // fix, WebOfTrust only checked the inner cert for bare
        // self-consistency (a signature from whoever revoker_id claims
        // to be) - this test would have passed on that broken code,
        // which is exactly why it needed fixing: origination disguised
        // as propagation.
        let (_victim_private, victim_public) = generate_keypair();
        let (attacker_private, attacker_public) = generate_keypair();
        let (_relay_private, relay_public) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new([0x99; 32], config);
        manager.add_trust(TrustRelationship {
            peer_id: relay_public,
            trust_level: 10,
            can_propagate_revocations: true,
            can_witness: true,
            established_at_ms: 0,
        });

        use ed25519_dalek::{SigningKey, Signer};
        let mut cert = RevocationCertificate {
            revoked_key_id: victim_public,
            timestamp_ms: 1000,
            sequence: 1,
            reason: RevocationReason::KeyCompromised,
            revoker_id: attacker_public,
            signature: [0u8; 64],
            superseded_by: None,
        };
        let message = cert.canonical_bytes();
        let signing = SigningKey::from_bytes(&attacker_private);
        cert.signature = signing.sign(&message).to_bytes();

        // Sanity: the certificate IS validly self-consistently signed,
        // and the relay IS genuinely trusted to propagate - the ONLY
        // thing wrong is the inner cert's revoker has no authority.
        assert!(cert.verify(&attacker_public));

        let result = manager.process_revocation(
            cert,
            RevocationSource::WebOfTrust { from_peer: relay_public },
            1000,
        );
        assert!(matches!(result, Err(RevocationError::NotAuthorized)));
        assert!(!manager.is_revoked(&victim_public));
        let _ = attacker_private;
    }

    #[test]
    fn test_witness_threshold_duplicate_public_key_not_counted() {
        let (_, node_public) = generate_keypair();
        let target_key = [0xAA; 32];

        let config = WebOfTrustConfig {
            witness_threshold: (2, 3),
            ..Default::default()
        };
        let mut manager = RevocationManager::new(node_public, config);

        let (witness1_private, witness1_public) = generate_keypair();

        manager.add_trust(TrustRelationship {
            peer_id: witness1_public,
            trust_level: 10,
            can_propagate_revocations: true,
            can_witness: true,
            established_at_ms: 0,
        });

        use ed25519_dalek::{SigningKey, Signer};
        let make_vote = |timestamp: u64| {
            let mut witness = RevocationWitness {
                revoked_key_id: target_key,
                witness_id: witness1_public,
                timestamp_ms: timestamp,
                reason: RevocationReason::KeyCompromised,
                signature: [0u8; 64],
            };
            let message = witness.canonical_bytes();
            let signing = SigningKey::from_bytes(&witness1_private);
            witness.signature = signing.sign(&message).to_bytes();
            witness
        };

        // First vote from witness1 is recorded.
        let first = manager.process_witness_vote(make_vote(1000), &witness1_public, 1000).unwrap();
        assert!(matches!(first, RevocationAction::WitnessRecorded { current_witnesses: 1, .. }));

        // Second vote, same `witness_public_key` (same actual signer) again
        // - even with a different timestamp, it must NOT count a second
        // time toward the threshold.
        let second = manager.process_witness_vote(make_vote(1001), &witness1_public, 1001);
        assert!(matches!(second, Err(RevocationError::DuplicateWitness)));
        assert!(!manager.is_revoked(&target_key));
    }

    #[test]
    fn test_witness_id_mismatch_rejected_and_not_counted() {
        let (_, node_public) = generate_keypair();
        let target_key = [0xAA; 32];

        let config = WebOfTrustConfig {
            witness_threshold: (2, 3),
            ..Default::default()
        };
        let mut manager = RevocationManager::new(node_public, config);

        let (witness1_private, witness1_public) = generate_keypair();
        let (_, some_other_id) = generate_keypair();

        manager.add_trust(TrustRelationship {
            peer_id: witness1_public,
            trust_level: 10,
            can_propagate_revocations: true,
            can_witness: true,
            established_at_ms: 0,
        });

        use ed25519_dalek::{SigningKey, Signer};
        // witness1 actually signs, but the record's `witness_id` field
        // claims a different (fabricated) identity than the signing key.
        let mut witness = RevocationWitness {
            revoked_key_id: target_key,
            witness_id: some_other_id,
            timestamp_ms: 1000,
            reason: RevocationReason::KeyCompromised,
            signature: [0u8; 64],
        };
        let message = witness.canonical_bytes();
        let signing = SigningKey::from_bytes(&witness1_private);
        witness.signature = signing.sign(&message).to_bytes();

        // The signature itself IS valid for witness1_public (it committed
        // to the fabricated witness_id at signing time).
        assert!(witness.verify(&witness1_public));

        let result = manager.process_witness_vote(witness, &witness1_public, 1000);
        assert!(matches!(result, Err(RevocationError::WitnessIdMismatch)));
        assert!(!manager.is_revoked(&target_key));
    }

    #[test]
    fn test_session_invalidation_on_revocation() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        let (private_key, public_key) = generate_keypair();

        let config = WebOfTrustConfig::default();
        let mut manager = RevocationManager::new(public_key, config);

        // Track invalidation calls
        let invalidation_called = Arc::new(AtomicBool::new(false));
        let invalidation_count = Arc::new(AtomicU32::new(0));
        let invalidated_key = Arc::new(std::sync::Mutex::new([0u8; 32]));

        let called_clone = Arc::clone(&invalidation_called);
        let count_clone = Arc::clone(&invalidation_count);
        let key_clone = Arc::clone(&invalidated_key);

        manager.register_session_invalidator(move |key_id| {
            called_clone.store(true, Ordering::SeqCst);
            count_clone.fetch_add(1, Ordering::SeqCst);
            key_clone.lock().unwrap().copy_from_slice(key_id);
        });

        // Create self-revocation
        let cert = manager.create_self_revocation(
            &private_key,
            RevocationReason::KeyCompromised,
            None,
            1000,
        );

        // Process the revocation
        let result = manager.process_revocation(
            cert,
            RevocationSource::Direct,
            1000,
        );

        assert!(matches!(result, Ok(RevocationAction::Revoked { .. })));
        assert!(invalidation_called.load(Ordering::SeqCst));
        assert_eq!(invalidation_count.load(Ordering::SeqCst), 1);
        assert_eq!(*invalidated_key.lock().unwrap(), public_key);
    }
}
