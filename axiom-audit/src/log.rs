//! Tamper-evident audit log
//!
//! Hash-chained audit records that can be verified for integrity.

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::event::{AuditEvent, EventType};
use crate::sensitivity::Sensitivity;

/// Audit log errors
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Log integrity violation at record {0}")]
    IntegrityViolation(u64),

    #[error("Record not found: {0}")]
    RecordNotFound(u64),

    #[error("Log is sealed and cannot be modified")]
    LogSealed,

    #[error("Invalid hash chain")]
    InvalidChain,
}

/// Result of chain verification
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Verification passed
    pub valid: bool,
    /// Number of records verified
    pub records_verified: u64,
    /// First invalid record (if any)
    pub first_invalid: Option<u64>,
    /// Hash at verification time
    pub final_hash: [u8; 32],
}

/// A single audit record with hash chain
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Sequence number
    pub sequence: u64,
    /// The audit event
    pub event: AuditEvent,
    /// Hash of previous record
    pub prev_hash: [u8; 32],
    /// Hash of this record
    pub hash: [u8; 32],
    /// Signature of this record (optional, for high-value events)
    pub signature: Option<[u8; 64]>,
}

impl AuditRecord {
    /// Create a new record
    fn new(sequence: u64, event: AuditEvent, prev_hash: [u8; 32]) -> Self {
        let mut record = Self {
            sequence,
            event,
            prev_hash,
            hash: [0u8; 32],
            signature: None,
        };
        record.hash = record.compute_hash();
        record
    }

    /// Compute hash of this record
    fn compute_hash(&self) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Include sequence number
        hasher.update(&self.sequence.to_le_bytes());

        // Include previous hash (creates chain)
        hasher.update(&self.prev_hash);

        // Include event data
        hasher.update(&self.event.timestamp.to_le_bytes());
        hasher.update(&self.event.subject);
        if let Some(ref resource) = self.event.resource {
            hasher.update(resource);
        }
        hasher.update(self.event.action.as_bytes());
        hasher.update(&[self.event.outcome as u8]);

        *hasher.finalize().as_bytes()
    }

    /// Verify this record's hash
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Sign this record with a keypair
    pub fn sign(&mut self, keypair: &axiom_crypto::Keypair) {
        use axiom_crypto::Signer;
        let sig = keypair.sign(&self.hash);
        self.signature = Some(*sig.as_bytes());
    }

    /// Verify signature if present
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> bool {
        use axiom_crypto::Verifier;
        use axiom_types::crypto::{NodeId, Signature};

        match self.signature {
            Some(sig_bytes) => {
                let node_id = NodeId::from_bytes(*public_key);
                let signature = Signature::from_bytes(sig_bytes);
                node_id.verify(&self.hash, &signature)
            }
            None => true, // No signature to verify
        }
    }
}

/// The audit log - append-only, hash-chained
#[cfg(feature = "std")]
pub struct AuditLog {
    /// Node ID that owns this log
    node_id: [u8; 32],
    /// All records
    records: Vec<AuditRecord>,
    /// Index by event type
    by_type: HashMap<EventType, Vec<u64>>,
    /// Index by subject
    by_subject: HashMap<[u8; 32], Vec<u64>>,
    /// Index by resource
    by_resource: HashMap<[u8; 32], Vec<u64>>,
    /// Current chain head hash
    head_hash: [u8; 32],
    /// Log is sealed (no more writes)
    sealed: bool,
    /// Optional signing keypair
    signing_key: Option<axiom_crypto::Keypair>,
    /// Alert callback
    alert_handler: Option<Box<dyn Fn(&AuditEvent) + Send + Sync>>,
}

#[cfg(feature = "std")]
impl AuditLog {
    /// Create a new audit log
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            records: Vec::new(),
            by_type: HashMap::new(),
            by_subject: HashMap::new(),
            by_resource: HashMap::new(),
            head_hash: [0u8; 32], // Genesis
            sealed: false,
            signing_key: None,
            alert_handler: None,
        }
    }

    /// Set signing key for high-value events
    pub fn with_signing_key(mut self, keypair: axiom_crypto::Keypair) -> Self {
        self.signing_key = Some(keypair);
        self
    }

    /// Set alert handler
    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuditEvent) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Box::new(handler));
        self
    }

    /// Record an audit event
    pub fn record(&mut self, event: AuditEvent) -> Result<u64, AuditError> {
        if self.sealed {
            return Err(AuditError::LogSealed);
        }

        let sequence = self.records.len() as u64;
        let mut record = AuditRecord::new(sequence, event.clone(), self.head_hash);

        // Sign if we have a key and event is high-value
        if let Some(ref keypair) = self.signing_key {
            if Self::should_sign(&event) {
                record.sign(keypair);
            }
        }

        // Update indices
        self.by_type
            .entry(event.event_type)
            .or_default()
            .push(sequence);

        self.by_subject
            .entry(event.subject)
            .or_default()
            .push(sequence);

        if let Some(resource) = event.resource {
            self.by_resource
                .entry(resource)
                .or_default()
                .push(sequence);
        }

        // Update head hash
        self.head_hash = record.hash;

        // Trigger alert if needed
        if event.is_alertable() {
            if let Some(ref handler) = self.alert_handler {
                handler(&event);
            }
        }

        self.records.push(record);
        Ok(sequence)
    }

    /// Check if event should be signed
    fn should_sign(event: &AuditEvent) -> bool {
        match event.event_type {
            EventType::Security => true,
            EventType::KeyManagement => true,
            EventType::Access if event.sensitivity == Some(Sensitivity::Phi) => true,
            EventType::Access if event.sensitivity == Some(Sensitivity::Restricted) => true,
            _ => false,
        }
    }

    /// Get a record by sequence number
    pub fn get(&self, sequence: u64) -> Option<&AuditRecord> {
        self.records.get(sequence as usize)
    }

    /// Get all records for an event type
    pub fn by_type(&self, event_type: EventType) -> Vec<&AuditRecord> {
        self.by_type
            .get(&event_type)
            .map(|seqs| seqs.iter().filter_map(|s| self.get(*s)).collect())
            .unwrap_or_default()
    }

    /// Get all records for a subject
    pub fn by_subject(&self, subject: &[u8; 32]) -> Vec<&AuditRecord> {
        self.by_subject
            .get(subject)
            .map(|seqs| seqs.iter().filter_map(|s| self.get(*s)).collect())
            .unwrap_or_default()
    }

    /// Get all records for a resource
    pub fn by_resource(&self, resource: &[u8; 32]) -> Vec<&AuditRecord> {
        self.by_resource
            .get(resource)
            .map(|seqs| seqs.iter().filter_map(|s| self.get(*s)).collect())
            .unwrap_or_default()
    }

    /// Get records in a time range
    pub fn in_time_range(&self, start: u64, end: u64) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.event.timestamp >= start && r.event.timestamp <= end)
            .collect()
    }

    /// Verify the entire hash chain
    pub fn verify_chain(&self) -> ChainVerification {
        let mut prev_hash = [0u8; 32]; // Genesis

        for (i, record) in self.records.iter().enumerate() {
            // Check previous hash link
            if record.prev_hash != prev_hash {
                return ChainVerification {
                    valid: false,
                    records_verified: i as u64,
                    first_invalid: Some(i as u64),
                    final_hash: prev_hash,
                };
            }

            // Check record hash
            if !record.verify() {
                return ChainVerification {
                    valid: false,
                    records_verified: i as u64,
                    first_invalid: Some(i as u64),
                    final_hash: prev_hash,
                };
            }

            prev_hash = record.hash;
        }

        ChainVerification {
            valid: true,
            records_verified: self.records.len() as u64,
            first_invalid: None,
            final_hash: self.head_hash,
        }
    }

    /// Seal the log (no more writes)
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Check if log is sealed
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Get current record count
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if log is empty
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get head hash for external verification
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash
    }

    /// Export records for a time range (for compliance reporting)
    pub fn export_range(&self, start: u64, end: u64) -> Vec<AuditRecord> {
        self.in_time_range(start, end).into_iter().cloned().collect()
    }

    /// Count events by type in time range
    pub fn count_by_type(&self, start: u64, end: u64) -> HashMap<EventType, u64> {
        let mut counts = HashMap::new();
        for record in self.in_time_range(start, end) {
            *counts.entry(record.event.event_type).or_insert(0) += 1;
        }
        counts
    }

    /// Get security events (for SOC monitoring)
    pub fn security_events(&self) -> Vec<&AuditRecord> {
        self.by_type(EventType::Security)
    }

    /// Get PHI access events (for HIPAA audit)
    pub fn phi_access_events(&self) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| {
                r.event.event_type == EventType::Access
                    && r.event.sensitivity == Some(Sensitivity::Phi)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AccessOutcome, AccessType};

    #[test]
    fn test_audit_log_basic() {
        let mut log = AuditLog::new([0u8; 32]);

        let event = AuditEvent::access(
            [1u8; 32],
            [2u8; 32],
            AccessType::Read,
            AccessOutcome::Success,
            Sensitivity::Phi,
            1000,
        );

        let seq = log.record(event).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_hash_chain_integrity() {
        let mut log = AuditLog::new([0u8; 32]);

        // Add multiple events
        for i in 0..10 {
            let event = AuditEvent::access(
                [1u8; 32],
                [2u8; 32],
                AccessType::Read,
                AccessOutcome::Success,
                Sensitivity::Internal,
                i * 1000,
            );
            log.record(event).unwrap();
        }

        // Verify chain
        let verification = log.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.records_verified, 10);
    }

    #[test]
    fn test_sealed_log() {
        let mut log = AuditLog::new([0u8; 32]);
        log.seal();

        let event = AuditEvent::system("test", "test".into(), 1000);
        let result = log.record(event);

        assert!(matches!(result, Err(AuditError::LogSealed)));
    }

    #[test]
    fn test_by_subject_index() {
        let mut log = AuditLog::new([0u8; 32]);
        let subject1 = [1u8; 32];
        let subject2 = [2u8; 32];

        // Events from subject1
        for i in 0..5 {
            let event = AuditEvent::access(
                subject1,
                [i; 32],
                AccessType::Read,
                AccessOutcome::Success,
                Sensitivity::Internal,
                i as u64 * 1000,
            );
            log.record(event).unwrap();
        }

        // Events from subject2
        for i in 0..3 {
            let event = AuditEvent::access(
                subject2,
                [i; 32],
                AccessType::Read,
                AccessOutcome::Success,
                Sensitivity::Internal,
                (i + 5) as u64 * 1000,
            );
            log.record(event).unwrap();
        }

        assert_eq!(log.by_subject(&subject1).len(), 5);
        assert_eq!(log.by_subject(&subject2).len(), 3);
    }
}
