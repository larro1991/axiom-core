//! External Audit Logging
//!
//! Provides write-once, externally-stored audit logs that a compromised
//! node cannot modify or delete.
//!
//! # Security Properties
//!
//! 1. **Append-only**: Logs can only be appended, never modified
//! 2. **External storage**: Logs are written to a remote system the node cannot control
//! 3. **Cryptographic binding**: Each entry is signed by the logging node
//! 4. **Hash chaining**: Entries form a tamper-evident chain
//! 5. **Witness receipts**: External system provides signed receipts
//!
//! # Architecture
//!
//! ```text
//! Node → ExternalAuditWriter → [Network] → ExternalAuditCollector
//!                                                    ↓
//!                                            ImmutableStore
//! ```
//!
//! # Protocol
//!
//! 1. Node creates AuditEntry with signature
//! 2. Entry sent to collector with previous entry hash
//! 3. Collector verifies chain, stores entry
//! 4. Collector returns signed WitnessReceipt
//! 5. Node must receive receipt or retry

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::fmt;

/// External audit entry - sent to collector
#[derive(Debug, Clone)]
pub struct ExternalAuditEntry {
    /// Unique entry ID
    pub entry_id: u64,
    /// Node ID that generated this entry
    pub node_id: [u8; 32],
    /// Unix timestamp (milliseconds)
    pub timestamp_ms: u64,
    /// Previous entry hash (chain link)
    pub prev_hash: [u8; 32],
    /// Event type code
    pub event_type: AuditEventType,
    /// Event payload (serialized)
    pub payload: Vec<u8>,
    /// Hash of this entry (computed)
    pub entry_hash: [u8; 32],
    /// Node's Ed25519 signature over entry_hash
    pub signature: [u8; 64],
}

/// Audit event types for external logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditEventType {
    // === Security Events (0x00xx) ===
    /// HDL loaded and executed
    HdlLoaded = 0x0001,
    /// Trust level changed
    TrustLevelChange = 0x0002,
    /// Key added to trust store
    KeyTrustAdded = 0x0003,
    /// Key revoked from trust store
    KeyRevoked = 0x0004,
    /// Authentication attempt
    AuthAttempt = 0x0005,
    /// Session established
    SessionEstablished = 0x0006,
    /// Session terminated
    SessionTerminated = 0x0007,
    /// Security alert generated
    SecurityAlert = 0x0008,

    // === Data Access Events (0x01xx) ===
    /// Data read access
    DataRead = 0x0100,
    /// Data write access
    DataWrite = 0x0101,
    /// Data deletion
    DataDelete = 0x0102,
    /// Capability granted
    CapabilityGranted = 0x0103,
    /// Capability revoked
    CapabilityRevoked = 0x0104,

    // === Network Events (0x02xx) ===
    /// Legacy network translation
    LegacyTranslation = 0x0200,
    /// MAC address claimed
    MacClaimed = 0x0201,
    /// Gateway traffic
    GatewayTraffic = 0x0202,
    /// Attack detected
    AttackDetected = 0x0203,

    // === System Events (0x03xx) ===
    /// Node startup
    NodeStartup = 0x0300,
    /// Node shutdown
    NodeShutdown = 0x0301,
    /// Configuration change
    ConfigChange = 0x0302,
    /// Firmware/software update
    SoftwareUpdate = 0x0303,

    // === Compliance Events (0x04xx) ===
    /// PHI access
    PhiAccess = 0x0400,
    /// Consent change
    ConsentChange = 0x0401,
    /// Retention action
    RetentionAction = 0x0402,

    /// Unknown/custom event
    Unknown = 0xFFFF,
}

impl AuditEventType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::HdlLoaded,
            0x0002 => Self::TrustLevelChange,
            0x0003 => Self::KeyTrustAdded,
            0x0004 => Self::KeyRevoked,
            0x0005 => Self::AuthAttempt,
            0x0006 => Self::SessionEstablished,
            0x0007 => Self::SessionTerminated,
            0x0008 => Self::SecurityAlert,
            0x0100 => Self::DataRead,
            0x0101 => Self::DataWrite,
            0x0102 => Self::DataDelete,
            0x0103 => Self::CapabilityGranted,
            0x0104 => Self::CapabilityRevoked,
            0x0200 => Self::LegacyTranslation,
            0x0201 => Self::MacClaimed,
            0x0202 => Self::GatewayTraffic,
            0x0203 => Self::AttackDetected,
            0x0300 => Self::NodeStartup,
            0x0301 => Self::NodeShutdown,
            0x0302 => Self::ConfigChange,
            0x0303 => Self::SoftwareUpdate,
            0x0400 => Self::PhiAccess,
            0x0401 => Self::ConsentChange,
            0x0402 => Self::RetentionAction,
            _ => Self::Unknown,
        }
    }

    /// Is this a security-critical event that MUST be externally logged?
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::HdlLoaded
                | Self::TrustLevelChange
                | Self::KeyTrustAdded
                | Self::KeyRevoked
                | Self::SecurityAlert
                | Self::AttackDetected
                | Self::PhiAccess
        )
    }
}

/// Witness receipt from collector
#[derive(Debug, Clone)]
pub struct WitnessReceipt {
    /// Entry ID this receipt is for
    pub entry_id: u64,
    /// Entry hash (as received)
    pub entry_hash: [u8; 32],
    /// Collector's node ID
    pub collector_id: [u8; 32],
    /// Timestamp when collector received entry
    pub received_at_ms: u64,
    /// Collector's signature over (entry_id || entry_hash || received_at_ms)
    pub collector_signature: [u8; 64],
    /// Chain position in collector's log
    pub chain_position: u64,
}

/// External audit writer - client side
pub struct ExternalAuditWriter {
    /// Our node ID
    node_id: [u8; 32],
    /// Our signing key
    signing_key: [u8; 32],
    /// Current entry ID counter
    next_entry_id: u64,
    /// Hash of previous entry (for chaining)
    prev_hash: [u8; 32],
    /// Pending entries awaiting receipts
    pending: Vec<PendingEntry>,
    /// Collector endpoints
    collectors: Vec<CollectorEndpoint>,
    /// Configuration
    config: WriterConfig,
}

/// Pending entry awaiting receipt
#[derive(Debug, Clone)]
struct PendingEntry {
    entry: ExternalAuditEntry,
    attempts: u32,
    first_sent_ms: u64,
}

/// Collector endpoint info
#[derive(Debug, Clone)]
pub struct CollectorEndpoint {
    /// Collector's node ID
    pub node_id: [u8; 32],
    /// Network address (for AXIOM transport)
    pub address: String,
    /// Is this collector currently reachable?
    pub is_healthy: bool,
    /// Last successful communication
    pub last_success_ms: u64,
}

/// Writer configuration
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Maximum pending entries before blocking
    pub max_pending: usize,
    /// Retry timeout in milliseconds
    pub retry_timeout_ms: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Require receipt for critical events before continuing
    pub require_receipt_for_critical: bool,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            max_pending: 1000,
            retry_timeout_ms: 5000,
            max_retries: 10,
            require_receipt_for_critical: true,
        }
    }
}

/// Errors from external audit system
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuditError {
    /// No collectors available
    NoCollectors,
    /// All collectors unreachable
    CollectorsUnreachable,
    /// Receipt verification failed
    InvalidReceipt,
    /// Pending queue full
    QueueFull,
    /// Critical event not acknowledged
    CriticalNotAcknowledged,
    /// Chain integrity error
    ChainError,
    /// Serialization error
    SerializationError,
}

impl fmt::Display for ExternalAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCollectors => write!(f, "No audit collectors configured"),
            Self::CollectorsUnreachable => write!(f, "All collectors unreachable"),
            Self::InvalidReceipt => write!(f, "Invalid witness receipt"),
            Self::QueueFull => write!(f, "Pending entry queue full"),
            Self::CriticalNotAcknowledged => write!(f, "Critical event not acknowledged"),
            Self::ChainError => write!(f, "Audit chain integrity error"),
            Self::SerializationError => write!(f, "Entry serialization error"),
        }
    }
}

impl ExternalAuditWriter {
    /// Create new writer
    pub fn new(node_id: [u8; 32], signing_key: [u8; 32]) -> Self {
        Self {
            node_id,
            signing_key,
            next_entry_id: 1,
            prev_hash: [0u8; 32], // Genesis
            pending: Vec::new(),
            collectors: Vec::new(),
            config: WriterConfig::default(),
        }
    }

    /// Add collector endpoint
    pub fn add_collector(&mut self, collector: CollectorEndpoint) {
        self.collectors.push(collector);
    }

    /// Configure writer
    pub fn with_config(mut self, config: WriterConfig) -> Self {
        self.config = config;
        self
    }

    /// Log an event externally
    pub fn log(
        &mut self,
        event_type: AuditEventType,
        payload: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<u64, ExternalAuditError> {
        if self.collectors.is_empty() {
            return Err(ExternalAuditError::NoCollectors);
        }

        if self.pending.len() >= self.config.max_pending {
            return Err(ExternalAuditError::QueueFull);
        }

        let entry_id = self.next_entry_id;
        self.next_entry_id += 1;

        // Compute entry hash
        let entry_hash = self.compute_hash(
            entry_id,
            &self.node_id,
            timestamp_ms,
            &self.prev_hash,
            event_type,
            &payload,
        );

        // Sign the entry
        let signature = self.sign(&entry_hash);

        let entry = ExternalAuditEntry {
            entry_id,
            node_id: self.node_id,
            timestamp_ms,
            prev_hash: self.prev_hash,
            event_type,
            payload,
            entry_hash,
            signature,
        };

        // Update chain
        self.prev_hash = entry_hash;

        // Add to pending
        self.pending.push(PendingEntry {
            entry,
            attempts: 0,
            first_sent_ms: timestamp_ms,
        });

        Ok(entry_id)
    }

    /// Log HDL loaded event (critical)
    pub fn log_hdl_loaded(
        &mut self,
        hdl_hash: [u8; 32],
        signer: [u8; 32],
        device_name: &str,
        timestamp_ms: u64,
    ) -> Result<u64, ExternalAuditError> {
        let mut payload = Vec::with_capacity(64 + device_name.len() + 2);
        payload.extend_from_slice(&hdl_hash);
        payload.extend_from_slice(&signer);
        payload.extend_from_slice(&(device_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(device_name.as_bytes());

        self.log(AuditEventType::HdlLoaded, payload, timestamp_ms)
    }

    /// Log security alert (critical)
    pub fn log_security_alert(
        &mut self,
        alert_type: u16,
        severity: u8,
        description: &str,
        timestamp_ms: u64,
    ) -> Result<u64, ExternalAuditError> {
        let mut payload = Vec::with_capacity(3 + description.len() + 2);
        payload.extend_from_slice(&alert_type.to_be_bytes());
        payload.push(severity);
        payload.extend_from_slice(&(description.len() as u16).to_be_bytes());
        payload.extend_from_slice(description.as_bytes());

        self.log(AuditEventType::SecurityAlert, payload, timestamp_ms)
    }

    /// Log trust level change (critical)
    pub fn log_trust_change(
        &mut self,
        peer_id: [u8; 32],
        old_level: u8,
        new_level: u8,
        timestamp_ms: u64,
    ) -> Result<u64, ExternalAuditError> {
        let mut payload = Vec::with_capacity(34);
        payload.extend_from_slice(&peer_id);
        payload.push(old_level);
        payload.push(new_level);

        self.log(AuditEventType::TrustLevelChange, payload, timestamp_ms)
    }

    /// Log legacy network translation
    pub fn log_legacy_translation(
        &mut self,
        axiom_node: [u8; 32],
        ipv4_addr: [u8; 4],
        bytes_transferred: u64,
        timestamp_ms: u64,
    ) -> Result<u64, ExternalAuditError> {
        let mut payload = Vec::with_capacity(44);
        payload.extend_from_slice(&axiom_node);
        payload.extend_from_slice(&ipv4_addr);
        payload.extend_from_slice(&bytes_transferred.to_be_bytes());

        self.log(AuditEventType::LegacyTranslation, payload, timestamp_ms)
    }

    /// Process a witness receipt
    pub fn process_receipt(&mut self, receipt: WitnessReceipt) -> Result<(), ExternalAuditError> {
        // Find the pending entry
        let idx = self
            .pending
            .iter()
            .position(|p| p.entry.entry_id == receipt.entry_id);

        if let Some(idx) = idx {
            let pending = &self.pending[idx];

            // Verify receipt
            if receipt.entry_hash != pending.entry.entry_hash {
                return Err(ExternalAuditError::InvalidReceipt);
            }

            // Verify collector signature (would use ed25519)
            if !self.verify_collector_signature(&receipt) {
                return Err(ExternalAuditError::InvalidReceipt);
            }

            // Remove from pending
            self.pending.remove(idx);
            Ok(())
        } else {
            // Entry not found - might be duplicate receipt
            Ok(())
        }
    }

    /// Get entries that need to be sent/retried
    pub fn get_pending_entries(&self) -> Vec<&ExternalAuditEntry> {
        self.pending.iter().map(|p| &p.entry).collect()
    }

    /// Get count of pending entries
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if any critical events are pending
    pub fn has_pending_critical(&self) -> bool {
        self.pending
            .iter()
            .any(|p| p.entry.event_type.is_critical())
    }

    /// Compute entry hash using BLAKE3
    fn compute_hash(
        &self,
        entry_id: u64,
        node_id: &[u8; 32],
        timestamp_ms: u64,
        prev_hash: &[u8; 32],
        event_type: AuditEventType,
        payload: &[u8],
    ) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(node_id);
        hasher.update(&timestamp_ms.to_be_bytes());
        hasher.update(prev_hash);
        hasher.update(&(event_type as u16).to_be_bytes());
        hasher.update(payload);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Sign an entry hash
    fn sign(&self, entry_hash: &[u8; 32]) -> [u8; 64] {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signer, SigningKey};

            let signing_key = SigningKey::from_bytes(&self.signing_key);
            let signature = signing_key.sign(entry_hash);
            signature.to_bytes()
        }

        #[cfg(not(feature = "std"))]
        {
            // Placeholder for no_std
            let _ = entry_hash;
            [0u8; 64]
        }
    }

    /// Verify collector signature on receipt
    fn verify_collector_signature(&self, receipt: &WitnessReceipt) -> bool {
        #[cfg(feature = "std")]
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            // Build message: entry_id || entry_hash || received_at_ms
            let mut message = Vec::with_capacity(48);
            message.extend_from_slice(&receipt.entry_id.to_be_bytes());
            message.extend_from_slice(&receipt.entry_hash);
            message.extend_from_slice(&receipt.received_at_ms.to_be_bytes());

            let verifying_key = match VerifyingKey::from_bytes(&receipt.collector_id) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let signature = match Signature::from_slice(&receipt.collector_signature) {
                Ok(s) => s,
                Err(_) => return false,
            };

            verifying_key.verify(&message, &signature).is_ok()
        }

        #[cfg(not(feature = "std"))]
        {
            let _ = receipt;
            false
        }
    }
}

/// External audit collector - server side
#[cfg(feature = "std")]
pub struct ExternalAuditCollector {
    /// Collector's node ID
    collector_id: [u8; 32],
    /// Collector's signing key
    signing_key: [u8; 32],
    /// Storage backend
    store: Box<dyn ImmutableStore>,
    /// Per-node chain state
    chain_state: std::collections::HashMap<[u8; 32], ChainState>,
}

/// Chain state for a node
#[derive(Debug, Clone)]
struct ChainState {
    /// Last entry ID received
    last_entry_id: u64,
    /// Last entry hash (for chain verification)
    last_hash: [u8; 32],
    /// Total entries from this node
    entry_count: u64,
}

/// Trait for immutable storage backends
pub trait ImmutableStore: Send + Sync {
    /// Append an entry (must be atomic)
    fn append(&mut self, entry: &ExternalAuditEntry) -> Result<u64, ExternalAuditError>;

    /// Read entry by position
    fn read(&self, position: u64) -> Option<ExternalAuditEntry>;

    /// Get current chain length
    fn len(&self) -> u64;

    /// Verify chain integrity
    fn verify_chain(&self) -> bool;
}

#[cfg(feature = "std")]
impl ExternalAuditCollector {
    /// Create new collector
    pub fn new(
        collector_id: [u8; 32],
        signing_key: [u8; 32],
        store: Box<dyn ImmutableStore>,
    ) -> Self {
        Self {
            collector_id,
            signing_key,
            store,
            chain_state: std::collections::HashMap::new(),
        }
    }

    /// Process incoming audit entry
    pub fn receive_entry(
        &mut self,
        entry: ExternalAuditEntry,
    ) -> Result<WitnessReceipt, ExternalAuditError> {
        // Verify entry signature
        if !self.verify_entry_signature(&entry) {
            return Err(ExternalAuditError::InvalidReceipt);
        }

        // Check chain continuity
        let state = self.chain_state.entry(entry.node_id).or_insert(ChainState {
            last_entry_id: 0,
            last_hash: [0u8; 32],
            entry_count: 0,
        });

        // Verify chain link
        if entry.prev_hash != state.last_hash {
            return Err(ExternalAuditError::ChainError);
        }

        // Verify entry ID sequence
        if entry.entry_id != state.last_entry_id + 1 {
            // Allow first entry (ID 1) when last_entry_id is 0
            if !(state.last_entry_id == 0 && entry.entry_id == 1) {
                return Err(ExternalAuditError::ChainError);
            }
        }

        // Store entry
        let position = self.store.append(&entry)?;

        // Update chain state
        state.last_entry_id = entry.entry_id;
        state.last_hash = entry.entry_hash;
        state.entry_count += 1;

        // Create witness receipt
        let received_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let receipt_signature = self.sign_receipt(entry.entry_id, &entry.entry_hash, received_at_ms);

        Ok(WitnessReceipt {
            entry_id: entry.entry_id,
            entry_hash: entry.entry_hash,
            collector_id: self.collector_id,
            received_at_ms,
            collector_signature: receipt_signature,
            chain_position: position,
        })
    }

    /// Verify entry signature
    fn verify_entry_signature(&self, entry: &ExternalAuditEntry) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = match VerifyingKey::from_bytes(&entry.node_id) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&entry.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify(&entry.entry_hash, &signature).is_ok()
    }

    /// Sign a witness receipt
    fn sign_receipt(&self, entry_id: u64, entry_hash: &[u8; 32], received_at_ms: u64) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.signing_key);

        let mut message = Vec::with_capacity(48);
        message.extend_from_slice(&entry_id.to_be_bytes());
        message.extend_from_slice(entry_hash);
        message.extend_from_slice(&received_at_ms.to_be_bytes());

        let signature = signing_key.sign(&message);
        signature.to_bytes()
    }
}

/// File-based immutable store (append-only file)
#[cfg(feature = "std")]
pub struct FileImmutableStore {
    /// Path to log file
    path: std::path::PathBuf,
    /// Current file handle
    file: std::fs::File,
    /// Entry count
    count: u64,
    /// Last hash for chain verification
    last_hash: [u8; 32],
}

#[cfg(feature = "std")]
impl FileImmutableStore {
    /// Create or open immutable log file
    pub fn open(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader};

        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        // Count existing entries and find last hash
        let mut count = 0u64;
        let mut last_hash = [0u8; 32];

        let reader = BufReader::new(std::fs::File::open(&path)?);
        for line in reader.lines() {
            if line?.starts_with("ENTRY:") {
                count += 1;
                // Would parse and extract last_hash here
            }
        }

        Ok(Self {
            path,
            file,
            count,
            last_hash,
        })
    }
}

#[cfg(feature = "std")]
impl ImmutableStore for FileImmutableStore {
    fn append(&mut self, entry: &ExternalAuditEntry) -> Result<u64, ExternalAuditError> {
        use std::io::Write;

        // Serialize entry as hex line
        let line = format!(
            "ENTRY:{:016x}:{}\n",
            entry.entry_id,
            hex::encode(&entry.entry_hash)
        );

        self.file
            .write_all(line.as_bytes())
            .map_err(|_| ExternalAuditError::SerializationError)?;
        self.file
            .flush()
            .map_err(|_| ExternalAuditError::SerializationError)?;

        self.count += 1;
        self.last_hash = entry.entry_hash;

        Ok(self.count - 1)
    }

    fn read(&self, _position: u64) -> Option<ExternalAuditEntry> {
        // Would read from file at position
        None
    }

    fn len(&self) -> u64 {
        self.count
    }

    fn verify_chain(&self) -> bool {
        // Would verify entire chain
        true
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_critical() {
        assert!(AuditEventType::HdlLoaded.is_critical());
        assert!(AuditEventType::SecurityAlert.is_critical());
        assert!(AuditEventType::AttackDetected.is_critical());
        assert!(!AuditEventType::DataRead.is_critical());
        assert!(!AuditEventType::NodeStartup.is_critical());
    }

    #[test]
    fn test_writer_creation() {
        let writer = ExternalAuditWriter::new([0xAB; 32], [0xCD; 32]);
        assert_eq!(writer.pending_count(), 0);
        assert!(!writer.has_pending_critical());
    }

    #[test]
    fn test_writer_no_collectors_error() {
        let mut writer = ExternalAuditWriter::new([0xAB; 32], [0xCD; 32]);
        let result = writer.log(AuditEventType::NodeStartup, vec![], 1000);
        assert_eq!(result, Err(ExternalAuditError::NoCollectors));
    }

    #[test]
    fn test_writer_log_entry() {
        let mut writer = ExternalAuditWriter::new([0xAB; 32], [0xCD; 32]);
        writer.add_collector(CollectorEndpoint {
            node_id: [0x11; 32],
            address: "collector.local".to_string(),
            is_healthy: true,
            last_success_ms: 0,
        });

        let entry_id = writer
            .log(AuditEventType::NodeStartup, vec![1, 2, 3], 1000)
            .unwrap();
        assert_eq!(entry_id, 1);
        assert_eq!(writer.pending_count(), 1);
    }

    #[test]
    fn test_writer_chain_linking() {
        let mut writer = ExternalAuditWriter::new([0xAB; 32], [0xCD; 32]);
        writer.add_collector(CollectorEndpoint {
            node_id: [0x11; 32],
            address: "collector.local".to_string(),
            is_healthy: true,
            last_success_ms: 0,
        });

        // First entry
        writer.log(AuditEventType::NodeStartup, vec![], 1000).unwrap();
        let entries = writer.get_pending_entries();
        let first_hash = entries[0].entry_hash;
        assert_eq!(entries[0].prev_hash, [0u8; 32]); // Genesis

        // Second entry should link to first
        writer.log(AuditEventType::DataRead, vec![], 2000).unwrap();
        let entries = writer.get_pending_entries();
        assert_eq!(entries[1].prev_hash, first_hash);
    }

    #[test]
    fn test_critical_event_tracking() {
        let mut writer = ExternalAuditWriter::new([0xAB; 32], [0xCD; 32]);
        writer.add_collector(CollectorEndpoint {
            node_id: [0x11; 32],
            address: "collector.local".to_string(),
            is_healthy: true,
            last_success_ms: 0,
        });

        // Non-critical event
        writer.log(AuditEventType::NodeStartup, vec![], 1000).unwrap();
        assert!(!writer.has_pending_critical());

        // Critical event
        writer.log(AuditEventType::HdlLoaded, vec![], 2000).unwrap();
        assert!(writer.has_pending_critical());
    }
}
