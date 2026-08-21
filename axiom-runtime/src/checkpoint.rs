//! Agent Checkpointing and Resume
//!
//! AI agents need to save and restore their state for:
//! - Fault tolerance (crash recovery)
//! - Migration (move between nodes)
//! - Memory pressure (swap out inactive agents)
//! - Long-running inference (pause/resume)
//!
//! # Design
//!
//! Unlike traditional process checkpointing (save all memory),
//! AI agents have structured state that's more efficiently serialized:
//!
//! - Model weights: Immutable, shared, don't checkpoint
//! - KV cache: Large but structured, checkpoint efficiently
//! - Agent state: Small, serialize directly
//! - Task queue: Serialize pending tasks
//!
//! # Format
//!
//! Checkpoints are versioned for forward compatibility:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │ Magic (4 bytes): "AXCP"             │
//! │ Version (4 bytes)                   │
//! │ Agent ID (32 bytes)                 │
//! │ State size (4 bytes)                │
//! │ Agent state (variable)              │
//! │ KV cache size (4 bytes)             │
//! │ KV cache (variable)                 │
//! │ Task queue size (4 bytes)           │
//! │ Tasks (variable)                    │
//! │ Checksum (4 bytes)                  │
//! └─────────────────────────────────────┘
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::agent::{AgentState};
use axiom_router::ai::AgentId;

/// Checkpoint magic bytes
const CHECKPOINT_MAGIC: &[u8; 4] = b"AXCP";

/// Current checkpoint version
const CHECKPOINT_VERSION: u32 = 1;

/// Unique checkpoint identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointId(u64);

impl CheckpointId {
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// What to include in the checkpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointOptions {
    /// Include KV cache (large but necessary for inference resume)
    pub include_kv_cache: bool,
    /// Include pending tasks
    pub include_tasks: bool,
    /// Include claimed resources (references only)
    pub include_resources: bool,
    /// Compression level (0 = none, 1-9 = zstd levels)
    pub compression: u8,
}

impl Default for CheckpointOptions {
    fn default() -> Self {
        Self {
            include_kv_cache: true,
            include_tasks: true,
            include_resources: true,
            compression: 0,
        }
    }
}

impl CheckpointOptions {
    /// Minimal checkpoint (just agent state)
    pub fn minimal() -> Self {
        Self {
            include_kv_cache: false,
            include_tasks: false,
            include_resources: false,
            compression: 0,
        }
    }

    /// Full checkpoint with compression
    pub fn full_compressed() -> Self {
        Self {
            include_kv_cache: true,
            include_tasks: true,
            include_resources: true,
            compression: 3,
        }
    }
}

/// A serializable task state
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    /// Task name
    pub name: String,
    /// Task priority (0-3)
    pub priority: u8,
    /// Required capability
    pub required_capability: Option<String>,
    /// Task-specific data
    pub data: Vec<u8>,
}

/// Serializable resource claim
#[derive(Debug, Clone)]
pub struct ResourceSnapshot {
    /// Resource name
    pub name: String,
    /// Capability that was claimed
    pub capability: String,
}

/// The checkpoint data
#[derive(Debug)]
pub struct Checkpoint {
    /// Unique ID
    pub id: CheckpointId,
    /// Agent that was checkpointed
    pub agent_id: AgentId,
    /// Agent state at checkpoint
    pub agent_state: AgentState,
    /// Agent name
    pub agent_name: String,
    /// Provided capabilities
    pub capabilities: Vec<String>,
    /// KV cache (if included)
    pub kv_cache: Option<Vec<u8>>,
    /// Pending tasks (if included)
    pub tasks: Vec<TaskSnapshot>,
    /// Claimed resources (if included)
    pub resources: Vec<ResourceSnapshot>,
    /// Timestamp (hybrid clock)
    pub timestamp: u64,
    /// Size in bytes
    pub size_bytes: usize,
}

impl Checkpoint {
    /// Serialize checkpoint to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic
        buf.extend_from_slice(CHECKPOINT_MAGIC);

        // Version
        buf.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());

        // Agent ID (32 bytes)
        buf.extend_from_slice(self.agent_id.as_bytes());

        // Agent state (1 byte)
        buf.push(self.agent_state as u8);

        // Agent name
        let name_bytes = self.agent_name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);

        // Capabilities
        buf.extend_from_slice(&(self.capabilities.len() as u32).to_le_bytes());
        for cap in &self.capabilities {
            let cap_bytes = cap.as_bytes();
            buf.extend_from_slice(&(cap_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(cap_bytes);
        }

        // KV cache
        if let Some(ref kv) = self.kv_cache {
            buf.extend_from_slice(&(kv.len() as u32).to_le_bytes());
            buf.extend_from_slice(kv);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        // Tasks
        buf.extend_from_slice(&(self.tasks.len() as u32).to_le_bytes());
        for task in &self.tasks {
            let name_bytes = task.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf.push(task.priority);
            if let Some(ref cap) = task.required_capability {
                let cap_bytes = cap.as_bytes();
                buf.extend_from_slice(&(cap_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(cap_bytes);
            } else {
                buf.extend_from_slice(&0u32.to_le_bytes());
            }
            buf.extend_from_slice(&(task.data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&task.data);
        }

        // Resources
        buf.extend_from_slice(&(self.resources.len() as u32).to_le_bytes());
        for res in &self.resources {
            let name_bytes = res.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            let cap_bytes = res.capability.as_bytes();
            buf.extend_from_slice(&(cap_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(cap_bytes);
        }

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        // Checksum (simple CRC32)
        let checksum = crc32(&buf);
        buf.extend_from_slice(&checksum.to_le_bytes());

        buf
    }

    /// Deserialize checkpoint from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CheckpointError> {
        if data.len() < 12 {
            return Err(CheckpointError::TooShort);
        }

        let mut pos = 0;

        // Magic
        if &data[pos..pos + 4] != CHECKPOINT_MAGIC {
            return Err(CheckpointError::InvalidMagic);
        }
        pos += 4;

        // Version
        let version = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        if version != CHECKPOINT_VERSION {
            return Err(CheckpointError::UnsupportedVersion(version));
        }
        pos += 4;

        // Agent ID
        let agent_id = AgentId::from_bytes(data[pos..pos + 32].try_into().unwrap());
        pos += 32;

        // Agent state
        let agent_state = match data[pos] {
            0 => AgentState::Created,
            1 => AgentState::Initializing,
            2 => AgentState::Ready,
            3 => AgentState::Running,
            4 => AgentState::Paused,
            5 => AgentState::ShuttingDown,
            6 => AgentState::Terminated,
            _ => return Err(CheckpointError::InvalidState),
        };
        pos += 1;

        // Agent name
        let name_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let agent_name = String::from_utf8(data[pos..pos + name_len].to_vec())
            .map_err(|_| CheckpointError::InvalidUtf8)?;
        pos += name_len;

        // Capabilities
        let cap_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut capabilities = Vec::with_capacity(cap_count);
        for _ in 0..cap_count {
            let cap_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let cap = String::from_utf8(data[pos..pos + cap_len].to_vec())
                .map_err(|_| CheckpointError::InvalidUtf8)?;
            pos += cap_len;
            capabilities.push(cap);
        }

        // KV cache
        let kv_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let kv_cache = if kv_len > 0 {
            let kv = data[pos..pos + kv_len].to_vec();
            pos += kv_len;
            Some(kv)
        } else {
            None
        };

        // Tasks
        let task_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut tasks = Vec::with_capacity(task_count);
        for _ in 0..task_count {
            let name_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let name = String::from_utf8(data[pos..pos + name_len].to_vec())
                .map_err(|_| CheckpointError::InvalidUtf8)?;
            pos += name_len;

            let priority = data[pos];
            pos += 1;

            let cap_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let required_capability = if cap_len > 0 {
                let cap = String::from_utf8(data[pos..pos + cap_len].to_vec())
                    .map_err(|_| CheckpointError::InvalidUtf8)?;
                pos += cap_len;
                Some(cap)
            } else {
                None
            };

            let data_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let task_data = data[pos..pos + data_len].to_vec();
            pos += data_len;

            tasks.push(TaskSnapshot {
                name,
                priority,
                required_capability,
                data: task_data,
            });
        }

        // Resources
        let res_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut resources = Vec::with_capacity(res_count);
        for _ in 0..res_count {
            let name_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let name = String::from_utf8(data[pos..pos + name_len].to_vec())
                .map_err(|_| CheckpointError::InvalidUtf8)?;
            pos += name_len;

            let cap_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let capability = String::from_utf8(data[pos..pos + cap_len].to_vec())
                .map_err(|_| CheckpointError::InvalidUtf8)?;
            pos += cap_len;

            resources.push(ResourceSnapshot { name, capability });
        }

        // Timestamp
        let timestamp = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Verify checksum
        let stored_checksum = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let computed_checksum = crc32(&data[..pos]);
        if stored_checksum != computed_checksum {
            return Err(CheckpointError::ChecksumMismatch);
        }

        Ok(Self {
            id: CheckpointId::generate(),
            agent_id,
            agent_state,
            agent_name,
            capabilities,
            kv_cache,
            tasks,
            resources,
            timestamp,
            size_bytes: data.len(),
        })
    }
}

/// Checkpoint errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    TooShort,
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidState,
    InvalidUtf8,
    ChecksumMismatch,
    IoError,
}

/// Simple CRC32 implementation
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Checkpoint manager
pub struct CheckpointManager {
    /// Stored checkpoints (in memory for now)
    checkpoints: hashbrown::HashMap<CheckpointId, Vec<u8>>,
    /// Default options
    default_options: CheckpointOptions,
    /// Stats
    total_checkpoints: u64,
    total_restores: u64,
    total_bytes: u64,
}

impl CheckpointManager {
    pub fn new() -> Self {
        Self {
            checkpoints: hashbrown::HashMap::new(),
            default_options: CheckpointOptions::default(),
            total_checkpoints: 0,
            total_restores: 0,
            total_bytes: 0,
        }
    }

    pub fn with_options(mut self, options: CheckpointOptions) -> Self {
        self.default_options = options;
        self
    }

    /// Create checkpoint from agent state
    pub fn create(
        &mut self,
        agent_id: AgentId,
        agent_state: AgentState,
        agent_name: &str,
        capabilities: Vec<String>,
        kv_cache: Option<Vec<u8>>,
        tasks: Vec<TaskSnapshot>,
        resources: Vec<ResourceSnapshot>,
    ) -> CheckpointId {
        let checkpoint = Checkpoint {
            id: CheckpointId::generate(),
            agent_id,
            agent_state,
            agent_name: String::from(agent_name),
            capabilities,
            kv_cache,
            tasks,
            resources,
            timestamp: 0, // Would use hybrid clock in real impl
            size_bytes: 0,
        };

        let bytes = checkpoint.to_bytes();
        let id = checkpoint.id;
        let size = bytes.len();

        self.checkpoints.insert(id, bytes);
        self.total_checkpoints += 1;
        self.total_bytes += size as u64;

        id
    }

    /// Restore checkpoint
    pub fn restore(&mut self, id: CheckpointId) -> Result<Checkpoint, CheckpointError> {
        let bytes = self.checkpoints
            .get(&id)
            .ok_or(CheckpointError::IoError)?;

        let checkpoint = Checkpoint::from_bytes(bytes)?;
        self.total_restores += 1;

        Ok(checkpoint)
    }

    /// Delete checkpoint
    pub fn delete(&mut self, id: CheckpointId) -> bool {
        self.checkpoints.remove(&id).is_some()
    }

    /// List all checkpoint IDs
    pub fn list(&self) -> Vec<CheckpointId> {
        self.checkpoints.keys().copied().collect()
    }

    /// Get checkpoint size
    pub fn checkpoint_size(&self, id: CheckpointId) -> Option<usize> {
        self.checkpoints.get(&id).map(|b| b.len())
    }

    /// Stats
    pub fn total_checkpoints(&self) -> u64 {
        self.total_checkpoints
    }

    pub fn total_restores(&self) -> u64 {
        self.total_restores
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn stored_count(&self) -> usize {
        self.checkpoints.len()
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id() -> AgentId {
        AgentId::from_bytes([0xAB; 32])
    }

    #[test]
    fn test_checkpoint_id() {
        let id1 = CheckpointId::generate();
        let id2 = CheckpointId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_checkpoint_options() {
        let default = CheckpointOptions::default();
        assert!(default.include_kv_cache);
        assert!(default.include_tasks);

        let minimal = CheckpointOptions::minimal();
        assert!(!minimal.include_kv_cache);
        assert!(!minimal.include_tasks);

        let full = CheckpointOptions::full_compressed();
        assert!(full.include_kv_cache);
        assert_eq!(full.compression, 3);
    }

    #[test]
    fn test_checkpoint_serialize_deserialize() {
        let checkpoint = Checkpoint {
            id: CheckpointId::generate(),
            agent_id: test_agent_id(),
            agent_state: AgentState::Running,
            agent_name: String::from("test-agent"),
            capabilities: vec![String::from("llm:completion")],
            kv_cache: Some(vec![1, 2, 3, 4]),
            tasks: vec![
                TaskSnapshot {
                    name: String::from("inference"),
                    priority: 2,
                    required_capability: Some(String::from("compute:tensor")),
                    data: vec![5, 6, 7],
                },
            ],
            resources: vec![
                ResourceSnapshot {
                    name: String::from("gpu-0"),
                    capability: String::from("compute:tensor:fp16"),
                },
            ],
            timestamp: 12345,
            size_bytes: 0,
        };

        let bytes = checkpoint.to_bytes();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(restored.agent_id, test_agent_id());
        assert_eq!(restored.agent_state, AgentState::Running);
        assert_eq!(restored.agent_name, "test-agent");
        assert_eq!(restored.capabilities.len(), 1);
        assert_eq!(restored.kv_cache.as_ref().unwrap(), &vec![1, 2, 3, 4]);
        assert_eq!(restored.tasks.len(), 1);
        assert_eq!(restored.tasks[0].name, "inference");
        assert_eq!(restored.resources.len(), 1);
        assert_eq!(restored.timestamp, 12345);
    }

    #[test]
    fn test_checkpoint_no_kv_cache() {
        let checkpoint = Checkpoint {
            id: CheckpointId::generate(),
            agent_id: test_agent_id(),
            agent_state: AgentState::Paused,
            agent_name: String::from("minimal"),
            capabilities: vec![],
            kv_cache: None,
            tasks: vec![],
            resources: vec![],
            timestamp: 0,
            size_bytes: 0,
        };

        let bytes = checkpoint.to_bytes();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();

        assert!(restored.kv_cache.is_none());
        assert!(restored.tasks.is_empty());
        assert!(restored.resources.is_empty());
    }

    #[test]
    fn test_checkpoint_invalid_magic() {
        let mut bytes = vec![0u8; 100];
        bytes[0..4].copy_from_slice(b"XXXX");

        let result = Checkpoint::from_bytes(&bytes);
        assert!(matches!(result, Err(CheckpointError::InvalidMagic)));
    }

    #[test]
    fn test_checkpoint_checksum_mismatch() {
        let checkpoint = Checkpoint {
            id: CheckpointId::generate(),
            agent_id: test_agent_id(),
            agent_state: AgentState::Running,
            agent_name: String::from("test"),
            capabilities: vec![],
            kv_cache: None,
            tasks: vec![],
            resources: vec![],
            timestamp: 0,
            size_bytes: 0,
        };

        let mut bytes = checkpoint.to_bytes();
        // Corrupt data
        bytes[10] ^= 0xFF;

        let result = Checkpoint::from_bytes(&bytes);
        assert!(matches!(result, Err(CheckpointError::ChecksumMismatch)));
    }

    #[test]
    fn test_checkpoint_manager() {
        let mut manager = CheckpointManager::new();

        // Create checkpoint
        let id = manager.create(
            test_agent_id(),
            AgentState::Running,
            "test-agent",
            vec![String::from("llm:completion")],
            Some(vec![1, 2, 3]),
            vec![],
            vec![],
        );

        assert_eq!(manager.stored_count(), 1);
        assert_eq!(manager.total_checkpoints(), 1);

        // List
        let ids = manager.list();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], id);

        // Restore
        let checkpoint = manager.restore(id).unwrap();
        assert_eq!(checkpoint.agent_name, "test-agent");
        assert_eq!(manager.total_restores(), 1);

        // Delete
        assert!(manager.delete(id));
        assert_eq!(manager.stored_count(), 0);
        assert!(!manager.delete(id)); // Already deleted
    }

    #[test]
    fn test_crc32() {
        // Known test vector
        let data = b"123456789";
        let crc = crc32(data);
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_all_agent_states() {
        for state in [
            AgentState::Created,
            AgentState::Initializing,
            AgentState::Ready,
            AgentState::Running,
            AgentState::Paused,
            AgentState::ShuttingDown,
            AgentState::Terminated,
        ] {
            let checkpoint = Checkpoint {
                id: CheckpointId::generate(),
                agent_id: test_agent_id(),
                agent_state: state,
                agent_name: String::from("test"),
                capabilities: vec![],
                kv_cache: None,
                tasks: vec![],
                resources: vec![],
                timestamp: 0,
                size_bytes: 0,
            };

            let bytes = checkpoint.to_bytes();
            let restored = Checkpoint::from_bytes(&bytes).unwrap();
            assert_eq!(restored.agent_state, state);
        }
    }
}
