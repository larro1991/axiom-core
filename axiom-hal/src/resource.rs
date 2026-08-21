//! Resource - Physical hardware that can be claimed
//!
//! A Resource is a piece of hardware with capabilities.
//! It can be discovered, claimed by an agent, and accessed directly.

use alloc::vec::Vec;
use axiom_types::crypto::NodeId;

use crate::capability::{Capability, CapabilityId};

/// Unique identifier for a resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceId(pub [u8; 16]);

impl ResourceId {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generate a new random ID
    pub fn generate() -> Self {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        let mut bytes = [0u8; 16];
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = count ^ (core::ptr::addr_of!(bytes) as u64);
        let hash = blake3::hash(&seed.to_le_bytes());
        bytes.copy_from_slice(&hash.as_bytes()[..16]);
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Current state of a resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceState {
    /// Available for claiming
    Available,
    /// Claimed by an agent
    Claimed {
        owner: NodeId,
        since: u64, // Unix timestamp
    },
    /// Temporarily unavailable (maintenance, error)
    Unavailable {
        reason: UnavailableReason,
        until: Option<u64>, // Expected availability
    },
}

/// Why a resource is unavailable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// Hardware error detected
    Error,
    /// Undergoing maintenance/reset
    Maintenance,
    /// Thermal throttling
    Thermal,
    /// Power constraint
    Power,
    /// Reserved by system
    Reserved,
}

/// Handle to a claimed resource
#[derive(Debug, Clone)]
pub struct ResourceHandle {
    /// Resource ID
    pub resource_id: ResourceId,
    /// Capability ID this claim is for
    pub capability_id: CapabilityId,
    /// Claim token (for verification)
    pub token: [u8; 16],
    /// When claim was made
    pub claimed_at: u64,
    /// Access method for this claim
    pub access: AccessMethod,
}

impl ResourceHandle {
    /// Check if handle is for a specific resource
    pub fn is_for(&self, resource_id: &ResourceId) -> bool {
        &self.resource_id == resource_id
    }
}

/// How to access the hardware
#[derive(Debug, Clone)]
pub enum AccessMethod {
    /// Memory-mapped I/O
    Mmio {
        /// Base physical address
        base: u64,
        /// Size of mapped region
        size: u64,
        /// Is this cached or uncached?
        cached: bool,
    },
    /// Port I/O (x86 legacy)
    PortIo {
        base: u16,
        size: u16,
    },
    /// Command queue (modern GPUs)
    CommandQueue {
        /// Queue base address
        queue_base: u64,
        /// Queue size (entries)
        queue_size: u32,
        /// Doorbell register address
        doorbell: u64,
    },
    /// DMA descriptor ring
    DmaRing {
        /// Ring buffer base
        ring_base: u64,
        /// Ring size (entries)
        ring_size: u32,
        /// Producer index register
        producer_reg: u64,
        /// Consumer index register
        consumer_reg: u64,
    },
    /// Shared memory region (for IPC-style access)
    SharedMemory {
        /// Base address
        base: u64,
        /// Size
        size: u64,
    },
    /// No direct access (managed by another subsystem)
    Managed,
}

impl AccessMethod {
    /// Get base address if applicable
    pub fn base_address(&self) -> Option<u64> {
        match self {
            AccessMethod::Mmio { base, .. } => Some(*base),
            AccessMethod::CommandQueue { queue_base, .. } => Some(*queue_base),
            AccessMethod::DmaRing { ring_base, .. } => Some(*ring_base),
            AccessMethod::SharedMemory { base, .. } => Some(*base),
            _ => None,
        }
    }

    /// Get size if applicable
    pub fn size(&self) -> Option<u64> {
        match self {
            AccessMethod::Mmio { size, .. } => Some(*size),
            AccessMethod::SharedMemory { size, .. } => Some(*size),
            _ => None,
        }
    }
}

/// A physical resource with capabilities
#[derive(Debug, Clone)]
pub struct Resource {
    /// Unique identifier
    pub id: ResourceId,
    /// Human-readable name (e.g., "GPU0", "HBM-Bank-3")
    pub name: alloc::string::String,
    /// Capabilities this resource provides
    pub capabilities: Vec<Capability>,
    /// Current state
    pub state: ResourceState,
    /// How to access when claimed
    pub access: AccessMethod,
    /// Minimum trust level required
    pub min_trust: axiom_types::trust::TrustLevel,
    /// Parent resource (for hierarchical resources)
    pub parent: Option<ResourceId>,
    /// Child resources
    pub children: Vec<ResourceId>,
}

impl Resource {
    /// Create a new resource
    pub fn new(name: &str) -> Self {
        Self {
            id: ResourceId::generate(),
            name: alloc::string::String::from(name),
            capabilities: Vec::new(),
            state: ResourceState::Available,
            access: AccessMethod::Managed,
            min_trust: axiom_types::trust::TrustLevel::Raw,
            parent: None,
            children: Vec::new(),
        }
    }

    /// Add a capability
    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Set access method
    pub fn with_access(mut self, access: AccessMethod) -> Self {
        self.access = access;
        self
    }

    /// Set minimum trust level
    pub fn with_min_trust(mut self, trust: axiom_types::trust::TrustLevel) -> Self {
        self.min_trust = trust;
        self
    }

    /// Check if resource is available
    pub fn is_available(&self) -> bool {
        matches!(self.state, ResourceState::Available)
    }

    /// Check if resource has a specific capability
    pub fn has_capability(&self, query: &str) -> bool {
        self.capabilities.iter().any(|c| c.matches(query))
    }

    /// Get best capability matching query
    pub fn get_capability(&self, query: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.matches(query))
    }

    /// Claim the resource (internal - use ResourceManager)
    pub(crate) fn claim(&mut self, owner: NodeId, now: u64) -> Option<ResourceHandle> {
        if !self.is_available() {
            return None;
        }

        // Generate claim token
        let mut token = [0u8; 16];
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(owner.as_bytes());
        hasher.update(&now.to_le_bytes());
        let hash = hasher.finalize();
        token.copy_from_slice(&hash.as_bytes()[..16]);

        self.state = ResourceState::Claimed { owner, since: now };

        Some(ResourceHandle {
            resource_id: self.id,
            capability_id: self.capabilities.first()
                .map(|c| c.id)
                .unwrap_or(crate::capability::CapabilityId([0; 16])),
            token,
            claimed_at: now,
            access: self.access.clone(),
        })
    }

    /// Release the resource (internal - use ResourceManager)
    pub(crate) fn release(&mut self, token: &[u8; 16]) -> bool {
        if let ResourceState::Claimed { .. } = &self.state {
            // In a real implementation, we'd verify the token
            let _ = token; // Acknowledge unused for now
            self.state = ResourceState::Available;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilityClass};

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_resource_creation() {
        let resource = Resource::new("GPU0")
            .with_capability(Capability::new(CapabilityClass::Compute, "compute:tensor:fp16"))
            .with_access(AccessMethod::CommandQueue {
                queue_base: 0x1000,
                queue_size: 256,
                doorbell: 0x2000,
            });

        assert!(resource.is_available());
        assert!(resource.has_capability("compute"));
        assert!(resource.has_capability("compute:tensor"));
    }

    #[test]
    fn test_resource_claim_release() {
        let mut resource = Resource::new("GPU0")
            .with_capability(Capability::new(CapabilityClass::Compute, "compute:tensor"));

        let owner = test_node_id(1);
        let handle = resource.claim(owner, 1000).unwrap();

        assert!(!resource.is_available());
        assert!(matches!(resource.state, ResourceState::Claimed { .. }));

        // Release
        assert!(resource.release(&handle.token));
        assert!(resource.is_available());
    }

    #[test]
    fn test_double_claim_fails() {
        let mut resource = Resource::new("GPU0")
            .with_capability(Capability::new(CapabilityClass::Compute, "compute:tensor"));

        let owner1 = test_node_id(1);
        let owner2 = test_node_id(2);

        let _handle1 = resource.claim(owner1, 1000).unwrap();
        let handle2 = resource.claim(owner2, 1001);

        assert!(handle2.is_none()); // Second claim should fail
    }

    #[test]
    fn test_access_method_properties() {
        let mmio = AccessMethod::Mmio {
            base: 0xFE000000,
            size: 0x10000,
            cached: false,
        };

        assert_eq!(mmio.base_address(), Some(0xFE000000));
        assert_eq!(mmio.size(), Some(0x10000));
    }
}
