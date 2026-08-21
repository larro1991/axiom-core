//! Resource Manager - Discovery and Coordination
//!
//! The central component that:
//! - Discovers available hardware resources
//! - Handles claim/release coordination
//! - Ensures isolation between agents
//! - Provides direct access once claimed

use alloc::vec::Vec;
use axiom_types::crypto::NodeId;
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

use crate::capability::{Capability, CapabilityClass, CapabilityId};
use crate::resource::{Resource, ResourceId, ResourceHandle, ResourceState};

/// Error when claiming a resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// Resource not found
    NotFound,
    /// Resource already claimed by another agent
    AlreadyClaimed(NodeId),
    /// Insufficient trust level
    InsufficientTrust {
        required: TrustLevel,
        provided: TrustLevel,
    },
    /// Resource is unavailable (error, maintenance)
    Unavailable,
    /// Capability not found on resource
    CapabilityNotFound,
}

/// Filter for resource discovery
#[derive(Debug, Clone, Default)]
pub struct DiscoveryFilter {
    /// Filter by capability class
    pub class: Option<CapabilityClass>,
    /// Filter by capability name/query
    pub capability_query: Option<alloc::string::String>,
    /// Minimum throughput
    pub min_throughput: Option<u64>,
    /// Maximum latency (ns)
    pub max_latency_ns: Option<u64>,
    /// Only available resources
    pub available_only: bool,
}

impl DiscoveryFilter {
    /// Create a new filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by capability class
    pub fn with_class(mut self, class: CapabilityClass) -> Self {
        self.class = Some(class);
        self
    }

    /// Filter by capability query
    pub fn with_query(mut self, query: &str) -> Self {
        self.capability_query = Some(alloc::string::String::from(query));
        self
    }

    /// Filter by minimum throughput
    pub fn with_min_throughput(mut self, throughput: u64) -> Self {
        self.min_throughput = Some(throughput);
        self
    }

    /// Only show available resources
    pub fn available_only(mut self) -> Self {
        self.available_only = true;
        self
    }

    /// Check if a resource matches this filter
    pub fn matches(&self, resource: &Resource) -> bool {
        // Check availability
        if self.available_only && !resource.is_available() {
            return false;
        }

        // Check capability class
        if let Some(class) = self.class {
            if !resource.capabilities.iter().any(|c| c.class == class) {
                return false;
            }
        }

        // Check capability query
        if let Some(ref query) = self.capability_query {
            if !resource.has_capability(query) {
                return false;
            }
        }

        // Check throughput
        if let Some(min_tp) = self.min_throughput {
            let max_tp = resource.capabilities
                .iter()
                .map(|c| c.metrics.throughput)
                .max()
                .unwrap_or(0);
            if max_tp < min_tp {
                return false;
            }
        }

        // Check latency
        if let Some(max_lat) = self.max_latency_ns {
            let min_lat = resource.capabilities
                .iter()
                .map(|c| c.metrics.latency_ns)
                .min()
                .unwrap_or(u64::MAX);
            if min_lat > max_lat {
                return false;
            }
        }

        true
    }
}

/// Result of a discovery query
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Resource ID
    pub resource_id: ResourceId,
    /// Resource name
    pub name: alloc::string::String,
    /// Matching capabilities
    pub capabilities: Vec<Capability>,
    /// Current state
    pub state: ResourceState,
    /// Score (higher = better match)
    pub score: u32,
}

/// The resource manager - central coordination point
pub struct ResourceManager {
    /// All known resources
    resources: HashMap<ResourceId, Resource>,
    /// Active claims (handle token -> resource ID)
    claims: HashMap<[u8; 16], ResourceId>,
    /// Our agent ID
    local_agent: NodeId,
    /// Current timestamp provider
    now_fn: fn() -> u64,
}

impl ResourceManager {
    /// Create a new resource manager
    pub fn new(local_agent: NodeId) -> Self {
        Self {
            resources: HashMap::new(),
            claims: HashMap::new(),
            local_agent,
            now_fn: || 0, // Default: no time
        }
    }

    /// Set the timestamp provider
    pub fn with_time_provider(mut self, now_fn: fn() -> u64) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Register a resource
    pub fn register(&mut self, resource: Resource) {
        self.resources.insert(resource.id, resource);
    }

    /// Unregister a resource
    pub fn unregister(&mut self, id: &ResourceId) -> Option<Resource> {
        // Remove any claims for this resource
        self.claims.retain(|_, rid| rid != id);
        self.resources.remove(id)
    }

    /// Get a resource by ID
    pub fn get(&self, id: &ResourceId) -> Option<&Resource> {
        self.resources.get(id)
    }

    /// Get a mutable resource by ID
    pub fn get_mut(&mut self, id: &ResourceId) -> Option<&mut Resource> {
        self.resources.get_mut(id)
    }

    /// Discover resources matching a filter
    pub fn discover(&self, filter: &DiscoveryFilter) -> Vec<DiscoveryResult> {
        let mut results: Vec<DiscoveryResult> = self.resources
            .values()
            .filter(|r| filter.matches(r))
            .map(|r| {
                // Calculate match score
                let mut score = 0u32;

                // Bonus for being available
                if r.is_available() {
                    score += 100;
                }

                // Bonus for matching capabilities
                if let Some(ref query) = filter.capability_query {
                    for cap in &r.capabilities {
                        if cap.matches(query) {
                            score += 50;
                            // Bonus for throughput
                            score += (cap.metrics.throughput / 1_000_000_000) as u32;
                        }
                    }
                }

                DiscoveryResult {
                    resource_id: r.id,
                    name: r.name.clone(),
                    capabilities: r.capabilities.clone(),
                    state: r.state.clone(),
                    score,
                }
            })
            .collect();

        // Sort by score (highest first)
        results.sort_by(|a, b| b.score.cmp(&a.score));
        results
    }

    /// Discover by semantic query (convenience method)
    pub fn find(&self, query: &str) -> Vec<DiscoveryResult> {
        self.discover(&DiscoveryFilter::new().with_query(query).available_only())
    }

    /// Claim a resource
    pub fn claim(
        &mut self,
        resource_id: &ResourceId,
        agent: &NodeId,
        trust_level: TrustLevel,
    ) -> Result<ResourceHandle, ClaimError> {
        let resource = self.resources
            .get_mut(resource_id)
            .ok_or(ClaimError::NotFound)?;

        // Check trust level
        if (trust_level as u8) > (resource.min_trust as u8) {
            return Err(ClaimError::InsufficientTrust {
                required: resource.min_trust,
                provided: trust_level,
            });
        }

        // Check if already claimed
        if let ResourceState::Claimed { owner, .. } = &resource.state {
            return Err(ClaimError::AlreadyClaimed(owner.clone()));
        }

        // Check if unavailable
        if let ResourceState::Unavailable { .. } = &resource.state {
            return Err(ClaimError::Unavailable);
        }

        // Perform the claim
        let now = (self.now_fn)();
        let handle = resource.claim(agent.clone(), now)
            .ok_or(ClaimError::Unavailable)?;

        // Track the claim
        self.claims.insert(handle.token, *resource_id);

        Ok(handle)
    }

    /// Release a claimed resource
    pub fn release(&mut self, handle: ResourceHandle) -> bool {
        if let Some(resource_id) = self.claims.remove(&handle.token) {
            if let Some(resource) = self.resources.get_mut(&resource_id) {
                return resource.release(&handle.token);
            }
        }
        false
    }

    /// Check if a resource is claimed by a specific agent
    pub fn is_claimed_by(&self, resource_id: &ResourceId, agent: &NodeId) -> bool {
        self.resources.get(resource_id)
            .map(|r| matches!(&r.state, ResourceState::Claimed { owner, .. } if owner == agent))
            .unwrap_or(false)
    }

    /// Get all resources claimed by an agent
    pub fn claims_by(&self, agent: &NodeId) -> Vec<&Resource> {
        self.resources
            .values()
            .filter(|r| matches!(&r.state, ResourceState::Claimed { owner, .. } if owner == agent))
            .collect()
    }

    /// Get total number of resources
    pub fn num_resources(&self) -> usize {
        self.resources.len()
    }

    /// Get number of available resources
    pub fn num_available(&self) -> usize {
        self.resources.values().filter(|r| r.is_available()).count()
    }

    /// Get all resources (for iteration)
    pub fn all_resources(&self) -> impl Iterator<Item = &Resource> {
        self.resources.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilityClass, CapabilityMetrics};
    use crate::resource::AccessMethod;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn create_gpu_resource(name: &str, tflops: f64) -> Resource {
        Resource::new(name)
            .with_capability(
                Capability::new(CapabilityClass::Compute, "compute:tensor:fp16")
                    .with_tag("gpu")
                    .with_metrics(CapabilityMetrics::compute(tflops, 100))
            )
            .with_access(AccessMethod::CommandQueue {
                queue_base: 0x1000,
                queue_size: 256,
                doorbell: 0x2000,
            })
    }

    #[test]
    fn test_resource_registration() {
        let mut manager = ResourceManager::new(test_node_id(0));

        let gpu = create_gpu_resource("GPU0", 100.0);
        let gpu_id = gpu.id;

        manager.register(gpu);

        assert_eq!(manager.num_resources(), 1);
        assert!(manager.get(&gpu_id).is_some());
    }

    #[test]
    fn test_discovery() {
        let mut manager = ResourceManager::new(test_node_id(0));

        manager.register(create_gpu_resource("GPU0", 100.0));
        manager.register(create_gpu_resource("GPU1", 200.0));
        manager.register(
            Resource::new("Memory0")
                .with_capability(Capability::new(CapabilityClass::Memory, "memory:hbm"))
        );

        // Find all compute resources
        let compute = manager.find("compute");
        assert_eq!(compute.len(), 2);

        // Find with class filter
        let filter = DiscoveryFilter::new()
            .with_class(CapabilityClass::Compute)
            .available_only();
        let results = manager.discover(&filter);
        assert_eq!(results.len(), 2);

        // Higher throughput GPU should be first
        assert!(results[0].score >= results[1].score);
    }

    #[test]
    fn test_claim_release() {
        let mut manager = ResourceManager::new(test_node_id(0));

        let gpu = create_gpu_resource("GPU0", 100.0);
        let gpu_id = gpu.id;
        manager.register(gpu);

        let agent = test_node_id(1);

        // Claim the GPU
        let handle = manager.claim(&gpu_id, &agent, TrustLevel::Sig).unwrap();

        // Verify it's claimed
        assert!(manager.is_claimed_by(&gpu_id, &agent));
        assert_eq!(manager.num_available(), 0);

        // Release
        assert!(manager.release(handle));
        assert_eq!(manager.num_available(), 1);
    }

    #[test]
    fn test_double_claim_fails() {
        let mut manager = ResourceManager::new(test_node_id(0));

        let gpu = create_gpu_resource("GPU0", 100.0);
        let gpu_id = gpu.id;
        manager.register(gpu);

        let agent1 = test_node_id(1);
        let agent2 = test_node_id(2);

        // First claim succeeds
        let _handle = manager.claim(&gpu_id, &agent1, TrustLevel::Sig).unwrap();

        // Second claim fails
        let result = manager.claim(&gpu_id, &agent2, TrustLevel::Sig);
        assert!(matches!(result, Err(ClaimError::AlreadyClaimed(_))));
    }

    #[test]
    fn test_trust_level_check() {
        let mut manager = ResourceManager::new(test_node_id(0));

        let gpu = create_gpu_resource("GPU0", 100.0)
            .with_min_trust(TrustLevel::Full); // Requires full trust
        let gpu_id = gpu.id;
        manager.register(gpu);

        let agent = test_node_id(1);

        // Claim with lower trust fails
        let result = manager.claim(&gpu_id, &agent, TrustLevel::Sig);
        assert!(matches!(result, Err(ClaimError::InsufficientTrust { .. })));

        // Claim with full trust succeeds
        let handle = manager.claim(&gpu_id, &agent, TrustLevel::Full);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_discovery_filter() {
        let filter = DiscoveryFilter::new()
            .with_class(CapabilityClass::Compute)
            .with_query("compute:tensor")  // Prefix matches "compute:tensor:fp16"
            .with_min_throughput(50_000_000_000_000) // 50 TFLOPS
            .available_only();

        let good_gpu = create_gpu_resource("GPU0", 100.0);
        let weak_gpu = create_gpu_resource("GPU1", 10.0); // Only 10 TFLOPS

        assert!(filter.matches(&good_gpu));
        assert!(!filter.matches(&weak_gpu)); // Below throughput threshold
    }
}
