//! Agent Context - Ties identity, resources, and network together
//!
//! The context is what an executing agent sees:
//! - Who am I? (identity)
//! - What resources do I have? (HAL claims)
//! - Who can I talk to? (network)

use alloc::string::String;
use alloc::vec::Vec;
use axiom_hal::{
    ResourceManager, ResourceHandle, ResourceId, Resource,
    DiscoveryFilter, CapabilityClass,
};
use axiom_router::ai::{AgentId, Intent};
use axiom_router::registry::{NodeRegistry, Endpoint};
use axiom_router::semantic::SemanticRouter;
use axiom_types::crypto::NodeId;
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

use crate::agent::{Agent, AgentState};
use crate::error::{RuntimeError, RuntimeResult};

/// A claimed resource with metadata
#[derive(Debug)]
pub struct ResourceClaim {
    /// The HAL handle
    pub handle: ResourceHandle,
    /// What capability this claim is for
    pub capability: String,
    /// When claimed (unix timestamp)
    pub claimed_at: u64,
    /// Usage counter
    pub use_count: u64,
}

impl ResourceClaim {
    /// Create a new claim
    pub fn new(handle: ResourceHandle, capability: &str, now: u64) -> Self {
        Self {
            handle,
            capability: String::from(capability),
            claimed_at: now,
            use_count: 0,
        }
    }

    /// Record usage
    pub fn record_use(&mut self) {
        self.use_count += 1;
    }
}

/// The agent's execution context
pub struct AgentContext {
    /// The agent (identity + state)
    agent: Agent,
    /// Resource manager (HAL)
    resources: ResourceManager,
    /// Node registry (network endpoints)
    network: NodeRegistry,
    /// Semantic router (capability discovery)
    router: SemanticRouter,
    /// Currently held resource claims
    claims: HashMap<ResourceId, ResourceClaim>,
    /// Time provider
    now_fn: fn() -> u64,
}

impl AgentContext {
    /// Create a new context for an agent
    pub fn new(agent: Agent) -> Self {
        let node_id = agent.node_id().clone();

        Self {
            agent,
            resources: ResourceManager::new(node_id.clone()),
            network: NodeRegistry::new(node_id.clone(), Endpoint::Local),
            router: SemanticRouter::new(node_id),
            claims: HashMap::new(),
            now_fn: || 0,
        }
    }

    /// Set time provider
    pub fn with_time_provider(mut self, now_fn: fn() -> u64) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Get the agent
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Get mutable agent (for state transitions)
    pub fn agent_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }

    /// Get agent ID
    pub fn id(&self) -> &AgentId {
        self.agent.id()
    }

    /// Get resource manager
    pub fn resources(&self) -> &ResourceManager {
        &self.resources
    }

    /// Get mutable resource manager
    pub fn resources_mut(&mut self) -> &mut ResourceManager {
        &mut self.resources
    }

    /// Get network registry
    pub fn network(&self) -> &NodeRegistry {
        &self.network
    }

    /// Get mutable network registry
    pub fn network_mut(&mut self) -> &mut NodeRegistry {
        &mut self.network
    }

    /// Get semantic router
    pub fn router(&self) -> &SemanticRouter {
        &self.router
    }

    /// Get mutable semantic router
    pub fn router_mut(&mut self) -> &mut SemanticRouter {
        &mut self.router
    }

    // ===== Resource Management =====

    /// Register a local resource
    pub fn register_resource(&mut self, resource: Resource) {
        self.resources.register(resource);
    }

    /// Discover resources matching a query
    pub fn discover_resources(&self, query: &str) -> Vec<&Resource> {
        self.resources
            .discover(&DiscoveryFilter::new().with_query(query).available_only())
            .iter()
            .filter_map(|r| self.resources.get(&r.resource_id))
            .collect()
    }

    /// Claim a resource by capability query
    pub fn claim(&mut self, capability_query: &str) -> RuntimeResult<&ResourceClaim> {
        // Find available resource
        let results = self.resources.discover(
            &DiscoveryFilter::new()
                .with_query(capability_query)
                .available_only()
        );

        let discovery = results.first()
            .ok_or_else(|| RuntimeError::ResourceNotFound(String::from(capability_query)))?;

        let resource_id = discovery.resource_id;

        // Claim it
        let handle = self.resources.claim(
            &resource_id,
            self.agent.node_id(),
            self.agent.config().trust_level,
        )?;

        let now = (self.now_fn)();
        let claim = ResourceClaim::new(handle, capability_query, now);

        self.claims.insert(resource_id, claim);
        Ok(self.claims.get(&resource_id).unwrap())
    }

    /// Claim a specific resource by ID
    pub fn claim_resource(&mut self, resource_id: &ResourceId, capability: &str) -> RuntimeResult<&ResourceClaim> {
        let handle = self.resources.claim(
            resource_id,
            self.agent.node_id(),
            self.agent.config().trust_level,
        )?;

        let now = (self.now_fn)();
        let claim = ResourceClaim::new(handle, capability, now);

        self.claims.insert(*resource_id, claim);
        Ok(self.claims.get(resource_id).unwrap())
    }

    /// Release a resource
    pub fn release(&mut self, resource_id: &ResourceId) -> bool {
        if let Some(claim) = self.claims.remove(resource_id) {
            self.resources.release(claim.handle)
        } else {
            false
        }
    }

    /// Release all resources
    pub fn release_all(&mut self) {
        let resource_ids: Vec<ResourceId> = self.claims.keys().cloned().collect();
        for id in resource_ids {
            self.release(&id);
        }
    }

    /// Get current claims
    pub fn claims(&self) -> &HashMap<ResourceId, ResourceClaim> {
        &self.claims
    }

    /// Check if we have a resource with given capability
    pub fn has_resource(&self, capability: &str) -> bool {
        self.claims.values().any(|c| c.capability == capability)
    }

    // ===== Network Operations =====

    /// Register a peer
    pub fn register_peer(&mut self, peer_id: NodeId, endpoint: Endpoint) {
        use axiom_router::registry::NodeInfo;
        self.network.register(peer_id, NodeInfo::new(endpoint));
    }

    /// Discover agents with a capability (via semantic router)
    pub fn discover_agents(&self, intent: &Intent) -> Vec<AgentId> {
        self.router
            .discover(intent)
            .into_iter()
            .map(|r| r.agent)
            .collect()
    }

    // ===== Lifecycle =====

    /// Initialize the context (claim required resources)
    pub fn initialize(&mut self) -> RuntimeResult<()> {
        // Transition agent state
        self.agent.transition(AgentState::Initializing)
            .map_err(|(from, to)| RuntimeError::InvalidState {
                from: alloc::format!("{:?}", from),
                to: alloc::format!("{:?}", to),
            })?;

        // Claim required capabilities
        let required = self.agent.config().required_capabilities.clone();
        for cap in required {
            if let Err(e) = self.claim(&cap) {
                // Clean up on failure
                self.release_all();
                let _ = self.agent.transition(AgentState::Terminated);
                return Err(e);
            }
        }

        // Try to claim preferred capabilities (don't fail if unavailable)
        let preferred = self.agent.config().preferred_capabilities.clone();
        for cap in preferred {
            let _ = self.claim(&cap); // Ignore errors
        }

        // Transition to ready
        self.agent.transition(AgentState::Ready)
            .map_err(|(from, to)| RuntimeError::InvalidState {
                from: alloc::format!("{:?}", from),
                to: alloc::format!("{:?}", to),
            })?;

        Ok(())
    }

    /// Shutdown the context (release resources)
    pub fn shutdown(&mut self) -> RuntimeResult<()> {
        // Transition to shutting down
        self.agent.transition(AgentState::ShuttingDown)
            .map_err(|(from, to)| RuntimeError::InvalidState {
                from: alloc::format!("{:?}", from),
                to: alloc::format!("{:?}", to),
            })?;

        // Release all resources
        self.release_all();

        // Transition to terminated
        self.agent.transition(AgentState::Terminated)
            .map_err(|(from, to)| RuntimeError::InvalidState {
                from: alloc::format!("{:?}", from),
                to: alloc::format!("{:?}", to),
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentConfig;
    use axiom_hal::{Capability, CapabilityClass, CapabilityMetrics, AccessMethod};

    fn create_test_gpu(name: &str, tflops: f64) -> Resource {
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
    fn test_context_creation() {
        let agent = Agent::new(AgentConfig::new("test"));
        let ctx = AgentContext::new(agent);

        assert_eq!(ctx.agent().state(), AgentState::Created);
    }

    #[test]
    fn test_resource_registration_and_claim() {
        let agent = Agent::new(AgentConfig::new("test"));
        let mut ctx = AgentContext::new(agent);

        // Register a GPU
        ctx.register_resource(create_test_gpu("GPU0", 100.0));

        // Claim it
        let claim = ctx.claim("compute:tensor").unwrap();
        assert_eq!(claim.capability, "compute:tensor");

        // Check we have it
        assert!(ctx.has_resource("compute:tensor"));
    }

    #[test]
    fn test_context_lifecycle() {
        let config = AgentConfig::new("test")
            .require("compute:tensor");

        let agent = Agent::new(config);
        let mut ctx = AgentContext::new(agent);

        // Register required resource
        ctx.register_resource(create_test_gpu("GPU0", 100.0));

        // Initialize
        assert!(ctx.initialize().is_ok());
        assert_eq!(ctx.agent().state(), AgentState::Ready);
        assert!(ctx.has_resource("compute:tensor"));

        // Shutdown
        assert!(ctx.shutdown().is_ok());
        assert_eq!(ctx.agent().state(), AgentState::Terminated);
        assert!(ctx.claims().is_empty());
    }

    #[test]
    fn test_missing_required_resource() {
        let config = AgentConfig::new("test")
            .require("compute:quantum"); // Not available!

        let agent = Agent::new(config);
        let mut ctx = AgentContext::new(agent);

        // Only register a GPU
        ctx.register_resource(create_test_gpu("GPU0", 100.0));

        // Initialize should fail
        assert!(ctx.initialize().is_err());
        assert_eq!(ctx.agent().state(), AgentState::Terminated);
    }

    #[test]
    fn test_preferred_capability_optional() {
        let config = AgentConfig::new("test")
            .require("compute:tensor")
            .prefer("compute:quantum"); // Optional

        let agent = Agent::new(config);
        let mut ctx = AgentContext::new(agent);

        // Only register GPU (no quantum)
        ctx.register_resource(create_test_gpu("GPU0", 100.0));

        // Initialize should succeed (quantum is optional)
        assert!(ctx.initialize().is_ok());
        assert_eq!(ctx.agent().state(), AgentState::Ready);
    }
}
