//! Multi-Agent Integration Tests
//!
//! Tests agents working together:
//! - Agent A provides a capability
//! - Agent B discovers and uses it
//! - Full request/response cycle

use axiom_hal::{
    Capability, CapabilityClass, CapabilityMetrics,
    Resource, AccessMethod,
};
use axiom_router::ai::{AgentId, Intent};
use axiom_router::registry::{NodeRegistry, NodeInfo, Endpoint};
use axiom_router::semantic::{SemanticRouter, SemanticCapability};
use axiom_runtime::{
    Agent, AgentConfig, AgentState,
    AgentContext,
    Task, TaskPriority, Executor,
};
use axiom_types::crypto::NodeId;
use axiom_types::trust::TrustLevel;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};

fn create_gpu(name: &str) -> Resource {
    Resource::new(name)
        .with_capability(
            Capability::new(CapabilityClass::Compute, "compute:tensor:fp16")
                .with_tag("gpu")
                .with_metrics(CapabilityMetrics::compute(100.0, 100))
        )
        .with_access(AccessMethod::CommandQueue {
            queue_base: 0x1000,
            queue_size: 256,
            doorbell: 0x2000,
        })
}

/// Simulates a provider agent that handles inference requests
struct InferenceProvider {
    context: AgentContext,
    executor: Executor,
    requests_handled: Arc<AtomicU32>,
}

impl InferenceProvider {
    fn new(name: &str) -> Self {
        let config = AgentConfig::new(name)
            .require("compute:tensor");

        let mut agent = Agent::new(config);
        agent.provide_capability("llm:completion");

        let mut ctx = AgentContext::new(agent);
        ctx.register_resource(create_gpu("GPU0"));

        Self {
            context: ctx,
            executor: Executor::new(),
            requests_handled: Arc::new(AtomicU32::new(0)),
        }
    }

    fn initialize(&mut self) -> Result<(), axiom_runtime::RuntimeError> {
        self.context.initialize()
    }

    fn agent_id(&self) -> AgentId {
        self.context.id().clone()
    }

    fn node_id(&self) -> NodeId {
        self.context.agent().node_id().clone()
    }

    /// Handle an inference request
    fn handle_request(&mut self, _payload: &[u8]) -> Vec<u8> {
        let counter = Arc::clone(&self.requests_handled);

        // Submit task to executor
        self.executor.submit(
            Task::new("inference", move |_ctx| {
                // Simulate doing inference
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }).with_priority(TaskPriority::High)
        );

        // Run the task
        let _ = self.executor.run_one(&mut self.context);

        // Return response
        b"inference complete".to_vec()
    }

    fn requests_handled(&self) -> u32 {
        self.requests_handled.load(Ordering::SeqCst)
    }

    fn shutdown(&mut self) -> Result<(), axiom_runtime::RuntimeError> {
        self.context.shutdown()
    }
}

/// Simulates a client agent that makes requests
struct InferenceClient {
    context: AgentContext,
    router: SemanticRouter,
    registry: NodeRegistry,
}

impl InferenceClient {
    fn new(name: &str) -> Self {
        let config = AgentConfig::new(name);
        let agent = Agent::new(config);
        let node_id = agent.node_id().clone();
        let ctx = AgentContext::new(agent);

        Self {
            context: ctx,
            router: SemanticRouter::new(node_id.clone()),
            registry: NodeRegistry::new(node_id, Endpoint::Local),
        }
    }

    fn initialize(&mut self) -> Result<(), axiom_runtime::RuntimeError> {
        // Client doesn't need resources, just initialize
        self.context.agent_mut().transition(AgentState::Initializing).unwrap();
        self.context.agent_mut().transition(AgentState::Ready).unwrap();
        Ok(())
    }

    /// Register a provider's capability
    fn register_provider(&mut self, node_id: NodeId, capability: &str, endpoint: Endpoint) {
        // Add to semantic router
        self.router.register(
            node_id.clone(),
            SemanticCapability::new(capability),
        );

        // Add to network registry
        self.registry.register(node_id, NodeInfo::new(endpoint));
    }

    /// Discover providers for an intent
    fn discover(&self, intent: &Intent) -> Vec<AgentId> {
        self.router
            .discover(intent)
            .into_iter()
            .map(|r| r.agent)
            .collect()
    }

    fn shutdown(&mut self) -> Result<(), axiom_runtime::RuntimeError> {
        self.context.agent_mut().transition(AgentState::ShuttingDown).unwrap();
        self.context.agent_mut().transition(AgentState::Terminated).unwrap();
        Ok(())
    }
}

#[test]
fn test_provider_client_discovery() {
    // Create provider
    let mut provider = InferenceProvider::new("llm-server");
    provider.initialize().expect("Provider init failed");

    // Create client
    let mut client = InferenceClient::new("llm-client");
    client.initialize().expect("Client init failed");

    // Client learns about provider
    client.register_provider(
        provider.node_id(),
        "llm:completion",
        Endpoint::udp("10.0.0.1:8080"),
    );

    // Client discovers provider
    let intent = Intent::from_str("llm:completion");
    let providers = client.discover(&intent);

    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].node_id(), &provider.node_id());

    // Cleanup
    provider.shutdown().unwrap();
    client.shutdown().unwrap();
}

#[test]
fn test_request_response_simulation() {
    // Create provider
    let mut provider = InferenceProvider::new("llm-server");
    provider.initialize().expect("Provider init failed");

    // Simulate requests
    let response1 = provider.handle_request(b"prompt 1");
    let response2 = provider.handle_request(b"prompt 2");
    let response3 = provider.handle_request(b"prompt 3");

    assert_eq!(response1, b"inference complete");
    assert_eq!(provider.requests_handled(), 3);

    provider.shutdown().unwrap();
}

#[test]
fn test_multiple_providers() {
    // Create multiple providers
    let mut provider1 = InferenceProvider::new("llm-server-1");
    let mut provider2 = InferenceProvider::new("llm-server-2");

    provider1.initialize().unwrap();
    provider2.initialize().unwrap();

    // Create client
    let mut client = InferenceClient::new("client");
    client.initialize().unwrap();

    // Register both providers
    client.register_provider(
        provider1.node_id(),
        "llm:completion",
        Endpoint::udp("10.0.0.1:8080"),
    );
    client.register_provider(
        provider2.node_id(),
        "llm:completion",
        Endpoint::udp("10.0.0.2:8080"),
    );

    // Discover - should find both
    let intent = Intent::from_str("llm:completion");
    let providers = client.discover(&intent);

    assert_eq!(providers.len(), 2);

    // Cleanup
    provider1.shutdown().unwrap();
    provider2.shutdown().unwrap();
    client.shutdown().unwrap();
}

#[test]
fn test_provider_with_multiple_capabilities() {
    let config = AgentConfig::new("multi-model-server")
        .require("compute:tensor");

    let mut agent = Agent::new(config);
    agent.provide_capability("llm:completion:gpt4");
    agent.provide_capability("llm:completion:claude");
    agent.provide_capability("llm:embedding");

    let mut ctx = AgentContext::new(agent);
    ctx.register_resource(create_gpu("GPU0"));
    ctx.initialize().unwrap();

    // Create client
    let mut client = InferenceClient::new("client");
    client.initialize().unwrap();

    // Register all capabilities
    for cap in ctx.agent().provided_capabilities() {
        client.register_provider(
            ctx.agent().node_id().clone(),
            cap,
            Endpoint::udp("10.0.0.1:8080"),
        );
    }

    // Can discover by specific capability
    let gpt4 = client.discover(&Intent::from_str("llm:completion:gpt4"));
    assert_eq!(gpt4.len(), 1);

    let claude = client.discover(&Intent::from_str("llm:completion:claude"));
    assert_eq!(claude.len(), 1);

    let embedding = client.discover(&Intent::from_str("llm:embedding"));
    assert_eq!(embedding.len(), 1);

    ctx.shutdown().unwrap();
    client.shutdown().unwrap();
}

#[test]
fn test_load_balancing_scenario() {
    // Create 3 providers with different reputations
    let mut router = SemanticRouter::new(NodeId::from_bytes([0; 32]));

    let nodes = [
        NodeId::from_bytes([1; 32]),
        NodeId::from_bytes([2; 32]),
        NodeId::from_bytes([3; 32]),
    ];

    // Register all with same capability
    for node in &nodes {
        router.register(node.clone(), SemanticCapability::new("service:inference"));
    }

    // Simulate different performance
    // Node 1: slow (high latency)
    router.update_reputation(&nodes[0], true, 500);

    // Node 2: fast
    router.update_reputation(&nodes[1], true, 10);
    router.update_reputation(&nodes[1], true, 15);

    // Node 3: unreliable
    router.update_reputation(&nodes[2], false, 0);

    // Discover - fastest (node 2) should be ranked highest
    let intent = Intent::from_str("service:inference");
    let results = router.discover(&intent);

    assert_eq!(results.len(), 3);
    // Node 2 (fast) should be first
    assert_eq!(results[0].agent.node_id(), &nodes[1]);
}

#[test]
fn test_capability_announcement_flow() {
    use axiom_router::announce::{AnnouncedCapability, AnnouncementManager};
    use axiom_types::crypto::IntentHash;

    // Provider announces its capability
    let provider_id = NodeId::from_bytes([1; 32]);
    let mut manager = AnnouncementManager::new(provider_id.clone());

    let intent_hash = IntentHash::from_bytes([0xAB; 16]);
    let cap = AnnouncedCapability::new(intent_hash, *b"llm\0");
    manager.register_capability(cap);

    // Create announcement frame (TTL=3)
    let frame = manager.create_announcement(3);

    // Frame was created successfully
    assert!(!frame.payload.is_empty());

    // Receiver processes announcement
    let mut router = SemanticRouter::new(NodeId::from_bytes([2; 32]));

    // In real system, we'd decode the announcement and register
    // For now, simulate:
    router.register(
        provider_id,
        SemanticCapability::new("llm:completion"),
    );

    // Can now discover
    let results = router.discover(&Intent::from_str("llm:completion"));
    assert_eq!(results.len(), 1);
}
