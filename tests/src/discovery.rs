//! Discovery Integration Tests
//!
//! Tests semantic capability discovery:
//! - Agents registering capabilities
//! - Discovering agents by intent
//! - Category and tag matching
//! - Reputation and scoring

use axiom_router::ai::{AgentId, Intent, Constraint};
use axiom_router::semantic::{SemanticRouter, SemanticCapability, SemanticQuery, Category};
use axiom_types::crypto::NodeId;
use axiom_types::trust::TrustLevel;

fn test_node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 32])
}

fn test_agent_id(byte: u8) -> AgentId {
    AgentId::from_node_id(test_node_id(byte))
}

#[test]
fn test_semantic_capability_hierarchy() {
    let mut router = SemanticRouter::new(test_node_id(0));

    // Register agents with different LLM capabilities
    router.register(
        test_node_id(1),
        SemanticCapability::new("llm:completion:gpt4")
            .with_tag("fast")
            .with_version(1, 0, 0),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("llm:completion:claude")
            .with_tag("accurate")
            .with_version(2, 0, 0),
    );

    router.register(
        test_node_id(3),
        SemanticCapability::new("llm:embedding")
            .with_tag("fast"),
    );

    // Query for any LLM capability
    let llm_agents = router.find_by_category("llm");
    assert_eq!(llm_agents.len(), 3);

    // Query for completion specifically
    let completion_agents = router.find_by_category("llm:completion");
    assert_eq!(completion_agents.len(), 2);

    // Query for specific model
    let gpt4_agents = router.find_by_category("llm:completion:gpt4");
    assert_eq!(gpt4_agents.len(), 1);
}

#[test]
fn test_discover_by_intent() {
    let mut router = SemanticRouter::new(test_node_id(0));

    // Two agents provide the same capability
    router.register(
        test_node_id(1),
        SemanticCapability::new("compute:inference")
            .with_tag("gpu"),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("compute:inference")
            .with_tag("tpu"),
    );

    // Discover by intent
    let intent = Intent::from_str("compute:inference");
    let results = router.discover(&intent);

    assert_eq!(results.len(), 2);
}

#[test]
fn test_discover_with_constraints() {
    let mut router = SemanticRouter::new(test_node_id(0));

    router.register(
        test_node_id(1),
        SemanticCapability::new("llm:completion"),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("llm:completion"),
    );

    // Discover with exclude constraint
    let intent = Intent::from_str("llm:completion")
        .with_constraint(Constraint::ExcludeAgent(test_agent_id(1)));

    let results = router.discover(&intent);

    // Should only find node 2
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].agent.node_id(), &test_node_id(2));
}

#[test]
fn test_discover_with_preference() {
    let mut router = SemanticRouter::new(test_node_id(0));

    router.register(
        test_node_id(1),
        SemanticCapability::new("storage:kv"),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("storage:kv"),
    );

    // Prefer node 2
    let intent = Intent::from_str("storage:kv")
        .with_constraint(Constraint::PreferAgent(test_agent_id(2)));

    let results = router.discover(&intent);

    // Node 2 should be first (higher score due to preference)
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].agent.node_id(), &test_node_id(2));
}

#[test]
fn test_multi_capability_discovery() {
    let mut router = SemanticRouter::new(test_node_id(0));

    // Node 1 has both LLM and embedding
    router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
    router.register(test_node_id(1), SemanticCapability::new("llm:embedding"));

    // Node 2 only has completion
    router.register(test_node_id(2), SemanticCapability::new("llm:completion"));

    // Node 3 only has embedding
    router.register(test_node_id(3), SemanticCapability::new("llm:embedding"));

    // Find agent that can do BOTH
    let intents = vec![
        Intent::from_str("llm:completion"),
        Intent::from_str("llm:embedding"),
    ];

    let multi_capable = router.discover_multi(&intents);

    // Only node 1 has both
    assert_eq!(multi_capable.len(), 1);
    assert_eq!(multi_capable[0], test_node_id(1));
}

#[test]
fn test_semantic_query_builder() {
    let mut router = SemanticRouter::new(test_node_id(0));

    // Register capabilities with different versions and tags
    router.register(
        test_node_id(1),
        SemanticCapability::new("api:rest")
            .with_tag("v1")
            .with_tag("deprecated")
            .with_version(1, 0, 0),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("api:rest")
            .with_tag("v2")
            .with_tag("stable")
            .with_version(2, 0, 0),
    );

    router.register(
        test_node_id(3),
        SemanticCapability::new("api:rest")
            .with_tag("v3")
            .with_tag("beta")
            .with_version(3, 0, 0),
    );

    // Query: api:rest, version >= 2.0.0, prefer stable
    let results = SemanticQuery::new()
        .category("api:rest")
        .min_version(2, 0, 0)
        .prefer_tag("stable")
        .execute(&router);

    // Should find v2 and v3, with v2 (stable) ranked higher
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].agent.node_id(), &test_node_id(2)); // stable preferred
}

#[test]
fn test_reputation_affects_discovery() {
    let mut router = SemanticRouter::new(test_node_id(0));

    router.register(test_node_id(1), SemanticCapability::new("service:cache"));
    router.register(test_node_id(2), SemanticCapability::new("service:cache"));

    // Node 1 has bad reputation (failures)
    router.update_reputation(&test_node_id(1), false, 0);
    router.update_reputation(&test_node_id(1), false, 0);

    // Node 2 has good reputation (fast responses)
    router.update_reputation(&test_node_id(2), true, 10);
    router.update_reputation(&test_node_id(2), true, 15);

    // Discover
    let intent = Intent::from_str("service:cache");
    let results = router.discover(&intent);

    // Node 2 (good reputation) should be first
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].agent.node_id(), &test_node_id(2));

    // Verify reputation scores
    let rep1 = router.get_reputation(&test_node_id(1));
    let rep2 = router.get_reputation(&test_node_id(2));
    assert!(rep2 > rep1);
}

#[test]
fn test_tag_based_discovery() {
    let mut router = SemanticRouter::new(test_node_id(0));

    router.register(
        test_node_id(1),
        SemanticCapability::new("compute:gpu")
            .with_tag("nvidia")
            .with_tag("cuda"),
    );

    router.register(
        test_node_id(2),
        SemanticCapability::new("compute:gpu")
            .with_tag("amd")
            .with_tag("rocm"),
    );

    // Find NVIDIA GPUs
    let nvidia = router.find_by_tag("nvidia");
    assert_eq!(nvidia.len(), 1);

    // Find CUDA-capable
    let cuda = router.find_by_tag("cuda");
    assert_eq!(cuda.len(), 1);

    // Find AMD
    let amd = router.find_by_tag("amd");
    assert_eq!(amd.len(), 1);
}

#[test]
fn test_category_matching() {
    let cat_llm = Category::from_str("llm");
    let cat_llm_completion = Category::from_str("llm:completion");
    let cat_llm_completion_gpt4 = Category::from_str("llm:completion:gpt4");
    let cat_image = Category::from_str("image");

    // Parent matches child
    assert!(cat_llm.matches(&cat_llm_completion));
    assert!(cat_llm.matches(&cat_llm_completion_gpt4));
    assert!(cat_llm_completion.matches(&cat_llm_completion_gpt4));

    // Child doesn't match parent
    assert!(!cat_llm_completion.matches(&cat_llm));

    // Different categories don't match
    assert!(!cat_llm.matches(&cat_image));
}

#[test]
fn test_unregister_node() {
    let mut router = SemanticRouter::new(test_node_id(0));

    router.register(test_node_id(1), SemanticCapability::new("service:a"));
    router.register(test_node_id(1), SemanticCapability::new("service:b"));
    router.register(test_node_id(2), SemanticCapability::new("service:a"));

    assert_eq!(router.num_capabilities(), 3);

    // Unregister node 1
    router.unregister_node(&test_node_id(1));

    // Should only have node 2's capability left
    assert_eq!(router.num_capabilities(), 1);
}
