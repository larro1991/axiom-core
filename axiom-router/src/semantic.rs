//! Semantic Intent Routing for AXIOM
//!
//! This module provides semantic routing that goes beyond exact hash matching:
//! - Category-based routing (e.g., "llm:*" matches all LLM capabilities)
//! - Constraint evaluation for capability selection
//! - Multi-intent queries (find agent that provides A AND B)
//! - Reputation-weighted selection

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

use crate::ai::{AgentId, Constraint, DiscoveryResult, Intent};

/// Category for capability classification
///
/// Categories allow hierarchical matching:
/// - `llm` matches all LLM capabilities
/// - `llm:completion` matches completion specifically
/// - `llm:completion:gpt4` matches specific model
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Category {
    /// Hierarchical path components
    pub path: Vec<String>,
}

impl Category {
    /// Create from a colon-separated string
    pub fn from_str(s: &str) -> Self {
        Self {
            path: s.split(':').map(String::from).collect(),
        }
    }

    /// Check if this category matches another (prefix match)
    pub fn matches(&self, other: &Category) -> bool {
        if self.path.len() > other.path.len() {
            return false;
        }
        self.path.iter().zip(other.path.iter()).all(|(a, b)| a == b)
    }

    /// Get depth of the category (more specific = deeper)
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

/// Semantic capability registration
#[derive(Debug, Clone)]
pub struct SemanticCapability {
    /// The exact intent hash
    pub intent_hash: IntentHash,
    /// Human-readable name
    pub name: String,
    /// Category for hierarchical matching
    pub category: Category,
    /// Tags for additional metadata
    pub tags: Vec<String>,
    /// Version (semver-like: major * 10000 + minor * 100 + patch)
    pub version: u32,
}

impl SemanticCapability {
    /// Create a new semantic capability
    pub fn new(name: &str) -> Self {
        let category = Category::from_str(name);
        Self {
            intent_hash: crate::ai::Intent::from_str(name).hash,
            name: String::from(name),
            category,
            tags: Vec::new(),
            version: 10000, // 1.0.0
        }
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(String::from(tag));
        self
    }

    /// Set version
    pub fn with_version(mut self, major: u8, minor: u8, patch: u8) -> Self {
        self.version = (major as u32) * 10000 + (minor as u32) * 100 + (patch as u32);
        self
    }
}

/// Result of semantic routing
#[derive(Debug, Clone)]
pub struct SemanticRoute {
    /// The agent providing the capability
    pub agent: AgentId,
    /// Matched capability
    pub capability: SemanticCapability,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Match score (higher = better match)
    pub match_score: u32,
    /// Latency (ms)
    pub latency_ms: u16,
    /// Load (0-255)
    pub load: u8,
}

/// Semantic router that provides intelligent capability matching
pub struct SemanticRouter {
    /// Capabilities indexed by intent hash
    capabilities: HashMap<IntentHash, Vec<(NodeId, SemanticCapability)>>,
    /// Category index for prefix matching
    category_index: HashMap<String, Vec<IntentHash>>,
    /// Tag index for tag-based discovery
    tag_index: HashMap<String, Vec<IntentHash>>,
    /// Trust scores per agent (learned over time)
    reputation: HashMap<NodeId, f32>,
    /// Local node ID
    local_id: NodeId,
}

impl SemanticRouter {
    /// Create a new semantic router
    pub fn new(local_id: NodeId) -> Self {
        Self {
            capabilities: HashMap::new(),
            category_index: HashMap::new(),
            tag_index: HashMap::new(),
            reputation: HashMap::new(),
            local_id,
        }
    }

    /// Register a semantic capability. Idempotent per (node_id, intent_hash) -
    /// re-registering the same capability for the same node replaces the
    /// previous entry rather than duplicating it. This is what makes
    /// "unregister_node, then register everything again" a safe way for a
    /// caller to fully replace one node's capability set on every
    /// re-announcement (a real AXIOM caller does exactly this - forge-node's
    /// `Announce` handling), without accumulating duplicate entries. A
    /// *different* node registering the same capability is a genuinely
    /// separate entry (multiple providers of one capability), not deduped
    /// against each other.
    pub fn register(&mut self, node_id: NodeId, capability: SemanticCapability) {
        let entries = self.capabilities.entry(capability.intent_hash).or_insert_with(Vec::new);
        entries.retain(|(id, _)| id != &node_id);
        entries.push((node_id.clone(), capability.clone()));

        // Index by category prefixes. Deduped per prefix - `category_index`
        // is conceptually "which intent hashes exist under this prefix",
        // not "how many times has something registered under this prefix";
        // without the dedup check, re-registering the same capability would
        // push a duplicate hash here every time, and `find_by_category`
        // would then return that same capability multiple times per
        // duplicate (it re-looks-up and re-emits an entry per hash it
        // iterates, with no dedup of its own).
        for depth in 1..=capability.category.depth() {
            let prefix: String = capability.category.path[..depth].join(":");
            let hashes = self.category_index.entry(prefix).or_insert_with(Vec::new);
            if !hashes.contains(&capability.intent_hash) {
                hashes.push(capability.intent_hash);
            }
        }

        // Index by tags - same dedup reasoning as category_index above.
        for tag in &capability.tags {
            let hashes = self.tag_index.entry(tag.clone()).or_insert_with(Vec::new);
            if !hashes.contains(&capability.intent_hash) {
                hashes.push(capability.intent_hash);
            }
        }
    }

    /// Unregister all capabilities for a node, pruning `category_index`/
    /// `tag_index` entries that no longer point to anything - including
    /// this node - still provides that intent hash. Also clears the node's
    /// reputation score (re-earned fresh if it reconnects later). Without
    /// this cleanup, every unregister+re-register cycle (the normal way a
    /// caller replaces a peer's capability set - see `register`'s doc
    /// comment) would leak a few index entries forever, even though the
    /// `capabilities` map itself was already being cleaned up correctly.
    pub fn unregister_node(&mut self, node_id: &NodeId) {
        // Capture what this node was providing *before* removing it, so we
        // know which category/tag index entries might now be orphaned.
        let removed_hashes: Vec<IntentHash> = self.capabilities
            .iter()
            .filter(|(_, entries)| entries.iter().any(|(id, _)| id == node_id))
            .map(|(hash, _)| *hash)
            .collect();

        for entries in self.capabilities.values_mut() {
            entries.retain(|(id, _)| id != node_id);
        }
        self.capabilities.retain(|_, entries| !entries.is_empty());

        for hash in removed_hashes {
            // Some other node might still provide this exact intent hash -
            // if so, the category/tag entries pointing at it are still needed.
            if self.capabilities.contains_key(&hash) {
                continue;
            }
            self.category_index.retain(|_, hashes| {
                hashes.retain(|h| *h != hash);
                !hashes.is_empty()
            });
            self.tag_index.retain(|_, hashes| {
                hashes.retain(|h| *h != hash);
                !hashes.is_empty()
            });
        }

        self.reputation.remove(node_id);
    }

    /// Find capabilities by category prefix
    pub fn find_by_category(&self, category_prefix: &str) -> Vec<&SemanticCapability> {
        let mut results = Vec::new();

        if let Some(intent_hashes) = self.category_index.get(category_prefix) {
            for hash in intent_hashes {
                if let Some(entries) = self.capabilities.get(hash) {
                    for (_, cap) in entries {
                        results.push(cap);
                    }
                }
            }
        }

        results
    }

    /// Find capabilities by tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<&SemanticCapability> {
        let mut results = Vec::new();

        if let Some(intent_hashes) = self.tag_index.get(tag) {
            for hash in intent_hashes {
                if let Some(entries) = self.capabilities.get(hash) {
                    for (_, cap) in entries {
                        // Only include capabilities that actually have this tag
                        if cap.tags.contains(&String::from(tag)) {
                            results.push(cap);
                        }
                    }
                }
            }
        }

        results
    }

    /// Discover agents that can fulfill an intent with constraint evaluation
    pub fn discover(&self, intent: &Intent) -> Vec<DiscoveryResult> {
        let mut results = Vec::new();

        if let Some(entries) = self.capabilities.get(&intent.hash) {
            for (node_id, cap) in entries {
                // Start with base score from capability depth (more specific = better)
                let mut score = (cap.category.depth() as u32) * 100;

                // Get reputation (default to 0.5 for unknown)
                let rep = self.reputation.get(node_id).copied().unwrap_or(0.5);
                score += (rep * 100.0) as u32;

                // Evaluate constraints
                let (passes, constraint_score) = self.evaluate_constraints(node_id, &intent.constraints);
                if !passes {
                    continue;
                }
                score += constraint_score;

                results.push(DiscoveryResult {
                    agent: AgentId::from_node_id(node_id.clone()),
                    trust_level: TrustLevel::Raw, // Updated by actual routing table
                    latency_ms: 0, // Filled by routing table
                    load: 128, // Default mid-load
                    score,
                });
            }
        }

        // Sort by score (highest first)
        results.sort_by(|a, b| b.score.cmp(&a.score));
        results
    }

    /// Discover agents that provide ALL of the specified intents
    pub fn discover_multi(&self, intents: &[Intent]) -> Vec<NodeId> {
        if intents.is_empty() {
            return Vec::new();
        }

        // Get nodes for first intent
        let first_nodes: hashbrown::HashSet<NodeId> = self.capabilities
            .get(&intents[0].hash)
            .map(|entries| entries.iter().map(|(id, _)| id.clone()).collect())
            .unwrap_or_default();

        // Intersect with nodes for remaining intents
        let mut result: hashbrown::HashSet<NodeId> = first_nodes;

        for intent in &intents[1..] {
            let nodes: hashbrown::HashSet<NodeId> = self.capabilities
                .get(&intent.hash)
                .map(|entries| entries.iter().map(|(id, _)| id.clone()).collect())
                .unwrap_or_default();

            result = result.intersection(&nodes).cloned().collect();
        }

        result.into_iter().collect()
    }

    /// Evaluate constraints against a node
    fn evaluate_constraints(&self, node_id: &NodeId, constraints: &[Constraint]) -> (bool, u32) {
        let mut bonus_score = 0u32;

        for constraint in constraints {
            match constraint {
                Constraint::MinTrust(min_level) => {
                    // Would need actual trust level from routing table
                    // For now, we pass if we have any reputation
                    if self.reputation.get(node_id).is_none() {
                        // Unknown trust - only fail for high trust requirements
                        if *min_level == TrustLevel::Full {
                            return (false, 0);
                        }
                    }
                }
                Constraint::MaxLatency(_max_ms) => {
                    // Would need actual latency measurement
                    // Pass for now, actual check done at routing table level
                }
                Constraint::MaxLoad(_max_load) => {
                    // Would need actual load measurement
                    // Pass for now, actual check done at routing table level
                }
                Constraint::PreferAgent(preferred) => {
                    if preferred.node_id() == node_id {
                        bonus_score += 500; // Significant preference bonus
                    }
                }
                Constraint::ExcludeAgent(excluded) => {
                    if excluded.node_id() == node_id {
                        return (false, 0);
                    }
                }
                Constraint::Custom(_custom) => {
                    // Custom constraints could be evaluated by AI
                    // For now, pass all custom constraints
                }
            }
        }

        (true, bonus_score)
    }

    /// Update reputation for a node after interaction
    pub fn update_reputation(&mut self, node_id: &NodeId, success: bool, response_time_ms: u32) {
        let entry = self.reputation.entry(node_id.clone()).or_insert(0.5);

        // Exponential moving average
        let alpha = 0.1;
        let new_score = if success {
            // Score based on response time (faster = better)
            let time_score = (1000.0 - (response_time_ms as f32).min(1000.0)) / 1000.0;
            0.5 + time_score * 0.5
        } else {
            0.0
        };

        *entry = *entry * (1.0 - alpha) + new_score * alpha;

        // Clamp to [0, 1]
        *entry = entry.clamp(0.0, 1.0);
    }

    /// Get reputation score for a node
    pub fn get_reputation(&self, node_id: &NodeId) -> f32 {
        self.reputation.get(node_id).copied().unwrap_or(0.5)
    }

    /// Get number of registered capabilities
    pub fn num_capabilities(&self) -> usize {
        self.capabilities.values().map(|v| v.len()).sum()
    }

    /// Get number of unique intents
    pub fn num_intents(&self) -> usize {
        self.capabilities.len()
    }
}

/// Builder for complex semantic queries
pub struct SemanticQuery {
    /// Primary intent
    intent: Option<Intent>,
    /// Category prefix filter
    category_prefix: Option<String>,
    /// Required tags (all must match)
    required_tags: Vec<String>,
    /// Optional tags (any can match, boost score)
    optional_tags: Vec<String>,
    /// Minimum version
    min_version: Option<u32>,
    /// Maximum results
    limit: usize,
}

impl SemanticQuery {
    /// Create a new query
    pub fn new() -> Self {
        Self {
            intent: None,
            category_prefix: None,
            required_tags: Vec::new(),
            optional_tags: Vec::new(),
            min_version: None,
            limit: 10,
        }
    }

    /// Set the intent to query
    pub fn intent(mut self, intent: Intent) -> Self {
        self.intent = Some(intent);
        self
    }

    /// Set category prefix filter
    pub fn category(mut self, prefix: &str) -> Self {
        self.category_prefix = Some(String::from(prefix));
        self
    }

    /// Add required tag
    pub fn require_tag(mut self, tag: &str) -> Self {
        self.required_tags.push(String::from(tag));
        self
    }

    /// Add optional tag (boosts score)
    pub fn prefer_tag(mut self, tag: &str) -> Self {
        self.optional_tags.push(String::from(tag));
        self
    }

    /// Set minimum version
    pub fn min_version(mut self, major: u8, minor: u8, patch: u8) -> Self {
        self.min_version = Some((major as u32) * 10000 + (minor as u32) * 100 + (patch as u32));
        self
    }

    /// Set result limit
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    /// Execute the query
    pub fn execute(&self, router: &SemanticRouter) -> Vec<SemanticRoute> {
        let mut results = Vec::new();

        // Get candidate capabilities
        let candidates: Vec<(&NodeId, &SemanticCapability)> = if let Some(intent) = &self.intent {
            router.capabilities
                .get(&intent.hash)
                .map(|entries| entries.iter().map(|(id, cap)| (id, cap)).collect())
                .unwrap_or_default()
        } else if let Some(prefix) = &self.category_prefix {
            let mut caps = Vec::new();
            if let Some(hashes) = router.category_index.get(prefix) {
                // Deduplicate hashes before looking up
                let unique_hashes: hashbrown::HashSet<_> = hashes.iter().collect();
                for hash in unique_hashes {
                    if let Some(entries) = router.capabilities.get(hash) {
                        for (id, cap) in entries {
                            caps.push((id, cap));
                        }
                    }
                }
            }
            caps
        } else {
            // No filter - return all
            router.capabilities
                .values()
                .flat_map(|entries| entries.iter().map(|(id, cap)| (id, cap)))
                .collect()
        };

        // Filter and score
        for (node_id, cap) in candidates {
            // Check required tags
            if !self.required_tags.iter().all(|tag| cap.tags.contains(tag)) {
                continue;
            }

            // Check version
            if let Some(min_ver) = self.min_version {
                if cap.version < min_ver {
                    continue;
                }
            }

            // Calculate score
            let mut score = cap.category.depth() as u32 * 100;

            // Bonus for optional tags
            for tag in &self.optional_tags {
                if cap.tags.contains(tag) {
                    score += 50;
                }
            }

            // Reputation bonus
            let rep = router.reputation.get(node_id).copied().unwrap_or(0.5);
            score += (rep * 100.0) as u32;

            results.push(SemanticRoute {
                agent: AgentId::from_node_id(node_id.clone()),
                capability: cap.clone(),
                trust_level: TrustLevel::Raw,
                match_score: score,
                latency_ms: 0,
                load: 128,
            });
        }

        // Sort by score and limit
        results.sort_by(|a, b| b.match_score.cmp(&a.match_score));
        results.truncate(self.limit);
        results
    }
}

impl Default for SemanticQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_category_matching() {
        let llm = Category::from_str("llm");
        let llm_completion = Category::from_str("llm:completion");
        let llm_completion_gpt4 = Category::from_str("llm:completion:gpt4");
        let image = Category::from_str("image");

        // Prefix matching
        assert!(llm.matches(&llm_completion));
        assert!(llm.matches(&llm_completion_gpt4));
        assert!(llm_completion.matches(&llm_completion_gpt4));

        // No match for different category
        assert!(!llm.matches(&image));

        // More specific doesn't match less specific
        assert!(!llm_completion.matches(&llm));
    }

    #[test]
    fn test_semantic_capability_registration() {
        let mut router = SemanticRouter::new(test_node_id(0));

        let cap = SemanticCapability::new("llm:completion")
            .with_tag("fast")
            .with_version(1, 2, 0);

        router.register(test_node_id(1), cap);

        assert_eq!(router.num_capabilities(), 1);
        assert_eq!(router.num_intents(), 1);
    }

    #[test]
    fn test_find_by_category() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
        router.register(test_node_id(2), SemanticCapability::new("llm:embedding"));
        router.register(test_node_id(3), SemanticCapability::new("image:generation"));

        let llm_caps = router.find_by_category("llm");
        assert_eq!(llm_caps.len(), 2);

        let image_caps = router.find_by_category("image");
        assert_eq!(image_caps.len(), 1);
    }

    #[test]
    fn test_find_by_tag() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));
        router.register(test_node_id(2), SemanticCapability::new("llm:embedding").with_tag("fast"));
        router.register(test_node_id(3), SemanticCapability::new("image:generation").with_tag("slow"));

        let fast_caps = router.find_by_tag("fast");
        assert_eq!(fast_caps.len(), 2);
    }

    #[test]
    fn test_register_same_node_same_capability_is_idempotent() {
        // AXIOM-5: re-registering the same (node, capability) pair must
        // replace, not duplicate - both in `capabilities` (num_capabilities)
        // and in the category/tag indexes (find_by_category/find_by_tag
        // would otherwise return the same capability multiple times).
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));
        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));
        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));

        assert_eq!(router.num_capabilities(), 1);
        assert_eq!(router.num_intents(), 1);
        assert_eq!(router.find_by_category("llm:completion").len(), 1);
        assert_eq!(router.find_by_tag("fast").len(), 1);
    }

    #[test]
    fn test_unregister_node_prunes_indexes_when_last_provider() {
        // AXIOM-5: unregistering the only provider of a capability must
        // remove it from category_index/tag_index too, not just
        // `capabilities` - otherwise those indexes leak a stale intent hash
        // forever every time a peer registers then disconnects/re-announces.
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));
        assert_eq!(router.find_by_category("llm:completion").len(), 1);
        assert_eq!(router.find_by_tag("fast").len(), 1);

        router.unregister_node(&test_node_id(1));

        assert_eq!(router.num_capabilities(), 0);
        assert_eq!(router.num_intents(), 0);
        assert_eq!(router.find_by_category("llm:completion").len(), 0);
        assert_eq!(router.find_by_tag("fast").len(), 0);
    }

    #[test]
    fn test_unregister_node_keeps_indexes_when_another_provider_remains() {
        // AXIOM-5: unregistering one provider must NOT prune index entries
        // that a *different* node still needs for the same capability.
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion").with_tag("fast"));
        router.register(test_node_id(2), SemanticCapability::new("llm:completion").with_tag("fast"));

        router.unregister_node(&test_node_id(1));

        assert_eq!(router.num_capabilities(), 1);
        assert_eq!(router.find_by_category("llm:completion").len(), 1);
        assert_eq!(router.find_by_tag("fast").len(), 1);
        assert_eq!(router.discover(&Intent::from_str("llm:completion"))[0].agent.node_id(), &test_node_id(2));
    }

    #[test]
    fn test_unregister_node_clears_reputation() {
        let mut router = SemanticRouter::new(test_node_id(0));
        router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
        router.update_reputation(&test_node_id(1), true, 50);
        assert_ne!(router.get_reputation(&test_node_id(1)), 0.5);

        router.unregister_node(&test_node_id(1));

        // Departed node's score resets to the default rather than sticking
        // around forever for a peer we no longer track.
        assert_eq!(router.get_reputation(&test_node_id(1)), 0.5);
    }

    #[test]
    fn test_discover_intent() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
        router.register(test_node_id(2), SemanticCapability::new("llm:completion"));

        let intent = Intent::from_str("llm:completion");
        let results = router.discover(&intent);

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_discover_with_exclude_constraint() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
        router.register(test_node_id(2), SemanticCapability::new("llm:completion"));

        let intent = Intent::from_str("llm:completion")
            .with_constraint(Constraint::ExcludeAgent(AgentId::from_node_id(test_node_id(1))));

        let results = router.discover(&intent);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent.node_id(), &test_node_id(2));
    }

    #[test]
    fn test_discover_multi() {
        let mut router = SemanticRouter::new(test_node_id(0));

        // Node 1 has both capabilities
        router.register(test_node_id(1), SemanticCapability::new("llm:completion"));
        router.register(test_node_id(1), SemanticCapability::new("llm:embedding"));

        // Node 2 has only completion
        router.register(test_node_id(2), SemanticCapability::new("llm:completion"));

        let intents = vec![
            Intent::from_str("llm:completion"),
            Intent::from_str("llm:embedding"),
        ];

        let results = router.discover_multi(&intents);

        // Only node 1 has both
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], test_node_id(1));
    }

    #[test]
    fn test_reputation_update() {
        let mut router = SemanticRouter::new(test_node_id(0));

        // Initial reputation should be 0.5
        assert_eq!(router.get_reputation(&test_node_id(1)), 0.5);

        // Successful fast response increases reputation
        router.update_reputation(&test_node_id(1), true, 50);
        assert!(router.get_reputation(&test_node_id(1)) > 0.5);

        // Failed response decreases reputation
        router.update_reputation(&test_node_id(1), false, 0);
        let rep_after_fail = router.get_reputation(&test_node_id(1));
        assert!(rep_after_fail < 0.95); // Should have decreased
    }

    #[test]
    fn test_semantic_query() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(
            test_node_id(1),
            SemanticCapability::new("llm:completion")
                .with_tag("fast")
                .with_version(1, 0, 0),
        );
        router.register(
            test_node_id(2),
            SemanticCapability::new("llm:completion")
                .with_tag("slow")
                .with_version(2, 0, 0),
        );

        // Query with version constraint
        let results = SemanticQuery::new()
            .category("llm")
            .min_version(1, 5, 0)
            .execute(&router);

        // Only version 2.0.0 passes
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent.node_id(), &test_node_id(2));
    }

    #[test]
    fn test_semantic_query_with_preferred_tag() {
        let mut router = SemanticRouter::new(test_node_id(0));

        router.register(
            test_node_id(1),
            SemanticCapability::new("llm:completion").with_tag("fast"),
        );
        router.register(
            test_node_id(2),
            SemanticCapability::new("llm:completion").with_tag("slow"),
        );

        let results = SemanticQuery::new()
            .category("llm")
            .prefer_tag("fast")
            .execute(&router);

        // Both returned, but fast should be first (higher score)
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].agent.node_id(), &test_node_id(1)); // fast first
    }
}
