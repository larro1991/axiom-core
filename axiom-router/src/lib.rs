//! Intent-Based Routing for AXIOM
//!
//! This crate provides the routing layer that maps IntentHashes to
//! capable nodes in the mesh.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Submodules
pub mod ai;
pub mod announce;
pub mod bootstrap;
pub mod forward;
pub mod registry;
pub mod semantic;

// Re-export commonly used types
pub use announce::{
    AnnouncedCapability, AnnouncementManager, AnnouncementScheduler, AnnouncePayload,
};
pub use bootstrap::{
    BootstrapConfig, MeshManager, MeshStats, PeerState, PeerInfo, LeaveReason,
};
pub use forward::{
    ForwardDecision, ForwardingEngine, ForwardingStats, DropReason,
    LoadBalancer, LoadBalanceStrategy,
};

use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

/// Entry in the routing table
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Node that can fulfill this intent
    pub node_id: NodeId,
    /// Trust level with this node
    pub trust_level: TrustLevel,
    /// Observed latency in milliseconds
    pub latency_ms: u16,
    /// Load indicator (0-255, lower = more available)
    pub capacity: u8,
    /// Last seen timestamp (Unix seconds)
    pub last_seen: u32,
}

/// Routing table for intent-based routing
pub struct RoutingTable {
    /// Map from intent hash to capable nodes
    routes: HashMap<IntentHash, Vec<RouteEntry>>,
    /// Local node ID
    local_id: NodeId,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(local_id: NodeId) -> Self {
        Self {
            routes: HashMap::new(),
            local_id,
        }
    }

    /// Register a capability at a node
    pub fn register(&mut self, intent_hash: IntentHash, entry: RouteEntry) {
        self.routes
            .entry(intent_hash)
            .or_insert_with(Vec::new)
            .push(entry);
    }

    /// Remove a node's capability
    pub fn unregister(&mut self, intent_hash: &IntentHash, node_id: &NodeId) {
        if let Some(entries) = self.routes.get_mut(intent_hash) {
            entries.retain(|e| &e.node_id != node_id);
            if entries.is_empty() {
                self.routes.remove(intent_hash);
            }
        }
    }

    /// Look up routes for an intent
    pub fn lookup(&self, intent_hash: &IntentHash) -> Option<&Vec<RouteEntry>> {
        self.routes.get(intent_hash)
    }

    /// Select the best route based on scoring
    pub fn select_best(&self, intent_hash: &IntentHash, priority: u8) -> Option<&RouteEntry> {
        self.routes.get(intent_hash).and_then(|entries| {
            entries.iter().max_by_key(|e| {
                // Score: prefer trusted, available, fast nodes
                let trust_score = (e.trust_level as u32) * 100;
                let capacity_score = (255 - e.capacity as u32) * 10;
                let latency_score = (1000u32).saturating_sub(e.latency_ms as u32);
                let priority_mult = if priority > 200 { 2 } else { 1 };

                (trust_score + capacity_score + latency_score) * priority_mult
            })
        })
    }

    /// Select top K routes for multi-path routing
    pub fn select_top_k(&self, intent_hash: &IntentHash, k: usize) -> Vec<&RouteEntry> {
        let Some(entries) = self.routes.get(intent_hash) else {
            return Vec::new();
        };

        let mut scored: Vec<_> = entries
            .iter()
            .map(|e| {
                let score = (e.trust_level as u32) * 100
                    + (255 - e.capacity as u32) * 10
                    + (1000u32).saturating_sub(e.latency_ms as u32);
                (e, score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored.into_iter().take(k).map(|(e, _)| e).collect()
    }

    /// Update metrics for a route entry
    pub fn update_metrics(
        &mut self,
        intent_hash: &IntentHash,
        node_id: &NodeId,
        latency_ms: u16,
        capacity: u8,
    ) {
        if let Some(entries) = self.routes.get_mut(intent_hash) {
            if let Some(entry) = entries.iter_mut().find(|e| &e.node_id == node_id) {
                entry.latency_ms = latency_ms;
                entry.capacity = capacity;
            }
        }
    }

    /// Get number of known intents
    pub fn num_intents(&self) -> usize {
        self.routes.len()
    }

    /// Get total number of route entries
    pub fn num_routes(&self) -> usize {
        self.routes.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    #[test]
    fn test_register_and_lookup() {
        let mut table = RoutingTable::new(test_node_id(0));

        let intent = test_intent_hash(1);
        let entry = RouteEntry {
            node_id: test_node_id(2),
            trust_level: TrustLevel::Sig,
            latency_ms: 50,
            capacity: 100,
            last_seen: 1700000000,
        };

        table.register(intent, entry);

        let routes = table.lookup(&intent).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].latency_ms, 50);
    }

    #[test]
    fn test_select_best() {
        let mut table = RoutingTable::new(test_node_id(0));

        let intent = test_intent_hash(1);

        // Add a slow node
        table.register(
            intent,
            RouteEntry {
                node_id: test_node_id(1),
                trust_level: TrustLevel::Sig,
                latency_ms: 200,
                capacity: 50,
                last_seen: 0,
            },
        );

        // Add a fast node
        table.register(
            intent,
            RouteEntry {
                node_id: test_node_id(2),
                trust_level: TrustLevel::Sig,
                latency_ms: 10,
                capacity: 50,
                last_seen: 0,
            },
        );

        let best = table.select_best(&intent, 128).unwrap();
        assert_eq!(best.node_id, test_node_id(2)); // Fast node wins
    }

    #[test]
    fn test_select_top_k() {
        let mut table = RoutingTable::new(test_node_id(0));

        let intent = test_intent_hash(1);

        for i in 0..5 {
            table.register(
                intent,
                RouteEntry {
                    node_id: test_node_id(i + 1),
                    trust_level: TrustLevel::Sig,
                    latency_ms: (i as u16 + 1) * 10,
                    capacity: 50,
                    last_seen: 0,
                },
            );
        }

        let top3 = table.select_top_k(&intent, 3);
        assert_eq!(top3.len(), 3);
        // Should be ordered by score (fastest first)
        assert_eq!(top3[0].latency_ms, 10);
    }
}
