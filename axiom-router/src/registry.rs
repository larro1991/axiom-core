//! Node Registry - Maps AI identities to network endpoints
//!
//! This module provides the crucial abstraction layer between:
//! - AI-native concepts (NodeId = identity = address)
//! - Legacy network reality (IP addresses, ports)
//!
//! The registry is responsible for:
//! - Mapping NodeId to transport endpoint
//! - Tracking node availability and health
//! - Handling endpoint changes (mobility, failover)
//!
//! # Philosophy
//!
//! AI doesn't care about IP:port. AI cares about identity.
//! This registry translates "who" (NodeId) to "where" (endpoint).
//! It's the last place legacy networking concepts should appear.

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::NodeId;
use hashbrown::HashMap;

/// Abstract endpoint - hides transport-specific details
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// Direct UDP endpoint (IPv4/IPv6:port)
    /// This is a necessary evil - the actual network uses addresses
    /// But it's encapsulated here, not leaked to AI code
    Udp(String),
    /// Relay through another node (for NAT traversal)
    Relay {
        via: NodeId,
        token: [u8; 16],
    },
    /// Local (same process)
    Local,
}

impl Endpoint {
    /// Create UDP endpoint from address string
    pub fn udp(addr: &str) -> Self {
        Self::Udp(String::from(addr))
    }

    /// Create relay endpoint
    pub fn relay(via: NodeId, token: [u8; 16]) -> Self {
        Self::Relay { via, token }
    }

    /// Check if endpoint is local
    pub fn is_local(&self) -> bool {
        matches!(self, Endpoint::Local)
    }

    /// Check if endpoint needs relay
    pub fn needs_relay(&self) -> bool {
        matches!(self, Endpoint::Relay { .. })
    }
}

/// Node registration info
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Primary endpoint
    pub endpoint: Endpoint,
    /// Alternative endpoints (fallback)
    pub alternatives: Vec<Endpoint>,
    /// Last successful contact (Unix timestamp)
    pub last_seen: u64,
    /// Latency estimate (microseconds)
    pub latency_us: u32,
    /// Is this node currently reachable?
    pub reachable: bool,
    /// Custom metadata (opaque to registry)
    pub metadata: Option<Vec<u8>>,
}

impl NodeInfo {
    /// Create new node info with UDP endpoint
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            alternatives: Vec::new(),
            last_seen: 0,
            latency_us: 0,
            reachable: true,
            metadata: None,
        }
    }

    /// Add alternative endpoint
    pub fn with_alternative(mut self, endpoint: Endpoint) -> Self {
        self.alternatives.push(endpoint);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Get best available endpoint
    pub fn best_endpoint(&self) -> &Endpoint {
        if self.reachable {
            &self.endpoint
        } else {
            // Try alternatives
            self.alternatives.first().unwrap_or(&self.endpoint)
        }
    }

    /// Mark as unreachable and promote next alternative
    pub fn mark_unreachable(&mut self) {
        self.reachable = false;
        if !self.alternatives.is_empty() {
            // Rotate: move primary to end, promote first alternative
            let old_primary = self.endpoint.clone();
            self.endpoint = self.alternatives.remove(0);
            self.alternatives.push(old_primary);
            self.reachable = true; // Try the new primary
        }
    }

    /// Update on successful contact
    pub fn mark_reachable(&mut self, now_unix: u64, latency_us: u32) {
        self.reachable = true;
        self.last_seen = now_unix;
        // Exponential moving average for latency
        self.latency_us = if self.latency_us == 0 {
            latency_us
        } else {
            (self.latency_us * 7 + latency_us) / 8
        };
    }
}

/// Node registry - the bridge between identity and network
pub struct NodeRegistry {
    /// NodeId -> NodeInfo mapping
    nodes: HashMap<NodeId, NodeInfo>,
    /// Our own NodeId
    local_id: NodeId,
    /// Our own endpoint (for announcements)
    local_endpoint: Endpoint,
}

impl NodeRegistry {
    /// Create a new registry
    pub fn new(local_id: NodeId, local_endpoint: Endpoint) -> Self {
        Self {
            nodes: HashMap::new(),
            local_id,
            local_endpoint,
        }
    }

    /// Get our local NodeId
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Get our local endpoint
    pub fn local_endpoint(&self) -> &Endpoint {
        &self.local_endpoint
    }

    /// Register a node
    pub fn register(&mut self, node_id: NodeId, info: NodeInfo) {
        self.nodes.insert(node_id, info);
    }

    /// Unregister a node
    pub fn unregister(&mut self, node_id: &NodeId) {
        self.nodes.remove(node_id);
    }

    /// Look up endpoint for a node
    pub fn lookup(&self, node_id: &NodeId) -> Option<&NodeInfo> {
        if node_id == &self.local_id {
            return None; // Can't look up self
        }
        self.nodes.get(node_id)
    }

    /// Get endpoint for sending to a node
    pub fn endpoint_for(&self, node_id: &NodeId) -> Option<&Endpoint> {
        self.lookup(node_id).map(|info| info.best_endpoint())
    }

    /// Update node on successful contact
    pub fn mark_success(&mut self, node_id: &NodeId, now_unix: u64, latency_us: u32) {
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.mark_reachable(now_unix, latency_us);
        }
    }

    /// Mark node as unreachable (will try alternatives)
    pub fn mark_failure(&mut self, node_id: &NodeId) {
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.mark_unreachable();
        }
    }

    /// Get all registered nodes
    pub fn all_nodes(&self) -> impl Iterator<Item = (&NodeId, &NodeInfo)> {
        self.nodes.iter()
    }

    /// Get number of registered nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Cleanup stale nodes (not seen for max_age_secs)
    pub fn cleanup_stale(&mut self, now_unix: u64, max_age_secs: u64) {
        self.nodes.retain(|_, info| {
            now_unix.saturating_sub(info.last_seen) < max_age_secs
        });
    }

    /// Get nodes sorted by latency (best first)
    pub fn by_latency(&self) -> Vec<(&NodeId, &NodeInfo)> {
        let mut nodes: Vec<_> = self.nodes.iter().collect();
        nodes.sort_by_key(|(_, info)| info.latency_us);
        nodes
    }

    /// Find nodes matching a predicate
    pub fn find<F>(&self, predicate: F) -> Vec<&NodeId>
    where
        F: Fn(&NodeInfo) -> bool,
    {
        self.nodes
            .iter()
            .filter(|(_, info)| predicate(info))
            .map(|(id, _)| id)
            .collect()
    }
}

/// Event emitted when registry changes
#[derive(Debug, Clone)]
pub enum RegistryEvent {
    /// New node registered
    NodeAdded(NodeId),
    /// Node removed
    NodeRemoved(NodeId),
    /// Node endpoint changed
    EndpointChanged(NodeId),
    /// Node became unreachable
    NodeUnreachable(NodeId),
    /// Node became reachable again
    NodeReachable(NodeId),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_endpoint_types() {
        let udp = Endpoint::udp("127.0.0.1:8080");
        assert!(!udp.is_local());
        assert!(!udp.needs_relay());

        let local = Endpoint::Local;
        assert!(local.is_local());

        let relay = Endpoint::relay(test_node_id(1), [0; 16]);
        assert!(relay.needs_relay());
    }

    #[test]
    fn test_registry_basic() {
        let local = test_node_id(0);
        let mut registry = NodeRegistry::new(local.clone(), Endpoint::Local);

        // Register a node
        let node1 = test_node_id(1);
        registry.register(node1.clone(), NodeInfo::new(Endpoint::udp("192.168.1.1:8080")));

        assert_eq!(registry.len(), 1);
        assert!(registry.lookup(&node1).is_some());
        assert!(registry.lookup(&local).is_none()); // Can't look up self
    }

    #[test]
    fn test_endpoint_failover() {
        let mut info = NodeInfo::new(Endpoint::udp("primary:8080"))
            .with_alternative(Endpoint::udp("backup1:8080"))
            .with_alternative(Endpoint::udp("backup2:8080"));

        assert_eq!(info.best_endpoint(), &Endpoint::udp("primary:8080"));

        // Primary fails
        info.mark_unreachable();
        assert_eq!(info.best_endpoint(), &Endpoint::udp("backup1:8080"));

        // First backup fails
        info.mark_unreachable();
        assert_eq!(info.best_endpoint(), &Endpoint::udp("backup2:8080"));
    }

    #[test]
    fn test_latency_tracking() {
        let mut info = NodeInfo::new(Endpoint::Local);

        // First measurement
        info.mark_reachable(1000, 100);
        assert_eq!(info.latency_us, 100);

        // EMA update (7/8 old + 1/8 new)
        info.mark_reachable(1001, 200);
        assert_eq!(info.latency_us, (100 * 7 + 200) / 8); // 112
    }

    #[test]
    fn test_cleanup_stale() {
        let local = test_node_id(0);
        let mut registry = NodeRegistry::new(local, Endpoint::Local);

        let mut info1 = NodeInfo::new(Endpoint::udp("node1:8080"));
        info1.last_seen = 1000;

        let mut info2 = NodeInfo::new(Endpoint::udp("node2:8080"));
        info2.last_seen = 900; // Older

        registry.register(test_node_id(1), info1);
        registry.register(test_node_id(2), info2);

        assert_eq!(registry.len(), 2);

        // Clean up nodes not seen in last 150 seconds
        registry.cleanup_stale(1050, 150);

        assert_eq!(registry.len(), 1); // Only node1 survives
    }

    #[test]
    fn test_find_by_predicate() {
        let local = test_node_id(0);
        let mut registry = NodeRegistry::new(local, Endpoint::Local);

        let mut fast_node = NodeInfo::new(Endpoint::udp("fast:8080"));
        fast_node.latency_us = 10;

        let mut slow_node = NodeInfo::new(Endpoint::udp("slow:8080"));
        slow_node.latency_us = 1000;

        registry.register(test_node_id(1), fast_node);
        registry.register(test_node_id(2), slow_node);

        // Find fast nodes (latency < 100)
        let fast = registry.find(|info| info.latency_us < 100);
        assert_eq!(fast.len(), 1);
    }
}
