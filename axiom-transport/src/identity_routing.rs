//! L3 Identity Routing - IP-Free Networking Layer
//!
//! Implements identity-based routing where NodeId (cryptographic public key)
//! replaces IP addresses. No IP, no ports, no DNS needed.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Layer 4: INTENT          "I need llm:completion"              │
//! │  Layer 3: IDENTITY        NodeId = 32-byte public key          │
//! │  Layer 2: MESH            Local broadcast, neighbor relay      │
//! │  Layer 1: PHYSICAL        Ethernet, UDP tunnel, etc.           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use axiom_types::crypto::{NodeId, IntentHash};
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

/// Physical layer address abstraction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PhysicalAddress {
    /// Ethernet MAC address
    Ethernet([u8; 6]),
    /// UDP tunnel (for legacy networks) - IP:port encoded
    UdpTunnel { addr: [u8; 4], port: u16 },
    /// IPv6 UDP tunnel. `scope_id` is required (not optional) because
    /// link-local addresses (fe80::/64) are only meaningful paired with the
    /// interface they were learned on - the same fe80 address can exist
    /// simultaneously on every interface of a host.
    Udp6Tunnel { addr: [u8; 16], port: u16, scope_id: u32 },
    /// Local/virtual connection
    Local(u64),
}

impl PhysicalAddress {
    /// Create from Ethernet MAC
    pub fn ethernet(mac: [u8; 6]) -> Self {
        Self::Ethernet(mac)
    }

    /// Create from IPv4 UDP tunnel
    pub fn udp_tunnel(ip: [u8; 4], port: u16) -> Self {
        Self::UdpTunnel { addr: ip, port }
    }

    /// Create from IPv6 UDP tunnel (e.g. a link-local discovery peer)
    pub fn udp6_tunnel(ip: [u8; 16], port: u16, scope_id: u32) -> Self {
        Self::Udp6Tunnel { addr: ip, port, scope_id }
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        match self {
            Self::Ethernet(mac) => mac == &[0xFF; 6],
            _ => false,
        }
    }
}

/// Information about a direct neighbor
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    /// Their cryptographic identity
    pub node_id: NodeId,
    /// Physical layer address
    pub physical_addr: PhysicalAddress,
    /// Link quality (0-255, higher is better)
    pub link_quality: u8,
    /// Round-trip latency in microseconds
    pub latency_us: u32,
    /// Last seen timestamp (unix millis)
    pub last_seen: u64,
    /// Capabilities they've announced
    pub capabilities: Vec<IntentHash>,
    /// Trust level with this neighbor
    pub trust_level: TrustLevel,
}

/// Route information for reaching a non-neighbor node
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Destination NodeId
    pub destination: NodeId,
    /// Next hop to reach destination
    pub next_hop: NodeId,
    /// Total hops to destination
    pub hop_count: u8,
    /// Path trust score (0.0 - 1.0)
    pub path_trust: f32,
    /// Estimated latency in microseconds
    pub latency_us: u32,
    /// Route freshness (unix millis)
    pub last_updated: u64,
    /// Alternative paths
    pub alternatives: Vec<NodeId>,
}

/// Identity-based routing table (replaces IP routing)
pub struct IdentityRouter {
    /// Our identity
    local_id: NodeId,

    /// Direct neighbors (one hop away)
    neighbors: HashMap<NodeId, NeighborInfo>,

    /// Routes to non-neighbors
    routes: HashMap<NodeId, RouteInfo>,

    /// Intent-based routes: IntentHash → capable NodeIds
    intent_routes: HashMap<IntentHash, Vec<NodeId>>,

    /// Physical address resolution (NodeId → PhysicalAddress for neighbors)
    physical_map: HashMap<NodeId, PhysicalAddress>,

    /// Pending route discoveries
    pending_discoveries: HashMap<NodeId, RouteDiscovery>,

    /// Configuration
    config: RouterConfig,
}

/// Router configuration
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum hops for route discovery
    pub max_hops: u8,
    /// Route expiry time in milliseconds
    pub route_expiry_ms: u64,
    /// Neighbor expiry time in milliseconds
    pub neighbor_expiry_ms: u64,
    /// Maximum neighbors to track
    pub max_neighbors: usize,
    /// Maximum routes to track
    pub max_routes: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            max_hops: 16,
            route_expiry_ms: 60_000,      // 1 minute
            neighbor_expiry_ms: 30_000,    // 30 seconds
            max_neighbors: 256,
            max_routes: 4096,
        }
    }
}

/// Pending route discovery state
#[derive(Debug)]
struct RouteDiscovery {
    target: NodeId,
    started_at: u64,
    attempts: u8,
    responses: Vec<RouteInfo>,
}

/// Result of a routing decision
#[derive(Debug)]
pub enum RoutingDecision {
    /// Deliver locally (we are the destination)
    DeliverLocal,
    /// Forward to neighbor (includes physical address)
    Forward {
        next_hop: NodeId,
        physical_addr: PhysicalAddress,
    },
    /// Broadcast to all neighbors
    Broadcast,
    /// Need to discover route first
    DiscoverRoute(NodeId),
    /// No route available
    NoRoute,
    /// Drop (TTL exceeded, loop detected, etc.)
    Drop(DropReason),
}

/// Reason for dropping a frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    TtlExceeded,
    LoopDetected,
    Untrusted,
    NoRoute,
}

/// L3 frame for identity-based routing
#[derive(Debug, Clone)]
pub struct IdentityFrame {
    /// Frame version
    pub version: u8,
    /// Frame type
    pub frame_type: IdentityFrameType,
    /// Source identity
    pub source: NodeId,
    /// Destination identity (all zeros = broadcast)
    pub destination: NodeId,
    /// Intent hash (for intent-based routing)
    pub intent: IntentHash,
    /// Time-to-live (hop limit)
    pub ttl: u8,
    /// Frame ID for deduplication
    pub frame_id: u64,
    /// Payload
    pub payload: Vec<u8>,
}

/// Identity frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFrameType {
    /// Regular data frame
    Data,
    /// Neighbor discovery hello
    NeighborHello,
    /// Neighbor goodbye
    NeighborBye,
    /// Route query
    RouteQuery,
    /// Route response
    RouteReply,
    /// Intent announcement
    IntentAnnounce,
    /// Intent query
    IntentQuery,
    /// Ping
    Ping,
    /// Pong
    Pong,
}

impl IdentityRouter {
    /// Create a new identity router
    pub fn new(local_id: NodeId, config: RouterConfig) -> Self {
        Self {
            local_id,
            neighbors: HashMap::new(),
            routes: HashMap::new(),
            intent_routes: HashMap::new(),
            physical_map: HashMap::new(),
            pending_discoveries: HashMap::new(),
            config,
        }
    }

    /// Get our local identity
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    // =========================================================================
    // NEIGHBOR MANAGEMENT (Replaces ARP)
    // =========================================================================

    /// Register a new neighbor (from hello message)
    pub fn add_neighbor(&mut self, info: NeighborInfo) {
        if self.neighbors.len() >= self.config.max_neighbors {
            // Evict oldest neighbor
            self.evict_oldest_neighbor();
        }

        self.physical_map.insert(info.node_id.clone(), info.physical_addr.clone());
        self.neighbors.insert(info.node_id.clone(), info);
    }

    /// Remove a neighbor
    pub fn remove_neighbor(&mut self, node_id: &NodeId) {
        self.neighbors.remove(node_id);
        self.physical_map.remove(node_id);

        // Invalidate routes through this neighbor
        self.routes.retain(|_, route| &route.next_hop != node_id);
    }

    /// Update neighbor metrics
    pub fn update_neighbor(&mut self, node_id: &NodeId, latency_us: u32, link_quality: u8) {
        if let Some(neighbor) = self.neighbors.get_mut(node_id) {
            neighbor.latency_us = latency_us;
            neighbor.link_quality = link_quality;
        }
    }

    /// Get neighbor info
    pub fn get_neighbor(&self, node_id: &NodeId) -> Option<&NeighborInfo> {
        self.neighbors.get(node_id)
    }

    /// List all neighbors
    pub fn neighbors(&self) -> impl Iterator<Item = &NeighborInfo> {
        self.neighbors.values()
    }

    /// Check if node is a direct neighbor
    pub fn is_neighbor(&self, node_id: &NodeId) -> bool {
        self.neighbors.contains_key(node_id)
    }

    fn evict_oldest_neighbor(&mut self) {
        if let Some(oldest) = self.neighbors
            .iter()
            .min_by_key(|(_, n)| n.last_seen)
            .map(|(id, _)| id.clone())
        {
            self.remove_neighbor(&oldest);
        }
    }

    // =========================================================================
    // ROUTING (Replaces IP Routing Table)
    // =========================================================================

    /// Make a routing decision for a frame
    pub fn route(&self, frame: &IdentityFrame) -> RoutingDecision {
        // Check TTL
        if frame.ttl == 0 {
            return RoutingDecision::Drop(DropReason::TtlExceeded);
        }

        // Check if destination is us
        if frame.destination == self.local_id {
            return RoutingDecision::DeliverLocal;
        }

        // Check if destination is broadcast (all zeros)
        if frame.destination == NodeId::zero() {
            return RoutingDecision::Broadcast;
        }

        // Check if destination is a direct neighbor
        if let Some(neighbor) = self.neighbors.get(&frame.destination) {
            return RoutingDecision::Forward {
                next_hop: frame.destination.clone(),
                physical_addr: neighbor.physical_addr.clone(),
            };
        }

        // Check routing table
        if let Some(route) = self.routes.get(&frame.destination) {
            if let Some(physical) = self.physical_map.get(&route.next_hop) {
                return RoutingDecision::Forward {
                    next_hop: route.next_hop.clone(),
                    physical_addr: physical.clone(),
                };
            }
        }

        // Need to discover route
        RoutingDecision::DiscoverRoute(frame.destination.clone())
    }

    /// Route by intent (find capable node)
    pub fn route_by_intent(&self, intent: &IntentHash) -> Option<RoutingDecision> {
        let capable_nodes = self.intent_routes.get(intent)?;

        // Score and select best node
        let best = capable_nodes.iter()
            .filter_map(|node_id| {
                // Prefer neighbors
                if let Some(neighbor) = self.neighbors.get(node_id) {
                    Some((node_id, self.score_neighbor(neighbor)))
                } else if let Some(route) = self.routes.get(node_id) {
                    Some((node_id, self.score_route(route)))
                } else {
                    None
                }
            })
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));

        best.map(|(node_id, _)| {
            if let Some(neighbor) = self.neighbors.get(node_id) {
                RoutingDecision::Forward {
                    next_hop: node_id.clone(),
                    physical_addr: neighbor.physical_addr.clone(),
                }
            } else if let Some(route) = self.routes.get(node_id) {
                if let Some(physical) = self.physical_map.get(&route.next_hop) {
                    RoutingDecision::Forward {
                        next_hop: route.next_hop.clone(),
                        physical_addr: physical.clone(),
                    }
                } else {
                    RoutingDecision::NoRoute
                }
            } else {
                RoutingDecision::NoRoute
            }
        })
    }

    /// Score a neighbor for route selection
    fn score_neighbor(&self, neighbor: &NeighborInfo) -> f32 {
        let trust_score = match neighbor.trust_level {
            TrustLevel::Full => 1.0,
            TrustLevel::Sig => 0.8,
            TrustLevel::Compress => 0.6,
            TrustLevel::Raw => 0.4,
        };
        let latency_score = 1.0 - (neighbor.latency_us as f32 / 1_000_000.0).min(1.0);
        let quality_score = neighbor.link_quality as f32 / 255.0;

        trust_score * 0.4 + latency_score * 0.3 + quality_score * 0.3
    }

    /// Score a route for selection
    fn score_route(&self, route: &RouteInfo) -> f32 {
        let hop_score = 1.0 - (route.hop_count as f32 / self.config.max_hops as f32);
        let trust_score = route.path_trust;
        let latency_score = 1.0 - (route.latency_us as f32 / 1_000_000.0).min(1.0);

        trust_score * 0.4 + hop_score * 0.3 + latency_score * 0.3
    }

    /// Add or update a route
    pub fn add_route(&mut self, route: RouteInfo) {
        if self.routes.len() >= self.config.max_routes {
            self.evict_worst_route();
        }
        self.routes.insert(route.destination.clone(), route);
    }

    /// Get route to a destination
    pub fn get_route(&self, destination: &NodeId) -> Option<&RouteInfo> {
        self.routes.get(destination)
    }

    fn evict_worst_route(&mut self) {
        if let Some(worst) = self.routes
            .iter()
            .min_by(|(_, a), (_, b)| {
                self.score_route(a).partial_cmp(&self.score_route(b))
                    .unwrap_or(core::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id.clone())
        {
            self.routes.remove(&worst);
        }
    }

    // =========================================================================
    // INTENT ROUTING
    // =========================================================================

    /// Register capability for intent routing
    pub fn register_intent(&mut self, intent: IntentHash, provider: NodeId) {
        self.intent_routes
            .entry(intent)
            .or_insert_with(Vec::new)
            .push(provider);
    }

    /// Unregister capability
    pub fn unregister_intent(&mut self, intent: &IntentHash, provider: &NodeId) {
        if let Some(providers) = self.intent_routes.get_mut(intent) {
            providers.retain(|p| p != provider);
            if providers.is_empty() {
                self.intent_routes.remove(intent);
            }
        }
    }

    /// Get providers for an intent
    pub fn get_intent_providers(&self, intent: &IntentHash) -> Option<&Vec<NodeId>> {
        self.intent_routes.get(intent)
    }

    // =========================================================================
    // MAINTENANCE
    // =========================================================================

    /// Clean up stale entries
    pub fn cleanup(&mut self, now_ms: u64) {
        // Remove stale neighbors
        let neighbor_expiry = now_ms.saturating_sub(self.config.neighbor_expiry_ms);
        let stale_neighbors: Vec<_> = self.neighbors
            .iter()
            .filter(|(_, n)| n.last_seen < neighbor_expiry)
            .map(|(id, _)| id.clone())
            .collect();

        for id in stale_neighbors {
            self.remove_neighbor(&id);
        }

        // Remove stale routes
        let route_expiry = now_ms.saturating_sub(self.config.route_expiry_ms);
        self.routes.retain(|_, r| r.last_updated >= route_expiry);
    }

    /// Get router statistics
    pub fn stats(&self) -> RouterStats {
        RouterStats {
            neighbor_count: self.neighbors.len(),
            route_count: self.routes.len(),
            intent_count: self.intent_routes.len(),
        }
    }
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct RouterStats {
    pub neighbor_count: usize,
    pub route_count: usize,
    pub intent_count: usize,
}

// =========================================================================
// NEIGHBOR DISCOVERY PROTOCOL
// =========================================================================

/// Neighbor hello message
#[derive(Debug, Clone)]
pub struct NeighborHello {
    /// Sender's NodeId
    pub node_id: NodeId,
    /// Sender's capabilities
    pub capabilities: Vec<IntentHash>,
    /// Protocol version
    pub version: u8,
}

impl NeighborHello {
    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34 + self.capabilities.len() * 16);
        buf.push(self.version);
        buf.extend_from_slice(self.node_id.as_bytes());
        buf.push(self.capabilities.len() as u8);
        for cap in &self.capabilities {
            buf.extend_from_slice(cap.as_bytes());
        }
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 34 {
            return None;
        }

        let version = data[0];
        let node_id = NodeId::from_bytes(data[1..33].try_into().ok()?);
        let cap_count = data[33] as usize;

        if data.len() < 34 + cap_count * 16 {
            return None;
        }

        let mut capabilities = Vec::with_capacity(cap_count);
        for i in 0..cap_count {
            let start = 34 + i * 16;
            let hash = IntentHash::from_bytes(data[start..start+16].try_into().ok()?);
            capabilities.push(hash);
        }

        Some(Self {
            node_id,
            capabilities,
            version,
        })
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    #[test]
    fn test_add_neighbor() {
        let mut router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        let neighbor = NeighborInfo {
            node_id: test_node_id(1),
            physical_addr: PhysicalAddress::ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            link_quality: 200,
            latency_us: 1000,
            last_seen: 12345,
            capabilities: vec![test_intent(1)],
            trust_level: TrustLevel::Sig,
        };

        router.add_neighbor(neighbor);

        assert!(router.is_neighbor(&test_node_id(1)));
        assert_eq!(router.stats().neighbor_count, 1);
    }

    #[test]
    fn test_route_to_neighbor() {
        let mut router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        router.add_neighbor(NeighborInfo {
            node_id: test_node_id(1),
            physical_addr: PhysicalAddress::ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            link_quality: 200,
            latency_us: 1000,
            last_seen: 12345,
            capabilities: vec![],
            trust_level: TrustLevel::Sig,
        });

        let frame = IdentityFrame {
            version: 1,
            frame_type: IdentityFrameType::Data,
            source: test_node_id(0),
            destination: test_node_id(1),
            intent: test_intent(0),
            ttl: 16,
            frame_id: 1,
            payload: vec![],
        };

        match router.route(&frame) {
            RoutingDecision::Forward { next_hop, .. } => {
                assert_eq!(next_hop, test_node_id(1));
            }
            _ => panic!("Expected Forward decision"),
        }
    }

    #[test]
    fn test_route_to_self() {
        let router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        let frame = IdentityFrame {
            version: 1,
            frame_type: IdentityFrameType::Data,
            source: test_node_id(1),
            destination: test_node_id(0),
            intent: test_intent(0),
            ttl: 16,
            frame_id: 1,
            payload: vec![],
        };

        match router.route(&frame) {
            RoutingDecision::DeliverLocal => {}
            _ => panic!("Expected DeliverLocal decision"),
        }
    }

    #[test]
    fn test_route_broadcast() {
        // Use non-zero local_id since NodeId::zero() is the broadcast address
        let router = IdentityRouter::new(test_node_id(1), RouterConfig::default());

        let frame = IdentityFrame {
            version: 1,
            frame_type: IdentityFrameType::Data,
            source: test_node_id(2),
            destination: NodeId::zero(), // Broadcast address
            intent: test_intent(0),
            ttl: 16,
            frame_id: 1,
            payload: vec![],
        };

        match router.route(&frame) {
            RoutingDecision::Broadcast => {}
            _ => panic!("Expected Broadcast decision"),
        }
    }

    #[test]
    fn test_ttl_exceeded() {
        let router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        let frame = IdentityFrame {
            version: 1,
            frame_type: IdentityFrameType::Data,
            source: test_node_id(1),
            destination: test_node_id(2),
            intent: test_intent(0),
            ttl: 0,
            frame_id: 1,
            payload: vec![],
        };

        match router.route(&frame) {
            RoutingDecision::Drop(DropReason::TtlExceeded) => {}
            _ => panic!("Expected Drop(TtlExceeded) decision"),
        }
    }

    #[test]
    fn test_intent_routing() {
        let mut router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        // Add neighbor with capability
        router.add_neighbor(NeighborInfo {
            node_id: test_node_id(1),
            physical_addr: PhysicalAddress::ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            link_quality: 200,
            latency_us: 1000,
            last_seen: 12345,
            capabilities: vec![test_intent(1)],
            trust_level: TrustLevel::Sig,
        });

        router.register_intent(test_intent(1), test_node_id(1));

        match router.route_by_intent(&test_intent(1)) {
            Some(RoutingDecision::Forward { next_hop, .. }) => {
                assert_eq!(next_hop, test_node_id(1));
            }
            _ => panic!("Expected Forward decision"),
        }
    }

    #[test]
    fn test_multi_hop_route() {
        let mut router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        // Add neighbor (node 1)
        router.add_neighbor(NeighborInfo {
            node_id: test_node_id(1),
            physical_addr: PhysicalAddress::ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            link_quality: 200,
            latency_us: 1000,
            last_seen: 12345,
            capabilities: vec![],
            trust_level: TrustLevel::Sig,
        });

        // Add route to node 2 via node 1
        router.add_route(RouteInfo {
            destination: test_node_id(2),
            next_hop: test_node_id(1),
            hop_count: 2,
            path_trust: 0.8,
            latency_us: 2000,
            last_updated: 12345,
            alternatives: vec![],
        });

        let frame = IdentityFrame {
            version: 1,
            frame_type: IdentityFrameType::Data,
            source: test_node_id(0),
            destination: test_node_id(2),
            intent: test_intent(0),
            ttl: 16,
            frame_id: 1,
            payload: vec![],
        };

        match router.route(&frame) {
            RoutingDecision::Forward { next_hop, .. } => {
                assert_eq!(next_hop, test_node_id(1)); // Route via node 1
            }
            _ => panic!("Expected Forward decision"),
        }
    }

    #[test]
    fn test_neighbor_hello_roundtrip() {
        let hello = NeighborHello {
            node_id: test_node_id(42),
            capabilities: vec![test_intent(1), test_intent(2)],
            version: 1,
        };

        let encoded = hello.encode();
        let decoded = NeighborHello::decode(&encoded).unwrap();

        assert_eq!(decoded.node_id, hello.node_id);
        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.version, 1);
    }

    #[test]
    fn test_udp6_tunnel_scope_id() {
        // Same address, different scope_id -> must not collapse to the same
        // key if ever used in a map keyed by PhysicalAddress (Hash/Eq derive
        // includes scope_id).
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a = PhysicalAddress::udp6_tunnel(addr, 7790, 2);
        let b = PhysicalAddress::udp6_tunnel(addr, 7790, 3);
        assert_ne!(a, b);

        match a {
            PhysicalAddress::Udp6Tunnel { addr: got_addr, port, scope_id } => {
                assert_eq!(got_addr, addr);
                assert_eq!(port, 7790);
                assert_eq!(scope_id, 2);
            }
            _ => panic!("Expected Udp6Tunnel"),
        }
    }

    #[test]
    fn test_cleanup() {
        let mut router = IdentityRouter::new(test_node_id(0), RouterConfig::default());

        router.add_neighbor(NeighborInfo {
            node_id: test_node_id(1),
            physical_addr: PhysicalAddress::ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            link_quality: 200,
            latency_us: 1000,
            last_seen: 1000, // Old timestamp
            capabilities: vec![],
            trust_level: TrustLevel::Sig,
        });

        assert_eq!(router.stats().neighbor_count, 1);

        // Cleanup with current time far in future
        router.cleanup(1_000_000);

        assert_eq!(router.stats().neighbor_count, 0);
    }
}
