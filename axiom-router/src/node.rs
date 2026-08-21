//! Unified mesh node API
//!
//! Integrates all routing components into a single, easy-to-use API:
//! - Routing table with load balancing
//! - Capability announcements with periodic refresh
//! - Multi-hop forwarding with loop detection
//! - Peer management with health tracking

use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::frame::Frame;
use axiom_types::trust::TrustLevel;

#[cfg(feature = "std")]
use std::net::SocketAddr;

use crate::{
    AnnouncedCapability, AnnouncementManager, AnnouncementScheduler, AnnouncePayload,
    BootstrapConfig, DropReason, ForwardDecision, ForwardingEngine,
    LoadBalanceStrategy, LoadBalancer, MeshManager, PeerState, RouteEntry, RoutingTable,
};

/// Configuration for a mesh node
#[derive(Debug, Clone)]
pub struct MeshNodeConfig {
    /// Bootstrap configuration
    pub bootstrap: BootstrapConfig,
    /// Load balancing strategy
    pub load_balance_strategy: LoadBalanceStrategy,
    /// Announcement interval (milliseconds)
    pub announce_interval_ms: u64,
    /// Announcement jitter (milliseconds)
    pub announce_jitter_ms: u64,
    /// Default TTL for announcements
    pub announce_ttl: u8,
    /// Max age for stale routes (seconds)
    pub route_max_age_seconds: u32,
}

impl Default for MeshNodeConfig {
    fn default() -> Self {
        Self {
            bootstrap: BootstrapConfig::default(),
            load_balance_strategy: LoadBalanceStrategy::PowerOfTwo,
            announce_interval_ms: 30000,
            announce_jitter_ms: 5000,
            announce_ttl: 8,
            route_max_age_seconds: 120,
        }
    }
}

/// Statistics for the mesh node
#[derive(Debug, Default, Clone)]
pub struct MeshNodeStats {
    /// Frames delivered locally
    pub frames_delivered: u64,
    /// Frames forwarded
    pub frames_forwarded: u64,
    /// Frames dropped (various reasons)
    pub frames_dropped: u64,
    /// Announcements sent
    pub announcements_sent: u64,
    /// Announcements processed
    pub announcements_received: u64,
    /// Routes learned
    pub routes_learned: u64,
}

/// A unified mesh node that integrates all routing components
#[cfg(feature = "std")]
pub struct MeshNode {
    /// Our node ID
    node_id: NodeId,
    /// Configuration
    config: MeshNodeConfig,
    /// Routing table
    routing_table: RoutingTable,
    /// Load balancer
    load_balancer: LoadBalancer,
    /// Announcement manager
    announcements: AnnouncementManager,
    /// Announcement scheduler
    scheduler: AnnouncementScheduler,
    /// Forwarding engine
    forwarding: ForwardingEngine,
    /// Mesh manager (peers)
    mesh: MeshManager,
    /// Statistics
    stats: MeshNodeStats,
}

#[cfg(feature = "std")]
impl MeshNode {
    /// Create a new mesh node
    pub fn new(node_id: NodeId, config: MeshNodeConfig) -> Self {
        Self {
            routing_table: RoutingTable::new(node_id.clone()),
            load_balancer: LoadBalancer::new(config.load_balance_strategy),
            announcements: AnnouncementManager::new(node_id.clone()),
            scheduler: AnnouncementScheduler::new(
                config.announce_interval_ms,
                config.announce_jitter_ms,
            ),
            forwarding: ForwardingEngine::new(node_id.clone()),
            mesh: MeshManager::new(node_id.clone(), config.bootstrap.clone()),
            stats: MeshNodeStats::default(),
            node_id,
            config,
        }
    }

    /// Get our node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // =========================================================================
    // Capability Management
    // =========================================================================

    /// Register a local capability
    pub fn register_capability(&mut self, intent_hash: IntentHash, category: [u8; 4]) {
        let cap = AnnouncedCapability::new(intent_hash, category);
        self.announcements.register_capability(cap);
        self.forwarding.register_local_intent(intent_hash);
    }

    /// Unregister a local capability
    pub fn unregister_capability(&mut self, intent_hash: &IntentHash) {
        self.announcements.unregister_capability(intent_hash);
        self.forwarding.unregister_local_intent(intent_hash);
    }

    /// Update load/latency metrics for a local capability
    pub fn update_capability_metrics(&mut self, intent_hash: &IntentHash, load: u8, latency_ms: u16) {
        self.announcements.update_capability_metrics(intent_hash, load, latency_ms);
    }

    // =========================================================================
    // Routing
    // =========================================================================

    /// Find the best route for an intent
    pub fn route(&mut self, intent_hash: &IntentHash) -> Option<&RouteEntry> {
        self.load_balancer.select(&self.routing_table, intent_hash)
    }

    /// Find multiple routes for an intent
    pub fn route_multi(&self, intent_hash: &IntentHash, count: usize) -> Vec<&RouteEntry> {
        self.routing_table.select_top_k(intent_hash, count)
    }

    /// Get all nodes that can handle an intent
    pub fn get_providers(&self, intent_hash: &IntentHash) -> Vec<NodeId> {
        self.routing_table.get_nodes_for_intent(intent_hash)
    }

    /// Check if we can handle an intent locally
    pub fn can_handle_locally(&self, intent_hash: &IntentHash) -> bool {
        self.announcements.local_capabilities()
            .iter()
            .any(|c| &c.intent_hash == intent_hash)
    }

    /// Upgrade trust level for a node after successful communication
    pub fn upgrade_node_trust(&mut self, intent_hash: &IntentHash, node_id: &NodeId, trust: TrustLevel) {
        self.routing_table.upgrade_trust(intent_hash, node_id, trust);
    }

    // =========================================================================
    // Forwarding
    // =========================================================================

    /// Decide what to do with an incoming frame
    pub fn decide_forward(&mut self, frame: &Frame) -> ForwardDecision {
        // Find next hops from routing table
        let next_hops = self.routing_table
            .get_nodes_for_intent(&frame.header.intent_hash);

        let decision = self.forwarding.decide(frame, &next_hops);

        // Update stats
        match &decision {
            ForwardDecision::DeliverLocal => {
                self.stats.frames_delivered += 1;
            }
            ForwardDecision::Forward(_) => {
                self.stats.frames_forwarded += 1;
            }
            ForwardDecision::DeliverAndForward(_) => {
                self.stats.frames_delivered += 1;
                self.stats.frames_forwarded += 1;
            }
            ForwardDecision::Drop(_) => {
                self.stats.frames_dropped += 1;
            }
        }

        decision
    }

    /// Prepare a frame for forwarding
    pub fn prepare_forward(&mut self, frame: &mut Frame) {
        self.forwarding.prepare_forward(frame);
    }

    // =========================================================================
    // Announcements
    // =========================================================================

    /// Check if it's time to send announcements
    pub fn should_announce(&self) -> bool {
        self.scheduler.should_announce()
    }

    /// Create an announcement frame for our capabilities
    pub fn create_announcement(&mut self) -> Frame {
        self.scheduler.record_announce();
        self.stats.announcements_sent += 1;
        self.announcements.create_announcement(self.config.announce_ttl)
    }

    /// Process an incoming announcement
    /// Returns (new_capabilities, optional_forward_frame)
    pub fn process_announcement(&mut self, frame: &Frame, from_node: NodeId, now_unix: u32)
        -> Option<(Vec<AnnouncedCapability>, Option<Frame>)>
    {
        self.stats.announcements_received += 1;

        let result = self.announcements.process_announcement(frame)?;
        let (new_caps, forward) = result;

        // Update routing table with new capabilities
        if !new_caps.is_empty() {
            let payload = AnnouncePayload {
                ttl: 0, // doesn't matter for routing
                capabilities: new_caps.clone(),
            };
            self.routing_table.apply_announcement(from_node, &payload, now_unix);
            self.stats.routes_learned += new_caps.len() as u64;
        }

        Some((new_caps, forward))
    }

    /// Get time until next announcement (milliseconds)
    pub fn time_until_announce(&self) -> u64 {
        self.scheduler.time_until_next()
    }

    // =========================================================================
    // Peer Management
    // =========================================================================

    /// Create a join request frame
    pub fn create_join_request(&mut self) -> Frame {
        let caps: Vec<_> = self.announcements.local_capabilities()
            .iter()
            .map(|c| c.intent_hash)
            .collect();
        self.mesh.create_join_request(caps)
    }

    /// Process a join request
    pub fn process_join_request(&mut self, frame: &Frame, from_addr: SocketAddr) -> Option<Frame> {
        self.mesh.process_join_request(frame, from_addr)
    }

    /// Process a join response
    pub fn process_join_response(&mut self, frame: &Frame, from_addr: SocketAddr) -> bool {
        self.mesh.process_join_response(frame, from_addr)
    }

    /// Create a leave notification
    pub fn create_leave_notification(&mut self) -> Frame {
        use crate::LeaveReason;
        self.mesh.create_leave_notification(LeaveReason::Shutdown)
    }

    /// Process a leave notification
    pub fn process_leave(&mut self, frame: &Frame) {
        self.mesh.process_leave(frame);
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.mesh.connected_count()
    }

    /// Record successful communication with a peer
    pub fn record_peer_success(&mut self, node_id: &NodeId, rtt_us: Option<u32>) {
        self.mesh.record_peer_activity(node_id, rtt_us);
    }

    /// Record failed communication with a peer
    pub fn record_peer_failure(&mut self, node_id: &NodeId) {
        self.mesh.record_failed_ping(node_id);
    }

    /// Get peers needing health check
    pub fn get_stale_peers(&self) -> Vec<NodeId> {
        self.mesh.get_peers_for_health_check()
    }

    // =========================================================================
    // Maintenance
    // =========================================================================

    /// Run periodic maintenance tasks
    pub fn maintenance(&mut self, now_unix: u32) {
        // Cleanup stale routes
        self.routing_table.cleanup_stale(now_unix, self.config.route_max_age_seconds);

        // Cleanup old announcement history
        self.announcements.cleanup_stale(std::time::Duration::from_secs(
            self.config.route_max_age_seconds as u64 * 2
        ));

        // Cleanup forwarding history
        self.forwarding.cleanup_history(std::time::Duration::from_secs(60));

        // Cleanup dead peers
        self.mesh.cleanup_dead_peers();
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Get mesh node statistics
    pub fn stats(&self) -> &MeshNodeStats {
        &self.stats
    }

    /// Get number of known routes
    pub fn route_count(&self) -> usize {
        self.routing_table.num_routes()
    }

    /// Get number of known intents
    pub fn intent_count(&self) -> usize {
        self.routing_table.num_intents()
    }

    /// Get forwarding statistics
    pub fn forwarding_stats(&self) -> &crate::ForwardingStats {
        self.forwarding.stats()
    }

    /// Get mesh statistics
    pub fn mesh_stats(&self) -> &crate::MeshStats {
        self.mesh.stats()
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct MeshNode;

#[cfg(not(feature = "std"))]
pub struct MeshNodeStats;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::frame::{FrameHeader, FrameType};
    use axiom_types::payload::PayloadType;
    use axiom_types::clock::HybridClock;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    #[test]
    fn test_mesh_node_capability_registration() {
        let mut node = MeshNode::new(test_node_id(1), MeshNodeConfig::default());

        // Register capability
        node.register_capability(test_intent_hash(0xAB), *b"llm\0");

        assert!(node.can_handle_locally(&test_intent_hash(0xAB)));
        assert!(!node.can_handle_locally(&test_intent_hash(0xCD)));

        // Unregister
        node.unregister_capability(&test_intent_hash(0xAB));
        assert!(!node.can_handle_locally(&test_intent_hash(0xAB)));
    }

    #[test]
    fn test_mesh_node_routing() {
        let mut node = MeshNode::new(test_node_id(1), MeshNodeConfig::default());

        // Add routes manually via announcement
        let announcement = AnnouncePayload {
            ttl: 5,
            capabilities: vec![
                AnnouncedCapability::new(test_intent_hash(0xAB), *b"llm\0")
                    .with_load(50)
                    .with_latency(10),
            ],
        };
        node.routing_table.apply_announcement(test_node_id(2), &announcement, 1700000000);

        // Should find the route
        let route = node.route(&test_intent_hash(0xAB));
        assert!(route.is_some());
        assert_eq!(route.unwrap().node_id, test_node_id(2));
    }

    #[test]
    fn test_mesh_node_forwarding() {
        let mut node = MeshNode::new(test_node_id(1), MeshNodeConfig::default());

        // Register local capability
        node.register_capability(test_intent_hash(0xAB), *b"llm\0");

        // Create a frame for that capability
        let header = FrameHeader::new(FrameType::Intent, test_node_id(5))
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(test_intent_hash(0xAB));

        let frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3]);

        // Should deliver locally
        let decision = node.decide_forward(&frame);
        assert!(matches!(decision, ForwardDecision::DeliverLocal));
    }

    #[test]
    fn test_mesh_node_announcement_cycle() {
        let mut node = MeshNode::new(test_node_id(1), MeshNodeConfig::default());

        // Register capability
        node.register_capability(test_intent_hash(0xAB), *b"llm\0");

        // Should want to announce immediately
        assert!(node.should_announce());

        // Create announcement
        let frame = node.create_announcement();
        assert_eq!(frame.header.frame_type, FrameType::Announce);

        // Should not want to announce immediately after
        assert!(!node.should_announce());
    }

    #[test]
    fn test_mesh_node_stats() {
        let mut node = MeshNode::new(test_node_id(1), MeshNodeConfig::default());

        // Register capability and process a frame
        node.register_capability(test_intent_hash(0xAB), *b"llm\0");

        let header = FrameHeader::new(FrameType::Intent, test_node_id(5))
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(test_intent_hash(0xAB));

        let frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3]);
        let _ = node.decide_forward(&frame);

        assert_eq!(node.stats().frames_delivered, 1);
    }
}
