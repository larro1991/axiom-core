//! Mesh bootstrap and peer discovery
//!
//! Handles initial joining of the mesh network:
//! - Bootstrap node configuration
//! - Initial peer discovery
//! - Join/leave protocol
//! - Periodic peer health checks

use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use hashbrown::HashMap;

/// True if `addr` is link-local unicast IPv6 (fe80::/10). Its scope_id is
/// only meaningful to the host that observed it — see the caveat on
/// [`JoinResponse::encode`].
#[cfg(feature = "std")]
fn is_link_local(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V6(v6) => v6.ip().is_unicast_link_local(),
        SocketAddr::V4(_) => false,
    }
}

/// Bootstrap node information
#[derive(Debug, Clone)]
pub struct BootstrapNode {
    /// Node's public ID
    pub node_id: NodeId,
    /// Network address
    #[cfg(feature = "std")]
    pub addr: SocketAddr,
    /// Priority (higher = try first)
    pub priority: u8,
    /// Whether this node is currently reachable
    pub reachable: bool,
}

/// Peer state in the mesh
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Just discovered, not yet verified
    Discovered,
    /// Handshake in progress
    Connecting,
    /// Fully connected and verified
    Connected,
    /// Connection lost, attempting reconnect
    Reconnecting,
    /// Peer left gracefully
    Left,
    /// Peer unreachable
    Dead,
}

/// Information about a connected peer
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Network address
    pub addr: SocketAddr,
    /// Current connection state
    pub state: PeerState,
    /// Trust level with this peer
    pub trust_level: TrustLevel,
    /// Last successful communication
    pub last_seen: std::time::Instant,
    /// Round-trip time estimate (microseconds)
    pub rtt_us: u32,
    /// Number of failed pings
    pub failed_pings: u32,
    /// Capabilities this peer provides
    pub capabilities: Vec<IntentHash>,
}

/// Configuration for mesh bootstrap
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Bootstrap nodes to try
    #[cfg(feature = "std")]
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// Maximum number of peers to maintain
    pub max_peers: usize,
    /// Peer health check interval (milliseconds)
    pub health_check_interval_ms: u64,
    /// Consider peer dead after this many failed checks
    pub max_failed_checks: u32,
    /// Time to wait for handshake response (milliseconds)
    pub handshake_timeout_ms: u64,
    /// Announce interval (milliseconds)
    pub announce_interval_ms: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "std")]
            bootstrap_nodes: Vec::new(),
            max_peers: 64,
            health_check_interval_ms: 5000,
            max_failed_checks: 3,
            handshake_timeout_ms: 3000,
            announce_interval_ms: 30000,
        }
    }
}

/// Join request payload
#[derive(Debug, Clone)]
pub struct JoinRequest {
    /// Requesting node's ID
    pub node_id: NodeId,
    /// Version info for compatibility
    pub protocol_version: u16,
    /// Capabilities we provide
    pub capabilities: Vec<IntentHash>,
}

impl JoinRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34 + self.capabilities.len() * 16);
        buf.extend_from_slice(self.node_id.as_bytes());
        buf.extend_from_slice(&self.protocol_version.to_be_bytes());
        for cap in &self.capabilities {
            buf.extend_from_slice(cap.as_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 34 {
            return None;
        }
        let node_id = NodeId::from_bytes(data[0..32].try_into().ok()?);
        let protocol_version = u16::from_be_bytes([data[32], data[33]]);

        let cap_data = &data[34..];
        if cap_data.len() % 16 != 0 {
            return None;
        }

        let capabilities = cap_data
            .chunks_exact(16)
            .map(|chunk| IntentHash::from_bytes(chunk.try_into().unwrap()))
            .collect();

        Some(Self {
            node_id,
            protocol_version,
            capabilities,
        })
    }
}

/// Join response payload
#[derive(Debug, Clone)]
pub struct JoinResponse {
    /// Whether join was accepted
    pub accepted: bool,
    /// Responding node's ID
    pub node_id: NodeId,
    /// Known peers to help bootstrap
    #[cfg(feature = "std")]
    pub known_peers: Vec<(NodeId, SocketAddr)>,
    #[cfg(not(feature = "std"))]
    pub known_peers: Vec<NodeId>,
}

impl JoinResponse {
    #[cfg(feature = "std")]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33 + self.known_peers.len() * 38);
        buf.push(if self.accepted { 1 } else { 0 });
        buf.extend_from_slice(self.node_id.as_bytes());

        for (node_id, addr) in &self.known_peers {
            // A link-local address's scope_id (interface index) is only
            // meaningful on the host that observed it. Relaying one to a
            // third node would have it resolved against a different (or
            // nonexistent) interface there, so these never go out on the wire.
            if is_link_local(addr) {
                continue;
            }
            buf.extend_from_slice(node_id.as_bytes());
            match addr {
                SocketAddr::V4(v4) => {
                    buf.push(4);
                    buf.extend_from_slice(&v4.ip().octets());
                    buf.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    buf.push(6);
                    buf.extend_from_slice(&v6.ip().octets());
                    buf.extend_from_slice(&v6.port().to_be_bytes());
                }
            }
        }
        buf
    }

    #[cfg(feature = "std")]
    pub fn decode(data: &[u8]) -> Option<Self> {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

        if data.len() < 33 {
            return None;
        }

        let accepted = data[0] == 1;
        let node_id = NodeId::from_bytes(data[1..33].try_into().ok()?);

        let mut known_peers = Vec::new();
        let mut pos = 33;

        while pos < data.len() {
            if pos + 33 > data.len() {
                break;
            }
            let peer_id = NodeId::from_bytes(data[pos..pos + 32].try_into().ok()?);
            pos += 32;

            let ip_version = data[pos];
            pos += 1;

            let addr = match ip_version {
                4 if pos + 6 <= data.len() => {
                    let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                    let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
                    pos += 6;
                    SocketAddr::V4(SocketAddrV4::new(ip, port))
                }
                6 if pos + 18 <= data.len() => {
                    let octets: [u8; 16] = data[pos..pos + 16].try_into().ok()?;
                    let ip = Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);
                    pos += 18;
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
                }
                _ => break,
            };

            known_peers.push((peer_id, addr));
        }

        Some(Self {
            accepted,
            node_id,
            known_peers,
        })
    }
}

/// Leave notification payload
#[derive(Debug, Clone)]
pub struct LeaveNotification {
    /// Node that's leaving
    pub node_id: NodeId,
    /// Reason code
    pub reason: LeaveReason,
}

/// Reason for leaving the mesh
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveReason {
    /// Normal shutdown
    Shutdown = 0,
    /// Restarting
    Restart = 1,
    /// Maintenance mode
    Maintenance = 2,
    /// Unknown/other
    Unknown = 255,
}

impl LeaveNotification {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(self.node_id.as_bytes());
        buf.push(self.reason as u8);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        let node_id = NodeId::from_bytes(data[0..32].try_into().ok()?);
        let reason = match data[32] {
            0 => LeaveReason::Shutdown,
            1 => LeaveReason::Restart,
            2 => LeaveReason::Maintenance,
            _ => LeaveReason::Unknown,
        };
        Some(Self { node_id, reason })
    }
}

/// Manages mesh bootstrap and peer connections
#[cfg(feature = "std")]
pub struct MeshManager {
    /// Our node ID
    local_id: NodeId,
    /// Configuration
    config: BootstrapConfig,
    /// Known peers
    peers: HashMap<NodeId, PeerInfo>,
    /// Address to node ID mapping
    addr_to_node: HashMap<SocketAddr, NodeId>,
    /// Our local clock
    clock: axiom_clock::ClockManager,
    /// Bootstrap state
    bootstrap_state: BootstrapState,
    /// Statistics
    stats: MeshStats,
}

/// Bootstrap state machine
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapState {
    /// Not yet started
    Init,
    /// Connecting to bootstrap nodes
    Bootstrapping,
    /// Successfully joined mesh
    Joined,
    /// Failed to join
    Failed,
}

/// Mesh statistics
#[derive(Debug, Default, Clone)]
pub struct MeshStats {
    /// Total peers discovered
    pub peers_discovered: u64,
    /// Currently connected peers
    pub peers_connected: u64,
    /// Join requests sent
    pub joins_sent: u64,
    /// Join requests received
    pub joins_received: u64,
    /// Leave notifications sent
    pub leaves_sent: u64,
}

#[cfg(feature = "std")]
impl MeshManager {
    /// Create a new mesh manager
    pub fn new(local_id: NodeId, config: BootstrapConfig) -> Self {
        Self {
            local_id,
            config,
            peers: HashMap::new(),
            addr_to_node: HashMap::new(),
            clock: axiom_clock::ClockManager::new(),
            bootstrap_state: BootstrapState::Init,
            stats: MeshStats::default(),
        }
    }

    /// Get bootstrap state
    pub fn state(&self) -> BootstrapState {
        self.bootstrap_state
    }

    /// Create a JOIN request frame
    pub fn create_join_request(&mut self, capabilities: Vec<IntentHash>) -> Frame {
        let request = JoinRequest {
            node_id: self.local_id.clone(),
            protocol_version: 1,
            capabilities,
        };

        let header = FrameHeader::new(FrameType::Join, self.local_id.clone())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(self.clock.tick());

        Frame::new(header, PayloadType::Raw, request.encode())
    }

    /// Create a JOIN response frame
    pub fn create_join_response(&mut self, accepted: bool, max_peers: usize) -> Frame {
        let known_peers: Vec<_> = self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected)
            .take(max_peers)
            .map(|(_, p)| (p.node_id.clone(), p.addr))
            .collect();

        let response = JoinResponse {
            accepted,
            node_id: self.local_id.clone(),
            known_peers,
        };

        let header = FrameHeader::new(FrameType::Join, self.local_id.clone())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(self.clock.tick());

        Frame::new(header, PayloadType::Raw, response.encode())
    }

    /// Create a LEAVE notification frame
    pub fn create_leave_notification(&mut self, reason: LeaveReason) -> Frame {
        let notification = LeaveNotification {
            node_id: self.local_id.clone(),
            reason,
        };

        let header = FrameHeader::new(FrameType::Leave, self.local_id.clone())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(self.clock.tick());

        self.stats.leaves_sent += 1;
        Frame::new(header, PayloadType::Raw, notification.encode())
    }

    /// Process an incoming JOIN request
    pub fn process_join_request(&mut self, frame: &Frame, from_addr: SocketAddr) -> Option<Frame> {
        let request = JoinRequest::decode(&frame.payload)?;

        self.stats.joins_received += 1;

        // Check if we should accept
        let accept = self.peers.len() < self.config.max_peers;

        if accept {
            // Add peer
            let peer_info = PeerInfo {
                node_id: request.node_id.clone(),
                addr: from_addr,
                state: PeerState::Connected,
                trust_level: frame.header.trust_level,
                last_seen: std::time::Instant::now(),
                rtt_us: 0,
                failed_pings: 0,
                capabilities: request.capabilities,
            };

            self.addr_to_node.insert(from_addr, request.node_id.clone());
            self.peers.insert(request.node_id, peer_info);
            self.stats.peers_discovered += 1;
            self.stats.peers_connected += 1;
        }

        Some(self.create_join_response(accept, 10))
    }

    /// Process an incoming JOIN response
    pub fn process_join_response(&mut self, frame: &Frame, from_addr: SocketAddr) -> bool {
        let response = match JoinResponse::decode(&frame.payload) {
            Some(r) => r,
            None => return false,
        };

        if response.accepted {
            // Add the responding node as a peer
            let peer_info = PeerInfo {
                node_id: response.node_id.clone(),
                addr: from_addr,
                state: PeerState::Connected,
                trust_level: frame.header.trust_level,
                last_seen: std::time::Instant::now(),
                rtt_us: 0,
                failed_pings: 0,
                capabilities: Vec::new(),
            };

            self.addr_to_node.insert(from_addr, response.node_id.clone());
            self.peers.insert(response.node_id, peer_info);
            self.stats.peers_connected += 1;

            // Queue known peers for connection
            for (node_id, addr) in response.known_peers {
                if !self.peers.contains_key(&node_id) && node_id != self.local_id {
                    let peer_info = PeerInfo {
                        node_id: node_id.clone(),
                        addr,
                        state: PeerState::Discovered,
                        trust_level: TrustLevel::Raw,
                        last_seen: std::time::Instant::now(),
                        rtt_us: 0,
                        failed_pings: 0,
                        capabilities: Vec::new(),
                    };
                    self.addr_to_node.insert(addr, node_id.clone());
                    self.peers.insert(node_id, peer_info);
                    self.stats.peers_discovered += 1;
                }
            }

            self.bootstrap_state = BootstrapState::Joined;
            true
        } else {
            false
        }
    }

    /// Process a LEAVE notification
    pub fn process_leave(&mut self, frame: &Frame) {
        if let Some(notification) = LeaveNotification::decode(&frame.payload) {
            if let Some(peer) = self.peers.get_mut(&notification.node_id) {
                peer.state = PeerState::Left;
                self.stats.peers_connected = self.stats.peers_connected.saturating_sub(1);
            }
        }
    }

    /// Get peers that need to be connected
    pub fn get_peers_to_connect(&self) -> Vec<(NodeId, SocketAddr)> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Discovered)
            .map(|(id, p)| (id.clone(), p.addr))
            .collect()
    }

    /// Get connected peers
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values().filter(|p| p.state == PeerState::Connected)
    }

    /// Get peer by node ID
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(node_id)
    }

    /// Get peer by address
    pub fn get_peer_by_addr(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.addr_to_node.get(addr).and_then(|id| self.peers.get(id))
    }

    /// Update peer state
    pub fn update_peer_state(&mut self, node_id: &NodeId, state: PeerState) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            let was_connected = peer.state == PeerState::Connected;
            peer.state = state;

            if was_connected && state != PeerState::Connected {
                self.stats.peers_connected = self.stats.peers_connected.saturating_sub(1);
            } else if !was_connected && state == PeerState::Connected {
                self.stats.peers_connected += 1;
            }
        }
    }

    /// Record successful communication with peer
    pub fn record_peer_activity(&mut self, node_id: &NodeId, rtt_us: Option<u32>) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.last_seen = std::time::Instant::now();
            peer.failed_pings = 0;
            if let Some(rtt) = rtt_us {
                // Exponential moving average
                peer.rtt_us = (peer.rtt_us * 7 + rtt) / 8;
            }
        }
    }

    /// Record failed ping
    pub fn record_failed_ping(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.failed_pings += 1;
            if peer.failed_pings >= self.config.max_failed_checks {
                peer.state = PeerState::Dead;
                self.stats.peers_connected = self.stats.peers_connected.saturating_sub(1);
            }
        }
    }

    /// Get peers that need health check
    pub fn get_peers_for_health_check(&self) -> Vec<NodeId> {
        let now = std::time::Instant::now();
        let check_interval = std::time::Duration::from_millis(self.config.health_check_interval_ms);

        self.peers
            .iter()
            .filter(|(_, p)| {
                p.state == PeerState::Connected &&
                now.duration_since(p.last_seen) > check_interval
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Remove dead peers
    pub fn cleanup_dead_peers(&mut self) {
        let dead: Vec<_> = self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Dead || p.state == PeerState::Left)
            .map(|(id, p)| (id.clone(), p.addr))
            .collect();

        for (node_id, addr) in dead {
            self.peers.remove(&node_id);
            self.addr_to_node.remove(&addr);
        }
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|p| p.state == PeerState::Connected).count()
    }

    /// Get statistics
    pub fn stats(&self) -> &MeshStats {
        &self.stats
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct MeshManager;

#[cfg(not(feature = "std"))]
pub struct MeshStats;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    #[test]
    fn test_join_request_encode_decode() {
        let request = JoinRequest {
            node_id: test_node_id(1),
            protocol_version: 1,
            capabilities: vec![test_intent_hash(0xAB), test_intent_hash(0xCD)],
        };

        let encoded = request.encode();
        let decoded = JoinRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.node_id, test_node_id(1));
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.capabilities.len(), 2);
    }

    #[test]
    fn test_join_response_encode_decode() {
        let response = JoinResponse {
            accepted: true,
            node_id: test_node_id(2),
            known_peers: vec![
                (test_node_id(3), "127.0.0.1:8080".parse().unwrap()),
                (test_node_id(4), "192.168.1.1:9000".parse().unwrap()),
            ],
        };

        let encoded = response.encode();
        let decoded = JoinResponse::decode(&encoded).unwrap();

        assert!(decoded.accepted);
        assert_eq!(decoded.node_id, test_node_id(2));
        assert_eq!(decoded.known_peers.len(), 2);
    }

    #[test]
    fn test_leave_notification_encode_decode() {
        let notification = LeaveNotification {
            node_id: test_node_id(5),
            reason: LeaveReason::Shutdown,
        };

        let encoded = notification.encode();
        let decoded = LeaveNotification::decode(&encoded).unwrap();

        assert_eq!(decoded.node_id, test_node_id(5));
        assert_eq!(decoded.reason, LeaveReason::Shutdown);
    }

    #[test]
    fn test_mesh_manager_join_flow() {
        let config = BootstrapConfig::default();
        let mut manager1 = MeshManager::new(test_node_id(1), config.clone());
        let mut manager2 = MeshManager::new(test_node_id(2), config);

        // Node 1 creates join request
        let join_frame = manager1.create_join_request(vec![test_intent_hash(0xAB)]);

        // Node 2 processes join request
        let addr1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let response_frame = manager2.process_join_request(&join_frame, addr1).unwrap();

        // Node 1 processes response
        let addr2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        assert!(manager1.process_join_response(&response_frame, addr2));

        // Both should now have each other as peers
        assert_eq!(manager1.connected_count(), 1);
        assert_eq!(manager2.connected_count(), 1);
        assert_eq!(manager1.state(), BootstrapState::Joined);
    }

    #[test]
    fn test_peer_health_tracking() {
        let config = BootstrapConfig {
            max_failed_checks: 3,
            ..Default::default()
        };
        let mut manager = MeshManager::new(test_node_id(1), config);

        // Add a peer
        let peer_id = test_node_id(2);
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        let peer_info = PeerInfo {
            node_id: peer_id.clone(),
            addr,
            state: PeerState::Connected,
            trust_level: TrustLevel::Sig,
            last_seen: std::time::Instant::now(),
            rtt_us: 1000,
            failed_pings: 0,
            capabilities: Vec::new(),
        };
        manager.peers.insert(peer_id.clone(), peer_info);
        manager.addr_to_node.insert(addr, peer_id.clone());
        manager.stats.peers_connected = 1;

        // Record activity
        manager.record_peer_activity(&peer_id, Some(500));
        assert_eq!(manager.get_peer(&peer_id).unwrap().rtt_us, 937); // (1000*7 + 500) / 8

        // Fail pings until dead
        for _ in 0..3 {
            manager.record_failed_ping(&peer_id);
        }
        assert_eq!(manager.get_peer(&peer_id).unwrap().state, PeerState::Dead);
    }

    #[test]
    fn test_leave_protocol() {
        let config = BootstrapConfig::default();
        let mut manager = MeshManager::new(test_node_id(1), config);

        // Create leave notification
        let leave_frame = manager.create_leave_notification(LeaveReason::Shutdown);

        // Another manager processes it
        let mut manager2 = MeshManager::new(test_node_id(2), BootstrapConfig::default());

        // Add node 1 as a peer first
        let peer_id = test_node_id(1);
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let peer_info = PeerInfo {
            node_id: peer_id.clone(),
            addr,
            state: PeerState::Connected,
            trust_level: TrustLevel::Sig,
            last_seen: std::time::Instant::now(),
            rtt_us: 0,
            failed_pings: 0,
            capabilities: Vec::new(),
        };
        manager2.peers.insert(peer_id.clone(), peer_info);
        manager2.stats.peers_connected = 1;

        // Process leave
        manager2.process_leave(&leave_frame);
        assert_eq!(manager2.get_peer(&peer_id).unwrap().state, PeerState::Left);
    }
}
