//! Packet Capture
//!
//! Provides pcap-like packet capture for forensics and analysis.

use alloc::string::String;
use alloc::vec::Vec;

/// Capture filter expression
#[derive(Debug, Clone)]
pub struct CaptureFilter {
    /// Protocol filter (axiom, ipv4, tcp, udp, etc.)
    pub protocol: Option<String>,
    /// Source node filter
    pub source: Option<[u8; 32]>,
    /// Destination node filter
    pub destination: Option<[u8; 32]>,
    /// Port filter
    pub port: Option<u16>,
    /// Minimum packet size
    pub min_size: Option<usize>,
    /// Maximum packet size
    pub max_size: Option<usize>,
}

impl CaptureFilter {
    /// Create empty filter (matches all)
    pub fn new() -> Self {
        Self {
            protocol: None,
            source: None,
            destination: None,
            port: None,
            min_size: None,
            max_size: None,
        }
    }

    /// Filter by protocol
    pub fn protocol(mut self, proto: &str) -> Self {
        self.protocol = Some(proto.to_string());
        self
    }

    /// Filter by port
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Filter by size range
    pub fn size_range(mut self, min: usize, max: usize) -> Self {
        self.min_size = Some(min);
        self.max_size = Some(max);
        self
    }

    /// Check if packet matches filter
    pub fn matches(&self, packet: &CapturedPacket) -> bool {
        // Size filter
        if let Some(min) = self.min_size {
            if packet.data.len() < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if packet.data.len() > max {
                return false;
            }
        }

        // Protocol filter (simplified - real impl would parse headers)
        if let Some(ref proto) = self.protocol {
            if packet.protocol != *proto {
                return false;
            }
        }

        // Port filter
        if let Some(port) = self.port {
            if packet.port != Some(port) {
                return false;
            }
        }

        true
    }
}

impl Default for CaptureFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// A captured packet
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Capture timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,
    /// Packet data
    pub data: Vec<u8>,
    /// Detected protocol
    pub protocol: String,
    /// Port (if applicable)
    pub port: Option<u16>,
    /// Interface name
    pub interface: String,
    /// Direction (true = incoming, false = outgoing)
    pub incoming: bool,
}

impl CapturedPacket {
    /// Create new captured packet
    pub fn new(data: Vec<u8>, timestamp_ns: u64, incoming: bool) -> Self {
        Self {
            timestamp_ns,
            data,
            protocol: "unknown".to_string(),
            port: None,
            interface: "forge0".to_string(),
            incoming,
        }
    }

    /// Set protocol
    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = protocol.to_string();
        self
    }

    /// Set port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

/// Capture session for recording packets
#[derive(Debug)]
pub struct CaptureSession {
    /// Session ID
    id: u64,
    /// Active filter
    filter: CaptureFilter,
    /// Captured packets
    packets: Vec<CapturedPacket>,
    /// Maximum packets to capture (0 = unlimited)
    max_packets: usize,
    /// Start timestamp
    start_time: u64,
    /// Is capture active?
    active: bool,
    /// Statistics
    stats: CaptureStats,
}

/// Capture statistics
#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    /// Packets captured
    pub captured: u64,
    /// Packets filtered out
    pub filtered: u64,
    /// Packets dropped (buffer full)
    pub dropped: u64,
    /// Bytes captured
    pub bytes: u64,
}

impl CaptureSession {
    /// Create new capture session
    pub fn new(id: u64, filter: CaptureFilter) -> Self {
        Self {
            id,
            filter,
            packets: Vec::new(),
            max_packets: 0,
            start_time: 0,
            active: false,
            stats: CaptureStats::default(),
        }
    }

    /// Start capture
    pub fn start(&mut self, now: u64) {
        self.start_time = now;
        self.active = true;
    }

    /// Stop capture
    pub fn stop(&mut self) {
        self.active = false;
    }

    /// Is capture active?
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set maximum packets
    pub fn set_max_packets(&mut self, max: usize) {
        self.max_packets = max;
    }

    /// Process a packet
    pub fn process(&mut self, packet: CapturedPacket) {
        if !self.active {
            return;
        }

        // Check filter
        if !self.filter.matches(&packet) {
            self.stats.filtered += 1;
            return;
        }

        // Check capacity
        if self.max_packets > 0 && self.packets.len() >= self.max_packets {
            self.stats.dropped += 1;
            return;
        }

        self.stats.bytes += packet.data.len() as u64;
        self.stats.captured += 1;
        self.packets.push(packet);
    }

    /// Get captured packets
    pub fn packets(&self) -> &[CapturedPacket] {
        &self.packets
    }

    /// Get statistics
    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

    /// Get session ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Clear captured packets
    pub fn clear(&mut self) {
        self.packets.clear();
        self.stats = CaptureStats::default();
    }
}

/// Capture manager for multiple sessions
#[derive(Debug, Default)]
pub struct CaptureManager {
    /// Active sessions
    sessions: Vec<CaptureSession>,
    /// Next session ID
    next_id: u64,
}

impl CaptureManager {
    /// Create new capture manager
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_id: 1,
        }
    }

    /// Create new capture session
    pub fn create_session(&mut self, filter: CaptureFilter) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.push(CaptureSession::new(id, filter));
        id
    }

    /// Get session by ID
    pub fn get_session(&self, id: u64) -> Option<&CaptureSession> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Get mutable session by ID
    pub fn get_session_mut(&mut self, id: u64) -> Option<&mut CaptureSession> {
        self.sessions.iter_mut().find(|s| s.id == id)
    }

    /// Remove session
    pub fn remove_session(&mut self, id: u64) -> Option<CaptureSession> {
        if let Some(pos) = self.sessions.iter().position(|s| s.id == id) {
            Some(self.sessions.remove(pos))
        } else {
            None
        }
    }

    /// Process packet for all active sessions
    pub fn process_packet(&mut self, packet: CapturedPacket) {
        for session in &mut self.sessions {
            if session.is_active() {
                session.process(packet.clone());
            }
        }
    }

    /// Number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_active()).count()
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_filter() {
        let filter = CaptureFilter::new()
            .protocol("axiom")
            .size_range(10, 1000);

        let small_packet = CapturedPacket::new(vec![0; 5], 0, true).with_protocol("axiom");
        let good_packet = CapturedPacket::new(vec![0; 100], 0, true).with_protocol("axiom");
        let wrong_proto = CapturedPacket::new(vec![0; 100], 0, true).with_protocol("ipv4");

        assert!(!filter.matches(&small_packet));
        assert!(filter.matches(&good_packet));
        assert!(!filter.matches(&wrong_proto));
    }

    #[test]
    fn test_capture_session() {
        let filter = CaptureFilter::new();
        let mut session = CaptureSession::new(1, filter);

        session.start(1000);
        assert!(session.is_active());

        // Capture some packets
        for i in 0..10 {
            let packet = CapturedPacket::new(vec![0; 64], i, true);
            session.process(packet);
        }

        assert_eq!(session.stats().captured, 10);
        assert_eq!(session.packets().len(), 10);
    }

    #[test]
    fn test_capture_manager() {
        let mut manager = CaptureManager::new();

        // Create session
        let id = manager.create_session(CaptureFilter::new());
        manager.get_session_mut(id).unwrap().start(0);

        // Process packets
        for i in 0..5 {
            let packet = CapturedPacket::new(vec![0; 32], i, true);
            manager.process_packet(packet);
        }

        let session = manager.get_session(id).unwrap();
        assert_eq!(session.stats().captured, 5);
    }

    #[test]
    fn test_max_packets() {
        let filter = CaptureFilter::new();
        let mut session = CaptureSession::new(1, filter);
        session.set_max_packets(5);
        session.start(0);

        // Try to capture 10 packets
        for i in 0..10 {
            let packet = CapturedPacket::new(vec![0; 32], i, true);
            session.process(packet);
        }

        assert_eq!(session.stats().captured, 5);
        assert_eq!(session.stats().dropped, 5);
    }
}
