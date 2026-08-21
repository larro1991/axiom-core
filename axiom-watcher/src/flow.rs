//! Flow tracking for stateful connection analysis
//!
//! Tracks TCP/UDP flows and detects anomalies like:
//! - Unusual flow durations
//! - Excessive data transfer
//! - Connection patterns (port scans, etc.)

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::anomaly::{TrafficAnomaly, AnomalyType};

/// Unique identifier for a network flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IP
    pub src_ip: [u8; 4],
    /// Destination IP
    pub dst_ip: [u8; 4],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
}

impl FlowKey {
    /// Create a new flow key
    pub fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Get the reverse flow key (for bidirectional matching)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Create a canonical key (smaller IP first for bidirectional flows)
    pub fn canonical(&self) -> Self {
        if self.src_ip < self.dst_ip ||
           (self.src_ip == self.dst_ip && self.src_port < self.dst_port) {
            *self
        } else {
            self.reverse()
        }
    }
}

/// Flow state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Just started
    New,
    /// Established and active
    Active,
    /// No recent packets
    Idle,
    /// Finished (FIN/RST seen for TCP)
    Finished,
}

/// A tracked network flow
#[derive(Debug, Clone)]
pub struct Flow {
    /// Flow key
    pub key: FlowKey,
    /// Current state
    pub state: FlowState,
    /// When first seen
    pub first_seen: u64,
    /// When last seen
    pub last_seen: u64,
    /// Packets in forward direction
    pub packets_fwd: u64,
    /// Packets in reverse direction
    pub packets_rev: u64,
    /// Bytes in forward direction
    pub bytes_fwd: u64,
    /// Bytes in reverse direction
    pub bytes_rev: u64,
    /// Inter-arrival times (for timing analysis)
    pub inter_arrival_times: Vec<u64>,
    /// Packet sizes (for fingerprinting)
    pub packet_sizes: Vec<usize>,
}

impl Flow {
    /// Create a new flow
    pub fn new(key: FlowKey, packet_size: usize, timestamp: u64) -> Self {
        Self {
            key,
            state: FlowState::New,
            first_seen: timestamp,
            last_seen: timestamp,
            packets_fwd: 1,
            packets_rev: 0,
            bytes_fwd: packet_size as u64,
            bytes_rev: 0,
            inter_arrival_times: Vec::new(),
            packet_sizes: vec![packet_size],
        }
    }

    /// Update flow with new packet
    pub fn update(&mut self, packet_size: usize, is_forward: bool, timestamp: u64) {
        // Track inter-arrival time
        if self.last_seen > 0 {
            let iat = timestamp.saturating_sub(self.last_seen);
            if self.inter_arrival_times.len() < 100 {
                self.inter_arrival_times.push(iat);
            }
        }

        self.last_seen = timestamp;

        if is_forward {
            self.packets_fwd += 1;
            self.bytes_fwd += packet_size as u64;
        } else {
            self.packets_rev += 1;
            self.bytes_rev += packet_size as u64;
        }

        if self.packet_sizes.len() < 100 {
            self.packet_sizes.push(packet_size);
        }

        // Update state
        if self.state == FlowState::New && (self.packets_fwd + self.packets_rev) > 3 {
            self.state = FlowState::Active;
        }
    }

    /// Duration in milliseconds
    pub fn duration(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }

    /// Total packets
    pub fn total_packets(&self) -> u64 {
        self.packets_fwd + self.packets_rev
    }

    /// Total bytes
    pub fn total_bytes(&self) -> u64 {
        self.bytes_fwd + self.bytes_rev
    }

    /// Average packet size
    pub fn avg_packet_size(&self) -> usize {
        if self.packet_sizes.is_empty() {
            0
        } else {
            self.packet_sizes.iter().sum::<usize>() / self.packet_sizes.len()
        }
    }

    /// Bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        let duration_secs = (self.duration() as f64) / 1000.0;
        if duration_secs > 0.0 {
            self.total_bytes() as f64 / duration_secs
        } else {
            0.0
        }
    }

    /// Check if flow is idle
    pub fn is_idle(&self, current_time: u64, threshold: u64) -> bool {
        current_time.saturating_sub(self.last_seen) > threshold
    }

    /// Get flow asymmetry (ratio of forward to reverse traffic)
    pub fn asymmetry(&self) -> f64 {
        let total = self.bytes_fwd + self.bytes_rev;
        if total == 0 {
            0.5
        } else {
            self.bytes_fwd as f64 / total as f64
        }
    }
}

/// Connection stats for an IP
#[derive(Debug, Clone, Default)]
struct IpConnectionStats {
    /// Unique destination IPs
    unique_dsts: hashbrown::HashSet<[u8; 4]>,
    /// Unique destination ports
    unique_ports: hashbrown::HashSet<u16>,
    /// Connection count
    connection_count: u64,
    /// Window start time
    window_start: u64,
}

/// Flow tracker
#[cfg(feature = "std")]
pub struct FlowTracker {
    /// Active flows
    flows: HashMap<FlowKey, Flow>,
    /// Connection stats per source IP (for scan detection)
    connection_stats: HashMap<[u8; 4], IpConnectionStats>,
    /// Total flows seen
    total_flows: u64,
    /// Timeout in seconds
    timeout_secs: u64,
    /// Max flows to track
    max_flows: usize,
    /// Scan detection thresholds
    scan_threshold_ports: usize,
    scan_threshold_hosts: usize,
    /// Time window for scan detection (seconds)
    scan_window: u64,
}

#[cfg(feature = "std")]
impl FlowTracker {
    /// Create new tracker
    pub fn new(timeout_secs: u64, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            connection_stats: HashMap::new(),
            total_flows: 0,
            timeout_secs,
            max_flows,
            scan_threshold_ports: 10,  // 10 unique ports = possible scan
            scan_threshold_hosts: 5,   // 5 unique hosts = possible scan
            scan_window: 60,           // Within 60 seconds
        }
    }

    /// Observe a packet and return any anomalies
    pub fn observe(
        &mut self,
        key: &FlowKey,
        packet_size: usize,
        timestamp: u64,
    ) -> Vec<TrafficAnomaly> {
        let mut anomalies = Vec::new();

        // Use canonical key for bidirectional matching
        let canonical = key.canonical();
        let is_forward = *key == canonical;

        if let Some(flow) = self.flows.get_mut(&canonical) {
            flow.update(packet_size, is_forward, timestamp);

            // Check for anomalies in existing flow
            // Clone data needed for anomaly check to avoid borrow issue
            let flow_snapshot = (
                flow.duration(),
                flow.state,
                flow.bytes_per_second(),
                flow.total_bytes(),
                flow.asymmetry(),
                flow.bytes_fwd,
                flow.bytes_rev,
                flow.key,
            );
            if let Some(anomaly) = Self::check_flow_anomalies_static(flow_snapshot, timestamp) {
                anomalies.push(anomaly);
            }
        } else {
            // New flow
            if self.flows.len() >= self.max_flows {
                // Remove oldest idle flow
                self.evict_oldest();
            }

            let flow = Flow::new(canonical, packet_size, timestamp);
            self.flows.insert(canonical, flow);
            self.total_flows += 1;

            // Update connection stats for scan detection
            if let Some(scan_anomaly) = self.update_connection_stats(key, timestamp) {
                anomalies.push(scan_anomaly);
            }
        }

        anomalies
    }

    /// Check for anomalies in a flow (static version to avoid borrow issues)
    /// Takes a snapshot tuple: (duration, state, bytes_per_second, total_bytes, asymmetry, bytes_fwd, bytes_rev, key)
    fn check_flow_anomalies_static(
        snapshot: (u64, FlowState, f64, u64, f64, u64, u64, FlowKey),
        _timestamp: u64,
    ) -> Option<TrafficAnomaly> {
        let (duration, state, bps, total_bytes, asymmetry, bytes_fwd, bytes_rev, key) = snapshot;

        // Check for very long flows (potential persistent connection)
        if duration > 3600_000 && state == FlowState::Active { // 1 hour
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::LargeTransfer,
                severity: 20,
                description: alloc::format!(
                    "Long-lived flow detected: {} hours",
                    duration / 3600_000
                ),
                source_ip: Some(key.src_ip),
                dest_ip: Some(key.dst_ip),
                flow_key: Some(key),
                evidence: vec![
                    alloc::format!("Duration: {}ms", duration),
                    alloc::format!("Bytes: {}", total_bytes),
                ],
            });
        }

        // Check for high data transfer rate
        if bps > 10_000_000.0 { // 10 MB/s
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::LargeTransfer,
                severity: 40,
                description: "High bandwidth flow detected".into(),
                source_ip: Some(key.src_ip),
                dest_ip: Some(key.dst_ip),
                flow_key: Some(key),
                evidence: vec![
                    alloc::format!("Rate: {:.2} MB/s", bps / 1_000_000.0),
                ],
            });
        }

        // Check for highly asymmetric flows (potential exfiltration)
        if total_bytes > 1_000_000 && asymmetry > 0.95 {
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::AsymmetricFlow,
                severity: 50,
                description: "Highly asymmetric flow (potential exfiltration)".into(),
                source_ip: Some(key.src_ip),
                dest_ip: Some(key.dst_ip),
                flow_key: Some(key),
                evidence: vec![
                    alloc::format!("Asymmetry: {:.2}%", asymmetry * 100.0),
                    alloc::format!("Forward: {} bytes", bytes_fwd),
                    alloc::format!("Reverse: {} bytes", bytes_rev),
                ],
            });
        }

        None
    }

    /// Update connection stats and check for scans
    fn update_connection_stats(
        &mut self,
        key: &FlowKey,
        timestamp: u64,
    ) -> Option<TrafficAnomaly> {
        let stats = self.connection_stats
            .entry(key.src_ip)
            .or_default();

        // Reset if outside window
        if timestamp.saturating_sub(stats.window_start) > self.scan_window * 1000 {
            stats.unique_dsts.clear();
            stats.unique_ports.clear();
            stats.connection_count = 0;
            stats.window_start = timestamp;
        }

        stats.unique_dsts.insert(key.dst_ip);
        stats.unique_ports.insert(key.dst_port);
        stats.connection_count += 1;

        // Check for port scan
        if stats.unique_ports.len() >= self.scan_threshold_ports {
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::PortScan,
                severity: 70,
                description: "Port scan detected".into(),
                source_ip: Some(key.src_ip),
                dest_ip: None,
                flow_key: None,
                evidence: vec![
                    alloc::format!("Unique ports: {}", stats.unique_ports.len()),
                    alloc::format!("In {} seconds", self.scan_window),
                ],
            });
        }

        // Check for horizontal scan
        if stats.unique_dsts.len() >= self.scan_threshold_hosts {
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::HorizontalScan,
                severity: 70,
                description: "Horizontal scan detected".into(),
                source_ip: Some(key.src_ip),
                dest_ip: None,
                flow_key: None,
                evidence: vec![
                    alloc::format!("Unique hosts: {}", stats.unique_dsts.len()),
                    alloc::format!("In {} seconds", self.scan_window),
                ],
            });
        }

        None
    }

    /// Evict oldest idle flow
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.flows
            .iter()
            .min_by_key(|(_, f)| f.last_seen)
            .map(|(k, _)| *k)
        {
            self.flows.remove(&oldest_key);
        }
    }

    /// Get a flow
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(&key.canonical())
    }

    /// Get active flow count
    pub fn active_count(&self) -> usize {
        self.flows.len()
    }

    /// Get total flow count
    pub fn total_count(&self) -> u64 {
        self.total_flows
    }

    /// Cleanup idle flows
    pub fn cleanup(&mut self, timestamp: u64) {
        let timeout_ms = self.timeout_secs * 1000;
        self.flows.retain(|_, flow| !flow.is_idle(timestamp, timeout_ms));

        // Also cleanup old connection stats
        let scan_window_ms = self.scan_window * 1000;
        self.connection_stats.retain(|_, stats| {
            timestamp.saturating_sub(stats.window_start) < scan_window_ms * 2
        });
    }

    /// Get all flows
    pub fn all_flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Get flows for an IP
    pub fn flows_for_ip(&self, ip: [u8; 4]) -> Vec<&Flow> {
        self.flows.values()
            .filter(|f| f.key.src_ip == ip || f.key.dst_ip == ip)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_canonical() {
        let key1 = FlowKey::new([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80, 6);
        let key2 = FlowKey::new([10, 0, 0, 1], [192, 168, 1, 1], 80, 12345, 6);

        // Canonical should be the same regardless of direction
        assert_eq!(key1.canonical(), key2.canonical());
    }

    #[test]
    fn test_flow_tracking() {
        let mut tracker = FlowTracker::new(300, 1000);

        let key = FlowKey::new([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80, 6);

        // First packet
        let anomalies = tracker.observe(&key, 100, 1000);
        assert!(anomalies.is_empty());
        assert_eq!(tracker.active_count(), 1);

        // More packets
        tracker.observe(&key, 200, 2000);
        tracker.observe(&key, 150, 3000);

        let flow = tracker.get(&key).unwrap();
        assert_eq!(flow.total_packets(), 3);
    }

    #[test]
    fn test_port_scan_detection() {
        let mut tracker = FlowTracker::new(300, 1000);
        tracker.scan_threshold_ports = 5;

        let src_ip = [192, 168, 1, 100];
        let dst_ip = [10, 0, 0, 1];

        // Connect to different ports
        for port in 1..=5 {
            let key = FlowKey::new(src_ip, dst_ip, 12345, port, 6);
            let anomalies = tracker.observe(&key, 100, 1000);

            if port == 5 {
                // Should detect scan at threshold
                assert!(!anomalies.is_empty());
                assert!(anomalies[0].description.contains("scan"));
            }
        }
    }

    #[test]
    fn test_flow_cleanup() {
        let mut tracker = FlowTracker::new(60, 1000); // 60 second timeout

        let key = FlowKey::new([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80, 6);
        tracker.observe(&key, 100, 1000);

        assert_eq!(tracker.active_count(), 1);

        // Not stale yet
        tracker.cleanup(30_000);
        assert_eq!(tracker.active_count(), 1);

        // Now stale (after 60 seconds = 60000ms)
        tracker.cleanup(100_000);
        assert_eq!(tracker.active_count(), 0);
    }
}
