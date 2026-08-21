//! Packet Monitor
//!
//! Provides passive packet capture and threat detection.

use alloc::string::String;
use alloc::vec::Vec;

/// Packet record for capture buffer
#[derive(Debug, Clone)]
pub struct PacketRecord {
    /// Timestamp (epoch seconds)
    pub timestamp: u64,
    /// Packet length
    pub length: usize,
    /// First N bytes of packet (for analysis)
    pub header_bytes: [u8; 64],
    /// Was this packet flagged as suspicious?
    pub suspicious: bool,
}

/// Ring buffer for packet capture
#[derive(Debug)]
pub struct PacketRingBuffer {
    /// Buffer storage
    buffer: Vec<PacketRecord>,
    /// Current write position
    write_pos: usize,
    /// Number of packets stored
    count: usize,
    /// Buffer capacity
    capacity: usize,
}

impl PacketRingBuffer {
    /// Create new ring buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            write_pos: 0,
            count: 0,
            capacity,
        }
    }

    /// Store a packet record
    pub fn push(&mut self, record: PacketRecord) {
        if self.buffer.len() < self.capacity {
            self.buffer.push(record);
        } else {
            self.buffer[self.write_pos] = record;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.count = (self.count + 1).min(self.capacity);
    }

    /// Get recent packets (most recent first)
    pub fn recent(&self, count: usize) -> Vec<&PacketRecord> {
        let count = count.min(self.count);
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let idx = (self.write_pos + self.capacity - 1 - i) % self.capacity;
            if idx < self.buffer.len() {
                result.push(&self.buffer[idx]);
            }
        }

        result
    }

    /// Total packets captured
    pub fn total_captured(&self) -> usize {
        self.count
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.write_pos = 0;
        self.count = 0;
    }
}

/// Packet monitor for traffic analysis
#[derive(Debug)]
pub struct PacketMonitor {
    /// Capture buffer
    buffer: PacketRingBuffer,
    /// Is capture enabled?
    capture_enabled: bool,
    /// Threat signatures (simplified)
    threat_signatures: Vec<ThreatSignature>,
    /// Statistics
    stats: MonitorStats,
}

/// Simple threat signature
#[derive(Debug, Clone)]
pub struct ThreatSignature {
    /// Signature name
    pub name: String,
    /// Byte pattern to match
    pub pattern: Vec<u8>,
    /// Offset to check (None = anywhere)
    pub offset: Option<usize>,
    /// Severity level
    pub severity: ThreatSeverity,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Monitor statistics
#[derive(Debug, Default, Clone)]
pub struct MonitorStats {
    /// Total packets analyzed
    pub packets_analyzed: u64,
    /// Suspicious packets detected
    pub suspicious_packets: u64,
    /// Threats matched
    pub threats_matched: u64,
    /// Bytes analyzed
    pub bytes_analyzed: u64,
}

impl PacketMonitor {
    /// Create new packet monitor
    pub fn new(capture_enabled: bool) -> Self {
        Self {
            buffer: PacketRingBuffer::new(10000), // Last 10k packets
            capture_enabled,
            threat_signatures: Vec::new(),
            stats: MonitorStats::default(),
        }
    }

    /// Record a packet
    pub fn record_packet(&mut self, packet: &[u8], timestamp: u64) {
        self.stats.packets_analyzed += 1;
        self.stats.bytes_analyzed += packet.len() as u64;

        if !self.capture_enabled {
            return;
        }

        let mut header_bytes = [0u8; 64];
        let copy_len = packet.len().min(64);
        header_bytes[..copy_len].copy_from_slice(&packet[..copy_len]);

        let record = PacketRecord {
            timestamp,
            length: packet.len(),
            header_bytes,
            suspicious: false,
        };

        self.buffer.push(record);
    }

    /// Check packet against threat signatures
    pub fn check_threat(&mut self, packet: &[u8]) -> Option<String> {
        for sig in &self.threat_signatures {
            if self.matches_signature(packet, sig) {
                self.stats.threats_matched += 1;
                self.stats.suspicious_packets += 1;
                return Some(sig.name.clone());
            }
        }
        None
    }

    /// Add a threat signature
    pub fn add_signature(&mut self, signature: ThreatSignature) {
        self.threat_signatures.push(signature);
    }

    /// Check if packet matches signature
    fn matches_signature(&self, packet: &[u8], sig: &ThreatSignature) -> bool {
        if let Some(offset) = sig.offset {
            // Check at specific offset
            if offset + sig.pattern.len() > packet.len() {
                return false;
            }
            &packet[offset..offset + sig.pattern.len()] == sig.pattern.as_slice()
        } else {
            // Search anywhere in packet
            packet.windows(sig.pattern.len()).any(|window| window == sig.pattern.as_slice())
        }
    }

    /// Get recent packets
    pub fn recent_packets(&self, count: usize) -> Vec<&PacketRecord> {
        self.buffer.recent(count)
    }

    /// Get statistics
    pub fn stats(&self) -> &MonitorStats {
        &self.stats
    }

    /// Enable/disable capture
    pub fn set_capture_enabled(&mut self, enabled: bool) {
        self.capture_enabled = enabled;
    }

    /// Is capture enabled?
    pub fn is_capture_enabled(&self) -> bool {
        self.capture_enabled
    }

    /// Clear capture buffer
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }
}

impl Default for PacketMonitor {
    fn default() -> Self {
        Self::new(true)
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer() {
        let mut buffer = PacketRingBuffer::new(5);

        // Add packets
        for i in 0..10 {
            buffer.push(PacketRecord {
                timestamp: i,
                length: 100,
                header_bytes: [0; 64],
                suspicious: false,
            });
        }

        // Should only have last 5
        assert_eq!(buffer.total_captured(), 5);

        // Most recent should be timestamp 9
        let recent = buffer.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].timestamp, 9);
        assert_eq!(recent[1].timestamp, 8);
        assert_eq!(recent[2].timestamp, 7);
    }

    #[test]
    fn test_packet_monitor() {
        let mut monitor = PacketMonitor::new(true);

        // Record some packets
        for i in 0..100 {
            monitor.record_packet(&[0u8; 64], i);
        }

        assert_eq!(monitor.stats().packets_analyzed, 100);
        assert_eq!(monitor.stats().bytes_analyzed, 6400);
    }

    #[test]
    fn test_threat_detection() {
        let mut monitor = PacketMonitor::new(true);

        // Add signature
        monitor.add_signature(ThreatSignature {
            name: "Evil Pattern".to_string(),
            pattern: vec![0xDE, 0xAD, 0xBE, 0xEF],
            offset: None,
            severity: ThreatSeverity::High,
        });

        // Normal packet - no threat
        let normal = [0u8; 64];
        assert!(monitor.check_threat(&normal).is_none());

        // Evil packet - threat detected
        let mut evil = [0u8; 64];
        evil[10..14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(monitor.check_threat(&evil), Some("Evil Pattern".to_string()));
    }
}
