//! ARP monitoring and attack detection
//!
//! Monitors ARP traffic and detects:
//! - ARP binding changes (possible ARP poisoning)
//! - Gratuitous ARP floods
//! - ARP rate anomalies
//! - Suspicious ARP patterns

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::detector::{Anomaly, AnomalyType, AnomalySeverity};
use crate::mac::MacAddress;

/// ARP operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    /// ARP Request (who-has)
    Request = 1,
    /// ARP Reply (is-at)
    Reply = 2,
}

impl ArpOperation {
    /// Parse from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            _ => None,
        }
    }
}

/// Parsed ARP packet
#[derive(Debug, Clone)]
pub struct ArpPacket {
    /// Operation (request/reply)
    pub operation: ArpOperation,
    /// Sender hardware address (MAC)
    pub sender_mac: MacAddress,
    /// Sender protocol address (IP)
    pub sender_ip: [u8; 4],
    /// Target hardware address (MAC)
    pub target_mac: MacAddress,
    /// Target protocol address (IP)
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    /// Parse ARP packet from bytes (after Ethernet header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        // ARP packet is at least 28 bytes for IPv4/Ethernet
        if data.len() < 28 {
            return None;
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let hw_size = data[4];
        let proto_size = data[5];
        let operation = u16::from_be_bytes([data[6], data[7]]);

        // We only handle Ethernet (1) and IPv4 (0x0800)
        if hw_type != 1 || proto_type != 0x0800 || hw_size != 6 || proto_size != 4 {
            return None;
        }

        let operation = ArpOperation::from_u16(operation)?;

        let sender_mac = MacAddress::from_bytes(&data[8..14]);
        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&data[14..18]);

        let target_mac = MacAddress::from_bytes(&data[18..24]);
        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&data[24..28]);

        Some(Self {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Check if this is a gratuitous ARP (announces own IP)
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }

    /// Check if this is a probe (sender IP is 0.0.0.0)
    pub fn is_probe(&self) -> bool {
        self.sender_ip == [0, 0, 0, 0]
    }
}

/// An ARP table entry
#[derive(Debug, Clone)]
pub struct ArpEntry {
    /// IP address
    pub ip: [u8; 4],
    /// MAC address
    pub mac: MacAddress,
    /// When first seen
    pub first_seen: u64,
    /// When last seen
    pub last_seen: u64,
    /// Number of times confirmed
    pub confirmations: u64,
    /// Is this a static entry (manually configured)
    pub is_static: bool,
    /// Switch port where seen
    pub port: Option<u16>,
}

impl ArpEntry {
    /// Create new entry
    pub fn new(ip: [u8; 4], mac: MacAddress, port: Option<u16>, timestamp: u64) -> Self {
        Self {
            ip,
            mac,
            first_seen: timestamp,
            last_seen: timestamp,
            confirmations: 1,
            is_static: false,
            port,
        }
    }

    /// Update entry with new observation
    pub fn update(&mut self, mac: MacAddress, port: Option<u16>, timestamp: u64) -> Option<MacAddress> {
        let old_mac = if self.mac != mac && !self.is_static {
            Some(self.mac)
        } else {
            None
        };

        if !self.is_static {
            self.mac = mac;
        }
        self.last_seen = timestamp;
        self.confirmations += 1;
        if port.is_some() {
            self.port = port;
        }

        old_mac
    }

    /// Check if stale
    pub fn is_stale(&self, current_time: u64, threshold: u64) -> bool {
        !self.is_static && current_time.saturating_sub(self.last_seen) > threshold
    }
}

/// Rate tracking for a source
#[derive(Debug, Clone)]
struct RateTracker {
    /// Timestamps of recent packets
    timestamps: Vec<u64>,
    /// Window size for rate calculation (seconds)
    window: u64,
}

impl RateTracker {
    fn new(window: u64) -> Self {
        Self {
            timestamps: Vec::new(),
            window,
        }
    }

    fn record(&mut self, timestamp: u64) {
        self.timestamps.push(timestamp);
        // Keep only timestamps within window
        let cutoff = timestamp.saturating_sub(self.window);
        self.timestamps.retain(|&t| t >= cutoff);
    }

    fn rate(&self) -> u32 {
        self.timestamps.len() as u32
    }
}

/// ARP monitor
#[cfg(feature = "std")]
pub struct ArpMonitor {
    /// ARP table (IP -> entry)
    arp_table: HashMap<[u8; 4], ArpEntry>,
    /// Rate trackers per source MAC
    rate_trackers: HashMap<MacAddress, RateTracker>,
    /// Gratuitous ARP counters
    gratuitous_counts: HashMap<MacAddress, (u64, u32)>, // (window_start, count)
    /// Stale threshold
    stale_threshold: u64,
    /// Max ARP rate before alerting
    max_rate: u32,
    /// Rate window in seconds
    rate_window: u64,
}

#[cfg(feature = "std")]
impl ArpMonitor {
    /// Create new monitor
    pub fn new(stale_threshold: u64, max_rate: u32) -> Self {
        Self {
            arp_table: HashMap::new(),
            rate_trackers: HashMap::new(),
            gratuitous_counts: HashMap::new(),
            stale_threshold,
            max_rate,
            rate_window: 1, // 1 second window for rate calculation
        }
    }

    /// Process an ARP packet
    pub fn process(&mut self, arp: ArpPacket, port: Option<u16>, timestamp: u64) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Track rate
        let tracker = self.rate_trackers
            .entry(arp.sender_mac)
            .or_insert_with(|| RateTracker::new(self.rate_window));
        tracker.record(timestamp);

        let rate = tracker.rate();
        if rate > self.max_rate {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::ArpFlood {
                    source_mac: arp.sender_mac,
                    rate,
                },
                severity: AnomalySeverity::High,
                source_mac: Some(arp.sender_mac),
                source_ip: Some(arp.sender_ip),
                switch_port: port,
                timestamp,
            });
        }

        // Track gratuitous ARPs
        if arp.is_gratuitous() {
            let (window_start, count) = self.gratuitous_counts
                .entry(arp.sender_mac)
                .or_insert((timestamp, 0));

            // Reset window if older than 60 seconds
            if timestamp.saturating_sub(*window_start) > 60 {
                *window_start = timestamp;
                *count = 0;
            }

            *count += 1;

            if *count > 5 {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::GratuitousArpSpam {
                        mac: arp.sender_mac,
                        count: *count,
                    },
                    severity: AnomalySeverity::Medium,
                    source_mac: Some(arp.sender_mac),
                    source_ip: Some(arp.sender_ip),
                    switch_port: port,
                    timestamp,
                });
            }
        }

        // Update ARP table and check for binding changes
        // Only track if sender IP is not 0.0.0.0 (ARP probe)
        if !arp.is_probe() {
            if let Some(entry) = self.arp_table.get_mut(&arp.sender_ip) {
                if let Some(old_mac) = entry.update(arp.sender_mac, port, timestamp) {
                    // MAC changed for this IP - possible ARP spoofing!
                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::ArpBindingChange {
                            ip: arp.sender_ip,
                            old_mac,
                            new_mac: arp.sender_mac,
                        },
                        severity: AnomalySeverity::Critical,
                        source_mac: Some(arp.sender_mac),
                        source_ip: Some(arp.sender_ip),
                        switch_port: port,
                        timestamp,
                    });
                }
            } else {
                // New IP
                self.arp_table.insert(
                    arp.sender_ip,
                    ArpEntry::new(arp.sender_ip, arp.sender_mac, port, timestamp),
                );
            }
        }

        anomalies
    }

    /// Add a static ARP entry (won't be updated by network traffic)
    pub fn add_static(&mut self, ip: [u8; 4], mac: MacAddress, timestamp: u64) {
        let mut entry = ArpEntry::new(ip, mac, None, timestamp);
        entry.is_static = true;
        self.arp_table.insert(ip, entry);
    }

    /// Get entry for an IP
    pub fn get(&self, ip: &[u8; 4]) -> Option<&ArpEntry> {
        self.arp_table.get(ip)
    }

    /// Get MAC for an IP
    pub fn resolve(&self, ip: &[u8; 4]) -> Option<MacAddress> {
        self.arp_table.get(ip).map(|e| e.mac)
    }

    /// Get all entries
    pub fn all_entries(&self) -> impl Iterator<Item = &ArpEntry> {
        self.arp_table.values()
    }

    /// Get count of entries
    pub fn count(&self) -> usize {
        self.arp_table.len()
    }

    /// Cleanup stale entries
    pub fn cleanup(&mut self, timestamp: u64) {
        let threshold = self.stale_threshold;
        self.arp_table.retain(|_, entry| !entry.is_stale(timestamp, threshold));

        // Also cleanup rate trackers
        for tracker in self.rate_trackers.values_mut() {
            let cutoff = timestamp.saturating_sub(tracker.window);
            tracker.timestamps.retain(|&t| t >= cutoff);
        }
        self.rate_trackers.retain(|_, t| !t.timestamps.is_empty());

        // Cleanup gratuitous counters
        self.gratuitous_counts.retain(|_, (start, _)| timestamp.saturating_sub(*start) < 120);
    }

    /// Generate ARP reply bytes for defense
    #[cfg(feature = "active-defense")]
    pub fn generate_reply(
        sender_mac: MacAddress,
        sender_ip: [u8; 4],
        target_mac: MacAddress,
        target_ip: [u8; 4],
    ) -> [u8; 28] {
        let mut packet = [0u8; 28];

        // Hardware type: Ethernet (1)
        packet[0..2].copy_from_slice(&1u16.to_be_bytes());
        // Protocol type: IPv4 (0x0800)
        packet[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        // Hardware size: 6
        packet[4] = 6;
        // Protocol size: 4
        packet[5] = 4;
        // Operation: Reply (2)
        packet[6..8].copy_from_slice(&2u16.to_be_bytes());
        // Sender MAC
        packet[8..14].copy_from_slice(sender_mac.as_bytes());
        // Sender IP
        packet[14..18].copy_from_slice(&sender_ip);
        // Target MAC
        packet[18..24].copy_from_slice(target_mac.as_bytes());
        // Target IP
        packet[24..28].copy_from_slice(&target_ip);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_reply(sender_mac: [u8; 6], sender_ip: [u8; 4], target_mac: [u8; 6], target_ip: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![
            0, 1,       // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            6,          // Hardware size
            4,          // Protocol size
            0, 2,       // Operation: Reply
        ];
        packet.extend_from_slice(&sender_mac);
        packet.extend_from_slice(&sender_ip);
        packet.extend_from_slice(&target_mac);
        packet.extend_from_slice(&target_ip);
        packet
    }

    #[test]
    fn test_arp_packet_parse() {
        let data = make_arp_reply(
            [0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF],
            [192, 168, 1, 10],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 1],
        );

        let arp = ArpPacket::parse(&data).unwrap();
        assert_eq!(arp.operation, ArpOperation::Reply);
        assert_eq!(arp.sender_ip, [192, 168, 1, 10]);
        assert_eq!(arp.target_ip, [192, 168, 1, 1]);
    }

    #[test]
    fn test_gratuitous_arp_detection() {
        let data = make_arp_reply(
            [0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF],
            [192, 168, 1, 10],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [192, 168, 1, 10], // Same as sender - gratuitous
        );

        let arp = ArpPacket::parse(&data).unwrap();
        assert!(arp.is_gratuitous());
    }

    #[test]
    fn test_arp_binding_change_detection() {
        let mut monitor = ArpMonitor::new(300, 10);

        // First ARP from IP 192.168.1.10 with MAC A
        let arp1 = ArpPacket {
            operation: ArpOperation::Reply,
            sender_mac: MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x01, 0x01]),
            sender_ip: [192, 168, 1, 10],
            target_mac: MacAddress::zero(),
            target_ip: [192, 168, 1, 1],
        };

        let anomalies = monitor.process(arp1, Some(1), 1000);
        assert!(anomalies.is_empty()); // First observation

        // Second ARP from same IP with different MAC - should alert!
        let arp2 = ArpPacket {
            operation: ArpOperation::Reply,
            sender_mac: MacAddress::from_array([0x00, 0x50, 0x56, 0x02, 0x02, 0x02]),
            sender_ip: [192, 168, 1, 10],
            target_mac: MacAddress::zero(),
            target_ip: [192, 168, 1, 1],
        };

        let anomalies = monitor.process(arp2, Some(2), 2000);
        assert!(!anomalies.is_empty());

        // Should have ARP binding change anomaly
        assert!(anomalies.iter().any(|a| matches!(
            a.anomaly_type,
            AnomalyType::ArpBindingChange { .. }
        )));
    }

    #[test]
    fn test_arp_flood_detection() {
        let mut monitor = ArpMonitor::new(300, 5); // Max 5 ARP/sec

        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x01, 0x01]);

        // Send 10 ARPs in same second
        for i in 0..10 {
            let arp = ArpPacket {
                operation: ArpOperation::Reply,
                sender_mac: mac,
                sender_ip: [192, 168, 1, i as u8],
                target_mac: MacAddress::zero(),
                target_ip: [192, 168, 1, 1],
            };

            let anomalies = monitor.process(arp, Some(1), 1000);

            // After 5, should start alerting
            if i >= 5 {
                assert!(anomalies.iter().any(|a| matches!(
                    a.anomaly_type,
                    AnomalyType::ArpFlood { .. }
                )));
            }
        }
    }

    #[test]
    fn test_static_entry_not_updated() {
        let mut monitor = ArpMonitor::new(300, 10);

        // Add static entry
        let correct_mac = MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x01, 0x01]);
        monitor.add_static([192, 168, 1, 10], correct_mac, 1000);

        // Try to update with different MAC - should NOT change
        let arp = ArpPacket {
            operation: ArpOperation::Reply,
            sender_mac: MacAddress::from_array([0x00, 0x50, 0x56, 0x02, 0x02, 0x02]),
            sender_ip: [192, 168, 1, 10],
            target_mac: MacAddress::zero(),
            target_ip: [192, 168, 1, 1],
        };

        let _ = monitor.process(arp, Some(1), 2000);

        // Static entry should still have original MAC
        let entry = monitor.get(&[192, 168, 1, 10]).unwrap();
        assert_eq!(entry.mac, correct_mac);
    }
}
