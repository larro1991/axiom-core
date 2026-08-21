//! MAC address tracking and anomaly detection
//!
//! Monitors MAC addresses and detects:
//! - MAC appearing on different switch ports (possible attack or misconfiguration)
//! - Duplicate MACs on multiple ports simultaneously
//! - MAC spoofing attempts

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use hashbrown::HashMap;

use crate::detector::{Anomaly, AnomalyType, AnomalySeverity};

/// MAC address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[..6]);
        Self(mac)
    }

    /// Create from array
    pub const fn from_array(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    /// Check if this is a multicast address (bit 0 of first byte is 1)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Check if this is a locally administered address (bit 1 of first byte is 1)
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Zero MAC address
    pub const fn zero() -> Self {
        Self([0; 6])
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// A MAC address binding to a switch port
#[derive(Debug, Clone)]
pub struct MacBinding {
    /// The MAC address
    pub mac: MacAddress,
    /// Switch port where last seen
    pub port: Option<u16>,
    /// When first seen
    pub first_seen: u64,
    /// When last seen
    pub last_seen: u64,
    /// Number of times seen
    pub seen_count: u64,
    /// Historical ports this MAC has been seen on
    pub port_history: Vec<(u16, u64)>, // (port, timestamp)
}

impl MacBinding {
    /// Create a new binding
    pub fn new(mac: MacAddress, port: Option<u16>, timestamp: u64) -> Self {
        let mut port_history = Vec::new();
        if let Some(p) = port {
            port_history.push((p, timestamp));
        }

        Self {
            mac,
            port,
            first_seen: timestamp,
            last_seen: timestamp,
            seen_count: 1,
            port_history,
        }
    }

    /// Update binding with new observation
    pub fn update(&mut self, port: Option<u16>, timestamp: u64) -> Option<u16> {
        let old_port = self.port;
        self.last_seen = timestamp;
        self.seen_count += 1;

        if let Some(p) = port {
            if self.port != Some(p) {
                // Port changed
                self.port_history.push((p, timestamp));
                // Keep only last 10 port changes
                if self.port_history.len() > 10 {
                    self.port_history.remove(0);
                }
            }
            self.port = Some(p);
        }

        old_port
    }

    /// Check if this binding is stale
    pub fn is_stale(&self, current_time: u64, stale_threshold: u64) -> bool {
        current_time.saturating_sub(self.last_seen) > stale_threshold
    }

    /// Get age in seconds
    pub fn age(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.first_seen)
    }
}

/// MAC address tracker
#[cfg(feature = "std")]
pub struct MacTracker {
    /// MAC bindings indexed by MAC address
    bindings: HashMap<MacAddress, MacBinding>,
    /// Port to MAC mappings (for detecting multiple MACs on same port)
    port_macs: HashMap<u16, Vec<MacAddress>>,
    /// Stale threshold in seconds
    stale_threshold: u64,
}

#[cfg(feature = "std")]
impl MacTracker {
    /// Create a new tracker
    pub fn new(stale_threshold: u64) -> Self {
        Self {
            bindings: HashMap::new(),
            port_macs: HashMap::new(),
            stale_threshold,
        }
    }

    /// Observe a MAC address on a port
    pub fn observe(&mut self, mac: MacAddress, port: Option<u16>, timestamp: u64) -> Option<Anomaly> {
        // Skip broadcast and multicast
        if mac.is_broadcast() || mac.is_multicast() {
            return None;
        }

        if let Some(binding) = self.bindings.get_mut(&mac) {
            let old_port = binding.update(port, timestamp);

            // Check if port changed
            if let (Some(old), Some(new)) = (old_port, port) {
                if old != new {
                    // MAC moved to different port - possible attack
                    return Some(Anomaly {
                        anomaly_type: AnomalyType::MacPortChange {
                            mac,
                            old_port: Some(old),
                            new_port: Some(new),
                        },
                        severity: AnomalySeverity::Medium,
                        source_mac: Some(mac),
                        source_ip: None,
                        switch_port: port,
                        timestamp,
                    });
                }
            }
        } else {
            // New MAC address
            let binding = MacBinding::new(mac, port, timestamp);
            self.bindings.insert(mac, binding);

            // Track port -> MAC mapping
            if let Some(p) = port {
                self.port_macs.entry(p).or_default().push(mac);
            }
        }

        None
    }

    /// Check for duplicate MACs (same MAC on multiple ports simultaneously)
    pub fn check_duplicates(&self, timestamp: u64) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let mut mac_ports: HashMap<MacAddress, Vec<u16>> = HashMap::new();

        // Build current port mapping for non-stale MACs
        for (mac, binding) in &self.bindings {
            if !binding.is_stale(timestamp, self.stale_threshold) {
                if let Some(port) = binding.port {
                    mac_ports.entry(*mac).or_default().push(port);
                }
            }
        }

        // This shouldn't happen normally (same MAC, multiple current ports)
        // but if we're seeing rapid port changes, flag it
        for binding in self.bindings.values() {
            let recent_ports: Vec<u16> = binding.port_history
                .iter()
                .filter(|(_, ts)| timestamp.saturating_sub(*ts) < 10) // Last 10 seconds
                .map(|(p, _)| *p)
                .collect();

            if recent_ports.len() > 1 {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::DuplicateMac {
                        mac: binding.mac,
                        ports: recent_ports,
                    },
                    severity: AnomalySeverity::High,
                    source_mac: Some(binding.mac),
                    source_ip: None,
                    switch_port: binding.port,
                    timestamp,
                });
            }
        }

        anomalies
    }

    /// Get binding for a MAC address
    pub fn get(&self, mac: &MacAddress) -> Option<&MacBinding> {
        self.bindings.get(mac)
    }

    /// Get all current bindings
    pub fn all_bindings(&self) -> impl Iterator<Item = &MacBinding> {
        self.bindings.values()
    }

    /// Get count of tracked MACs
    pub fn count(&self) -> usize {
        self.bindings.len()
    }

    /// Cleanup stale entries
    pub fn cleanup(&mut self, timestamp: u64) {
        let stale_threshold = self.stale_threshold;
        self.bindings.retain(|_, binding| !binding.is_stale(timestamp, stale_threshold));

        // Cleanup port_macs too
        for macs in self.port_macs.values_mut() {
            macs.retain(|mac| self.bindings.contains_key(mac));
        }
        self.port_macs.retain(|_, macs| !macs.is_empty());
    }

    /// Check if a MAC is known
    pub fn is_known(&self, mac: &MacAddress) -> bool {
        self.bindings.contains_key(mac)
    }

    /// Get the expected port for a MAC
    pub fn expected_port(&self, mac: &MacAddress) -> Option<u16> {
        self.bindings.get(mac).and_then(|b| b.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);
        assert_eq!(mac.to_string(), "00:50:56:AB:CD:EF");
    }

    #[test]
    fn test_mac_address_types() {
        let broadcast = MacAddress::from_array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(broadcast.is_broadcast());
        assert!(broadcast.is_multicast());

        let multicast = MacAddress::from_array([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);
        assert!(multicast.is_multicast());
        assert!(!multicast.is_broadcast());

        let local = MacAddress::from_array([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(local.is_local());

        let normal = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);
        assert!(!normal.is_broadcast());
        assert!(!normal.is_multicast());
        assert!(!normal.is_local());
    }

    #[test]
    fn test_mac_tracker_basic() {
        let mut tracker = MacTracker::new(300);
        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);

        // First observation - no anomaly
        let result = tracker.observe(mac, Some(1), 1000);
        assert!(result.is_none());
        assert_eq!(tracker.count(), 1);

        // Same MAC, same port - no anomaly
        let result = tracker.observe(mac, Some(1), 2000);
        assert!(result.is_none());
    }

    #[test]
    fn test_mac_port_change_detection() {
        let mut tracker = MacTracker::new(300);
        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);

        // First observation on port 1
        tracker.observe(mac, Some(1), 1000);

        // Same MAC on port 2 - should trigger anomaly
        let result = tracker.observe(mac, Some(2), 2000);
        assert!(result.is_some());

        let anomaly = result.unwrap();
        assert!(matches!(
            anomaly.anomaly_type,
            AnomalyType::MacPortChange { old_port: Some(1), new_port: Some(2), .. }
        ));
    }

    #[test]
    fn test_mac_tracker_cleanup() {
        let mut tracker = MacTracker::new(100); // 100 second stale threshold
        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);

        tracker.observe(mac, Some(1), 1000);
        assert_eq!(tracker.count(), 1);

        // Not stale yet
        tracker.cleanup(1050);
        assert_eq!(tracker.count(), 1);

        // Now stale
        tracker.cleanup(1200);
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_broadcast_multicast_ignored() {
        let mut tracker = MacTracker::new(300);

        let broadcast = MacAddress::from_array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let multicast = MacAddress::from_array([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);

        tracker.observe(broadcast, Some(1), 1000);
        tracker.observe(multicast, Some(1), 1000);

        assert_eq!(tracker.count(), 0); // Both should be ignored
    }
}
