//! Network baseline management
//!
//! Learns normal network behavior during a training period,
//! then detects deviations from the baseline.

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::mac::MacAddress;

/// A baseline entry for a MAC address
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    /// MAC address
    pub mac: MacAddress,
    /// Expected switch port(s)
    pub expected_ports: Vec<u16>,
    /// Typical traffic rate (frames/sec)
    pub typical_rate: f64,
    /// First seen during baseline
    pub first_seen: u64,
    /// Last seen during baseline
    pub last_seen: u64,
    /// Total observations
    pub observations: u64,
}

impl BaselineEntry {
    /// Create new entry
    pub fn new(mac: MacAddress, port: Option<u16>, timestamp: u64) -> Self {
        Self {
            mac,
            expected_ports: port.into_iter().collect(),
            typical_rate: 0.0,
            first_seen: timestamp,
            last_seen: timestamp,
            observations: 1,
        }
    }

    /// Update with new observation
    pub fn observe(&mut self, port: Option<u16>, timestamp: u64) {
        self.last_seen = timestamp;
        self.observations += 1;

        if let Some(p) = port {
            if !self.expected_ports.contains(&p) {
                self.expected_ports.push(p);
            }
        }

        // Update rate estimate
        let duration = (self.last_seen - self.first_seen).max(1) as f64;
        self.typical_rate = self.observations as f64 / duration;
    }

    /// Check if a port is expected
    pub fn is_port_expected(&self, port: u16) -> bool {
        self.expected_ports.contains(&port)
    }
}

/// Network baseline
#[cfg(feature = "std")]
pub struct NetworkBaseline {
    /// Baseline entries by MAC
    entries: HashMap<MacAddress, BaselineEntry>,
    /// Learning period in seconds
    learning_period: u64,
    /// When learning started
    start_time: u64,
    /// Is learning complete
    learning_complete: bool,
}

#[cfg(feature = "std")]
impl NetworkBaseline {
    /// Create new baseline
    pub fn new(learning_period: u64) -> Self {
        Self {
            entries: HashMap::new(),
            learning_period,
            start_time: 0,
            learning_complete: false,
        }
    }

    /// Set start time
    pub fn set_start_time(&mut self, timestamp: u64) {
        self.start_time = timestamp;
    }

    /// Check if still in learning mode
    pub fn is_learning(&self, current_time: u64) -> bool {
        !self.learning_complete && current_time < self.start_time + self.learning_period
    }

    /// Mark learning as complete
    pub fn complete(&mut self) {
        self.learning_complete = true;
    }

    /// Observe a MAC during learning
    pub fn observe(&mut self, mac: MacAddress, port: Option<u16>, timestamp: u64) {
        if mac.is_broadcast() || mac.is_multicast() {
            return;
        }

        if let Some(entry) = self.entries.get_mut(&mac) {
            entry.observe(port, timestamp);
        } else {
            self.entries.insert(mac, BaselineEntry::new(mac, port, timestamp));
        }
    }

    /// Get baseline for a MAC
    pub fn get(&self, mac: &MacAddress) -> Option<&BaselineEntry> {
        self.entries.get(mac)
    }

    /// Check if MAC is in baseline
    pub fn is_known(&self, mac: &MacAddress) -> bool {
        self.entries.contains_key(mac)
    }

    /// Check if port is expected for MAC
    pub fn is_port_expected(&self, mac: &MacAddress, port: u16) -> bool {
        self.entries.get(mac)
            .map(|e| e.is_port_expected(port))
            .unwrap_or(false)
    }

    /// Get all baseline entries
    pub fn all_entries(&self) -> impl Iterator<Item = &BaselineEntry> {
        self.entries.values()
    }

    /// Get count
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Export baseline (for persistence)
    pub fn export(&self) -> Vec<BaselineEntry> {
        self.entries.values().cloned().collect()
    }

    /// Import baseline entries
    pub fn import(&mut self, entries: Vec<BaselineEntry>) {
        for entry in entries {
            self.entries.insert(entry.mac, entry);
        }
        self.learning_complete = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_learning() {
        let mut baseline = NetworkBaseline::new(3600); // 1 hour
        baseline.set_start_time(0);

        assert!(baseline.is_learning(1000));
        assert!(baseline.is_learning(3500));
        assert!(!baseline.is_learning(3700));
    }

    #[test]
    fn test_baseline_observation() {
        let mut baseline = NetworkBaseline::new(3600);
        baseline.set_start_time(0);

        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);

        baseline.observe(mac, Some(1), 100);
        baseline.observe(mac, Some(1), 200);
        baseline.observe(mac, Some(2), 300);

        let entry = baseline.get(&mac).unwrap();
        assert_eq!(entry.observations, 3);
        assert!(entry.expected_ports.contains(&1));
        assert!(entry.expected_ports.contains(&2));
    }

    #[test]
    fn test_baseline_export_import() {
        let mut baseline = NetworkBaseline::new(3600);
        baseline.set_start_time(0);

        let mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);
        baseline.observe(mac, Some(1), 100);

        let exported = baseline.export();
        assert_eq!(exported.len(), 1);

        let mut new_baseline = NetworkBaseline::new(3600);
        new_baseline.import(exported);

        assert!(new_baseline.is_known(&mac));
        assert!(new_baseline.learning_complete);
    }
}
