//! Behavioral baseline and deviation detection
//!
//! Learns normal traffic patterns per host and detects deviations.

use alloc::string::String;
use alloc::vec::Vec;

/// A behavioral deviation alert
#[derive(Debug, Clone)]
pub struct BehaviorDeviation {
    /// Severity (0-100)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Evidence
    pub evidence: Vec<String>,
}

/// Behavior profile for a host
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    /// IP address
    pub ip: [u8; 4],
    /// Common destination ports
    pub common_ports: Vec<u16>,
    /// Port access counts
    port_counts: hashbrown::HashMap<u16, u32>,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Packet size samples
    packet_sizes: Vec<usize>,
    /// Common destinations
    pub common_destinations: Vec<[u8; 4]>,
    /// Destination counts
    dest_counts: hashbrown::HashMap<[u8; 4], u32>,
    /// Hourly activity pattern (0-23)
    hourly_activity: [u32; 24],
    /// Total observations
    pub observations: u64,
    /// First seen
    pub first_seen: u64,
    /// Last seen
    pub last_seen: u64,
}

impl BehaviorProfile {
    /// Create new profile
    pub fn new(ip: [u8; 4], timestamp: u64) -> Self {
        Self {
            ip,
            common_ports: Vec::new(),
            port_counts: hashbrown::HashMap::new(),
            avg_packet_size: 0.0,
            packet_sizes: Vec::new(),
            common_destinations: Vec::new(),
            dest_counts: hashbrown::HashMap::new(),
            hourly_activity: [0; 24],
            observations: 0,
            first_seen: timestamp,
            last_seen: timestamp,
        }
    }

    /// Update profile with observation
    pub fn observe(
        &mut self,
        dst_ip: [u8; 4],
        dst_port: u16,
        packet_size: usize,
        timestamp: u64,
    ) {
        // Update port counts
        *self.port_counts.entry(dst_port).or_insert(0) += 1;

        // Update destination counts
        *self.dest_counts.entry(dst_ip).or_insert(0) += 1;

        // Update packet size average
        self.packet_sizes.push(packet_size);
        if self.packet_sizes.len() > 1000 {
            self.packet_sizes.remove(0);
        }
        self.avg_packet_size = self.packet_sizes.iter().sum::<usize>() as f64
            / self.packet_sizes.len() as f64;

        // Update hourly activity (simple: use bottom bits of timestamp as hour approximation)
        let hour = ((timestamp / 3600) % 24) as usize;
        self.hourly_activity[hour] += 1;

        // Update timestamps
        self.last_seen = timestamp;
        self.observations += 1;

        // Periodically update common ports/destinations
        if self.observations % 100 == 0 {
            self.update_common_items();
        }
    }

    /// Update common ports and destinations lists
    fn update_common_items(&mut self) {
        // Sort ports by count
        let mut ports: Vec<_> = self.port_counts.iter().collect();
        ports.sort_by(|a, b| b.1.cmp(a.1));
        self.common_ports = ports.iter().take(10).map(|(&p, _)| p).collect();

        // Sort destinations by count
        let mut dests: Vec<_> = self.dest_counts.iter().collect();
        dests.sort_by(|a, b| b.1.cmp(a.1));
        self.common_destinations = dests.iter().take(10).map(|(&d, _)| d).collect();
    }

    /// Check if port is unusual for this host
    pub fn is_unusual_port(&self, port: u16) -> bool {
        // Need baseline data first
        if self.observations < 100 {
            return false;
        }

        // Port never seen before = unusual
        !self.port_counts.contains_key(&port)
    }

    /// Check if destination is unusual
    pub fn is_unusual_destination(&self, dst_ip: [u8; 4]) -> bool {
        if self.observations < 100 {
            return false;
        }
        !self.dest_counts.contains_key(&dst_ip)
    }

    /// Check if packet size is unusual
    pub fn is_unusual_packet_size(&self, size: usize) -> bool {
        if self.packet_sizes.len() < 100 {
            return false;
        }

        // More than 3 standard deviations from mean
        let variance: f64 = self.packet_sizes.iter()
            .map(|&s| {
                let diff = s as f64 - self.avg_packet_size;
                diff * diff
            })
            .sum::<f64>() / self.packet_sizes.len() as f64;
        let std_dev = variance.sqrt();

        let deviation = (size as f64 - self.avg_packet_size).abs();
        deviation > 3.0 * std_dev
    }

    /// Get activity score for hour (0.0-1.0)
    pub fn hour_activity_score(&self, hour: usize) -> f64 {
        let max = *self.hourly_activity.iter().max().unwrap_or(&1) as f64;
        if max == 0.0 {
            return 0.0;
        }
        self.hourly_activity[hour] as f64 / max
    }
}

/// Tracks behavior across all hosts
#[cfg(feature = "std")]
pub struct BehaviorTracker {
    /// Profiles by IP
    profiles: hashbrown::HashMap<[u8; 4], BehaviorProfile>,
    /// Baseline learning period
    learning_period: u64,
    /// Start time
    start_time: u64,
    /// Alert on new host
    alert_on_new_host: bool,
    /// Alert on unusual port
    alert_on_unusual_port: bool,
    /// Alert on unusual destination
    alert_on_unusual_dest: bool,
}

#[cfg(feature = "std")]
impl BehaviorTracker {
    /// Create new tracker
    pub fn new(learning_period: u64) -> Self {
        Self {
            profiles: hashbrown::HashMap::new(),
            learning_period,
            start_time: 0,
            alert_on_new_host: true,
            alert_on_unusual_port: true,
            alert_on_unusual_dest: true,
        }
    }

    /// Set start time
    pub fn set_start_time(&mut self, timestamp: u64) {
        self.start_time = timestamp;
    }

    /// Check if still in learning mode
    pub fn is_learning(&self, timestamp: u64) -> bool {
        timestamp < self.start_time + self.learning_period
    }

    /// Observe traffic and check for deviations
    pub fn observe(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        dst_port: u16,
        packet_size: usize,
        timestamp: u64,
    ) -> Option<BehaviorDeviation> {
        let is_learning = self.is_learning(timestamp);

        // Get or create profile
        let is_new_host = !self.profiles.contains_key(&src_ip);
        let profile = self.profiles
            .entry(src_ip)
            .or_insert_with(|| BehaviorProfile::new(src_ip, timestamp));

        // During learning, just update profile
        if is_learning {
            profile.observe(dst_ip, dst_port, packet_size, timestamp);
            return None;
        }

        // Check for deviations
        let mut deviation = None;

        if is_new_host && self.alert_on_new_host {
            deviation = Some(BehaviorDeviation {
                severity: 40,
                description: alloc::format!(
                    "New host detected: {:?}",
                    src_ip
                ),
                evidence: vec![
                    alloc::format!("First seen at timestamp: {}", timestamp),
                ],
            });
        } else if self.alert_on_unusual_port && profile.is_unusual_port(dst_port) {
            deviation = Some(BehaviorDeviation {
                severity: 50,
                description: alloc::format!(
                    "Host {:?} accessing unusual port {}",
                    src_ip, dst_port
                ),
                evidence: vec![
                    alloc::format!("Common ports: {:?}", profile.common_ports),
                    alloc::format!("Observations: {}", profile.observations),
                ],
            });
        } else if self.alert_on_unusual_dest && profile.is_unusual_destination(dst_ip) {
            deviation = Some(BehaviorDeviation {
                severity: 45,
                description: alloc::format!(
                    "Host {:?} connecting to unusual destination {:?}",
                    src_ip, dst_ip
                ),
                evidence: vec![
                    alloc::format!("Common destinations: {:?}", profile.common_destinations),
                ],
            });
        }

        // Always update profile
        profile.observe(dst_ip, dst_port, packet_size, timestamp);

        deviation
    }

    /// Get profile for IP
    pub fn get_profile(&self, ip: &[u8; 4]) -> Option<&BehaviorProfile> {
        self.profiles.get(ip)
    }

    /// Get all profiles
    pub fn all_profiles(&self) -> impl Iterator<Item = &BehaviorProfile> {
        self.profiles.values()
    }

    /// Count of tracked hosts
    pub fn host_count(&self) -> usize {
        self.profiles.len()
    }

    /// Configure alerting
    pub fn configure(
        &mut self,
        new_host: bool,
        unusual_port: bool,
        unusual_dest: bool,
    ) {
        self.alert_on_new_host = new_host;
        self.alert_on_unusual_port = unusual_port;
        self.alert_on_unusual_dest = unusual_dest;
    }
}

#[cfg(feature = "std")]
impl Default for BehaviorTracker {
    fn default() -> Self {
        Self::new(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_profile_creation() {
        let profile = BehaviorProfile::new([192, 168, 1, 10], 1000);
        assert_eq!(profile.observations, 0);
        assert_eq!(profile.first_seen, 1000);
    }

    #[test]
    fn test_profile_observation() {
        let mut profile = BehaviorProfile::new([192, 168, 1, 10], 1000);

        // Add observations
        for i in 0u64..100 {
            profile.observe(
                [10, 0, 0, 1],
                443,
                100 + (i as usize % 50),
                1000 + i,
            );
        }

        assert_eq!(profile.observations, 100);
        assert!(!profile.is_unusual_port(443));
        assert!(profile.is_unusual_port(8080));
    }

    #[test]
    fn test_behavior_tracker_learning() {
        let mut tracker = BehaviorTracker::new(100);
        tracker.set_start_time(0);

        // During learning period
        assert!(tracker.is_learning(50));

        // After learning period
        assert!(!tracker.is_learning(150));
    }

    #[test]
    fn test_new_host_detection() {
        let mut tracker = BehaviorTracker::new(100);
        tracker.set_start_time(0);

        // During learning - no alerts
        let result = tracker.observe(
            [192, 168, 1, 10],
            [10, 0, 0, 1],
            443,
            100,
            50,
        );
        assert!(result.is_none());

        // After learning - new host alert
        let result = tracker.observe(
            [192, 168, 1, 20],
            [10, 0, 0, 1],
            443,
            100,
            150,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_unusual_port_detection() {
        let mut tracker = BehaviorTracker::new(0); // No learning period
        tracker.set_start_time(0);

        // Build baseline
        for i in 0u64..150 {
            tracker.observe(
                [192, 168, 1, 10],
                [10, 0, 0, 1],
                443,
                100,
                i,
            );
        }

        // Now access unusual port
        let result = tracker.observe(
            [192, 168, 1, 10],
            [10, 0, 0, 1],
            22, // SSH - unusual for this host
            100,
            200,
        );
        assert!(result.is_some());
    }
}
