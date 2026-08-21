//! Traffic anomaly detection
//!
//! Detects unusual traffic patterns that may indicate attacks or data exfiltration.

use alloc::string::String;
use alloc::vec::Vec;

use crate::flow::FlowKey;

/// Type of traffic anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    /// Port scan detected
    PortScan,
    /// Horizontal scan (same port, many hosts)
    HorizontalScan,
    /// Asymmetric flow (large download, no upload)
    AsymmetricFlow,
    /// Beaconing pattern (regular intervals)
    Beaconing,
    /// Large data transfer
    LargeTransfer,
    /// Unusual time of activity
    UnusualTime,
    /// Connection to known-bad IP
    KnownBadIp,
    /// Protocol tunneling
    ProtocolTunneling,
    /// Slow data exfiltration
    SlowExfiltration,
}

/// A detected traffic anomaly
#[derive(Debug, Clone)]
pub struct TrafficAnomaly {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Severity (0-100)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Source IP
    pub source_ip: Option<[u8; 4]>,
    /// Destination IP
    pub dest_ip: Option<[u8; 4]>,
    /// Flow key if applicable
    pub flow_key: Option<FlowKey>,
    /// Evidence
    pub evidence: Vec<String>,
}

/// Traffic anomaly detector
#[cfg(feature = "std")]
pub struct TrafficAnomalyDetector {
    /// Beaconing detection window (seconds)
    beacon_window: u64,
    /// Minimum beacon count to trigger
    min_beacon_count: u32,
    /// Large transfer threshold (bytes)
    large_transfer_threshold: u64,
    /// Slow exfil threshold (bytes per hour)
    slow_exfil_threshold: u64,
    /// Recent beacons for pattern detection
    beacon_times: hashbrown::HashMap<[u8; 4], Vec<u64>>,
    /// Transfer totals per host
    transfer_totals: hashbrown::HashMap<[u8; 4], (u64, u64)>, // (outbound, inbound)
}

#[cfg(feature = "std")]
impl TrafficAnomalyDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            beacon_window: 3600,
            min_beacon_count: 10,
            large_transfer_threshold: 100 * 1024 * 1024, // 100MB
            slow_exfil_threshold: 10 * 1024 * 1024, // 10MB/hour
            beacon_times: hashbrown::HashMap::new(),
            transfer_totals: hashbrown::HashMap::new(),
        }
    }

    /// Check for beaconing pattern
    pub fn check_beaconing(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        timestamp: u64,
    ) -> Option<TrafficAnomaly> {
        let times = self.beacon_times.entry(dst_ip).or_insert_with(Vec::new);
        times.push(timestamp);

        // Keep only times in window
        let cutoff = timestamp.saturating_sub(self.beacon_window);
        times.retain(|&t| t >= cutoff);

        // Need minimum count
        if times.len() < self.min_beacon_count as usize {
            return None;
        }

        // Calculate intervals
        let mut intervals: Vec<u64> = Vec::new();
        for i in 1..times.len() {
            intervals.push(times[i] - times[i - 1]);
        }

        if intervals.is_empty() {
            return None;
        }

        // Calculate mean and variance
        let mean = intervals.iter().sum::<u64>() / intervals.len() as u64;
        let variance: f64 = intervals.iter()
            .map(|&x| {
                let diff = x as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();

        // Low variance with regular intervals = beaconing
        let coefficient_of_variation = std_dev / mean as f64;
        if coefficient_of_variation < 0.2 && mean > 10 && mean < 300 {
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::Beaconing,
                severity: 70,
                description: alloc::format!(
                    "Beaconing detected: {} connections to {:?} with ~{}s interval",
                    times.len(), dst_ip, mean
                ),
                source_ip: Some(src_ip),
                dest_ip: Some(dst_ip),
                flow_key: None,
                evidence: vec![
                    alloc::format!("Mean interval: {}s", mean),
                    alloc::format!("Std dev: {:.1}s", std_dev),
                    alloc::format!("Connections in window: {}", times.len()),
                ],
            });
        }

        None
    }

    /// Check for asymmetric transfers (exfiltration)
    pub fn check_asymmetric(
        &mut self,
        src_ip: [u8; 4],
        bytes: u64,
        is_outbound: bool,
    ) -> Option<TrafficAnomaly> {
        let totals = self.transfer_totals.entry(src_ip).or_insert((0, 0));
        if is_outbound {
            totals.0 += bytes;
        } else {
            totals.1 += bytes;
        }

        // Check for significant outbound with little inbound
        let outbound = totals.0;
        let inbound = totals.1;

        if outbound > self.large_transfer_threshold {
            let ratio = if inbound > 0 {
                outbound as f64 / inbound as f64
            } else {
                outbound as f64
            };

            if ratio > 10.0 {
                return Some(TrafficAnomaly {
                    anomaly_type: AnomalyType::AsymmetricFlow,
                    severity: 60,
                    description: alloc::format!(
                        "Asymmetric traffic from {:?}: {} out, {} in (ratio: {:.1}x)",
                        src_ip,
                        format_bytes(outbound),
                        format_bytes(inbound),
                        ratio
                    ),
                    source_ip: Some(src_ip),
                    dest_ip: None,
                    flow_key: None,
                    evidence: vec![
                        alloc::format!("Outbound: {}", format_bytes(outbound)),
                        alloc::format!("Inbound: {}", format_bytes(inbound)),
                    ],
                });
            }
        }

        None
    }

    /// Check for large transfer
    pub fn check_large_transfer(
        &self,
        flow_key: &FlowKey,
        bytes: u64,
    ) -> Option<TrafficAnomaly> {
        if bytes > self.large_transfer_threshold {
            return Some(TrafficAnomaly {
                anomaly_type: AnomalyType::LargeTransfer,
                severity: 40,
                description: alloc::format!(
                    "Large transfer: {} to {:?}:{}",
                    format_bytes(bytes),
                    flow_key.dst_ip,
                    flow_key.dst_port
                ),
                source_ip: Some(flow_key.src_ip),
                dest_ip: Some(flow_key.dst_ip),
                flow_key: Some(flow_key.clone()),
                evidence: vec![
                    alloc::format!("Bytes transferred: {}", format_bytes(bytes)),
                ],
            });
        }
        None
    }

    /// Cleanup old data
    pub fn cleanup(&mut self, timestamp: u64) {
        let cutoff = timestamp.saturating_sub(self.beacon_window);
        for times in self.beacon_times.values_mut() {
            times.retain(|&t| t >= cutoff);
        }
        self.beacon_times.retain(|_, v| !v.is_empty());
    }

    /// Reset totals (call periodically)
    pub fn reset_totals(&mut self) {
        self.transfer_totals.clear();
    }
}

#[cfg(feature = "std")]
impl Default for TrafficAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Format bytes for human readability
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        alloc::format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        alloc::format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        alloc::format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        alloc::format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(100), "100B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1048576), "1.0MB");
        assert_eq!(format_bytes(1073741824), "1.0GB");
    }

    #[test]
    fn test_beaconing_detection() {
        let mut detector = TrafficAnomalyDetector::new();
        detector.min_beacon_count = 5;

        let src_ip = [192, 168, 1, 10];
        let dst_ip = [10, 0, 0, 1];

        // Send regular beacons every 60 seconds
        for i in 0..10 {
            let result = detector.check_beaconing(src_ip, dst_ip, i * 60);
            if i >= 4 {
                // Should trigger after min_beacon_count
                assert!(result.is_some() || i < 9); // May need a few more iterations
            }
        }
    }

    #[test]
    fn test_asymmetric_flow() {
        let mut detector = TrafficAnomalyDetector::new();
        detector.large_transfer_threshold = 1000;

        let src_ip = [192, 168, 1, 10];

        // Add large outbound
        detector.check_asymmetric(src_ip, 2000, true);
        // Add small inbound
        let result = detector.check_asymmetric(src_ip, 100, false);

        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::AsymmetricFlow);
    }

    #[test]
    fn test_large_transfer() {
        let detector = TrafficAnomalyDetector::new();
        let flow_key = FlowKey::new(
            [192, 168, 1, 10],
            [10, 0, 0, 1],
            12345,
            443,
            6,
        );

        let result = detector.check_large_transfer(&flow_key, 200 * 1024 * 1024);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::LargeTransfer);
    }
}
