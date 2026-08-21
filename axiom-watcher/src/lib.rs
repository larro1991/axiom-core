//! AXIOM Watcher - Layer 3-7 Traffic Analysis
//!
//! Provides deep packet inspection and behavioral analysis for network traffic.
//!
//! # Features
//!
//! - **Flow Tracking**: Stateful connection monitoring with TCP/UDP flow analysis
//! - **Protocol Detection**: Identify protocols regardless of port (HTTP on 8080, etc.)
//! - **Behavioral Baselines**: Learn normal traffic patterns per host/service
//! - **Covert Channel Detection**: DNS tunneling, ICMP exfiltration, timing channels
//! - **Host Fingerprinting**: Identify hosts by traffic behavior patterns
//! - **Anomaly Detection**: Detect deviations from learned baselines
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                      AXIOM WATCHER                         │
//! ├────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
//! │  │ Flow Tracker │  │  Protocol    │  │   Behavioral     │ │
//! │  │              │  │  Detector    │  │   Analyzer       │ │
//! │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
//! │         │                 │                   │           │
//! │         └─────────────────┼───────────────────┘           │
//! │                           ▼                               │
//! │                  ┌────────────────┐                       │
//! │                  │ Anomaly Engine │                       │
//! │                  └────────┬───────┘                       │
//! │                           │                               │
//! │         ┌─────────────────┼─────────────────┐             │
//! │         ▼                 ▼                 ▼             │
//! │  ┌────────────┐  ┌──────────────┐  ┌──────────────┐      │
//! │  │  Covert    │  │   Host       │  │   Traffic    │      │
//! │  │  Channel   │  │ Fingerprint  │  │   Anomaly    │      │
//! │  └────────────┘  └──────────────┘  └──────────────┘      │
//! └────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod anomaly;
pub mod behavior;
pub mod covert;
pub mod fingerprint;
pub mod flow;
pub mod protocol;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use anomaly::{TrafficAnomaly, AnomalyType, TrafficAnomalyDetector};
pub use behavior::{BehaviorProfile, BehaviorTracker, BehaviorDeviation};
pub use covert::{CovertChannel, CovertChannelType, CovertDetector};
pub use fingerprint::{HostFingerprint, FingerprintDatabase};
pub use flow::{Flow, FlowKey, FlowState, FlowTracker};
pub use protocol::{Protocol, ProtocolDetector, ProtocolFeatures};

use axiom_guardian::mac::MacAddress;

/// Watcher configuration
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Enable flow tracking
    pub flow_tracking: bool,
    /// Enable protocol detection
    pub protocol_detection: bool,
    /// Enable behavioral analysis
    pub behavioral_analysis: bool,
    /// Enable covert channel detection
    pub covert_detection: bool,
    /// Enable host fingerprinting
    pub fingerprinting: bool,
    /// Flow timeout in seconds
    pub flow_timeout_secs: u64,
    /// Baseline learning period in seconds
    pub baseline_learning_secs: u64,
    /// Maximum flows to track
    pub max_flows: usize,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            flow_tracking: true,
            protocol_detection: true,
            behavioral_analysis: true,
            covert_detection: true,
            fingerprinting: true,
            flow_timeout_secs: 300,
            baseline_learning_secs: 3600,
            max_flows: 100_000,
        }
    }
}

/// Watcher statistics
#[derive(Debug, Clone, Default)]
pub struct WatcherStats {
    /// Packets processed
    pub packets_processed: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Active flows
    pub active_flows: usize,
    /// Total flows seen
    pub total_flows: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Covert channels detected
    pub covert_channels_detected: u64,
    /// Hosts fingerprinted
    pub hosts_fingerprinted: usize,
}

/// A watcher alert
#[derive(Debug, Clone)]
pub struct WatcherAlert {
    /// Timestamp
    pub timestamp: u64,
    /// Alert type
    pub alert_type: WatcherAlertType,
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
    /// Related evidence
    pub evidence: Vec<String>,
}

/// Types of watcher alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherAlertType {
    /// Traffic anomaly detected
    TrafficAnomaly,
    /// Behavioral deviation
    BehaviorDeviation,
    /// Covert channel suspected
    CovertChannel,
    /// New/unknown host
    NewHost,
    /// Host behavior changed
    HostBehaviorChange,
    /// Protocol anomaly
    ProtocolAnomaly,
    /// Data exfiltration suspected
    DataExfiltration,
    /// Lateral movement detected
    LateralMovement,
    /// Port scan detected
    PortScan,
    /// Unusual connection pattern
    UnusualConnection,
}

/// The network watcher
#[cfg(feature = "std")]
pub struct Watcher {
    config: WatcherConfig,
    flow_tracker: FlowTracker,
    protocol_detector: ProtocolDetector,
    behavior_tracker: BehaviorTracker,
    covert_detector: CovertDetector,
    fingerprint_db: FingerprintDatabase,
    anomaly_detector: TrafficAnomalyDetector,
    stats: WatcherStats,
    start_time: u64,
    alert_handler: Option<Box<dyn Fn(&WatcherAlert) + Send + Sync>>,
}

#[cfg(feature = "std")]
impl Watcher {
    /// Create a new watcher
    pub fn new(config: WatcherConfig) -> Self {
        Self {
            flow_tracker: FlowTracker::new(config.flow_timeout_secs, config.max_flows),
            protocol_detector: ProtocolDetector::new(),
            behavior_tracker: BehaviorTracker::new(config.baseline_learning_secs),
            covert_detector: CovertDetector::new(),
            fingerprint_db: FingerprintDatabase::new(),
            anomaly_detector: TrafficAnomalyDetector::new(),
            config,
            stats: WatcherStats::default(),
            start_time: 0,
            alert_handler: None,
        }
    }

    /// Set start time
    pub fn set_start_time(&mut self, timestamp: u64) {
        self.start_time = timestamp;
        self.behavior_tracker.set_start_time(timestamp);
    }

    /// Set alert handler
    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&WatcherAlert) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Box::new(handler));
        self
    }

    /// Process an IP packet
    pub fn process_packet(
        &mut self,
        packet: &[u8],
        timestamp: u64,
    ) -> Vec<WatcherAlert> {
        let mut alerts = Vec::new();
        self.stats.packets_processed += 1;
        self.stats.bytes_processed += packet.len() as u64;

        // Parse IP header (minimum 20 bytes)
        if packet.len() < 20 {
            return alerts;
        }

        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return alerts; // Only IPv4 for now
        }

        let ihl = (packet[0] & 0x0F) as usize * 4;
        if packet.len() < ihl {
            return alerts;
        }

        let protocol = packet[9];
        let src_ip = [packet[12], packet[13], packet[14], packet[15]];
        let dst_ip = [packet[16], packet[17], packet[18], packet[19]];

        let transport_payload = &packet[ihl..];

        // Extract ports for TCP/UDP
        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && transport_payload.len() >= 4 {
            (
                u16::from_be_bytes([transport_payload[0], transport_payload[1]]),
                u16::from_be_bytes([transport_payload[2], transport_payload[3]]),
            )
        } else {
            (0, 0)
        };

        // Track flow
        if self.config.flow_tracking {
            let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol);
            let flow_alerts = self.flow_tracker.observe(&flow_key, packet.len(), timestamp);
            for anomaly in flow_alerts {
                alerts.push(self.traffic_anomaly_to_alert(anomaly, timestamp));
            }
            self.stats.active_flows = self.flow_tracker.active_count();
            self.stats.total_flows = self.flow_tracker.total_count();
        }

        // Detect protocol
        if self.config.protocol_detection && transport_payload.len() > 8 {
            let app_payload = if protocol == 6 && transport_payload.len() > 20 {
                // Skip TCP header (minimum 20 bytes, could be more with options)
                let tcp_header_len = ((transport_payload[12] >> 4) as usize) * 4;
                if transport_payload.len() > tcp_header_len {
                    &transport_payload[tcp_header_len..]
                } else {
                    &[]
                }
            } else if protocol == 17 && transport_payload.len() > 8 {
                &transport_payload[8..] // UDP header is 8 bytes
            } else {
                &[]
            };

            if !app_payload.is_empty() {
                if let Some(detected) = self.protocol_detector.detect(app_payload, dst_port) {
                    // Check for protocol anomalies (e.g., HTTP on unusual port)
                    if self.is_unusual_protocol_port(&detected, dst_port) {
                        alerts.push(WatcherAlert {
                            timestamp,
                            alert_type: WatcherAlertType::ProtocolAnomaly,
                            severity: 30,
                            description: alloc::format!(
                                "{:?} detected on unusual port {}",
                                detected, dst_port
                            ),
                            source_ip: Some(src_ip),
                            dest_ip: Some(dst_ip),
                            flow_key: Some(FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol)),
                            evidence: Vec::new(),
                        });
                    }
                }
            }
        }

        // Behavioral analysis
        if self.config.behavioral_analysis {
            if let Some(deviation) = self.behavior_tracker.observe(
                src_ip,
                dst_ip,
                dst_port,
                packet.len(),
                timestamp,
            ) {
                alerts.push(self.behavior_deviation_to_alert(deviation, src_ip, timestamp));
            }
        }

        // Covert channel detection
        if self.config.covert_detection {
            // Check DNS specifically
            if dst_port == 53 || src_port == 53 {
                if let Some(channel) = self.covert_detector.check_dns(
                    transport_payload,
                    src_ip,
                    timestamp,
                ) {
                    self.stats.covert_channels_detected += 1;
                    alerts.push(self.covert_channel_to_alert(channel, src_ip, dst_ip, timestamp));
                }
            }

            // Check ICMP
            if protocol == 1 {
                if let Some(channel) = self.covert_detector.check_icmp(
                    transport_payload,
                    src_ip,
                    timestamp,
                ) {
                    self.stats.covert_channels_detected += 1;
                    alerts.push(self.covert_channel_to_alert(channel, src_ip, dst_ip, timestamp));
                }
            }
        }

        // Update host fingerprint
        if self.config.fingerprinting {
            self.fingerprint_db.observe(src_ip, dst_port, protocol, packet.len(), timestamp);
            self.stats.hosts_fingerprinted = self.fingerprint_db.count();
        }

        // Update stats
        self.stats.anomalies_detected += alerts.len() as u64;

        // Fire alert handler
        for alert in &alerts {
            if let Some(ref handler) = self.alert_handler {
                handler(alert);
            }
        }

        alerts
    }

    /// Check if protocol on unusual port
    fn is_unusual_protocol_port(&self, protocol: &Protocol, port: u16) -> bool {
        match protocol {
            Protocol::Http => port != 80 && port != 8080 && port != 8000,
            Protocol::Https => port != 443 && port != 8443,
            Protocol::Dns => port != 53,
            Protocol::Ssh => port != 22,
            Protocol::Smtp => port != 25 && port != 587 && port != 465,
            Protocol::Ftp => port != 21,
            _ => false,
        }
    }

    fn traffic_anomaly_to_alert(&self, anomaly: TrafficAnomaly, timestamp: u64) -> WatcherAlert {
        WatcherAlert {
            timestamp,
            alert_type: WatcherAlertType::TrafficAnomaly,
            severity: anomaly.severity,
            description: anomaly.description,
            source_ip: anomaly.source_ip,
            dest_ip: anomaly.dest_ip,
            flow_key: anomaly.flow_key,
            evidence: anomaly.evidence,
        }
    }

    fn behavior_deviation_to_alert(
        &self,
        deviation: BehaviorDeviation,
        source_ip: [u8; 4],
        timestamp: u64,
    ) -> WatcherAlert {
        WatcherAlert {
            timestamp,
            alert_type: WatcherAlertType::BehaviorDeviation,
            severity: deviation.severity,
            description: deviation.description,
            source_ip: Some(source_ip),
            dest_ip: None,
            flow_key: None,
            evidence: deviation.evidence,
        }
    }

    fn covert_channel_to_alert(
        &self,
        channel: CovertChannel,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        timestamp: u64,
    ) -> WatcherAlert {
        WatcherAlert {
            timestamp,
            alert_type: WatcherAlertType::CovertChannel,
            severity: channel.severity,
            description: channel.description,
            source_ip: Some(src_ip),
            dest_ip: Some(dst_ip),
            flow_key: None,
            evidence: channel.evidence,
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> &WatcherStats {
        &self.stats
    }

    /// Check if baseline learning is complete
    pub fn is_baseline_complete(&self, timestamp: u64) -> bool {
        !self.behavior_tracker.is_learning(timestamp)
    }

    /// Cleanup stale data
    pub fn cleanup(&mut self, timestamp: u64) {
        self.flow_tracker.cleanup(timestamp);
        self.covert_detector.cleanup(timestamp);
    }

    /// Get flow tracker
    pub fn flows(&self) -> &FlowTracker {
        &self.flow_tracker
    }

    /// Get behavior tracker
    pub fn behaviors(&self) -> &BehaviorTracker {
        &self.behavior_tracker
    }

    /// Get fingerprint database
    pub fn fingerprints(&self) -> &FingerprintDatabase {
        &self.fingerprint_db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watcher_creation() {
        let config = WatcherConfig::default();
        let watcher = Watcher::new(config);
        assert_eq!(watcher.stats.packets_processed, 0);
    }

    #[test]
    fn test_watcher_config() {
        let config = WatcherConfig {
            flow_tracking: true,
            protocol_detection: true,
            behavioral_analysis: true,
            covert_detection: true,
            fingerprinting: true,
            flow_timeout_secs: 600,
            baseline_learning_secs: 7200,
            max_flows: 50000,
        };
        assert_eq!(config.max_flows, 50000);
    }
}
