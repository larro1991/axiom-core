//! AXIOM Network Guardian
//!
//! Layer 2 attack detection and defense for legacy and hybrid networks.
//!
//! # Overview
//!
//! Traditional Ethernet networks have no authentication at Layer 2. This makes them
//! vulnerable to attacks like:
//!
//! - **MAC Spoofing**: Attacker uses another device's MAC address
//! - **ARP Poisoning**: Attacker sends fake ARP replies to redirect traffic
//! - **VLAN Hopping**: Attacker escapes their VLAN to access others
//! - **DC Impersonation**: Attacker waits for Domain Controller reboot, then impersonates
//!
//! The Guardian monitors network traffic, maintains baselines, detects anomalies,
//! and can actively defend critical assets.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Network Guardian                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │ ARP Monitor │  │ MAC Tracker │  │ Critical Asset Watch│ │
//! │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
//! │         │                │                    │            │
//! │         └────────────────┼────────────────────┘            │
//! │                          ▼                                 │
//! │                 ┌────────────────┐                         │
//! │                 │ Anomaly Engine │                         │
//! │                 └────────┬───────┘                         │
//! │                          │                                 │
//! │         ┌────────────────┼────────────────┐                │
//! │         ▼                ▼                ▼                │
//! │  ┌────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │   Alert    │  │ Audit Log   │  │   Defend    │         │
//! │  └────────────┘  └─────────────┘  └─────────────┘         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use axiom_guardian::{Guardian, GuardianConfig, CriticalAsset};
//!
//! // Create guardian
//! let config = GuardianConfig::default()
//!     .with_active_defense(true)
//!     .with_arp_monitoring(true);
//!
//! let mut guardian = Guardian::new(config);
//!
//! // Register critical assets (e.g., Domain Controllers)
//! guardian.register_critical_asset(CriticalAsset::new(
//!     "DC01",
//!     [0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF],  // MAC
//!     [192, 168, 1, 10].into(),               // IP
//! ));
//!
//! // Process network frames
//! guardian.process_frame(&frame_bytes, switch_port);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arp;
pub mod asset;
pub mod baseline;
pub mod defender;
pub mod detector;
pub mod mac;
pub mod legacy_boundary;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use arp::{ArpEntry, ArpMonitor, ArpPacket, ArpOperation};
pub use asset::{CriticalAsset, AssetStatus, AssetWatcher};
pub use baseline::{NetworkBaseline, BaselineEntry};
pub use defender::{DefenseAction, Defender, DefenseResult};
pub use detector::{Anomaly, AnomalyType, AnomalySeverity, AnomalyDetector};
pub use mac::{MacAddress, MacTracker, MacBinding};
pub use legacy_boundary::{
    LegacyBoundary, LegacyDevice, LegacyDeviceType, LegacyCommand, LegacyResponse,
    MacAlgorithm, LegacyBoundaryError,
};

/// Guardian configuration
#[derive(Debug, Clone)]
pub struct GuardianConfig {
    /// Enable ARP monitoring
    pub arp_monitoring: bool,
    /// Enable MAC tracking
    pub mac_tracking: bool,
    /// Enable active defense (requires feature)
    pub active_defense: bool,
    /// Baseline learning period in seconds
    pub baseline_learning_secs: u64,
    /// How long before a MAC binding is considered stale (seconds)
    pub mac_stale_secs: u64,
    /// How long before an ARP entry is considered stale (seconds)
    pub arp_stale_secs: u64,
    /// Maximum ARP rate per source before alerting (per second)
    pub max_arp_rate: u32,
    /// Alert on any critical asset state change
    pub alert_on_critical_change: bool,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            arp_monitoring: true,
            mac_tracking: true,
            active_defense: false,
            baseline_learning_secs: 3600, // 1 hour
            mac_stale_secs: 300,          // 5 minutes
            arp_stale_secs: 120,          // 2 minutes
            max_arp_rate: 10,             // 10 ARP/sec is suspicious
            alert_on_critical_change: true,
        }
    }
}

impl GuardianConfig {
    /// Enable active defense
    pub fn with_active_defense(mut self, enabled: bool) -> Self {
        self.active_defense = enabled;
        self
    }

    /// Enable ARP monitoring
    pub fn with_arp_monitoring(mut self, enabled: bool) -> Self {
        self.arp_monitoring = enabled;
        self
    }

    /// Enable MAC tracking
    pub fn with_mac_tracking(mut self, enabled: bool) -> Self {
        self.mac_tracking = enabled;
        self
    }

    /// Set baseline learning period
    pub fn with_baseline_learning(mut self, secs: u64) -> Self {
        self.baseline_learning_secs = secs;
        self
    }
}

/// Guardian statistics
#[derive(Debug, Clone, Default)]
pub struct GuardianStats {
    /// Total frames processed
    pub frames_processed: u64,
    /// ARP packets seen
    pub arp_packets: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Defense actions taken
    pub defense_actions: u64,
    /// Currently tracked MAC addresses
    pub tracked_macs: usize,
    /// Currently tracked ARP entries
    pub tracked_arps: usize,
    /// Critical assets monitored
    pub critical_assets: usize,
}

/// Alert from the Guardian
#[derive(Debug, Clone)]
pub struct GuardianAlert {
    /// Timestamp
    pub timestamp: u64,
    /// Alert type
    pub alert_type: AlertType,
    /// Severity
    pub severity: AnomalySeverity,
    /// Description
    pub description: String,
    /// Source MAC (if applicable)
    pub source_mac: Option<MacAddress>,
    /// Source IP (if applicable)
    pub source_ip: Option<[u8; 4]>,
    /// Switch port (if known)
    pub switch_port: Option<u16>,
    /// Recommended action
    pub recommended_action: Option<DefenseAction>,
}

/// Types of alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertType {
    /// MAC address seen on different port
    MacPortChange,
    /// ARP binding changed (IP now mapped to different MAC)
    ArpBindingChange,
    /// Gratuitous ARP flood detected
    ArpFlood,
    /// Critical asset went offline
    CriticalAssetOffline,
    /// Possible impersonation of critical asset
    CriticalAssetImpersonation,
    /// Duplicate MAC detected
    DuplicateMac,
    /// Suspicious ARP pattern
    SuspiciousArpPattern,
    /// VLAN violation
    VlanViolation,
}

/// The Network Guardian
#[cfg(feature = "std")]
pub struct Guardian {
    config: GuardianConfig,
    baseline: NetworkBaseline,
    arp_monitor: ArpMonitor,
    mac_tracker: MacTracker,
    asset_watcher: AssetWatcher,
    detector: AnomalyDetector,
    defender: Defender,
    stats: GuardianStats,
    start_time: u64,
    alert_handler: Option<Box<dyn Fn(&GuardianAlert) + Send + Sync>>,
}

#[cfg(feature = "std")]
impl Guardian {
    /// Create a new Guardian
    pub fn new(config: GuardianConfig) -> Self {
        Self {
            baseline: NetworkBaseline::new(config.baseline_learning_secs),
            arp_monitor: ArpMonitor::new(config.arp_stale_secs, config.max_arp_rate),
            mac_tracker: MacTracker::new(config.mac_stale_secs),
            asset_watcher: AssetWatcher::new(),
            detector: AnomalyDetector::new(),
            defender: Defender::new(config.active_defense),
            config,
            stats: GuardianStats::default(),
            start_time: 0,
            alert_handler: None,
        }
    }

    /// Set the start time (for baseline calculation)
    pub fn set_start_time(&mut self, timestamp: u64) {
        self.start_time = timestamp;
        self.baseline.set_start_time(timestamp);
    }

    /// Set alert handler callback
    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&GuardianAlert) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Box::new(handler));
        self
    }

    /// Register a critical asset to protect
    pub fn register_critical_asset(&mut self, asset: CriticalAsset) {
        self.asset_watcher.register(asset);
        self.stats.critical_assets = self.asset_watcher.asset_count();
    }

    /// Process an Ethernet frame
    pub fn process_frame(&mut self, frame: &[u8], switch_port: Option<u16>, timestamp: u64) -> Vec<GuardianAlert> {
        self.stats.frames_processed += 1;
        let mut alerts = Vec::new();

        // Parse Ethernet header (minimum 14 bytes)
        if frame.len() < 14 {
            return alerts;
        }

        let dst_mac = MacAddress::from_bytes(&frame[0..6]);
        let src_mac = MacAddress::from_bytes(&frame[6..12]);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        // Track MAC address
        if self.config.mac_tracking {
            if let Some(anomaly) = self.mac_tracker.observe(src_mac, switch_port, timestamp) {
                alerts.push(self.anomaly_to_alert(anomaly, timestamp));
            }
        }

        // Check if it's an ARP packet (ethertype 0x0806)
        if ethertype == 0x0806 && self.config.arp_monitoring {
            self.stats.arp_packets += 1;
            if let Some(arp) = ArpPacket::parse(&frame[14..]) {
                let arp_alerts = self.process_arp(arp, switch_port, timestamp);
                alerts.extend(arp_alerts);
            }
        }

        // Update baseline if in learning mode
        if self.baseline.is_learning(timestamp) {
            self.baseline.observe(src_mac, switch_port, timestamp);
        }

        // Check critical assets
        let asset_alerts = self.asset_watcher.check_frame(src_mac, switch_port, timestamp);
        for anomaly in asset_alerts {
            alerts.push(self.anomaly_to_alert(anomaly, timestamp));
        }

        // Update stats
        self.stats.tracked_macs = self.mac_tracker.count();
        self.stats.tracked_arps = self.arp_monitor.count();
        self.stats.anomalies_detected += alerts.len() as u64;

        // Fire alert handler
        for alert in &alerts {
            if let Some(ref handler) = self.alert_handler {
                handler(alert);
            }
        }

        // Take defense actions if enabled
        if self.config.active_defense {
            for alert in &alerts {
                if let Some(ref action) = alert.recommended_action {
                    if let Some(_result) = self.defender.execute(action.clone(), timestamp) {
                        self.stats.defense_actions += 1;
                    }
                }
            }
        }

        alerts
    }

    /// Process an ARP packet
    fn process_arp(&mut self, arp: ArpPacket, switch_port: Option<u16>, timestamp: u64) -> Vec<GuardianAlert> {
        let mut alerts = Vec::new();

        // Check for anomalies
        let anomalies = self.arp_monitor.process(arp.clone(), switch_port, timestamp);
        for anomaly in anomalies {
            alerts.push(self.anomaly_to_alert(anomaly, timestamp));
        }

        // Check if this affects a critical asset
        if let Some(anomaly) = self.asset_watcher.check_arp(&arp, switch_port, timestamp) {
            alerts.push(self.anomaly_to_alert(anomaly, timestamp));
        }

        alerts
    }

    /// Convert an anomaly to an alert
    fn anomaly_to_alert(&self, anomaly: Anomaly, timestamp: u64) -> GuardianAlert {
        let (alert_type, description, recommended) = match anomaly.anomaly_type {
            AnomalyType::MacPortChange { mac, old_port, new_port } => (
                AlertType::MacPortChange,
                alloc::format!(
                    "MAC {} moved from port {} to port {}",
                    mac, old_port.unwrap_or(0), new_port.unwrap_or(0)
                ),
                Some(DefenseAction::LogOnly),
            ),
            AnomalyType::ArpBindingChange { ip, old_mac, new_mac } => (
                AlertType::ArpBindingChange,
                alloc::format!(
                    "IP {:?} changed from MAC {} to {}",
                    ip, old_mac, new_mac
                ),
                Some(DefenseAction::ArpCorrection { ip, correct_mac: old_mac }),
            ),
            AnomalyType::ArpFlood { source_mac, rate } => (
                AlertType::ArpFlood,
                alloc::format!(
                    "ARP flood from {} at {} packets/sec",
                    source_mac, rate
                ),
                Some(DefenseAction::RateLimit { mac: source_mac }),
            ),
            AnomalyType::CriticalAssetOffline { asset_name, mac } => (
                AlertType::CriticalAssetOffline,
                alloc::format!(
                    "Critical asset '{}' ({}) went offline",
                    asset_name, mac
                ),
                Some(DefenseAction::AlertSecurity),
            ),
            AnomalyType::CriticalAssetImpersonation { asset_name, real_mac, attacker_mac } => (
                AlertType::CriticalAssetImpersonation,
                alloc::format!(
                    "CRITICAL: Possible impersonation of '{}' - real MAC {}, attacker MAC {}",
                    asset_name, real_mac, attacker_mac
                ),
                Some(DefenseAction::IsolatePort { mac: attacker_mac }),
            ),
            AnomalyType::DuplicateMac { mac, ports } => (
                AlertType::DuplicateMac,
                alloc::format!(
                    "MAC {} seen on multiple ports: {:?}",
                    mac, ports
                ),
                Some(DefenseAction::AlertSecurity),
            ),
            AnomalyType::GratuitousArpSpam { mac, count } => (
                AlertType::SuspiciousArpPattern,
                alloc::format!(
                    "Gratuitous ARP spam from {} ({} in window)",
                    mac, count
                ),
                Some(DefenseAction::RateLimit { mac }),
            ),
        };

        GuardianAlert {
            timestamp,
            alert_type,
            severity: anomaly.severity,
            description,
            source_mac: anomaly.source_mac,
            source_ip: anomaly.source_ip,
            switch_port: anomaly.switch_port,
            recommended_action: recommended,
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> &GuardianStats {
        &self.stats
    }

    /// Check if baseline learning is complete
    pub fn is_baseline_complete(&self, timestamp: u64) -> bool {
        !self.baseline.is_learning(timestamp)
    }

    /// Get the current network baseline
    pub fn baseline(&self) -> &NetworkBaseline {
        &self.baseline
    }

    /// Manually mark baseline learning as complete
    pub fn complete_baseline(&mut self) {
        self.baseline.complete();
    }

    /// Cleanup stale entries
    pub fn cleanup(&mut self, timestamp: u64) {
        self.mac_tracker.cleanup(timestamp);
        self.arp_monitor.cleanup(timestamp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_creation() {
        let config = GuardianConfig::default()
            .with_active_defense(false)
            .with_arp_monitoring(true);

        let guardian = Guardian::new(config);
        assert_eq!(guardian.stats.frames_processed, 0);
    }

    #[test]
    fn test_mac_address_parsing() {
        let mac = MacAddress::from_bytes(&[0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);
        assert_eq!(mac.to_string(), "00:50:56:AB:CD:EF");
    }

    #[test]
    fn test_basic_frame_processing() {
        let config = GuardianConfig::default();
        let mut guardian = Guardian::new(config);
        guardian.set_start_time(0);

        // Ethernet frame: dst_mac, src_mac, ethertype (not ARP)
        let frame = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst: broadcast
            0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF,  // src
            0x08, 0x00,                          // ethertype: IPv4
        ];

        let alerts = guardian.process_frame(&frame, Some(1), 1000);
        assert!(alerts.is_empty()); // No alerts for normal traffic
        assert_eq!(guardian.stats.frames_processed, 1);
    }

    #[test]
    fn test_critical_asset_registration() {
        let config = GuardianConfig::default();
        let mut guardian = Guardian::new(config);

        let dc = CriticalAsset::new(
            "DC01",
            MacAddress::from_bytes(&[0x00, 0x50, 0x56, 0x01, 0x02, 0x03]),
            [192, 168, 1, 10],
        );

        guardian.register_critical_asset(dc);
        assert_eq!(guardian.stats.critical_assets, 1);
    }
}
