//! Critical asset protection
//!
//! Special monitoring for critical infrastructure like Domain Controllers,
//! database servers, etc.

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::arp::ArpPacket;
use crate::detector::{Anomaly, AnomalyType, AnomalySeverity};
use crate::mac::MacAddress;

/// Status of a critical asset
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetStatus {
    /// Asset is online and responding
    Online,
    /// Asset went offline
    Offline,
    /// Asset status is unknown (not enough data)
    Unknown,
    /// Possible impersonation detected
    Compromised,
}

/// A critical asset to protect
#[derive(Debug, Clone)]
pub struct CriticalAsset {
    /// Human-readable name
    pub name: String,
    /// MAC address
    pub mac: MacAddress,
    /// IP address
    pub ip: [u8; 4],
    /// Expected switch port (if known)
    pub expected_port: Option<u16>,
    /// Current status
    pub status: AssetStatus,
    /// Last seen timestamp
    pub last_seen: u64,
    /// How long before considered offline (seconds)
    pub offline_threshold: u64,
    /// Alert on any state change
    pub alert_on_change: bool,
}

impl CriticalAsset {
    /// Create a new critical asset
    pub fn new(name: &str, mac: MacAddress, ip: [u8; 4]) -> Self {
        Self {
            name: name.into(),
            mac,
            ip,
            expected_port: None,
            status: AssetStatus::Unknown,
            last_seen: 0,
            offline_threshold: 60, // 1 minute default
            alert_on_change: true,
        }
    }

    /// Set expected port
    pub fn with_port(mut self, port: u16) -> Self {
        self.expected_port = Some(port);
        self
    }

    /// Set offline threshold
    pub fn with_offline_threshold(mut self, secs: u64) -> Self {
        self.offline_threshold = secs;
        self
    }

    /// Disable change alerts
    pub fn without_alerts(mut self) -> Self {
        self.alert_on_change = false;
        self
    }

    /// Check if asset is offline
    pub fn is_offline(&self, current_time: u64) -> bool {
        self.status == AssetStatus::Offline ||
        (self.last_seen > 0 && current_time.saturating_sub(self.last_seen) > self.offline_threshold)
    }

    /// Update last seen
    pub fn mark_seen(&mut self, timestamp: u64, port: Option<u16>) {
        self.last_seen = timestamp;
        if self.expected_port.is_none() && port.is_some() {
            self.expected_port = port;
        }
        self.status = AssetStatus::Online;
    }
}

/// Watches critical assets for attacks
#[cfg(feature = "std")]
pub struct AssetWatcher {
    /// Registered assets by MAC
    by_mac: HashMap<MacAddress, CriticalAsset>,
    /// Registered assets by IP
    by_ip: HashMap<[u8; 4], MacAddress>,
}

#[cfg(feature = "std")]
impl AssetWatcher {
    /// Create new watcher
    pub fn new() -> Self {
        Self {
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
        }
    }

    /// Register a critical asset
    pub fn register(&mut self, asset: CriticalAsset) {
        self.by_ip.insert(asset.ip, asset.mac);
        self.by_mac.insert(asset.mac, asset);
    }

    /// Unregister an asset
    pub fn unregister(&mut self, mac: &MacAddress) {
        if let Some(asset) = self.by_mac.remove(mac) {
            self.by_ip.remove(&asset.ip);
        }
    }

    /// Get asset count
    pub fn asset_count(&self) -> usize {
        self.by_mac.len()
    }

    /// Check a frame for critical asset activity
    pub fn check_frame(&mut self, src_mac: MacAddress, port: Option<u16>, timestamp: u64) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Check if this is from a registered asset
        if let Some(asset) = self.by_mac.get_mut(&src_mac) {
            let was_offline = asset.is_offline(timestamp);

            // Update status
            asset.mark_seen(timestamp, port);

            // Check port expectation
            if let (Some(expected), Some(actual)) = (asset.expected_port, port) {
                if expected != actual && asset.alert_on_change {
                    // Critical asset on unexpected port!
                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::MacPortChange {
                            mac: src_mac,
                            old_port: Some(expected),
                            new_port: Some(actual),
                        },
                        severity: AnomalySeverity::High,
                        source_mac: Some(src_mac),
                        source_ip: Some(asset.ip),
                        switch_port: port,
                        timestamp,
                    });
                }
            }

            // Was offline but now online - noteworthy
            if was_offline {
                // This is actually good - asset came back
                // Could log for audit purposes
            }
        }

        anomalies
    }

    /// Check ARP for impersonation attempts
    pub fn check_arp(&mut self, arp: &ArpPacket, port: Option<u16>, timestamp: u64) -> Option<Anomaly> {
        // Check if someone is claiming one of our protected IPs
        let expected_mac = *self.by_ip.get(&arp.sender_ip)?;

        if arp.sender_mac != expected_mac {
            // Someone else is claiming this IP!
            let asset = self.by_mac.get_mut(&expected_mac)?;
            let asset_name = asset.name.clone();

            // Mark as potentially compromised
            asset.status = AssetStatus::Compromised;

            return Some(Anomaly {
                anomaly_type: AnomalyType::CriticalAssetImpersonation {
                    asset_name,
                    real_mac: expected_mac,
                    attacker_mac: arp.sender_mac,
                },
                severity: AnomalySeverity::Critical,
                source_mac: Some(arp.sender_mac),
                source_ip: Some(arp.sender_ip),
                switch_port: port,
                timestamp,
            });
        }

        None
    }

    /// Check for offline assets
    pub fn check_offline(&mut self, timestamp: u64) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        for asset in self.by_mac.values_mut() {
            if asset.status == AssetStatus::Online && asset.is_offline(timestamp) {
                asset.status = AssetStatus::Offline;

                if asset.alert_on_change {
                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::CriticalAssetOffline {
                            asset_name: asset.name.clone(),
                            mac: asset.mac,
                        },
                        severity: AnomalySeverity::High,
                        source_mac: Some(asset.mac),
                        source_ip: Some(asset.ip),
                        switch_port: asset.expected_port,
                        timestamp,
                    });
                }
            }
        }

        anomalies
    }

    /// Get all assets
    pub fn all_assets(&self) -> impl Iterator<Item = &CriticalAsset> {
        self.by_mac.values()
    }

    /// Get asset by MAC
    pub fn get_by_mac(&self, mac: &MacAddress) -> Option<&CriticalAsset> {
        self.by_mac.get(mac)
    }

    /// Get asset by IP
    pub fn get_by_ip(&self, ip: &[u8; 4]) -> Option<&CriticalAsset> {
        self.by_ip.get(ip).and_then(|mac| self.by_mac.get(mac))
    }

    /// Check if an IP is protected
    pub fn is_protected_ip(&self, ip: &[u8; 4]) -> bool {
        self.by_ip.contains_key(ip)
    }

    /// Check if a MAC is protected
    pub fn is_protected_mac(&self, mac: &MacAddress) -> bool {
        self.by_mac.contains_key(mac)
    }
}

#[cfg(feature = "std")]
impl Default for AssetWatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::ArpOperation;

    #[test]
    fn test_critical_asset_creation() {
        let asset = CriticalAsset::new(
            "DC01",
            MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]),
            [192, 168, 1, 10],
        ).with_port(5);

        assert_eq!(asset.name, "DC01");
        assert_eq!(asset.expected_port, Some(5));
        assert_eq!(asset.status, AssetStatus::Unknown);
    }

    #[test]
    fn test_asset_watcher_registration() {
        let mut watcher = AssetWatcher::new();

        let dc = CriticalAsset::new(
            "DC01",
            MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]),
            [192, 168, 1, 10],
        );

        watcher.register(dc);

        assert!(watcher.is_protected_ip(&[192, 168, 1, 10]));
        assert_eq!(watcher.asset_count(), 1);
    }

    #[test]
    fn test_impersonation_detection() {
        let mut watcher = AssetWatcher::new();

        let dc_mac = MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]);
        let dc = CriticalAsset::new("DC01", dc_mac, [192, 168, 1, 10]);
        watcher.register(dc);

        // Attacker sends ARP claiming DC's IP with different MAC
        let attacker_mac = MacAddress::from_array([0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC]);
        let arp = ArpPacket {
            operation: ArpOperation::Reply,
            sender_mac: attacker_mac,
            sender_ip: [192, 168, 1, 10], // DC's IP!
            target_mac: MacAddress::zero(),
            target_ip: [192, 168, 1, 1],
        };

        let anomaly = watcher.check_arp(&arp, Some(99), 1000);
        assert!(anomaly.is_some());

        let anomaly = anomaly.unwrap();
        assert!(matches!(
            anomaly.anomaly_type,
            AnomalyType::CriticalAssetImpersonation { .. }
        ));
        assert_eq!(anomaly.severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_offline_detection() {
        let mut watcher = AssetWatcher::new();

        let dc_mac = MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]);
        let dc = CriticalAsset::new("DC01", dc_mac, [192, 168, 1, 10])
            .with_offline_threshold(60);
        watcher.register(dc);

        // DC sends traffic - mark as online
        watcher.check_frame(dc_mac, Some(5), 1000);

        // Check at t=1050 - should still be online
        let anomalies = watcher.check_offline(1050);
        assert!(anomalies.is_empty());

        // Check at t=1100 (more than 60s later) - should be offline
        let anomalies = watcher.check_offline(1100);
        assert!(!anomalies.is_empty());
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::CriticalAssetOffline { .. }
        ));
    }
}
