//! Anomaly detection engine
//!
//! Core anomaly types and detection logic.

use alloc::string::String;
use alloc::vec::Vec;

use crate::mac::MacAddress;

/// Severity of an anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    /// Informational - normal but noteworthy
    Info = 0,
    /// Low - minor deviation from normal
    Low = 1,
    /// Medium - suspicious activity
    Medium = 2,
    /// High - likely attack in progress
    High = 3,
    /// Critical - active attack confirmed
    Critical = 4,
}

/// Types of anomalies we detect
#[derive(Debug, Clone)]
pub enum AnomalyType {
    /// MAC address appeared on a different port
    MacPortChange {
        mac: MacAddress,
        old_port: Option<u16>,
        new_port: Option<u16>,
    },

    /// ARP binding changed (IP now maps to different MAC)
    ArpBindingChange {
        ip: [u8; 4],
        old_mac: MacAddress,
        new_mac: MacAddress,
    },

    /// ARP flood from a single source
    ArpFlood {
        source_mac: MacAddress,
        rate: u32,
    },

    /// Critical asset went offline
    CriticalAssetOffline {
        asset_name: String,
        mac: MacAddress,
    },

    /// Someone is trying to impersonate a critical asset
    CriticalAssetImpersonation {
        asset_name: String,
        real_mac: MacAddress,
        attacker_mac: MacAddress,
    },

    /// Same MAC seen on multiple ports simultaneously
    DuplicateMac {
        mac: MacAddress,
        ports: Vec<u16>,
    },

    /// Excessive gratuitous ARPs
    GratuitousArpSpam {
        mac: MacAddress,
        count: u32,
    },
}

/// An detected anomaly
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Severity
    pub severity: AnomalySeverity,
    /// Source MAC if known
    pub source_mac: Option<MacAddress>,
    /// Source IP if known
    pub source_ip: Option<[u8; 4]>,
    /// Switch port if known
    pub switch_port: Option<u16>,
    /// When detected
    pub timestamp: u64,
}

/// Anomaly detector (aggregates from multiple sources)
#[cfg(feature = "std")]
pub struct AnomalyDetector {
    /// Recent anomalies for correlation
    recent: Vec<Anomaly>,
    /// Max anomalies to keep
    max_recent: usize,
}

#[cfg(feature = "std")]
impl AnomalyDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            recent: Vec::new(),
            max_recent: 1000,
        }
    }

    /// Record an anomaly
    pub fn record(&mut self, anomaly: Anomaly) {
        self.recent.push(anomaly);
        if self.recent.len() > self.max_recent {
            self.recent.remove(0);
        }
    }

    /// Check for correlated anomalies (multiple indicators of same attack)
    pub fn correlate(&self, timestamp: u64, window_secs: u64) -> Vec<CorrelatedAttack> {
        let mut attacks = Vec::new();
        let window_start = timestamp.saturating_sub(window_secs);

        // Find anomalies in window
        let recent: Vec<_> = self.recent.iter()
            .filter(|a| a.timestamp >= window_start)
            .collect();

        // Look for DC impersonation pattern:
        // 1. Critical asset goes offline
        // 2. ARP binding changes for that IP
        // 3. Different MAC claims that IP
        let offline_assets: Vec<_> = recent.iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::CriticalAssetOffline { .. }))
            .collect();

        for offline in offline_assets {
            if let AnomalyType::CriticalAssetOffline { ref asset_name, mac } = offline.anomaly_type {
                // Check for binding change after offline
                let binding_changes: Vec<_> = recent.iter()
                    .filter(|a| a.timestamp > offline.timestamp)
                    .filter(|a| matches!(&a.anomaly_type, AnomalyType::ArpBindingChange { old_mac, .. } if *old_mac == mac))
                    .collect();

                if !binding_changes.is_empty() {
                    let mut indicators = vec![(*offline).clone()];
                    for bc in binding_changes {
                        indicators.push((*bc).clone());
                    }
                    attacks.push(CorrelatedAttack {
                        attack_type: AttackType::DcImpersonation,
                        confidence: 0.9,
                        indicators,
                        description: alloc::format!(
                            "Possible DC impersonation: '{}' went offline and MAC binding changed",
                            asset_name
                        ),
                    });
                }
            }
        }

        // Look for ARP poisoning pattern:
        // Multiple ARP binding changes from same new MAC
        let mut attacker_ips: hashbrown::HashMap<MacAddress, Vec<[u8; 4]>> = hashbrown::HashMap::new();
        for anomaly in &recent {
            if let AnomalyType::ArpBindingChange { ip, new_mac, .. } = anomaly.anomaly_type {
                attacker_ips.entry(new_mac).or_default().push(ip);
            }
        }

        for (attacker_mac, ips) in attacker_ips {
            if ips.len() >= 2 {
                let indicators: Vec<Anomaly> = recent.iter()
                    .filter(|a| matches!(&a.anomaly_type, AnomalyType::ArpBindingChange { new_mac, .. } if *new_mac == attacker_mac))
                    .map(|a| (*a).clone())
                    .collect();
                attacks.push(CorrelatedAttack {
                    attack_type: AttackType::ArpPoisoning,
                    confidence: 0.8,
                    indicators,
                    description: alloc::format!(
                        "ARP poisoning: MAC {} claiming {} different IPs",
                        attacker_mac, ips.len()
                    ),
                });
            }
        }

        attacks
    }

    /// Get recent anomalies
    pub fn recent(&self) -> &[Anomaly] {
        &self.recent
    }

    /// Get anomalies by severity
    pub fn by_severity(&self, min_severity: AnomalySeverity) -> Vec<&Anomaly> {
        self.recent.iter()
            .filter(|a| a.severity >= min_severity)
            .collect()
    }

    /// Clear old anomalies
    pub fn cleanup(&mut self, timestamp: u64, max_age_secs: u64) {
        let cutoff = timestamp.saturating_sub(max_age_secs);
        self.recent.retain(|a| a.timestamp >= cutoff);
    }
}

#[cfg(feature = "std")]
impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of correlated attack
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    /// DC/critical server impersonation
    DcImpersonation,
    /// ARP cache poisoning
    ArpPoisoning,
    /// MAC flooding
    MacFlooding,
    /// MITM attempt
    ManInTheMiddle,
}

/// A correlated attack (multiple anomalies indicating single attack)
#[derive(Debug, Clone)]
pub struct CorrelatedAttack {
    /// Type of attack
    pub attack_type: AttackType,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Related anomalies
    pub indicators: Vec<Anomaly>,
    /// Human-readable description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(AnomalySeverity::Critical > AnomalySeverity::High);
        assert!(AnomalySeverity::High > AnomalySeverity::Medium);
        assert!(AnomalySeverity::Medium > AnomalySeverity::Low);
        assert!(AnomalySeverity::Low > AnomalySeverity::Info);
    }

    #[test]
    fn test_anomaly_detector_record() {
        let mut detector = AnomalyDetector::new();

        let anomaly = Anomaly {
            anomaly_type: AnomalyType::ArpFlood {
                source_mac: MacAddress::from_array([0; 6]),
                rate: 100,
            },
            severity: AnomalySeverity::High,
            source_mac: None,
            source_ip: None,
            switch_port: None,
            timestamp: 1000,
        };

        detector.record(anomaly);
        assert_eq!(detector.recent().len(), 1);
    }

    #[test]
    fn test_filter_by_severity() {
        let mut detector = AnomalyDetector::new();

        // Add anomalies of different severities
        for (i, severity) in [
            AnomalySeverity::Info,
            AnomalySeverity::Low,
            AnomalySeverity::Medium,
            AnomalySeverity::High,
            AnomalySeverity::Critical,
        ].iter().enumerate() {
            detector.record(Anomaly {
                anomaly_type: AnomalyType::ArpFlood {
                    source_mac: MacAddress::from_array([0; 6]),
                    rate: 100,
                },
                severity: *severity,
                source_mac: None,
                source_ip: None,
                switch_port: None,
                timestamp: i as u64 * 1000,
            });
        }

        assert_eq!(detector.by_severity(AnomalySeverity::Critical).len(), 1);
        assert_eq!(detector.by_severity(AnomalySeverity::High).len(), 2);
        assert_eq!(detector.by_severity(AnomalySeverity::Medium).len(), 3);
    }
}
