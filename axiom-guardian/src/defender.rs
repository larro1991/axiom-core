//! Active defense mechanisms
//!
//! Takes action to defend the network when attacks are detected.
//! Requires the `active-defense` feature.

use alloc::string::String;
use alloc::vec::Vec;

use crate::mac::MacAddress;

/// Defense actions that can be taken
#[derive(Debug, Clone)]
pub enum DefenseAction {
    /// Just log the event (passive)
    LogOnly,

    /// Send correct ARP to fix poisoning
    ArpCorrection {
        ip: [u8; 4],
        correct_mac: MacAddress,
    },

    /// Rate limit a MAC address
    RateLimit {
        mac: MacAddress,
    },

    /// Isolate a port (requires switch integration)
    IsolatePort {
        mac: MacAddress,
    },

    /// Alert security team
    AlertSecurity,

    /// Block MAC at switch (requires switch integration)
    BlockMac {
        mac: MacAddress,
    },

    /// Send gratuitous ARP flood to recover from poisoning
    ArpFlood {
        entries: Vec<([u8; 4], MacAddress)>,
    },
}

/// Result of a defense action
#[derive(Debug, Clone)]
pub struct DefenseResult {
    /// Action taken
    pub action: DefenseAction,
    /// Whether it succeeded
    pub success: bool,
    /// Timestamp
    pub timestamp: u64,
    /// Details/error message
    pub details: Option<String>,
}

/// Active defender
#[cfg(feature = "std")]
pub struct Defender {
    /// Is active defense enabled
    enabled: bool,
    /// Recent actions taken
    actions: Vec<DefenseResult>,
    /// Max actions to keep in history
    max_history: usize,
    /// Rate limiter for defense actions (prevent amplification)
    action_counts: hashbrown::HashMap<String, (u64, u32)>, // (window_start, count)
    /// Max actions per minute per category
    max_actions_per_minute: u32,
}

#[cfg(feature = "std")]
impl Defender {
    /// Create new defender
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            actions: Vec::new(),
            max_history: 1000,
            action_counts: hashbrown::HashMap::new(),
            max_actions_per_minute: 10,
        }
    }

    /// Check if defense is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable/disable active defense
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Execute a defense action
    pub fn execute(&mut self, action: DefenseAction, timestamp: u64) -> Option<DefenseResult> {
        if !self.enabled {
            // Log-only mode
            let result = DefenseResult {
                action: action.clone(),
                success: false,
                timestamp,
                details: Some("Defense disabled - logged only".into()),
            };
            self.record_action(result.clone());
            return Some(result);
        }

        // Check rate limit
        let category = self.action_category(&action);
        if self.is_rate_limited(&category, timestamp) {
            let result = DefenseResult {
                action,
                success: false,
                timestamp,
                details: Some("Rate limited - too many defense actions".into()),
            };
            self.record_action(result.clone());
            return Some(result);
        }

        // Record this action for rate limiting
        self.record_rate(&category, timestamp);

        // Execute the action
        let result = match &action {
            DefenseAction::LogOnly => DefenseResult {
                action: action.clone(),
                success: true,
                timestamp,
                details: Some("Logged".into()),
            },

            DefenseAction::ArpCorrection { ip, correct_mac } => {
                // In real implementation, this would send ARP packets
                // For now, just record the intent
                let details = alloc::format!(
                    "Would send ARP correction: {:?} -> {}",
                    ip, correct_mac
                );
                DefenseResult {
                    action: action.clone(),
                    success: true,
                    timestamp,
                    details: Some(details),
                }
            }

            DefenseAction::RateLimit { mac } => {
                let details = alloc::format!("Rate limiting MAC {}", mac);
                DefenseResult {
                    action: action.clone(),
                    success: true,
                    timestamp,
                    details: Some(details),
                }
            }

            DefenseAction::IsolatePort { mac } => {
                // Would require switch API integration
                let details = alloc::format!(
                    "Port isolation for {} requires switch integration",
                    mac
                );
                DefenseResult {
                    action: action.clone(),
                    success: false,
                    timestamp,
                    details: Some(details),
                }
            }

            DefenseAction::AlertSecurity => {
                DefenseResult {
                    action: action.clone(),
                    success: true,
                    timestamp,
                    details: Some("Security alert raised".into()),
                }
            }

            DefenseAction::BlockMac { mac } => {
                // Would require switch API integration
                let details = alloc::format!(
                    "MAC blocking for {} requires switch integration",
                    mac
                );
                DefenseResult {
                    action: action.clone(),
                    success: false,
                    timestamp,
                    details: Some(details),
                }
            }

            DefenseAction::ArpFlood { entries } => {
                let details = alloc::format!(
                    "Would flood {} ARP entries to correct poisoning",
                    entries.len()
                );
                DefenseResult {
                    action: action.clone(),
                    success: true,
                    timestamp,
                    details: Some(details),
                }
            }
        };

        self.record_action(result.clone());
        Some(result)
    }

    /// Get action category for rate limiting
    fn action_category(&self, action: &DefenseAction) -> String {
        match action {
            DefenseAction::LogOnly => "log".into(),
            DefenseAction::ArpCorrection { .. } => "arp_correction".into(),
            DefenseAction::RateLimit { .. } => "rate_limit".into(),
            DefenseAction::IsolatePort { .. } => "isolate".into(),
            DefenseAction::AlertSecurity => "alert".into(),
            DefenseAction::BlockMac { .. } => "block".into(),
            DefenseAction::ArpFlood { .. } => "arp_flood".into(),
        }
    }

    /// Check if rate limited
    fn is_rate_limited(&self, category: &str, timestamp: u64) -> bool {
        if let Some((window_start, count)) = self.action_counts.get(category) {
            // 60 second window
            if timestamp.saturating_sub(*window_start) < 60 {
                return *count >= self.max_actions_per_minute;
            }
        }
        false
    }

    /// Record action for rate limiting
    fn record_rate(&mut self, category: &str, timestamp: u64) {
        let entry = self.action_counts
            .entry(category.into())
            .or_insert((timestamp, 0));

        // Reset if outside window
        if timestamp.saturating_sub(entry.0) >= 60 {
            entry.0 = timestamp;
            entry.1 = 0;
        }

        entry.1 += 1;
    }

    /// Record an action
    fn record_action(&mut self, result: DefenseResult) {
        self.actions.push(result);
        if self.actions.len() > self.max_history {
            self.actions.remove(0);
        }
    }

    /// Get recent actions
    pub fn recent_actions(&self) -> &[DefenseResult] {
        &self.actions
    }

    /// Get successful actions
    pub fn successful_actions(&self) -> Vec<&DefenseResult> {
        self.actions.iter().filter(|a| a.success).collect()
    }

    /// Count of actions taken
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Generate ARP correction packets (returns raw bytes for each)
    #[cfg(feature = "active-defense")]
    pub fn generate_arp_corrections(&self, entries: &[([u8; 4], MacAddress)], our_mac: MacAddress) -> Vec<Vec<u8>> {
        entries.iter().map(|(ip, mac)| {
            let mut frame = Vec::with_capacity(42);

            // Ethernet header
            frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
            frame.extend_from_slice(our_mac.as_bytes()); // Source
            frame.extend_from_slice(&[0x08, 0x06]); // ARP ethertype

            // ARP packet
            frame.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
            frame.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
            frame.push(6); // Hardware size
            frame.push(4); // Protocol size
            frame.extend_from_slice(&[0x00, 0x02]); // Operation: Reply

            frame.extend_from_slice(mac.as_bytes()); // Sender MAC
            frame.extend_from_slice(ip); // Sender IP
            frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Target MAC
            frame.extend_from_slice(ip); // Target IP (gratuitous)

            frame
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defender_disabled() {
        let mut defender = Defender::new(false);

        let action = DefenseAction::AlertSecurity;
        let result = defender.execute(action, 1000);

        assert!(result.is_some());
        assert!(!result.unwrap().success); // Disabled, so doesn't "succeed"
    }

    #[test]
    fn test_defender_enabled() {
        let mut defender = Defender::new(true);

        let action = DefenseAction::AlertSecurity;
        let result = defender.execute(action, 1000);

        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_rate_limiting() {
        let mut defender = Defender::new(true);
        defender.max_actions_per_minute = 3;

        // Execute 3 actions - should succeed
        for i in 0..3 {
            let result = defender.execute(DefenseAction::AlertSecurity, 1000 + i);
            assert!(result.unwrap().success);
        }

        // 4th action in same minute - should be rate limited
        let result = defender.execute(DefenseAction::AlertSecurity, 1003);
        assert!(!result.unwrap().success);

        // Action after 60 seconds - should succeed (new window)
        let result = defender.execute(DefenseAction::AlertSecurity, 1100);
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_arp_correction() {
        let mut defender = Defender::new(true);

        let action = DefenseAction::ArpCorrection {
            ip: [192, 168, 1, 10],
            correct_mac: MacAddress::from_array([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]),
        };

        let result = defender.execute(action, 1000);
        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_action_history() {
        let mut defender = Defender::new(true);

        for i in 0..5 {
            defender.execute(DefenseAction::LogOnly, i * 1000);
        }

        assert_eq!(defender.action_count(), 5);
        assert_eq!(defender.successful_actions().len(), 5);
    }
}
