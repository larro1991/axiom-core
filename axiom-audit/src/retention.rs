//! Data retention policies
//!
//! Manages data lifecycle according to regulatory requirements.

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::sensitivity::Sensitivity;

/// Action to take when retention period expires
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionAction {
    /// Delete data permanently
    Delete,
    /// Archive to cold storage
    Archive,
    /// Anonymize/de-identify
    Anonymize,
    /// Flag for review
    Review,
    /// No action (manual handling required)
    Manual,
}

/// A retention policy
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Policy name
    pub name: String,
    /// Sensitivity levels this applies to
    pub applies_to: Vec<Sensitivity>,
    /// Minimum retention period (days)
    pub min_days: u32,
    /// Maximum retention period (days, None = forever)
    pub max_days: Option<u32>,
    /// Action when min period expires
    pub on_min_expire: RetentionAction,
    /// Action when max period expires
    pub on_max_expire: RetentionAction,
    /// Legal hold override
    pub legal_hold_exempt: bool,
}

impl RetentionPolicy {
    /// Create HIPAA-compliant PHI policy
    pub fn hipaa_phi() -> Self {
        Self {
            name: "HIPAA PHI Retention".into(),
            applies_to: vec![Sensitivity::Phi],
            min_days: 2190, // 6 years
            max_days: None, // No max for medical records
            on_min_expire: RetentionAction::Archive,
            on_max_expire: RetentionAction::Manual,
            legal_hold_exempt: false,
        }
    }

    /// Create GDPR-compliant PII policy
    pub fn gdpr_pii() -> Self {
        Self {
            name: "GDPR PII Retention".into(),
            applies_to: vec![Sensitivity::Pii],
            min_days: 0,    // No minimum (data minimization)
            max_days: Some(1095), // 3 years typical
            on_min_expire: RetentionAction::Review,
            on_max_expire: RetentionAction::Delete,
            legal_hold_exempt: false,
        }
    }

    /// Create audit log retention policy
    pub fn audit_logs() -> Self {
        Self {
            name: "Audit Log Retention".into(),
            applies_to: vec![
                Sensitivity::Public,
                Sensitivity::Internal,
                Sensitivity::Confidential,
                Sensitivity::Phi,
                Sensitivity::Pii,
                Sensitivity::Restricted,
            ],
            min_days: 2555, // 7 years (SOX, financial)
            max_days: None,
            on_min_expire: RetentionAction::Archive,
            on_max_expire: RetentionAction::Manual,
            legal_hold_exempt: false,
        }
    }

    /// Check if policy applies to given sensitivity
    pub fn applies(&self, sensitivity: Sensitivity) -> bool {
        self.applies_to.contains(&sensitivity)
    }

    /// Get retention status for data created at given timestamp
    pub fn status(&self, created_at: u64, now: u64) -> RetentionStatus {
        let age_days = ((now - created_at) / 86400) as u32;

        if let Some(max) = self.max_days {
            if age_days >= max {
                return RetentionStatus::Expired {
                    action: self.on_max_expire,
                    days_over: age_days - max,
                };
            }
        }

        if age_days >= self.min_days {
            return RetentionStatus::PastMinimum {
                action: self.on_min_expire,
                days_over: age_days - self.min_days,
            };
        }

        RetentionStatus::Active {
            days_remaining: self.min_days - age_days,
        }
    }
}

/// Current retention status
#[derive(Debug, Clone)]
pub enum RetentionStatus {
    /// Data is within retention period
    Active {
        /// Days until minimum retention reached
        days_remaining: u32,
    },
    /// Past minimum retention, action available
    PastMinimum {
        /// Recommended action
        action: RetentionAction,
        /// Days past minimum
        days_over: u32,
    },
    /// Past maximum retention, action required
    Expired {
        /// Required action
        action: RetentionAction,
        /// Days past maximum
        days_over: u32,
    },
}

/// Tracks data lifecycle events
#[derive(Debug, Clone)]
pub struct DataLifecycle {
    /// Data identifier
    pub data_id: [u8; 32],
    /// Creation timestamp
    pub created_at: u64,
    /// Sensitivity at creation
    pub sensitivity: Sensitivity,
    /// Applied policy name
    pub policy: String,
    /// Legal hold flag
    pub legal_hold: bool,
    /// Lifecycle events
    pub events: Vec<LifecycleEvent>,
}

/// A lifecycle event
#[derive(Debug, Clone)]
pub struct LifecycleEvent {
    /// Event timestamp
    pub timestamp: u64,
    /// Event type
    pub event_type: LifecycleEventType,
    /// Event details
    pub details: String,
    /// Who triggered this
    pub triggered_by: Option<[u8; 32]>,
}

/// Types of lifecycle events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEventType {
    /// Data created
    Created,
    /// Data accessed
    Accessed,
    /// Data modified
    Modified,
    /// Data archived
    Archived,
    /// Data restored from archive
    Restored,
    /// Data anonymized
    Anonymized,
    /// Data deleted
    Deleted,
    /// Legal hold applied
    LegalHoldApplied,
    /// Legal hold released
    LegalHoldReleased,
    /// Retention review completed
    ReviewCompleted,
}

impl DataLifecycle {
    /// Create new lifecycle tracker
    pub fn new(
        data_id: [u8; 32],
        sensitivity: Sensitivity,
        policy: String,
        now: u64,
    ) -> Self {
        let mut lifecycle = Self {
            data_id,
            created_at: now,
            sensitivity,
            policy,
            legal_hold: false,
            events: Vec::new(),
        };

        lifecycle.add_event(LifecycleEventType::Created, "Data created".into(), None, now);
        lifecycle
    }

    /// Add a lifecycle event
    pub fn add_event(
        &mut self,
        event_type: LifecycleEventType,
        details: String,
        triggered_by: Option<[u8; 32]>,
        timestamp: u64,
    ) {
        self.events.push(LifecycleEvent {
            timestamp,
            event_type,
            details,
            triggered_by,
        });
    }

    /// Apply legal hold
    pub fn apply_legal_hold(&mut self, reason: String, by: [u8; 32], now: u64) {
        if !self.legal_hold {
            self.legal_hold = true;
            self.add_event(
                LifecycleEventType::LegalHoldApplied,
                reason,
                Some(by),
                now,
            );
        }
    }

    /// Release legal hold
    pub fn release_legal_hold(&mut self, reason: String, by: [u8; 32], now: u64) {
        if self.legal_hold {
            self.legal_hold = false;
            self.add_event(
                LifecycleEventType::LegalHoldReleased,
                reason,
                Some(by),
                now,
            );
        }
    }

    /// Check if data can be deleted
    pub fn can_delete(&self, policy: &RetentionPolicy, now: u64) -> bool {
        if self.legal_hold {
            return false;
        }

        match policy.status(self.created_at, now) {
            RetentionStatus::Active { .. } => false,
            RetentionStatus::PastMinimum { action, .. } => action == RetentionAction::Delete,
            RetentionStatus::Expired { action, .. } => action == RetentionAction::Delete,
        }
    }

    /// Get data age in days
    pub fn age_days(&self, now: u64) -> u32 {
        ((now - self.created_at) / 86400) as u32
    }
}

/// Manages retention policies and data lifecycle
#[cfg(feature = "std")]
pub struct RetentionManager {
    /// Policies by name
    policies: HashMap<String, RetentionPolicy>,
    /// Default policy by sensitivity
    default_policies: HashMap<Sensitivity, String>,
    /// Tracked data lifecycles
    lifecycles: HashMap<[u8; 32], DataLifecycle>,
}

#[cfg(feature = "std")]
impl RetentionManager {
    /// Create with default policies
    pub fn new() -> Self {
        let mut mgr = Self {
            policies: HashMap::new(),
            default_policies: HashMap::new(),
            lifecycles: HashMap::new(),
        };

        // Add default policies
        let hipaa = RetentionPolicy::hipaa_phi();
        mgr.default_policies.insert(Sensitivity::Phi, hipaa.name.clone());
        mgr.policies.insert(hipaa.name.clone(), hipaa);

        let gdpr = RetentionPolicy::gdpr_pii();
        mgr.default_policies.insert(Sensitivity::Pii, gdpr.name.clone());
        mgr.policies.insert(gdpr.name.clone(), gdpr);

        let audit = RetentionPolicy::audit_logs();
        mgr.policies.insert(audit.name.clone(), audit);

        mgr
    }

    /// Add a custom policy
    pub fn add_policy(&mut self, policy: RetentionPolicy) {
        self.policies.insert(policy.name.clone(), policy);
    }

    /// Set default policy for sensitivity level
    pub fn set_default(&mut self, sensitivity: Sensitivity, policy_name: &str) {
        if self.policies.contains_key(policy_name) {
            self.default_policies.insert(sensitivity, policy_name.into());
        }
    }

    /// Get policy for sensitivity
    pub fn get_policy(&self, sensitivity: Sensitivity) -> Option<&RetentionPolicy> {
        self.default_policies
            .get(&sensitivity)
            .and_then(|name| self.policies.get(name))
    }

    /// Track new data
    pub fn track(&mut self, data_id: [u8; 32], sensitivity: Sensitivity, now: u64) {
        let policy_name = self
            .default_policies
            .get(&sensitivity)
            .cloned()
            .unwrap_or_else(|| "default".into());

        let lifecycle = DataLifecycle::new(data_id, sensitivity, policy_name, now);
        self.lifecycles.insert(data_id, lifecycle);
    }

    /// Get lifecycle for data
    pub fn get_lifecycle(&self, data_id: &[u8; 32]) -> Option<&DataLifecycle> {
        self.lifecycles.get(data_id)
    }

    /// Get mutable lifecycle
    pub fn get_lifecycle_mut(&mut self, data_id: &[u8; 32]) -> Option<&mut DataLifecycle> {
        self.lifecycles.get_mut(data_id)
    }

    /// Find data ready for action
    pub fn find_actionable(&self, now: u64) -> Vec<(&[u8; 32], RetentionAction)> {
        let mut results = Vec::new();

        for (id, lifecycle) in &self.lifecycles {
            if lifecycle.legal_hold {
                continue;
            }

            if let Some(policy) = self.get_policy(lifecycle.sensitivity) {
                match policy.status(lifecycle.created_at, now) {
                    RetentionStatus::Expired { action, .. } => {
                        results.push((id, action));
                    }
                    _ => {}
                }
            }
        }

        results
    }
}

#[cfg(feature = "std")]
impl Default for RetentionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hipaa_policy() {
        let policy = RetentionPolicy::hipaa_phi();
        assert_eq!(policy.min_days, 2190); // 6 years
        assert!(policy.applies(Sensitivity::Phi));
        assert!(!policy.applies(Sensitivity::Public));
    }

    #[test]
    fn test_retention_status() {
        let policy = RetentionPolicy::hipaa_phi();
        let created = 0u64;

        // Day 100 - active
        let now = 100 * 86400;
        match policy.status(created, now) {
            RetentionStatus::Active { days_remaining } => {
                assert_eq!(days_remaining, 2090);
            }
            _ => panic!("Expected Active status"),
        }

        // Day 3000 - past minimum
        let now = 3000 * 86400;
        match policy.status(created, now) {
            RetentionStatus::PastMinimum { days_over, .. } => {
                assert_eq!(days_over, 810);
            }
            _ => panic!("Expected PastMinimum status"),
        }
    }

    #[test]
    fn test_legal_hold() {
        let mut lifecycle = DataLifecycle::new(
            [1u8; 32],
            Sensitivity::Phi,
            "HIPAA".into(),
            0,
        );

        let policy = RetentionPolicy::hipaa_phi();

        // Even past retention, legal hold prevents deletion
        lifecycle.apply_legal_hold("Litigation".into(), [2u8; 32], 1000);
        assert!(!lifecycle.can_delete(&policy, 10000 * 86400));

        // After release, deletion possible
        lifecycle.release_legal_hold("Case closed".into(), [2u8; 32], 2000);
        assert!(lifecycle.legal_hold == false);
    }
}
