//! Audit event types
//!
//! Defines all auditable events in the system.

use alloc::string::String;
use alloc::vec::Vec;
use crate::sensitivity::Sensitivity;

/// Type of audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Data access (read/write/delete)
    Access,
    /// Authentication event
    Authentication,
    /// Authorization decision
    Authorization,
    /// Configuration change
    ConfigChange,
    /// Security event (threat, impersonation)
    Security,
    /// System event (boot, shutdown)
    System,
    /// Network event (connection, disconnection)
    Network,
    /// Key management event
    KeyManagement,
    /// Data lifecycle event (retention, purge)
    DataLifecycle,
    /// Compliance event (report, audit)
    Compliance,
}

/// Type of data access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessType {
    /// Read/view data
    Read,
    /// Create new data
    Create,
    /// Modify existing data
    Update,
    /// Delete data
    Delete,
    /// Export/download data
    Export,
    /// Print data
    Print,
    /// Transmit to external system
    Transmit,
    /// Query/search (may reveal existence)
    Query,
}

/// Outcome of an access attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessOutcome {
    /// Access granted and completed
    Success,
    /// Access denied - insufficient privileges
    DeniedPrivilege,
    /// Access denied - data not found
    DeniedNotFound,
    /// Access denied - policy violation
    DeniedPolicy,
    /// Access denied - rate limited
    DeniedRateLimit,
    /// Access failed - error
    Failed,
    /// Access pending approval
    Pending,
}

impl AccessOutcome {
    /// Was access successful?
    pub fn is_success(&self) -> bool {
        *self == AccessOutcome::Success
    }

    /// Was access denied?
    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            AccessOutcome::DeniedPrivilege
                | AccessOutcome::DeniedNotFound
                | AccessOutcome::DeniedPolicy
                | AccessOutcome::DeniedRateLimit
        )
    }

    /// Is this a security-relevant denial?
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            AccessOutcome::DeniedPrivilege | AccessOutcome::DeniedPolicy
        )
    }
}

/// Authentication method used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// Cryptographic signature (Ed25519)
    Signature,
    /// Pre-shared key
    PreSharedKey,
    /// Certificate-based
    Certificate,
    /// Multi-factor
    MultiFactor,
    /// Delegated (via trusted node)
    Delegated,
    /// Anonymous (no auth)
    Anonymous,
}

/// Security event subtype
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    /// Failed authentication attempt
    AuthFailure,
    /// Brute force detected
    BruteForce,
    /// Identity impersonation detected
    Impersonation,
    /// Privilege escalation attempt
    PrivilegeEscalation,
    /// Anomalous behavior detected
    Anomaly,
    /// Malformed packet/request
    Malformed,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Trust level changed
    TrustChange,
}

/// A complete audit event
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Event type
    pub event_type: EventType,
    /// Timestamp (microseconds since epoch)
    pub timestamp: u64,
    /// Subject (who performed the action) - NodeId bytes
    pub subject: [u8; 32],
    /// Resource (what was accessed) - hash or ID
    pub resource: Option<[u8; 32]>,
    /// Action details
    pub action: String,
    /// Outcome
    pub outcome: AccessOutcome,
    /// Data sensitivity (if applicable)
    pub sensitivity: Option<Sensitivity>,
    /// Source location (IP, NodeId, etc.)
    pub source_location: Option<String>,
    /// Additional context
    pub context: Vec<(String, String)>,
}

impl AuditEvent {
    /// Create an access event
    pub fn access(
        subject: [u8; 32],
        resource: [u8; 32],
        access_type: AccessType,
        outcome: AccessOutcome,
        sensitivity: Sensitivity,
        timestamp: u64,
    ) -> Self {
        Self {
            event_type: EventType::Access,
            timestamp,
            subject,
            resource: Some(resource),
            action: alloc::format!("{:?}", access_type),
            outcome,
            sensitivity: Some(sensitivity),
            source_location: None,
            context: Vec::new(),
        }
    }

    /// Create an authentication event
    pub fn authentication(
        subject: [u8; 32],
        method: AuthMethod,
        success: bool,
        timestamp: u64,
    ) -> Self {
        Self {
            event_type: EventType::Authentication,
            timestamp,
            subject,
            resource: None,
            action: alloc::format!("{:?}", method),
            outcome: if success {
                AccessOutcome::Success
            } else {
                AccessOutcome::DeniedPrivilege
            },
            sensitivity: None,
            source_location: None,
            context: Vec::new(),
        }
    }

    /// Create a security event
    pub fn security(
        subject: [u8; 32],
        security_type: SecurityEventType,
        details: String,
        timestamp: u64,
    ) -> Self {
        Self {
            event_type: EventType::Security,
            timestamp,
            subject,
            resource: None,
            action: alloc::format!("{:?}", security_type),
            outcome: AccessOutcome::Failed,
            sensitivity: None,
            source_location: None,
            context: vec![("details".into(), details)],
        }
    }

    /// Create a system event
    pub fn system(action: &str, details: String, timestamp: u64) -> Self {
        Self {
            event_type: EventType::System,
            timestamp,
            subject: [0u8; 32], // System itself
            resource: None,
            action: action.into(),
            outcome: AccessOutcome::Success,
            sensitivity: None,
            source_location: None,
            context: vec![("details".into(), details)],
        }
    }

    /// Create a key management event
    pub fn key_event(
        subject: [u8; 32],
        action: &str,
        key_id: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            event_type: EventType::KeyManagement,
            timestamp,
            subject,
            resource: Some(key_id),
            action: action.into(),
            outcome: AccessOutcome::Success,
            sensitivity: Some(Sensitivity::Restricted),
            source_location: None,
            context: Vec::new(),
        }
    }

    /// Add source location
    pub fn with_source(mut self, location: String) -> Self {
        self.source_location = Some(location);
        self
    }

    /// Add context key-value pair
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }

    /// Check if this event should trigger an alert
    pub fn is_alertable(&self) -> bool {
        match self.event_type {
            EventType::Security => true,
            EventType::Authentication if self.outcome.is_denied() => true,
            EventType::Access if self.outcome.is_security_relevant() => true,
            EventType::KeyManagement => true,
            _ => false,
        }
    }

    /// Get HIPAA-relevant event description
    pub fn hipaa_description(&self) -> String {
        match self.event_type {
            EventType::Access => {
                let sens = self
                    .sensitivity
                    .map(|s| alloc::format!("{:?}", s))
                    .unwrap_or_else(|| "Unknown".into());
                alloc::format!(
                    "Access {} to {} data: {:?}",
                    self.action, sens, self.outcome
                )
            }
            EventType::Authentication => {
                alloc::format!("Authentication via {}: {:?}", self.action, self.outcome)
            }
            EventType::Security => {
                alloc::format!("Security event: {}", self.action)
            }
            _ => alloc::format!("{:?}: {}", self.event_type, self.action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_event() {
        let subject = [1u8; 32];
        let resource = [2u8; 32];
        let event = AuditEvent::access(
            subject,
            resource,
            AccessType::Read,
            AccessOutcome::Success,
            Sensitivity::Phi,
            1000,
        );

        assert_eq!(event.event_type, EventType::Access);
        assert_eq!(event.sensitivity, Some(Sensitivity::Phi));
        assert!(!event.is_alertable()); // Success is not alertable
    }

    #[test]
    fn test_security_event_alertable() {
        let subject = [1u8; 32];
        let event = AuditEvent::security(
            subject,
            SecurityEventType::Impersonation,
            "Self-impersonation detected".into(),
            1000,
        );

        assert!(event.is_alertable());
    }

    #[test]
    fn test_denied_access_alertable() {
        let subject = [1u8; 32];
        let resource = [2u8; 32];
        let event = AuditEvent::access(
            subject,
            resource,
            AccessType::Read,
            AccessOutcome::DeniedPrivilege,
            Sensitivity::Phi,
            1000,
        );

        assert!(event.is_alertable());
    }
}
