//! Response actions
//!
//! Defines the actions that can be taken in response to incidents.

use alloc::string::String;
use alloc::vec::Vec;

/// Action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    /// Log the event
    LogEvent,
    /// Alert security team
    AlertSecurity,
    /// Rate limit a host
    RateLimit,
    /// Isolate a host
    IsolateHost,
    /// Block a connection
    BlockConnection,
    /// Block a MAC address
    BlockMac,
    /// Send ARP correction
    ArpCorrection,
    /// Kill a session
    KillSession,
    /// Quarantine a device
    Quarantine,
    /// Run a script/command
    RunScript,
    /// Create a ticket
    CreateTicket,
    /// Send notification
    Notify,
}

impl ActionType {
    /// Get action name
    pub fn name(&self) -> &'static str {
        match self {
            ActionType::LogEvent => "Log Event",
            ActionType::AlertSecurity => "Alert Security",
            ActionType::RateLimit => "Rate Limit",
            ActionType::IsolateHost => "Isolate Host",
            ActionType::BlockConnection => "Block Connection",
            ActionType::BlockMac => "Block MAC",
            ActionType::ArpCorrection => "ARP Correction",
            ActionType::KillSession => "Kill Session",
            ActionType::Quarantine => "Quarantine",
            ActionType::RunScript => "Run Script",
            ActionType::CreateTicket => "Create Ticket",
            ActionType::Notify => "Notify",
        }
    }

    /// Get action risk level (0-10)
    pub fn risk_level(&self) -> u8 {
        match self {
            ActionType::LogEvent => 0,
            ActionType::AlertSecurity => 1,
            ActionType::Notify => 1,
            ActionType::CreateTicket => 2,
            ActionType::RateLimit => 4,
            ActionType::ArpCorrection => 5,
            ActionType::BlockConnection => 6,
            ActionType::KillSession => 7,
            ActionType::BlockMac => 8,
            ActionType::IsolateHost => 9,
            ActionType::Quarantine => 9,
            ActionType::RunScript => 10,
        }
    }

    /// Requires approval?
    pub fn requires_approval(&self) -> bool {
        self.risk_level() >= 7
    }
}

/// Action status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    /// Pending execution
    Pending,
    /// Waiting for approval
    AwaitingApproval,
    /// Currently executing
    Executing,
    /// Completed successfully
    Success,
    /// Failed
    Failed,
    /// Skipped (dry run)
    Skipped,
}

/// A response action
#[derive(Debug, Clone)]
pub struct ResponseAction {
    /// Action ID
    pub id: u64,
    /// Action type
    pub action_type: ActionType,
    /// Target (IP, MAC, etc.)
    pub target: Option<String>,
    /// Parameters
    pub parameters: Vec<(String, String)>,
    /// Description
    pub description: String,
    /// Related incident ID
    pub incident_id: Option<u64>,
}

impl ResponseAction {
    /// Create new action
    pub fn new(action_type: ActionType) -> Self {
        Self {
            id: 0,
            action_type,
            target: None,
            parameters: Vec::new(),
            description: String::new(),
            incident_id: None,
        }
    }

    /// Set target
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    /// Add parameter
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.parameters.push((key, value));
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    /// Get parameter value
    pub fn get_param(&self, key: &str) -> Option<&String> {
        self.parameters.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

/// Result of an action
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Action ID
    pub action_id: u64,
    /// Action type
    pub action_type: ActionType,
    /// Status
    pub status: ActionStatus,
    /// Timestamp
    pub timestamp: u64,
    /// Message
    pub message: String,
    /// Details
    pub details: Vec<String>,
}

impl ActionResult {
    /// Create success result
    pub fn success(action: &ResponseAction, timestamp: u64, message: String) -> Self {
        Self {
            action_id: action.id,
            action_type: action.action_type,
            status: ActionStatus::Success,
            timestamp,
            message,
            details: Vec::new(),
        }
    }

    /// Create failure result
    pub fn failure(action: &ResponseAction, timestamp: u64, message: String) -> Self {
        Self {
            action_id: action.id,
            action_type: action.action_type,
            status: ActionStatus::Failed,
            timestamp,
            message,
            details: Vec::new(),
        }
    }

    /// Create skipped result (dry run)
    pub fn skipped(action: &ResponseAction, timestamp: u64) -> Self {
        Self {
            action_id: action.id,
            action_type: action.action_type,
            status: ActionStatus::Skipped,
            timestamp,
            message: "Skipped (dry run mode)".into(),
            details: Vec::new(),
        }
    }

    /// Add detail
    pub fn with_detail(mut self, detail: String) -> Self {
        self.details.push(detail);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_properties() {
        assert_eq!(ActionType::LogEvent.risk_level(), 0);
        assert!(ActionType::IsolateHost.requires_approval());
        assert!(!ActionType::AlertSecurity.requires_approval());
    }

    #[test]
    fn test_action_creation() {
        let action = ResponseAction::new(ActionType::RateLimit)
            .with_target("192.168.1.10".into())
            .with_param("rate".into(), "100kbps".into());

        assert_eq!(action.action_type, ActionType::RateLimit);
        assert_eq!(action.target, Some("192.168.1.10".into()));
        assert_eq!(action.get_param("rate"), Some(&"100kbps".into()));
    }

    #[test]
    fn test_action_result() {
        let action = ResponseAction::new(ActionType::AlertSecurity);
        let result = ActionResult::success(&action, 1000, "Alert sent".into());

        assert_eq!(result.status, ActionStatus::Success);
    }
}
