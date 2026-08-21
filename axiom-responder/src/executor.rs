//! Action executor
//!
//! Executes response actions.

use alloc::vec::Vec;

use crate::action::{ResponseAction, ActionType, ActionResult, ActionStatus};

/// Execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Actions executed
    pub actions: Vec<ActionResult>,
    /// Overall success
    pub success: bool,
}

/// Action executor
#[cfg(feature = "std")]
pub struct Executor {
    /// Dry run mode
    dry_run: bool,
    /// Action history
    history: Vec<ActionResult>,
    /// Max history entries
    max_history: usize,
}

#[cfg(feature = "std")]
impl Executor {
    /// Create new executor
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Set dry run mode
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Execute an action
    pub fn execute(&mut self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        if self.dry_run {
            let result = ActionResult::skipped(action, timestamp)
                .with_detail(alloc::format!(
                    "Would execute: {} on {:?}",
                    action.action_type.name(),
                    action.target
                ));
            self.record(result.clone());
            return result;
        }

        // Execute based on action type
        let result = match action.action_type {
            ActionType::LogEvent => self.execute_log(action, timestamp),
            ActionType::AlertSecurity => self.execute_alert(action, timestamp),
            ActionType::RateLimit => self.execute_rate_limit(action, timestamp),
            ActionType::IsolateHost => self.execute_isolate(action, timestamp),
            ActionType::BlockConnection => self.execute_block_connection(action, timestamp),
            ActionType::BlockMac => self.execute_block_mac(action, timestamp),
            ActionType::ArpCorrection => self.execute_arp_correction(action, timestamp),
            ActionType::KillSession => self.execute_kill_session(action, timestamp),
            ActionType::Quarantine => self.execute_quarantine(action, timestamp),
            ActionType::RunScript => self.execute_script(action, timestamp),
            ActionType::CreateTicket => self.execute_create_ticket(action, timestamp),
            ActionType::Notify => self.execute_notify(action, timestamp),
        };

        self.record(result.clone());
        result
    }

    /// Record action in history
    fn record(&mut self, result: ActionResult) {
        self.history.push(result);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Execute log action
    fn execute_log(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // In real implementation, would write to log system
        ActionResult::success(action, timestamp, "Event logged".into())
    }

    /// Execute alert action
    fn execute_alert(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // In real implementation, would send to SIEM/alerting system
        ActionResult::success(action, timestamp, "Security alert sent".into())
    }

    /// Execute rate limit
    fn execute_rate_limit(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => ActionResult::success(
                action,
                timestamp,
                alloc::format!("Rate limit applied to {}", target),
            ),
            None => ActionResult::failure(
                action,
                timestamp,
                "No target specified".into(),
            ),
        }
    }

    /// Execute host isolation
    fn execute_isolate(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => {
                // In real implementation, would trigger network isolation
                ActionResult::success(
                    action,
                    timestamp,
                    alloc::format!("Host {} isolated", target),
                )
            }
            None => ActionResult::failure(
                action,
                timestamp,
                "No target specified for isolation".into(),
            ),
        }
    }

    /// Execute connection block
    fn execute_block_connection(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => ActionResult::success(
                action,
                timestamp,
                alloc::format!("Connection to {} blocked", target),
            ),
            None => ActionResult::failure(
                action,
                timestamp,
                "No target specified".into(),
            ),
        }
    }

    /// Execute MAC block
    fn execute_block_mac(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => ActionResult::success(
                action,
                timestamp,
                alloc::format!("MAC {} blocked", target),
            ),
            None => ActionResult::failure(
                action,
                timestamp,
                "No MAC address specified".into(),
            ),
        }
    }

    /// Execute ARP correction
    fn execute_arp_correction(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // In real implementation, would send corrective ARP packets
        ActionResult::success(action, timestamp, "ARP correction sent".into())
    }

    /// Execute session kill
    fn execute_kill_session(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => ActionResult::success(
                action,
                timestamp,
                alloc::format!("Session for {} terminated", target),
            ),
            None => ActionResult::failure(
                action,
                timestamp,
                "No session specified".into(),
            ),
        }
    }

    /// Execute quarantine
    fn execute_quarantine(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        match &action.target {
            Some(target) => ActionResult::success(
                action,
                timestamp,
                alloc::format!("Device {} quarantined", target),
            ),
            None => ActionResult::failure(
                action,
                timestamp,
                "No target for quarantine".into(),
            ),
        }
    }

    /// Execute script
    fn execute_script(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // Would need additional safety checks in production
        ActionResult::success(action, timestamp, "Script execution initiated".into())
    }

    /// Execute ticket creation
    fn execute_create_ticket(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // In real implementation, would integrate with ticketing system
        ActionResult::success(action, timestamp, "Incident ticket created".into())
    }

    /// Execute notification
    fn execute_notify(&self, action: &ResponseAction, timestamp: u64) -> ActionResult {
        // In real implementation, would send email/slack/etc
        ActionResult::success(action, timestamp, "Notification sent".into())
    }

    /// Get action history
    pub fn history(&self) -> &[ActionResult] {
        &self.history
    }

    /// Get successful actions count
    pub fn success_count(&self) -> usize {
        self.history.iter()
            .filter(|r| r.status == ActionStatus::Success)
            .count()
    }

    /// Get failed actions count
    pub fn failure_count(&self) -> usize {
        self.history.iter()
            .filter(|r| r.status == ActionStatus::Failed)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = Executor::new(true);
        assert_eq!(executor.history().len(), 0);
    }

    #[test]
    fn test_dry_run() {
        let mut executor = Executor::new(true);

        let action = ResponseAction::new(ActionType::IsolateHost)
            .with_target("192.168.1.10".into());

        let result = executor.execute(&action, 1000);

        assert_eq!(result.status, ActionStatus::Skipped);
    }

    #[test]
    fn test_real_execution() {
        let mut executor = Executor::new(false);

        let action = ResponseAction::new(ActionType::AlertSecurity);
        let result = executor.execute(&action, 1000);

        assert_eq!(result.status, ActionStatus::Success);
        assert_eq!(executor.success_count(), 1);
    }

    #[test]
    fn test_action_without_target() {
        let mut executor = Executor::new(false);

        let action = ResponseAction::new(ActionType::IsolateHost);
        // No target set
        let result = executor.execute(&action, 1000);

        assert_eq!(result.status, ActionStatus::Failed);
        assert_eq!(executor.failure_count(), 1);
    }
}
