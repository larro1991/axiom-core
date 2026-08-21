//! AXIOM Responder - Automated Incident Response
//!
//! Provides automated response capabilities for detected security incidents.
//!
//! # Features
//!
//! - **Playbooks**: Pre-defined response workflows
//! - **Response Actions**: Containment, isolation, remediation
//! - **Integration**: Works with network infrastructure
//! - **Audit Trail**: Logs all response actions
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                       AXIOM RESPONDER                            │
//! ├──────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
//! │  │  Incidents   │  │  Playbooks   │  │    Response Engine     │ │
//! │  │  (from       │  │              │  │                        │ │
//! │  │   Analyst)   │  │              │  │                        │ │
//! │  └──────┬───────┘  └──────┬───────┘  └────────────┬───────────┘ │
//! │         │                 │                        │             │
//! │         └─────────────────┼────────────────────────┘             │
//! │                           ▼                                      │
//! │                  ┌────────────────┐                             │
//! │                  │ Action Router  │                             │
//! │                  └────────┬───────┘                             │
//! │                           │                                     │
//! │         ┌─────────────────┼─────────────────┐                   │
//! │         ▼                 ▼                 ▼                   │
//! │  ┌────────────┐  ┌──────────────┐  ┌──────────────┐            │
//! │  │  Network   │  │    Host      │  │   Alert/     │            │
//! │  │  Actions   │  │   Actions    │  │   Notify     │            │
//! │  └────────────┘  └──────────────┘  └──────────────┘            │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod action;
pub mod playbook;
pub mod executor;

use alloc::boxed::Box;
use alloc::vec::Vec;

pub use action::{ResponseAction, ActionType, ActionResult, ActionStatus};
pub use playbook::{Playbook, PlaybookStep, PlaybookTrigger};
#[cfg(feature = "std")]
pub use executor::{Executor, ExecutionResult};

use axiom_analyst::{Incident, IncidentSeverity, killchain::KillChainPhase};

/// Responder configuration
#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// Enable automatic response
    pub auto_response: bool,
    /// Minimum severity for auto-response
    pub auto_response_min_severity: IncidentSeverity,
    /// Maximum concurrent actions
    pub max_concurrent_actions: usize,
    /// Action timeout (seconds)
    pub action_timeout: u64,
    /// Dry run mode (log but don't execute)
    pub dry_run: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            auto_response: false, // Disabled by default for safety
            auto_response_min_severity: IncidentSeverity::High,
            max_concurrent_actions: 10,
            action_timeout: 60,
            dry_run: true, // Dry run by default
        }
    }
}

/// Responder statistics
#[derive(Debug, Clone, Default)]
pub struct ResponderStats {
    /// Actions executed
    pub actions_executed: u64,
    /// Actions succeeded
    pub actions_succeeded: u64,
    /// Actions failed
    pub actions_failed: u64,
    /// Incidents responded to
    pub incidents_responded: u64,
    /// Playbooks executed
    pub playbooks_executed: u64,
}

/// Response handler callback
pub type ResponseHandler = Box<dyn Fn(&ActionResult) + Send + Sync>;

/// The automated responder
#[cfg(feature = "std")]
pub struct Responder {
    config: ResponderConfig,
    playbooks: Vec<Playbook>,
    executor: Executor,
    stats: ResponderStats,
    action_handler: Option<ResponseHandler>,
}

#[cfg(feature = "std")]
impl Responder {
    /// Create new responder
    pub fn new(config: ResponderConfig) -> Self {
        let dry_run = config.dry_run;
        Self {
            executor: Executor::new(dry_run),
            config,
            playbooks: Vec::new(),
            stats: ResponderStats::default(),
            action_handler: None,
        }
    }

    /// Add a playbook
    pub fn add_playbook(&mut self, playbook: Playbook) {
        self.playbooks.push(playbook);
    }

    /// Set action handler
    pub fn with_action_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&ActionResult) + Send + Sync + 'static,
    {
        self.action_handler = Some(Box::new(handler));
        self
    }

    /// Respond to an incident
    pub fn respond(&mut self, incident: &Incident, timestamp: u64) -> Vec<ActionResult> {
        let mut results = Vec::new();

        // Check if we should auto-respond
        if !self.config.auto_response && !self.config.dry_run {
            return results;
        }

        if incident.severity < self.config.auto_response_min_severity {
            return results;
        }

        // Find matching playbooks - clone to avoid borrow issues
        let matching_playbooks: Vec<Playbook> = self.playbooks
            .iter()
            .filter(|p| p.matches(incident))
            .cloned()
            .collect();

        for playbook in &matching_playbooks {
            let playbook_results = self.execute_playbook(playbook, incident, timestamp);
            results.extend(playbook_results);
            self.stats.playbooks_executed += 1;
        }

        // If no playbook matched, execute default actions based on severity
        if results.is_empty() {
            results = self.execute_default_response(incident, timestamp);
        }

        self.stats.incidents_responded += 1;
        results
    }

    /// Execute a playbook
    fn execute_playbook(
        &mut self,
        playbook: &Playbook,
        incident: &Incident,
        timestamp: u64,
    ) -> Vec<ActionResult> {
        let mut results = Vec::new();

        for step in &playbook.steps {
            let action = self.build_action_from_step(step, incident, timestamp);
            let result = self.executor.execute(&action, timestamp);

            self.stats.actions_executed += 1;
            if result.status == ActionStatus::Success {
                self.stats.actions_succeeded += 1;
            } else {
                self.stats.actions_failed += 1;
            }

            if let Some(ref handler) = self.action_handler {
                handler(&result);
            }

            results.push(result);
        }

        results
    }

    /// Build action from playbook step
    fn build_action_from_step(
        &self,
        step: &PlaybookStep,
        incident: &Incident,
        timestamp: u64,
    ) -> ResponseAction {
        ResponseAction {
            id: timestamp, // Use timestamp as action ID
            action_type: step.action_type,
            target: step.target.clone().or_else(|| {
                incident.attacker_entities.first().map(|e| e.identifier.clone())
            }),
            parameters: step.parameters.clone(),
            description: step.description.clone(),
            incident_id: Some(incident.id),
        }
    }

    /// Execute default response based on severity
    fn execute_default_response(
        &mut self,
        incident: &Incident,
        timestamp: u64,
    ) -> Vec<ActionResult> {
        let mut results = Vec::new();

        // Default actions based on severity
        let actions: Vec<ResponseAction> = match incident.severity {
            IncidentSeverity::Critical => vec![
                ResponseAction {
                    id: timestamp,
                    action_type: ActionType::AlertSecurity,
                    target: None,
                    parameters: vec![
                        ("severity".into(), "critical".into()),
                        ("incident_id".into(), alloc::format!("{}", incident.id)),
                    ],
                    description: "Critical security alert".into(),
                    incident_id: Some(incident.id),
                },
                ResponseAction {
                    id: timestamp + 1,
                    action_type: ActionType::IsolateHost,
                    target: incident.attacker_entities.first().map(|e| e.identifier.clone()),
                    parameters: Vec::new(),
                    description: "Isolate attacker host".into(),
                    incident_id: Some(incident.id),
                },
            ],
            IncidentSeverity::High => vec![
                ResponseAction {
                    id: timestamp,
                    action_type: ActionType::AlertSecurity,
                    target: None,
                    parameters: vec![
                        ("severity".into(), "high".into()),
                        ("incident_id".into(), alloc::format!("{}", incident.id)),
                    ],
                    description: "High severity alert".into(),
                    incident_id: Some(incident.id),
                },
                ResponseAction {
                    id: timestamp + 1,
                    action_type: ActionType::RateLimit,
                    target: incident.attacker_entities.first().map(|e| e.identifier.clone()),
                    parameters: Vec::new(),
                    description: "Rate limit suspicious host".into(),
                    incident_id: Some(incident.id),
                },
            ],
            _ => vec![
                ResponseAction {
                    id: timestamp,
                    action_type: ActionType::LogEvent,
                    target: None,
                    parameters: vec![
                        ("incident_id".into(), alloc::format!("{}", incident.id)),
                    ],
                    description: "Log incident for review".into(),
                    incident_id: Some(incident.id),
                },
            ],
        };

        for action in actions {
            let result = self.executor.execute(&action, timestamp);

            self.stats.actions_executed += 1;
            if result.status == ActionStatus::Success {
                self.stats.actions_succeeded += 1;
            } else {
                self.stats.actions_failed += 1;
            }

            if let Some(ref handler) = self.action_handler {
                handler(&result);
            }

            results.push(result);
        }

        results
    }

    /// Get statistics
    pub fn stats(&self) -> &ResponderStats {
        &self.stats
    }

    /// Enable/disable auto-response
    pub fn set_auto_response(&mut self, enabled: bool) {
        self.config.auto_response = enabled;
    }

    /// Set dry run mode
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.config.dry_run = dry_run;
        self.executor.set_dry_run(dry_run);
    }

    /// Create standard playbooks
    pub fn with_standard_playbooks(mut self) -> Self {
        // ARP spoofing response
        self.add_playbook(Playbook {
            name: "ARP Spoofing Response".into(),
            description: "Respond to ARP spoofing attacks".into(),
            trigger: PlaybookTrigger::KillChainPhase(KillChainPhase::LateralMovement),
            min_severity: IncidentSeverity::Medium,
            steps: vec![
                PlaybookStep {
                    action_type: ActionType::AlertSecurity,
                    target: None,
                    parameters: vec![("type".into(), "arp_spoof".into())],
                    description: "Alert on ARP spoofing".into(),
                },
                PlaybookStep {
                    action_type: ActionType::ArpCorrection,
                    target: None,
                    parameters: Vec::new(),
                    description: "Send corrective ARP".into(),
                },
            ],
        });

        // Data exfiltration response
        self.add_playbook(Playbook {
            name: "Data Exfiltration Response".into(),
            description: "Respond to data exfiltration attempts".into(),
            trigger: PlaybookTrigger::KillChainPhase(KillChainPhase::Actions),
            min_severity: IncidentSeverity::High,
            steps: vec![
                PlaybookStep {
                    action_type: ActionType::AlertSecurity,
                    target: None,
                    parameters: vec![("type".into(), "exfiltration".into())],
                    description: "Alert on exfiltration".into(),
                },
                PlaybookStep {
                    action_type: ActionType::BlockConnection,
                    target: None,
                    parameters: Vec::new(),
                    description: "Block exfiltration connection".into(),
                },
                PlaybookStep {
                    action_type: ActionType::IsolateHost,
                    target: None,
                    parameters: Vec::new(),
                    description: "Isolate compromised host".into(),
                },
            ],
        });

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_creation() {
        let config = ResponderConfig::default();
        let responder = Responder::new(config);
        assert_eq!(responder.stats.actions_executed, 0);
    }

    #[test]
    fn test_config_defaults() {
        let config = ResponderConfig::default();
        assert!(!config.auto_response);
        assert!(config.dry_run);
    }
}
