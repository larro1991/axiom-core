//! Response playbooks
//!
//! Pre-defined response workflows for different incident types.

use alloc::string::String;
use alloc::vec::Vec;

use axiom_analyst::{Incident, IncidentSeverity, killchain::KillChainPhase};
use crate::action::ActionType;

/// Playbook trigger condition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaybookTrigger {
    /// Trigger on specific kill chain phase
    KillChainPhase(KillChainPhase),
    /// Trigger on minimum severity
    Severity(IncidentSeverity),
    /// Trigger on incident title match
    TitleContains(String),
    /// Always trigger
    Always,
}

/// A step in a playbook
#[derive(Debug, Clone)]
pub struct PlaybookStep {
    /// Action type
    pub action_type: ActionType,
    /// Target (if fixed, otherwise derived from incident)
    pub target: Option<String>,
    /// Parameters
    pub parameters: Vec<(String, String)>,
    /// Description
    pub description: String,
}

impl PlaybookStep {
    /// Create new step
    pub fn new(action_type: ActionType, description: &str) -> Self {
        Self {
            action_type,
            target: None,
            parameters: Vec::new(),
            description: description.into(),
        }
    }

    /// With target
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = Some(target.into());
        self
    }

    /// With parameter
    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        self.parameters.push((key.into(), value.into()));
        self
    }
}

/// A response playbook
#[derive(Debug, Clone)]
pub struct Playbook {
    /// Playbook name
    pub name: String,
    /// Description
    pub description: String,
    /// Trigger condition
    pub trigger: PlaybookTrigger,
    /// Minimum severity to apply
    pub min_severity: IncidentSeverity,
    /// Steps to execute
    pub steps: Vec<PlaybookStep>,
}

impl Playbook {
    /// Create new playbook
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            trigger: PlaybookTrigger::Always,
            min_severity: IncidentSeverity::Info,
            steps: Vec::new(),
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    /// Set trigger
    pub fn with_trigger(mut self, trigger: PlaybookTrigger) -> Self {
        self.trigger = trigger;
        self
    }

    /// Set minimum severity
    pub fn with_min_severity(mut self, severity: IncidentSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Add step
    pub fn add_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Check if playbook matches incident
    pub fn matches(&self, incident: &Incident) -> bool {
        // Check severity
        if incident.severity < self.min_severity {
            return false;
        }

        // Check trigger condition
        match &self.trigger {
            PlaybookTrigger::Always => true,
            PlaybookTrigger::Severity(min) => incident.severity >= *min,
            PlaybookTrigger::KillChainPhase(phase) => {
                incident.kill_chain_phases.contains(phase)
            }
            PlaybookTrigger::TitleContains(pattern) => {
                incident.title.contains(pattern.as_str())
            }
        }
    }
}

/// Pre-built playbooks
#[cfg(feature = "std")]
pub mod prebuilt {
    use super::*;

    /// Create reconnaissance response playbook
    pub fn recon_response() -> Playbook {
        Playbook::new("Reconnaissance Response")
            .with_description("Respond to reconnaissance activity")
            .with_trigger(PlaybookTrigger::KillChainPhase(KillChainPhase::Reconnaissance))
            .with_min_severity(IncidentSeverity::Low)
            .add_step(PlaybookStep::new(ActionType::LogEvent, "Log recon activity"))
            .add_step(PlaybookStep::new(ActionType::AlertSecurity, "Alert on scanning"))
    }

    /// Create lateral movement response playbook
    pub fn lateral_movement_response() -> Playbook {
        Playbook::new("Lateral Movement Response")
            .with_description("Respond to lateral movement")
            .with_trigger(PlaybookTrigger::KillChainPhase(KillChainPhase::LateralMovement))
            .with_min_severity(IncidentSeverity::High)
            .add_step(PlaybookStep::new(ActionType::AlertSecurity, "Alert on lateral movement"))
            .add_step(PlaybookStep::new(ActionType::IsolateHost, "Isolate compromised host"))
    }

    /// Create C2 response playbook
    pub fn c2_response() -> Playbook {
        Playbook::new("C2 Response")
            .with_description("Respond to command and control activity")
            .with_trigger(PlaybookTrigger::KillChainPhase(KillChainPhase::CommandAndControl))
            .with_min_severity(IncidentSeverity::Critical)
            .add_step(PlaybookStep::new(ActionType::AlertSecurity, "Critical C2 alert"))
            .add_step(PlaybookStep::new(ActionType::BlockConnection, "Block C2 connection"))
            .add_step(PlaybookStep::new(ActionType::Quarantine, "Quarantine infected host"))
    }

    /// Create exfiltration response playbook
    pub fn exfil_response() -> Playbook {
        Playbook::new("Data Exfiltration Response")
            .with_description("Respond to data exfiltration")
            .with_trigger(PlaybookTrigger::KillChainPhase(KillChainPhase::Actions))
            .with_min_severity(IncidentSeverity::Critical)
            .add_step(PlaybookStep::new(ActionType::AlertSecurity, "Exfiltration alert"))
            .add_step(PlaybookStep::new(ActionType::BlockConnection, "Block exfiltration"))
            .add_step(PlaybookStep::new(ActionType::IsolateHost, "Isolate source host"))
            .add_step(PlaybookStep::new(ActionType::CreateTicket, "Create IR ticket"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_incident(severity: IncidentSeverity, phases: Vec<KillChainPhase>) -> Incident {
        let mut incident = Incident::new(1, "Test Incident".into(), severity, 1000);
        for phase in phases {
            incident.add_phase(phase);
        }
        incident
    }

    #[test]
    fn test_playbook_creation() {
        let playbook = Playbook::new("Test")
            .with_trigger(PlaybookTrigger::Always)
            .add_step(PlaybookStep::new(ActionType::LogEvent, "Log it"));

        assert_eq!(playbook.steps.len(), 1);
    }

    #[test]
    fn test_playbook_matching() {
        let playbook = Playbook::new("Recon")
            .with_trigger(PlaybookTrigger::KillChainPhase(KillChainPhase::Reconnaissance))
            .with_min_severity(IncidentSeverity::Low);

        let incident1 = make_incident(
            IncidentSeverity::Medium,
            vec![KillChainPhase::Reconnaissance],
        );
        assert!(playbook.matches(&incident1));

        let incident2 = make_incident(
            IncidentSeverity::Medium,
            vec![KillChainPhase::Exploitation],
        );
        assert!(!playbook.matches(&incident2));
    }

    #[test]
    fn test_severity_matching() {
        let playbook = Playbook::new("High Only")
            .with_min_severity(IncidentSeverity::High);

        let high = make_incident(IncidentSeverity::High, vec![]);
        let low = make_incident(IncidentSeverity::Low, vec![]);

        assert!(playbook.matches(&high));
        assert!(!playbook.matches(&low));
    }

    #[test]
    fn test_prebuilt_playbooks() {
        let recon = prebuilt::recon_response();
        assert!(!recon.steps.is_empty());

        let c2 = prebuilt::c2_response();
        assert!(c2.min_severity >= IncidentSeverity::High);
    }
}
