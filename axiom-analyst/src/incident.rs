//! Incident management
//!
//! Creates and manages security incidents from detected attacks.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{AttackChain, SecurityEvent, Entity, killchain::KillChainPhase};

/// Incident severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    /// Informational
    Info = 0,
    /// Low
    Low = 1,
    /// Medium
    Medium = 2,
    /// High
    High = 3,
    /// Critical
    Critical = 4,
}

impl IncidentSeverity {
    /// From numeric score
    pub fn from_score(score: f64) -> Self {
        match score as u8 {
            0..=20 => IncidentSeverity::Info,
            21..=40 => IncidentSeverity::Low,
            41..=60 => IncidentSeverity::Medium,
            61..=80 => IncidentSeverity::High,
            _ => IncidentSeverity::Critical,
        }
    }
}

/// Incident status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    /// New incident
    New,
    /// Under investigation
    Investigating,
    /// Contained
    Contained,
    /// Resolved
    Resolved,
    /// False positive
    FalsePositive,
}

/// A security incident
#[derive(Debug, Clone)]
pub struct Incident {
    /// Incident ID
    pub id: u64,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: IncidentSeverity,
    /// Status
    pub status: IncidentStatus,
    /// Threat score (0-100)
    pub threat_score: f64,
    /// Confidence (0.0-1.0)
    pub confidence: f64,
    /// Affected entities
    pub affected_entities: Vec<Entity>,
    /// Attacker entities
    pub attacker_entities: Vec<Entity>,
    /// Related event IDs
    pub event_ids: Vec<u64>,
    /// Kill chain phases involved
    pub kill_chain_phases: Vec<KillChainPhase>,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated
    pub updated_at: u64,
    /// Response actions taken
    pub actions: Vec<String>,
    /// Notes
    pub notes: Vec<String>,
}

impl Incident {
    /// Create new incident
    pub fn new(id: u64, title: String, severity: IncidentSeverity, timestamp: u64) -> Self {
        Self {
            id,
            title,
            description: String::new(),
            severity,
            status: IncidentStatus::New,
            threat_score: 0.0,
            confidence: 0.0,
            affected_entities: Vec::new(),
            attacker_entities: Vec::new(),
            event_ids: Vec::new(),
            kill_chain_phases: Vec::new(),
            created_at: timestamp,
            updated_at: timestamp,
            actions: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Add affected entity
    pub fn add_affected(&mut self, entity: Entity) {
        if !self.affected_entities.contains(&entity) {
            self.affected_entities.push(entity);
        }
    }

    /// Add attacker entity
    pub fn add_attacker(&mut self, entity: Entity) {
        if !self.attacker_entities.contains(&entity) {
            self.attacker_entities.push(entity);
        }
    }

    /// Add event
    pub fn add_event(&mut self, event_id: u64) {
        if !self.event_ids.contains(&event_id) {
            self.event_ids.push(event_id);
        }
    }

    /// Add kill chain phase
    pub fn add_phase(&mut self, phase: KillChainPhase) {
        if !self.kill_chain_phases.contains(&phase) {
            self.kill_chain_phases.push(phase);
            self.kill_chain_phases.sort();
        }
    }

    /// Add action
    pub fn add_action(&mut self, action: String, timestamp: u64) {
        self.actions.push(action);
        self.updated_at = timestamp;
    }

    /// Add note
    pub fn add_note(&mut self, note: String, timestamp: u64) {
        self.notes.push(note);
        self.updated_at = timestamp;
    }

    /// Update status
    pub fn set_status(&mut self, status: IncidentStatus, timestamp: u64) {
        self.status = status;
        self.updated_at = timestamp;
    }

    /// Is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, IncidentStatus::New | IncidentStatus::Investigating)
    }
}

/// Incident manager
#[cfg(feature = "std")]
pub struct IncidentManager {
    /// All incidents
    incidents: Vec<Incident>,
    /// Max incidents
    max_incidents: usize,
    /// Incident counter
    incident_counter: u64,
}

#[cfg(feature = "std")]
impl IncidentManager {
    /// Create new manager
    pub fn new(max_incidents: usize) -> Self {
        Self {
            incidents: Vec::new(),
            max_incidents,
            incident_counter: 0,
        }
    }

    /// Create incident from attack chain
    pub fn create_from_chain(&mut self, chain: &AttackChain, timestamp: u64) -> Incident {
        self.incident_counter += 1;

        let severity = IncidentSeverity::from_score(chain.threat_score);

        let title = if let Some(ref attacker) = chain.attacker {
            alloc::format!("Attack chain from {}", attacker.identifier)
        } else {
            "Multi-stage attack detected".into()
        };

        let mut incident = Incident::new(self.incident_counter, title, severity, timestamp);
        incident.threat_score = chain.threat_score;
        incident.confidence = chain.confidence;
        incident.description = chain.description.clone();

        // Add entities
        if let Some(ref attacker) = chain.attacker {
            incident.add_attacker(attacker.clone());
        }
        if let Some(ref target) = chain.target {
            incident.add_affected(target.clone());
        }

        // Add events and phases
        for event_id in chain.all_event_ids() {
            incident.add_event(event_id);
        }
        for stage in &chain.stages {
            incident.add_phase(stage.phase);
        }

        self.add_incident(incident.clone());
        incident
    }

    /// Create incident from single event
    pub fn create_from_event(&mut self, event: &SecurityEvent) -> Incident {
        self.incident_counter += 1;

        let severity = IncidentSeverity::from_score(event.severity as f64);

        let mut incident = Incident::new(
            self.incident_counter,
            event.description.clone(),
            severity,
            event.timestamp,
        );
        incident.threat_score = event.severity as f64;
        incident.confidence = 0.8;

        if let Some(ref source) = event.source {
            incident.add_attacker(source.clone());
        }
        if let Some(ref target) = event.target {
            incident.add_affected(target.clone());
        }

        incident.add_event(event.id);

        if let Some(phase) = event.kill_chain_phase {
            incident.add_phase(phase);
        }

        self.add_incident(incident.clone());
        incident
    }

    /// Add incident
    fn add_incident(&mut self, incident: Incident) {
        self.incidents.push(incident);

        // Cleanup if over limit
        if self.incidents.len() > self.max_incidents {
            // Remove oldest resolved incident
            if let Some(pos) = self.incidents.iter().position(|i| !i.is_active()) {
                self.incidents.remove(pos);
            } else {
                // Remove oldest incident
                self.incidents.remove(0);
            }
        }
    }

    /// Get incident by ID
    pub fn get(&self, id: u64) -> Option<&Incident> {
        self.incidents.iter().find(|i| i.id == id)
    }

    /// Get mutable incident by ID
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Incident> {
        self.incidents.iter_mut().find(|i| i.id == id)
    }

    /// Get active incidents
    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incidents.iter().filter(|i| i.is_active()).collect()
    }

    /// Get active count
    pub fn active_count(&self) -> usize {
        self.incidents.iter().filter(|i| i.is_active()).count()
    }

    /// Get total count
    pub fn total_count(&self) -> u64 {
        self.incident_counter
    }

    /// Cleanup old incidents
    pub fn cleanup(&mut self, timestamp: u64) {
        // Keep incidents for at least 24 hours
        let cutoff = timestamp.saturating_sub(86400 * 1000);
        self.incidents.retain(|i| {
            i.is_active() || i.updated_at >= cutoff
        });
    }

    /// Get incidents by severity
    pub fn by_severity(&self, min_severity: IncidentSeverity) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| i.severity >= min_severity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(1, "Test".into(), IncidentSeverity::High, 1000);
        assert_eq!(incident.id, 1);
        assert!(incident.is_active());
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(IncidentSeverity::from_score(10.0), IncidentSeverity::Info);
        assert_eq!(IncidentSeverity::from_score(50.0), IncidentSeverity::Medium);
        assert_eq!(IncidentSeverity::from_score(90.0), IncidentSeverity::Critical);
    }

    #[test]
    fn test_incident_manager() {
        let mut manager = IncidentManager::new(100);

        let mut chain = AttackChain::new(1);
        chain.threat_score = 80.0;
        chain.confidence = 0.9;
        chain.description = "Test attack".into();

        let incident = manager.create_from_chain(&chain, 1000);
        assert_eq!(incident.severity, IncidentSeverity::High);
        assert_eq!(manager.active_count(), 1);
    }
}
