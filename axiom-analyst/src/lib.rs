//! AXIOM Analyst - Security Event Correlation Engine
//!
//! Correlates events from multiple sources to detect complex attack patterns.
//!
//! # Features
//!
//! - **Event Correlation**: Links related events across time windows
//! - **Attack Chain Detection**: Identifies multi-stage attacks
//! - **Kill Chain Mapping**: Maps activity to cyber kill chain phases
//! - **Threat Scoring**: Calculates composite threat scores
//! - **Alert Aggregation**: Reduces alert fatigue through smart grouping
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                       AXIOM ANALYST                              │
//! ├──────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
//! │  │  Guardian    │  │   Watcher    │  │    External Feeds      │ │
//! │  │  Events      │  │   Events     │  │    (Threat Intel)      │ │
//! │  └──────┬───────┘  └──────┬───────┘  └────────────┬───────────┘ │
//! │         │                 │                        │             │
//! │         └─────────────────┼────────────────────────┘             │
//! │                           ▼                                      │
//! │                 ┌──────────────────┐                            │
//! │                 │  Event Ingester  │                            │
//! │                 └────────┬─────────┘                            │
//! │                          │                                      │
//! │         ┌────────────────┼────────────────┐                     │
//! │         ▼                ▼                ▼                     │
//! │  ┌────────────┐  ┌─────────────┐  ┌─────────────┐              │
//! │  │ Temporal   │  │  Entity     │  │  Pattern    │              │
//! │  │ Correlator │  │  Resolver   │  │  Matcher    │              │
//! │  └─────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
//! │        │                │                │                      │
//! │        └────────────────┼────────────────┘                      │
//! │                         ▼                                       │
//! │              ┌──────────────────┐                               │
//! │              │  Attack Detector │                               │
//! │              └────────┬─────────┘                               │
//! │                       │                                         │
//! │         ┌─────────────┼─────────────┐                          │
//! │         ▼             ▼             ▼                          │
//! │  ┌───────────┐  ┌───────────┐  ┌───────────┐                   │
//! │  │ Incidents │  │  Reports  │  │  Actions  │                   │
//! │  └───────────┘  └───────────┘  └───────────┘                   │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod attack;
pub mod correlate;
pub mod entity;
pub mod incident;
pub mod killchain;
pub mod timeline;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use attack::{AttackChain, AttackStage, AttackDetector};
pub use correlate::{Correlator, CorrelationResult, CorrelationRule};
pub use entity::{Entity, EntityType, EntityResolver};
pub use incident::{Incident, IncidentSeverity, IncidentManager};
pub use killchain::{KillChainPhase, KillChainMapper};
pub use timeline::{Timeline, TimelineEvent};

use axiom_guardian::detector::{Anomaly, AnomalySeverity};
use axiom_watcher::{WatcherAlert, WatcherAlertType};

/// Analyst configuration
#[derive(Debug, Clone)]
pub struct AnalystConfig {
    /// Event retention window (seconds)
    pub retention_window: u64,
    /// Correlation time window (seconds)
    pub correlation_window: u64,
    /// Minimum events for attack chain
    pub min_chain_events: usize,
    /// Alert aggregation window (seconds)
    pub aggregation_window: u64,
    /// Threat score threshold for incident
    pub incident_threshold: f64,
    /// Maximum incidents to track
    pub max_incidents: usize,
}

impl Default for AnalystConfig {
    fn default() -> Self {
        Self {
            retention_window: 3600,     // 1 hour
            correlation_window: 300,    // 5 minutes
            min_chain_events: 3,
            aggregation_window: 60,     // 1 minute
            incident_threshold: 70.0,
            max_incidents: 1000,
        }
    }
}

/// Analyst statistics
#[derive(Debug, Clone, Default)]
pub struct AnalystStats {
    /// Events processed
    pub events_processed: u64,
    /// Correlations found
    pub correlations_found: u64,
    /// Attack chains detected
    pub attack_chains_detected: u64,
    /// Active incidents
    pub active_incidents: usize,
    /// Total incidents
    pub total_incidents: u64,
}

/// Unified event from any source
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Event ID
    pub id: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Event type
    pub event_type: EventType,
    /// Severity (0-100)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Source entity
    pub source: Option<Entity>,
    /// Target entity
    pub target: Option<Entity>,
    /// Kill chain phase
    pub kill_chain_phase: Option<KillChainPhase>,
    /// Evidence/details
    pub evidence: Vec<String>,
    /// Related event IDs
    pub related_events: Vec<u64>,
}

/// Event type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Network layer anomaly
    NetworkAnomaly,
    /// Layer 2 attack
    Layer2Attack,
    /// Layer 3-7 anomaly
    TrafficAnomaly,
    /// Behavioral deviation
    BehaviorDeviation,
    /// Protocol anomaly
    ProtocolAnomaly,
    /// Covert channel
    CovertChannel,
    /// Port scan
    PortScan,
    /// Lateral movement
    LateralMovement,
    /// Data exfiltration
    DataExfiltration,
    /// Credential attack
    CredentialAttack,
    /// Impersonation
    Impersonation,
}

impl SecurityEvent {
    /// Create event from Guardian anomaly
    pub fn from_anomaly(anomaly: &Anomaly, event_id: u64) -> Self {
        use axiom_guardian::detector::AnomalyType;

        let (event_type, kill_chain) = match &anomaly.anomaly_type {
            AnomalyType::MacPortChange { .. } => (EventType::Layer2Attack, Some(KillChainPhase::LateralMovement)),
            AnomalyType::ArpBindingChange { .. } => (EventType::Layer2Attack, Some(KillChainPhase::LateralMovement)),
            AnomalyType::ArpFlood { .. } => (EventType::Layer2Attack, Some(KillChainPhase::Actions)),
            AnomalyType::CriticalAssetOffline { .. } => (EventType::NetworkAnomaly, Some(KillChainPhase::Actions)),
            AnomalyType::CriticalAssetImpersonation { .. } => (EventType::Impersonation, Some(KillChainPhase::LateralMovement)),
            AnomalyType::DuplicateMac { .. } => (EventType::Layer2Attack, Some(KillChainPhase::LateralMovement)),
            AnomalyType::GratuitousArpSpam { .. } => (EventType::Layer2Attack, Some(KillChainPhase::Installation)),
        };

        let severity = match anomaly.severity {
            AnomalySeverity::Critical => 95,
            AnomalySeverity::High => 75,
            AnomalySeverity::Medium => 50,
            AnomalySeverity::Low => 25,
            AnomalySeverity::Info => 10,
        };

        let source = anomaly.source_mac.map(|mac| Entity::from_mac(mac.as_bytes()));

        Self {
            id: event_id,
            timestamp: anomaly.timestamp,
            event_type,
            severity,
            description: alloc::format!("{:?}", anomaly.anomaly_type),
            source,
            target: anomaly.source_ip.map(Entity::from_ip),
            kill_chain_phase: kill_chain,
            evidence: Vec::new(),
            related_events: Vec::new(),
        }
    }

    /// Create event from Watcher alert
    pub fn from_watcher_alert(alert: &WatcherAlert, event_id: u64) -> Self {
        let (event_type, kill_chain) = match alert.alert_type {
            WatcherAlertType::TrafficAnomaly => (EventType::TrafficAnomaly, None),
            WatcherAlertType::BehaviorDeviation => (EventType::BehaviorDeviation, Some(KillChainPhase::Actions)),
            WatcherAlertType::CovertChannel => (EventType::CovertChannel, Some(KillChainPhase::CommandAndControl)),
            WatcherAlertType::NewHost => (EventType::NetworkAnomaly, Some(KillChainPhase::Delivery)),
            WatcherAlertType::HostBehaviorChange => (EventType::BehaviorDeviation, Some(KillChainPhase::Installation)),
            WatcherAlertType::ProtocolAnomaly => (EventType::ProtocolAnomaly, None),
            WatcherAlertType::DataExfiltration => (EventType::DataExfiltration, Some(KillChainPhase::Actions)),
            WatcherAlertType::LateralMovement => (EventType::LateralMovement, Some(KillChainPhase::LateralMovement)),
            WatcherAlertType::PortScan => (EventType::PortScan, Some(KillChainPhase::Reconnaissance)),
            WatcherAlertType::UnusualConnection => (EventType::NetworkAnomaly, Some(KillChainPhase::CommandAndControl)),
        };

        let source = alert.source_ip.map(Entity::from_ip);
        let target = alert.dest_ip.map(Entity::from_ip);

        Self {
            id: event_id,
            timestamp: alert.timestamp,
            event_type,
            severity: alert.severity,
            description: alert.description.clone(),
            source,
            target,
            kill_chain_phase: kill_chain,
            evidence: alert.evidence.clone(),
            related_events: Vec::new(),
        }
    }
}

/// The security analyst engine
#[cfg(feature = "std")]
pub struct Analyst {
    config: AnalystConfig,
    correlator: Correlator,
    entity_resolver: EntityResolver,
    attack_detector: AttackDetector,
    kill_chain_mapper: KillChainMapper,
    incident_manager: IncidentManager,
    timeline: Timeline,
    stats: AnalystStats,
    event_counter: u64,
    incident_handler: Option<Box<dyn Fn(&Incident) + Send + Sync>>,
}

#[cfg(feature = "std")]
impl Analyst {
    /// Create new analyst
    pub fn new(config: AnalystConfig) -> Self {
        let retention_window = config.retention_window;
        let max_incidents = config.max_incidents;

        Self {
            correlator: Correlator::new(config.correlation_window),
            entity_resolver: EntityResolver::new(),
            attack_detector: AttackDetector::new(config.min_chain_events),
            kill_chain_mapper: KillChainMapper::new(),
            incident_manager: IncidentManager::new(max_incidents),
            timeline: Timeline::new(retention_window),
            config,
            stats: AnalystStats::default(),
            event_counter: 0,
            incident_handler: None,
        }
    }

    /// Set incident handler
    pub fn with_incident_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&Incident) + Send + Sync + 'static,
    {
        self.incident_handler = Some(Box::new(handler));
        self
    }

    /// Process a Guardian anomaly
    pub fn process_anomaly(&mut self, anomaly: &Anomaly) -> Vec<Incident> {
        self.event_counter += 1;
        let event = SecurityEvent::from_anomaly(anomaly, self.event_counter);
        self.process_event(event)
    }

    /// Process a Watcher alert
    pub fn process_watcher_alert(&mut self, alert: &WatcherAlert) -> Vec<Incident> {
        self.event_counter += 1;
        let event = SecurityEvent::from_watcher_alert(alert, self.event_counter);
        self.process_event(event)
    }

    /// Process a security event
    pub fn process_event(&mut self, event: SecurityEvent) -> Vec<Incident> {
        self.stats.events_processed += 1;
        let timestamp = event.timestamp;

        // Add to timeline
        self.timeline.add_event(event.clone());

        // Resolve entities
        if let Some(ref source) = event.source {
            self.entity_resolver.observe_entity(source.clone(), timestamp);
        }
        if let Some(ref target) = event.target {
            self.entity_resolver.observe_entity(target.clone(), timestamp);
        }

        // Correlate with existing events
        let correlations = self.correlator.correlate(&event, &self.timeline);
        self.stats.correlations_found += correlations.len() as u64;

        // Detect attack chains
        let attack_chains = self.attack_detector.detect(
            &event,
            &correlations,
            &self.timeline,
        );

        // Create incidents from attack chains
        let mut new_incidents = Vec::new();
        for chain in &attack_chains {
            self.stats.attack_chains_detected += 1;

            let incident = self.incident_manager.create_from_chain(chain, timestamp);
            if let Some(ref handler) = self.incident_handler {
                handler(&incident);
            }
            new_incidents.push(incident);
        }

        // Check for high-severity single events
        if attack_chains.is_empty() && event.severity >= self.config.incident_threshold as u8 {
            let incident = self.incident_manager.create_from_event(&event);
            self.stats.total_incidents += 1;
            if let Some(ref handler) = self.incident_handler {
                handler(&incident);
            }
            new_incidents.push(incident);
        }

        self.stats.active_incidents = self.incident_manager.active_count();
        self.stats.total_incidents = self.incident_manager.total_count();

        new_incidents
    }

    /// Get statistics
    pub fn stats(&self) -> &AnalystStats {
        &self.stats
    }

    /// Get timeline
    pub fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// Get active incidents
    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incident_manager.active_incidents()
    }

    /// Get entity info
    pub fn entity_info(&self, entity: &Entity) -> Option<&entity::EntityInfo> {
        self.entity_resolver.get_info(entity)
    }

    /// Cleanup old data
    pub fn cleanup(&mut self, timestamp: u64) {
        self.timeline.cleanup(timestamp);
        self.incident_manager.cleanup(timestamp);
        self.correlator.cleanup(timestamp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyst_creation() {
        let config = AnalystConfig::default();
        let analyst = Analyst::new(config);
        assert_eq!(analyst.stats.events_processed, 0);
    }

    #[test]
    fn test_event_type_classification() {
        assert_ne!(EventType::PortScan, EventType::CovertChannel);
    }
}
