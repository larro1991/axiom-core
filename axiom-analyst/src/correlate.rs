//! Event correlation engine
//!
//! Links related events based on time, entity, and behavioral patterns.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{SecurityEvent, Timeline};

/// Correlation rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationRule {
    /// Same source entity
    SameSource,
    /// Same target entity
    SameTarget,
    /// Source to target relationship
    SourceToTarget,
    /// Same event type
    SameEventType,
    /// Same kill chain phase
    SameKillChainPhase,
    /// Sequential kill chain phases
    SequentialPhases,
    /// Temporal proximity
    TemporalProximity,
}

/// Result of correlation
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    /// Rule that matched
    pub rule: CorrelationRule,
    /// Related event IDs
    pub event_ids: Vec<u64>,
    /// Confidence (0.0-1.0)
    pub confidence: f64,
    /// Description
    pub description: String,
}

/// Event correlator
#[cfg(feature = "std")]
pub struct Correlator {
    /// Time window for correlation (seconds)
    time_window: u64,
    /// Correlation group counter
    group_counter: u64,
    /// Active rules
    rules: Vec<CorrelationRule>,
}

#[cfg(feature = "std")]
impl Correlator {
    /// Create new correlator
    pub fn new(time_window: u64) -> Self {
        Self {
            time_window,
            group_counter: 0,
            rules: vec![
                CorrelationRule::SameSource,
                CorrelationRule::SourceToTarget,
                CorrelationRule::SequentialPhases,
                CorrelationRule::TemporalProximity,
            ],
        }
    }

    /// Correlate event with timeline
    pub fn correlate(
        &mut self,
        event: &SecurityEvent,
        timeline: &Timeline,
    ) -> Vec<CorrelationResult> {
        let mut results = Vec::new();
        let window_start = event.timestamp.saturating_sub(self.time_window * 1000);

        // Get events in time window
        let recent_events = timeline.events_in_range(window_start, event.timestamp);

        // Clone rules to avoid borrow issue
        let rules = self.rules.clone();
        for rule in rules {
            if let Some(result) = self.apply_rule(rule, event, &recent_events) {
                results.push(result);
            }
        }

        results
    }

    /// Apply a correlation rule
    fn apply_rule(
        &mut self,
        rule: CorrelationRule,
        event: &SecurityEvent,
        candidates: &[&crate::timeline::TimelineEvent],
    ) -> Option<CorrelationResult> {
        match rule {
            CorrelationRule::SameSource => {
                let source = event.source.as_ref()?;
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        e.event.source.as_ref() == Some(source) &&
                        e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if matches.len() >= 2 {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.7,
                        description: alloc::format!(
                            "Multiple events from same source: {}",
                            source.identifier
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::SameTarget => {
                let target = event.target.as_ref()?;
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        e.event.target.as_ref() == Some(target) &&
                        e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if matches.len() >= 2 {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.6,
                        description: alloc::format!(
                            "Multiple events targeting: {}",
                            target.identifier
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::SourceToTarget => {
                let source = event.source.as_ref()?;
                // Find events where current source was previously a target
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        e.event.target.as_ref() == Some(source) &&
                        e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if !matches.is_empty() {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.8,
                        description: alloc::format!(
                            "Source {} was previously targeted (pivot)",
                            source.identifier
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::SameEventType => {
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        e.event.event_type == event.event_type &&
                        e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if matches.len() >= 3 {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.5,
                        description: alloc::format!(
                            "Multiple {:?} events",
                            event.event_type
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::SameKillChainPhase => {
                let phase = event.kill_chain_phase?;
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        e.event.kill_chain_phase == Some(phase) &&
                        e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if matches.len() >= 2 {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.6,
                        description: alloc::format!(
                            "Multiple events in {} phase",
                            phase.name()
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::SequentialPhases => {
                let current_phase = event.kill_chain_phase?;
                let source = event.source.as_ref()?;

                // Look for earlier phases from same source
                let prior_phases: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        if let (Some(phase), Some(src)) = (e.event.kill_chain_phase, e.event.source.as_ref()) {
                            phase < current_phase && src == source
                        } else {
                            false
                        }
                    })
                    .map(|e| e.event.id)
                    .collect();

                if !prior_phases.is_empty() {
                    Some(CorrelationResult {
                        rule,
                        event_ids: prior_phases,
                        confidence: 0.9,
                        description: alloc::format!(
                            "Kill chain progression detected for {}",
                            source.identifier
                        ),
                    })
                } else {
                    None
                }
            }

            CorrelationRule::TemporalProximity => {
                // Events within very close time proximity (< 5 seconds)
                let matches: Vec<u64> = candidates
                    .iter()
                    .filter(|e| {
                        let time_diff = if e.event.timestamp > event.timestamp {
                            e.event.timestamp - event.timestamp
                        } else {
                            event.timestamp - e.event.timestamp
                        };
                        time_diff < 5000 && e.event.id != event.id
                    })
                    .map(|e| e.event.id)
                    .collect();

                if matches.len() >= 3 {
                    Some(CorrelationResult {
                        rule,
                        event_ids: matches,
                        confidence: 0.4,
                        description: "Burst of activity in short timeframe".into(),
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Get next correlation group ID
    pub fn next_group_id(&mut self) -> u64 {
        self.group_counter += 1;
        self.group_counter
    }

    /// Cleanup (nothing to clean currently)
    pub fn cleanup(&mut self, _timestamp: u64) {
        // Nothing to clean - correlator is stateless
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventType, Entity};

    fn make_event(id: u64, timestamp: u64, source_ip: [u8; 4]) -> SecurityEvent {
        SecurityEvent {
            id,
            timestamp,
            event_type: EventType::NetworkAnomaly,
            severity: 50,
            description: "Test".into(),
            source: Some(Entity::from_ip(source_ip)),
            target: None,
            kill_chain_phase: None,
            evidence: Vec::new(),
            related_events: Vec::new(),
        }
    }

    #[test]
    fn test_same_source_correlation() {
        let mut correlator = Correlator::new(300);
        let mut timeline = Timeline::new(3600);

        let source = [192, 168, 1, 10];
        timeline.add_event(make_event(1, 1000, source));
        timeline.add_event(make_event(2, 2000, source));
        timeline.add_event(make_event(3, 3000, source));

        let event = make_event(4, 4000, source);
        let results = correlator.correlate(&event, &timeline);

        assert!(!results.is_empty());
        let same_source = results.iter().find(|r| r.rule == CorrelationRule::SameSource);
        assert!(same_source.is_some());
    }

    #[test]
    fn test_correlator_creation() {
        let correlator = Correlator::new(300);
        assert!(!correlator.rules.is_empty());
    }
}
