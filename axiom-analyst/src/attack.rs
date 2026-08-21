//! Attack chain detection
//!
//! Identifies multi-stage attacks from correlated events.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{SecurityEvent, Timeline, CorrelationResult, Entity, killchain::KillChainPhase};

/// Attack stage
#[derive(Debug, Clone)]
pub struct AttackStage {
    /// Kill chain phase
    pub phase: KillChainPhase,
    /// Event IDs in this stage
    pub event_ids: Vec<u64>,
    /// First event timestamp
    pub start_time: u64,
    /// Last event timestamp
    pub end_time: u64,
    /// Description
    pub description: String,
}

/// An attack chain (multi-stage attack)
#[derive(Debug, Clone)]
pub struct AttackChain {
    /// Chain ID
    pub id: u64,
    /// Target entity
    pub target: Option<Entity>,
    /// Attacker entity
    pub attacker: Option<Entity>,
    /// Stages
    pub stages: Vec<AttackStage>,
    /// Overall confidence (0.0-1.0)
    pub confidence: f64,
    /// Threat score (0-100)
    pub threat_score: f64,
    /// Description
    pub description: String,
    /// Start time
    pub start_time: u64,
    /// Last activity time
    pub last_activity: u64,
}

impl AttackChain {
    /// Create new attack chain
    pub fn new(id: u64) -> Self {
        Self {
            id,
            target: None,
            attacker: None,
            stages: Vec::new(),
            confidence: 0.0,
            threat_score: 0.0,
            description: String::new(),
            start_time: 0,
            last_activity: 0,
        }
    }

    /// Add a stage
    pub fn add_stage(&mut self, stage: AttackStage) {
        if self.start_time == 0 || stage.start_time < self.start_time {
            self.start_time = stage.start_time;
        }
        if stage.end_time > self.last_activity {
            self.last_activity = stage.end_time;
        }
        self.stages.push(stage);
        self.recalculate_score();
    }

    /// Recalculate threat score
    fn recalculate_score(&mut self) {
        if self.stages.is_empty() {
            self.threat_score = 0.0;
            return;
        }

        // Base score from kill chain coverage
        let phases_covered: f64 = self.stages.iter()
            .map(|s| s.phase.severity_multiplier())
            .sum();

        // Bonus for chain progression
        let chain_bonus = if self.stages.len() >= 3 { 1.5 } else { 1.0 };

        // Calculate final score
        self.threat_score = (phases_covered * 10.0 * chain_bonus).min(100.0);
    }

    /// Get all event IDs
    pub fn all_event_ids(&self) -> Vec<u64> {
        self.stages.iter().flat_map(|s| s.event_ids.iter().copied()).collect()
    }

    /// Duration in milliseconds
    pub fn duration(&self) -> u64 {
        self.last_activity.saturating_sub(self.start_time)
    }
}

/// Attack chain detector
#[cfg(feature = "std")]
pub struct AttackDetector {
    /// Minimum stages for a chain
    min_stages: usize,
    /// Chain counter
    chain_counter: u64,
    /// Active chains being built
    active_chains: Vec<AttackChain>,
}

#[cfg(feature = "std")]
impl AttackDetector {
    /// Create new detector
    pub fn new(min_stages: usize) -> Self {
        Self {
            min_stages,
            chain_counter: 0,
            active_chains: Vec::new(),
        }
    }

    /// Detect attack chains from event and correlations
    pub fn detect(
        &mut self,
        event: &SecurityEvent,
        correlations: &[CorrelationResult],
        timeline: &Timeline,
    ) -> Vec<AttackChain> {
        let mut completed_chains = Vec::new();

        // Look for sequential phase correlation (strongest indicator)
        for correlation in correlations {
            if correlation.rule == crate::CorrelationRule::SequentialPhases {
                // Build attack chain from correlated events
                if let Some(chain) = self.build_chain_from_correlation(event, correlation, timeline) {
                    if chain.stages.len() >= self.min_stages {
                        completed_chains.push(chain);
                    } else {
                        // Store for potential future completion
                        self.active_chains.push(chain);
                    }
                }
            }
        }

        // Check if event completes any active chains
        for chain in &mut self.active_chains {
            if let Some(phase) = event.kill_chain_phase {
                // Check if this event advances the chain
                let latest_phase = chain.stages.last().map(|s| s.phase);
                if let Some(last) = latest_phase {
                    if phase > last {
                        chain.add_stage(AttackStage {
                            phase,
                            event_ids: vec![event.id],
                            start_time: event.timestamp,
                            end_time: event.timestamp,
                            description: event.description.clone(),
                        });
                    }
                }
            }
        }

        // Move completed chains to output
        let mut i = 0;
        while i < self.active_chains.len() {
            if self.active_chains[i].stages.len() >= self.min_stages {
                let chain = self.active_chains.remove(i);
                completed_chains.push(chain);
            } else {
                i += 1;
            }
        }

        completed_chains
    }

    /// Build chain from correlation
    fn build_chain_from_correlation(
        &mut self,
        current_event: &SecurityEvent,
        correlation: &CorrelationResult,
        timeline: &Timeline,
    ) -> Option<AttackChain> {
        self.chain_counter += 1;
        let mut chain = AttackChain::new(self.chain_counter);

        chain.attacker = current_event.source.clone();
        chain.target = current_event.target.clone();

        // Get correlated events and build stages
        let mut all_events: Vec<&SecurityEvent> = correlation.event_ids
            .iter()
            .filter_map(|&id| timeline.get_event(id).map(|e| &e.event))
            .collect();

        // Add current event
        all_events.push(current_event);

        // Sort by timestamp
        all_events.sort_by_key(|e| e.timestamp);

        // Group by kill chain phase
        let mut current_phase: Option<KillChainPhase> = None;
        let mut current_stage_events: Vec<u64> = Vec::new();
        let mut stage_start = 0u64;

        for event in all_events {
            if let Some(phase) = event.kill_chain_phase {
                if current_phase != Some(phase) {
                    // Save previous stage
                    if !current_stage_events.is_empty() {
                        if let Some(prev_phase) = current_phase {
                            chain.add_stage(AttackStage {
                                phase: prev_phase,
                                event_ids: current_stage_events.clone(),
                                start_time: stage_start,
                                end_time: event.timestamp,
                                description: alloc::format!("{} phase", prev_phase.name()),
                            });
                        }
                    }

                    // Start new stage
                    current_phase = Some(phase);
                    current_stage_events.clear();
                    stage_start = event.timestamp;
                }
                current_stage_events.push(event.id);
            }
        }

        // Add final stage
        if !current_stage_events.is_empty() {
            if let Some(phase) = current_phase {
                chain.add_stage(AttackStage {
                    phase,
                    event_ids: current_stage_events,
                    start_time: stage_start,
                    end_time: current_event.timestamp,
                    description: alloc::format!("{} phase", phase.name()),
                });
            }
        }

        // Set confidence based on correlation
        chain.confidence = correlation.confidence;
        chain.description = alloc::format!(
            "Attack chain with {} stages, {} events",
            chain.stages.len(),
            chain.all_event_ids().len()
        );

        if chain.stages.is_empty() {
            None
        } else {
            Some(chain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;

    #[test]
    fn test_attack_chain_creation() {
        let mut chain = AttackChain::new(1);

        chain.add_stage(AttackStage {
            phase: KillChainPhase::Reconnaissance,
            event_ids: vec![1],
            start_time: 1000,
            end_time: 1500,
            description: "Recon".into(),
        });

        chain.add_stage(AttackStage {
            phase: KillChainPhase::Exploitation,
            event_ids: vec![2, 3],
            start_time: 2000,
            end_time: 2500,
            description: "Exploit".into(),
        });

        assert_eq!(chain.stages.len(), 2);
        assert_eq!(chain.all_event_ids().len(), 3);
        assert!(chain.threat_score > 0.0);
    }

    #[test]
    fn test_detector_creation() {
        let detector = AttackDetector::new(3);
        assert_eq!(detector.min_stages, 3);
    }
}
