//! Kill Chain Mapping
//!
//! Maps security events to the Cyber Kill Chain framework.

use alloc::vec::Vec;

/// Kill Chain phases (based on Lockheed Martin)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KillChainPhase {
    /// Reconnaissance - Attacker researches target
    Reconnaissance = 0,
    /// Weaponization - Attacker creates exploit
    Weaponization = 1,
    /// Delivery - Transmit weapon to target
    Delivery = 2,
    /// Exploitation - Exploit vulnerability
    Exploitation = 3,
    /// Installation - Install backdoor/malware
    Installation = 4,
    /// Command and Control - Remote control channel
    CommandAndControl = 5,
    /// Lateral Movement - Move through network
    LateralMovement = 6,
    /// Actions on Objectives - Complete goal
    Actions = 7,
}

impl KillChainPhase {
    /// Get phase name
    pub fn name(&self) -> &'static str {
        match self {
            KillChainPhase::Reconnaissance => "Reconnaissance",
            KillChainPhase::Weaponization => "Weaponization",
            KillChainPhase::Delivery => "Delivery",
            KillChainPhase::Exploitation => "Exploitation",
            KillChainPhase::Installation => "Installation",
            KillChainPhase::CommandAndControl => "Command & Control",
            KillChainPhase::LateralMovement => "Lateral Movement",
            KillChainPhase::Actions => "Actions on Objectives",
        }
    }

    /// Get phase severity multiplier
    pub fn severity_multiplier(&self) -> f64 {
        match self {
            KillChainPhase::Reconnaissance => 1.0,
            KillChainPhase::Weaponization => 1.1,
            KillChainPhase::Delivery => 1.2,
            KillChainPhase::Exploitation => 1.5,
            KillChainPhase::Installation => 1.6,
            KillChainPhase::CommandAndControl => 1.8,
            KillChainPhase::LateralMovement => 1.9,
            KillChainPhase::Actions => 2.0,
        }
    }

    /// Get detection priority (higher = more important to detect)
    pub fn priority(&self) -> u8 {
        match self {
            KillChainPhase::Reconnaissance => 2,
            KillChainPhase::Weaponization => 3,
            KillChainPhase::Delivery => 4,
            KillChainPhase::Exploitation => 7,
            KillChainPhase::Installation => 8,
            KillChainPhase::CommandAndControl => 9,
            KillChainPhase::LateralMovement => 9,
            KillChainPhase::Actions => 10,
        }
    }

    /// All phases in order
    pub fn all() -> Vec<KillChainPhase> {
        vec![
            KillChainPhase::Reconnaissance,
            KillChainPhase::Weaponization,
            KillChainPhase::Delivery,
            KillChainPhase::Exploitation,
            KillChainPhase::Installation,
            KillChainPhase::CommandAndControl,
            KillChainPhase::LateralMovement,
            KillChainPhase::Actions,
        ]
    }
}

/// Kill chain progress tracker
#[derive(Debug, Clone, Default)]
pub struct KillChainProgress {
    /// Phases observed
    phases: [bool; 8],
    /// Phase timestamps
    timestamps: [Option<u64>; 8],
    /// Phase event counts
    event_counts: [u32; 8],
}

impl KillChainProgress {
    /// Create new progress tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record phase observation
    pub fn observe(&mut self, phase: KillChainPhase, timestamp: u64) {
        let idx = phase as usize;
        self.phases[idx] = true;
        if self.timestamps[idx].is_none() {
            self.timestamps[idx] = Some(timestamp);
        }
        self.event_counts[idx] += 1;
    }

    /// Check if phase observed
    pub fn has_phase(&self, phase: KillChainPhase) -> bool {
        self.phases[phase as usize]
    }

    /// Get completion percentage
    pub fn completion(&self) -> f64 {
        let count = self.phases.iter().filter(|&&p| p).count();
        count as f64 / 8.0 * 100.0
    }

    /// Get furthest phase reached
    pub fn furthest_phase(&self) -> Option<KillChainPhase> {
        for phase in KillChainPhase::all().into_iter().rev() {
            if self.has_phase(phase) {
                return Some(phase);
            }
        }
        None
    }

    /// Get phases observed
    pub fn observed_phases(&self) -> Vec<KillChainPhase> {
        KillChainPhase::all()
            .into_iter()
            .filter(|&p| self.has_phase(p))
            .collect()
    }

    /// Calculate threat score based on progress
    pub fn threat_score(&self) -> f64 {
        let mut score = 0.0;
        for phase in KillChainPhase::all() {
            if self.has_phase(phase) {
                score += 10.0 * phase.severity_multiplier();
            }
        }
        score.min(100.0)
    }
}

/// Maps events to kill chain phases
#[cfg(feature = "std")]
pub struct KillChainMapper {
    /// Progress per entity (by identifier)
    entity_progress: hashbrown::HashMap<String, KillChainProgress>,
}

#[cfg(feature = "std")]
impl KillChainMapper {
    /// Create new mapper
    pub fn new() -> Self {
        Self {
            entity_progress: hashbrown::HashMap::new(),
        }
    }

    /// Record phase for entity
    pub fn record(&mut self, entity_id: &str, phase: KillChainPhase, timestamp: u64) {
        self.entity_progress
            .entry(entity_id.into())
            .or_insert_with(KillChainProgress::new)
            .observe(phase, timestamp);
    }

    /// Get progress for entity
    pub fn get_progress(&self, entity_id: &str) -> Option<&KillChainProgress> {
        self.entity_progress.get(entity_id)
    }

    /// Get entities with significant progress
    pub fn active_chains(&self, min_phases: usize) -> Vec<(&String, &KillChainProgress)> {
        self.entity_progress
            .iter()
            .filter(|(_, p)| p.observed_phases().len() >= min_phases)
            .collect()
    }

    /// Get highest threat entities
    pub fn highest_threat(&self, count: usize) -> Vec<(&String, f64)> {
        let mut entities: Vec<_> = self.entity_progress
            .iter()
            .map(|(id, p)| (id, p.threat_score()))
            .collect();
        entities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        entities.truncate(count);
        entities
    }
}

#[cfg(feature = "std")]
impl Default for KillChainMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_chain_phases() {
        assert!(KillChainPhase::Actions > KillChainPhase::Reconnaissance);
        assert_eq!(KillChainPhase::all().len(), 8);
    }

    #[test]
    fn test_progress_tracking() {
        let mut progress = KillChainProgress::new();

        progress.observe(KillChainPhase::Reconnaissance, 1000);
        progress.observe(KillChainPhase::Delivery, 2000);
        progress.observe(KillChainPhase::Installation, 3000);

        assert!(progress.has_phase(KillChainPhase::Reconnaissance));
        assert!(progress.has_phase(KillChainPhase::Delivery));
        assert!(!progress.has_phase(KillChainPhase::Exploitation));

        assert_eq!(progress.furthest_phase(), Some(KillChainPhase::Installation));
    }

    #[test]
    fn test_threat_score() {
        let mut progress = KillChainProgress::new();

        progress.observe(KillChainPhase::CommandAndControl, 1000);
        progress.observe(KillChainPhase::Actions, 2000);

        let score = progress.threat_score();
        assert!(score > 30.0); // C2 and Actions are high-severity phases
    }

    #[test]
    fn test_mapper() {
        let mut mapper = KillChainMapper::new();

        mapper.record("192.168.1.10", KillChainPhase::Reconnaissance, 1000);
        mapper.record("192.168.1.10", KillChainPhase::Delivery, 2000);

        let progress = mapper.get_progress("192.168.1.10").unwrap();
        assert_eq!(progress.observed_phases().len(), 2);
    }
}
