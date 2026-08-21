//! Trust Engine
//!
//! Evaluates trust levels for nodes based on identity, history, and behavior.

use hashbrown::HashMap;
use axiom_types::NodeId;

/// Trust level for a node
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Blocked - do not communicate
    Blocked = 0,
    /// Untrusted - allow minimal communication
    Untrusted = 1,
    /// Unknown - no prior interaction
    Unknown = 2,
    /// Neutral - some positive interaction
    Neutral = 3,
    /// Trusted - verified positive history
    Trusted = 4,
    /// Highly Trusted - long-term reliable
    HighlyTrusted = 5,
    /// Self - this is us
    LocalSelf = 6,
}

impl TrustLevel {
    /// Is this node blocked?
    pub fn is_blocked(&self) -> bool {
        *self == TrustLevel::Blocked
    }

    /// Is this node trusted enough for secure communication?
    pub fn is_trusted(&self) -> bool {
        *self >= TrustLevel::Trusted
    }

    /// Can we route through this node?
    pub fn can_route(&self) -> bool {
        *self >= TrustLevel::Neutral
    }

    /// Numeric value for calculations
    pub fn value(&self) -> u8 {
        *self as u8
    }
}

/// Trust record for a node
#[derive(Debug, Clone)]
pub struct TrustRecord {
    /// Node identity
    pub node_id: NodeId,
    /// Current trust level
    pub level: TrustLevel,
    /// Successful interactions
    pub successful_interactions: u64,
    /// Failed interactions
    pub failed_interactions: u64,
    /// Last interaction timestamp
    pub last_interaction: u64,
    /// First seen timestamp
    pub first_seen: u64,
    /// Reason for current level (if manual)
    pub reason: Option<String>,
}

impl TrustRecord {
    /// Create new record for unknown node
    pub fn new(node_id: NodeId, now: u64) -> Self {
        Self {
            node_id,
            level: TrustLevel::Unknown,
            successful_interactions: 0,
            failed_interactions: 0,
            last_interaction: now,
            first_seen: now,
            reason: None,
        }
    }

    /// Record a successful interaction
    pub fn record_success(&mut self, now: u64) {
        self.successful_interactions += 1;
        self.last_interaction = now;
        self.recalculate_level();
    }

    /// Record a failed interaction
    pub fn record_failure(&mut self, now: u64) {
        self.failed_interactions += 1;
        self.last_interaction = now;
        self.recalculate_level();
    }

    /// Recalculate trust level based on history
    fn recalculate_level(&mut self) {
        // Don't override manual blocks
        if self.level == TrustLevel::Blocked && self.reason.is_some() {
            return;
        }

        let total = self.successful_interactions + self.failed_interactions;
        if total == 0 {
            self.level = TrustLevel::Unknown;
            return;
        }

        let success_rate = self.successful_interactions as f64 / total as f64;

        self.level = if self.failed_interactions > 10 && success_rate < 0.5 {
            TrustLevel::Untrusted
        } else if success_rate < 0.7 {
            TrustLevel::Neutral
        } else if self.successful_interactions > 100 && success_rate > 0.95 {
            TrustLevel::HighlyTrusted
        } else if self.successful_interactions > 10 && success_rate > 0.9 {
            TrustLevel::Trusted
        } else {
            TrustLevel::Neutral
        };
    }

    /// Success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_interactions + self.failed_interactions;
        if total == 0 {
            0.5 // Unknown defaults to neutral
        } else {
            self.successful_interactions as f64 / total as f64
        }
    }
}

/// Result of self-identity verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfVerifyResult {
    /// Legitimate self-command (valid signature)
    ValidSelf,
    /// Impersonation attempt (claims to be us, but signature invalid/missing)
    Impersonation,
    /// Not claiming to be us
    NotSelf,
}

/// Trust engine for evaluating node trust
#[derive(Debug)]
pub struct TrustEngine {
    /// Trust records by node
    records: HashMap<NodeId, TrustRecord>,
    /// Local node ID
    local_id: NodeId,
    /// Default trust for unknown nodes
    default_trust: TrustLevel,
    /// Count of detected impersonation attempts
    impersonation_attempts: u64,
    /// Last impersonation source (for forensics)
    last_impersonation_source: Option<[u8; 32]>,
}

impl TrustEngine {
    /// Create new trust engine
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            local_id: NodeId::zero(),
            default_trust: TrustLevel::Unknown,
            impersonation_attempts: 0,
            last_impersonation_source: None,
        }
    }

    /// Set local node ID
    pub fn set_local_id(&mut self, id: NodeId) {
        self.local_id = id;
    }

    /// Set default trust level for unknown nodes
    pub fn set_default_trust(&mut self, level: TrustLevel) {
        self.default_trust = level;
    }

    /// Quick trust check (Tier 1 - fast path)
    pub fn quick_check(&self, node_id: &NodeId) -> TrustLevel {
        // Check if it's us
        if *node_id == self.local_id && !self.local_id.is_zero() {
            return TrustLevel::LocalSelf;
        }

        // Check cache
        if let Some(record) = self.records.get(node_id) {
            record.level
        } else {
            self.default_trust
        }
    }

    /// Verify a packet claiming to be from self
    /// CRITICAL: Packets claiming LocalSelf MUST be cryptographically verified
    ///
    /// A NIC receiving a command "from itself" could be:
    /// 1. Legitimate loopback (internal routing, self-test)
    /// 2. Impersonation attack (attacker spoofs our NodeId)
    ///
    /// Returns SelfVerifyResult indicating whether this is valid or an attack
    pub fn verify_self_claim(&mut self, claimed_source: &NodeId, has_valid_signature: bool, raw_source: Option<[u8; 32]>) -> SelfVerifyResult {
        // Not claiming to be us? Not our concern here
        if *claimed_source != self.local_id || self.local_id.is_zero() {
            return SelfVerifyResult::NotSelf;
        }

        // Claims to be us - verify signature
        if has_valid_signature {
            // Legitimate self-command (loopback, internal routing)
            SelfVerifyResult::ValidSelf
        } else {
            // IMPERSONATION DETECTED
            // Someone is sending packets claiming to be from our own identity
            // This is either:
            // - An attack attempting to bypass trust checks
            // - A misconfigured node with same ID (should never happen with proper key generation)
            // - Network loop reflecting our own unsigned traffic back
            self.impersonation_attempts += 1;
            self.last_impersonation_source = raw_source;
            SelfVerifyResult::Impersonation
        }
    }

    /// Check if a packet claims to be from self (pre-crypto check)
    /// Use this for fast rejection before signature verification
    pub fn claims_self(&self, source: &NodeId) -> bool {
        !self.local_id.is_zero() && *source == self.local_id
    }

    /// Get count of detected impersonation attempts
    pub fn impersonation_attempts(&self) -> u64 {
        self.impersonation_attempts
    }

    /// Get last raw source bytes from impersonation attempt (for forensics)
    pub fn last_impersonation_source(&self) -> Option<[u8; 32]> {
        self.last_impersonation_source
    }

    /// Reset impersonation counter (after investigation)
    pub fn reset_impersonation_counter(&mut self) {
        self.impersonation_attempts = 0;
        self.last_impersonation_source = None;
    }

    /// Get or create trust record
    pub fn get_or_create(&mut self, node_id: NodeId, now: u64) -> &mut TrustRecord {
        self.records.entry(node_id).or_insert_with(|| TrustRecord::new(node_id, now))
    }

    /// Get trust record if exists
    pub fn get(&self, node_id: &NodeId) -> Option<&TrustRecord> {
        self.records.get(node_id)
    }

    /// Record successful interaction
    pub fn record_success(&mut self, node_id: NodeId, now: u64) {
        self.get_or_create(node_id, now).record_success(now);
    }

    /// Record failed interaction
    pub fn record_failure(&mut self, node_id: NodeId, now: u64) {
        self.get_or_create(node_id, now).record_failure(now);
    }

    /// Manually set trust level
    pub fn set_trust(&mut self, node_id: NodeId, level: TrustLevel, reason: Option<String>, now: u64) {
        let record = self.get_or_create(node_id, now);
        record.level = level;
        record.reason = reason;
    }

    /// Block a node
    pub fn block(&mut self, node_id: NodeId, reason: String, now: u64) {
        self.set_trust(node_id, TrustLevel::Blocked, Some(reason), now);
    }

    /// Unblock a node (resets to unknown)
    pub fn unblock(&mut self, node_id: NodeId, now: u64) {
        if let Some(record) = self.records.get_mut(&node_id) {
            record.level = TrustLevel::Unknown;
            record.reason = None;
            record.last_interaction = now;
        }
    }

    /// Get all blocked nodes
    pub fn blocked_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.records.iter()
            .filter(|(_, r)| r.level == TrustLevel::Blocked)
            .map(|(id, _)| id)
    }

    /// Get all trusted nodes
    pub fn trusted_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.records.iter()
            .filter(|(_, r)| r.level.is_trusted())
            .map(|(id, _)| id)
    }

    /// Number of known nodes
    pub fn known_nodes(&self) -> usize {
        self.records.len()
    }
}

impl Default for TrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(n: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = n;
        NodeId::from_bytes(id)
    }

    #[test]
    fn test_trust_levels() {
        assert!(TrustLevel::Blocked.is_blocked());
        assert!(!TrustLevel::Trusted.is_blocked());

        assert!(TrustLevel::Trusted.is_trusted());
        assert!(TrustLevel::HighlyTrusted.is_trusted());
        assert!(!TrustLevel::Neutral.is_trusted());

        assert!(TrustLevel::Neutral.can_route());
        assert!(!TrustLevel::Untrusted.can_route());
    }

    #[test]
    fn test_trust_engine_basic() {
        let mut engine = TrustEngine::new();
        let node = test_node_id(1);

        // Unknown node
        assert_eq!(engine.quick_check(&node), TrustLevel::Unknown);

        // Record interactions
        for _ in 0..20 {
            engine.record_success(node, 1000);
        }

        // Should be trusted now
        assert!(engine.quick_check(&node).is_trusted());
    }

    #[test]
    fn test_trust_engine_block() {
        let mut engine = TrustEngine::new();
        let node = test_node_id(1);

        engine.block(node, "Suspicious activity".to_string(), 1000);
        assert!(engine.quick_check(&node).is_blocked());

        engine.unblock(node, 2000);
        assert!(!engine.quick_check(&node).is_blocked());
    }

    #[test]
    fn test_trust_local_self() {
        let mut engine = TrustEngine::new();
        let local = test_node_id(1);
        engine.set_local_id(local);

        assert_eq!(engine.quick_check(&local), TrustLevel::LocalSelf);
    }

    #[test]
    fn test_trust_record_history() {
        let mut record = TrustRecord::new(test_node_id(1), 0);

        // Initially unknown
        assert_eq!(record.level, TrustLevel::Unknown);

        // Build trust
        for i in 0..50 {
            record.record_success(i);
        }
        assert!(record.level >= TrustLevel::Trusted);

        // Some failures shouldn't break trust
        record.record_failure(51);
        record.record_failure(52);
        assert!(record.success_rate() > 0.9);
    }

    #[test]
    fn test_self_impersonation_detection() {
        let mut engine = TrustEngine::new();
        let local = test_node_id(1);
        let other = test_node_id(2);
        engine.set_local_id(local);

        // Not claiming to be us
        assert_eq!(
            engine.verify_self_claim(&other, false, None),
            SelfVerifyResult::NotSelf
        );

        // Valid self (with signature)
        assert_eq!(
            engine.verify_self_claim(&local, true, None),
            SelfVerifyResult::ValidSelf
        );
        assert_eq!(engine.impersonation_attempts(), 0);

        // IMPERSONATION: claims to be us without valid signature
        let fake_source = [0xDE; 32];
        assert_eq!(
            engine.verify_self_claim(&local, false, Some(fake_source)),
            SelfVerifyResult::Impersonation
        );
        assert_eq!(engine.impersonation_attempts(), 1);
        assert_eq!(engine.last_impersonation_source(), Some(fake_source));

        // Multiple impersonation attempts should accumulate
        engine.verify_self_claim(&local, false, None);
        engine.verify_self_claim(&local, false, None);
        assert_eq!(engine.impersonation_attempts(), 3);

        // Reset counter
        engine.reset_impersonation_counter();
        assert_eq!(engine.impersonation_attempts(), 0);
    }

    #[test]
    fn test_claims_self() {
        let mut engine = TrustEngine::new();
        let local = test_node_id(1);
        let other = test_node_id(2);

        // Before setting local ID
        assert!(!engine.claims_self(&local));

        engine.set_local_id(local);

        // After setting local ID
        assert!(engine.claims_self(&local));
        assert!(!engine.claims_self(&other));
    }
}

use alloc::string::String;
