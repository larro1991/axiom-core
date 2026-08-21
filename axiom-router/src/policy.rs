//! Policy-Based Routing - Enterprise compliance and control
//!
//! Implements AGP-inspired policy routing:
//! - Match rules for intent, source, destination, tags
//! - Actions: forward, rate-limit, require-auth, drop
//! - Cost-aware routing for resource optimization
//! - Audit logging for compliance

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::trust::TrustLevel;

/// A routing policy
#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    /// Policy name
    pub name: String,
    /// Policy priority (higher = evaluated first)
    pub priority: u8,
    /// Whether policy is enabled
    pub enabled: bool,
    /// Match conditions (all must match)
    pub match_rules: Vec<MatchRule>,
    /// Action to take when matched
    pub action: RouteAction,
    /// Description
    pub description: Option<String>,
}

impl RoutingPolicy {
    /// Create a new policy
    pub fn new(name: impl Into<String>, priority: u8) -> Self {
        Self {
            name: name.into(),
            priority,
            enabled: true,
            match_rules: Vec::new(),
            action: RouteAction::Forward { prefer_local: false },
            description: None,
        }
    }

    /// Add a match rule
    pub fn with_rule(mut self, rule: MatchRule) -> Self {
        self.match_rules.push(rule);
        self
    }

    /// Set the action
    pub fn with_action(mut self, action: RouteAction) -> Self {
        self.action = action;
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Enable/disable
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Match rule for policy evaluation
#[derive(Debug, Clone)]
pub enum MatchRule {
    /// Match specific intent hash
    Intent(IntentHash),
    /// Match intent prefix (category)
    IntentPrefix([u8; 4]),
    /// Match source node
    Source(NodeId),
    /// Match source in list
    SourceList(Vec<NodeId>),
    /// Match destination node
    Destination(NodeId),
    /// Match tag
    Tag(String),
    /// Match any of several tags
    AnyTag(Vec<String>),
    /// Match trust level (minimum)
    MinTrust(TrustLevel),
    /// Match time range (hour of day, 0-23)
    TimeRange { start_hour: u8, end_hour: u8 },
    /// Match data size (bytes)
    MaxSize(usize),
    /// Custom predicate (name only - evaluated externally)
    Custom(String),
    /// Logical NOT
    Not(Box<MatchRule>),
    /// Logical AND
    And(Vec<MatchRule>),
    /// Logical OR
    Or(Vec<MatchRule>),
}

impl MatchRule {
    /// Create a NOT rule
    pub fn not(rule: MatchRule) -> Self {
        MatchRule::Not(Box::new(rule))
    }

    /// Create an AND rule
    pub fn and(rules: Vec<MatchRule>) -> Self {
        MatchRule::And(rules)
    }

    /// Create an OR rule
    pub fn or(rules: Vec<MatchRule>) -> Self {
        MatchRule::Or(rules)
    }
}

/// Action to take when policy matches
#[derive(Debug, Clone)]
pub enum RouteAction {
    /// Forward to destination (default routing)
    Forward {
        /// Prefer local nodes
        prefer_local: bool,
    },

    /// Forward with cost weighting
    ForwardWeighted {
        /// Cost weight multiplier
        cost_weight: f32,
        /// Maximum hops
        max_hops: Option<u8>,
    },

    /// Rate limit requests
    RateLimit {
        /// Requests per second
        requests_per_sec: u32,
        /// Burst size
        burst_size: u32,
    },

    /// Require minimum authentication
    RequireAuth {
        /// Minimum trust level
        min_trust: TrustLevel,
        /// Require specific auth method
        auth_method: Option<String>,
    },

    /// Redirect to different intent
    Redirect {
        /// New intent hash
        to_intent: IntentHash,
    },

    /// Drop the request
    Drop {
        /// Reason for dropping
        reason: String,
        /// Whether to notify sender
        notify: bool,
    },

    /// Queue for later processing
    Queue {
        /// Queue name
        queue: String,
        /// Priority in queue
        priority: u8,
    },

    /// Log and continue (audit)
    Audit {
        /// Log level
        level: AuditLevel,
        /// Include payload
        include_payload: bool,
    },

    /// Apply multiple actions in sequence
    Chain(Vec<RouteAction>),
}

/// Audit log level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Policy evaluation context
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Intent being routed
    pub intent: IntentHash,
    /// Source node
    pub source: NodeId,
    /// Destination node (if known)
    pub destination: Option<NodeId>,
    /// Tags on the request
    pub tags: Vec<String>,
    /// Trust level of source
    pub trust_level: TrustLevel,
    /// Payload size in bytes
    pub payload_size: usize,
    /// Current hour (0-23)
    pub current_hour: u8,
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub enum PolicyResult {
    /// Allow with action
    Allow(RouteAction),
    /// Deny with reason
    Deny(String),
    /// No matching policy (use default routing)
    NoMatch,
}

/// Policy engine
pub struct PolicyEngine {
    /// Policies in priority order
    policies: Vec<RoutingPolicy>,
    /// Default action when no policy matches
    default_action: RouteAction,
    /// Audit log entries
    audit_log: Vec<AuditEntry>,
    /// Max audit log size
    max_audit_entries: usize,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            default_action: RouteAction::Forward { prefer_local: false },
            audit_log: Vec::new(),
            max_audit_entries: 10000,
        }
    }

    /// Add a policy
    pub fn add_policy(&mut self, policy: RoutingPolicy) {
        self.policies.push(policy);
        // Sort by priority (highest first)
        self.policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a policy by name
    pub fn remove_policy(&mut self, name: &str) -> bool {
        let len = self.policies.len();
        self.policies.retain(|p| p.name != name);
        self.policies.len() < len
    }

    /// Set default action
    pub fn set_default(&mut self, action: RouteAction) {
        self.default_action = action;
    }

    /// Evaluate policies for a context
    pub fn evaluate(&mut self, ctx: &PolicyContext) -> PolicyResult {
        // Collect audit events to process after iteration
        let mut audits: Vec<(String, AuditLevel, bool)> = Vec::new();
        let mut result: Option<PolicyResult> = None;

        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            if self.matches_all_rules(&policy.match_rules, ctx) {
                // Handle audit action specially
                if let RouteAction::Audit { level, include_payload } = &policy.action {
                    audits.push((policy.name.clone(), *level, *include_payload));
                    continue; // Audit doesn't stop evaluation
                }

                // Check for drop action
                if let RouteAction::Drop { reason, .. } = &policy.action {
                    result = Some(PolicyResult::Deny(reason.clone()));
                    break;
                }

                result = Some(PolicyResult::Allow(policy.action.clone()));
                break;
            }
        }

        // Process collected audit events
        for (policy_name, level, include_payload) in audits {
            self.log_audit(ctx, &policy_name, level, include_payload);
        }

        // Return result or default
        result.unwrap_or_else(|| PolicyResult::Allow(self.default_action.clone()))
    }

    /// Check if all rules match
    fn matches_all_rules(&self, rules: &[MatchRule], ctx: &PolicyContext) -> bool {
        if rules.is_empty() {
            return true;
        }
        rules.iter().all(|rule| self.matches_rule(rule, ctx))
    }

    /// Check if a single rule matches
    fn matches_rule(&self, rule: &MatchRule, ctx: &PolicyContext) -> bool {
        match rule {
            MatchRule::Intent(hash) => ctx.intent == *hash,
            MatchRule::IntentPrefix(prefix) => ctx.intent.as_bytes()[..4] == *prefix,
            MatchRule::Source(node) => ctx.source == *node,
            MatchRule::SourceList(nodes) => nodes.contains(&ctx.source),
            MatchRule::Destination(node) => ctx.destination.as_ref() == Some(node),
            MatchRule::Tag(tag) => ctx.tags.contains(tag),
            MatchRule::AnyTag(tags) => tags.iter().any(|t| ctx.tags.contains(t)),
            MatchRule::MinTrust(level) => ctx.trust_level >= *level,
            MatchRule::TimeRange { start_hour, end_hour } => {
                if start_hour <= end_hour {
                    ctx.current_hour >= *start_hour && ctx.current_hour <= *end_hour
                } else {
                    // Wraps around midnight
                    ctx.current_hour >= *start_hour || ctx.current_hour <= *end_hour
                }
            }
            MatchRule::MaxSize(size) => ctx.payload_size <= *size,
            MatchRule::Custom(_) => true, // External evaluation
            MatchRule::Not(inner) => !self.matches_rule(inner, ctx),
            MatchRule::And(rules) => rules.iter().all(|r| self.matches_rule(r, ctx)),
            MatchRule::Or(rules) => rules.iter().any(|r| self.matches_rule(r, ctx)),
        }
    }

    /// Log an audit entry
    fn log_audit(&mut self, ctx: &PolicyContext, policy: &str, level: AuditLevel, _include_payload: bool) {
        if self.audit_log.len() >= self.max_audit_entries {
            self.audit_log.remove(0);
        }

        self.audit_log.push(AuditEntry {
            timestamp: 0, // Would use real clock
            policy_name: String::from(policy),
            level,
            intent: ctx.intent.clone(),
            source: ctx.source.clone(),
            destination: ctx.destination.clone(),
        });
    }

    /// Get audit log
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Clear audit log
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    /// List all policies
    pub fn list_policies(&self) -> &[RoutingPolicy] {
        &self.policies
    }

    /// Get policy by name
    pub fn get_policy(&self, name: &str) -> Option<&RoutingPolicy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// Enable/disable a policy
    pub fn set_policy_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(policy) = self.policies.iter_mut().find(|p| p.name == name) {
            policy.enabled = enabled;
            true
        } else {
            false
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: u64,
    /// Policy that triggered audit
    pub policy_name: String,
    /// Audit level
    pub level: AuditLevel,
    /// Intent that was routed
    pub intent: IntentHash,
    /// Source node
    pub source: NodeId,
    /// Destination node
    pub destination: Option<NodeId>,
}

/// Common policy templates
pub struct PolicyTemplates;

impl PolicyTemplates {
    /// Block all requests from a node
    pub fn block_node(name: &str, node: NodeId) -> RoutingPolicy {
        RoutingPolicy::new(name, 100)
            .with_rule(MatchRule::Source(node))
            .with_action(RouteAction::Drop {
                reason: String::from("Blocked node"),
                notify: false,
            })
    }

    /// Rate limit by tag
    pub fn rate_limit_tag(name: &str, tag: &str, rps: u32) -> RoutingPolicy {
        RoutingPolicy::new(name, 50)
            .with_rule(MatchRule::Tag(String::from(tag)))
            .with_action(RouteAction::RateLimit {
                requests_per_sec: rps,
                burst_size: rps * 2,
            })
    }

    /// Require auth for sensitive intents
    pub fn require_auth(name: &str, intent: IntentHash, min_trust: TrustLevel) -> RoutingPolicy {
        RoutingPolicy::new(name, 80)
            .with_rule(MatchRule::Intent(intent))
            .with_action(RouteAction::RequireAuth {
                min_trust,
                auth_method: None,
            })
    }

    /// Audit all traffic
    pub fn audit_all(name: &str) -> RoutingPolicy {
        RoutingPolicy::new(name, 1)
            .with_action(RouteAction::Audit {
                level: AuditLevel::Info,
                include_payload: false,
            })
    }

    /// Business hours only
    pub fn business_hours(name: &str, start: u8, end: u8) -> RoutingPolicy {
        RoutingPolicy::new(name, 60)
            .with_rule(MatchRule::Not(Box::new(MatchRule::TimeRange {
                start_hour: start,
                end_hour: end,
            })))
            .with_action(RouteAction::Drop {
                reason: String::from("Outside business hours"),
                notify: true,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    fn test_context() -> PolicyContext {
        PolicyContext {
            intent: test_intent_hash(1),
            source: test_node_id(10),
            destination: Some(test_node_id(20)),
            tags: vec![String::from("test"), String::from("important")],
            trust_level: TrustLevel::Sig,
            payload_size: 1000,
            current_hour: 14,
        }
    }

    #[test]
    fn test_policy_creation() {
        let policy = RoutingPolicy::new("test", 50)
            .with_rule(MatchRule::Tag(String::from("test")))
            .with_action(RouteAction::Forward { prefer_local: true })
            .with_description("Test policy");

        assert_eq!(policy.name, "test");
        assert_eq!(policy.priority, 50);
        assert!(policy.enabled);
    }

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("block-test", 100)
            .with_rule(MatchRule::Source(test_node_id(10)))
            .with_action(RouteAction::Drop {
                reason: String::from("Blocked"),
                notify: false,
            }));

        let ctx = test_context();
        let result = engine.evaluate(&ctx);

        assert!(matches!(result, PolicyResult::Deny(_)));
    }

    #[test]
    fn test_no_match() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("other", 100)
            .with_rule(MatchRule::Source(test_node_id(99))) // Won't match
            .with_action(RouteAction::Drop {
                reason: String::from("Blocked"),
                notify: false,
            }));

        let ctx = test_context();
        let result = engine.evaluate(&ctx);

        assert!(matches!(result, PolicyResult::Allow(_)));
    }

    #[test]
    fn test_priority_order() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("low", 10)
            .with_rule(MatchRule::Tag(String::from("test")))
            .with_action(RouteAction::Forward { prefer_local: false }));

        engine.add_policy(RoutingPolicy::new("high", 100)
            .with_rule(MatchRule::Tag(String::from("test")))
            .with_action(RouteAction::RateLimit {
                requests_per_sec: 10,
                burst_size: 20,
            }));

        let ctx = test_context();
        let result = engine.evaluate(&ctx);

        // High priority should match first
        assert!(matches!(result, PolicyResult::Allow(RouteAction::RateLimit { .. })));
    }

    #[test]
    fn test_complex_match_rules() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("complex", 50)
            .with_rule(MatchRule::And(vec![
                MatchRule::Tag(String::from("test")),
                MatchRule::MinTrust(TrustLevel::Sig),
            ]))
            .with_action(RouteAction::Forward { prefer_local: true }));

        let ctx = test_context();
        let result = engine.evaluate(&ctx);

        assert!(matches!(result, PolicyResult::Allow(RouteAction::Forward { prefer_local: true })));
    }

    #[test]
    fn test_not_rule() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("not-important", 50)
            .with_rule(MatchRule::not(MatchRule::Tag(String::from("important"))))
            .with_action(RouteAction::Drop {
                reason: String::from("Not important"),
                notify: false,
            }));

        let ctx = test_context(); // Has "important" tag
        let result = engine.evaluate(&ctx);

        // Should NOT match because context has "important" tag
        assert!(matches!(result, PolicyResult::Allow(_)));
    }

    #[test]
    fn test_time_range() {
        let rule = MatchRule::TimeRange { start_hour: 9, end_hour: 17 };
        let engine = PolicyEngine::new();

        let mut ctx = test_context();
        ctx.current_hour = 14;
        assert!(engine.matches_rule(&rule, &ctx));

        ctx.current_hour = 20;
        assert!(!engine.matches_rule(&rule, &ctx));
    }

    #[test]
    fn test_audit_logging() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("audit", 1)
            .with_action(RouteAction::Audit {
                level: AuditLevel::Info,
                include_payload: false,
            }));

        let ctx = test_context();
        engine.evaluate(&ctx);

        assert_eq!(engine.audit_log().len(), 1);
    }

    #[test]
    fn test_policy_templates() {
        let block = PolicyTemplates::block_node("block", test_node_id(10));
        assert!(matches!(block.action, RouteAction::Drop { .. }));

        let rate = PolicyTemplates::rate_limit_tag("rate", "api", 100);
        assert!(matches!(rate.action, RouteAction::RateLimit { .. }));

        let auth = PolicyTemplates::require_auth("auth", test_intent_hash(1), TrustLevel::Full);
        assert!(matches!(auth.action, RouteAction::RequireAuth { .. }));
    }

    #[test]
    fn test_enable_disable() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("test", 50)
            .with_rule(MatchRule::Tag(String::from("test")))
            .with_action(RouteAction::Drop {
                reason: String::from("Blocked"),
                notify: false,
            }));

        let ctx = test_context();

        // Should match when enabled
        assert!(matches!(engine.evaluate(&ctx), PolicyResult::Deny(_)));

        // Disable
        engine.set_policy_enabled("test", false);
        assert!(matches!(engine.evaluate(&ctx), PolicyResult::Allow(_)));

        // Re-enable
        engine.set_policy_enabled("test", true);
        assert!(matches!(engine.evaluate(&ctx), PolicyResult::Deny(_)));
    }

    #[test]
    fn test_remove_policy() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy::new("test", 50));
        assert_eq!(engine.list_policies().len(), 1);

        engine.remove_policy("test");
        assert_eq!(engine.list_policies().len(), 0);
    }
}
