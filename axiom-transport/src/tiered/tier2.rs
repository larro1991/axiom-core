//! Tier 2: Smart Agents (The Specialists)
//!
//! Domain-specific intelligence with small models. One job, done well.
//! Millisecond latency, runs locally.
//!
//! # What Smart Agents Do
//! - Single-domain reasoning
//! - Learn from experience (within domain)
//! - Update Tier 1 translators
//! - Handle domain-specific exceptions
//! - Report to Tier 3 when confused
//!
//! # What Smart Agents DON'T Do
//! - General reasoning
//! - Cross-domain thinking
//! - Natural language
//! - Handle truly novel situations

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use axiom_types::{NodeId, IntentHash, TrustLevel};

use super::tier1::{Translator, EscalateReason, ProtocolId, protocols};

/// Agent configuration
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Maximum learning samples
    pub max_samples: usize,
    /// Confidence threshold for decisions (0.0 - 1.0)
    pub confidence_threshold: f32,
    /// Maximum queue depth
    pub max_queue_depth: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_samples: 1000,
            confidence_threshold: 0.7,
            max_queue_depth: 100,
        }
    }
}

/// Types of specialized agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentType {
    /// Routing decisions
    Routing,
    /// Trust evaluation
    Trust,
    /// Protocol understanding
    Protocol,
    /// Security/anomaly detection
    Security,
    /// Hardware management
    Hardware,
}

/// Decision made by a smart agent
#[derive(Debug, Clone)]
pub enum Decision {
    /// Definitive action to take
    Action(AgentAction),
    /// Need more information
    NeedInfo(InfoRequest),
    /// Escalate to Tier 3
    Escalate(Tier3Request),
}

/// Actions an agent can take
#[derive(Debug, Clone)]
pub enum AgentAction {
    /// Add route to Tier 1
    AddRoute {
        destination: NodeId,
        next_hop: NodeId,
        protocol: ProtocolId,
    },
    /// Remove route from Tier 1
    RemoveRoute {
        destination: NodeId,
    },
    /// Update trust level
    SetTrust {
        node_id: NodeId,
        trust: TrustLevel,
    },
    /// Block a node
    Block {
        node_id: NodeId,
        duration_ms: u64,
    },
    /// Allow packet through
    Allow,
    /// Drop packet
    Drop,
    /// Log an event
    Log {
        level: LogLevel,
        message: String,
    },
}

/// Log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Information request
#[derive(Debug, Clone)]
pub enum InfoRequest {
    /// Need route discovery
    DiscoverRoute(NodeId),
    /// Need trust verification
    VerifyTrust(NodeId),
    /// Need protocol identification
    IdentifyProtocol(Vec<u8>),
}

/// Request to Tier 3
#[derive(Debug, Clone)]
pub struct Tier3Request {
    /// Context for the request
    pub context: String,
    /// Raw data if relevant
    pub data: Option<Vec<u8>>,
    /// Priority (higher = more urgent)
    pub priority: u8,
}

/// Base trait for all smart agents
pub trait Agent {
    /// Get agent type
    fn agent_type(&self) -> AgentType;

    /// Process an escalation from Tier 1
    fn handle_escalation(&mut self, reason: &EscalateReason, packet: &[u8], context: &Context) -> Decision;

    /// Learn from feedback
    fn learn(&mut self, sample: &LearningSample);

    /// Get agent statistics
    fn stats(&self) -> AgentStats;
}

/// Context for agent decisions
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Current timestamp
    pub now: u64,
    /// Source node (if known)
    pub source: Option<NodeId>,
    /// Destination node (if known)
    pub destination: Option<NodeId>,
    /// Local node ID
    pub local_id: NodeId,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Learning sample for agents
#[derive(Debug, Clone)]
pub struct LearningSample {
    /// Input that triggered decision
    pub input: Vec<u8>,
    /// Decision that was made
    pub decision: Decision,
    /// Was it correct?
    pub correct: bool,
    /// Feedback from higher tier
    pub feedback: Option<String>,
}

/// Agent statistics
#[derive(Debug, Clone, Default)]
pub struct AgentStats {
    /// Decisions made
    pub decisions: u64,
    /// Successful decisions
    pub successes: u64,
    /// Failed decisions
    pub failures: u64,
    /// Escalations to Tier 3
    pub escalations: u64,
}

// =========================================================================
// ROUTING AGENT
// =========================================================================

/// Routing specialist - understands network topology
pub struct RoutingAgent {
    config: AgentConfig,
    /// Known topology (simplified representation)
    topology: HashMap<NodeId, Vec<NodeId>>,
    /// Route discovery in progress
    discoveries: HashMap<NodeId, RouteDiscovery>,
    /// Learning history
    history: Vec<LearningSample>,
    stats: AgentStats,
}

#[derive(Debug, Clone)]
struct RouteDiscovery {
    target: NodeId,
    started: u64,
    attempts: u8,
    responses: Vec<(NodeId, u8)>, // (next_hop, hop_count)
}

impl RoutingAgent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            topology: HashMap::new(),
            discoveries: HashMap::new(),
            history: Vec::new(),
            stats: AgentStats::default(),
        }
    }

    /// Add known neighbor
    pub fn add_neighbor(&mut self, neighbor: NodeId) {
        self.topology.entry(neighbor).or_insert_with(Vec::new);
    }

    /// Process route response
    pub fn on_route_response(&mut self, target: NodeId, via: NodeId, hop_count: u8) {
        if let Some(discovery) = self.discoveries.get_mut(&target) {
            discovery.responses.push((via, hop_count));
        }
    }

    /// Select best route from discovered options
    fn select_best_route(&self, target: &NodeId) -> Option<NodeId> {
        self.discoveries.get(target).and_then(|d| {
            d.responses.iter()
                .min_by_key(|(_, hops)| *hops)
                .map(|(via, _)| via.clone())
        })
    }
}

impl Agent for RoutingAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Routing
    }

    fn handle_escalation(&mut self, reason: &EscalateReason, _packet: &[u8], context: &Context) -> Decision {
        self.stats.decisions += 1;

        match reason {
            EscalateReason::NoRoute => {
                let dest = context.destination.clone().unwrap_or_default();

                // Check if we're already discovering
                if let Some(discovery) = self.discoveries.get(&dest) {
                    if let Some(best) = self.select_best_route(&dest) {
                        self.stats.successes += 1;
                        return Decision::Action(AgentAction::AddRoute {
                            destination: dest,
                            next_hop: best,
                            protocol: protocols::AXIOM,
                        });
                    }
                }

                // Start discovery
                self.discoveries.insert(dest.clone(), RouteDiscovery {
                    target: dest.clone(),
                    started: context.now,
                    attempts: 1,
                    responses: Vec::new(),
                });

                Decision::NeedInfo(InfoRequest::DiscoverRoute(dest))
            }
            _ => {
                self.stats.escalations += 1;
                Decision::Escalate(Tier3Request {
                    context: alloc::format!("Routing agent can't handle: {:?}", reason),
                    data: None,
                    priority: 1,
                })
            }
        }
    }

    fn learn(&mut self, sample: &LearningSample) {
        if self.history.len() >= self.config.max_samples {
            self.history.remove(0);
        }
        self.history.push(sample.clone());

        if sample.correct {
            self.stats.successes += 1;
        } else {
            self.stats.failures += 1;
        }
    }

    fn stats(&self) -> AgentStats {
        self.stats.clone()
    }
}

// =========================================================================
// TRUST AGENT
// =========================================================================

/// Trust specialist - evaluates node behavior
pub struct TrustAgent {
    config: AgentConfig,
    /// Behavior history per node
    behavior: HashMap<NodeId, BehaviorHistory>,
    /// Learning history
    history: Vec<LearningSample>,
    stats: AgentStats,
}

#[derive(Debug, Clone, Default)]
struct BehaviorHistory {
    /// Good interactions
    good: u64,
    /// Bad interactions
    bad: u64,
    /// Last interaction timestamp
    last_seen: u64,
    /// Current computed trust score (0.0 - 1.0)
    score: f32,
}

impl TrustAgent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            behavior: HashMap::new(),
            history: Vec::new(),
            stats: AgentStats::default(),
        }
    }

    /// Record good behavior
    pub fn record_good(&mut self, node: &NodeId, now: u64) {
        let history = self.behavior.entry(node.clone()).or_default();
        history.good += 1;
        history.last_seen = now;
        let (good, bad) = (history.good, history.bad);
        history.score = Self::compute_score_static(good, bad);
    }

    /// Record bad behavior
    pub fn record_bad(&mut self, node: &NodeId, now: u64) {
        let history = self.behavior.entry(node.clone()).or_default();
        history.bad += 1;
        history.last_seen = now;
        let (good, bad) = (history.good, history.bad);
        history.score = Self::compute_score_static(good, bad);
    }

    /// Compute trust score (static version for borrow checker)
    fn compute_score_static(good: u64, bad: u64) -> f32 {
        if good + bad == 0 {
            return 0.5; // Unknown
        }
        good as f32 / (good + bad) as f32
    }

    /// Compute trust score
    fn compute_score(&self, good: u64, bad: u64) -> f32 {
        Self::compute_score_static(good, bad)
    }

    /// Get trust level from score
    fn score_to_trust(&self, score: f32) -> TrustLevel {
        if score >= 0.9 {
            TrustLevel::Full
        } else if score >= 0.7 {
            TrustLevel::Sig
        } else if score >= 0.4 {
            TrustLevel::Compress
        } else {
            TrustLevel::Raw
        }
    }
}

impl Agent for TrustAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Trust
    }

    fn handle_escalation(&mut self, reason: &EscalateReason, _packet: &[u8], context: &Context) -> Decision {
        self.stats.decisions += 1;

        match reason {
            EscalateReason::UnknownSource | EscalateReason::TrustDecisionNeeded => {
                let source = context.source.clone().unwrap_or_default();

                // Check behavior history
                if let Some(history) = self.behavior.get(&source) {
                    if history.good + history.bad >= 10 {
                        // Have enough data to decide
                        let trust = self.score_to_trust(history.score);
                        self.stats.successes += 1;
                        return Decision::Action(AgentAction::SetTrust {
                            node_id: source,
                            trust,
                        });
                    }
                }

                // Not enough data - start verification
                Decision::NeedInfo(InfoRequest::VerifyTrust(source))
            }
            _ => {
                self.stats.escalations += 1;
                Decision::Escalate(Tier3Request {
                    context: alloc::format!("Trust agent can't handle: {:?}", reason),
                    data: None,
                    priority: 2,
                })
            }
        }
    }

    fn learn(&mut self, sample: &LearningSample) {
        if self.history.len() >= self.config.max_samples {
            self.history.remove(0);
        }
        self.history.push(sample.clone());

        if sample.correct {
            self.stats.successes += 1;
        } else {
            self.stats.failures += 1;
        }
    }

    fn stats(&self) -> AgentStats {
        self.stats.clone()
    }
}

// =========================================================================
// SECURITY AGENT
// =========================================================================

/// Security specialist - detects anomalies and threats
pub struct SecurityAgent {
    config: AgentConfig,
    /// Suspicious patterns
    suspicious_patterns: Vec<SuspiciousPattern>,
    /// Blocked nodes with expiry
    blocked: HashMap<NodeId, u64>,
    /// Recent alerts
    alerts: Vec<SecurityAlert>,
    /// Learning history
    history: Vec<LearningSample>,
    stats: AgentStats,
}

#[derive(Debug, Clone)]
struct SuspiciousPattern {
    /// Pattern description
    description: String,
    /// Byte pattern to match
    pattern: Vec<u8>,
    /// Severity (1-10)
    severity: u8,
}

#[derive(Debug, Clone)]
struct SecurityAlert {
    /// Timestamp
    timestamp: u64,
    /// Source of alert
    source: Option<NodeId>,
    /// Alert description
    description: String,
    /// Severity (1-10)
    severity: u8,
}

impl SecurityAgent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            suspicious_patterns: Vec::new(),
            blocked: HashMap::new(),
            alerts: Vec::new(),
            history: Vec::new(),
            stats: AgentStats::default(),
        }
    }

    /// Add a suspicious pattern to detect
    pub fn add_pattern(&mut self, description: String, pattern: Vec<u8>, severity: u8) {
        self.suspicious_patterns.push(SuspiciousPattern {
            description,
            pattern,
            severity,
        });
    }

    /// Check packet for suspicious patterns
    fn check_patterns(&self, packet: &[u8]) -> Option<&SuspiciousPattern> {
        for pattern in &self.suspicious_patterns {
            if packet.windows(pattern.pattern.len())
                .any(|window| window == pattern.pattern.as_slice())
            {
                return Some(pattern);
            }
        }
        None
    }

    /// Get recent alerts
    pub fn recent_alerts(&self, count: usize) -> &[SecurityAlert] {
        let start = self.alerts.len().saturating_sub(count);
        &self.alerts[start..]
    }
}

impl Agent for SecurityAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Security
    }

    fn handle_escalation(&mut self, reason: &EscalateReason, packet: &[u8], context: &Context) -> Decision {
        self.stats.decisions += 1;

        match reason {
            EscalateReason::Suspicious => {
                // Check for known malicious patterns - clone data to avoid borrow issues
                let pattern_match = self.check_patterns(packet).map(|p| {
                    (p.description.clone(), p.severity)
                });

                if let Some((description, severity)) = pattern_match {
                    let source = context.source.clone();

                    self.alerts.push(SecurityAlert {
                        timestamp: context.now,
                        source: source.clone(),
                        description: description.clone(),
                        severity,
                    });

                    if severity >= 7 {
                        // High severity - block source
                        if let Some(src) = source {
                            self.stats.successes += 1;
                            return Decision::Action(AgentAction::Block {
                                node_id: src,
                                duration_ms: 3600_000, // 1 hour
                            });
                        }
                    }

                    // Log and drop
                    self.stats.successes += 1;
                    return Decision::Action(AgentAction::Log {
                        level: LogLevel::Warn,
                        message: description,
                    });
                }

                // No pattern match - allow with logging
                Decision::Action(AgentAction::Allow)
            }
            _ => {
                self.stats.escalations += 1;
                Decision::Escalate(Tier3Request {
                    context: alloc::format!("Security agent can't handle: {:?}", reason),
                    data: Some(packet.to_vec()),
                    priority: 3,
                })
            }
        }
    }

    fn learn(&mut self, sample: &LearningSample) {
        if self.history.len() >= self.config.max_samples {
            self.history.remove(0);
        }
        self.history.push(sample.clone());

        if sample.correct {
            self.stats.successes += 1;
        } else {
            self.stats.failures += 1;
        }
    }

    fn stats(&self) -> AgentStats {
        self.stats.clone()
    }
}

// =========================================================================
// SMART AGENT MANAGER
// =========================================================================

/// Manages multiple smart agents
pub struct SmartAgent {
    /// Routing agent
    routing: RoutingAgent,
    /// Trust agent
    trust: TrustAgent,
    /// Security agent
    security: SecurityAgent,
    /// Reference to Tier 1 translator
    translator: Option<*mut Translator>,
}

impl SmartAgent {
    /// Create a new smart agent manager
    pub fn new(config: AgentConfig) -> Self {
        Self {
            routing: RoutingAgent::new(config.clone()),
            trust: TrustAgent::new(config.clone()),
            security: SecurityAgent::new(config),
            translator: None,
        }
    }

    /// Link to Tier 1 translator for updates
    ///
    /// # Safety
    /// The translator pointer must remain valid for the lifetime of the SmartAgent
    pub unsafe fn link_translator(&mut self, translator: *mut Translator) {
        self.translator = Some(translator);
    }

    /// Handle escalation from Tier 1
    pub fn handle(&mut self, reason: &EscalateReason, packet: &[u8], context: &Context) -> Decision {
        // Route to appropriate agent
        match reason {
            EscalateReason::NoRoute => self.routing.handle_escalation(reason, packet, context),
            EscalateReason::UnknownSource | EscalateReason::TrustDecisionNeeded => {
                self.trust.handle_escalation(reason, packet, context)
            }
            EscalateReason::Suspicious => self.security.handle_escalation(reason, packet, context),
            EscalateReason::UnknownProtocol => {
                // Protocol agent would handle this - escalate for now
                Decision::Escalate(Tier3Request {
                    context: "Unknown protocol".into(),
                    data: Some(packet.to_vec()),
                    priority: 1,
                })
            }
        }
    }

    /// Apply action to Tier 1 translator
    ///
    /// # Safety
    /// Requires valid translator link
    pub unsafe fn apply_action(&mut self, action: &AgentAction, now: u64) {
        if let Some(translator) = self.translator {
            let translator = &mut *translator;
            match action {
                AgentAction::AddRoute { destination, next_hop, protocol } => {
                    translator.add_route(destination.clone(), next_hop.clone(), *protocol, now);
                }
                AgentAction::RemoveRoute { destination } => {
                    translator.remove_route(destination);
                }
                AgentAction::SetTrust { node_id, trust } => {
                    translator.add_trust(node_id.clone(), *trust, now);
                }
                AgentAction::Block { node_id, duration_ms } => {
                    translator.block(node_id.clone(), now + duration_ms);
                }
                _ => {}
            }
        }
    }

    /// Get combined statistics
    pub fn stats(&self) -> HashMap<AgentType, AgentStats> {
        let mut map = HashMap::new();
        map.insert(AgentType::Routing, self.routing.stats());
        map.insert(AgentType::Trust, self.trust.stats());
        map.insert(AgentType::Security, self.security.stats());
        map
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_routing_agent_discovery() {
        let mut agent = RoutingAgent::new(AgentConfig::default());

        let context = Context {
            now: 1000,
            destination: Some(test_node_id(5)),
            local_id: test_node_id(1),
            ..Default::default()
        };

        let decision = agent.handle_escalation(
            &EscalateReason::NoRoute,
            &[],
            &context,
        );

        match decision {
            Decision::NeedInfo(InfoRequest::DiscoverRoute(dest)) => {
                assert_eq!(dest, test_node_id(5));
            }
            _ => panic!("Expected NeedInfo(DiscoverRoute)"),
        }
    }

    #[test]
    fn test_routing_agent_with_response() {
        let mut agent = RoutingAgent::new(AgentConfig::default());
        let target = test_node_id(5);

        // First call starts discovery
        let context = Context {
            now: 1000,
            destination: Some(target.clone()),
            local_id: test_node_id(1),
            ..Default::default()
        };
        agent.handle_escalation(&EscalateReason::NoRoute, &[], &context);

        // Simulate route responses
        agent.on_route_response(target.clone(), test_node_id(2), 2);
        agent.on_route_response(target.clone(), test_node_id(3), 1); // Better

        // Second call should select best route
        let decision = agent.handle_escalation(&EscalateReason::NoRoute, &[], &context);

        match decision {
            Decision::Action(AgentAction::AddRoute { next_hop, .. }) => {
                assert_eq!(next_hop, test_node_id(3)); // Shorter path
            }
            _ => panic!("Expected Action(AddRoute)"),
        }
    }

    #[test]
    fn test_trust_agent_with_history() {
        let mut agent = TrustAgent::new(AgentConfig::default());
        let source = test_node_id(5);

        // Build up good history
        for _ in 0..15 {
            agent.record_good(&source, 1000);
        }

        let context = Context {
            now: 2000,
            source: Some(source.clone()),
            local_id: test_node_id(1),
            ..Default::default()
        };

        let decision = agent.handle_escalation(
            &EscalateReason::TrustDecisionNeeded,
            &[],
            &context,
        );

        match decision {
            Decision::Action(AgentAction::SetTrust { trust, .. }) => {
                assert_eq!(trust, TrustLevel::Full); // 100% good
            }
            _ => panic!("Expected Action(SetTrust)"),
        }
    }

    #[test]
    fn test_trust_agent_unknown() {
        let mut agent = TrustAgent::new(AgentConfig::default());

        let context = Context {
            now: 1000,
            source: Some(test_node_id(99)), // Never seen
            local_id: test_node_id(1),
            ..Default::default()
        };

        let decision = agent.handle_escalation(
            &EscalateReason::UnknownSource,
            &[],
            &context,
        );

        match decision {
            Decision::NeedInfo(InfoRequest::VerifyTrust(_)) => {}
            _ => panic!("Expected NeedInfo(VerifyTrust)"),
        }
    }

    #[test]
    fn test_security_agent_pattern_match() {
        let mut agent = SecurityAgent::new(AgentConfig::default());

        // Add malicious pattern
        agent.add_pattern(
            "Test malware signature".into(),
            vec![0xBA, 0xAD, 0xC0, 0xDE],
            8,
        );

        let packet = vec![0x00, 0x00, 0xBA, 0xAD, 0xC0, 0xDE, 0x00];
        let context = Context {
            now: 1000,
            source: Some(test_node_id(5)),
            local_id: test_node_id(1),
            ..Default::default()
        };

        let decision = agent.handle_escalation(
            &EscalateReason::Suspicious,
            &packet,
            &context,
        );

        match decision {
            Decision::Action(AgentAction::Block { .. }) => {
                // High severity should block
                assert_eq!(agent.recent_alerts(10).len(), 1);
            }
            _ => panic!("Expected Action(Block)"),
        }
    }

    #[test]
    fn test_smart_agent_manager() {
        let mut manager = SmartAgent::new(AgentConfig::default());

        let context = Context {
            now: 1000,
            destination: Some(test_node_id(5)),
            local_id: test_node_id(1),
            ..Default::default()
        };

        // Test routing escalation
        let decision = manager.handle(&EscalateReason::NoRoute, &[], &context);
        assert!(matches!(decision, Decision::NeedInfo(InfoRequest::DiscoverRoute(_))));

        // Test trust escalation
        let context2 = Context {
            source: Some(test_node_id(3)),
            ..context.clone()
        };
        let decision2 = manager.handle(&EscalateReason::UnknownSource, &[], &context2);
        assert!(matches!(decision2, Decision::NeedInfo(InfoRequest::VerifyTrust(_))));

        // Check stats
        let stats = manager.stats();
        assert_eq!(stats.get(&AgentType::Routing).unwrap().decisions, 1);
        assert_eq!(stats.get(&AgentType::Trust).unwrap().decisions, 1);
    }
}
