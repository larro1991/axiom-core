//! Security Engine - Unified SENTINEL Integration
//!
//! Orchestrates all SENTINEL components (Guardian, Watcher, Analyst, Responder)
//! and provides tiered intelligence for packet processing decisions.

use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};

// ============================================================================
// TIERED INTELLIGENCE (no_std compatible)
// ============================================================================

/// Tier 1 decision - microsecond latency using lookup tables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier1Decision {
    /// Allow packet through (fast path)
    Allow,
    /// Block immediately (known bad)
    Block,
    /// Escalate to Tier 2 for analysis
    Escalate,
}

/// Tier 2 decision - millisecond latency using smart agents
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier2Decision {
    /// Allow with monitoring
    Allow,
    /// Block with reason
    Block(String),
    /// Rate limit this source
    RateLimit,
    /// Escalate to Tier 3 AI
    EscalateToAi,
    /// Generate alert
    Alert(String),
}

/// Tier 3 decision - second latency using full AI analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier3Decision {
    /// Allow - no threat detected
    Allow,
    /// Block with detailed analysis
    Block { reason: String, confidence: u8 },
    /// Quarantine the source
    Quarantine { source: [u8; 4], duration_secs: u64 },
    /// Create incident for SOC review
    CreateIncident { title: String, severity: u8 },
}

/// Tiered Intelligence statistics
#[derive(Debug, Default, Clone)]
pub struct TieredStats {
    pub tier1_allow: u64,
    pub tier1_block: u64,
    pub tier1_escalate: u64,
    pub tier2_allow: u64,
    pub tier2_block: u64,
    pub tier2_rate_limit: u64,
    pub tier2_escalate: u64,
    pub tier3_decisions: u64,
}

/// Tier 1 Engine - Microsecond decisions via lookup tables
#[derive(Debug)]
pub struct Tier1Engine {
    /// Blocked MAC addresses
    blocked_macs: HashSet<[u8; 6]>,
    /// Blocked IP addresses
    blocked_ips: HashSet<[u8; 4]>,
    /// Trusted MAC addresses (fast path)
    trusted_macs: HashSet<[u8; 6]>,
    /// Trusted IP addresses (fast path)
    trusted_ips: HashSet<[u8; 4]>,
    /// Rate limited IPs with reset timestamp
    rate_limited: HashMap<[u8; 4], u64>,
}

impl Tier1Engine {
    pub fn new() -> Self {
        Self {
            blocked_macs: HashSet::new(),
            blocked_ips: HashSet::new(),
            trusted_macs: HashSet::new(),
            trusted_ips: HashSet::new(),
            rate_limited: HashMap::new(),
        }
    }

    /// Fast decision based on lookup tables only
    pub fn decide(&self, src_mac: &[u8; 6], src_ip: &[u8; 4], now: u64) -> Tier1Decision {
        // Check blocklists first
        if self.blocked_macs.contains(src_mac) {
            return Tier1Decision::Block;
        }
        if self.blocked_ips.contains(src_ip) {
            return Tier1Decision::Block;
        }

        // Check rate limiting
        if let Some(&reset_time) = self.rate_limited.get(src_ip) {
            if now < reset_time {
                return Tier1Decision::Block;
            }
        }

        // Check trusted sources (fast path)
        if self.trusted_macs.contains(src_mac) || self.trusted_ips.contains(src_ip) {
            return Tier1Decision::Allow;
        }

        // Unknown source - escalate for analysis
        Tier1Decision::Escalate
    }

    pub fn block_mac(&mut self, mac: [u8; 6]) {
        self.blocked_macs.insert(mac);
        self.trusted_macs.remove(&mac);
    }

    pub fn block_ip(&mut self, ip: [u8; 4]) {
        self.blocked_ips.insert(ip);
        self.trusted_ips.remove(&ip);
    }

    pub fn trust_mac(&mut self, mac: [u8; 6]) {
        self.trusted_macs.insert(mac);
        self.blocked_macs.remove(&mac);
    }

    pub fn trust_ip(&mut self, ip: [u8; 4]) {
        self.trusted_ips.insert(ip);
        self.blocked_ips.remove(&ip);
    }

    pub fn rate_limit(&mut self, ip: [u8; 4], until: u64) {
        self.rate_limited.insert(ip, until);
    }

    pub fn unblock_mac(&mut self, mac: &[u8; 6]) {
        self.blocked_macs.remove(mac);
    }

    pub fn unblock_ip(&mut self, ip: &[u8; 4]) {
        self.blocked_ips.remove(ip);
    }

    /// Cleanup expired rate limits
    pub fn cleanup(&mut self, now: u64) {
        self.rate_limited.retain(|_, &mut reset| reset > now);
    }

    /// Get blocked MAC count
    pub fn blocked_mac_count(&self) -> usize {
        self.blocked_macs.len()
    }

    /// Get blocked IP count
    pub fn blocked_ip_count(&self) -> usize {
        self.blocked_ips.len()
    }
}

impl Default for Tier1Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Tier 2 Engine - Smart agent analysis (millisecond decisions)
#[derive(Debug)]
pub struct Tier2Engine {
    /// Suspicious source tracking (IP -> suspicion score)
    suspicion_scores: HashMap<[u8; 4], u32>,
    /// Suspicion threshold for escalation
    escalation_threshold: u32,
    /// Block threshold (auto-block if exceeded)
    block_threshold: u32,
    /// Alert threshold
    alert_threshold: u32,
}

impl Tier2Engine {
    pub fn new() -> Self {
        Self {
            suspicion_scores: HashMap::new(),
            escalation_threshold: 50,
            block_threshold: 100,
            alert_threshold: 25,
        }
    }

    /// Analyze based on alert count and severity
    pub fn decide(
        &mut self,
        src_ip: [u8; 4],
        alert_count: usize,
        total_severity: u32,
    ) -> Tier2Decision {
        // No alerts = allow with monitoring
        if alert_count == 0 {
            return Tier2Decision::Allow;
        }

        // Update suspicion score
        let score = self.suspicion_scores.entry(src_ip).or_insert(0);
        *score = score.saturating_add(total_severity);

        // Decision based on score
        if *score >= self.block_threshold {
            return Tier2Decision::Block(alloc::format!(
                "Suspicion score {} exceeds threshold", score
            ));
        }

        if *score >= self.escalation_threshold {
            return Tier2Decision::EscalateToAi;
        }

        if *score >= self.alert_threshold {
            return Tier2Decision::Alert(alloc::format!(
                "Elevated suspicion from {:?}: score {}", src_ip, score
            ));
        }

        if alert_count >= 3 {
            return Tier2Decision::RateLimit;
        }

        Tier2Decision::Allow
    }

    /// Decay suspicion scores over time
    pub fn decay(&mut self, amount: u32) {
        for (_, score) in self.suspicion_scores.iter_mut() {
            *score = score.saturating_sub(amount);
        }
        self.suspicion_scores.retain(|_, &mut score| score > 0);
    }

    /// Reset suspicion for an IP
    pub fn reset_suspicion(&mut self, ip: &[u8; 4]) {
        self.suspicion_scores.remove(ip);
    }

    /// Get suspicion score for an IP
    pub fn get_suspicion(&self, ip: &[u8; 4]) -> u32 {
        self.suspicion_scores.get(ip).copied().unwrap_or(0)
    }
}

impl Default for Tier2Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Tiered Intelligence Engine
#[derive(Debug)]
pub struct TieredIntelligence {
    /// Tier 1: Fast lookup tables
    tier1: Tier1Engine,
    /// Tier 2: Smart agent analysis
    tier2: Tier2Engine,
    /// Tier 3 enabled (requires external AI)
    tier3_enabled: bool,
    /// Statistics
    stats: TieredStats,
}

impl TieredIntelligence {
    pub fn new() -> Self {
        Self {
            tier1: Tier1Engine::new(),
            tier2: Tier2Engine::new(),
            tier3_enabled: false,
            stats: TieredStats::default(),
        }
    }

    pub fn tier1(&self) -> &Tier1Engine {
        &self.tier1
    }

    pub fn tier1_mut(&mut self) -> &mut Tier1Engine {
        &mut self.tier1
    }

    pub fn tier2(&self) -> &Tier2Engine {
        &self.tier2
    }

    pub fn tier2_mut(&mut self) -> &mut Tier2Engine {
        &mut self.tier2
    }

    pub fn stats(&self) -> &TieredStats {
        &self.stats
    }

    pub fn enable_tier3(&mut self, enabled: bool) {
        self.tier3_enabled = enabled;
    }

    /// Record Tier 1 decision
    pub fn record_tier1(&mut self, decision: Tier1Decision) {
        match decision {
            Tier1Decision::Allow => self.stats.tier1_allow += 1,
            Tier1Decision::Block => self.stats.tier1_block += 1,
            Tier1Decision::Escalate => self.stats.tier1_escalate += 1,
        }
    }

    /// Record Tier 2 decision
    pub fn record_tier2(&mut self, decision: &Tier2Decision) {
        match decision {
            Tier2Decision::Allow => self.stats.tier2_allow += 1,
            Tier2Decision::Block(_) => self.stats.tier2_block += 1,
            Tier2Decision::RateLimit => self.stats.tier2_rate_limit += 1,
            Tier2Decision::EscalateToAi => self.stats.tier2_escalate += 1,
            Tier2Decision::Alert(_) => {} // Alerts don't change allow/block stats
        }
    }

    /// Record Tier 3 decision
    pub fn record_tier3(&mut self) {
        self.stats.tier3_decisions += 1;
    }

    /// Periodic maintenance
    pub fn maintain(&mut self, now: u64) {
        self.tier1.cleanup(now);
        self.tier2.decay(1);
    }
}

impl Default for TieredIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SECURITY ENGINE (no_std compatible core)
// ============================================================================

/// Security Engine Configuration
#[derive(Debug, Clone)]
pub struct SecurityEngineConfig {
    /// Enable Layer 2 monitoring (Guardian)
    pub enable_layer2: bool,
    /// Enable Layer 3-7 monitoring (Watcher)
    pub enable_layer3_7: bool,
    /// Enable event correlation (Analyst)
    pub enable_correlation: bool,
    /// Enable automated response (Responder)
    pub enable_response: bool,
    /// Dry run mode (log actions but don't execute)
    pub dry_run: bool,
}

impl Default for SecurityEngineConfig {
    fn default() -> Self {
        Self {
            enable_layer2: true,
            enable_layer3_7: true,
            enable_correlation: true,
            enable_response: true,
            dry_run: true, // Safe default
        }
    }
}

/// Security Engine Statistics
#[derive(Debug, Default, Clone)]
pub struct SecurityEngineStats {
    /// Total frames processed
    pub frames_processed: u64,
    /// Total packets processed
    pub packets_processed: u64,
    /// Layer 2 alerts generated
    pub layer2_alerts: u64,
    /// Layer 3-7 alerts generated
    pub layer3_7_alerts: u64,
    /// Packets blocked
    pub packets_blocked: u64,
    /// Packets allowed
    pub packets_allowed: u64,
}

/// Result of security processing
#[derive(Debug, Clone)]
pub struct SecurityResult {
    /// Should the packet be allowed?
    pub allow: bool,
    /// Reason for decision
    pub reason: String,
    /// Alert count
    pub alert_count: usize,
    /// Tier that made the decision
    pub decision_tier: u8,
}

/// Security Engine - Orchestrates tiered intelligence
///
/// This is the no_std compatible core. For full SENTINEL integration,
/// use SecurityEngineStd with the std feature.
#[derive(Debug)]
pub struct SecurityEngine {
    /// Configuration
    config: SecurityEngineConfig,
    /// Tiered intelligence
    tiered: TieredIntelligence,
    /// Statistics
    stats: SecurityEngineStats,
}

impl SecurityEngine {
    /// Create new Security Engine with configuration
    pub fn new(config: SecurityEngineConfig) -> Self {
        Self {
            config,
            tiered: TieredIntelligence::new(),
            stats: SecurityEngineStats::default(),
        }
    }

    /// Process a frame through Tier 1 only (no_std compatible)
    pub fn process_tier1(&mut self, src_mac: &[u8; 6], src_ip: &[u8; 4], now: u64) -> SecurityResult {
        self.stats.frames_processed += 1;

        let decision = self.tiered.tier1().decide(src_mac, src_ip, now);
        self.tiered.record_tier1(decision);

        match decision {
            Tier1Decision::Block => {
                self.stats.packets_blocked += 1;
                SecurityResult {
                    allow: false,
                    reason: "Blocked by Tier 1 (blocklist)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                }
            }
            Tier1Decision::Allow => {
                self.stats.packets_allowed += 1;
                SecurityResult {
                    allow: true,
                    reason: "Allowed by Tier 1 (trusted)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                }
            }
            Tier1Decision::Escalate => {
                // In no_std mode, we just allow with monitoring
                self.stats.packets_allowed += 1;
                SecurityResult {
                    allow: true,
                    reason: "Unknown source (escalated)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                }
            }
        }
    }

    /// Process through Tier 1 and Tier 2
    pub fn process_tier1_2(
        &mut self,
        src_mac: &[u8; 6],
        src_ip: &[u8; 4],
        alert_count: usize,
        total_severity: u32,
        now: u64,
    ) -> SecurityResult {
        self.stats.frames_processed += 1;

        // Tier 1: Fast path check
        let tier1_decision = self.tiered.tier1().decide(src_mac, src_ip, now);
        self.tiered.record_tier1(tier1_decision);

        match tier1_decision {
            Tier1Decision::Block => {
                self.stats.packets_blocked += 1;
                return SecurityResult {
                    allow: false,
                    reason: "Blocked by Tier 1 (blocklist)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Allow => {
                self.stats.packets_allowed += 1;
                return SecurityResult {
                    allow: true,
                    reason: "Allowed by Tier 1 (trusted)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Escalate => {
                // Continue to Tier 2
            }
        }

        // Tier 2: Smart agent analysis
        let tier2_decision = self.tiered.tier2_mut().decide(*src_ip, alert_count, total_severity);
        self.tiered.record_tier2(&tier2_decision);

        let (allow, reason) = match tier2_decision {
            Tier2Decision::Allow => (true, "Allowed by Tier 2".into()),
            Tier2Decision::Block(r) => {
                self.tiered.tier1_mut().block_ip(*src_ip);
                (false, alloc::format!("Blocked by Tier 2: {}", r))
            }
            Tier2Decision::RateLimit => {
                self.tiered.tier1_mut().rate_limit(*src_ip, now + 60);
                (true, "Rate limited by Tier 2".into())
            }
            Tier2Decision::Alert(msg) => (true, alloc::format!("Alert: {}", msg)),
            Tier2Decision::EscalateToAi => {
                self.tiered.record_tier3();
                (true, "Escalated to Tier 3 (allowed pending AI)".into())
            }
        };

        if allow {
            self.stats.packets_allowed += 1;
        } else {
            self.stats.packets_blocked += 1;
        }

        SecurityResult {
            allow,
            reason,
            alert_count,
            decision_tier: 2,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &SecurityEngineConfig {
        &self.config
    }

    /// Get statistics
    pub fn stats(&self) -> &SecurityEngineStats {
        &self.stats
    }

    /// Get tiered intelligence stats
    pub fn tiered_stats(&self) -> &TieredStats {
        self.tiered.stats()
    }

    /// Get tiered intelligence
    pub fn tiered(&self) -> &TieredIntelligence {
        &self.tiered
    }

    /// Get mutable tiered intelligence
    pub fn tiered_mut(&mut self) -> &mut TieredIntelligence {
        &mut self.tiered
    }

    /// Manually trust a source
    pub fn trust_source(&mut self, ip: [u8; 4], mac: Option<[u8; 6]>) {
        self.tiered.tier1_mut().trust_ip(ip);
        if let Some(m) = mac {
            self.tiered.tier1_mut().trust_mac(m);
        }
    }

    /// Manually block a source
    pub fn block_source(&mut self, ip: [u8; 4], mac: Option<[u8; 6]>) {
        self.tiered.tier1_mut().block_ip(ip);
        if let Some(m) = mac {
            self.tiered.tier1_mut().block_mac(m);
        }
    }

    /// Periodic maintenance
    pub fn maintain(&mut self, now: u64) {
        self.tiered.maintain(now);
    }
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new(SecurityEngineConfig::default())
    }
}

// ============================================================================
// FULL SENTINEL INTEGRATION (std feature required)
// ============================================================================

#[cfg(feature = "std")]
use axiom_guardian::{Guardian, GuardianConfig, GuardianAlert};
#[cfg(feature = "std")]
use axiom_watcher::{Watcher, WatcherConfig, WatcherAlert};
#[cfg(feature = "std")]
use axiom_analyst::{Analyst, AnalystConfig, Incident};
#[cfg(feature = "std")]
use axiom_responder::{Responder, ResponderConfig, ActionResult};

/// Full Security Engine with SENTINEL integration (requires std)
#[cfg(feature = "std")]
pub struct SecurityEngineStd {
    /// Base security engine (tiered intelligence)
    base: SecurityEngine,
    /// Layer 2 defense (Guardian)
    guardian: Guardian,
    /// Layer 3-7 analysis (Watcher)
    watcher: Watcher,
    /// Event correlation (Analyst)
    analyst: Analyst,
    /// Automated response (Responder)
    responder: Responder,
    /// Recent incidents
    recent_incidents: Vec<Incident>,
    /// Action history
    action_history: Vec<ActionResult>,
}

#[cfg(feature = "std")]
impl SecurityEngineStd {
    /// Create new full Security Engine
    pub fn new(config: SecurityEngineConfig) -> Self {
        let guardian_config = GuardianConfig::default();
        let watcher_config = WatcherConfig::default();
        let analyst_config = AnalystConfig::default();
        let responder_config = ResponderConfig {
            dry_run: config.dry_run,
            ..Default::default()
        };

        Self {
            base: SecurityEngine::new(config),
            guardian: Guardian::new(guardian_config),
            watcher: Watcher::new(watcher_config),
            analyst: Analyst::new(analyst_config),
            responder: Responder::new(responder_config),
            recent_incidents: Vec::new(),
            action_history: Vec::new(),
        }
    }

    /// Process an Ethernet frame through full SENTINEL stack
    pub fn process_frame(&mut self, frame: &[u8], switch_port: Option<u16>, timestamp: u64) -> SecurityResult {
        // Extract source MAC and IP
        let src_mac = if frame.len() >= 12 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&frame[6..12]);
            mac
        } else {
            [0u8; 6]
        };

        let src_ip = if frame.len() >= 30 {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&frame[26..30]);
            ip
        } else {
            [0u8; 4]
        };

        // Tier 1: Fast path check
        let tier1_decision = self.base.tiered.tier1().decide(&src_mac, &src_ip, timestamp);
        self.base.tiered.record_tier1(tier1_decision);

        match tier1_decision {
            Tier1Decision::Block => {
                self.base.stats.packets_blocked += 1;
                return SecurityResult {
                    allow: false,
                    reason: "Blocked by Tier 1 (blocklist)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Allow => {
                self.base.stats.packets_allowed += 1;
                return SecurityResult {
                    allow: true,
                    reason: "Allowed by Tier 1 (trusted)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Escalate => {
                // Continue to deeper analysis
            }
        }

        // Layer 2 analysis (Guardian)
        let guardian_alerts: Vec<GuardianAlert> = if self.base.config.enable_layer2 {
            self.guardian.process_frame(frame, switch_port, timestamp)
        } else {
            Vec::new()
        };

        self.base.stats.layer2_alerts += guardian_alerts.len() as u64;

        // Calculate total severity from alerts
        let alert_count = guardian_alerts.len();
        let total_severity: u32 = guardian_alerts.iter()
            .map(|a| {
                use axiom_guardian::detector::AnomalySeverity;
                match a.severity {
                    AnomalySeverity::Critical => 40,
                    AnomalySeverity::High => 30,
                    AnomalySeverity::Medium => 20,
                    AnomalySeverity::Low => 10,
                    AnomalySeverity::Info => 5,
                }
            })
            .sum();

        // Tier 2: Smart agent analysis
        let tier2_decision = self.base.tiered.tier2_mut().decide(src_ip, alert_count, total_severity);
        self.base.tiered.record_tier2(&tier2_decision);

        let (allow, reason) = match tier2_decision {
            Tier2Decision::Allow => (true, "Allowed by Tier 2".into()),
            Tier2Decision::Block(r) => {
                self.base.tiered.tier1_mut().block_ip(src_ip);
                (false, alloc::format!("Blocked by Tier 2: {}", r))
            }
            Tier2Decision::RateLimit => {
                self.base.tiered.tier1_mut().rate_limit(src_ip, timestamp + 60);
                (true, "Rate limited by Tier 2".into())
            }
            Tier2Decision::Alert(msg) => (true, alloc::format!("Alert: {}", msg)),
            Tier2Decision::EscalateToAi => {
                self.base.tiered.record_tier3();
                (true, "Escalated to Tier 3".into())
            }
        };

        if allow {
            self.base.stats.packets_allowed += 1;
        } else {
            self.base.stats.packets_blocked += 1;
        }

        self.base.stats.frames_processed += 1;

        SecurityResult {
            allow,
            reason,
            alert_count,
            decision_tier: 2,
        }
    }

    /// Process an IP packet through full SENTINEL stack
    pub fn process_packet(&mut self, packet: &[u8], timestamp: u64) -> SecurityResult {
        // Extract source IP
        let src_ip = if packet.len() >= 16 {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&packet[12..16]);
            ip
        } else {
            [0u8; 4]
        };

        let src_mac = [0u8; 6]; // No MAC in IP packet

        // Tier 1: Fast path check
        let tier1_decision = self.base.tiered.tier1().decide(&src_mac, &src_ip, timestamp);
        self.base.tiered.record_tier1(tier1_decision);

        match tier1_decision {
            Tier1Decision::Block => {
                self.base.stats.packets_blocked += 1;
                return SecurityResult {
                    allow: false,
                    reason: "Blocked by Tier 1 (blocklist)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Allow => {
                self.base.stats.packets_allowed += 1;
                return SecurityResult {
                    allow: true,
                    reason: "Allowed by Tier 1 (trusted)".into(),
                    alert_count: 0,
                    decision_tier: 1,
                };
            }
            Tier1Decision::Escalate => {
                // Continue to deeper analysis
            }
        }

        // Layer 3-7 analysis (Watcher)
        let watcher_alerts: Vec<WatcherAlert> = if self.base.config.enable_layer3_7 {
            self.watcher.process_packet(packet, timestamp)
        } else {
            Vec::new()
        };

        self.base.stats.layer3_7_alerts += watcher_alerts.len() as u64;

        // Calculate total severity from alerts
        let alert_count = watcher_alerts.len();
        let total_severity: u32 = watcher_alerts.iter()
            .map(|a| a.severity as u32)
            .sum();

        // Tier 2: Smart agent analysis
        let tier2_decision = self.base.tiered.tier2_mut().decide(src_ip, alert_count, total_severity);
        self.base.tiered.record_tier2(&tier2_decision);

        let (allow, reason) = match tier2_decision {
            Tier2Decision::Allow => (true, "Allowed by Tier 2".into()),
            Tier2Decision::Block(r) => {
                self.base.tiered.tier1_mut().block_ip(src_ip);
                (false, alloc::format!("Blocked by Tier 2: {}", r))
            }
            Tier2Decision::RateLimit => {
                self.base.tiered.tier1_mut().rate_limit(src_ip, timestamp + 60);
                (true, "Rate limited by Tier 2".into())
            }
            Tier2Decision::Alert(msg) => (true, alloc::format!("Alert: {}", msg)),
            Tier2Decision::EscalateToAi => {
                self.base.tiered.record_tier3();
                (true, "Escalated to Tier 3".into())
            }
        };

        if allow {
            self.base.stats.packets_allowed += 1;
        } else {
            self.base.stats.packets_blocked += 1;
        }

        self.base.stats.packets_processed += 1;

        SecurityResult {
            allow,
            reason,
            alert_count,
            decision_tier: 2,
        }
    }

    /// Get base security engine
    pub fn base(&self) -> &SecurityEngine {
        &self.base
    }

    /// Get mutable base security engine
    pub fn base_mut(&mut self) -> &mut SecurityEngine {
        &mut self.base
    }

    /// Get Guardian
    pub fn guardian(&self) -> &Guardian {
        &self.guardian
    }

    /// Get mutable Guardian
    pub fn guardian_mut(&mut self) -> &mut Guardian {
        &mut self.guardian
    }

    /// Get Watcher
    pub fn watcher(&self) -> &Watcher {
        &self.watcher
    }

    /// Get mutable Watcher
    pub fn watcher_mut(&mut self) -> &mut Watcher {
        &mut self.watcher
    }

    /// Get Analyst
    pub fn analyst(&self) -> &Analyst {
        &self.analyst
    }

    /// Get Responder
    pub fn responder(&self) -> &Responder {
        &self.responder
    }

    /// Get recent incidents
    pub fn recent_incidents(&self) -> &[Incident] {
        &self.recent_incidents
    }

    /// Get action history
    pub fn action_history(&self) -> &[ActionResult] {
        &self.action_history
    }

    /// Periodic maintenance
    pub fn maintain(&mut self, timestamp: u64) {
        self.base.maintain(timestamp);
        self.guardian.cleanup(timestamp);
        self.watcher.cleanup(timestamp);
    }

    /// Trust a source
    pub fn trust_source(&mut self, ip: [u8; 4], mac: Option<[u8; 6]>) {
        self.base.trust_source(ip, mac);
    }

    /// Block a source
    pub fn block_source(&mut self, ip: [u8; 4], mac: Option<[u8; 6]>) {
        self.base.block_source(ip, mac);
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_blocklist() {
        let mut tier1 = Tier1Engine::new();

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [192, 168, 1, 100];

        // Initially escalates (unknown)
        assert_eq!(tier1.decide(&mac, &ip, 1000), Tier1Decision::Escalate);

        // Block MAC
        tier1.block_mac(mac);
        assert_eq!(tier1.decide(&mac, &ip, 1000), Tier1Decision::Block);

        // Unblock MAC, block IP
        tier1.unblock_mac(&mac);
        tier1.block_ip(ip);
        assert_eq!(tier1.decide(&mac, &ip, 1000), Tier1Decision::Block);
    }

    #[test]
    fn test_tier1_trusted() {
        let mut tier1 = Tier1Engine::new();

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [192, 168, 1, 100];

        // Trust MAC
        tier1.trust_mac(mac);
        assert_eq!(tier1.decide(&mac, &ip, 1000), Tier1Decision::Allow);
    }

    #[test]
    fn test_tier1_rate_limit() {
        let mut tier1 = Tier1Engine::new();

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [192, 168, 1, 100];

        // Rate limit until time 2000
        tier1.rate_limit(ip, 2000);

        // Before expiry - blocked
        assert_eq!(tier1.decide(&mac, &ip, 1000), Tier1Decision::Block);

        // After expiry - escalate (unknown)
        assert_eq!(tier1.decide(&mac, &ip, 2001), Tier1Decision::Escalate);
    }

    #[test]
    fn test_tier2_decisions() {
        let mut tier2 = Tier2Engine::new();

        let ip = [192, 168, 1, 100];

        // No alerts = allow
        let decision = tier2.decide(ip, 0, 0);
        assert!(matches!(decision, Tier2Decision::Allow));

        // High severity = eventually block
        let decision = tier2.decide(ip, 5, 150);
        assert!(matches!(decision, Tier2Decision::Block(_)));
    }

    #[test]
    fn test_tiered_intelligence() {
        let mut ti = TieredIntelligence::new();

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = [192, 168, 1, 100];

        // Test tier 1 recording
        let decision = ti.tier1().decide(&mac, &ip, 1000);
        ti.record_tier1(decision);

        assert_eq!(ti.stats().tier1_escalate, 1);
    }

    #[test]
    fn test_security_engine_creation() {
        let engine = SecurityEngine::new(SecurityEngineConfig::default());

        assert_eq!(engine.stats().frames_processed, 0);
        assert_eq!(engine.stats().packets_processed, 0);
    }

    #[test]
    fn test_security_engine_trusted_source() {
        let mut engine = SecurityEngine::new(SecurityEngineConfig::default());

        let ip = [192, 168, 1, 100];
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Trust the source
        engine.trust_source(ip, Some(mac));

        let result = engine.process_tier1(&mac, &ip, 1000);
        assert!(result.allow);
        assert_eq!(result.decision_tier, 1);
        assert!(result.reason.contains("Tier 1"));
    }

    #[test]
    fn test_security_engine_blocked_source() {
        let mut engine = SecurityEngine::new(SecurityEngineConfig::default());

        let ip = [10, 0, 0, 1];
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];

        // Block the source
        engine.block_source(ip, Some(mac));

        let result = engine.process_tier1(&mac, &ip, 1000);
        assert!(!result.allow);
        assert_eq!(result.decision_tier, 1);
        assert!(result.reason.contains("Block"));
    }

    #[test]
    fn test_tier1_and_tier2_processing() {
        let mut engine = SecurityEngine::new(SecurityEngineConfig::default());

        let ip = [192, 168, 1, 100];
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Unknown source with no alerts
        let result = engine.process_tier1_2(&mac, &ip, 0, 0, 1000);
        assert!(result.allow);
        assert_eq!(result.decision_tier, 2);

        // Unknown source with high alerts
        let result = engine.process_tier1_2(&mac, &ip, 5, 150, 2000);
        assert!(!result.allow);
        assert!(result.reason.contains("Block"));
    }
}
