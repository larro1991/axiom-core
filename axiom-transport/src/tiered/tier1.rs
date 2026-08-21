//! Tier 1: Translators (The Reflexes)
//!
//! Fast, deterministic packet processing with NO AI inference.
//! All decisions are pure lookups - microsecond latency.
//!
//! # What Translators Do
//! - Protocol detection (pattern matching)
//! - Encode/decode (deterministic codecs)
//! - Signature verify (hardware crypto)
//! - Route lookup (hash table)
//! - Trust check (cache lookup)
//!
//! # What Translators DON'T Do
//! - Think
//! - Learn
//! - Adapt
//! - Handle exceptions (escalate to Tier 2)

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use axiom_types::{NodeId, IntentHash, TrustLevel};

/// Translator configuration
#[derive(Debug, Clone)]
pub struct TranslatorConfig {
    /// Maximum entries in routing cache
    pub max_routing_entries: usize,
    /// Maximum entries in trust cache
    pub max_trust_entries: usize,
    /// Maximum protocol patterns
    pub max_protocol_patterns: usize,
    /// Signature verification enabled
    pub verify_signatures: bool,
}

impl Default for TranslatorConfig {
    fn default() -> Self {
        Self {
            max_routing_entries: 10_000,
            max_trust_entries: 10_000,
            max_protocol_patterns: 100,
            verify_signatures: true,
        }
    }
}

/// Result of translation (fast path decision)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateResult {
    /// Forward to next hop
    Forward {
        next_hop: NodeId,
        via_protocol: ProtocolId,
    },
    /// Deliver locally
    DeliverLocal,
    /// Drop packet (known bad)
    Drop(DropReason),
    /// Broadcast to all neighbors
    Broadcast,
    /// Escalate to Tier 2 (can't decide)
    Escalate(EscalateReason),
}

/// Why a packet was dropped
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Sender not trusted
    Untrusted,
    /// Invalid signature
    BadSignature,
    /// TTL exceeded
    TtlExceeded,
    /// Blocked by policy
    PolicyBlocked,
    /// Malformed packet
    Malformed,
}

/// Why we need Tier 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalateReason {
    /// Unknown source identity
    UnknownSource,
    /// Unknown protocol
    UnknownProtocol,
    /// No route found
    NoRoute,
    /// Suspicious pattern (needs analysis)
    Suspicious,
    /// Trust decision needed
    TrustDecisionNeeded,
}

/// Protocol identifier
pub type ProtocolId = u16;

/// Well-known protocols
pub mod protocols {
    use super::ProtocolId;

    pub const AXIOM: ProtocolId = 0x0001;
    pub const ETHERNET: ProtocolId = 0x0002;
    pub const IPV4: ProtocolId = 0x0800;
    pub const IPV6: ProtocolId = 0x86DD;
    pub const ARP: ProtocolId = 0x0806;
    pub const TCP: ProtocolId = 0x0006;
    pub const UDP: ProtocolId = 0x0011;
    pub const HTTP: ProtocolId = 0x0050;
    pub const HTTPS: ProtocolId = 0x01BB;
    pub const DNS: ProtocolId = 0x0035;
    pub const UNKNOWN: ProtocolId = 0xFFFF;
}

/// Protocol detection pattern
#[derive(Debug, Clone)]
pub struct ProtocolPattern {
    /// Protocol ID
    pub protocol: ProtocolId,
    /// Byte offset to check
    pub offset: usize,
    /// Expected byte pattern
    pub pattern: Vec<u8>,
    /// Mask (0xFF = must match, 0x00 = ignore)
    pub mask: Vec<u8>,
}

/// Routing cache entry
#[derive(Debug, Clone)]
pub struct RouteCacheEntry {
    /// Destination
    pub destination: NodeId,
    /// Next hop
    pub next_hop: NodeId,
    /// Outbound protocol
    pub protocol: ProtocolId,
    /// Entry timestamp
    pub timestamp: u64,
    /// Hit count
    pub hits: u64,
}

/// Trust cache entry
#[derive(Debug, Clone)]
pub struct TrustCacheEntry {
    /// Node identity
    pub node_id: NodeId,
    /// Trust level
    pub trust: TrustLevel,
    /// Entry timestamp
    pub timestamp: u64,
    /// Last verified
    pub last_verified: u64,
}

/// Tier 1 Translator - Fast path packet processor
///
/// NO THINKING. Pure lookup tables populated by Tier 2/3.
#[derive(Debug)]
pub struct Translator {
    /// Configuration
    config: TranslatorConfig,

    /// Protocol detection patterns (ordered by priority)
    protocol_patterns: Vec<ProtocolPattern>,

    /// Routing cache (NodeId -> next hop)
    routing_cache: HashMap<NodeId, RouteCacheEntry>,

    /// Trust cache (NodeId -> trust level)
    trust_cache: HashMap<NodeId, TrustCacheEntry>,

    /// Intent routing (IntentHash -> capable nodes)
    intent_cache: HashMap<IntentHash, Vec<NodeId>>,

    /// Blocked identities (immediate drop)
    blocklist: HashMap<NodeId, u64>,

    /// Statistics
    stats: TranslatorStats,
}

/// Translator statistics
#[derive(Debug, Default, Clone)]
pub struct TranslatorStats {
    /// Packets processed
    pub packets_processed: u64,
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Packets delivered locally
    pub packets_local: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Packets escalated to Tier 2
    pub packets_escalated: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
}

impl Translator {
    /// Create a new translator
    pub fn new(config: TranslatorConfig) -> Self {
        let mut translator = Self {
            config,
            protocol_patterns: Vec::new(),
            routing_cache: HashMap::new(),
            trust_cache: HashMap::new(),
            intent_cache: HashMap::new(),
            blocklist: HashMap::new(),
            stats: TranslatorStats::default(),
        };

        // Initialize with basic AXIOM protocol detection
        translator.add_protocol_pattern(ProtocolPattern {
            protocol: protocols::AXIOM,
            offset: 0,
            pattern: vec![0x41, 0x58], // "AX" magic
            mask: vec![0xFF, 0xFF],
        });

        translator
    }

    // =========================================================================
    // CORE TRANSLATION (Fast Path)
    // =========================================================================

    /// Translate a packet - THE HOT PATH
    ///
    /// This function MUST be fast. No allocations. No syscalls. No thinking.
    pub fn translate(&mut self, packet: &[u8], source: Option<&NodeId>) -> TranslateResult {
        self.stats.packets_processed += 1;

        // 1. Quick blocklist check
        if let Some(src) = source {
            if self.blocklist.contains_key(src) {
                self.stats.packets_dropped += 1;
                return TranslateResult::Drop(DropReason::PolicyBlocked);
            }
        }

        // 2. Detect protocol (pattern match)
        let protocol = self.detect_protocol(packet);
        if protocol == protocols::UNKNOWN {
            self.stats.packets_escalated += 1;
            return TranslateResult::Escalate(EscalateReason::UnknownProtocol);
        }

        // 3. Quick decode to get destination
        let dest = match self.quick_decode_destination(packet, protocol) {
            Some(d) => d,
            None => {
                self.stats.packets_dropped += 1;
                return TranslateResult::Drop(DropReason::Malformed);
            }
        };

        // 4. Check if broadcast
        if dest == NodeId::zero() {
            self.stats.packets_forwarded += 1;
            return TranslateResult::Broadcast;
        }

        // 5. Trust check for source
        if let Some(src) = source {
            match self.check_trust(src) {
                TrustCheckResult::Trusted => {}
                TrustCheckResult::Untrusted => {
                    self.stats.packets_dropped += 1;
                    return TranslateResult::Drop(DropReason::Untrusted);
                }
                TrustCheckResult::Unknown => {
                    self.stats.packets_escalated += 1;
                    return TranslateResult::Escalate(EscalateReason::TrustDecisionNeeded);
                }
            }
        }

        // 6. Route lookup
        if let Some(entry) = self.routing_cache.get(&dest) {
            self.stats.cache_hits += 1;
            self.stats.packets_forwarded += 1;
            return TranslateResult::Forward {
                next_hop: entry.next_hop.clone(),
                via_protocol: entry.protocol,
            };
        }

        // 7. No route - escalate
        self.stats.cache_misses += 1;
        self.stats.packets_escalated += 1;
        TranslateResult::Escalate(EscalateReason::NoRoute)
    }

    /// Detect protocol from packet bytes (pattern matching)
    fn detect_protocol(&self, packet: &[u8]) -> ProtocolId {
        for pattern in &self.protocol_patterns {
            if pattern.offset + pattern.pattern.len() > packet.len() {
                continue;
            }

            let mut matches = true;
            for (i, (&expected, &mask)) in pattern.pattern.iter()
                .zip(pattern.mask.iter())
                .enumerate()
            {
                let actual = packet[pattern.offset + i];
                if (actual & mask) != (expected & mask) {
                    matches = false;
                    break;
                }
            }

            if matches {
                return pattern.protocol;
            }
        }

        protocols::UNKNOWN
    }

    /// Quick decode to extract destination (protocol-specific)
    fn quick_decode_destination(&self, packet: &[u8], protocol: ProtocolId) -> Option<NodeId> {
        match protocol {
            protocols::AXIOM => {
                // AXIOM frame: magic(2) + version(1) + type(1) + source(32) + dest(32)
                if packet.len() < 68 {
                    return None;
                }
                let mut dest_bytes = [0u8; 32];
                dest_bytes.copy_from_slice(&packet[36..68]);
                Some(NodeId::from_bytes(dest_bytes))
            }
            _ => {
                // For other protocols, escalate to Tier 2
                None
            }
        }
    }

    /// Check trust level from cache
    fn check_trust(&self, node_id: &NodeId) -> TrustCheckResult {
        match self.trust_cache.get(node_id) {
            Some(entry) => {
                match entry.trust {
                    TrustLevel::Full | TrustLevel::Sig => TrustCheckResult::Trusted,
                    TrustLevel::Raw => TrustCheckResult::Untrusted,
                    TrustLevel::Compress => TrustCheckResult::Unknown,
                }
            }
            None => TrustCheckResult::Unknown,
        }
    }

    // =========================================================================
    // CACHE MANAGEMENT (Called by Tier 2)
    // =========================================================================

    /// Add a routing entry (called by Tier 2 after route discovery)
    pub fn add_route(&mut self, dest: NodeId, next_hop: NodeId, protocol: ProtocolId, now: u64) {
        if self.routing_cache.len() >= self.config.max_routing_entries {
            self.evict_oldest_route();
        }

        self.routing_cache.insert(dest.clone(), RouteCacheEntry {
            destination: dest,
            next_hop,
            protocol,
            timestamp: now,
            hits: 0,
        });
    }

    /// Remove a routing entry
    pub fn remove_route(&mut self, dest: &NodeId) {
        self.routing_cache.remove(dest);
    }

    /// Add a trust entry (called by Tier 2 after trust evaluation)
    pub fn add_trust(&mut self, node_id: NodeId, trust: TrustLevel, now: u64) {
        if self.trust_cache.len() >= self.config.max_trust_entries {
            self.evict_oldest_trust();
        }

        self.trust_cache.insert(node_id.clone(), TrustCacheEntry {
            node_id,
            trust,
            timestamp: now,
            last_verified: now,
        });
    }

    /// Remove a trust entry
    pub fn remove_trust(&mut self, node_id: &NodeId) {
        self.trust_cache.remove(node_id);
    }

    /// Add to blocklist
    pub fn block(&mut self, node_id: NodeId, until: u64) {
        self.blocklist.insert(node_id, until);
    }

    /// Remove from blocklist
    pub fn unblock(&mut self, node_id: &NodeId) {
        self.blocklist.remove(node_id);
    }

    /// Add intent capability (called by Tier 2 after capability discovery)
    pub fn add_intent_capability(&mut self, intent: IntentHash, nodes: Vec<NodeId>) {
        self.intent_cache.insert(intent, nodes);
    }

    /// Add protocol detection pattern
    pub fn add_protocol_pattern(&mut self, pattern: ProtocolPattern) {
        if self.protocol_patterns.len() < self.config.max_protocol_patterns {
            self.protocol_patterns.push(pattern);
        }
    }

    // =========================================================================
    // MAINTENANCE
    // =========================================================================

    /// Clean up expired entries
    pub fn cleanup(&mut self, now: u64, max_age: u64) {
        // Clean blocklist
        self.blocklist.retain(|_, &mut until| until > now);

        // Clean old routing entries
        self.routing_cache.retain(|_, entry| {
            now.saturating_sub(entry.timestamp) < max_age
        });

        // Clean old trust entries
        self.trust_cache.retain(|_, entry| {
            now.saturating_sub(entry.timestamp) < max_age
        });
    }

    fn evict_oldest_route(&mut self) {
        if let Some(oldest) = self.routing_cache.iter()
            .min_by_key(|(_, e)| e.timestamp)
            .map(|(k, _)| k.clone())
        {
            self.routing_cache.remove(&oldest);
        }
    }

    fn evict_oldest_trust(&mut self) {
        if let Some(oldest) = self.trust_cache.iter()
            .min_by_key(|(_, e)| e.timestamp)
            .map(|(k, _)| k.clone())
        {
            self.trust_cache.remove(&oldest);
        }
    }

    // =========================================================================
    // STATISTICS
    // =========================================================================

    /// Get current statistics
    pub fn stats(&self) -> &TranslatorStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = TranslatorStats::default();
    }

    /// Get cache sizes
    pub fn cache_sizes(&self) -> (usize, usize, usize) {
        (
            self.routing_cache.len(),
            self.trust_cache.len(),
            self.intent_cache.len(),
        )
    }
}

/// Trust check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustCheckResult {
    Trusted,
    Untrusted,
    Unknown,
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

    fn make_axiom_packet(dest: &NodeId) -> Vec<u8> {
        let mut packet = vec![0u8; 100];
        // Magic
        packet[0] = 0x41; // 'A'
        packet[1] = 0x58; // 'X'
        // Version
        packet[2] = 1;
        // Type
        packet[3] = 0;
        // Source (bytes 4-35)
        packet[4..36].copy_from_slice(&[1u8; 32]);
        // Destination (bytes 36-67)
        packet[36..68].copy_from_slice(dest.as_bytes());
        packet
    }

    #[test]
    fn test_protocol_detection() {
        let translator = Translator::new(TranslatorConfig::default());

        // AXIOM packet
        let axiom_packet = make_axiom_packet(&test_node_id(2));
        assert_eq!(translator.detect_protocol(&axiom_packet), protocols::AXIOM);

        // Unknown packet
        let unknown_packet = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(translator.detect_protocol(&unknown_packet), protocols::UNKNOWN);
    }

    #[test]
    fn test_translate_with_route() {
        let mut translator = Translator::new(TranslatorConfig::default());

        // Add route
        let dest = test_node_id(2);
        let next_hop = test_node_id(3);
        translator.add_route(dest.clone(), next_hop.clone(), protocols::AXIOM, 1000);

        // Add trust for source
        let source = test_node_id(1);
        translator.add_trust(source.clone(), TrustLevel::Sig, 1000);

        // Create packet
        let packet = make_axiom_packet(&dest);

        // Translate
        let result = translator.translate(&packet, Some(&source));

        match result {
            TranslateResult::Forward { next_hop: nh, via_protocol } => {
                assert_eq!(nh, next_hop);
                assert_eq!(via_protocol, protocols::AXIOM);
            }
            _ => panic!("Expected Forward, got {:?}", result),
        }
    }

    #[test]
    fn test_translate_no_route() {
        let mut translator = Translator::new(TranslatorConfig::default());

        // Add trust but no route
        let source = test_node_id(1);
        translator.add_trust(source.clone(), TrustLevel::Sig, 1000);

        let dest = test_node_id(99); // No route to this
        let packet = make_axiom_packet(&dest);

        let result = translator.translate(&packet, Some(&source));
        assert_eq!(result, TranslateResult::Escalate(EscalateReason::NoRoute));
    }

    #[test]
    fn test_blocklist() {
        let mut translator = Translator::new(TranslatorConfig::default());

        let blocked = test_node_id(1);
        translator.block(blocked.clone(), u64::MAX);

        let packet = make_axiom_packet(&test_node_id(2));
        let result = translator.translate(&packet, Some(&blocked));

        assert_eq!(result, TranslateResult::Drop(DropReason::PolicyBlocked));
    }

    #[test]
    fn test_broadcast() {
        let mut translator = Translator::new(TranslatorConfig::default());

        let source = test_node_id(1);
        translator.add_trust(source.clone(), TrustLevel::Sig, 1000);

        // Broadcast destination (all zeros)
        let packet = make_axiom_packet(&NodeId::zero());
        let result = translator.translate(&packet, Some(&source));

        assert_eq!(result, TranslateResult::Broadcast);
    }

    #[test]
    fn test_untrusted_source() {
        let mut translator = Translator::new(TranslatorConfig::default());

        // Add route
        let dest = test_node_id(2);
        translator.add_route(dest.clone(), test_node_id(3), protocols::AXIOM, 1000);

        // Source with Raw trust (untrusted)
        let source = test_node_id(1);
        translator.add_trust(source.clone(), TrustLevel::Raw, 1000);

        let packet = make_axiom_packet(&dest);
        let result = translator.translate(&packet, Some(&source));

        assert_eq!(result, TranslateResult::Drop(DropReason::Untrusted));
    }

    #[test]
    fn test_cleanup() {
        let mut translator = Translator::new(TranslatorConfig::default());

        // Add old entries
        translator.add_route(test_node_id(1), test_node_id(2), protocols::AXIOM, 100);
        translator.add_trust(test_node_id(1), TrustLevel::Sig, 100);
        translator.block(test_node_id(3), 500); // Expires at 500

        // Verify entries exist
        assert_eq!(translator.routing_cache.len(), 1);
        assert_eq!(translator.trust_cache.len(), 1);
        assert_eq!(translator.blocklist.len(), 1);

        // Cleanup old entries (max age = 100, now = 1000)
        translator.cleanup(1000, 100);

        // All should be removed
        assert_eq!(translator.routing_cache.len(), 0);
        assert_eq!(translator.trust_cache.len(), 0);
        assert_eq!(translator.blocklist.len(), 0);
    }

    #[test]
    fn test_stats() {
        let mut translator = Translator::new(TranslatorConfig::default());

        // Process some packets
        let source = test_node_id(1);
        translator.add_trust(source.clone(), TrustLevel::Sig, 1000);

        let dest = test_node_id(2);
        translator.add_route(dest.clone(), test_node_id(3), protocols::AXIOM, 1000);

        let packet = make_axiom_packet(&dest);

        for _ in 0..10 {
            translator.translate(&packet, Some(&source));
        }

        let stats = translator.stats();
        assert_eq!(stats.packets_processed, 10);
        assert_eq!(stats.packets_forwarded, 10);
        assert_eq!(stats.cache_hits, 10);
    }
}
