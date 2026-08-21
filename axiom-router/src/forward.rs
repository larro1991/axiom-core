//! Multi-hop forwarding for AXIOM mesh
//!
//! Provides frame forwarding with loop detection using causal clocks.

use alloc::vec::Vec;
use axiom_types::clock::HybridClock;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::frame::Frame;

#[cfg(feature = "std")]
use hashbrown::HashMap;

/// Maximum hop count before dropping frames
pub const MAX_HOP_COUNT: u8 = 32;

/// Decision on what to do with a frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Deliver to local handler
    DeliverLocal,
    /// Forward to specified nodes
    Forward(Vec<NodeId>),
    /// Both deliver locally and forward
    DeliverAndForward(Vec<NodeId>),
    /// Drop the frame (loop detected, expired, etc.)
    Drop(DropReason),
}

/// Reason for dropping a frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Loop detected via clock comparison
    LoopDetected,
    /// Max hop count exceeded
    HopCountExceeded,
    /// Frame is duplicate
    Duplicate,
    /// No route to destination
    NoRoute,
    /// Frame expired
    Expired,
}

/// Tracks frame history for loop detection
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct FrameHistory {
    /// Clock when we last saw this frame
    pub clock: HybridClock,
    /// How many times we've seen it
    pub seen_count: u32,
    /// When we first processed this
    pub first_seen: std::time::Instant,
}

/// Forwarding engine for multi-hop routing
#[cfg(feature = "std")]
pub struct ForwardingEngine {
    /// Our node ID
    local_id: NodeId,
    /// History of frames we've seen (for loop detection)
    /// Key: (intent_hash, trace_id or sender+clock hash)
    frame_history: HashMap<FrameKey, FrameHistory>,
    /// Our local clock manager
    clock: axiom_clock::ClockManager,
    /// Intents we can handle locally
    local_intents: hashbrown::HashSet<IntentHash>,
    /// Statistics
    stats: ForwardingStats,
}

/// Key for frame deduplication
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FrameKey {
    /// Intent hash (or zero for non-intent frames)
    intent_hash: IntentHash,
    /// Trace ID if present, or derived from sender+clock
    frame_id: u64,
}

impl FrameKey {
    pub fn from_frame(frame: &Frame) -> Self {
        let intent_hash = frame.header.intent_hash;

        let frame_id = if let Some(trace_id) = frame.trace_id {
            trace_id.as_u64()
        } else {
            // Derive from sender + clock
            let sender_hash = {
                let bytes = frame.header.sender_id.as_bytes();
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            };
            let clock_val = frame.header.clock.physical ^ (frame.header.clock.logical as u64);
            sender_hash ^ clock_val
        };

        Self { intent_hash, frame_id }
    }
}

/// Forwarding statistics
#[derive(Debug, Default, Clone)]
pub struct ForwardingStats {
    /// Frames delivered locally
    pub delivered_local: u64,
    /// Frames forwarded
    pub forwarded: u64,
    /// Frames dropped (loops)
    pub loops_detected: u64,
    /// Frames dropped (hop count)
    pub hop_exceeded: u64,
    /// Frames dropped (duplicates)
    pub duplicates: u64,
    /// Frames dropped (no route)
    pub no_route: u64,
}

#[cfg(feature = "std")]
impl ForwardingEngine {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            frame_history: HashMap::new(),
            clock: axiom_clock::ClockManager::new(),
            local_intents: hashbrown::HashSet::new(),
            stats: ForwardingStats::default(),
        }
    }

    /// Register an intent we can handle locally
    pub fn register_local_intent(&mut self, intent_hash: IntentHash) {
        self.local_intents.insert(intent_hash);
    }

    /// Unregister a local intent
    pub fn unregister_local_intent(&mut self, intent_hash: &IntentHash) {
        self.local_intents.remove(intent_hash);
    }

    /// Decide what to do with an incoming frame
    pub fn decide(
        &mut self,
        frame: &Frame,
        next_hops: &[NodeId],
    ) -> ForwardDecision {
        // Update our clock based on incoming frame
        self.clock.update(&frame.header.clock);

        // Check for loop detection
        let key = FrameKey::from_frame(frame);

        if let Some(history) = self.frame_history.get_mut(&key) {
            // We've seen this frame before
            if frame.header.clock.happens_before(&history.clock)
                || frame.header.clock == history.clock
            {
                // This is old or same as what we've seen - loop or duplicate
                history.seen_count += 1;
                self.stats.loops_detected += 1;
                return ForwardDecision::Drop(DropReason::LoopDetected);
            }
            // Update with newer clock
            history.clock = frame.header.clock.clone();
            history.seen_count += 1;
        } else {
            // First time seeing this frame
            self.frame_history.insert(
                key,
                FrameHistory {
                    clock: frame.header.clock.clone(),
                    seen_count: 1,
                    first_seen: std::time::Instant::now(),
                },
            );
        }

        // Check if we're the intended destination
        let is_for_us = self.local_intents.contains(&frame.header.intent_hash);

        // Check if we should forward (have next hops and it's not just for us)
        let should_forward = !next_hops.is_empty()
            && !next_hops.iter().all(|n| n == &self.local_id);

        // Filter out ourselves from next hops
        let forward_to: Vec<NodeId> = next_hops
            .iter()
            .filter(|n| *n != &self.local_id)
            .cloned()
            .collect();

        match (is_for_us, should_forward && !forward_to.is_empty()) {
            (true, true) => {
                self.stats.delivered_local += 1;
                self.stats.forwarded += 1;
                ForwardDecision::DeliverAndForward(forward_to)
            }
            (true, false) => {
                self.stats.delivered_local += 1;
                ForwardDecision::DeliverLocal
            }
            (false, true) => {
                self.stats.forwarded += 1;
                ForwardDecision::Forward(forward_to)
            }
            (false, false) => {
                self.stats.no_route += 1;
                ForwardDecision::Drop(DropReason::NoRoute)
            }
        }
    }

    /// Prepare a frame for forwarding (update clock, etc.)
    pub fn prepare_forward(&mut self, frame: &mut Frame) {
        // Update clock
        frame.header.clock = self.clock.tick();
        // Note: We don't change sender_id - that stays as the original sender
        // Forwarding nodes are transparent
    }

    /// Clean up old frame history
    pub fn cleanup_history(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.frame_history.retain(|_, v| now.duration_since(v.first_seen) < max_age);
    }

    /// Get forwarding statistics
    pub fn stats(&self) -> &ForwardingStats {
        &self.stats
    }

    /// Get number of tracked frames
    pub fn history_size(&self) -> usize {
        self.frame_history.len()
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct ForwardingEngine;

#[cfg(not(feature = "std"))]
pub struct ForwardingStats;

/// Load balancing strategy for selecting routes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// Round-robin across available routes
    RoundRobin,
    /// Random selection
    Random,
    /// Pick two candidates, choose the best
    PowerOfTwo,
    /// Always pick the lowest latency route
    LowestLatency,
    /// Weighted by capacity
    WeightedCapacity,
}

/// Load balancer for route selection
pub struct LoadBalancer {
    strategy: LoadBalanceStrategy,
    round_robin_index: usize,
}

impl LoadBalancer {
    pub fn new(strategy: LoadBalanceStrategy) -> Self {
        Self {
            strategy,
            round_robin_index: 0,
        }
    }

    /// Select next hop(s) from available routes
    pub fn select<'a>(&mut self, routes: &'a [NodeId]) -> Option<&'a NodeId> {
        if routes.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let idx = self.round_robin_index % routes.len();
                self.round_robin_index = self.round_robin_index.wrapping_add(1);
                Some(&routes[idx])
            }
            LoadBalanceStrategy::Random => {
                // Simple pseudo-random using round_robin_index as state
                let idx = (self.round_robin_index * 1103515245 + 12345) % routes.len();
                self.round_robin_index = idx;
                Some(&routes[idx])
            }
            LoadBalanceStrategy::PowerOfTwo |
            LoadBalanceStrategy::LowestLatency |
            LoadBalanceStrategy::WeightedCapacity => {
                // For these strategies, we'd need route metrics
                // For now, just pick first
                Some(&routes[0])
            }
        }
    }
}


#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::frame::{FrameHeader, FrameType};
    use axiom_types::payload::PayloadType;
    use axiom_types::trust::TrustLevel;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_intent_hash(byte: u8) -> IntentHash {
        IntentHash::from_bytes([byte; 16])
    }

    fn create_test_frame(sender: u8, intent: u8, clock: HybridClock) -> Frame {
        let header = FrameHeader::new(FrameType::Intent, test_node_id(sender))
            .with_trust_level(TrustLevel::Sig)
            .with_clock(clock)
            .with_intent(test_intent_hash(intent));

        Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3])
    }

    #[test]
    fn test_local_delivery() {
        let mut engine = ForwardingEngine::new(test_node_id(0));

        // Register a local intent
        engine.register_local_intent(test_intent_hash(1));

        // Create a frame for that intent
        let frame = create_test_frame(2, 1, HybridClock::new(1000, 1));

        // Should deliver locally
        let decision = engine.decide(&frame, &[]);
        assert_eq!(decision, ForwardDecision::DeliverLocal);
    }

    #[test]
    fn test_forward_to_next_hop() {
        let mut engine = ForwardingEngine::new(test_node_id(0));

        // Don't register local intent - we just forward
        let frame = create_test_frame(2, 1, HybridClock::new(1000, 1));

        // Should forward to next hop
        let decision = engine.decide(&frame, &[test_node_id(3)]);
        assert_eq!(decision, ForwardDecision::Forward(vec![test_node_id(3)]));
    }

    #[test]
    fn test_deliver_and_forward() {
        let mut engine = ForwardingEngine::new(test_node_id(0));

        // Register local intent AND have next hops
        engine.register_local_intent(test_intent_hash(1));

        let frame = create_test_frame(2, 1, HybridClock::new(1000, 1));

        let decision = engine.decide(&frame, &[test_node_id(3), test_node_id(4)]);
        match decision {
            ForwardDecision::DeliverAndForward(nodes) => {
                assert_eq!(nodes.len(), 2);
            }
            _ => panic!("Expected DeliverAndForward"),
        }
    }

    #[test]
    fn test_loop_detection() {
        let mut engine = ForwardingEngine::new(test_node_id(0));
        engine.register_local_intent(test_intent_hash(1));

        // First time - should deliver
        let frame1 = create_test_frame(2, 1, HybridClock::new(1000, 1));
        let decision1 = engine.decide(&frame1, &[]);
        assert_eq!(decision1, ForwardDecision::DeliverLocal);

        // Same frame again (same or older clock) - should detect as loop
        let frame2 = create_test_frame(2, 1, HybridClock::new(1000, 1));
        let decision2 = engine.decide(&frame2, &[]);
        assert_eq!(decision2, ForwardDecision::Drop(DropReason::LoopDetected));
    }

    #[test]
    fn test_newer_frame_not_loop() {
        let mut engine = ForwardingEngine::new(test_node_id(0));
        engine.register_local_intent(test_intent_hash(1));

        // First frame
        let frame1 = create_test_frame(2, 1, HybridClock::new(1000, 1));
        let _ = engine.decide(&frame1, &[]);

        // Newer frame from same source - should NOT be detected as loop
        let frame2 = create_test_frame(2, 1, HybridClock::new(1000, 2));
        let decision = engine.decide(&frame2, &[]);
        assert_eq!(decision, ForwardDecision::DeliverLocal);
    }

    #[test]
    fn test_no_route() {
        let mut engine = ForwardingEngine::new(test_node_id(0));

        // Don't register local intent, no next hops
        let frame = create_test_frame(2, 1, HybridClock::new(1000, 1));

        let decision = engine.decide(&frame, &[]);
        assert_eq!(decision, ForwardDecision::Drop(DropReason::NoRoute));
    }

    #[test]
    fn test_filter_self_from_next_hops() {
        let mut engine = ForwardingEngine::new(test_node_id(0));

        let frame = create_test_frame(2, 1, HybridClock::new(1000, 1));

        // Include ourselves in next hops - should be filtered out
        let decision = engine.decide(&frame, &[test_node_id(0), test_node_id(3)]);
        match decision {
            ForwardDecision::Forward(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0], test_node_id(3));
            }
            _ => panic!("Expected Forward"),
        }
    }
}
