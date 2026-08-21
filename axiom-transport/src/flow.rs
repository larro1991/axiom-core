//! Flow control for AXIOM transport
//!
//! Implements window-based flow control and back-pressure signaling.

use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;

#[cfg(feature = "std")]
use hashbrown::HashMap;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use tokio::time::Instant;

/// Flow control states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Normal operation - can send freely
    Open,
    /// Reduced capacity - slow down
    Throttled,
    /// Back-pressure applied - pause sending
    Paused,
    /// Connection is blocked
    Blocked,
}

impl FlowState {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Throttled => 1,
            Self::Paused => 2,
            Self::Blocked => 3,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Open,
            1 => Self::Throttled,
            2 => Self::Paused,
            _ => Self::Blocked,
        }
    }
}

/// Flow control payload structure
/// Layout: [intent_hash: 16 bytes][state: 1 byte][window: 4 bytes][rate_limit: 4 bytes]
#[derive(Debug, Clone)]
pub struct FlowPayload {
    /// The intent this flow control applies to (or zero for global)
    pub intent_hash: IntentHash,
    /// Current flow state
    pub state: FlowState,
    /// Receive window size (bytes we can accept)
    pub window: u32,
    /// Rate limit (bytes per second, 0 = unlimited)
    pub rate_limit: u32,
}

impl FlowPayload {
    pub fn new(intent_hash: IntentHash) -> Self {
        Self {
            intent_hash,
            state: FlowState::Open,
            window: 65536, // Default 64KB window
            rate_limit: 0,
        }
    }

    pub fn with_state(mut self, state: FlowState) -> Self {
        self.state = state;
        self
    }

    pub fn with_window(mut self, window: u32) -> Self {
        self.window = window;
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: u32) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(25);
        payload.extend_from_slice(self.intent_hash.as_bytes());
        payload.push(self.state.to_u8());
        payload.extend_from_slice(&self.window.to_be_bytes());
        payload.extend_from_slice(&self.rate_limit.to_be_bytes());
        payload
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 25 {
            return None;
        }

        let mut intent_bytes = [0u8; 16];
        intent_bytes.copy_from_slice(&data[0..16]);
        let intent_hash = IntentHash::from_bytes(intent_bytes);

        let state = FlowState::from_u8(data[16]);
        let window = u32::from_be_bytes([data[17], data[18], data[19], data[20]]);
        let rate_limit = u32::from_be_bytes([data[21], data[22], data[23], data[24]]);

        Some(Self {
            intent_hash,
            state,
            window,
            rate_limit,
        })
    }
}

/// Configuration for flow control
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Initial receive window size
    pub initial_window: u32,
    /// Minimum window size before pausing
    pub min_window: u32,
    /// Maximum window size
    pub max_window: u32,
    /// Window growth factor when increasing
    pub window_growth: f32,
    /// High watermark (fraction of window that triggers throttle)
    pub high_watermark: f32,
    /// Low watermark (fraction of window that clears throttle)
    pub low_watermark: f32,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            initial_window: 65536,    // 64KB
            min_window: 1024,         // 1KB
            max_window: 16777216,     // 16MB
            window_growth: 1.5,
            high_watermark: 0.8,
            low_watermark: 0.2,
        }
    }
}

/// Tracks flow control state for a peer/intent combination
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct FlowTracker {
    /// Current state
    pub state: FlowState,
    /// Bytes available in receive window
    pub window_available: u32,
    /// Total window size
    pub window_size: u32,
    /// Rate limit (bytes/sec, 0 = none)
    pub rate_limit: u32,
    /// Bytes sent in current period
    pub bytes_sent: u64,
    /// Bytes received in current period
    pub bytes_received: u64,
    /// Last window update time
    pub last_update: Instant,
}

#[cfg(feature = "std")]
impl FlowTracker {
    pub fn new(config: &FlowConfig) -> Self {
        Self {
            state: FlowState::Open,
            window_available: config.initial_window,
            window_size: config.initial_window,
            rate_limit: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_update: Instant::now(),
        }
    }

    /// Update state based on flow control message from peer
    pub fn update_from_peer(&mut self, flow: &FlowPayload) {
        self.state = flow.state;
        self.window_available = flow.window;
        self.rate_limit = flow.rate_limit;
        self.last_update = Instant::now();
    }

    /// Record bytes being sent
    pub fn record_send(&mut self, bytes: u32) {
        self.bytes_sent += bytes as u64;
        self.window_available = self.window_available.saturating_sub(bytes);
    }

    /// Record bytes being received (opens window on peer side)
    pub fn record_receive(&mut self, bytes: u32) {
        self.bytes_received += bytes as u64;
    }

    /// Acknowledge processed bytes (returns window credit)
    pub fn ack_processed(&mut self, bytes: u32, config: &FlowConfig) {
        self.window_available = (self.window_available + bytes).min(config.max_window);
    }

    /// Check if we can send given number of bytes
    pub fn can_send(&self, bytes: u32) -> bool {
        match self.state {
            FlowState::Open | FlowState::Throttled => self.window_available >= bytes,
            FlowState::Paused | FlowState::Blocked => false,
        }
    }

    /// Calculate the state we should advertise to peer
    pub fn calculate_advertised_state(&self, config: &FlowConfig) -> FlowState {
        let fill_ratio = 1.0 - (self.window_available as f32 / self.window_size as f32);

        if fill_ratio >= config.high_watermark {
            FlowState::Paused
        } else if fill_ratio >= config.low_watermark {
            FlowState::Throttled
        } else {
            FlowState::Open
        }
    }
}

/// Manages flow control for multiple peers/intents
#[cfg(feature = "std")]
pub struct FlowManager {
    config: FlowConfig,
    node_id: NodeId,
    /// Flow trackers per peer address
    peer_flow: HashMap<SocketAddr, FlowTracker>,
    /// Flow trackers per intent (for intent-specific flow control)
    intent_flow: HashMap<IntentHash, FlowTracker>,
}

#[cfg(feature = "std")]
impl FlowManager {
    pub fn new(config: FlowConfig, node_id: NodeId) -> Self {
        Self {
            config,
            node_id,
            peer_flow: HashMap::new(),
            intent_flow: HashMap::new(),
        }
    }

    /// Get or create flow tracker for a peer
    pub fn get_peer_flow(&mut self, addr: SocketAddr) -> &mut FlowTracker {
        self.peer_flow
            .entry(addr)
            .or_insert_with(|| FlowTracker::new(&self.config))
    }

    /// Get or create flow tracker for an intent
    pub fn get_intent_flow(&mut self, intent: IntentHash) -> &mut FlowTracker {
        self.intent_flow
            .entry(intent)
            .or_insert_with(|| FlowTracker::new(&self.config))
    }

    /// Process incoming flow control frame
    pub fn process_flow_frame(&mut self, frame: &Frame, addr: SocketAddr) -> Option<()> {
        let flow_payload = FlowPayload::decode(&frame.payload)?;

        // Update peer-level flow control
        let tracker = self.get_peer_flow(addr);
        tracker.update_from_peer(&flow_payload);

        // If intent-specific, also update intent tracker
        if flow_payload.intent_hash != IntentHash::zero() {
            let intent_tracker = self.get_intent_flow(flow_payload.intent_hash);
            intent_tracker.update_from_peer(&flow_payload);
        }

        Some(())
    }

    /// Check if we can send a frame to a peer
    pub fn can_send(&mut self, addr: SocketAddr, frame_size: u32) -> bool {
        let tracker = self.get_peer_flow(addr);
        tracker.can_send(frame_size)
    }

    /// Check if we can send a frame for a specific intent
    pub fn can_send_intent(&mut self, intent: IntentHash, frame_size: u32) -> bool {
        let tracker = self.get_intent_flow(intent);
        tracker.can_send(frame_size)
    }

    /// Record that we sent data
    pub fn record_send(&mut self, addr: SocketAddr, bytes: u32, intent: Option<IntentHash>) {
        self.get_peer_flow(addr).record_send(bytes);
        if let Some(ih) = intent {
            self.get_intent_flow(ih).record_send(bytes);
        }
    }

    /// Record that we received data
    pub fn record_receive(&mut self, addr: SocketAddr, bytes: u32, intent: Option<IntentHash>) {
        self.get_peer_flow(addr).record_receive(bytes);
        if let Some(ih) = intent {
            self.get_intent_flow(ih).record_receive(bytes);
        }
    }

    /// Create a flow control frame to send to peer
    pub fn create_flow_frame(&self, intent: IntentHash) -> Frame {
        let header = FrameHeader::new(FrameType::Flow, self.node_id.clone())
            .with_trust_level(TrustLevel::Raw)
            .with_intent(intent);

        let tracker = self.intent_flow.get(&intent);
        let (state, window) = if let Some(t) = tracker {
            (t.calculate_advertised_state(&self.config), t.window_available)
        } else {
            (FlowState::Open, self.config.initial_window)
        };

        let flow_payload = FlowPayload::new(intent)
            .with_state(state)
            .with_window(window);

        Frame::new(header, PayloadType::Raw, flow_payload.encode())
    }

    /// Create a global flow control frame (applies to all intents)
    pub fn create_global_flow_frame(&self, addr: SocketAddr) -> Frame {
        let header = FrameHeader::new(FrameType::Flow, self.node_id.clone())
            .with_trust_level(TrustLevel::Raw);

        let tracker = self.peer_flow.get(&addr);
        let (state, window) = if let Some(t) = tracker {
            (t.calculate_advertised_state(&self.config), t.window_available)
        } else {
            (FlowState::Open, self.config.initial_window)
        };

        let flow_payload = FlowPayload::new(IntentHash::zero())
            .with_state(state)
            .with_window(window);

        Frame::new(header, PayloadType::Raw, flow_payload.encode())
    }

    /// Get current flow state for a peer
    pub fn get_peer_state(&self, addr: &SocketAddr) -> FlowState {
        self.peer_flow
            .get(addr)
            .map(|t| t.state)
            .unwrap_or(FlowState::Open)
    }

    /// Get current flow state for an intent
    pub fn get_intent_state(&self, intent: &IntentHash) -> FlowState {
        self.intent_flow
            .get(intent)
            .map(|t| t.state)
            .unwrap_or(FlowState::Open)
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.peer_flow.clear();
        self.intent_flow.clear();
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct FlowTracker;

#[cfg(not(feature = "std"))]
pub struct FlowManager;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_flow_payload_roundtrip() {
        let intent = IntentHash::from_bytes([0x42; 16]);
        let flow = FlowPayload::new(intent)
            .with_state(FlowState::Throttled)
            .with_window(32768)
            .with_rate_limit(1000000);

        let encoded = flow.encode();
        let decoded = FlowPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.intent_hash, intent);
        assert_eq!(decoded.state, FlowState::Throttled);
        assert_eq!(decoded.window, 32768);
        assert_eq!(decoded.rate_limit, 1000000);
    }

    #[test]
    fn test_flow_state_roundtrip() {
        for state in [FlowState::Open, FlowState::Throttled, FlowState::Paused, FlowState::Blocked] {
            assert_eq!(FlowState::from_u8(state.to_u8()), state);
        }
    }

    #[test]
    fn test_flow_tracker_window() {
        let config = FlowConfig::default();
        let mut tracker = FlowTracker::new(&config);

        assert!(tracker.can_send(1000));

        // Record sending
        tracker.record_send(60000);
        assert_eq!(tracker.window_available, config.initial_window - 60000);

        // Should still be able to send small frames
        assert!(tracker.can_send(1000));

        // Send more to exhaust window
        tracker.record_send(tracker.window_available);
        assert!(!tracker.can_send(1));

        // Ack restores window
        tracker.ack_processed(10000, &config);
        assert!(tracker.can_send(10000));
    }

    #[test]
    fn test_flow_tracker_state_calculation() {
        let config = FlowConfig {
            initial_window: 10000,
            high_watermark: 0.8,
            low_watermark: 0.2,
            ..Default::default()
        };

        let mut tracker = FlowTracker::new(&config);

        // Empty buffer = Open
        assert_eq!(tracker.calculate_advertised_state(&config), FlowState::Open);

        // 50% full = Throttled
        tracker.record_send(5000);
        assert_eq!(tracker.calculate_advertised_state(&config), FlowState::Throttled);

        // 90% full = Paused
        tracker.record_send(4000);
        assert_eq!(tracker.calculate_advertised_state(&config), FlowState::Paused);
    }

    #[test]
    fn test_flow_manager_peer_tracking() {
        let config = FlowConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = FlowManager::new(config, node_id);

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Initially can send
        assert!(manager.can_send(addr, 1000));

        // Record sends
        manager.record_send(addr, 60000, None);

        // Still can send
        assert!(manager.can_send(addr, 1000));
    }

    #[test]
    fn test_flow_manager_intent_tracking() {
        let config = FlowConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = FlowManager::new(config, node_id);

        let intent = IntentHash::from_bytes([0xAB; 16]);

        // Initially can send
        assert!(manager.can_send_intent(intent, 1000));

        // Simulate receiving a throttle message
        let tracker = manager.get_intent_flow(intent);
        tracker.state = FlowState::Paused;

        // Now cannot send
        assert!(!manager.can_send_intent(intent, 1000));
    }
}
