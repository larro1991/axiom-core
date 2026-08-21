//! Congestion control for AXIOM transport
//!
//! Implements congestion control algorithms to prevent network overload:
//! - AIMD (Additive Increase, Multiplicative Decrease)
//! - Optional: BBR-inspired AI-aware congestion control
//!
//! # Algorithm
//!
//! The controller maintains a congestion window (cwnd) that limits how many
//! bytes can be in-flight at any time. On successful ACKs, the window grows
//! additively. On packet loss (timeout or NACK), the window shrinks multiplicatively.

use alloc::collections::VecDeque;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use hashbrown::HashMap;

/// Configuration for congestion control
#[derive(Debug, Clone)]
pub struct CongestionConfig {
    /// Initial congestion window (bytes)
    pub initial_cwnd: u32,
    /// Minimum congestion window (bytes)
    pub min_cwnd: u32,
    /// Maximum congestion window (bytes)
    pub max_cwnd: u32,
    /// Slow start threshold (bytes)
    pub ssthresh: u32,
    /// Additive increase factor (bytes per RTT)
    pub aimd_increase: u32,
    /// Multiplicative decrease factor (e.g., 0.5 = halve on loss)
    pub aimd_decrease: f32,
    /// RTT smoothing factor (EWMA alpha)
    pub rtt_alpha: f32,
    /// RTT deviation smoothing factor
    pub rtt_beta: f32,
    /// Fast retransmit threshold (duplicate ACKs)
    pub fast_retransmit_thresh: u32,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            initial_cwnd: 10 * 1400, // 10 segments
            min_cwnd: 2 * 1400,      // 2 segments minimum
            max_cwnd: 1_000_000,     // ~1MB max
            ssthresh: 64 * 1400,     // 64 segments
            aimd_increase: 1400,     // 1 segment per RTT
            aimd_decrease: 0.5,      // Halve on loss
            rtt_alpha: 0.125,        // RFC 6298
            rtt_beta: 0.25,          // RFC 6298
            fast_retransmit_thresh: 3,
        }
    }
}

/// Current state of congestion control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Exponential growth (cwnd doubles each RTT)
    SlowStart,
    /// Linear growth (AIMD phase)
    CongestionAvoidance,
    /// Fast recovery after loss detection
    FastRecovery,
}

/// RTT estimator using Jacobson/Karels algorithm
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT (microseconds)
    srtt: u64,
    /// RTT variance
    rttvar: u64,
    /// Calculated RTO (retransmission timeout)
    rto: u64,
    /// Minimum observed RTT
    min_rtt: u64,
    /// Number of samples
    samples: u32,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            srtt: 100_000,     // 100ms initial estimate
            rttvar: 50_000,    // 50ms initial variance
            rto: 1_000_000,    // 1s initial RTO
            min_rtt: u64::MAX,
            samples: 0,
        }
    }
}

impl RttEstimator {
    /// Update RTT estimate with new measurement
    pub fn update(&mut self, rtt_us: u64, alpha: f32, beta: f32) {
        self.samples += 1;

        if self.samples == 1 {
            // First sample
            self.srtt = rtt_us;
            self.rttvar = rtt_us / 2;
        } else {
            // Jacobson/Karels algorithm
            let diff = if rtt_us > self.srtt {
                rtt_us - self.srtt
            } else {
                self.srtt - rtt_us
            };

            self.rttvar = ((1.0 - beta) * self.rttvar as f32 + beta * diff as f32) as u64;
            self.srtt = ((1.0 - alpha) * self.srtt as f32 + alpha * rtt_us as f32) as u64;
        }

        // Update min RTT
        self.min_rtt = self.min_rtt.min(rtt_us);

        // Calculate RTO: srtt + 4 * rttvar, with bounds
        self.rto = (self.srtt + 4 * self.rttvar).max(200_000).min(60_000_000); // 200ms - 60s
    }

    /// Get smoothed RTT
    pub fn srtt(&self) -> u64 {
        self.srtt
    }

    /// Get calculated RTO
    pub fn rto(&self) -> u64 {
        self.rto
    }

    /// Get minimum observed RTT
    pub fn min_rtt(&self) -> u64 {
        self.min_rtt
    }
}

/// Congestion controller for a single peer
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct CongestionController {
    config: CongestionConfig,
    /// Current congestion window (bytes)
    cwnd: u32,
    /// Slow start threshold
    ssthresh: u32,
    /// Current state
    state: CongestionState,
    /// Bytes in flight (sent but not yet acknowledged)
    bytes_in_flight: u32,
    /// RTT estimator
    rtt: RttEstimator,
    /// Duplicate ACK count
    dup_ack_count: u32,
    /// Last acknowledged sequence
    last_ack_seq: u64,
    /// Timestamp of last send
    last_send: std::time::Instant,
    /// Statistics
    stats: CongestionStats,
}

/// Congestion control statistics
#[derive(Debug, Default, Clone)]
pub struct CongestionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes acknowledged
    pub bytes_acked: u64,
    /// Packets lost (timeout)
    pub timeout_losses: u64,
    /// Packets lost (fast retransmit)
    pub fast_retransmit_losses: u64,
    /// Times entered slow start
    pub slow_start_entries: u64,
    /// Times entered fast recovery
    pub fast_recovery_entries: u64,
}

#[cfg(feature = "std")]
impl CongestionController {
    pub fn new(config: CongestionConfig) -> Self {
        let initial_cwnd = config.initial_cwnd;
        let ssthresh = config.ssthresh;

        Self {
            config,
            cwnd: initial_cwnd,
            ssthresh,
            state: CongestionState::SlowStart,
            bytes_in_flight: 0,
            rtt: RttEstimator::default(),
            dup_ack_count: 0,
            last_ack_seq: 0,
            last_send: std::time::Instant::now(),
            stats: CongestionStats::default(),
        }
    }

    /// Check if we can send more data
    pub fn can_send(&self, bytes: u32) -> bool {
        self.bytes_in_flight + bytes <= self.cwnd
    }

    /// Available window (bytes we can still send)
    pub fn available_window(&self) -> u32 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Record data being sent
    pub fn on_send(&mut self, bytes: u32) {
        self.bytes_in_flight += bytes;
        self.stats.bytes_sent += bytes as u64;
        self.last_send = std::time::Instant::now();
    }

    /// Process an acknowledgment
    pub fn on_ack(&mut self, acked_bytes: u32, ack_seq: u64, rtt_us: Option<u64>) {
        self.stats.bytes_acked += acked_bytes as u64;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        // Update RTT if we have a measurement
        if let Some(rtt) = rtt_us {
            self.rtt.update(rtt, self.config.rtt_alpha, self.config.rtt_beta);
        }

        // Check for duplicate ACK
        if ack_seq == self.last_ack_seq {
            self.dup_ack_count += 1;

            if self.dup_ack_count >= self.config.fast_retransmit_thresh
                && self.state != CongestionState::FastRecovery
            {
                // Enter fast recovery
                self.enter_fast_recovery();
            }
            return;
        }

        // New ACK
        self.last_ack_seq = ack_seq;
        self.dup_ack_count = 0;

        match self.state {
            CongestionState::SlowStart => {
                // Exponential growth: increase cwnd by acked_bytes
                self.cwnd = (self.cwnd + acked_bytes).min(self.config.max_cwnd);

                // Transition to congestion avoidance if we hit ssthresh
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear growth: increase by MSS * (acked_bytes / cwnd)
                // Simplified: add aimd_increase per cwnd of data acked
                let increase = (self.config.aimd_increase as u64 * acked_bytes as u64
                    / self.cwnd as u64) as u32;
                self.cwnd = (self.cwnd + increase.max(1)).min(self.config.max_cwnd);
            }
            CongestionState::FastRecovery => {
                // Exit fast recovery
                self.cwnd = self.ssthresh;
                self.state = CongestionState::CongestionAvoidance;
            }
        }
    }

    /// Process a timeout (packet loss)
    pub fn on_timeout(&mut self) {
        self.stats.timeout_losses += 1;

        // Multiplicative decrease
        self.ssthresh = ((self.cwnd as f32 * self.config.aimd_decrease) as u32)
            .max(self.config.min_cwnd);
        self.cwnd = self.config.min_cwnd;

        // Back to slow start
        self.state = CongestionState::SlowStart;
        self.stats.slow_start_entries += 1;
        self.dup_ack_count = 0;

        // Double RTO on timeout (exponential backoff)
        self.rtt.rto = (self.rtt.rto * 2).min(60_000_000); // Max 60s
    }

    /// Enter fast recovery mode
    fn enter_fast_recovery(&mut self) {
        self.stats.fast_retransmit_losses += 1;
        self.stats.fast_recovery_entries += 1;

        // Set ssthresh to half of cwnd
        self.ssthresh = ((self.cwnd as f32 * self.config.aimd_decrease) as u32)
            .max(self.config.min_cwnd);

        // Set cwnd to ssthresh + 3*MSS (for the 3 dup ACKs)
        self.cwnd = self.ssthresh + 3 * 1400;
        self.state = CongestionState::FastRecovery;
    }

    /// Get current congestion window
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get current state
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Get RTT estimator
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Get calculated RTO
    pub fn rto(&self) -> u64 {
        self.rtt.rto()
    }

    /// Get bytes in flight
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    /// Get statistics
    pub fn stats(&self) -> &CongestionStats {
        &self.stats
    }
}

/// Manages congestion control for multiple peers
#[cfg(feature = "std")]
pub struct CongestionManager {
    config: CongestionConfig,
    /// Per-peer controllers
    controllers: HashMap<SocketAddr, CongestionController>,
}

#[cfg(feature = "std")]
impl CongestionManager {
    pub fn new(config: CongestionConfig) -> Self {
        Self {
            config,
            controllers: HashMap::new(),
        }
    }

    /// Get or create controller for a peer
    pub fn get_or_create(&mut self, peer: SocketAddr) -> &mut CongestionController {
        self.controllers
            .entry(peer)
            .or_insert_with(|| CongestionController::new(self.config.clone()))
    }

    /// Get controller for a peer (if exists)
    pub fn get(&self, peer: &SocketAddr) -> Option<&CongestionController> {
        self.controllers.get(peer)
    }

    /// Get mutable controller for a peer (if exists)
    pub fn get_mut(&mut self, peer: &SocketAddr) -> Option<&mut CongestionController> {
        self.controllers.get_mut(peer)
    }

    /// Check if we can send to a peer
    pub fn can_send(&mut self, peer: SocketAddr, bytes: u32) -> bool {
        self.get_or_create(peer).can_send(bytes)
    }

    /// Record data sent to a peer
    pub fn on_send(&mut self, peer: SocketAddr, bytes: u32) {
        self.get_or_create(peer).on_send(bytes);
    }

    /// Process ACK from a peer
    pub fn on_ack(&mut self, peer: &SocketAddr, acked_bytes: u32, ack_seq: u64, rtt_us: Option<u64>) {
        if let Some(ctrl) = self.controllers.get_mut(peer) {
            ctrl.on_ack(acked_bytes, ack_seq, rtt_us);
        }
    }

    /// Process timeout for a peer
    pub fn on_timeout(&mut self, peer: &SocketAddr) {
        if let Some(ctrl) = self.controllers.get_mut(peer) {
            ctrl.on_timeout();
        }
    }

    /// Remove a peer's controller
    pub fn remove(&mut self, peer: &SocketAddr) {
        self.controllers.remove(peer);
    }

    /// Get number of tracked peers
    pub fn peer_count(&self) -> usize {
        self.controllers.len()
    }

    /// Get total bytes in flight across all peers
    pub fn total_bytes_in_flight(&self) -> u64 {
        self.controllers.values().map(|c| c.bytes_in_flight() as u64).sum()
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct CongestionController;

#[cfg(not(feature = "std"))]
pub struct CongestionManager;

#[cfg(not(feature = "std"))]
pub struct CongestionStats;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_estimator() {
        let mut est = RttEstimator::default();

        // First sample
        est.update(100_000, 0.125, 0.25); // 100ms
        assert_eq!(est.srtt, 100_000);

        // Second sample - RTT decreased
        est.update(80_000, 0.125, 0.25); // 80ms
        assert!(est.srtt < 100_000);
        assert!(est.srtt > 80_000);

        // Min RTT should be tracked
        assert_eq!(est.min_rtt, 80_000);
    }

    #[test]
    fn test_slow_start() {
        let config = CongestionConfig {
            initial_cwnd: 10_000,
            ssthresh: 50_000,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        assert_eq!(ctrl.state(), CongestionState::SlowStart);
        assert_eq!(ctrl.cwnd(), 10_000);

        // Simulate ACKs during slow start
        ctrl.on_send(5000);
        ctrl.on_ack(5000, 1, Some(50_000));

        // Window should grow
        assert!(ctrl.cwnd() > 10_000);
        assert_eq!(ctrl.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_transition_to_congestion_avoidance() {
        let config = CongestionConfig {
            initial_cwnd: 10_000,
            ssthresh: 15_000,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        // ACK enough to pass ssthresh
        ctrl.on_send(10_000);
        ctrl.on_ack(10_000, 1, Some(50_000)); // cwnd = 20_000 now

        assert_eq!(ctrl.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_timeout_recovery() {
        let config = CongestionConfig::default();
        let mut ctrl = CongestionController::new(config);

        // Build up cwnd
        for i in 0..10 {
            ctrl.on_send(1400);
            ctrl.on_ack(1400, i + 1, Some(50_000));
        }

        let cwnd_before = ctrl.cwnd();

        // Timeout
        ctrl.on_timeout();

        // Should drop to minimum and enter slow start
        assert_eq!(ctrl.state(), CongestionState::SlowStart);
        assert!(ctrl.cwnd() < cwnd_before);
        assert_eq!(ctrl.stats().timeout_losses, 1);
    }

    #[test]
    fn test_fast_retransmit() {
        let config = CongestionConfig {
            fast_retransmit_thresh: 3,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        // Initial ACK
        ctrl.on_send(1400);
        ctrl.on_ack(1400, 1, Some(50_000));

        // 3 duplicate ACKs (same seq)
        ctrl.on_ack(0, 1, None);
        ctrl.on_ack(0, 1, None);
        ctrl.on_ack(0, 1, None);

        // Should be in fast recovery
        assert_eq!(ctrl.state(), CongestionState::FastRecovery);
        assert_eq!(ctrl.stats().fast_recovery_entries, 1);
    }

    #[test]
    fn test_congestion_manager() {
        let config = CongestionConfig::default();
        let mut manager = CongestionManager::new(config);

        let peer1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let peer2: SocketAddr = "127.0.0.1:8002".parse().unwrap();

        // Create controllers for two peers
        assert!(manager.can_send(peer1, 1400));
        manager.on_send(peer1, 1400);

        assert!(manager.can_send(peer2, 1400));
        manager.on_send(peer2, 1400);

        assert_eq!(manager.peer_count(), 2);
        assert_eq!(manager.total_bytes_in_flight(), 2800);

        // ACK from peer1
        manager.on_ack(&peer1, 1400, 1, Some(50_000));
        assert_eq!(manager.total_bytes_in_flight(), 1400);
    }

    #[test]
    fn test_can_send_respects_window() {
        let config = CongestionConfig {
            initial_cwnd: 10_000,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        // Can send initially
        assert!(ctrl.can_send(5000));
        ctrl.on_send(5000);

        // Can send more
        assert!(ctrl.can_send(5000));
        ctrl.on_send(5000);

        // Window full
        assert!(!ctrl.can_send(1000));

        // After ACK, can send again
        ctrl.on_ack(5000, 1, Some(50_000));
        assert!(ctrl.can_send(1000));
    }
}
