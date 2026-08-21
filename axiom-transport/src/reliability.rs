//! Reliability layer for AXIOM transport
//!
//! Provides ACK-based reliable delivery with retransmission support.

use crate::{TransportError, TransportResult};
use alloc::vec::Vec;
use axiom_codec::{Decoder, Encoder};
use axiom_types::crypto::{NodeId, TraceId};
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;
use core::time::Duration;

#[cfg(feature = "std")]
use hashbrown::HashMap;

#[cfg(feature = "std")]
use std::collections::VecDeque;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use tokio::net::UdpSocket;

#[cfg(feature = "std")]
use tokio::time::{timeout, Instant};

/// Bound on `ReliabilityManager::received`'s size - oldest entries evicted
/// first once exceeded, same FIFO-backstop pattern as
/// `forge-node`'s `ForwardedFrameCache`/`FORWARD_DEDUP_CAPACITY`. Needed
/// because `received` is now keyed per-source-address (see `is_duplicate`),
/// which opens a NEW unbounded-growth vector versus the old
/// trace_id-only keying: a spoofed UDP source (or many distinct real ones)
/// sending frames with distinct trace_ids grows this map by one entry per
/// packet, and the existing time-based `cleanup_received` sweep only runs
/// every `received_cleanup_interval` - not per-insert - so it doesn't bound
/// growth WITHIN that window on its own.
#[cfg(feature = "std")]
const RECEIVED_DEDUP_CAPACITY: usize = 8192;

/// Configuration for the reliability layer
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    /// Initial retransmission timeout (milliseconds)
    pub initial_rto_ms: u64,
    /// Maximum retransmission timeout (milliseconds)
    pub max_rto_ms: u64,
    /// Maximum number of retransmission attempts
    pub max_retries: u32,
    /// ACK delay (milliseconds) - wait to batch ACKs
    pub ack_delay_ms: u64,
    /// Maximum number of pending (unacknowledged) frames
    pub max_pending: usize,
    /// Selective ACK window size
    pub sack_window: u32,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            initial_rto_ms: 200,
            max_rto_ms: 60000,
            max_retries: 10,
            ack_delay_ms: 20,
            max_pending: 1000,
            sack_window: 32,
        }
    }
}

/// Acknowledgment payload structure
/// Layout: [trace_id: 8 bytes][ack_count: u16][sack_bitmap: u32]
#[derive(Debug, Clone)]
pub struct AckPayload {
    /// The trace ID being acknowledged
    pub trace_id: TraceId,
    /// Cumulative ACK count (number of consecutive frames received)
    pub ack_count: u16,
    /// Selective ACK bitmap (bits set for out-of-order frames received)
    pub sack_bitmap: u32,
}

impl AckPayload {
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            ack_count: 1,
            sack_bitmap: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(14);
        payload.extend_from_slice(self.trace_id.as_bytes());
        payload.extend_from_slice(&self.ack_count.to_be_bytes());
        payload.extend_from_slice(&self.sack_bitmap.to_be_bytes());
        payload
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let mut trace_bytes = [0u8; 8];
        trace_bytes.copy_from_slice(&data[0..8]);
        let trace_id = TraceId::from_bytes(trace_bytes);

        let ack_count = u16::from_be_bytes([data[8], data[9]]);
        let sack_bitmap = u32::from_be_bytes([data[10], data[11], data[12], data[13]]);

        Some(Self {
            trace_id,
            ack_count,
            sack_bitmap,
        })
    }
}

/// NACK payload structure (request retransmission)
/// Layout: [trace_id: 8 bytes][missing_seq: u16]
#[derive(Debug, Clone)]
pub struct NackPayload {
    /// The trace ID for the stream with missing frames
    pub trace_id: TraceId,
    /// The sequence number of the missing frame
    pub missing_seq: u16,
}

impl NackPayload {
    pub fn new(trace_id: TraceId, missing_seq: u16) -> Self {
        Self { trace_id, missing_seq }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(10);
        payload.extend_from_slice(self.trace_id.as_bytes());
        payload.extend_from_slice(&self.missing_seq.to_be_bytes());
        payload
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let mut trace_bytes = [0u8; 8];
        trace_bytes.copy_from_slice(&data[0..8]);
        let trace_id = TraceId::from_bytes(trace_bytes);

        let missing_seq = u16::from_be_bytes([data[8], data[9]]);

        Some(Self { trace_id, missing_seq })
    }
}

/// Tracks a pending frame awaiting acknowledgment
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PendingFrame {
    /// The frame data (encoded)
    pub data: Vec<u8>,
    /// Original frame for reference
    pub frame: Frame,
    /// Destination address
    pub dest: SocketAddr,
    /// Time of last transmission
    pub last_sent: Instant,
    /// Number of transmission attempts
    pub attempts: u32,
    /// Current retransmission timeout
    pub rto_ms: u64,
}

/// Manages reliable delivery for a connection
#[cfg(feature = "std")]
pub struct ReliabilityManager {
    config: ReliabilityConfig,
    /// Frames pending acknowledgment, keyed by trace_id
    pending: HashMap<TraceId, PendingFrame>,
    /// Our node ID for generating frames
    node_id: NodeId,
    /// Received (source_addr, trace_id) pairs for duplicate detection -
    /// keyed per-peer, NOT on trace_id alone. Every sender's trace_id
    /// values can collide with another sender's (previously because both
    /// started a sequential counter at 1; now, even with random trace_ids,
    /// two peers CAN still legitimately land on the same 64-bit value) - a
    /// global `HashMap<TraceId, Instant>` meant peer B's frame could be
    /// wrongly dropped as a duplicate of peer A's merely because they
    /// shared a trace_id.
    received: HashMap<(SocketAddr, TraceId), Instant>,
    /// Insertion order for `received`, for `RECEIVED_DEDUP_CAPACITY` FIFO
    /// eviction - see that constant's doc comment.
    received_order: VecDeque<(SocketAddr, TraceId)>,
    /// Cleanup threshold for received map
    received_cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: Instant,
}

#[cfg(feature = "std")]
impl ReliabilityManager {
    /// Create a new reliability manager
    pub fn new(config: ReliabilityConfig, node_id: NodeId) -> Self {
        Self {
            config,
            pending: HashMap::new(),
            node_id,
            received: HashMap::new(),
            received_order: VecDeque::new(),
            received_cleanup_interval: Duration::from_secs(60),
            last_cleanup: Instant::now(),
        }
    }

    /// Generate a new trace ID for reliable delivery.
    ///
    /// Random, not sequential (previously a bare incrementing counter via
    /// `TraceId::from_u64(seq_counter)`) - a predictable trace_id is what
    /// made forging Ack/Nack/Flow control frames practical in the first
    /// place: guessing a peer's next in-flight trace_id used to be free.
    ///
    /// Tradeoff, documented rather than solved here: `AckPayload`'s
    /// `ack_count`/`sack_bitmap` fields suggest an eventually-intended
    /// cumulative/windowed-ACK design that would want trace_ids ordered
    /// per-peer. `process_ack` only ever reads the bare `trace_id` field
    /// today - `ack_count`/`sack_bitmap` are decoded but not read anywhere
    /// in the current code - so nothing depends on sequential ordering
    /// right now. Randomizing trace_ids forecloses that cumulative-ACK
    /// design unless a SEPARATE per-peer sequence number is added later
    /// specifically for it.
    pub fn generate_trace_id(&mut self) -> TraceId {
        let random_id: u64 = rand::RngCore::next_u64(&mut rand::rngs::OsRng);
        TraceId::from_u64(random_id)
    }

    /// Track a frame for reliable delivery
    pub fn track_frame(&mut self, frame: Frame, data: Vec<u8>, dest: SocketAddr) -> TransportResult<()> {
        let trace_id = frame.trace_id.ok_or_else(|| {
            TransportError::Io("Frame must have trace_id for reliable delivery".to_string())
        })?;

        if self.pending.len() >= self.config.max_pending {
            return Err(TransportError::Io("Too many pending frames".to_string()));
        }

        let pending = PendingFrame {
            data,
            frame,
            dest,
            last_sent: Instant::now(),
            attempts: 1,
            rto_ms: self.config.initial_rto_ms,
        };

        self.pending.insert(trace_id, pending);
        Ok(())
    }

    /// Process an incoming ACK frame.
    ///
    /// `source` is the address the Ack actually arrived from - it must
    /// match the address `PendingFrame` was originally sent to
    /// (`pending.dest`) or the ack is rejected. Defense in depth alongside
    /// control-frame signing (see `SecureTransport::sign_control_frame`):
    /// a `NodeId` doesn't inherently bind to a network address anywhere in
    /// this crate, so an attacker with their OWN valid keypair could still
    /// produce a validly-SIGNED Ack under their own identity; checking the
    /// arrival address against the frame's actual tracked destination
    /// closes that gap.
    pub fn process_ack(&mut self, source: SocketAddr, ack: &AckPayload) -> Option<()> {
        let pending = self.pending.get(&ack.trace_id)?;
        if pending.dest != source {
            return None;
        }
        self.pending.remove(&ack.trace_id);
        Some(())
    }

    /// Process an incoming NACK frame, returns frame to retransmit if found.
    ///
    /// Respects `max_retries` the same way the timeout-driven path
    /// (`get_retransmit_frames`) already does - previously this
    /// incremented `attempts` and returned the frame for retransmission
    /// UNCONDITIONALLY, meaning NACK-driven retransmission had no cap at
    /// all (worse than the timeout path, which at least had one). Also
    /// checks `source` against `pending.dest` - see `process_ack`'s doc
    /// comment for why.
    pub fn process_nack(&mut self, source: SocketAddr, nack: &NackPayload) -> Option<PendingFrame> {
        let pending = self.pending.get_mut(&nack.trace_id)?;

        if pending.dest != source {
            return None;
        }

        if pending.attempts >= self.config.max_retries {
            // Same cap `get_retransmit_frames` enforces on timeout -
            // give up and evict rather than retransmit forever.
            self.pending.remove(&nack.trace_id);
            return None;
        }

        pending.last_sent = Instant::now();
        pending.attempts += 1;
        Some(pending.clone())
    }

    /// Get frames that need retransmission (timeout expired)
    pub fn get_retransmit_frames(&mut self) -> Vec<PendingFrame> {
        let now = Instant::now();
        let mut retransmit = Vec::new();
        let mut expired = Vec::new();

        for (trace_id, pending) in self.pending.iter_mut() {
            let elapsed = now.duration_since(pending.last_sent).as_millis() as u64;

            if elapsed >= pending.rto_ms {
                if pending.attempts >= self.config.max_retries {
                    // Too many retries, mark for removal
                    expired.push(*trace_id);
                } else {
                    // Schedule retransmission
                    pending.attempts += 1;
                    pending.last_sent = now;
                    // Exponential backoff
                    pending.rto_ms = (pending.rto_ms * 2).min(self.config.max_rto_ms);
                    retransmit.push(pending.clone());
                }
            }
        }

        // Remove expired frames
        for trace_id in expired {
            self.pending.remove(&trace_id);
        }

        retransmit
    }

    /// Create an ACK frame for a received frame
    pub fn create_ack_frame(&self, trace_id: TraceId) -> Frame {
        let header = FrameHeader::new(FrameType::Ack, self.node_id.clone())
            .with_trust_level(TrustLevel::Raw);

        let ack_payload = AckPayload::new(trace_id);
        Frame::new(header, PayloadType::Raw, ack_payload.encode())
    }

    /// Create a NACK frame requesting retransmission
    pub fn create_nack_frame(&self, trace_id: TraceId, missing_seq: u16) -> Frame {
        let header = FrameHeader::new(FrameType::Nack, self.node_id.clone())
            .with_trust_level(TrustLevel::Raw);

        let nack_payload = NackPayload::new(trace_id, missing_seq);
        Frame::new(header, PayloadType::Raw, nack_payload.encode())
    }

    /// Check if we've already received this frame (duplicate detection).
    ///
    /// Keyed on `(source, trace_id)`, not `trace_id` alone - see
    /// `received`'s doc comment. Bounded by `RECEIVED_DEDUP_CAPACITY` (FIFO
    /// eviction) in addition to the existing time-based sweep, since
    /// per-address keying opens a new unbounded-growth vector (see that
    /// constant's doc comment).
    pub fn is_duplicate(&mut self, source: SocketAddr, trace_id: &TraceId) -> bool {
        // Cleanup old entries periodically
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > self.received_cleanup_interval {
            self.cleanup_received();
            self.last_cleanup = now;
        }

        let key = (source, *trace_id);
        if self.received.contains_key(&key) {
            return true;
        }

        self.received.insert(key, now);
        self.received_order.push_back(key);
        if self.received_order.len() > RECEIVED_DEDUP_CAPACITY {
            if let Some(oldest) = self.received_order.pop_front() {
                self.received.remove(&oldest);
            }
        }

        false
    }

    /// Clean up old received entries
    fn cleanup_received(&mut self) {
        let now = Instant::now();
        let threshold = self.received_cleanup_interval;
        self.received.retain(|_, instant| now.duration_since(*instant) < threshold);

        // Drop any now-stale keys from the order queue too, so it doesn't
        // grow forever holding references to entries already gone from
        // `received`. Explicit field borrow (rather than a method-call
        // closure on `self`) keeps this a simple two-field disjoint borrow.
        let received = &self.received;
        self.received_order.retain(|key| received.contains_key(key));
    }

    /// Get number of pending frames
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear all pending frames
    pub fn clear(&mut self) {
        self.pending.clear();
        self.received.clear();
        self.received_order.clear();
    }
}

/// Reliable UDP transport wrapper
#[cfg(feature = "std")]
pub struct ReliableTransport {
    socket: Option<UdpSocket>,
    manager: ReliabilityManager,
    config: ReliabilityConfig,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    bind_addr: String,
}

#[cfg(feature = "std")]
impl ReliableTransport {
    /// Create a new reliable transport
    pub fn new(config: ReliabilityConfig, node_id: NodeId, bind_addr: &str) -> Self {
        Self {
            socket: None,
            manager: ReliabilityManager::new(config.clone(), node_id),
            config,
            recv_buffer: vec![0u8; 65536],
            send_buffer: vec![0u8; 65536],
            bind_addr: bind_addr.to_string(),
        }
    }

    /// Bind to the configured address
    pub async fn bind(&mut self) -> TransportResult<SocketAddr> {
        let socket = UdpSocket::bind(&self.bind_addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))?;

        self.socket = Some(socket);
        Ok(local_addr)
    }

    /// Send a frame reliably (with ACK tracking)
    pub async fn send_reliable(&mut self, mut frame: Frame, dest: SocketAddr) -> TransportResult<TraceId> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        // Assign a trace ID if not present
        let trace_id = if let Some(tid) = frame.trace_id {
            tid
        } else {
            let tid = self.manager.generate_trace_id();
            frame = frame.with_trace_id(tid);
            tid
        };

        // Encode the frame
        let size = Encoder::encode(&frame, &mut self.send_buffer)?;
        let data = self.send_buffer[..size].to_vec();

        // Track for acknowledgment
        self.manager.track_frame(frame, data.clone(), dest)?;

        // Send
        socket
            .send_to(&data, dest)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        Ok(trace_id)
    }

    /// Send a frame without reliability (fire and forget)
    pub async fn send_unreliable(&mut self, frame: &Frame, dest: SocketAddr) -> TransportResult<()> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        let size = Encoder::encode(frame, &mut self.send_buffer)?;
        socket
            .send_to(&self.send_buffer[..size], dest)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Receive a frame, automatically handling ACK/NACK
    pub async fn recv(&mut self) -> TransportResult<(Frame, SocketAddr)> {
        loop {
            // Check socket is bound
            if self.socket.is_none() {
                return Err(TransportError::NotBound);
            }

            // Check for retransmissions first
            let retransmits = self.manager.get_retransmit_frames();
            for pending in retransmits {
                if let Some(socket) = self.socket.as_ref() {
                    let _ = socket.send_to(&pending.data, pending.dest).await;
                }
            }

            // Receive with timeout to allow retransmit checking
            let recv_result = {
                let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;
                timeout(
                    Duration::from_millis(self.config.initial_rto_ms),
                    socket.recv_from(&mut self.recv_buffer),
                )
                .await
            };

            match recv_result {
                Ok(Ok((size, addr))) => {
                    let decoded = Decoder::decode(&self.recv_buffer[..size])?;

                    let frame = Frame {
                        header: decoded.header.clone(),
                        trace_id: decoded.trace_id,
                        routing: decoded.routing,
                        fragment_info: decoded.fragment_info,
                        payload_header: decoded.payload_header,
                        payload: decoded.payload,
                        auth: decoded.auth,
                    };

                    match frame.header.frame_type {
                        FrameType::Ack => {
                            // Process ACK
                            if let Some(ack) = AckPayload::decode(&frame.payload) {
                                self.manager.process_ack(addr, &ack);
                            }
                            continue; // Don't return ACK frames to caller
                        }
                        FrameType::Nack => {
                            // Process NACK - retransmit if we have the frame
                            if let Some(nack) = NackPayload::decode(&frame.payload) {
                                if let Some(pending) = self.manager.process_nack(addr, &nack) {
                                    if let Some(socket) = self.socket.as_ref() {
                                        let _ = socket.send_to(&pending.data, pending.dest).await;
                                    }
                                }
                            }
                            continue; // Don't return NACK frames to caller
                        }
                        _ => {
                            // Regular frame - send ACK if it has a trace_id
                            if let Some(trace_id) = frame.trace_id {
                                // Check for duplicate
                                let is_dup = self.manager.is_duplicate(addr, &trace_id);

                                // Send ACK (even for duplicates - sender might need it)
                                let ack_frame = self.manager.create_ack_frame(trace_id);
                                if let Ok(size) = Encoder::encode(&ack_frame, &mut self.send_buffer) {
                                    if let Some(socket) = self.socket.as_ref() {
                                        let _ = socket.send_to(&self.send_buffer[..size], addr).await;
                                    }
                                }

                                if is_dup {
                                    continue;
                                }
                            }
                            return Ok((frame, addr));
                        }
                    }
                }
                Ok(Err(e)) => {
                    return Err(TransportError::ReceiveFailed(e.to_string()));
                }
                Err(_) => {
                    // Timeout - continue loop to check retransmits
                    continue;
                }
            }
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.socket
            .as_ref()
            .ok_or(TransportError::NotBound)?
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Get pending frame count
    pub fn pending_count(&self) -> usize {
        self.manager.pending_count()
    }

    /// Wait for all pending frames to be acknowledged
    pub async fn flush(&mut self, timeout_ms: u64) -> TransportResult<()> {
        let start = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);

        while self.manager.pending_count() > 0 {
            if start.elapsed() > timeout_duration {
                return Err(TransportError::Timeout);
            }

            // Process receives (which handles ACKs)
            let _ = timeout(Duration::from_millis(100), self.recv()).await;
        }

        Ok(())
    }
}

// Stub for no_std
#[cfg(not(feature = "std"))]
pub struct ReliabilityManager;

#[cfg(not(feature = "std"))]
pub struct ReliableTransport;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::clock::HybridClock;
    use axiom_types::crypto::IntentHash;

    fn create_test_frame(payload: Vec<u8>) -> Frame {
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x42; 32]))
            .with_trust_level(TrustLevel::Raw)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        Frame::new(header, PayloadType::Raw, payload)
    }

    #[test]
    fn test_ack_payload_roundtrip() {
        let trace_id = TraceId::from_u64(0x123456789ABCDEF0);
        let mut ack = AckPayload::new(trace_id);
        ack.ack_count = 5;
        ack.sack_bitmap = 0b1010_1010;

        let encoded = ack.encode();
        let decoded = AckPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.trace_id, trace_id);
        assert_eq!(decoded.ack_count, 5);
        assert_eq!(decoded.sack_bitmap, 0b1010_1010);
    }

    #[test]
    fn test_nack_payload_roundtrip() {
        let trace_id = TraceId::from_u64(0xFEDCBA9876543210);
        let nack = NackPayload::new(trace_id, 42);

        let encoded = nack.encode();
        let decoded = NackPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.trace_id, trace_id);
        assert_eq!(decoded.missing_seq, 42);
    }

    #[test]
    fn test_reliability_manager_tracking() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        // Trace IDs are random now, not sequential (see
        // test_generate_trace_id_is_random_not_sequential for the dedicated
        // adversarial test) - just confirm two draws are usable and distinct.
        let trace_id = manager.generate_trace_id();
        let trace_id2 = manager.generate_trace_id();
        assert_ne!(trace_id, trace_id2);
    }

    /// A3: `generate_trace_id` must not be a predictable sequential
    /// counter - that predictability is what made forging Ack/Nack/Flow
    /// control frames practical (guessing the next trace_id was free).
    #[test]
    fn test_generate_trace_id_is_random_not_sequential() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let a = manager.generate_trace_id();
        let b = manager.generate_trace_id();

        assert_ne!(a, b);
        // A sequential-counter implementation would produce exactly these
        // two values in order - vanishingly unlikely by chance from a real
        // random source.
        assert_ne!(a, TraceId::from_u64(1));
        assert_ne!(b, TraceId::from_u64(2));
    }

    #[test]
    fn test_duplicate_detection() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let addr: SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let trace_id = TraceId::from_u64(12345);

        // First time should not be duplicate
        assert!(!manager.is_duplicate(addr, &trace_id));

        // Second time should be duplicate
        assert!(manager.is_duplicate(addr, &trace_id));
    }

    /// A3: dedup must be scoped per-peer, not global on trace_id alone -
    /// two different senders whose trace_ids happen to collide (previously
    /// guaranteed on "frame #1" from every peer, since both counters
    /// started at 1) must not shadow each other.
    #[test]
    fn test_duplicate_detection_is_per_peer_not_global() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let addr_a: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        let trace_id = TraceId::from_u64(1); // both peers' "first frame"

        assert!(!manager.is_duplicate(addr_a, &trace_id), "peer A's frame 1 is new");
        assert!(
            !manager.is_duplicate(addr_b, &trace_id),
            "peer B's frame 1 must NOT be treated as a duplicate of peer A's frame 1"
        );
        assert!(manager.is_duplicate(addr_a, &trace_id), "peer A's frame 1 seen again IS a duplicate");
        assert!(manager.is_duplicate(addr_b, &trace_id), "peer B's frame 1 seen again IS a duplicate");
    }

    /// A3: `received`'s new per-address keying must still be capacity
    /// bounded - a burst of distinct (addr, trace_id) pairs (spoofed or
    /// real) must not grow the map without limit.
    #[test]
    fn test_received_dedup_capacity_is_bounded() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        for i in 0..(RECEIVED_DEDUP_CAPACITY as u64 + 500) {
            let addr: SocketAddr = format!("127.0.0.1:{}", 1024 + (i % 60000)).parse().unwrap();
            manager.is_duplicate(addr, &TraceId::from_u64(i));
        }

        assert!(
            manager.received.len() <= RECEIVED_DEDUP_CAPACITY,
            "received map must be capacity-bounded, not grow without limit: got {}",
            manager.received.len()
        );
    }

    /// A3: NACK-driven retransmission must respect `max_retries`, the same
    /// way the timeout-driven path (`get_retransmit_frames`) already does.
    /// Previously `process_nack` had no cap at all.
    #[test]
    fn test_nack_retransmission_respects_max_retries() {
        let mut config = ReliabilityConfig::default();
        config.max_retries = 2;
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let trace_id = TraceId::from_u64(999);
        let mut frame = create_test_frame(vec![1, 2, 3]);
        frame.trace_id = Some(trace_id);
        manager.track_frame(frame, vec![0u8; 10], dest).unwrap();

        let nack = NackPayload::new(trace_id, 0);

        // track_frame starts attempts at 1; max_retries = 2.
        assert!(manager.process_nack(dest, &nack).is_some(), "first NACK-driven retry is allowed");
        assert!(
            manager.process_nack(dest, &nack).is_none(),
            "NACK-driven retransmission must stop once max_retries is reached"
        );
        assert_eq!(
            manager.pending_count(),
            0,
            "frame must be evicted once max_retries is exceeded via the NACK path"
        );
    }

    /// A3: defense-in-depth source-address binding for `process_ack` -
    /// `PendingFrame` already stores the destination address the frame was
    /// actually sent to; an Ack arriving from a different address must be
    /// rejected even if (hypothetically) it were otherwise well-formed.
    #[test]
    fn test_ack_from_wrong_source_is_rejected() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let real_dest: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let attacker_addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();

        let trace_id = TraceId::from_u64(777);
        let mut frame = create_test_frame(vec![1, 2, 3]);
        frame.trace_id = Some(trace_id);
        manager.track_frame(frame, vec![0u8; 10], real_dest).unwrap();
        assert_eq!(manager.pending_count(), 1);

        let ack = AckPayload::new(trace_id);
        assert!(
            manager.process_ack(attacker_addr, &ack).is_none(),
            "ack from the wrong source must be rejected"
        );
        assert_eq!(manager.pending_count(), 1, "pending frame must survive a wrong-source ack");

        assert!(manager.process_ack(real_dest, &ack).is_some());
        assert_eq!(manager.pending_count(), 0);
    }

    /// Same source-address binding, for `process_nack`.
    #[test]
    fn test_nack_from_wrong_source_is_rejected() {
        let config = ReliabilityConfig::default();
        let node_id = NodeId::from_bytes([0x11; 32]);
        let mut manager = ReliabilityManager::new(config, node_id);

        let real_dest: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        let attacker_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();

        let trace_id = TraceId::from_u64(778);
        let mut frame = create_test_frame(vec![4, 5, 6]);
        frame.trace_id = Some(trace_id);
        manager.track_frame(frame, vec![0u8; 10], real_dest).unwrap();

        let nack = NackPayload::new(trace_id, 0);
        assert!(
            manager.process_nack(attacker_addr, &nack).is_none(),
            "nack from the wrong source must be rejected"
        );
        assert_eq!(manager.pending_count(), 1, "pending frame must survive a wrong-source nack");
    }

    #[tokio::test]
    async fn test_reliable_send_receive() {
        let config = ReliabilityConfig::default();

        // Create sender
        let sender_node = NodeId::from_bytes([0x11; 32]);
        let mut sender = ReliableTransport::new(config.clone(), sender_node, "127.0.0.1:0");
        sender.bind().await.unwrap();

        // Create receiver
        let receiver_node = NodeId::from_bytes([0x22; 32]);
        let mut receiver = ReliableTransport::new(config, receiver_node, "127.0.0.1:0");
        let receiver_addr = receiver.bind().await.unwrap();

        // Send frame
        let frame = create_test_frame(vec![1, 2, 3, 4, 5]);
        let trace_id = sender.send_reliable(frame.clone(), receiver_addr).await.unwrap();

        // Receive frame
        let (received, from_addr) = tokio::time::timeout(
            Duration::from_secs(1),
            receiver.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.payload, vec![1, 2, 3, 4, 5]);
        assert_eq!(received.trace_id, Some(trace_id));

        // Wait for ACK
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Process ACK on sender side
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            sender.recv(),
        ).await;

        // Note: We'd need to check pending count is 0, but the ACK loop runs in recv()
    }
}
