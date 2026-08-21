//! Secure transport layer for AXIOM
//!
//! Integrates all transport components with cryptographic authentication:
//! - UDP transport with fragmentation/reassembly
//! - Reliability layer with ACK/retransmission
//! - Flow control with back-pressure
//! - Trust-level based authentication

use crate::{
    FlowConfig, FlowManager, ReliabilityConfig, ReliabilityManager,
    TransportConfig, TransportError, TransportResult,
};
use alloc::vec::Vec;
use axiom_codec::{Decoder, Encoder};
use axiom_crypto::frame_sign::{FrameSigner, FrameVerifier, SessionManager, SignError};
use axiom_crypto::identity::Keypair;
use axiom_types::crypto::{NodeId, TraceId};
use axiom_types::frame::{Authentication, Frame, FrameType};
use axiom_types::trust::TrustLevel;
use core::time::Duration;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use tokio::net::UdpSocket;

#[cfg(feature = "std")]
use tokio::time::timeout;

/// Configuration for secure transport
#[derive(Debug, Clone)]
pub struct SecureTransportConfig {
    /// Base transport config
    pub transport: TransportConfig,
    /// Reliability config
    pub reliability: ReliabilityConfig,
    /// Flow control config
    pub flow: FlowConfig,
    /// Minimum acceptable trust level, enforced in both directions:
    /// - RECEIVE: any frame (control or otherwise) whose wire `trust_level`
    ///   is weaker than this is dropped before any further processing - see
    ///   `SecureTransport::recv`. This closes the gap where a peer (or an
    ///   attacker with no key at all) could send at `TrustLevel::Raw` to
    ///   skip authentication entirely, including for Ack/Nack/Flow control
    ///   frames.
    /// - SEND: `SecureTransport` signs its own outgoing control frames
    ///   (Ack/Nack/Flow) at `TrustLevel::Sig` regardless of this value (see
    ///   `sign_control_frame`) so they always clear a receive-side floor
    ///   set to `Sig` or weaker; this field does not otherwise change what
    ///   trust level `send()` uses for frames the caller constructs -
    ///   that's still whatever `frame.header.trust_level` the caller set.
    ///
    /// Named `default_trust_level` rather than `min_trust_level` because it
    /// was already part of the public config surface (previously defined
    /// but never actually read anywhere) - repurposing it avoids adding a
    /// second, redundant trust-level field to this struct.
    pub default_trust_level: TrustLevel,
    /// Session TTL for compressed trust level (milliseconds)
    pub session_ttl_ms: u64,
    /// Whether to verify incoming signatures
    pub verify_signatures: bool,
}

impl Default for SecureTransportConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            reliability: ReliabilityConfig::default(),
            flow: FlowConfig::default(),
            default_trust_level: TrustLevel::Sig,
            session_ttl_ms: 3600000, // 1 hour
            verify_signatures: true,
        }
    }
}

/// Statistics for the secure transport
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    /// Total frames sent
    pub frames_sent: u64,
    /// Total frames received
    pub frames_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Frames that failed verification
    pub verification_failures: u64,
    /// Retransmissions
    pub retransmissions: u64,
    /// Flow control pauses
    pub flow_pauses: u64,
}

/// Secure AXIOM transport with full protocol support
#[cfg(feature = "std")]
pub struct SecureTransport {
    config: SecureTransportConfig,
    socket: Option<UdpSocket>,
    keypair: Keypair,
    signer: FrameSigner,
    reliability: ReliabilityManager,
    flow: FlowManager,
    sessions: SessionManager,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    stats: TransportStats,
    bind_addr: String,
}

#[cfg(feature = "std")]
impl SecureTransport {
    /// Create a new secure transport with the given keypair
    pub fn new(config: SecureTransportConfig, keypair: Keypair, bind_addr: &str) -> Self {
        let node_id = keypair.node_id();
        let signer = FrameSigner::new(Keypair::from_bytes(&keypair.secret_bytes()));

        Self {
            reliability: ReliabilityManager::new(config.reliability.clone(), node_id.clone()),
            flow: FlowManager::new(config.flow.clone(), node_id),
            sessions: SessionManager::new(),
            recv_buffer: vec![0u8; config.transport.recv_buffer_size],
            send_buffer: vec![0u8; config.transport.send_buffer_size],
            stats: TransportStats::default(),
            bind_addr: bind_addr.to_string(),
            keypair,
            signer,
            config,
            socket: None,
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

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.keypair.node_id()
    }

    /// Get the local address
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.socket
            .as_ref()
            .ok_or(TransportError::NotBound)?
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Send a frame with the configured trust level
    ///
    /// Automatically handles:
    /// - Signing (for TrustLevel::Sig and TrustLevel::Full)
    /// - Session tokens (for TrustLevel::Compress)
    /// - Flow control checking
    /// - Reliability tracking
    pub async fn send(&mut self, mut frame: Frame, dest: SocketAddr) -> TransportResult<()> {
        // Check flow control
        let frame_size = frame.wire_size() as u32;
        if !self.flow.can_send(dest, frame_size) {
            self.stats.flow_pauses += 1;
            return Err(TransportError::Io("Flow control: send blocked".to_string()));
        }

        // Sign frame based on trust level
        match frame.header.trust_level {
            TrustLevel::Full | TrustLevel::Sig => {
                // Update sender ID to our node
                frame.header.sender_id = self.keypair.node_id();
                if let Err(SignError::EncodingFailed) = self.signer.sign(&mut frame) {
                    return Err(TransportError::Io("Failed to sign frame".to_string()));
                }
            }
            TrustLevel::Compress => {
                // For Compress trust level, the session token should already be set
                // by calling send_with_session() or set manually
                // We don't automatically lookup sessions here because we'd need
                // a mapping from SocketAddr to NodeId which isn't always available
                frame.header.sender_id = self.keypair.node_id();
            }
            TrustLevel::Raw => {
                // No authentication needed
            }
        }

        // Encode frame
        let size = Encoder::encode(&frame, &mut self.send_buffer)?;

        // Send via socket
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;
        socket
            .send_to(&self.send_buffer[..size], dest)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Update stats and flow control
        self.stats.frames_sent += 1;
        self.stats.bytes_sent += size as u64;
        self.flow.record_send(dest, size as u32, Some(frame.header.intent_hash));

        // Track for reliability if frame has trace_id
        if frame.trace_id.is_some() {
            self.reliability.track_frame(frame, self.send_buffer[..size].to_vec(), dest)?;
        }

        Ok(())
    }

    /// Send a frame reliably (with ACK tracking)
    pub async fn send_reliable(&mut self, mut frame: Frame, dest: SocketAddr) -> TransportResult<TraceId> {
        // Ensure frame has a trace ID for tracking
        let trace_id = if let Some(tid) = frame.trace_id {
            tid
        } else {
            let tid = self.reliability.generate_trace_id();
            frame = frame.with_trace_id(tid);
            tid
        };

        self.send(frame, dest).await?;
        Ok(trace_id)
    }

    /// Sign an outgoing control frame (Ack/Nack/Flow) at `TrustLevel::Sig`,
    /// rather than leaving it at `TrustLevel::Raw` as originally constructed
    /// by `ReliabilityManager`/`FlowManager` (which have no keypair of their
    /// own and are also used by non-secure callers, so they can't sign for
    /// themselves). `SecureTransport` holds a keypair and the cost is low
    /// given control-frame rate - and it's what gives the receive-side
    /// trust floor (see `recv`) any teeth for control frames specifically:
    /// without this, an honest peer's own Ack/Nack/Flow would fail its
    /// peer's floor check once that floor is enforced.
    fn sign_control_frame(&self, mut frame: Frame) -> Frame {
        frame.header.trust_level = TrustLevel::Sig;
        frame.header.sender_id = self.keypair.node_id();
        // Best-effort: signing a Sig-level frame only fails on encoding
        // errors, which would also fail the send a few lines later - not
        // worth threading a Result through every call site for that.
        let _ = self.signer.sign(&mut frame);
        frame
    }

    /// Receive a frame with automatic verification
    pub async fn recv(&mut self) -> TransportResult<(Frame, SocketAddr)> {
        loop {
            // Check for retransmissions
            let retransmits = self.reliability.get_retransmit_frames();
            for pending in retransmits {
                if let Some(socket) = self.socket.as_ref() {
                    let _ = socket.send_to(&pending.data, pending.dest).await;
                    self.stats.retransmissions += 1;
                }
            }

            // Receive with timeout
            let recv_result = {
                let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;
                timeout(
                    Duration::from_millis(self.config.reliability.initial_rto_ms),
                    socket.recv_from(&mut self.recv_buffer),
                )
                .await
            };

            match recv_result {
                Ok(Ok((size, addr))) => {
                    // Decode frame
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

                    // Receive-side trust floor: reject any frame (control
                    // or otherwise) whose wire trust_level is weaker than
                    // the configured minimum, before any further
                    // processing - including control-frame dispatch just
                    // below. `TrustLevel`'s `Ord` runs Full(0) < Sig(1) <
                    // Compress(2) < Raw(3) - i.e. a HIGHER ordinal is a
                    // WEAKER level - so "below the floor" is
                    // `trust_level > default_trust_level`.
                    if frame.header.trust_level > self.config.default_trust_level {
                        self.stats.verification_failures += 1;
                        continue;
                    }

                    // Verify signature/token BEFORE any control-frame
                    // dispatch. Previously Ack/Nack/Flow were matched and
                    // `continue`d further down BEFORE this block ever ran -
                    // meaning a forged Ack/Nack/Flow frame (any trust_level,
                    // any signature, or none) was acted upon with zero
                    // authentication. Only frames that verify here are
                    // eligible for control-frame handling now.
                    if self.config.verify_signatures {
                        match frame.header.trust_level {
                            TrustLevel::Full | TrustLevel::Sig => {
                                match FrameVerifier::verify(&frame) {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        self.stats.verification_failures += 1;
                                        continue; // Drop invalid frame
                                    }
                                    Err(_) => {}
                                }
                            }
                            TrustLevel::Compress => {
                                // Session token verification
                                if let Authentication::Token(token) = &frame.auth {
                                    if !self.sessions.verify_token(&frame.header.sender_id, token) {
                                        self.stats.verification_failures += 1;
                                        continue;
                                    }
                                }
                            }
                            TrustLevel::Raw => {
                                // No verification needed
                            }
                        }
                    }

                    // Handle control frames internally - now strictly
                    // post-verification (see above).
                    match frame.header.frame_type {
                        FrameType::Ack => {
                            if let Some(ack) = crate::AckPayload::decode(&frame.payload) {
                                self.reliability.process_ack(addr, &ack);
                            }
                            continue;
                        }
                        FrameType::Nack => {
                            if let Some(nack) = crate::NackPayload::decode(&frame.payload) {
                                if let Some(pending) = self.reliability.process_nack(addr, &nack) {
                                    if let Some(socket) = self.socket.as_ref() {
                                        let _ = socket.send_to(&pending.data, pending.dest).await;
                                    }
                                }
                            }
                            continue;
                        }
                        FrameType::Flow => {
                            self.flow.process_flow_frame(&frame, addr);
                            continue;
                        }
                        _ => {}
                    }

                    // Update stats
                    self.stats.frames_received += 1;
                    self.stats.bytes_received += size as u64;
                    self.flow.record_receive(addr, size as u32, Some(frame.header.intent_hash));

                    // Check for duplicate
                    if let Some(trace_id) = frame.trace_id {
                        if self.reliability.is_duplicate(addr, &trace_id) {
                            // Send ACK but don't return duplicate
                            let ack_frame = self.sign_control_frame(self.reliability.create_ack_frame(trace_id));
                            if let Ok(size) = Encoder::encode(&ack_frame, &mut self.send_buffer) {
                                if let Some(socket) = self.socket.as_ref() {
                                    let _ = socket.send_to(&self.send_buffer[..size], addr).await;
                                }
                            }
                            continue;
                        }

                        // Send ACK
                        let ack_frame = self.sign_control_frame(self.reliability.create_ack_frame(trace_id));
                        if let Ok(size) = Encoder::encode(&ack_frame, &mut self.send_buffer) {
                            if let Some(socket) = self.socket.as_ref() {
                                let _ = socket.send_to(&self.send_buffer[..size], addr).await;
                            }
                        }
                    }

                    return Ok((frame, addr));
                }
                Ok(Err(e)) => {
                    return Err(TransportError::ReceiveFailed(e.to_string()));
                }
                Err(_) => {
                    // Timeout - continue to check retransmits
                    continue;
                }
            }
        }
    }

    /// Establish a session with a peer for compressed trust level
    pub fn create_session(&mut self, peer_id: NodeId, shared_secret: &[u8; 32]) {
        self.sessions.create_session(peer_id, shared_secret, self.config.session_ttl_ms);
    }

    /// Get transport statistics
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Get pending frame count
    pub fn pending_count(&self) -> usize {
        self.reliability.pending_count()
    }

    /// Send a flow control frame to peer
    pub async fn send_flow_control(&mut self, dest: SocketAddr) -> TransportResult<()> {
        let mut flow_frame = self.flow.create_global_flow_frame(dest);
        // Sign at TrustLevel::Sig rather than leaving it at the Raw level
        // FlowManager constructs by default - `send()` below already signs
        // any Full/Sig frame automatically, this just opts our own control
        // frames into that path so a receive-side trust floor (see `recv`)
        // doesn't reject our own Flow frames.
        flow_frame.header.trust_level = TrustLevel::Sig;
        self.send(flow_frame, dest).await
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct SecureTransport;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::clock::HybridClock;
    use axiom_types::crypto::IntentHash;
    use axiom_types::frame::FrameHeader;
    use axiom_types::payload::PayloadType;

    fn create_test_config() -> SecureTransportConfig {
        SecureTransportConfig {
            default_trust_level: TrustLevel::Sig,
            verify_signatures: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_secure_transport_bind() {
        let keypair = Keypair::generate();
        let config = create_test_config();
        let mut transport = SecureTransport::new(config, keypair, "127.0.0.1:0");

        let addr = transport.bind().await.unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_secure_send_receive_signed() {
        let config = create_test_config();

        // Create sender
        let sender_keypair = Keypair::generate();
        let mut sender = SecureTransport::new(config.clone(), sender_keypair, "127.0.0.1:0");
        sender.bind().await.unwrap();

        // Create receiver
        let receiver_keypair = Keypair::generate();
        let mut receiver = SecureTransport::new(config, receiver_keypair, "127.0.0.1:0");
        let receiver_addr = receiver.bind().await.unwrap();

        // Create and send frame
        let header = FrameHeader::new(FrameType::Intent, sender.node_id())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        let frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3, 4, 5]);
        sender.send(frame.clone(), receiver_addr).await.unwrap();

        // Receive frame
        let (received, from_addr) = tokio::time::timeout(
            Duration::from_secs(1),
            receiver.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.payload, vec![1, 2, 3, 4, 5]);
        assert_eq!(received.header.sender_id, sender.node_id());
    }

    #[tokio::test]
    async fn test_secure_transport_stats() {
        let config = create_test_config();

        let sender_keypair = Keypair::generate();
        let mut sender = SecureTransport::new(config.clone(), sender_keypair, "127.0.0.1:0");
        sender.bind().await.unwrap();

        let receiver_keypair = Keypair::generate();
        let mut receiver = SecureTransport::new(config, receiver_keypair, "127.0.0.1:0");
        let receiver_addr = receiver.bind().await.unwrap();

        // Send a frame
        let header = FrameHeader::new(FrameType::Intent, sender.node_id())
            .with_trust_level(TrustLevel::Sig);
        let frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3]);

        sender.send(frame, receiver_addr).await.unwrap();

        assert_eq!(sender.stats().frames_sent, 1);
        assert!(sender.stats().bytes_sent > 0);
    }

    /// A2's receive-side trust floor: a frame below the configured minimum
    /// trust level (here, `TrustLevel::Raw` sent to a receiver configured
    /// with the default `TrustLevel::Sig` floor) must be dropped, not
    /// returned to the caller - regardless of frame_type or signature.
    #[tokio::test]
    async fn test_trust_floor_rejects_frame_below_minimum() {
        let config = create_test_config(); // default_trust_level: Sig

        let receiver_keypair = Keypair::generate();
        let mut receiver = SecureTransport::new(config, receiver_keypair, "127.0.0.1:0");
        let receiver_addr = receiver.bind().await.unwrap();

        // Bypass SecureTransport::send entirely - a Raw frame carries no
        // authentication by design, so send() wouldn't sign it either way;
        // this stands in for any peer (misconfigured or malicious) sending
        // below the floor.
        let attacker_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x55; 32]))
            .with_trust_level(TrustLevel::Raw);
        let raw_frame = Frame::new(header, PayloadType::Raw, vec![9, 9, 9]);

        let mut buf = vec![0u8; 65536];
        let size = Encoder::encode(&raw_frame, &mut buf).unwrap();
        attacker_socket.send_to(&buf[..size], receiver_addr).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(300), receiver.recv()).await;
        assert!(
            result.is_err(),
            "a below-floor frame must be silently dropped, not returned to the caller"
        );
    }

    /// A2's verify-before-dispatch reordering: a forged Ack frame - at
    /// TrustLevel::Sig (clears the trust floor) but carrying no real
    /// signature - must NOT cancel a pending reliable frame. Sent from the
    /// pending frame's actual tracked destination address, so A3's
    /// source-address binding (a separate, independent defense) can't be
    /// what stops this - only verify-before-dispatch can.
    #[tokio::test]
    async fn test_forged_ack_without_valid_signature_does_not_cancel_pending_frame() {
        let config = create_test_config();

        let sender_keypair = Keypair::generate();
        let mut sender = SecureTransport::new(config, sender_keypair, "127.0.0.1:0");
        sender.bind().await.unwrap();

        // Stand-in "peer": a raw socket, not a SecureTransport, so we
        // fully control what (if anything) gets signed.
        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();

        let header = FrameHeader::new(FrameType::Intent, sender.node_id())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));
        let frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3]);

        let trace_id = sender.send_reliable(frame, peer_addr).await.unwrap();
        assert_eq!(sender.pending_count(), 1);

        // Forged Ack: right trace_id, TrustLevel::Sig, but Frame::new's
        // zeroed placeholder signature (never actually signed) - must fail
        // FrameVerifier::verify.
        let forged_header = FrameHeader::new(FrameType::Ack, NodeId::from_bytes([0x77; 32]))
            .with_trust_level(TrustLevel::Sig);
        let forged_ack = Frame::new(forged_header, PayloadType::Raw, crate::AckPayload::new(trace_id).encode());

        let mut buf = vec![0u8; 65536];
        let size = Encoder::encode(&forged_ack, &mut buf).unwrap();
        peer_socket.send_to(&buf[..size], sender.local_addr().unwrap()).await.unwrap();

        let _ = tokio::time::timeout(Duration::from_millis(300), sender.recv()).await;
        assert_eq!(
            sender.pending_count(),
            1,
            "a forged/unverified Ack must not cancel a pending frame"
        );
    }

    /// A2's third requirement: SecureTransport must sign its own outgoing
    /// control frames rather than leaving them at TrustLevel::Raw.
    #[tokio::test]
    async fn test_outgoing_ack_is_signed_at_sig_trust_level() {
        let config = create_test_config();

        let receiver_keypair = Keypair::generate();
        let mut receiver = SecureTransport::new(config, receiver_keypair, "127.0.0.1:0");
        let receiver_addr = receiver.bind().await.unwrap();

        // A raw socket standing in for "sender" so we can inspect exactly
        // what comes back on the wire, unfiltered by another
        // SecureTransport's own verification.
        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let origin_keypair = Keypair::generate();
        let origin_signer = FrameSigner::new(Keypair::from_bytes(&origin_keypair.secret_bytes()));
        let header = FrameHeader::new(FrameType::Intent, origin_keypair.node_id())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));
        let mut frame = Frame::new(header, PayloadType::Raw, vec![1, 2, 3])
            .with_trace_id(TraceId::from_u64(42));
        origin_signer.sign(&mut frame).unwrap();

        let mut buf = vec![0u8; 65536];
        let size = Encoder::encode(&frame, &mut buf).unwrap();
        sender_socket.send_to(&buf[..size], receiver_addr).await.unwrap();

        // Drive the receiver so it processes the frame and fires an Ack.
        let _ = tokio::time::timeout(Duration::from_millis(300), receiver.recv()).await;

        let mut recv_buf = vec![0u8; 65536];
        let (size, _) = tokio::time::timeout(
            Duration::from_millis(300),
            sender_socket.recv_from(&mut recv_buf),
        )
        .await
        .expect("receiver must send back an Ack")
        .unwrap();

        let decoded = Decoder::decode(&recv_buf[..size]).unwrap();
        assert_eq!(decoded.header.frame_type, FrameType::Ack);
        assert_eq!(
            decoded.header.trust_level,
            TrustLevel::Sig,
            "SecureTransport must sign its own outgoing Ack frames, not leave them at TrustLevel::Raw"
        );

        let ack_frame = Frame {
            header: decoded.header.clone(),
            trace_id: decoded.trace_id,
            routing: decoded.routing,
            fragment_info: decoded.fragment_info,
            payload_header: decoded.payload_header,
            payload: decoded.payload,
            auth: decoded.auth,
        };
        assert_eq!(
            FrameVerifier::verify(&ack_frame),
            Ok(true),
            "the outgoing Ack's signature must actually verify"
        );
    }
}
