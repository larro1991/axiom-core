//! UDP transport implementation
//!
//! Provides async UDP socket handling with fragmentation support.

use crate::fragment::{Fragmenter, Reassembler};
use crate::{TransportConfig, TransportError, TransportResult};
use alloc::vec::Vec;
use axiom_codec::{Decoder, Encoder};
use axiom_types::frame::Frame;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use tokio::net::UdpSocket;

#[cfg(feature = "std")]
use tokio::time::{timeout, Duration};

/// UDP transport configuration
#[derive(Debug, Clone)]
pub struct UdpTransportConfig {
    /// Base transport config
    pub base: TransportConfig,
    /// Bind address (e.g., "0.0.0.0:0" for any available port)
    pub bind_addr: String,
}

impl Default for UdpTransportConfig {
    fn default() -> Self {
        Self {
            base: TransportConfig::default(),
            bind_addr: "0.0.0.0:0".to_string(),
        }
    }
}

/// UDP transport for AXIOM frames
#[cfg(feature = "std")]
pub struct UdpTransport {
    config: UdpTransportConfig,
    socket: Option<UdpSocket>,
    fragmenter: Fragmenter,
    reassembler: Reassembler,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
}

#[cfg(feature = "std")]
impl UdpTransport {
    /// Create a new UDP transport with the given configuration
    pub fn new(config: UdpTransportConfig) -> Self {
        let fragmenter = Fragmenter::new(config.base.mtu);
        let reassembler = Reassembler::new(
            config.base.max_reassembly_buffers,
            config.base.reassembly_timeout_ms,
        );

        Self {
            recv_buffer: vec![0u8; config.base.recv_buffer_size],
            send_buffer: vec![0u8; config.base.send_buffer_size],
            config,
            socket: None,
            fragmenter,
            reassembler,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(UdpTransportConfig::default())
    }

    /// Bind the transport to its configured address
    pub async fn bind(&mut self) -> TransportResult<SocketAddr> {
        let socket = UdpSocket::bind(&self.config.bind_addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))?;

        self.socket = Some(socket);
        Ok(local_addr)
    }

    /// Get the local address (if bound)
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.socket
            .as_ref()
            .ok_or(TransportError::NotBound)?
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Send a frame to the specified address
    ///
    /// Automatically fragments if the frame exceeds MTU
    pub async fn send_to(&mut self, frame: &Frame, addr: SocketAddr) -> TransportResult<()> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        // Fragment if needed
        let frames = if self.fragmenter.needs_fragmentation(frame) {
            self.fragmenter.fragment(frame)
        } else {
            vec![frame.clone()]
        };

        for frag in frames {
            let size = Encoder::encode(&frag, &mut self.send_buffer)?;

            if self.config.base.write_timeout_ms > 0 {
                timeout(
                    Duration::from_millis(self.config.base.write_timeout_ms),
                    socket.send_to(&self.send_buffer[..size], addr),
                )
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            } else {
                socket
                    .send_to(&self.send_buffer[..size], addr)
                    .await
                    .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Receive a frame from any address
    ///
    /// Automatically handles reassembly of fragmented frames
    pub async fn recv_from(&mut self) -> TransportResult<(Frame, SocketAddr)> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        loop {
            let (size, addr) = if self.config.base.read_timeout_ms > 0 {
                timeout(
                    Duration::from_millis(self.config.base.read_timeout_ms),
                    socket.recv_from(&mut self.recv_buffer),
                )
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?
            } else {
                socket
                    .recv_from(&mut self.recv_buffer)
                    .await
                    .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?
            };

            // Decode the frame
            let decoded = Decoder::decode(&self.recv_buffer[..size])?;

            let frame = Frame {
                header: decoded.header,
                trace_id: decoded.trace_id,
                routing: decoded.routing,
                fragment_info: decoded.fragment_info,
                payload_header: decoded.payload_header,
                payload: decoded.payload,
                auth: decoded.auth,
            };

            // Get current time for reassembly timeout
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            // Process through reassembler. A per-fragment error here (e.g. a
            // duplicate fragment - attacker-inducible by replaying one) used
            // to propagate via `?` straight out of `recv_from`, failing the
            // CALLER's receive for a completely unrelated frame that just
            // happened to arrive next. One bad/duplicate fragment from
            // anyone must not error out someone else's receive call - log
            // and drop this datagram, keep waiting for the next one.
            match self.reassembler.process(frame, now_ms) {
                Ok(Some(complete_frame)) => return Ok((complete_frame, addr)),
                Ok(None) => continue, // Fragment received, keep waiting
                Err(e) => {
                    tracing::warn!(error = %e, %addr, "dropping datagram: fragment reassembly error");
                    continue;
                }
            }
        }
    }

    /// Connect to a specific peer address
    ///
    /// After connecting, use `send` and `recv` instead of `send_to` and `recv_from`
    pub async fn connect(&mut self, addr: SocketAddr) -> TransportResult<()> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;
        socket
            .connect(addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    /// Send a frame to the connected peer
    pub async fn send(&mut self, frame: &Frame) -> TransportResult<()> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        // Fragment if needed
        let frames = if self.fragmenter.needs_fragmentation(frame) {
            self.fragmenter.fragment(frame)
        } else {
            vec![frame.clone()]
        };

        for frag in frames {
            let size = Encoder::encode(&frag, &mut self.send_buffer)?;

            if self.config.base.write_timeout_ms > 0 {
                timeout(
                    Duration::from_millis(self.config.base.write_timeout_ms),
                    socket.send(&self.send_buffer[..size]),
                )
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            } else {
                socket
                    .send(&self.send_buffer[..size])
                    .await
                    .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Receive a frame from the connected peer
    pub async fn recv(&mut self) -> TransportResult<Frame> {
        let socket = self.socket.as_ref().ok_or(TransportError::NotBound)?;

        loop {
            let size = if self.config.base.read_timeout_ms > 0 {
                timeout(
                    Duration::from_millis(self.config.base.read_timeout_ms),
                    socket.recv(&mut self.recv_buffer),
                )
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?
            } else {
                socket
                    .recv(&mut self.recv_buffer)
                    .await
                    .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?
            };

            // Decode the frame
            let decoded = Decoder::decode(&self.recv_buffer[..size])?;

            let frame = Frame {
                header: decoded.header,
                trace_id: decoded.trace_id,
                routing: decoded.routing,
                fragment_info: decoded.fragment_info,
                payload_header: decoded.payload_header,
                payload: decoded.payload,
                auth: decoded.auth,
            };

            // Get current time for reassembly timeout
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            // Process through reassembler. Same log-and-continue rationale
            // as `recv_from` above - a per-fragment error must not fail this
            // call for an unrelated datagram.
            match self.reassembler.process(frame, now_ms) {
                Ok(Some(complete_frame)) => return Ok(complete_frame),
                Ok(None) => continue, // Fragment received, keep waiting
                Err(e) => {
                    tracing::warn!(error = %e, "dropping datagram: fragment reassembly error");
                    continue;
                }
            }
        }
    }

    /// Get pending reassembly count
    pub fn pending_reassemblies(&self) -> usize {
        self.reassembler.pending_count()
    }

    /// Clear all pending reassemblies
    pub fn clear_reassemblies(&mut self) {
        self.reassembler.clear();
    }
}

// Stub for no_std
#[cfg(not(feature = "std"))]
pub struct UdpTransport;

#[cfg(not(feature = "std"))]
impl UdpTransport {
    pub fn new(_config: UdpTransportConfig) -> Self {
        Self
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::clock::HybridClock;
    use axiom_types::crypto::{IntentHash, NodeId};
    use axiom_types::frame::{FrameHeader, FrameType};
    use axiom_types::payload::PayloadType;
    use axiom_types::trust::TrustLevel;

    fn create_test_frame(payload_size: usize) -> Frame {
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x42; 32]))
            .with_trust_level(TrustLevel::Raw)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        Frame::new(header, PayloadType::Raw, vec![0xDE; payload_size])
    }

    #[tokio::test]
    async fn test_bind() {
        let mut transport = UdpTransport::with_defaults();
        let addr = transport.bind().await.unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_send_receive_small_frame() {
        // Sender
        let mut sender = UdpTransport::with_defaults();
        sender.bind().await.unwrap();

        // Receiver
        let mut receiver = UdpTransport::with_defaults();
        let recv_addr = receiver.bind().await.unwrap();

        // Send frame
        let frame = create_test_frame(100);
        sender.send_to(&frame, recv_addr).await.unwrap();

        // Receive frame
        let (received, from_addr) = tokio::time::timeout(
            Duration::from_secs(1),
            receiver.recv_from(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.payload, frame.payload);
        // The source port should match (IP may differ due to 0.0.0.0 binding)
        assert_eq!(from_addr.port(), sender.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn test_send_receive_large_fragmented_frame() {
        // Use small MTU to force fragmentation
        let mut config = UdpTransportConfig::default();
        config.base.mtu = 200;

        let mut sender = UdpTransport::new(config.clone());
        sender.bind().await.unwrap();

        let mut receiver = UdpTransport::new(config);
        let recv_addr = receiver.bind().await.unwrap();

        // Send large frame that will be fragmented
        let frame = create_test_frame(1000);
        sender.send_to(&frame, recv_addr).await.unwrap();

        // Receive and reassemble
        let (received, _) = tokio::time::timeout(
            Duration::from_secs(5),
            receiver.recv_from(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.payload.len(), 1000);
        assert_eq!(received.payload, frame.payload);
    }

    #[tokio::test]
    async fn test_connected_mode() {
        let mut server = UdpTransport::with_defaults();
        let server_addr = server.bind().await.unwrap();

        let mut client = UdpTransport::with_defaults();
        client.bind().await.unwrap();
        client.connect(server_addr).await.unwrap();

        // Send from client
        let frame = create_test_frame(50);
        client.send(&frame).await.unwrap();

        // Receive on server
        let (received, from_addr) = tokio::time::timeout(
            Duration::from_secs(1),
            server.recv_from(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.payload, frame.payload);
    }

    /// A3's acceptance bar for UdpTransport's reassembly integration: a
    /// duplicate fragment (attacker-inducible by replaying one, or just a
    /// re-sent UDP datagram) must not fail `recv_from` for the CALLER -
    /// only the bad datagram is dropped, reassembly of everything else
    /// keeps working. Previously `self.reassembler.process(frame, now_ms)?`
    /// propagated `ReassemblyError::DuplicateFragment` straight out of
    /// `recv_from`, which - in the `SecureTransport`/real-socket case -
    /// would fail the caller's receive for whatever frame happened to
    /// arrive next, not the duplicate itself.
    #[tokio::test]
    async fn test_duplicate_fragment_does_not_error_recv_from() {
        let mut config = UdpTransportConfig::default();
        config.base.mtu = 200;

        let mut sender = UdpTransport::new(config.clone());
        sender.bind().await.unwrap();
        let sender_addr = sender.local_addr().unwrap();

        let mut receiver = UdpTransport::new(config);
        let recv_addr = receiver.bind().await.unwrap();
        receiver.connect(sender_addr).await.unwrap();
        sender.connect(recv_addr).await.unwrap();

        let frame = create_test_frame(1000);
        let fragments = Fragmenter::new(200).fragment(&frame);
        assert!(fragments.len() > 2, "test needs at least 3 fragments");

        // Send fragment 0 twice (duplicate), then the rest once each.
        sender.send(&fragments[0]).await.unwrap();
        sender.send(&fragments[0]).await.unwrap();
        for frag in &fragments[1..] {
            sender.send(frag).await.unwrap();
        }

        // Despite the injected duplicate, recv() must still succeed and
        // return the fully reassembled frame - not bubble up
        // DuplicateFragment as an error to this call.
        let received = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("recv must not hang")
            .expect("recv must not error out on an unrelated duplicate fragment");

        assert_eq!(received.payload, frame.payload);
    }
}
