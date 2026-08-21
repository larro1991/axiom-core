//! Async Network I/O for AXIOM
//!
//! This module provides the actual network transport:
//! - UDP sockets with async I/O
//! - Frame send/receive with codec integration
//! - Connection tracking
//! - Retry and timeout handling
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              Application                │
//! │         (send/recv Frames)              │
//! ├─────────────────────────────────────────┤
//! │            AxiomSocket                  │
//! │    (frame codec, reliability, routing)  │
//! ├─────────────────────────────────────────┤
//! │           UdpTransport                  │
//! │      (async UDP, buffering)             │
//! ├─────────────────────────────────────────┤
//! │          tokio::net::UdpSocket          │
//! └─────────────────────────────────────────┘
//! ```

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::net::SocketAddr;
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(feature = "std")]
use tokio::net::UdpSocket;
#[cfg(feature = "std")]
use tokio::sync::{mpsc, RwLock};

use axiom_codec::{Encoder, Decoder};
use axiom_types::Frame;
use axiom_types::NodeId;

/// Maximum UDP packet size (MTU - headers)
pub const MAX_PACKET_SIZE: usize = 1472;

/// Default receive buffer size
pub const DEFAULT_RECV_BUFFER: usize = 65536;

/// Network errors
#[derive(Debug)]
#[cfg(feature = "std")]
pub enum NetError {
    /// Socket bind failed
    BindFailed(std::io::Error),
    /// Send failed
    SendFailed(std::io::Error),
    /// Receive failed
    RecvFailed(std::io::Error),
    /// Frame too large for UDP
    FrameTooLarge(usize),
    /// Codec error
    CodecError(String),
    /// Timeout
    Timeout,
    /// Channel closed
    ChannelClosed,
    /// No route to destination
    NoRoute,
}

#[cfg(feature = "std")]
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::BindFailed(e) => write!(f, "bind failed: {}", e),
            NetError::SendFailed(e) => write!(f, "send failed: {}", e),
            NetError::RecvFailed(e) => write!(f, "recv failed: {}", e),
            NetError::FrameTooLarge(size) => write!(f, "frame too large: {} bytes", size),
            NetError::CodecError(e) => write!(f, "codec error: {}", e),
            NetError::Timeout => write!(f, "timeout"),
            NetError::ChannelClosed => write!(f, "channel closed"),
            NetError::NoRoute => write!(f, "no route to destination"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetError {}

/// Peer connection state
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Network address
    pub addr: SocketAddr,
    /// Node ID (if known)
    pub node_id: Option<NodeId>,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_recv: u64,
    /// Round-trip time estimate (microseconds)
    pub rtt_us: u64,
}

#[cfg(feature = "std")]
impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            node_id: None,
            last_seen: Instant::now(),
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            rtt_us: 0,
        }
    }

    pub fn with_node_id(mut self, node_id: NodeId) -> Self {
        self.node_id = Some(node_id);
        self
    }

    pub fn record_send(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    pub fn record_recv(&mut self, bytes: usize) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
        self.last_seen = Instant::now();
    }

    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Received frame with metadata
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ReceivedFrame {
    /// The frame
    pub frame: Frame,
    /// Source address
    pub from: SocketAddr,
    /// Receive timestamp
    pub received_at: Instant,
}

/// UDP transport layer
#[cfg(feature = "std")]
pub struct UdpTransport {
    /// The underlying socket
    socket: Arc<UdpSocket>,
    /// Local address
    local_addr: SocketAddr,
    /// Known peers
    peers: RwLock<HashMap<SocketAddr, PeerInfo>>,
    /// NodeId to address mapping
    node_addrs: RwLock<HashMap<NodeId, SocketAddr>>,
    /// Receive buffer size
    recv_buffer_size: usize,
    /// Stats
    total_sent: std::sync::atomic::AtomicU64,
    total_recv: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "std")]
impl UdpTransport {
    /// Bind to an address
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(NetError::BindFailed)?;

        let local_addr = socket.local_addr().map_err(NetError::BindFailed)?;

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            peers: RwLock::new(HashMap::new()),
            node_addrs: RwLock::new(HashMap::new()),
            recv_buffer_size: DEFAULT_RECV_BUFFER,
            total_sent: std::sync::atomic::AtomicU64::new(0),
            total_recv: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Register a peer's address
    pub async fn register_peer(&self, node_id: NodeId, addr: SocketAddr) {
        let mut node_addrs = self.node_addrs.write().await;
        node_addrs.insert(node_id.clone(), addr);

        let mut peers = self.peers.write().await;
        peers.entry(addr)
            .or_insert_with(|| PeerInfo::new(addr))
            .node_id = Some(node_id);
    }

    /// Get address for a node
    pub async fn get_addr(&self, node_id: &NodeId) -> Option<SocketAddr> {
        let node_addrs = self.node_addrs.read().await;
        node_addrs.get(node_id).copied()
    }

    /// Send raw bytes to an address
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(NetError::FrameTooLarge(data.len()));
        }

        let sent = self.socket
            .send_to(data, addr)
            .await
            .map_err(NetError::SendFailed)?;

        // Update stats
        self.total_sent.fetch_add(sent as u64, std::sync::atomic::Ordering::Relaxed);

        let mut peers = self.peers.write().await;
        peers.entry(addr)
            .or_insert_with(|| PeerInfo::new(addr))
            .record_send(sent);

        Ok(sent)
    }

    /// Send a frame to an address
    pub async fn send_frame(&self, frame: &Frame, addr: SocketAddr) -> Result<usize, NetError> {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        let size = Encoder::encode(frame, &mut buffer)
            .map_err(|e| NetError::CodecError(format!("{:?}", e)))?;
        self.send_to(&buffer[..size], addr).await
    }

    /// Send a frame to a node by ID
    pub async fn send_to_node(&self, frame: &Frame, node_id: &NodeId) -> Result<usize, NetError> {
        let addr = self.get_addr(node_id).await.ok_or(NetError::NoRoute)?;
        self.send_frame(frame, addr).await
    }

    /// Receive raw bytes
    pub async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        let mut buf = vec![0u8; self.recv_buffer_size];

        let (len, addr) = self.socket
            .recv_from(&mut buf)
            .await
            .map_err(NetError::RecvFailed)?;

        buf.truncate(len);

        // Update stats
        self.total_recv.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);

        let mut peers = self.peers.write().await;
        peers.entry(addr)
            .or_insert_with(|| PeerInfo::new(addr))
            .record_recv(len);

        Ok((buf, addr))
    }

    /// Receive a frame
    pub async fn recv_frame(&self) -> Result<ReceivedFrame, NetError> {
        let (data, from) = self.recv_from().await?;

        let decoded = Decoder::decode(&data)
            .map_err(|e| NetError::CodecError(format!("{:?}", e)))?;

        // Convert DecodedFrame to Frame
        let frame = Frame {
            header: decoded.header,
            trace_id: decoded.trace_id,
            fragment_info: decoded.fragment_info,
            payload_header: decoded.payload_header,
            payload: decoded.payload,
            auth: decoded.auth,
        };

        Ok(ReceivedFrame {
            frame,
            from,
            received_at: Instant::now(),
        })
    }

    /// Get peer info
    pub async fn peer_info(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(addr).cloned()
    }

    /// List all known peers
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Remove stale peers
    pub async fn cleanup_stale(&self, timeout: Duration) -> usize {
        let mut peers = self.peers.write().await;
        let before = peers.len();
        peers.retain(|_, info| !info.is_stale(timeout));
        before - peers.len()
    }

    /// Total bytes sent
    pub fn total_sent(&self) -> u64 {
        self.total_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total bytes received
    pub fn total_recv(&self) -> u64 {
        self.total_recv.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get socket clone for custom operations
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
}

/// High-level AXIOM socket
///
/// Combines UDP transport with frame handling, reliability, and routing.
#[cfg(feature = "std")]
pub struct AxiomSocket {
    /// Underlying transport
    transport: Arc<UdpTransport>,
    /// Our node ID
    local_id: NodeId,
    /// Incoming frame channel
    incoming_tx: mpsc::Sender<ReceivedFrame>,
    incoming_rx: mpsc::Receiver<ReceivedFrame>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "std")]
impl AxiomSocket {
    /// Create a new AXIOM socket
    pub async fn bind(addr: SocketAddr, local_id: NodeId) -> Result<Self, NetError> {
        let transport = Arc::new(UdpTransport::bind(addr).await?);
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);

        Ok(Self {
            transport,
            local_id,
            incoming_tx,
            incoming_rx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.transport.local_addr()
    }

    /// Get local node ID
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Register a peer
    pub async fn register_peer(&self, node_id: NodeId, addr: SocketAddr) {
        self.transport.register_peer(node_id, addr).await;
    }

    /// Send a frame to an address
    pub async fn send(&self, frame: &Frame, addr: SocketAddr) -> Result<usize, NetError> {
        self.transport.send_frame(frame, addr).await
    }

    /// Send a frame to a node
    pub async fn send_to_node(&self, frame: &Frame, node_id: &NodeId) -> Result<usize, NetError> {
        self.transport.send_to_node(frame, node_id).await
    }

    /// Receive next frame (non-blocking via channel)
    pub async fn recv(&mut self) -> Option<ReceivedFrame> {
        self.incoming_rx.recv().await
    }

    /// Start the receive loop in background
    pub fn start_recv_loop(&self) -> tokio::task::JoinHandle<()> {
        let transport = Arc::clone(&self.transport);
        let tx = self.incoming_tx.clone();
        let running = Arc::clone(&self.running);

        running.store(true, std::sync::atomic::Ordering::SeqCst);

        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                match transport.recv_frame().await {
                    Ok(frame) => {
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        // Log error in real impl
                        continue;
                    }
                }
            }
        })
    }

    /// Stop the receive loop
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get transport for direct access
    pub fn transport(&self) -> &Arc<UdpTransport> {
        &self.transport
    }

    /// List peers
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        self.transport.list_peers().await
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::{Frame, FrameHeader, FrameType, PayloadType};
    use axiom_types::trust::TrustLevel;

    fn test_node_id(id: u8) -> NodeId {
        NodeId::from_bytes([id; 32])
    }

    fn test_frame(sender_id: u8) -> Frame {
        let header = FrameHeader::new(FrameType::Stream, test_node_id(sender_id))
            .with_trust_level(TrustLevel::Raw);
        Frame::new(header, PayloadType::Raw, vec![1, 2, 3, 4])
    }

    #[tokio::test]
    async fn test_udp_transport_bind() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_udp_send_recv() {
        let t1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let t2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let addr1 = t1.local_addr();
        let addr2 = t2.local_addr();

        // Send from t1 to t2
        let data = b"hello axiom";
        t1.send_to(data, addr2).await.unwrap();

        // Receive on t2
        let (recv_data, from) = t2.recv_from().await.unwrap();
        assert_eq!(recv_data, data);
        assert_eq!(from, addr1);
    }

    #[tokio::test]
    async fn test_frame_send_recv() {
        let t1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let t2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let addr2 = t2.local_addr();

        // Send frame
        let frame = test_frame(1);
        t1.send_frame(&frame, addr2).await.unwrap();

        // Receive frame
        let received = t2.recv_frame().await.unwrap();
        assert_eq!(received.frame.payload, frame.payload);
    }

    #[tokio::test]
    async fn test_peer_registration() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let node_id = test_node_id(42);
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();

        transport.register_peer(node_id.clone(), addr).await;

        let resolved = transport.get_addr(&node_id).await;
        assert_eq!(resolved, Some(addr));
    }

    #[tokio::test]
    async fn test_peer_stats() {
        let t1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let t2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let addr2 = t2.local_addr();

        // Send multiple packets
        for _ in 0..5 {
            t1.send_to(b"test", addr2).await.unwrap();
        }

        // Check stats
        let info = t1.peer_info(&addr2).await.unwrap();
        assert_eq!(info.packets_sent, 5);
        assert_eq!(info.bytes_sent, 20); // 5 * 4 bytes
    }

    #[tokio::test]
    async fn test_axiom_socket() {
        let node1 = test_node_id(1);
        let node2 = test_node_id(2);

        let mut sock1 = AxiomSocket::bind("127.0.0.1:0".parse().unwrap(), node1.clone())
            .await
            .unwrap();
        let sock2 = AxiomSocket::bind("127.0.0.1:0".parse().unwrap(), node2.clone())
            .await
            .unwrap();

        // Register peers
        sock1.register_peer(node2.clone(), sock2.local_addr()).await;
        sock2.register_peer(node1.clone(), sock1.local_addr()).await;

        // Start recv loop on sock1
        let _handle = sock1.start_recv_loop();

        // Send from sock2 to sock1
        let frame = test_frame(2);
        sock2.send_to_node(&frame, &node1).await.unwrap();

        // Give it a moment
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Receive on sock1
        let received = sock1.recv().await.unwrap();
        assert_eq!(received.frame.payload, frame.payload);

        sock1.stop();
    }

    #[tokio::test]
    async fn test_frame_too_large() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let large_data = vec![0u8; MAX_PACKET_SIZE + 1];
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = transport.send_to(&large_data, addr).await;
        assert!(matches!(result, Err(NetError::FrameTooLarge(_))));
    }

    #[tokio::test]
    async fn test_cleanup_stale_peers() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Register a peer
        let node_id = test_node_id(1);
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        transport.register_peer(node_id, addr).await;

        // Not stale yet
        let removed = transport.cleanup_stale(Duration::from_secs(60)).await;
        assert_eq!(removed, 0);

        // With zero timeout, everything is stale
        let removed = transport.cleanup_stale(Duration::from_secs(0)).await;
        assert_eq!(removed, 1);
    }
}
