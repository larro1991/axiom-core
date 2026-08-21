//! AXIOM Node - Live Protocol Testing Binary
//!
//! A simple node that:
//! 1. Generates a cryptographic identity (NodeId)
//! 2. Binds to a UDP port
//! 3. Sends/receives AXIOM frames
//! 4. Performs trust negotiation with peers

use axiom_crypto::identity::Keypair;
use axiom_transport::{UdpTransport, UdpTransportConfig, TransportConfig};
use axiom_types::crypto::NodeId;
use axiom_types::frame::{Frame, FrameHeader, FrameType};
use axiom_types::payload::PayloadType;
use axiom_types::TrustLevel;

use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn, error, Level};

#[derive(Parser, Debug)]
#[command(name = "axiom-node")]
#[command(about = "AXIOM Protocol Node for live testing")]
struct Args {
    /// Node name (for logging)
    #[arg(short, long, default_value = "node")]
    name: String,

    /// Port to bind to
    #[arg(short, long, default_value = "9000")]
    port: u16,

    /// Peer address to connect to (e.g., "172.28.0.10:9000")
    #[arg(long)]
    peer: Option<String>,

    /// Run as provider (announces capability)
    #[arg(long)]
    provider: bool,

    /// Run as client (discovers and connects)
    #[arg(long)]
    client: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let args = Args::parse();

    // Generate identity
    let keypair = Keypair::generate();
    let node_id = NodeId::from_bytes(keypair.public_key_bytes());

    info!("========================================");
    info!("AXIOM Node: {}", args.name);
    info!("NodeId: {:?}", &node_id.as_bytes()[..8]);
    info!("Binding to port: {}", args.port);
    info!("========================================");

    // Create transport with configured bind address
    let config = UdpTransportConfig {
        base: TransportConfig::default(),
        bind_addr: format!("0.0.0.0:{}", args.port),
    };
    let mut transport = UdpTransport::new(config);

    // Bind to port
    let local_addr = transport.bind().await?;
    info!("Bound to: {}", local_addr);

    if args.provider {
        run_provider(&args, &mut transport, &node_id).await?;
    } else if args.client {
        run_client(&args, &mut transport, &node_id).await?;
    } else {
        // Default: run as echo server
        run_echo_server(&args, &mut transport, &node_id).await?;
    }

    Ok(())
}

/// Run as provider - listen for connections and announce capability
async fn run_provider(
    args: &Args,
    transport: &mut UdpTransport,
    node_id: &NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("[{}] Running as PROVIDER", args.name);
    info!("[{}] Waiting for client connections...", args.name);

    loop {
        // Wait for incoming frame
        match timeout(Duration::from_secs(30), transport.recv_from()).await {
            Ok(Ok((frame, from_addr))) => {
                info!("[{}] Received frame from {}", args.name, from_addr);
                info!("[{}]   Type: {:?}", args.name, frame.header.frame_type);
                info!("[{}]   Payload: {} bytes", args.name, frame.payload.len());

                // Send response
                let response = create_response_frame(node_id, &frame);
                transport.send_to(&response, from_addr).await?;
                info!("[{}] Sent response to {}", args.name, from_addr);
            }
            Ok(Err(e)) => {
                warn!("[{}] Receive error: {}", args.name, e);
            }
            Err(_) => {
                info!("[{}] No activity for 30s, still listening...", args.name);
            }
        }
    }
}

/// Run as client - connect to peer and send messages
async fn run_client(
    args: &Args,
    transport: &mut UdpTransport,
    node_id: &NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr: SocketAddr = args.peer.as_ref()
        .ok_or("Client mode requires --peer address")?
        .parse()?;

    info!("[{}] Running as CLIENT", args.name);
    info!("[{}] Connecting to peer: {}", args.name, peer_addr);

    // Wait a bit for provider to be ready
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send hello frame
    let hello = create_hello_frame(node_id);
    info!("[{}] Sending HELLO to {}", args.name, peer_addr);
    transport.send_to(&hello, peer_addr).await?;

    // Wait for response
    match timeout(Duration::from_secs(10), transport.recv_from()).await {
        Ok(Ok((frame, from_addr))) => {
            info!("[{}] Received response from {}", args.name, from_addr);
            info!("[{}]   Type: {:?}", args.name, frame.header.frame_type);
            info!("[{}]   Payload: {} bytes", args.name, frame.payload.len());
            info!("[{}] HANDSHAKE SUCCESSFUL!", args.name);
        }
        Ok(Err(e)) => {
            error!("[{}] Receive error: {}", args.name, e);
        }
        Err(_) => {
            error!("[{}] Timeout waiting for response", args.name);
        }
    }

    // Send a few more messages
    for i in 1..=3 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let msg = create_stream_frame(node_id, format!("Message {}", i).as_bytes());
        info!("[{}] Sending message {}", args.name, i);
        transport.send_to(&msg, peer_addr).await?;

        match timeout(Duration::from_secs(5), transport.recv_from()).await {
            Ok(Ok((_frame, _))) => {
                info!("[{}] Got response for message {}", args.name, i);
            }
            _ => {
                warn!("[{}] No response for message {}", args.name, i);
            }
        }
    }

    info!("[{}] Client test complete!", args.name);
    Ok(())
}

/// Run as echo server - respond to any frame
async fn run_echo_server(
    args: &Args,
    transport: &mut UdpTransport,
    node_id: &NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("[{}] Running as ECHO SERVER", args.name);

    loop {
        match timeout(Duration::from_secs(60), transport.recv_from()).await {
            Ok(Ok((frame, from_addr))) => {
                info!("[{}] Echo: received from {}", args.name, from_addr);

                // Echo back
                let response = create_response_frame(node_id, &frame);
                transport.send_to(&response, from_addr).await?;
                info!("[{}] Echo: sent response", args.name);
            }
            Ok(Err(e)) => {
                warn!("[{}] Error: {}", args.name, e);
            }
            Err(_) => {
                info!("[{}] Idle timeout, still running...", args.name);
            }
        }
    }
}

/// Create a hello frame for initial contact
fn create_hello_frame(node_id: &NodeId) -> Frame {
    let header = FrameHeader::new(FrameType::Trust, node_id.clone())
        .with_trust_level(TrustLevel::Raw);

    // Hello payload: version (2 bytes) + "HELLO" + node_id
    let mut payload = vec![0x00, 0x01]; // Version 1
    payload.extend_from_slice(b"HELLO");
    payload.extend_from_slice(node_id.as_bytes());

    Frame::new(header, PayloadType::Raw, payload)
}

/// Create a stream frame (for data transfer)
fn create_stream_frame(node_id: &NodeId, data: &[u8]) -> Frame {
    let header = FrameHeader::new(FrameType::Stream, node_id.clone())
        .with_trust_level(TrustLevel::Raw);

    Frame::new(header, PayloadType::Raw, data.to_vec())
}

/// Create a response frame
fn create_response_frame(node_id: &NodeId, request: &Frame) -> Frame {
    let header = FrameHeader::new(FrameType::Fulfill, node_id.clone())
        .with_trust_level(TrustLevel::Raw);

    // Response: "ACK" + original payload length
    let mut payload = b"ACK:".to_vec();
    payload.extend_from_slice(&(request.payload.len() as u32).to_be_bytes());

    Frame::new(header, PayloadType::Raw, payload)
}
