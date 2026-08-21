//! Transport Layer for AXIOM
//!
//! Provides UDP transport with fragmentation, reassembly, reliability, and security.
//!
//! # Layers
//!
//! - `UdpTransport`: Raw UDP with fragmentation/reassembly
//! - `ReliableTransport`: ACK-based reliability on top of UDP
//! - `SecureTransport`: Full-featured transport with authentication

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]
#![allow(private_interfaces)]

extern crate alloc;

mod flow;
mod fragment;
mod reliability;
mod secure;
mod udp;

pub mod bridge;
pub mod identity_routing;
pub mod tiered;
pub mod cross_tier_auth;

#[cfg(feature = "quic")]
pub mod wan;

pub use flow::{FlowConfig, FlowManager, FlowPayload, FlowState, FlowTracker};
pub use fragment::{Fragmenter, Reassembler, ReassemblyError};
pub use reliability::{
    AckPayload, NackPayload, ReliabilityConfig, ReliabilityManager, ReliableTransport,
};
pub use secure::{SecureTransport, SecureTransportConfig, TransportStats};
pub use udp::{UdpTransport, UdpTransportConfig};
pub use cross_tier_auth::{
    AuthToken, TokenIssuer, TokenVerifier, TrustedIssuer,
    TrustTier, Capability, TokenError,
    serialize_token, deserialize_token,
};

use axiom_types::error::CodecError;
use thiserror::Error;

/// Transport errors
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("Timeout")]
    Timeout,

    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),

    #[error("Address parse error: {0}")]
    AddressParse(String),

    #[error("Reassembly error: {0}")]
    Reassembly(#[from] ReassemblyError),

    #[error("Frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Socket not bound")]
    NotBound,
}

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Base transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum transmission unit (bytes)
    pub mtu: usize,
    /// Receive buffer size
    pub recv_buffer_size: usize,
    /// Send buffer size
    pub send_buffer_size: usize,
    /// Read timeout (milliseconds), 0 = no timeout
    pub read_timeout_ms: u64,
    /// Write timeout (milliseconds), 0 = no timeout
    pub write_timeout_ms: u64,
    /// Fragment reassembly timeout (milliseconds)
    pub reassembly_timeout_ms: u64,
    /// Maximum concurrent reassembly buffers
    pub max_reassembly_buffers: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mtu: 1400, // Safe for most networks after IP/UDP headers
            recv_buffer_size: 65536,
            send_buffer_size: 65536,
            read_timeout_ms: 30000,
            write_timeout_ms: 5000,
            reassembly_timeout_ms: 30000,
            max_reassembly_buffers: 1000,
        }
    }
}
