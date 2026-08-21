//! Legacy Protocol Bridge
//!
//! Enables AXIOM nodes to communicate with legacy IPv4/IPv6 networks
//! by translating between AXIOM intent-based addressing and IP-based addressing.
//!
//! # Bridge Types
//!
//! - `Gateway`: Full bidirectional translation between AXIOM and IP
//! - `TunAdapter`: TAP/TUN interface for OS integration
//! - `ProxyBridge`: Application-level proxy for specific protocols

pub mod gateway;
pub mod ipv4;

pub use gateway::{Gateway, GatewayConfig, GatewayMode};
pub use ipv4::{Ipv4Bridge, Ipv4Address, Ipv4Packet};
