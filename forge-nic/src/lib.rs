//! FORGE NIC - AI-Native Network Interface Controller
//!
//! The FORGE NIC is an AI-native network interface that combines:
//! - Universal Driver support for any hardware
//! - Tiered Intelligence (Tier 1/2/3) for packet processing
//! - Built-in security (trust evaluation, threat detection)
//! - Legacy protocol bridging (IPv4 ↔ AXIOM)
//! - Natural language interface for network queries
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         FORGE NIC                                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  TIER 3: AI BRAIN (Slow Path)                                   │
//! │  • Complex threat analysis       • Policy generation            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  TIER 2: SMART AGENTS (Medium Path)                             │
//! │  • Security Agent    • Traffic Agent    • Protocol Agent        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  TIER 1: TRANSLATOR (Fast Path)                                 │
//! │  • Trust Cache    • Route Cache    • Protocol Tables            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  UNIVERSAL DRIVER LAYER                                         │
//! │  • HDL-Lite    • Auto-config    • Bounds-checked I/O            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod capture;
pub mod monitor;
pub mod nic;
pub mod security;
pub mod trust;

// Re-export commonly used types from HAL
pub use axiom_hal::{
    NetworkCapability, NicInfo, NicFeatures, NicMetrics, NetworkError,
    DriverDatabase, HdlParser, PciId, UniversalDriver,
};

// Re-export from transport
pub use axiom_transport::bridge::{Gateway, GatewayConfig};
pub use axiom_types::NodeId;

// Re-export SENTINEL components (std feature only)
#[cfg(feature = "std")]
pub use axiom_guardian::{Guardian, GuardianConfig, GuardianAlert};
#[cfg(feature = "std")]
pub use axiom_watcher::{Watcher, WatcherConfig, WatcherAlert};
#[cfg(feature = "std")]
pub use axiom_analyst::{Analyst, AnalystConfig, Incident, IncidentSeverity};
#[cfg(feature = "std")]
pub use axiom_responder::{Responder, ResponderConfig, ActionResult, ActionType};

// Local types
pub use nic::{ForgeNic, ForgeNicConfig, NicState, NicStats, NicError, PacketAction};
pub use trust::{TrustEngine, TrustLevel as ForgeTrustLevel, SelfVerifyResult, TrustRecord};
pub use monitor::{PacketMonitor, ThreatSignature};
pub use capture::{CaptureSession, CaptureFilter, CaptureManager};
pub use security::{SecurityEngine, SecurityEngineConfig, SecurityResult, TieredIntelligence};
#[cfg(feature = "std")]
pub use security::SecurityEngineStd;
