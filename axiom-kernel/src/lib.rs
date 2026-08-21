//! AXIOM Kernel
//!
//! The kernel ties together all AXIOM components:
//! - Hardware abstraction (axiom-hal)
//! - Networking (axiom-transport, axiom-router)
//! - Runtime (axiom-runtime)
//! - Cryptographic identity (axiom-crypto)
//!
//! # Deployment Targets
//!
//! - `linux` feature: AXIOM-Linux for development/single-node
//! - `cloud` feature: AXIOM-Cloud for distributed deployments
//! - `vm` feature: AXIOM-VM for hypervisor-based isolation

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod boot;
pub mod config;
pub mod init;
pub mod shutdown;

#[cfg(feature = "linux")]
pub mod linux;

#[cfg(feature = "cloud")]
pub mod cloud;

#[cfg(feature = "vm")]
pub mod vm;

pub use boot::{BootConfig, BootError, Kernel, KernelState};
pub use config::{HardwareConfig, KernelConfig, KernelConfigBuilder, NetworkConfig};
pub use init::{CustomInitAgent, DefaultInitAgent, InitAgent, InitAgentBuilder, InitError};
pub use shutdown::{ShutdownCoordinator, ShutdownPhase, ShutdownReason};

use thiserror::Error;

/// Kernel-level errors
#[derive(Debug, Error)]
pub enum KernelError {
    #[error("Boot failed: {0}")]
    Boot(#[from] BootError),

    #[error("Init agent failed: {0}")]
    Init(#[from] InitError),

    #[error("Network error: {0}")]
    Network(#[from] axiom_transport::TransportError),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Hardware error: {0}")]
    Hardware(String),

    #[error("Agent error: {0}")]
    Agent(String),
}

pub type KernelResult<T> = Result<T, KernelError>;
