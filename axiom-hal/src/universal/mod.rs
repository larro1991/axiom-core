//! Universal Driver - Hardware Description Language (HDL-Lite)
//!
//! A declarative language for describing hardware devices and their
//! operations without writing traditional driver code.
//!
//! # Architecture
//! ```text
//! HDL-Lite Description → Parser → HardwareDescription → UniversalDriver
//! ```
//!
//! # Components
//!
//! - `types`: Core type definitions for hardware descriptions
//! - `parser`: HDL-Lite parser for declarative hardware descriptions
//! - `engine`: Execution engine that interprets HDL operations
//! - `database`: Registry of known device patterns for auto-configuration

pub mod database;
pub mod engine;
pub mod parser;
pub mod secure_parser;
pub mod signing;
pub mod types;

pub use database::{DriverDatabase, DriverEntry, PciId};
pub use engine::UniversalDriver;
pub use parser::HdlParser;
pub use secure_parser::{SecureHdlParser, SecureParseError, VerifiedHdl, ProductionHdlConfig};
pub use signing::{
    HdlVerifier, HdlTrustStore, TrustedKey, KeyPurpose,
    SignatureVerification, SignatureError, SignatureHeader,
};
pub use types::*;
