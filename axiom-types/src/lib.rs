//! AXIOM Protocol Core Types
//!
//! This crate defines the fundamental types used throughout the AXIOM protocol.
//! It is `no_std` compatible when the `std` feature is disabled.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod clock;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod intent;
pub mod payload;
pub mod trust;

pub use clock::HybridClock;
pub use crypto::{IntentHash, NodeId, SessionToken, Signature, TraceId};
pub use error::{AxiomError, ErrorCategory, ErrorSeverity};
pub use frame::{Frame, FrameFlags, FrameHeader, FrameType, Priority};
pub use intent::{Constraint, ConstraintValue, IntentDescriptor};
pub use payload::{DType, PayloadType, TensorPayload};
pub use trust::TrustLevel;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes (2 bits: 0b10)
pub const MAGIC: u8 = 0b10;

/// Maximum payload size - the true max the 24-bit PayloadLen wire field
/// (`axiom_codec::Encoder::encode_payload_header`'s bit layout, bits 4-27)
/// can represent: 2^24 - 1, NOT a round 16 MiB. Fable full-repo review
/// (2026-07-31): the previous value (2^24 exactly) let a payload of
/// exactly that length pass the encoder's `> MAX_PAYLOAD_SIZE` check, then
/// get silently truncated to a wire length of 0 by the 24-bit field -
/// the payload bytes still went out, just declared as zero-length, which
/// desyncs any length-driven reader downstream.
pub const MAX_PAYLOAD_SIZE: usize = 0xFF_FFFF;

/// Fixed header size in bytes
pub const FIXED_HEADER_SIZE: usize = 58;

/// Signature size in bytes (Ed25519)
pub const SIGNATURE_SIZE: usize = 64;

/// Session token size in bytes
pub const SESSION_TOKEN_SIZE: usize = 16;

/// Intent hash size in bytes
pub const INTENT_HASH_SIZE: usize = 16;

/// Node ID size in bytes (Ed25519 public key)
pub const NODE_ID_SIZE: usize = 32;

/// Trace ID size in bytes
pub const TRACE_ID_SIZE: usize = 8;

/// Causal clock size in bytes
pub const CLOCK_SIZE: usize = 7;

/// Routing extension size in bytes: destination NodeId (32) + TTL (1).
/// AXIOM-14 Cycle 1a - multi-hop forwarding wire support, not yet wired
/// into any forwarding logic (that's Cycle 1b). See `frame::RoutingExt`.
pub const ROUTING_EXT_SIZE: usize = NODE_ID_SIZE + 1;
