//! AXIOM Cryptographic Operations
//!
//! This crate provides:
//! - Ed25519 signing and verification
//! - BLAKE3 hashing for intent hashes
//! - X25519 key exchange for encrypted payloads
//! - XChaCha20-Poly1305 authenticated encryption
//! - Frame signing and session management
//! - Trust negotiation protocol

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

pub mod did;
pub mod encrypt;
pub mod frame_sign;
pub mod hash;
pub mod identity;
pub mod negotiate;
pub mod raw_session;
pub mod attestation;
pub mod revocation;

pub use frame_sign::{FrameSigner, FrameVerifier, SessionManager, SignError};
pub use hash::IntentHasher;
pub use identity::{Keypair, PublicKey, Signer, Verifier};
pub use negotiate::{
    ChallengePayload, EstablishedSession, HelloPayload, NegotiationContext, NegotiationError,
    NegotiationState, ResponsePayload, TrustMessageType, TrustNegotiator,
};

// Security modules
pub use raw_session::{RawSession, RawSessionState, Heartbeat, KeyRotation, RawSessionError};
pub use attestation::{
    AttestationNode, AttestationMesh, AttestationReport, AttestedState,
    AttestationError, PcrValues,
};
pub use revocation::{
    RevocationManager, RevocationCertificate, RevocationWitness, RevocationEntry,
    RevocationReason, RevocationAction, RevocationError, WebOfTrustConfig,
    TrustRelationship, RevocationSource,
};
