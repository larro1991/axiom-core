//! AXIOM Runtime - AI Agent Execution Environment
//!
//! This crate ties together:
//! - **Identity**: Cryptographic agent identity (AgentId)
//! - **Network**: AXIOM protocol for communication
//! - **Hardware**: HAL for resource access
//!
//! # Philosophy
//!
//! An AI agent needs:
//! 1. **Identity** - Who am I? (cryptographic, verifiable)
//! 2. **Resources** - What can I use? (compute, memory)
//! 3. **Communication** - Who can I talk to? (network)
//! 4. **Execution** - Where do I run? (this runtime)
//!
//! # Example
//!
//! ```ignore
//! use axiom_runtime::{AgentRuntime, RuntimeConfig};
//!
//! // Create runtime with identity
//! let runtime = AgentRuntime::new(RuntimeConfig::default())?;
//!
//! // Discover and claim resources
//! let gpu = runtime.claim_resource("compute:tensor:fp16")?;
//!
//! // Communicate with other agents
//! runtime.request(intent!("llm:completion"), payload).await?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod agent;
pub mod context;
pub mod executor;
pub mod error;
pub mod ipc;
pub mod scheduler;
pub mod checkpoint;

pub use agent::{Agent, AgentConfig, AgentState};
pub use context::{AgentContext, ResourceClaim};
pub use executor::{Task, TaskPriority, Executor};
pub use error::{RuntimeError, RuntimeResult};
pub use ipc::{LocalRouter, Message, MessagePriority, Mailbox, SharedData, ChannelId, IpcError};
pub use scheduler::{Scheduler, Worker, WorkerId, WorkUnit, WorkQueue, AffinityHint, WorkerState};
pub use checkpoint::{Checkpoint, CheckpointId, CheckpointManager, CheckpointOptions, CheckpointError, TaskSnapshot, ResourceSnapshot};

// Re-export key types from other crates for convenience
pub use axiom_router::ai::{AgentId, Intent};
pub use axiom_hal::{ResourceManager, Resource, Capability};
