//! AI-Native Hardware Abstraction Layer
//!
//! This crate provides hardware access without traditional drivers.
//! Instead of translating human concepts to hardware, it exposes
//! hardware as **capabilities** that AI can discover, claim, and use directly.
//!
//! # Philosophy
//!
//! Traditional OS: App → Syscall → Driver → Hardware
//! AI-Native:      Agent → Intent → Capability → Hardware (direct)
//!
//! AI doesn't need:
//! - Human-friendly abstractions (files, streams)
//! - Permission bitmasks (AI evaluates intent)
//! - Stable APIs (AI adapts)
//!
//! AI does need:
//! - Discovery: What resources exist?
//! - Coordination: Who owns what?
//! - Isolation: Don't corrupt my tensors
//! - Direct access: No translation overhead
//!
//! # Resource Types
//!
//! - **Compute**: Tensor accelerators (GPU/TPU/NPU)
//! - **Memory**: Storage for models, activations, KV cache
//! - **Mover**: DMA engines for zero-copy data movement
//! - **Network**: Handled by AXIOM protocol (axiom-router)
//!
//! # Example
//!
//! ```ignore
//! use axiom_hal::{ResourceManager, Intent};
//!
//! // Discover compute resources
//! let compute = manager.discover(intent!("compute:tensor:fp16"));
//!
//! // Claim one
//! let handle = manager.claim(&compute[0], my_agent_id)?;
//!
//! // Direct access - no driver translation
//! let mmio = manager.access(&handle);
//! // Write commands directly to hardware queue
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod capability;
pub mod resource;
pub mod compute;
pub mod memory;
pub mod mover;
pub mod manager;
pub mod tensor_alloc;
pub mod universal;
pub mod network;

pub use capability::{
    Capability, CapabilityClass, CapabilityMetrics, CapabilityId,
};
pub use resource::{
    Resource, ResourceId, ResourceState, ResourceHandle, AccessMethod,
};
pub use compute::{
    ComputeCapability, ComputeType, TensorOp, DataType as ComputeDataType,
};
pub use memory::{
    MemoryCapability, MemoryType, MemoryRegion,
};
pub use mover::{
    MoverCapability, TransferPath, DmaDescriptor,
};
pub use manager::{
    ResourceManager, ClaimError, DiscoveryFilter,
};
pub use tensor_alloc::{
    MemoryPool, Arena, BumpAllocator, TensorAllocator,
    SizeClass, AllocHandle, AllocStats,
};
pub use universal::{
    UniversalDriver, DriverDatabase, DriverEntry, PciId,
    HardwareDescription, DeviceClass, Register, OperationDef,
    HdlParser,
};
pub use network::{
    NetworkCapability, NicInfo, NicFeatures, NicMetrics, NetworkError,
};
