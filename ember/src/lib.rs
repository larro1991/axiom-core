//! EMBER - Estimation of Mesh-Based Emergent Resources
//!
//! A system for determining how many desktop/edge nodes are needed
//! to collaboratively solve AI workloads that would otherwise require
//! expensive cloud infrastructure.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        EMBER COORDINATOR                         │
//! │  • Workload decomposition    • Resource matching                │
//! │  • Progress tracking         • Result aggregation               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                     AXIOM MESH NETWORK                          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use ember::{Coordinator, Workload, WorkloadType};
//!
//! let mut coord = Coordinator::new(my_node_id);
//!
//! // Register node capabilities
//! coord.register_node(node_id, capability);
//!
//! // Create a workload
//! let workload = Workload::protein_folding(sequence, 500);
//!
//! // Estimate required resources
//! let estimate = coord.estimate(&workload);
//! println!("Need {} nodes for {} hours", estimate.nodes_required, estimate.time_hours);
//!
//! // Submit and track
//! let job_id = coord.submit(workload)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod capability;
pub mod coordinator;
pub mod estimate;
pub mod workload;
pub mod task;

pub use capability::{NodeCapability, CapabilityClass, GpuType, CapabilityDatabase};
pub use coordinator::{Coordinator, CoordinatorConfig, CoordinatorError};
pub use estimate::{ResourceEstimate, EstimateConfig};
pub use workload::{Workload, WorkloadType, WorkloadRequirements, WorkloadState};
pub use task::{Task, TaskId, TaskState, TaskResult};
