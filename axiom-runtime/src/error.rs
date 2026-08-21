//! Runtime errors

use alloc::string::String;
use axiom_hal::ClaimError;

/// Runtime result type
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Errors that can occur in the runtime
#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// Agent not initialized
    NotInitialized,
    /// Resource claim failed
    ResourceClaim(ClaimError),
    /// Resource not found
    ResourceNotFound(String),
    /// Network error
    Network(String),
    /// Task execution error
    TaskFailed(String),
    /// Invalid state transition
    InvalidState {
        from: String,
        to: String,
    },
    /// Capability not available
    CapabilityUnavailable(String),
    /// Permission denied
    PermissionDenied(String),
    /// Timeout
    Timeout,
    /// Internal error
    Internal(String),
}

impl From<ClaimError> for RuntimeError {
    fn from(e: ClaimError) -> Self {
        RuntimeError::ResourceClaim(e)
    }
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeError::NotInitialized => write!(f, "Agent not initialized"),
            RuntimeError::ResourceClaim(e) => write!(f, "Resource claim failed: {:?}", e),
            RuntimeError::ResourceNotFound(name) => write!(f, "Resource not found: {}", name),
            RuntimeError::Network(msg) => write!(f, "Network error: {}", msg),
            RuntimeError::TaskFailed(msg) => write!(f, "Task failed: {}", msg),
            RuntimeError::InvalidState { from, to } => {
                write!(f, "Invalid state transition: {} -> {}", from, to)
            }
            RuntimeError::CapabilityUnavailable(cap) => {
                write!(f, "Capability unavailable: {}", cap)
            }
            RuntimeError::PermissionDenied(reason) => {
                write!(f, "Permission denied: {}", reason)
            }
            RuntimeError::Timeout => write!(f, "Operation timed out"),
            RuntimeError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RuntimeError {}
