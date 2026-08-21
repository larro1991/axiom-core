//! Error types and categories

use alloc::string::String;
use crate::clock::HybridClock;

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ErrorSeverity {
    /// Informational (not really an error)
    Info = 0,
    /// Warning (operation succeeded but with caveats)
    Warn = 1,
    /// Error (operation failed but recoverable)
    Error = 2,
    /// Fatal (connection/session should be terminated)
    Fatal = 3,
}

impl ErrorSeverity {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::Info,
            1 => Self::Warn,
            2 => Self::Error,
            3 => Self::Fatal,
            _ => unreachable!(),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Default for ErrorSeverity {
    fn default() -> Self {
        Self::Error
    }
}

/// Error category codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCategory {
    /// Unclassified error
    Unknown = 0x00,
    /// Requested capability not found
    CapabilityUnavailable = 0x01,
    /// Capability exists but at capacity
    CapabilityOverloaded = 0x02,
    /// Authentication/authorization failed
    TrustDenied = 0x03,
    /// Session/token expired
    TrustExpired = 0x04,
    /// Causal clock too far in past/future
    ClockSkew = 0x05,
    /// Could not parse payload
    PayloadMalformed = 0x06,
    /// Payload exceeds limits
    PayloadTooLarge = 0x07,
    /// Memory, GPU, queue full
    ResourceExhausted = 0x08,
    /// TTL expired before fulfillment
    IntentTimeout = 0x09,
    /// No path to destination
    RouteUnreachable = 0x0A,
    /// Incompatible protocol version
    VersionMismatch = 0x0B,
    /// Shared dictionary mismatch
    CompressionFailed = 0x0C,
    /// Frame fragmentation error
    FragmentError = 0x0D,
    /// Flow control violation
    FlowViolation = 0x0E,
    /// Internal implementation error
    Internal = 0xFF,
}

impl ErrorCategory {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::Unknown,
            0x01 => Self::CapabilityUnavailable,
            0x02 => Self::CapabilityOverloaded,
            0x03 => Self::TrustDenied,
            0x04 => Self::TrustExpired,
            0x05 => Self::ClockSkew,
            0x06 => Self::PayloadMalformed,
            0x07 => Self::PayloadTooLarge,
            0x08 => Self::ResourceExhausted,
            0x09 => Self::IntentTimeout,
            0x0A => Self::RouteUnreachable,
            0x0B => Self::VersionMismatch,
            0x0C => Self::CompressionFailed,
            0x0D => Self::FragmentError,
            0x0E => Self::FlowViolation,
            0xFF => Self::Internal,
            _ => Self::Unknown,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get a human-readable description
    pub fn description(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown error",
            Self::CapabilityUnavailable => "Requested capability not found",
            Self::CapabilityOverloaded => "Capability is at capacity",
            Self::TrustDenied => "Authentication or authorization failed",
            Self::TrustExpired => "Session or token has expired",
            Self::ClockSkew => "Causal clock is too far in past or future",
            Self::PayloadMalformed => "Could not parse payload",
            Self::PayloadTooLarge => "Payload exceeds size limits",
            Self::ResourceExhausted => "Resource exhausted (memory, GPU, queue)",
            Self::IntentTimeout => "Intent TTL expired before fulfillment",
            Self::RouteUnreachable => "No route to destination",
            Self::VersionMismatch => "Incompatible protocol version",
            Self::CompressionFailed => "Shared dictionary or compression mismatch",
            Self::FragmentError => "Frame fragmentation or reassembly error",
            Self::FlowViolation => "Flow control violation",
            Self::Internal => "Internal implementation error",
        }
    }

    /// Suggested default severity for this category
    pub fn default_severity(self) -> ErrorSeverity {
        match self {
            Self::Unknown => ErrorSeverity::Error,
            Self::CapabilityUnavailable => ErrorSeverity::Error,
            Self::CapabilityOverloaded => ErrorSeverity::Warn,
            Self::TrustDenied => ErrorSeverity::Error,
            Self::TrustExpired => ErrorSeverity::Warn,
            Self::ClockSkew => ErrorSeverity::Warn,
            Self::PayloadMalformed => ErrorSeverity::Error,
            Self::PayloadTooLarge => ErrorSeverity::Error,
            Self::ResourceExhausted => ErrorSeverity::Warn,
            Self::IntentTimeout => ErrorSeverity::Warn,
            Self::RouteUnreachable => ErrorSeverity::Error,
            Self::VersionMismatch => ErrorSeverity::Fatal,
            Self::CompressionFailed => ErrorSeverity::Error,
            Self::FragmentError => ErrorSeverity::Error,
            Self::FlowViolation => ErrorSeverity::Warn,
            Self::Internal => ErrorSeverity::Fatal,
        }
    }
}

impl Default for ErrorCategory {
    fn default() -> Self {
        Self::Unknown
    }
}

/// AXIOM protocol error
#[derive(Debug, Clone)]
pub struct AxiomError {
    /// Error severity
    pub severity: ErrorSeverity,
    /// Error category
    pub category: ErrorCategory,
    /// Confidence in error diagnosis (0.0 - 1.0)
    pub confidence: f32,
    /// Clock of the frame that caused this error
    pub in_response_to: HybridClock,
    /// Human-readable message (for debugging)
    pub message: String,
    /// Additional structured context
    pub context: alloc::vec::Vec<u8>,
}

impl AxiomError {
    /// Create a new error with default settings
    pub fn new(category: ErrorCategory) -> Self {
        Self {
            severity: category.default_severity(),
            category,
            confidence: 1.0,
            in_response_to: HybridClock::zero(),
            message: String::from(category.description()),
            context: alloc::vec::Vec::new(),
        }
    }

    /// Set severity
    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set the causal reference
    pub fn in_response_to(mut self, clock: HybridClock) -> Self {
        self.in_response_to = clock;
        self
    }

    /// Set message
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Set context bytes
    pub fn with_context(mut self, context: alloc::vec::Vec<u8>) -> Self {
        self.context = context;
        self
    }

    /// Check if this is a fatal error
    pub fn is_fatal(&self) -> bool {
        self.severity == ErrorSeverity::Fatal
    }

    /// Check if this is recoverable
    pub fn is_recoverable(&self) -> bool {
        !self.is_fatal()
    }
}

impl core::fmt::Display for AxiomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[{:?}] {:?}: {} (confidence: {:.0}%)",
            self.severity,
            self.category,
            self.message,
            self.confidence * 100.0
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AxiomError {}

/// Result type for AXIOM operations
pub type AxiomResult<T> = Result<T, AxiomError>;

/// Error during frame encoding/decoding
#[derive(Debug, Clone, thiserror::Error)]
pub enum CodecError {
    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Buffer too small: need {needed} bytes, have {have}")]
    BufferTooSmall { needed: usize, have: usize },

    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(u8),

    #[error("Payload too large: {0} bytes (max {max})", max = crate::MAX_PAYLOAD_SIZE)]
    PayloadTooLarge(usize),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Truncated frame")]
    TruncatedFrame,

    #[error("Invalid UTF-8 in string field")]
    InvalidUtf8,

    #[error("Invalid data type: {0}")]
    InvalidDType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Info < ErrorSeverity::Warn);
        assert!(ErrorSeverity::Warn < ErrorSeverity::Error);
        assert!(ErrorSeverity::Error < ErrorSeverity::Fatal);
    }

    #[test]
    fn test_axiom_error_builder() {
        let err = AxiomError::new(ErrorCategory::CapabilityUnavailable)
            .with_confidence(0.95)
            .with_message("Service 'inference.llm' not found");

        assert_eq!(err.category, ErrorCategory::CapabilityUnavailable);
        assert_eq!(err.confidence, 0.95);
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_fatal_error() {
        let err = AxiomError::new(ErrorCategory::VersionMismatch);
        assert!(err.is_fatal());
        assert!(!err.is_recoverable());
    }
}
