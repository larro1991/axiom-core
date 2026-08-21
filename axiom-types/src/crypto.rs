//! Cryptographic primitives and identifiers

use crate::{INTENT_HASH_SIZE, NODE_ID_SIZE, SIGNATURE_SIZE, SESSION_TOKEN_SIZE, TRACE_ID_SIZE};
use core::fmt;

/// Node identity - Ed25519 public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; NODE_ID_SIZE]);

impl NodeId {
    /// Create a NodeId from raw bytes
    pub const fn from_bytes(bytes: [u8; NODE_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_SIZE] {
        &self.0
    }

    /// Zero NodeId (used as placeholder)
    pub const fn zero() -> Self {
        Self([0u8; NODE_ID_SIZE])
    }

    /// Check if this is the zero NodeId
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId(")?;
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...")
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::zero()
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create a Signature from raw bytes
    pub const fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Zero signature (invalid, used as placeholder)
    pub const fn zero() -> Self {
        Self([0u8; SIGNATURE_SIZE])
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(")?;
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

/// Intent hash - BLAKE3 truncated to 128 bits (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentHash(pub [u8; INTENT_HASH_SIZE]);

impl IntentHash {
    /// Create an IntentHash from raw bytes
    pub const fn from_bytes(bytes: [u8; INTENT_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub const fn as_bytes(&self) -> &[u8; INTENT_HASH_SIZE] {
        &self.0
    }

    /// Zero hash (used for non-intent frames)
    pub const fn zero() -> Self {
        Self([0u8; INTENT_HASH_SIZE])
    }

    /// Check if this is the zero hash
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for IntentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntentHash(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for IntentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...")
    }
}

impl Default for IntentHash {
    fn default() -> Self {
        Self::zero()
    }
}

/// Session token for compressed authentication (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken(pub [u8; SESSION_TOKEN_SIZE]);

impl SessionToken {
    /// Create a SessionToken from raw bytes
    pub const fn from_bytes(bytes: [u8; SESSION_TOKEN_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub const fn as_bytes(&self) -> &[u8; SESSION_TOKEN_SIZE] {
        &self.0
    }

    /// Zero token
    pub const fn zero() -> Self {
        Self([0u8; SESSION_TOKEN_SIZE])
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionToken(")?;
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::zero()
    }
}

/// Trace ID for request correlation (8 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId(pub [u8; TRACE_ID_SIZE]);

impl TraceId {
    /// Create a TraceId from raw bytes
    pub const fn from_bytes(bytes: [u8; TRACE_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create from u64
    pub const fn from_u64(value: u64) -> Self {
        Self(value.to_be_bytes())
    }

    /// Get the raw bytes
    pub const fn as_bytes(&self) -> &[u8; TRACE_ID_SIZE] {
        &self.0
    }

    /// Get as u64
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    /// Zero TraceId (no trace)
    pub const fn zero() -> Self {
        Self([0u8; TRACE_ID_SIZE])
    }

    /// Check if this is the zero TraceId
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({:016x})", self.as_u64())
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.as_u64())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_zero() {
        let id = NodeId::zero();
        assert!(id.is_zero());

        let id = NodeId::from_bytes([1u8; 32]);
        assert!(!id.is_zero());
    }

    #[test]
    fn test_trace_id_u64() {
        let value = 0x123456789ABCDEF0u64;
        let trace = TraceId::from_u64(value);
        assert_eq!(trace.as_u64(), value);
    }

    #[test]
    fn test_intent_hash_display() {
        let hash = IntentHash::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        let display = format!("{}", hash);
        assert!(display.starts_with("123456789abcdef0"));
    }
}
