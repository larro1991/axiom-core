//! Hybrid Logical Clock implementation
//!
//! Provides causal ordering without strict sequencing.

use core::cmp::Ordering;

/// Hybrid Logical Clock combining physical time with logical counters.
///
/// Layout:
/// - physical: 40 bits (Unix timestamp in seconds, good until year 36812)
/// - logical: 16 bits (Lamport counter within physical tick)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridClock {
    /// Unix timestamp in seconds (40-bit effective range)
    pub physical: u64,
    /// Logical counter within the same physical second
    pub logical: u16,
}

impl HybridClock {
    /// Create a new clock at the given physical time
    pub const fn new(physical: u64, logical: u16) -> Self {
        Self { physical, logical }
    }

    /// Create a clock at physical time zero
    pub const fn zero() -> Self {
        Self {
            physical: 0,
            logical: 0,
        }
    }

    /// Create a clock from the current system time
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let physical = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            physical,
            logical: 0,
        }
    }

    /// Increment the logical counter (called on send)
    pub fn tick(&mut self) {
        self.logical = self.logical.saturating_add(1);
    }

    /// Update clock based on received frame's clock
    pub fn update(&mut self, received: &HybridClock) {
        match self.physical.cmp(&received.physical) {
            Ordering::Less => {
                self.physical = received.physical;
                self.logical = received.logical.saturating_add(1);
            }
            Ordering::Equal => {
                self.logical = self.logical.max(received.logical).saturating_add(1);
            }
            Ordering::Greater => {
                self.logical = self.logical.saturating_add(1);
            }
        }
    }

    /// Check if this clock happens-before another
    pub fn happens_before(&self, other: &HybridClock) -> bool {
        self.physical < other.physical
            || (self.physical == other.physical && self.logical < other.logical)
    }

    /// Check if clocks are concurrent (neither happens-before the other)
    pub fn concurrent_with(&self, other: &HybridClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self)
    }

    /// Encode to 7 bytes (wire format)
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut bytes = [0u8; 7];
        // Physical: 40 bits in bytes 0-4
        let physical_bytes = self.physical.to_be_bytes();
        bytes[0..5].copy_from_slice(&physical_bytes[3..8]);
        // Logical: 16 bits in bytes 5-6
        let logical_bytes = self.logical.to_be_bytes();
        bytes[5..7].copy_from_slice(&logical_bytes);
        bytes
    }

    /// Decode from 7 bytes (wire format)
    pub fn from_bytes(bytes: &[u8; 7]) -> Self {
        let mut physical_bytes = [0u8; 8];
        physical_bytes[3..8].copy_from_slice(&bytes[0..5]);
        let physical = u64::from_be_bytes(physical_bytes);

        let logical = u16::from_be_bytes([bytes[5], bytes[6]]);

        Self { physical, logical }
    }

    /// Maximum physical time representable (40 bits)
    pub const MAX_PHYSICAL: u64 = (1 << 40) - 1;
}

impl PartialOrd for HybridClock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HybridClock {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.physical.cmp(&other.physical) {
            Ordering::Equal => self.logical.cmp(&other.logical),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happens_before() {
        let a = HybridClock::new(100, 5);
        let b = HybridClock::new(100, 10);
        let c = HybridClock::new(101, 0);

        assert!(a.happens_before(&b));
        assert!(a.happens_before(&c));
        assert!(b.happens_before(&c));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn test_concurrent() {
        let a = HybridClock::new(100, 5);
        let b = HybridClock::new(100, 5);

        assert!(a.concurrent_with(&b));
        assert!(!a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn test_serialization() {
        let original = HybridClock::new(1_700_000_000, 12345);
        let bytes = original.to_bytes();
        let decoded = HybridClock::from_bytes(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_update() {
        let mut local = HybridClock::new(100, 5);
        let remote = HybridClock::new(100, 10);

        local.update(&remote);
        assert_eq!(local.physical, 100);
        assert_eq!(local.logical, 11);
    }

    #[test]
    fn test_update_future() {
        let mut local = HybridClock::new(100, 5);
        let remote = HybridClock::new(200, 3);

        local.update(&remote);
        assert_eq!(local.physical, 200);
        assert_eq!(local.logical, 4);
    }
}
