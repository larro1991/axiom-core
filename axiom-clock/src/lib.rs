//! Hybrid Logical Clock management for AXIOM
//!
//! Re-exports the HybridClock from axiom-types and provides
//! additional utilities for clock management in a distributed setting.

#![cfg_attr(not(feature = "std"), no_std)]

pub use axiom_types::clock::HybridClock;

/// Clock manager for maintaining local clock state
pub struct ClockManager {
    clock: HybridClock,
}

impl ClockManager {
    /// Create a new clock manager
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self {
            clock: HybridClock::now(),
        }
    }

    /// Create with a specific starting clock
    pub fn with_clock(clock: HybridClock) -> Self {
        Self { clock }
    }

    /// Get the current clock value
    pub fn current(&self) -> HybridClock {
        self.clock
    }

    /// Tick the clock (for sending)
    pub fn tick(&mut self) -> HybridClock {
        self.clock.tick();
        self.clock
    }

    /// Update from a received clock
    pub fn update(&mut self, received: &HybridClock) {
        self.clock.update(received);
    }

    /// Synchronize physical time (call periodically)
    #[cfg(feature = "std")]
    pub fn sync_physical(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.clock.physical {
            self.clock.physical = now;
            self.clock.logical = 0;
        }
    }
}

#[cfg(feature = "std")]
impl Default for ClockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_manager_tick() {
        let mut manager = ClockManager::with_clock(HybridClock::new(100, 0));

        let c1 = manager.tick();
        assert_eq!(c1.logical, 1);

        let c2 = manager.tick();
        assert_eq!(c2.logical, 2);
    }

    #[test]
    fn test_clock_manager_update() {
        let mut manager = ClockManager::with_clock(HybridClock::new(100, 5));

        // Receive from future
        manager.update(&HybridClock::new(200, 10));
        assert_eq!(manager.current().physical, 200);
        assert_eq!(manager.current().logical, 11);
    }
}
