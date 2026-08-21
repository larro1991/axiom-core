//! Memory Capability - Storage for Tensors and Models
//!
//! AI memory is different from traditional memory:
//! - Large contiguous allocations (model weights)
//! - High bandwidth is critical (HBM vs DDR)
//! - Caching behavior matters (KV cache)
//! - Persistence may be needed (checkpoints)

use alloc::vec::Vec;

/// Type of memory
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemoryType {
    /// High Bandwidth Memory (GPU-attached)
    Hbm = 0x01,
    /// GDDR (older GPU memory)
    Gddr = 0x02,
    /// System DDR (CPU-attached)
    Ddr = 0x03,
    /// Non-volatile memory (Optane, etc.)
    Nvm = 0x04,
    /// On-chip SRAM (fastest, smallest)
    Sram = 0x05,
    /// Unified memory (CPU+GPU shared)
    Unified = 0x06,
}

impl MemoryType {
    /// Typical latency in nanoseconds
    pub fn typical_latency_ns(&self) -> u64 {
        match self {
            MemoryType::Sram => 1,      // ~1ns
            MemoryType::Hbm => 100,     // ~100ns
            MemoryType::Gddr => 150,    // ~150ns
            MemoryType::Ddr => 80,      // ~80ns
            MemoryType::Unified => 100, // Depends
            MemoryType::Nvm => 300,     // ~300ns
        }
    }

    /// Typical bandwidth in GB/s
    pub fn typical_bandwidth_gbps(&self) -> u32 {
        match self {
            MemoryType::Sram => 10000,  // Very high but small
            MemoryType::Hbm => 900,     // HBM3: ~900 GB/s
            MemoryType::Gddr => 500,    // GDDR6X: ~500 GB/s
            MemoryType::Ddr => 50,      // DDR5: ~50 GB/s
            MemoryType::Unified => 200, // Depends on platform
            MemoryType::Nvm => 10,      // ~10 GB/s
        }
    }
}

/// A region of memory
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address
    pub base: u64,
    /// Size in bytes
    pub size: u64,
    /// Is this region currently allocated?
    pub allocated: bool,
    /// Who owns this region (if allocated)
    pub owner: Option<axiom_types::crypto::NodeId>,
}

impl MemoryRegion {
    /// Create a new free region
    pub fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            allocated: false,
            owner: None,
        }
    }

    /// End address (exclusive)
    pub fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Check if regions overlap
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.base < other.end() && other.base < self.end()
    }

    /// Check if this region contains an address
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

/// Memory-specific capability details
#[derive(Debug, Clone)]
pub struct MemoryCapability {
    /// Type of memory
    pub memory_type: MemoryType,
    /// Total capacity in bytes
    pub capacity: u64,
    /// Bandwidth in bytes/sec
    pub bandwidth: u64,
    /// Latency in nanoseconds
    pub latency_ns: u64,
    /// Minimum allocation granularity (bytes)
    pub alignment: u64,
    /// Maximum single allocation size
    pub max_alloc: u64,
    /// Is this memory persistent across power cycles?
    pub persistent: bool,
    /// Is this memory coherent with CPU?
    pub coherent: bool,
    /// Free regions (for allocation tracking)
    free_regions: Vec<MemoryRegion>,
}

impl MemoryCapability {
    /// Create a new memory capability
    pub fn new(memory_type: MemoryType, capacity: u64) -> Self {
        Self {
            memory_type,
            capacity,
            bandwidth: (memory_type.typical_bandwidth_gbps() as u64) * 1_000_000_000,
            latency_ns: memory_type.typical_latency_ns(),
            alignment: 256, // 256-byte alignment typical
            max_alloc: capacity,
            persistent: matches!(memory_type, MemoryType::Nvm),
            coherent: matches!(memory_type, MemoryType::Ddr | MemoryType::Unified),
            free_regions: vec![MemoryRegion::new(0, capacity)],
        }
    }

    /// Set bandwidth
    pub fn with_bandwidth(mut self, bandwidth: u64) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    /// Set alignment requirement
    pub fn with_alignment(mut self, alignment: u64) -> Self {
        self.alignment = alignment;
        self
    }

    /// Get available (free) memory
    pub fn available(&self) -> u64 {
        self.free_regions.iter().map(|r| r.size).sum()
    }

    /// Get fragmentation ratio (0.0 = no fragmentation, 1.0 = fully fragmented)
    pub fn fragmentation(&self) -> f64 {
        if self.free_regions.is_empty() {
            return 0.0;
        }
        let largest = self.free_regions.iter().map(|r| r.size).max().unwrap_or(0);
        let total = self.available();
        if total == 0 {
            return 0.0;
        }
        1.0 - (largest as f64 / total as f64)
    }

    /// Allocate a region
    pub fn allocate(&mut self, size: u64, owner: axiom_types::crypto::NodeId) -> Option<MemoryRegion> {
        // Round up to alignment
        let aligned_size = (size + self.alignment - 1) & !(self.alignment - 1);

        // Find first fit
        for i in 0..self.free_regions.len() {
            if self.free_regions[i].size >= aligned_size {
                let region = &mut self.free_regions[i];
                let base = region.base;

                // Split the region
                if region.size == aligned_size {
                    // Exact fit - remove the region
                    self.free_regions.remove(i);
                } else {
                    // Partial - shrink the free region
                    region.base += aligned_size;
                    region.size -= aligned_size;
                }

                return Some(MemoryRegion {
                    base,
                    size: aligned_size,
                    allocated: true,
                    owner: Some(owner),
                });
            }
        }

        None // No suitable region found
    }

    /// Free a region
    pub fn free(&mut self, region: MemoryRegion) {
        // Add back to free list
        let mut new_region = MemoryRegion::new(region.base, region.size);

        // Try to coalesce with adjacent free regions
        let mut i = 0;
        while i < self.free_regions.len() {
            let existing = &self.free_regions[i];

            // Check if new region is adjacent to existing
            if new_region.end() == existing.base {
                // New region is immediately before existing
                new_region.size += existing.size;
                self.free_regions.remove(i);
            } else if existing.end() == new_region.base {
                // Existing is immediately before new region
                new_region.base = existing.base;
                new_region.size += existing.size;
                self.free_regions.remove(i);
            } else {
                i += 1;
            }
        }

        // Insert in sorted order by base address
        let pos = self.free_regions
            .iter()
            .position(|r| r.base > new_region.base)
            .unwrap_or(self.free_regions.len());
        self.free_regions.insert(pos, new_region);
    }

    /// Check if a specific allocation size is possible
    pub fn can_allocate(&self, size: u64) -> bool {
        let aligned_size = (size + self.alignment - 1) & !(self.alignment - 1);
        self.free_regions.iter().any(|r| r.size >= aligned_size)
    }

    /// Estimate time to transfer data (seconds)
    pub fn transfer_time(&self, bytes: u64) -> f64 {
        bytes as f64 / self.bandwidth as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::crypto::NodeId;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_memory_type_properties() {
        assert!(MemoryType::Hbm.typical_bandwidth_gbps() > MemoryType::Ddr.typical_bandwidth_gbps());
        assert!(MemoryType::Sram.typical_latency_ns() < MemoryType::Hbm.typical_latency_ns());
    }

    #[test]
    fn test_memory_allocation() {
        let mut mem = MemoryCapability::new(MemoryType::Hbm, 16_000_000_000); // 16GB

        let owner = test_node_id(1);

        // Allocate 4GB
        let region1 = mem.allocate(4_000_000_000, owner.clone()).unwrap();
        assert_eq!(region1.base, 0);
        assert!(region1.size >= 4_000_000_000);

        // Allocate another 4GB
        let region2 = mem.allocate(4_000_000_000, owner.clone()).unwrap();
        assert!(region2.base >= region1.end());

        // Available should be reduced (16GB - 8GB = 8GB remaining)
        assert!(mem.available() <= 8_000_000_000);
    }

    #[test]
    fn test_memory_free_coalesce() {
        let mut mem = MemoryCapability::new(MemoryType::Hbm, 1_000_000);
        let owner = test_node_id(1);

        // Allocate three regions
        let r1 = mem.allocate(100_000, owner.clone()).unwrap();
        let r2 = mem.allocate(100_000, owner.clone()).unwrap();
        let r3 = mem.allocate(100_000, owner.clone()).unwrap();

        // Free the middle one
        mem.free(r2);

        // Free the first one - should coalesce
        mem.free(r1);

        // Free the third - should coalesce into one big region
        mem.free(r3);

        // Should have one free region equal to original capacity
        assert_eq!(mem.free_regions.len(), 1);
        assert_eq!(mem.available(), 1_000_000);
    }

    #[test]
    fn test_fragmentation() {
        let mut mem = MemoryCapability::new(MemoryType::Hbm, 1_000_000);
        let owner = test_node_id(1);

        // No fragmentation initially
        assert_eq!(mem.fragmentation(), 0.0);

        // Allocate and free to create fragments
        let r1 = mem.allocate(100_000, owner.clone()).unwrap();
        let _r2 = mem.allocate(100_000, owner.clone()).unwrap();
        let r3 = mem.allocate(100_000, owner.clone()).unwrap();

        mem.free(r1);
        mem.free(r3);

        // Now we have fragmentation (two non-contiguous free regions)
        assert!(mem.fragmentation() > 0.0);
    }

    #[test]
    fn test_transfer_time() {
        let mem = MemoryCapability::new(MemoryType::Hbm, 16_000_000_000)
            .with_bandwidth(900_000_000_000); // 900 GB/s

        // 900GB at 900 GB/s = 1 second
        let time = mem.transfer_time(900_000_000_000);
        assert!((time - 1.0).abs() < 0.01);
    }
}
