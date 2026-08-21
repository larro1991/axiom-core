//! AI-Native Memory Allocator
//!
//! Traditional allocators: general-purpose, unpredictable patterns
//! AI workloads: predictable sizes, burst allocation, long-lived tensors
//!
//! This allocator optimizes for:
//! - Power-of-2 tensor sizes (slab allocator)
//! - Batch allocations (arena allocator)
//! - KV cache growth (bump allocator with resize)
//! - Zero fragmentation for inference
//!
//! # Design
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Memory Pool                     │
//! ├─────────────────────────────────────────────┤
//! │  Slab 64B │ Slab 256B │ Slab 1K │ Slab 4K  │  <- Small tensors
//! ├─────────────────────────────────────────────┤
//! │           Arena (batch lifetime)            │  <- Activations
//! ├─────────────────────────────────────────────┤
//! │           Bump (KV cache)                   │  <- Growing data
//! └─────────────────────────────────────────────┘
//! ```

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Allocation size class (power of 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeClass {
    /// 64 bytes - small embeddings
    Tiny = 64,
    /// 256 bytes - small vectors
    Small = 256,
    /// 1 KB - typical activations
    Medium = 1024,
    /// 4 KB - page-sized
    Large = 4096,
    /// 16 KB - larger tensors
    Huge = 16384,
    /// 64 KB - very large
    Giant = 65536,
}

impl SizeClass {
    /// Get the size class for a given byte count
    pub fn for_size(bytes: usize) -> Option<Self> {
        match bytes {
            0..=64 => Some(SizeClass::Tiny),
            65..=256 => Some(SizeClass::Small),
            257..=1024 => Some(SizeClass::Medium),
            1025..=4096 => Some(SizeClass::Large),
            4097..=16384 => Some(SizeClass::Huge),
            16385..=65536 => Some(SizeClass::Giant),
            _ => None, // Too large for slab
        }
    }

    pub fn size(&self) -> usize {
        *self as usize
    }
}

/// A handle to an allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocHandle(u64);

impl AllocHandle {
    fn new(slab_idx: u8, slot_idx: u32) -> Self {
        let id = ((slab_idx as u64) << 32) | (slot_idx as u64);
        Self(id)
    }

    fn slab_idx(&self) -> usize {
        (self.0 >> 32) as usize
    }

    fn slot_idx(&self) -> usize {
        (self.0 & 0xFFFF_FFFF) as usize
    }
}

/// A slab allocator for fixed-size allocations
struct Slab {
    size_class: SizeClass,
    /// Backing storage
    storage: Vec<u8>,
    /// Free list (indices of free slots)
    free_list: Vec<u32>,
    /// Total slots
    capacity: usize,
    /// Currently allocated
    allocated: usize,
}

impl Slab {
    fn new(size_class: SizeClass, num_slots: usize) -> Self {
        let slot_size = size_class.size();
        let total_size = slot_size * num_slots;

        // Pre-fill free list
        let free_list: Vec<u32> = (0..num_slots as u32).rev().collect();

        Self {
            size_class,
            storage: vec![0u8; total_size],
            free_list,
            capacity: num_slots,
            allocated: 0,
        }
    }

    fn alloc(&mut self) -> Option<(u32, &mut [u8])> {
        let slot_idx = self.free_list.pop()?;
        self.allocated += 1;

        let slot_size = self.size_class.size();
        let start = slot_idx as usize * slot_size;
        let end = start + slot_size;

        Some((slot_idx, &mut self.storage[start..end]))
    }

    fn free(&mut self, slot_idx: u32) {
        debug_assert!((slot_idx as usize) < self.capacity);
        self.free_list.push(slot_idx);
        self.allocated -= 1;
    }

    fn get(&self, slot_idx: u32) -> &[u8] {
        let slot_size = self.size_class.size();
        let start = slot_idx as usize * slot_size;
        let end = start + slot_size;
        &self.storage[start..end]
    }

    fn get_mut(&mut self, slot_idx: u32) -> &mut [u8] {
        let slot_size = self.size_class.size();
        let start = slot_idx as usize * slot_size;
        let end = start + slot_size;
        &mut self.storage[start..end]
    }

    fn utilization(&self) -> f32 {
        self.allocated as f32 / self.capacity as f32
    }
}

/// Arena allocator for batch-lifetime allocations
///
/// All allocations in an arena are freed together when the arena is reset.
/// Perfect for intermediate activations during inference.
pub struct Arena {
    storage: Vec<u8>,
    cursor: usize,
    high_water: usize,
}

impl Arena {
    pub fn new(capacity: usize) -> Self {
        Self {
            storage: vec![0u8; capacity],
            cursor: 0,
            high_water: 0,
        }
    }

    /// Allocate bytes (8-byte aligned)
    pub fn alloc(&mut self, bytes: usize) -> Option<&mut [u8]> {
        // Align to 8 bytes
        let aligned_cursor = (self.cursor + 7) & !7;
        let end = aligned_cursor + bytes;

        if end > self.storage.len() {
            return None;
        }

        self.cursor = end;
        self.high_water = self.high_water.max(end);

        Some(&mut self.storage[aligned_cursor..end])
    }

    /// Reset arena (free all allocations)
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Current usage
    pub fn used(&self) -> usize {
        self.cursor
    }

    /// Maximum ever used
    pub fn high_water_mark(&self) -> usize {
        self.high_water
    }

    /// Total capacity
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Available space
    pub fn available(&self) -> usize {
        self.storage.len() - self.cursor
    }
}

/// Bump allocator for monotonically growing data (like KV cache)
pub struct BumpAllocator {
    storage: Vec<u8>,
    cursor: AtomicUsize,
}

impl BumpAllocator {
    pub fn new(capacity: usize) -> Self {
        Self {
            storage: vec![0u8; capacity],
            cursor: AtomicUsize::new(0),
        }
    }

    /// Allocate bytes (returns start offset)
    pub fn alloc(&self, bytes: usize) -> Option<usize> {
        let old = self.cursor.fetch_add(bytes, Ordering::Relaxed);
        if old + bytes > self.storage.len() {
            // Rollback
            self.cursor.fetch_sub(bytes, Ordering::Relaxed);
            return None;
        }
        Some(old)
    }

    /// Get slice at offset
    pub fn get(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len > self.cursor.load(Ordering::Relaxed) {
            return None;
        }
        Some(&self.storage[offset..offset + len])
    }

    /// Current usage
    pub fn used(&self) -> usize {
        self.cursor.load(Ordering::Relaxed)
    }

    /// Total capacity
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }
}

/// Allocation statistics
#[derive(Debug, Default)]
pub struct AllocStats {
    pub total_allocations: u64,
    pub total_frees: u64,
    pub bytes_allocated: u64,
    pub peak_bytes: u64,
    pub slab_hits: u64,
    pub arena_allocs: u64,
    pub large_allocs: u64,
}

/// The main AI-native memory pool
pub struct MemoryPool {
    /// Slabs for different size classes
    slabs: Vec<Slab>,
    /// Arena for batch allocations
    arena: Arena,
    /// Stats
    stats: AllocStats,
    /// Total pool size
    total_size: usize,
}

impl MemoryPool {
    /// Create a memory pool with given capacity
    pub fn new(total_bytes: usize) -> Self {
        // Divide space: 60% slabs, 30% arena, 10% overhead
        let slab_bytes = total_bytes * 60 / 100;
        let arena_bytes = total_bytes * 30 / 100;

        // Create slabs for each size class
        // Allocate proportionally more slots for smaller sizes
        let slabs = vec![
            Slab::new(SizeClass::Tiny, slab_bytes * 30 / 100 / 64),
            Slab::new(SizeClass::Small, slab_bytes * 25 / 100 / 256),
            Slab::new(SizeClass::Medium, slab_bytes * 20 / 100 / 1024),
            Slab::new(SizeClass::Large, slab_bytes * 15 / 100 / 4096),
            Slab::new(SizeClass::Huge, slab_bytes * 7 / 100 / 16384),
            Slab::new(SizeClass::Giant, slab_bytes * 3 / 100 / 65536),
        ];

        Self {
            slabs,
            arena: Arena::new(arena_bytes),
            stats: AllocStats::default(),
            total_size: total_bytes,
        }
    }

    /// Allocate from slab
    pub fn alloc(&mut self, bytes: usize) -> Option<(AllocHandle, &mut [u8])> {
        let size_class = SizeClass::for_size(bytes)?;
        let slab_idx = match size_class {
            SizeClass::Tiny => 0,
            SizeClass::Small => 1,
            SizeClass::Medium => 2,
            SizeClass::Large => 3,
            SizeClass::Huge => 4,
            SizeClass::Giant => 5,
        };

        let slab = &mut self.slabs[slab_idx];
        let (slot_idx, slice) = slab.alloc()?;

        self.stats.total_allocations += 1;
        self.stats.slab_hits += 1;
        self.stats.bytes_allocated += size_class.size() as u64;
        self.stats.peak_bytes = self.stats.peak_bytes.max(self.stats.bytes_allocated);

        let handle = AllocHandle::new(slab_idx as u8, slot_idx);
        Some((handle, &mut slice[..bytes]))
    }

    /// Free slab allocation
    pub fn free(&mut self, handle: AllocHandle) {
        let slab_idx = handle.slab_idx();
        let slot_idx = handle.slot_idx() as u32;

        if slab_idx < self.slabs.len() {
            let size_class = self.slabs[slab_idx].size_class;
            self.slabs[slab_idx].free(slot_idx);
            self.stats.total_frees += 1;
            self.stats.bytes_allocated -= size_class.size() as u64;
        }
    }

    /// Get slice from handle
    pub fn get(&self, handle: AllocHandle) -> Option<&[u8]> {
        let slab_idx = handle.slab_idx();
        let slot_idx = handle.slot_idx() as u32;

        if slab_idx < self.slabs.len() {
            Some(self.slabs[slab_idx].get(slot_idx))
        } else {
            None
        }
    }

    /// Get mutable slice from handle
    pub fn get_mut(&mut self, handle: AllocHandle) -> Option<&mut [u8]> {
        let slab_idx = handle.slab_idx();
        let slot_idx = handle.slot_idx() as u32;

        if slab_idx < self.slabs.len() {
            Some(self.slabs[slab_idx].get_mut(slot_idx))
        } else {
            None
        }
    }

    /// Allocate from arena (batch-scoped)
    pub fn arena_alloc(&mut self, bytes: usize) -> Option<&mut [u8]> {
        let result = self.arena.alloc(bytes);
        if result.is_some() {
            self.stats.arena_allocs += 1;
        }
        result
    }

    /// Reset arena (free all arena allocations)
    pub fn arena_reset(&mut self) {
        self.arena.reset();
    }

    /// Get arena stats
    pub fn arena_used(&self) -> usize {
        self.arena.used()
    }

    /// Get allocation statistics
    pub fn stats(&self) -> &AllocStats {
        &self.stats
    }

    /// Get slab utilization
    pub fn slab_utilization(&self) -> Vec<(SizeClass, f32)> {
        self.slabs
            .iter()
            .map(|s| (s.size_class, s.utilization()))
            .collect()
    }

    /// Total pool size
    pub fn total_size(&self) -> usize {
        self.total_size
    }
}

/// Tensor allocation helper
///
/// Provides convenient methods for allocating tensors of specific shapes
pub struct TensorAllocator {
    pool: MemoryPool,
}

impl TensorAllocator {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pool: MemoryPool::new(pool_size),
        }
    }

    /// Allocate a 1D tensor
    pub fn alloc_1d<T: Sized>(&mut self, len: usize) -> Option<(AllocHandle, &mut [u8])> {
        let bytes = len * core::mem::size_of::<T>();
        self.pool.alloc(bytes)
    }

    /// Allocate a 2D tensor (row-major)
    pub fn alloc_2d<T: Sized>(&mut self, rows: usize, cols: usize) -> Option<(AllocHandle, &mut [u8])> {
        let bytes = rows * cols * core::mem::size_of::<T>();
        self.pool.alloc(bytes)
    }

    /// Allocate for batch activations (use arena)
    pub fn alloc_activation(&mut self, bytes: usize) -> Option<&mut [u8]> {
        self.pool.arena_alloc(bytes)
    }

    /// End of batch (reset activations)
    pub fn end_batch(&mut self) {
        self.pool.arena_reset();
    }

    /// Free tensor
    pub fn free(&mut self, handle: AllocHandle) {
        self.pool.free(handle);
    }

    /// Get pool stats
    pub fn stats(&self) -> &AllocStats {
        self.pool.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_class() {
        assert_eq!(SizeClass::for_size(32), Some(SizeClass::Tiny));
        assert_eq!(SizeClass::for_size(64), Some(SizeClass::Tiny));
        assert_eq!(SizeClass::for_size(65), Some(SizeClass::Small));
        assert_eq!(SizeClass::for_size(256), Some(SizeClass::Small));
        assert_eq!(SizeClass::for_size(1024), Some(SizeClass::Medium));
        assert_eq!(SizeClass::for_size(4096), Some(SizeClass::Large));
        assert_eq!(SizeClass::for_size(65536), Some(SizeClass::Giant));
        assert_eq!(SizeClass::for_size(65537), None);
    }

    #[test]
    fn test_slab_allocator() {
        let mut slab = Slab::new(SizeClass::Small, 10);

        // Allocate all slots
        let mut handles = Vec::new();
        for _ in 0..10 {
            let (idx, slice) = slab.alloc().unwrap();
            slice[0] = 42;
            handles.push(idx);
        }

        // Should be full
        assert!(slab.alloc().is_none());
        assert_eq!(slab.allocated, 10);

        // Free one
        slab.free(handles.pop().unwrap());
        assert_eq!(slab.allocated, 9);

        // Can allocate again
        assert!(slab.alloc().is_some());
    }

    #[test]
    fn test_arena_allocator() {
        let mut arena = Arena::new(1024);

        // Allocate some memory
        let a = arena.alloc(100).unwrap();
        assert_eq!(a.len(), 100);

        let b = arena.alloc(200).unwrap();
        assert_eq!(b.len(), 200);

        assert!(arena.used() > 300); // Due to alignment

        // Reset
        arena.reset();
        assert_eq!(arena.used(), 0);

        // Can allocate again
        let c = arena.alloc(500).unwrap();
        assert_eq!(c.len(), 500);
    }

    #[test]
    fn test_arena_high_water() {
        let mut arena = Arena::new(1024);

        arena.alloc(100).unwrap();
        arena.alloc(200).unwrap();
        let hw1 = arena.high_water_mark();

        arena.reset();
        arena.alloc(50).unwrap();

        // High water should not decrease
        assert_eq!(arena.high_water_mark(), hw1);
    }

    #[test]
    fn test_bump_allocator() {
        let bump = BumpAllocator::new(1024);

        let offset1 = bump.alloc(100).unwrap();
        assert_eq!(offset1, 0);

        let offset2 = bump.alloc(200).unwrap();
        assert_eq!(offset2, 100);

        assert_eq!(bump.used(), 300);

        // Get slice
        let slice = bump.get(0, 100).unwrap();
        assert_eq!(slice.len(), 100);
    }

    #[test]
    fn test_memory_pool_basic() {
        let mut pool = MemoryPool::new(1024 * 1024); // 1 MB

        // Allocate small
        let (h1, slice) = pool.alloc(32).unwrap();
        slice[0] = 1;

        // Allocate medium
        let (h2, slice) = pool.alloc(512).unwrap();
        slice[0] = 2;

        // Free
        pool.free(h1);
        pool.free(h2);

        assert_eq!(pool.stats().total_allocations, 2);
        assert_eq!(pool.stats().total_frees, 2);
    }

    #[test]
    fn test_memory_pool_arena() {
        let mut pool = MemoryPool::new(1024 * 1024);

        // Arena allocations
        let a1 = pool.arena_alloc(1000).unwrap();
        a1[0] = 1;

        let a2 = pool.arena_alloc(2000).unwrap();
        a2[0] = 2;

        assert!(pool.arena_used() >= 3000);

        // Reset arena
        pool.arena_reset();
        assert_eq!(pool.arena_used(), 0);

        assert_eq!(pool.stats().arena_allocs, 2);
    }

    #[test]
    fn test_alloc_handle_encoding() {
        let handle = AllocHandle::new(3, 12345);
        assert_eq!(handle.slab_idx(), 3);
        assert_eq!(handle.slot_idx(), 12345);
    }

    #[test]
    fn test_slab_utilization() {
        let mut pool = MemoryPool::new(1024 * 1024);

        // Allocate some tiny objects
        for _ in 0..10 {
            pool.alloc(32).unwrap();
        }

        let util = pool.slab_utilization();
        // Tiny slab should have some utilization
        assert!(util[0].1 > 0.0);
    }

    #[test]
    fn test_tensor_allocator() {
        let mut alloc = TensorAllocator::new(1024 * 1024);

        // Allocate 1D tensor of 100 f32s
        let (h1, slice) = alloc.alloc_1d::<f32>(100).unwrap();
        assert_eq!(slice.len(), 400); // 100 * 4 bytes

        // Allocate 2D tensor 10x10 f32s
        let (h2, slice) = alloc.alloc_2d::<f32>(10, 10).unwrap();
        assert_eq!(slice.len(), 400);

        // Batch activation
        let act = alloc.alloc_activation(1000).unwrap();
        assert_eq!(act.len(), 1000);

        // End batch
        alloc.end_batch();

        // Free tensors
        alloc.free(h1);
        alloc.free(h2);
    }
}
