//! Queue management and priority scheduling for AXIOM transport
//!
//! Provides priority-aware queuing and scheduling for outgoing frames:
//! - Per-priority queues (Low, Normal, High, Critical)
//! - Weighted fair queuing
//! - Queue depth limits with back-pressure
//! - Statistics and monitoring

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use axiom_types::frame::{Frame, Priority};

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use hashbrown::HashMap;

/// Configuration for queue management
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum queue depth per priority (frames)
    pub max_queue_depth: usize,
    /// Maximum total bytes across all queues
    pub max_total_bytes: usize,
    /// Weight for Low priority (relative to Normal=100)
    pub weight_low: u32,
    /// Weight for Normal priority
    pub weight_normal: u32,
    /// Weight for High priority
    pub weight_high: u32,
    /// Weight for Critical priority
    pub weight_critical: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_queue_depth: 1000,
            max_total_bytes: 10_000_000, // 10MB
            weight_low: 25,              // 25% of Normal
            weight_normal: 100,          // Baseline
            weight_high: 200,            // 2x Normal
            weight_critical: 400,        // 4x Normal
        }
    }
}

/// Queued frame entry
#[derive(Debug, Clone)]
pub struct QueuedFrame {
    /// The frame to send
    pub frame: Frame,
    /// Encoded frame data
    pub data: Vec<u8>,
    /// Destination address
    #[cfg(feature = "std")]
    pub dest: SocketAddr,
    /// When this frame was queued
    #[cfg(feature = "std")]
    pub queued_at: std::time::Instant,
    /// Number of send attempts
    pub attempts: u32,
}

/// Queue statistics
#[derive(Debug, Default, Clone)]
pub struct QueueStats {
    /// Frames enqueued
    pub enqueued: u64,
    /// Frames dequeued
    pub dequeued: u64,
    /// Frames dropped due to full queue
    pub dropped_full: u64,
    /// Frames dropped due to timeout
    pub dropped_timeout: u64,
    /// Total bytes enqueued
    pub bytes_enqueued: u64,
    /// Total bytes dequeued
    pub bytes_dequeued: u64,
}

/// Priority queue for a single priority level
#[cfg(feature = "std")]
#[derive(Debug)]
struct PriorityQueue {
    queue: VecDeque<QueuedFrame>,
    bytes: usize,
    weight: u32,
    deficit: u32,
}

#[cfg(feature = "std")]
impl PriorityQueue {
    fn new(weight: u32) -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            weight,
            deficit: 0,
        }
    }

    fn enqueue(&mut self, entry: QueuedFrame) {
        self.bytes += entry.data.len();
        self.queue.push_back(entry);
    }

    fn dequeue(&mut self) -> Option<QueuedFrame> {
        self.queue.pop_front().map(|entry| {
            self.bytes -= entry.data.len();
            entry
        })
    }

    fn peek(&self) -> Option<&QueuedFrame> {
        self.queue.front()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Weighted fair queue scheduler
#[cfg(feature = "std")]
pub struct QueueScheduler {
    config: QueueConfig,
    /// Queues by priority
    queues: [PriorityQueue; 4],
    /// Total bytes across all queues
    total_bytes: usize,
    /// Statistics
    stats: QueueStats,
}

#[cfg(feature = "std")]
impl QueueScheduler {
    pub fn new(config: QueueConfig) -> Self {
        Self {
            queues: [
                PriorityQueue::new(config.weight_low),
                PriorityQueue::new(config.weight_normal),
                PriorityQueue::new(config.weight_high),
                PriorityQueue::new(config.weight_critical),
            ],
            total_bytes: 0,
            stats: QueueStats::default(),
            config,
        }
    }

    /// Get queue index for a priority
    fn priority_index(priority: Priority) -> usize {
        match priority {
            Priority::Low => 0,
            Priority::Normal => 1,
            Priority::High => 2,
            Priority::Critical => 3,
        }
    }

    /// Enqueue a frame
    pub fn enqueue(&mut self, frame: Frame, data: Vec<u8>, dest: SocketAddr) -> Result<(), QueueFullError> {
        let priority = frame.header.priority;
        let idx = Self::priority_index(priority);

        // Check queue limits
        if self.queues[idx].len() >= self.config.max_queue_depth {
            self.stats.dropped_full += 1;
            return Err(QueueFullError::QueueDepthExceeded);
        }

        if self.total_bytes + data.len() > self.config.max_total_bytes {
            self.stats.dropped_full += 1;
            return Err(QueueFullError::TotalBytesExceeded);
        }

        let entry = QueuedFrame {
            frame,
            data: data.clone(),
            dest,
            queued_at: std::time::Instant::now(),
            attempts: 0,
        };

        self.total_bytes += entry.data.len();
        self.stats.enqueued += 1;
        self.stats.bytes_enqueued += entry.data.len() as u64;
        self.queues[idx].enqueue(entry);

        Ok(())
    }

    /// Dequeue the next frame using weighted fair scheduling
    pub fn dequeue(&mut self) -> Option<QueuedFrame> {
        // Deficit round-robin weighted fair queuing
        // Start from highest priority
        for iteration in 0..2 {
            // Give each queue a chance based on its weight
            for idx in (0..4).rev() {
                let queue = &mut self.queues[idx];

                if queue.is_empty() {
                    continue;
                }

                // Add weight to deficit
                if iteration == 0 {
                    queue.deficit += queue.weight;
                }

                // Check if we have enough deficit to send
                if let Some(entry) = queue.peek() {
                    let size = entry.data.len() as u32;
                    if queue.deficit >= size || idx == 3 {
                        // Critical priority always sends if it has frames
                        queue.deficit = queue.deficit.saturating_sub(size);
                        let entry = queue.dequeue().unwrap();
                        self.total_bytes -= entry.data.len();
                        self.stats.dequeued += 1;
                        self.stats.bytes_dequeued += entry.data.len() as u64;
                        return Some(entry);
                    }
                }
            }
        }

        None
    }

    /// Dequeue from a specific priority (for targeted dequeue)
    pub fn dequeue_priority(&mut self, priority: Priority) -> Option<QueuedFrame> {
        let idx = Self::priority_index(priority);
        self.queues[idx].dequeue().map(|entry| {
            self.total_bytes -= entry.data.len();
            self.stats.dequeued += 1;
            self.stats.bytes_dequeued += entry.data.len() as u64;
            entry
        })
    }

    /// Get depth of a priority queue
    pub fn queue_depth(&self, priority: Priority) -> usize {
        self.queues[Self::priority_index(priority)].len()
    }

    /// Get total queue depth
    pub fn total_depth(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Get total bytes in queue
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Check if all queues are empty
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(|q| q.is_empty())
    }

    /// Remove frames older than max_age
    pub fn cleanup_stale(&mut self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let mut removed = 0;

        for queue in &mut self.queues {
            let mut retained = VecDeque::new();
            while let Some(entry) = queue.queue.pop_front() {
                if now.duration_since(entry.queued_at) < max_age {
                    retained.push_back(entry);
                } else {
                    queue.bytes -= entry.data.len();
                    self.total_bytes -= entry.data.len();
                    self.stats.dropped_timeout += 1;
                    removed += 1;
                }
            }
            queue.queue = retained;
        }

        removed
    }

    /// Get queue statistics
    pub fn stats(&self) -> &QueueStats {
        &self.stats
    }
}

/// Error when queue is full
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueFullError {
    /// Per-priority queue depth exceeded
    QueueDepthExceeded,
    /// Total bytes limit exceeded
    TotalBytesExceeded,
}

/// Per-peer queue manager
#[cfg(feature = "std")]
pub struct QueueManager {
    config: QueueConfig,
    /// Per-peer schedulers
    schedulers: HashMap<SocketAddr, QueueScheduler>,
    /// Global statistics
    global_stats: QueueStats,
}

#[cfg(feature = "std")]
impl QueueManager {
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            schedulers: HashMap::new(),
            global_stats: QueueStats::default(),
        }
    }

    /// Get or create scheduler for a peer
    pub fn get_or_create(&mut self, peer: SocketAddr) -> &mut QueueScheduler {
        self.schedulers
            .entry(peer)
            .or_insert_with(|| QueueScheduler::new(self.config.clone()))
    }

    /// Enqueue a frame for a peer
    pub fn enqueue(&mut self, frame: Frame, data: Vec<u8>, dest: SocketAddr) -> Result<(), QueueFullError> {
        let result = self.get_or_create(dest).enqueue(frame, data, dest);
        if result.is_ok() {
            self.global_stats.enqueued += 1;
        } else {
            self.global_stats.dropped_full += 1;
        }
        result
    }

    /// Dequeue the next frame from any peer (round-robin)
    pub fn dequeue_any(&mut self) -> Option<QueuedFrame> {
        // Simple round-robin across peers with frames
        for scheduler in self.schedulers.values_mut() {
            if let Some(entry) = scheduler.dequeue() {
                self.global_stats.dequeued += 1;
                return Some(entry);
            }
        }
        None
    }

    /// Dequeue from a specific peer
    pub fn dequeue_peer(&mut self, peer: &SocketAddr) -> Option<QueuedFrame> {
        self.schedulers.get_mut(peer).and_then(|s| {
            s.dequeue().map(|entry| {
                self.global_stats.dequeued += 1;
                entry
            })
        })
    }

    /// Get total depth across all peers
    pub fn total_depth(&self) -> usize {
        self.schedulers.values().map(|s| s.total_depth()).sum()
    }

    /// Get total bytes across all peers
    pub fn total_bytes(&self) -> usize {
        self.schedulers.values().map(|s| s.total_bytes()).sum()
    }

    /// Cleanup stale frames across all peers
    pub fn cleanup_stale(&mut self, max_age: std::time::Duration) -> usize {
        let mut total = 0;
        for scheduler in self.schedulers.values_mut() {
            total += scheduler.cleanup_stale(max_age);
        }
        self.global_stats.dropped_timeout += total as u64;
        total
    }

    /// Remove empty schedulers
    pub fn cleanup_empty(&mut self) {
        self.schedulers.retain(|_, s| !s.is_empty());
    }

    /// Get number of peers with queued frames
    pub fn peer_count(&self) -> usize {
        self.schedulers.len()
    }

    /// Get global statistics
    pub fn stats(&self) -> &QueueStats {
        &self.global_stats
    }
}

// Stubs for no_std
#[cfg(not(feature = "std"))]
pub struct QueueScheduler;

#[cfg(not(feature = "std"))]
pub struct QueueManager;

#[cfg(not(feature = "std"))]
pub struct QueueStats;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use axiom_types::clock::HybridClock;
    use axiom_types::crypto::{IntentHash, NodeId};
    use axiom_types::frame::FrameHeader;
    use axiom_types::frame::FrameType;
    use axiom_types::payload::PayloadType;
    use axiom_types::trust::TrustLevel;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn test_frame(priority: Priority) -> Frame {
        let header = FrameHeader::new(FrameType::Intent, test_node_id(1))
            .with_priority(priority)
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        Frame::new(header, PayloadType::Raw, vec![1, 2, 3])
    }

    #[test]
    fn test_queue_scheduler_basic() {
        let config = QueueConfig::default();
        let mut scheduler = QueueScheduler::new(config);

        let dest: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Enqueue a frame
        let frame = test_frame(Priority::Normal);
        let data = vec![1, 2, 3, 4, 5];
        scheduler.enqueue(frame, data, dest).unwrap();

        assert_eq!(scheduler.total_depth(), 1);
        assert_eq!(scheduler.queue_depth(Priority::Normal), 1);

        // Dequeue
        let entry = scheduler.dequeue().unwrap();
        assert_eq!(entry.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(scheduler.total_depth(), 0);
    }

    #[test]
    fn test_priority_scheduling() {
        let config = QueueConfig::default();
        let mut scheduler = QueueScheduler::new(config);

        let dest: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Enqueue frames in order: Low, Normal, High, Critical
        for (idx, priority) in [Priority::Low, Priority::Normal, Priority::High, Priority::Critical]
            .iter()
            .enumerate()
        {
            let frame = test_frame(*priority);
            let data = vec![idx as u8];
            scheduler.enqueue(frame, data, dest).unwrap();
        }

        // Critical should come first
        let entry1 = scheduler.dequeue().unwrap();
        assert_eq!(entry1.data, vec![3]); // Critical

        // Then High
        let entry2 = scheduler.dequeue().unwrap();
        assert_eq!(entry2.data, vec![2]); // High
    }

    #[test]
    fn test_queue_full_error() {
        let config = QueueConfig {
            max_queue_depth: 2,
            ..Default::default()
        };
        let mut scheduler = QueueScheduler::new(config);

        let dest: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Fill queue
        for _ in 0..2 {
            let frame = test_frame(Priority::Normal);
            scheduler.enqueue(frame, vec![1, 2, 3], dest).unwrap();
        }

        // Third should fail
        let frame = test_frame(Priority::Normal);
        let result = scheduler.enqueue(frame, vec![1, 2, 3], dest);
        assert_eq!(result, Err(QueueFullError::QueueDepthExceeded));
    }

    #[test]
    fn test_total_bytes_limit() {
        let config = QueueConfig {
            max_total_bytes: 10,
            ..Default::default()
        };
        let mut scheduler = QueueScheduler::new(config);

        let dest: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Enqueue 6 bytes
        let frame1 = test_frame(Priority::Normal);
        scheduler.enqueue(frame1, vec![1, 2, 3, 4, 5, 6], dest).unwrap();

        // Try to enqueue 6 more bytes (would exceed 10)
        let frame2 = test_frame(Priority::Normal);
        let result = scheduler.enqueue(frame2, vec![1, 2, 3, 4, 5, 6], dest);
        assert_eq!(result, Err(QueueFullError::TotalBytesExceeded));
    }

    #[test]
    fn test_queue_manager_multi_peer() {
        let config = QueueConfig::default();
        let mut manager = QueueManager::new(config);

        let peer1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let peer2: SocketAddr = "127.0.0.1:8002".parse().unwrap();

        // Enqueue to different peers
        let frame1 = test_frame(Priority::Normal);
        manager.enqueue(frame1, vec![1], peer1).unwrap();

        let frame2 = test_frame(Priority::High);
        manager.enqueue(frame2, vec![2], peer2).unwrap();

        assert_eq!(manager.peer_count(), 2);
        assert_eq!(manager.total_depth(), 2);

        // Dequeue from peer2 (high priority should come first overall if we track globally)
        let entry1 = manager.dequeue_peer(&peer2).unwrap();
        assert_eq!(entry1.data, vec![2]);
    }

    #[test]
    fn test_weighted_fair_queuing() {
        let config = QueueConfig {
            weight_low: 25,
            weight_normal: 100,
            weight_high: 200,
            weight_critical: 400,
            ..Default::default()
        };
        let mut scheduler = QueueScheduler::new(config);

        let dest: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Enqueue many frames at different priorities
        for _ in 0..10 {
            let frame = test_frame(Priority::Low);
            scheduler.enqueue(frame, vec![0], dest).unwrap();
        }
        for _ in 0..10 {
            let frame = test_frame(Priority::Normal);
            scheduler.enqueue(frame, vec![1], dest).unwrap();
        }
        for _ in 0..10 {
            let frame = test_frame(Priority::High);
            scheduler.enqueue(frame, vec![2], dest).unwrap();
        }

        // Dequeue all and count by priority
        let mut counts = [0usize; 4];
        let mut dequeued = Vec::new();

        while let Some(entry) = scheduler.dequeue() {
            let prio_idx = entry.data[0] as usize;
            counts[prio_idx] += 1;
            dequeued.push(entry.data[0]);
        }

        // All should be dequeued eventually
        assert_eq!(counts.iter().sum::<usize>(), 30);

        // Higher priority should generally come before lower
        // (Critical/High should dominate the first half)
        let first_half: Vec<_> = dequeued[..15].to_vec();
        let high_in_first = first_half.iter().filter(|&&x| x >= 2).count();
        assert!(high_in_first > 5, "High priority should dominate early dequeues");
    }
}
