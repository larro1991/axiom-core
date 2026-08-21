//! Work-Stealing Scheduler for AI Workloads
//!
//! Traditional schedulers: time-slice based, fairness focused
//! AI workloads: bursty, heterogeneous, dependency-driven
//!
//! This scheduler:
//! - Deques per worker for locality
//! - Work stealing when idle
//! - Priority-aware stealing
//! - Affinity hints for NUMA-aware placement

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::executor::{Task, TaskPriority, TaskId};

/// Worker identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub usize);

/// Affinity hint for task placement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityHint {
    /// No preference, schedule anywhere
    Any,
    /// Prefer specific worker (e.g., for cache locality)
    PreferWorker(WorkerId),
    /// Must run on specific worker (e.g., GPU affinity)
    RequireWorker(WorkerId),
    /// Prefer workers with GPU access
    PreferGpu,
    /// Prefer workers with specific NUMA node
    PreferNuma(u8),
}

/// A schedulable work unit
#[derive(Debug)]
pub struct WorkUnit {
    pub task: Task,
    pub affinity: AffinityHint,
    /// Dependencies that must complete first
    pub dependencies: Vec<TaskId>,
    /// Estimated cost (microseconds)
    pub estimated_cost: u64,
}

impl WorkUnit {
    pub fn new(task: Task) -> Self {
        Self {
            task,
            affinity: AffinityHint::Any,
            dependencies: Vec::new(),
            estimated_cost: 1000, // Default 1ms
        }
    }

    pub fn with_affinity(mut self, affinity: AffinityHint) -> Self {
        self.affinity = affinity;
        self
    }

    pub fn with_dependency(mut self, dep: TaskId) -> Self {
        self.dependencies.push(dep);
        self
    }

    pub fn with_cost(mut self, micros: u64) -> Self {
        self.estimated_cost = micros;
        self
    }
}

/// Per-worker double-ended queue
///
/// - Push to back (local work)
/// - Pop from back (LIFO for locality)
/// - Steal from front (FIFO for fairness)
pub struct WorkQueue {
    /// The actual queue, separated by priority
    queues: [VecDeque<WorkUnit>; 4],
    /// Total items across all priorities
    len: AtomicUsize,
}

impl WorkQueue {
    pub fn new() -> Self {
        Self {
            queues: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            len: AtomicUsize::new(0),
        }
    }

    /// Push work (local worker)
    pub fn push(&mut self, work: WorkUnit) {
        let idx = work.task.priority as usize;
        self.queues[idx].push_back(work);
        self.len.fetch_add(1, Ordering::Relaxed);
    }

    /// Pop work (local worker, LIFO)
    pub fn pop(&mut self) -> Option<WorkUnit> {
        // Check highest priority first
        for priority in (0..4).rev() {
            if let Some(work) = self.queues[priority].pop_back() {
                self.len.fetch_sub(1, Ordering::Relaxed);
                return Some(work);
            }
        }
        None
    }

    /// Steal work (remote worker, FIFO for fairness)
    pub fn steal(&mut self) -> Option<WorkUnit> {
        // Steal highest priority first
        for priority in (0..4).rev() {
            if let Some(work) = self.queues[priority].pop_front() {
                self.len.fetch_sub(1, Ordering::Relaxed);
                return Some(work);
            }
        }
        None
    }

    /// Number of items
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Worker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Actively processing
    Running,
    /// Looking for work
    Idle,
    /// Attempting to steal
    Stealing,
    /// Shutting down
    Stopping,
}

/// Per-worker statistics
#[derive(Debug, Default)]
pub struct WorkerStats {
    pub tasks_executed: u64,
    pub tasks_stolen: u64,
    pub tasks_stolen_from: u64,
    pub total_work_time_us: u64,
    pub total_idle_time_us: u64,
}

/// A worker in the scheduler
pub struct Worker {
    id: WorkerId,
    queue: WorkQueue,
    state: WorkerState,
    stats: WorkerStats,
    /// Which NUMA node this worker prefers
    numa_node: Option<u8>,
    /// Whether this worker has GPU access
    has_gpu: bool,
}

impl Worker {
    pub fn new(id: WorkerId) -> Self {
        Self {
            id,
            queue: WorkQueue::new(),
            state: WorkerState::Idle,
            stats: WorkerStats::default(),
            numa_node: None,
            has_gpu: false,
        }
    }

    pub fn with_numa(mut self, node: u8) -> Self {
        self.numa_node = Some(node);
        self
    }

    pub fn with_gpu(mut self) -> Self {
        self.has_gpu = true;
        self
    }

    pub fn id(&self) -> WorkerId {
        self.id
    }

    pub fn state(&self) -> WorkerState {
        self.state
    }

    pub fn stats(&self) -> &WorkerStats {
        &self.stats
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Schedule work on this worker
    pub fn schedule(&mut self, work: WorkUnit) {
        self.queue.push(work);
    }

    /// Get next work item
    pub fn next_work(&mut self) -> Option<WorkUnit> {
        self.queue.pop()
    }

    /// Let another worker steal from us
    pub fn allow_steal(&mut self) -> Option<WorkUnit> {
        let work = self.queue.steal();
        if work.is_some() {
            self.stats.tasks_stolen_from += 1;
        }
        work
    }

    /// Record that we stole work
    pub fn record_steal(&mut self) {
        self.stats.tasks_stolen += 1;
    }

    /// Record task execution
    pub fn record_execution(&mut self, duration_us: u64) {
        self.stats.tasks_executed += 1;
        self.stats.total_work_time_us += duration_us;
    }

    /// Record idle time
    pub fn record_idle(&mut self, duration_us: u64) {
        self.stats.total_idle_time_us += duration_us;
    }

    pub fn set_state(&mut self, state: WorkerState) {
        self.state = state;
    }

    pub fn numa_node(&self) -> Option<u8> {
        self.numa_node
    }

    pub fn has_gpu(&self) -> bool {
        self.has_gpu
    }
}

/// The work-stealing scheduler
pub struct Scheduler {
    workers: Vec<Worker>,
    /// Global queue for overflow
    global_queue: WorkQueue,
    /// Round-robin counter for global distribution
    next_worker: AtomicUsize,
    /// Total tasks scheduled
    total_scheduled: AtomicU64,
    /// Total tasks completed
    total_completed: AtomicU64,
}

impl Scheduler {
    /// Create scheduler with N workers
    pub fn new(num_workers: usize) -> Self {
        let workers = (0..num_workers)
            .map(|i| Worker::new(WorkerId(i)))
            .collect();

        Self {
            workers,
            global_queue: WorkQueue::new(),
            next_worker: AtomicUsize::new(0),
            total_scheduled: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
        }
    }

    /// Configure a worker
    pub fn configure_worker<F>(&mut self, id: WorkerId, f: F)
    where
        F: FnOnce(Worker) -> Worker,
    {
        if let Some(worker) = self.workers.get_mut(id.0) {
            let old = core::mem::replace(worker, Worker::new(id));
            *worker = f(old);
        }
    }

    /// Schedule work with affinity hints
    pub fn schedule(&mut self, work: WorkUnit) {
        self.total_scheduled.fetch_add(1, Ordering::Relaxed);

        match work.affinity {
            AffinityHint::Any => {
                // Round-robin to workers
                let idx = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.workers.len();
                self.workers[idx].schedule(work);
            }
            AffinityHint::PreferWorker(id) => {
                if id.0 < self.workers.len() {
                    self.workers[id.0].schedule(work);
                } else {
                    self.global_queue.push(work);
                }
            }
            AffinityHint::RequireWorker(id) => {
                if id.0 < self.workers.len() {
                    self.workers[id.0].schedule(work);
                } else {
                    // Can't schedule, put in global queue and hope
                    self.global_queue.push(work);
                }
            }
            AffinityHint::PreferGpu => {
                // Find a worker with GPU
                if let Some(worker) = self.workers.iter_mut().find(|w| w.has_gpu) {
                    worker.schedule(work);
                } else {
                    self.global_queue.push(work);
                }
            }
            AffinityHint::PreferNuma(node) => {
                // Find a worker on the preferred NUMA node
                if let Some(worker) = self.workers.iter_mut().find(|w| w.numa_node == Some(node)) {
                    worker.schedule(work);
                } else {
                    self.global_queue.push(work);
                }
            }
        }
    }

    /// Worker asks for work
    pub fn get_work(&mut self, worker_id: WorkerId) -> Option<WorkUnit> {
        let worker_idx = worker_id.0;
        if worker_idx >= self.workers.len() {
            return None;
        }

        // First, try local queue
        if let Some(work) = self.workers[worker_idx].next_work() {
            return Some(work);
        }

        // Second, try global queue
        if let Some(work) = self.global_queue.pop() {
            return Some(work);
        }

        // Third, try stealing from other workers
        self.workers[worker_idx].set_state(WorkerState::Stealing);

        let num_workers = self.workers.len();
        for offset in 1..num_workers {
            let victim_idx = (worker_idx + offset) % num_workers;
            // Can't borrow both mutably, so use split_at_mut
            if victim_idx < worker_idx {
                let (left, right) = self.workers.split_at_mut(worker_idx);
                if let Some(work) = left[victim_idx].allow_steal() {
                    right[0].record_steal();
                    right[0].set_state(WorkerState::Running);
                    return Some(work);
                }
            } else {
                let (left, right) = self.workers.split_at_mut(victim_idx);
                if let Some(work) = right[0].allow_steal() {
                    left[worker_idx].record_steal();
                    left[worker_idx].set_state(WorkerState::Running);
                    return Some(work);
                }
            }
        }

        self.workers[worker_idx].set_state(WorkerState::Idle);
        None
    }

    /// Mark work as completed
    pub fn complete(&mut self, worker_id: WorkerId, duration_us: u64) {
        self.total_completed.fetch_add(1, Ordering::Relaxed);
        if let Some(worker) = self.workers.get_mut(worker_id.0) {
            worker.record_execution(duration_us);
        }
    }

    /// Number of workers
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// Get worker by ID
    pub fn worker(&self, id: WorkerId) -> Option<&Worker> {
        self.workers.get(id.0)
    }

    /// Total pending work across all queues
    pub fn pending_work(&self) -> usize {
        let worker_work: usize = self.workers.iter().map(|w| w.queue_len()).sum();
        worker_work + self.global_queue.len()
    }

    /// Stats
    pub fn total_scheduled(&self) -> u64 {
        self.total_scheduled.load(Ordering::Relaxed)
    }

    pub fn total_completed(&self) -> u64 {
        self.total_completed.load(Ordering::Relaxed)
    }

    /// Get load balance info
    pub fn load_balance(&self) -> Vec<usize> {
        self.workers.iter().map(|w| w.queue_len()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(name: &str, priority: TaskPriority) -> Task {
        Task::new(name, |_ctx| Ok(())).with_priority(priority)
    }

    #[test]
    fn test_work_queue_priority() {
        let mut queue = WorkQueue::new();

        // Add work at different priorities
        queue.push(WorkUnit::new(make_task("low", TaskPriority::Low)));
        queue.push(WorkUnit::new(make_task("high", TaskPriority::High)));
        queue.push(WorkUnit::new(make_task("normal", TaskPriority::Normal)));
        queue.push(WorkUnit::new(make_task("critical", TaskPriority::Critical)));

        assert_eq!(queue.len(), 4);

        // Pop should return highest priority first (LIFO within priority)
        assert_eq!(queue.pop().unwrap().task.priority, TaskPriority::Critical);
        assert_eq!(queue.pop().unwrap().task.priority, TaskPriority::High);
        assert_eq!(queue.pop().unwrap().task.priority, TaskPriority::Normal);
        assert_eq!(queue.pop().unwrap().task.priority, TaskPriority::Low);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_work_queue_steal() {
        let mut queue = WorkQueue::new();

        // Add multiple items at same priority
        for i in 0..5 {
            queue.push(WorkUnit::new(make_task(&format!("task{}", i), TaskPriority::Normal)));
        }

        // Steal takes from front (FIFO)
        let stolen = queue.steal().unwrap();
        assert!(stolen.task.priority == TaskPriority::Normal);
        assert_eq!(queue.len(), 4);
    }

    #[test]
    fn test_scheduler_round_robin() {
        let mut scheduler = Scheduler::new(3);

        // Schedule 6 tasks with Any affinity
        for i in 0..6 {
            let work = WorkUnit::new(make_task(&format!("task{}", i), TaskPriority::Normal));
            scheduler.schedule(work);
        }

        // Should be distributed: 2, 2, 2
        let loads = scheduler.load_balance();
        assert_eq!(loads, vec![2, 2, 2]);
    }

    #[test]
    fn test_scheduler_affinity() {
        let mut scheduler = Scheduler::new(3);

        // Schedule to specific worker
        let work = WorkUnit::new(make_task("affinity_task", TaskPriority::Normal))
            .with_affinity(AffinityHint::PreferWorker(WorkerId(1)));
        scheduler.schedule(work);

        let loads = scheduler.load_balance();
        assert_eq!(loads, vec![0, 1, 0]);
    }

    #[test]
    fn test_scheduler_gpu_affinity() {
        let mut scheduler = Scheduler::new(3);

        // Configure worker 2 with GPU
        scheduler.configure_worker(WorkerId(2), |w| w.with_gpu());

        // Schedule GPU work
        let work = WorkUnit::new(make_task("gpu_task", TaskPriority::Normal))
            .with_affinity(AffinityHint::PreferGpu);
        scheduler.schedule(work);

        let loads = scheduler.load_balance();
        assert_eq!(loads, vec![0, 0, 1]);
    }

    #[test]
    fn test_scheduler_numa_affinity() {
        let mut scheduler = Scheduler::new(4);

        // Configure NUMA topology
        scheduler.configure_worker(WorkerId(0), |w| w.with_numa(0));
        scheduler.configure_worker(WorkerId(1), |w| w.with_numa(0));
        scheduler.configure_worker(WorkerId(2), |w| w.with_numa(1));
        scheduler.configure_worker(WorkerId(3), |w| w.with_numa(1));

        // Schedule to NUMA node 1
        let work = WorkUnit::new(make_task("numa_task", TaskPriority::Normal))
            .with_affinity(AffinityHint::PreferNuma(1));
        scheduler.schedule(work);

        // Should go to worker 2 (first on NUMA 1)
        let loads = scheduler.load_balance();
        assert_eq!(loads[2] + loads[3], 1);
        assert_eq!(loads[0] + loads[1], 0);
    }

    #[test]
    fn test_scheduler_work_stealing() {
        let mut scheduler = Scheduler::new(2);

        // Put all work on worker 0
        for i in 0..4 {
            let work = WorkUnit::new(make_task(&format!("steal{}", i), TaskPriority::Normal))
                .with_affinity(AffinityHint::RequireWorker(WorkerId(0)));
            scheduler.schedule(work);
        }

        assert_eq!(scheduler.load_balance(), vec![4, 0]);

        // Worker 1 tries to get work (should steal)
        let work = scheduler.get_work(WorkerId(1));
        assert!(work.is_some());

        // Worker 1 stole from worker 0
        let worker1 = scheduler.worker(WorkerId(1)).unwrap();
        assert_eq!(worker1.stats().tasks_stolen, 1);

        let worker0 = scheduler.worker(WorkerId(0)).unwrap();
        assert_eq!(worker0.stats().tasks_stolen_from, 1);
    }

    #[test]
    fn test_scheduler_local_first() {
        let mut scheduler = Scheduler::new(2);

        // Schedule work to both workers
        for i in 0..2 {
            let work = WorkUnit::new(make_task(&format!("local{}", i), TaskPriority::Normal))
                .with_affinity(AffinityHint::RequireWorker(WorkerId(i)));
            scheduler.schedule(work);
        }

        // Worker 0 gets local work first
        let work = scheduler.get_work(WorkerId(0));
        assert!(work.is_some());

        // Didn't steal
        let worker0 = scheduler.worker(WorkerId(0)).unwrap();
        assert_eq!(worker0.stats().tasks_stolen, 0);
    }

    #[test]
    fn test_scheduler_completion() {
        let mut scheduler = Scheduler::new(2);

        let work = WorkUnit::new(make_task("completion_task", TaskPriority::Normal));
        scheduler.schedule(work);

        assert_eq!(scheduler.total_scheduled(), 1);
        assert_eq!(scheduler.total_completed(), 0);

        // Get and complete work
        let _ = scheduler.get_work(WorkerId(0));
        scheduler.complete(WorkerId(0), 1000);

        assert_eq!(scheduler.total_completed(), 1);

        let worker = scheduler.worker(WorkerId(0)).unwrap();
        assert_eq!(worker.stats().tasks_executed, 1);
        assert_eq!(worker.stats().total_work_time_us, 1000);
    }

    #[test]
    fn test_work_unit_builder() {
        let task = make_task("builder_task", TaskPriority::High);
        let work = WorkUnit::new(task)
            .with_affinity(AffinityHint::PreferGpu)
            .with_dependency(TaskId(42))
            .with_dependency(TaskId(43))
            .with_cost(5000);

        assert_eq!(work.affinity, AffinityHint::PreferGpu);
        assert_eq!(work.dependencies.len(), 2);
        assert_eq!(work.estimated_cost, 5000);
    }
}
