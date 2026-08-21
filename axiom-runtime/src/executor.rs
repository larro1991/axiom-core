//! Executor - Task scheduling and execution
//!
//! Manages the execution of tasks on claimed resources.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use axiom_hal::ResourceId;
use hashbrown::HashMap;

use crate::context::AgentContext;
use crate::error::{RuntimeError, RuntimeResult};

/// Task priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TaskPriority {
    /// Background/batch tasks
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority (user-facing)
    High = 2,
    /// Critical (system tasks)
    Critical = 3,
}

impl Default for TaskPriority {
    fn default() -> Self {
        TaskPriority::Normal
    }
}

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Queued, waiting to run
    Pending,
    /// Currently running
    Running,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

/// Unique task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    /// Generate a new task ID
    pub fn generate() -> Self {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

/// A task to be executed
pub struct Task {
    /// Unique ID
    pub id: TaskId,
    /// Human-readable name
    pub name: String,
    /// Priority
    pub priority: TaskPriority,
    /// Current state
    pub state: TaskState,
    /// Required resource capability
    pub required_capability: Option<String>,
    /// The actual work (simplified - in real impl this would be more complex)
    work: Box<dyn FnOnce(&mut AgentContext) -> RuntimeResult<()> + Send>,
    /// Created timestamp
    pub created_at: u64,
    /// Started timestamp
    pub started_at: Option<u64>,
    /// Completed timestamp
    pub completed_at: Option<u64>,
}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("state", &self.state)
            .field("required_capability", &self.required_capability)
            .field("work", &"<closure>")
            .field("created_at", &self.created_at)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

impl Task {
    /// Create a new task
    pub fn new<F>(name: &str, work: F) -> Self
    where
        F: FnOnce(&mut AgentContext) -> RuntimeResult<()> + Send + 'static,
    {
        Self {
            id: TaskId::generate(),
            name: String::from(name),
            priority: TaskPriority::Normal,
            state: TaskState::Pending,
            required_capability: None,
            work: Box::new(work),
            created_at: 0,
            started_at: None,
            completed_at: None,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: TaskPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set required capability
    pub fn requiring(mut self, capability: &str) -> Self {
        self.required_capability = Some(String::from(capability));
        self
    }

    /// Execute the task
    fn execute(self, ctx: &mut AgentContext) -> RuntimeResult<()> {
        (self.work)(ctx)
    }
}

/// Task queue (priority-based)
pub struct TaskQueue {
    /// Tasks by priority
    queues: [VecDeque<Task>; 4],
    /// Total tasks
    total: usize,
}

impl TaskQueue {
    /// Create a new task queue
    pub fn new() -> Self {
        Self {
            queues: [
                VecDeque::new(), // Low
                VecDeque::new(), // Normal
                VecDeque::new(), // High
                VecDeque::new(), // Critical
            ],
            total: 0,
        }
    }

    /// Add a task
    pub fn push(&mut self, task: Task) {
        let idx = task.priority as usize;
        self.queues[idx].push_back(task);
        self.total += 1;
    }

    /// Get next task (highest priority first)
    pub fn pop(&mut self) -> Option<Task> {
        // Check from highest priority to lowest
        for idx in (0..4).rev() {
            if let Some(task) = self.queues[idx].pop_front() {
                self.total -= 1;
                return Some(task);
            }
        }
        None
    }

    /// Number of pending tasks
    pub fn len(&self) -> usize {
        self.total
    }

    /// Is queue empty?
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about execution
#[derive(Debug, Clone, Default)]
pub struct ExecutorStats {
    /// Total tasks executed
    pub tasks_executed: u64,
    /// Tasks completed successfully
    pub tasks_completed: u64,
    /// Tasks failed
    pub tasks_failed: u64,
    /// Tasks cancelled
    pub tasks_cancelled: u64,
    /// Total execution time (microseconds)
    pub total_exec_time_us: u64,
}

/// The executor - runs tasks on an agent context
pub struct Executor {
    /// Task queue
    queue: TaskQueue,
    /// Currently running task (simplified - single task at a time)
    current: Option<TaskId>,
    /// Stats
    stats: ExecutorStats,
    /// Time provider
    now_fn: fn() -> u64,
}

impl Executor {
    /// Create a new executor
    pub fn new() -> Self {
        Self {
            queue: TaskQueue::new(),
            current: None,
            stats: ExecutorStats::default(),
            now_fn: || 0,
        }
    }

    /// Set time provider
    pub fn with_time_provider(mut self, now_fn: fn() -> u64) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Submit a task
    pub fn submit(&mut self, mut task: Task) -> TaskId {
        task.created_at = (self.now_fn)();
        let id = task.id;
        self.queue.push(task);
        id
    }

    /// Run next task
    pub fn run_one(&mut self, ctx: &mut AgentContext) -> RuntimeResult<Option<TaskId>> {
        // Check agent can execute
        if !ctx.agent().can_execute() {
            return Err(RuntimeError::InvalidState {
                from: alloc::format!("{:?}", ctx.agent().state()),
                to: String::from("Running"),
            });
        }

        // Get next task
        let Some(mut task) = self.queue.pop() else {
            return Ok(None);
        };

        let task_id = task.id;

        // Check required capability
        if let Some(ref cap) = task.required_capability {
            if !ctx.has_resource(cap) {
                // Try to claim it
                if ctx.claim(cap).is_err() {
                    self.stats.tasks_failed += 1;
                    return Err(RuntimeError::CapabilityUnavailable(cap.clone()));
                }
            }
        }

        // Mark as running
        task.state = TaskState::Running;
        task.started_at = Some((self.now_fn)());
        self.current = Some(task_id);

        // Execute
        let result = task.execute(ctx);

        // Record stats
        self.current = None;
        self.stats.tasks_executed += 1;

        match result {
            Ok(()) => {
                self.stats.tasks_completed += 1;
                Ok(Some(task_id))
            }
            Err(e) => {
                self.stats.tasks_failed += 1;
                Err(e)
            }
        }
    }

    /// Run all pending tasks
    pub fn run_all(&mut self, ctx: &mut AgentContext) -> RuntimeResult<usize> {
        let mut count = 0;
        while !self.queue.is_empty() {
            match self.run_one(ctx) {
                Ok(Some(_)) => count += 1,
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }

    /// Get pending task count
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Get stats
    pub fn stats(&self) -> &ExecutorStats {
        &self.stats
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentConfig, AgentState};

    fn setup_context() -> AgentContext {
        let agent = Agent::new(AgentConfig::new("test"));
        let mut ctx = AgentContext::new(agent);

        // Transition to Ready so we can execute
        ctx.agent_mut().transition(AgentState::Initializing).unwrap();
        ctx.agent_mut().transition(AgentState::Ready).unwrap();

        ctx
    }

    #[test]
    fn test_task_creation() {
        let task = Task::new("test-task", |_ctx| Ok(()))
            .with_priority(TaskPriority::High)
            .requiring("compute:tensor");

        assert_eq!(task.name, "test-task");
        assert_eq!(task.priority, TaskPriority::High);
        assert_eq!(task.required_capability, Some(String::from("compute:tensor")));
    }

    #[test]
    fn test_task_queue_priority() {
        let mut queue = TaskQueue::new();

        queue.push(Task::new("low", |_| Ok(())).with_priority(TaskPriority::Low));
        queue.push(Task::new("critical", |_| Ok(())).with_priority(TaskPriority::Critical));
        queue.push(Task::new("normal", |_| Ok(())).with_priority(TaskPriority::Normal));

        // Should come out in priority order (highest first)
        assert_eq!(queue.pop().unwrap().name, "critical");
        assert_eq!(queue.pop().unwrap().name, "normal");
        assert_eq!(queue.pop().unwrap().name, "low");
    }

    #[test]
    fn test_executor_run_one() {
        let mut ctx = setup_context();
        let mut executor = Executor::new();

        // Track if task ran
        use core::sync::atomic::{AtomicBool, Ordering};
        static RAN: AtomicBool = AtomicBool::new(false);

        executor.submit(Task::new("test", |_ctx| {
            RAN.store(true, Ordering::SeqCst);
            Ok(())
        }));

        let result = executor.run_one(&mut ctx);
        assert!(result.is_ok());
        assert!(RAN.load(Ordering::SeqCst));
        assert_eq!(executor.stats().tasks_completed, 1);
    }

    #[test]
    fn test_executor_run_all() {
        let mut ctx = setup_context();
        let mut executor = Executor::new();

        executor.submit(Task::new("task1", |_| Ok(())));
        executor.submit(Task::new("task2", |_| Ok(())));
        executor.submit(Task::new("task3", |_| Ok(())));

        let count = executor.run_all(&mut ctx).unwrap();
        assert_eq!(count, 3);
        assert_eq!(executor.stats().tasks_completed, 3);
    }

    #[test]
    fn test_executor_task_failure() {
        let mut ctx = setup_context();
        let mut executor = Executor::new();

        executor.submit(Task::new("failing", |_| {
            Err(RuntimeError::TaskFailed(String::from("oops")))
        }));

        let result = executor.run_one(&mut ctx);
        assert!(result.is_err());
        assert_eq!(executor.stats().tasks_failed, 1);
    }
}
