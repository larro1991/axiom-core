//! Task definitions for workload decomposition

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::NodeId;
use crate::workload::WorkloadId;

/// Unique task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Task execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Waiting to be assigned
    Pending,
    /// Assigned to a node
    Assigned,
    /// Currently executing
    Running,
    /// Completed successfully
    Completed,
    /// Failed (may be retried)
    Failed,
    /// Cancelled
    Cancelled,
}

/// Result of task execution
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// Success flag
    pub success: bool,
    /// Output data (if successful)
    pub output: Option<Vec<u8>>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Peak memory used in MB
    pub peak_memory_mb: u32,
}

impl TaskResult {
    /// Create successful result
    pub fn success(output: Vec<u8>, execution_time_ms: u64, peak_memory_mb: u32) -> Self {
        Self {
            success: true,
            output: Some(output),
            error: None,
            execution_time_ms,
            peak_memory_mb,
        }
    }

    /// Create failed result
    pub fn failure(error: String, execution_time_ms: u64) -> Self {
        Self {
            success: false,
            output: None,
            error: Some(error),
            execution_time_ms,
            peak_memory_mb: 0,
        }
    }
}

/// Task priority for scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    /// Low priority (background)
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority (time-sensitive)
    High = 2,
    /// Critical (deadline approaching)
    Critical = 3,
}

/// An individual task within a workload
#[derive(Debug, Clone)]
pub struct Task {
    /// Unique identifier
    pub id: TaskId,
    /// Parent workload
    pub workload_id: WorkloadId,
    /// Task name/description
    pub name: String,
    /// Current state
    pub state: TaskState,
    /// Assigned node (if assigned)
    pub assigned_to: Option<NodeId>,
    /// Task input data
    pub input: Vec<u8>,
    /// Task result (if completed)
    pub result: Option<TaskResult>,
    /// Dependencies (task IDs that must complete first)
    pub dependencies: Vec<TaskId>,
    /// Priority
    pub priority: TaskPriority,
    /// Required VRAM (GB)
    pub required_vram_gb: u32,
    /// Estimated compute (TFLOP-hours)
    pub estimated_compute: f32,
    /// Created timestamp
    pub created_at: u64,
    /// Assigned timestamp
    pub assigned_at: Option<u64>,
    /// Started timestamp
    pub started_at: Option<u64>,
    /// Completed timestamp
    pub completed_at: Option<u64>,
    /// Retry count
    pub retries: u32,
    /// Max retries allowed
    pub max_retries: u32,
    /// Verification task ID (if this needs verification)
    pub verification_task: Option<TaskId>,
    /// Is this a verification task?
    pub is_verification: bool,
}

impl Task {
    /// Create a new task
    pub fn new(
        id: TaskId,
        workload_id: WorkloadId,
        name: String,
        input: Vec<u8>,
        required_vram_gb: u32,
        estimated_compute: f32,
    ) -> Self {
        Self {
            id,
            workload_id,
            name,
            state: TaskState::Pending,
            assigned_to: None,
            input,
            result: None,
            dependencies: Vec::new(),
            priority: TaskPriority::Normal,
            required_vram_gb,
            estimated_compute,
            created_at: 0,
            assigned_at: None,
            started_at: None,
            completed_at: None,
            retries: 0,
            max_retries: 3,
            verification_task: None,
            is_verification: false,
        }
    }

    /// Check if task is ready to run (all dependencies met)
    pub fn is_ready(&self, completed_tasks: &[TaskId]) -> bool {
        self.state == TaskState::Pending
            && self.dependencies.iter().all(|dep| completed_tasks.contains(dep))
    }

    /// Mark task as assigned
    pub fn assign(&mut self, node_id: NodeId, now: u64) {
        self.assigned_to = Some(node_id);
        self.assigned_at = Some(now);
        self.state = TaskState::Assigned;
    }

    /// Mark task as running
    pub fn start(&mut self, now: u64) {
        self.started_at = Some(now);
        self.state = TaskState::Running;
    }

    /// Complete task with result
    pub fn complete(&mut self, result: TaskResult, now: u64) {
        self.result = Some(result);
        self.completed_at = Some(now);
        self.state = if self.result.as_ref().map(|r| r.success).unwrap_or(false) {
            TaskState::Completed
        } else {
            TaskState::Failed
        };
    }

    /// Fail task and check if can retry
    pub fn fail(&mut self, error: String, now: u64) -> bool {
        self.result = Some(TaskResult::failure(error, 0));

        if self.retries < self.max_retries {
            self.retries += 1;
            self.state = TaskState::Pending;
            self.assigned_to = None;
            self.assigned_at = None;
            self.started_at = None;
            true // Can retry
        } else {
            self.completed_at = Some(now);
            self.state = TaskState::Failed;
            false // No more retries
        }
    }

    /// Cancel task
    pub fn cancel(&mut self, now: u64) {
        self.completed_at = Some(now);
        self.state = TaskState::Cancelled;
    }

    /// Get execution time if completed
    pub fn execution_time(&self) -> Option<u64> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            _ => None,
        }
    }

    /// Get wait time (time in queue)
    pub fn wait_time(&self) -> Option<u64> {
        match (self.assigned_at, self.started_at) {
            (Some(assigned), Some(started)) => Some(started - assigned),
            _ => None,
        }
    }

    /// Is task in terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled
        )
    }
}

/// Task decomposition for a workload stage
#[derive(Debug, Clone)]
pub struct TaskDecomposition {
    /// Stage name
    pub stage: String,
    /// Tasks in this stage
    pub tasks: Vec<Task>,
    /// Previous stage (dependency)
    pub depends_on_stage: Option<String>,
}

impl TaskDecomposition {
    pub fn new(stage: String) -> Self {
        Self {
            stage,
            tasks: Vec::new(),
            depends_on_stage: None,
        }
    }

    /// Add a task to this stage
    pub fn add_task(&mut self, task: Task) {
        self.tasks.push(task);
    }

    /// Total estimated compute for this stage
    pub fn total_compute(&self) -> f32 {
        self.tasks.iter().map(|t| t.estimated_compute).sum()
    }

    /// Max VRAM required (largest task)
    pub fn max_vram_required(&self) -> u32 {
        self.tasks.iter().map(|t| t.required_vram_gb).max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_lifecycle() {
        let mut task = Task::new(
            TaskId(1),
            WorkloadId(1),
            "Test Task".into(),
            vec![1, 2, 3],
            8,
            1.0,
        );

        assert_eq!(task.state, TaskState::Pending);
        assert!(task.is_ready(&[]));

        // Assign
        let node = NodeId::from_bytes([1; 32]);
        task.assign(node, 1000);
        assert_eq!(task.state, TaskState::Assigned);

        // Start
        task.start(1001);
        assert_eq!(task.state, TaskState::Running);

        // Complete
        let result = TaskResult::success(vec![4, 5, 6], 100, 500);
        task.complete(result, 1101);
        assert_eq!(task.state, TaskState::Completed);
        assert!(task.is_terminal());
    }

    #[test]
    fn test_task_dependencies() {
        let mut task = Task::new(
            TaskId(2),
            WorkloadId(1),
            "Dependent Task".into(),
            vec![],
            4,
            0.5,
        );
        task.dependencies = vec![TaskId(1)];

        // Not ready without dependency
        assert!(!task.is_ready(&[]));

        // Ready when dependency complete
        assert!(task.is_ready(&[TaskId(1)]));
    }

    #[test]
    fn test_task_retry() {
        let mut task = Task::new(
            TaskId(1),
            WorkloadId(1),
            "Flaky Task".into(),
            vec![],
            4,
            0.5,
        );
        task.max_retries = 2;

        // First failure - can retry
        assert!(task.fail("Error 1".into(), 1000));
        assert_eq!(task.retries, 1);
        assert_eq!(task.state, TaskState::Pending);

        // Second failure - can retry
        assert!(task.fail("Error 2".into(), 2000));
        assert_eq!(task.retries, 2);
        assert_eq!(task.state, TaskState::Pending);

        // Third failure - no more retries
        assert!(!task.fail("Error 3".into(), 3000));
        assert_eq!(task.state, TaskState::Failed);
    }
}
