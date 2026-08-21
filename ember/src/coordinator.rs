//! EMBER Coordinator - orchestrates distributed workloads

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::NodeId;
use hashbrown::HashMap;

use crate::capability::{CapabilityDatabase, NodeCapability};
use crate::estimate::{EstimateConfig, ResourceEstimate};
use crate::task::{Task, TaskId, TaskPriority, TaskResult, TaskState};
use crate::workload::{Workload, WorkloadId, WorkloadState, WorkloadType};

/// Coordinator configuration
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Maximum concurrent workloads
    pub max_workloads: usize,
    /// Maximum tasks per node
    pub max_tasks_per_node: u32,
    /// Task timeout in seconds
    pub task_timeout_secs: u64,
    /// Node stale threshold in seconds
    pub node_stale_threshold_secs: u64,
    /// Enable result verification
    pub enable_verification: bool,
    /// Estimation config
    pub estimate_config: EstimateConfig,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            max_workloads: 100,
            max_tasks_per_node: 4,
            task_timeout_secs: 3600,     // 1 hour
            node_stale_threshold_secs: 300, // 5 minutes
            enable_verification: true,
            estimate_config: EstimateConfig::default(),
        }
    }
}

/// Coordinator errors
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("Workload not found: {0:?}")]
    WorkloadNotFound(WorkloadId),

    #[error("Task not found: {0:?}")]
    TaskNotFound(TaskId),

    #[error("No available nodes for task")]
    NoAvailableNodes,

    #[error("Node not registered: {0:?}")]
    NodeNotRegistered(NodeId),

    #[error("Maximum workloads reached")]
    MaxWorkloadsReached,

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),
}

/// The EMBER Coordinator
#[cfg(feature = "std")]
pub struct Coordinator {
    /// Our node ID
    local_id: NodeId,
    /// Configuration
    config: CoordinatorConfig,
    /// Capability database
    capabilities: CapabilityDatabase,
    /// Active workloads
    workloads: HashMap<WorkloadId, Workload>,
    /// All tasks
    tasks: HashMap<TaskId, Task>,
    /// Task assignment: TaskId -> NodeId
    task_assignments: HashMap<TaskId, NodeId>,
    /// Node -> assigned task count
    node_task_count: HashMap<NodeId, u32>,
    /// Next workload ID
    next_workload_id: u64,
    /// Next task ID
    next_task_id: u64,
    /// Statistics
    stats: CoordinatorStats,
}

/// Coordinator statistics
#[derive(Debug, Default, Clone)]
pub struct CoordinatorStats {
    /// Total workloads submitted
    pub workloads_submitted: u64,
    /// Workloads completed
    pub workloads_completed: u64,
    /// Workloads failed
    pub workloads_failed: u64,
    /// Total tasks created
    pub tasks_created: u64,
    /// Tasks completed
    pub tasks_completed: u64,
    /// Tasks failed
    pub tasks_failed: u64,
    /// Task retries
    pub task_retries: u64,
    /// Average task execution time (ms)
    pub avg_task_time_ms: u64,
}

#[cfg(feature = "std")]
impl Coordinator {
    /// Create new coordinator
    pub fn new(local_id: NodeId) -> Self {
        Self::with_config(local_id, CoordinatorConfig::default())
    }

    /// Create with custom config
    pub fn with_config(local_id: NodeId, config: CoordinatorConfig) -> Self {
        Self {
            local_id,
            config,
            capabilities: CapabilityDatabase::new(),
            workloads: HashMap::new(),
            tasks: HashMap::new(),
            task_assignments: HashMap::new(),
            node_task_count: HashMap::new(),
            next_workload_id: 1,
            next_task_id: 1,
            stats: CoordinatorStats::default(),
        }
    }

    /// Register a node's capabilities
    pub fn register_node(&mut self, cap: NodeCapability) {
        let node_id = cap.node_id;
        self.capabilities.register(cap);
        self.node_task_count.entry(node_id).or_insert(0);
    }

    /// Update node as seen
    pub fn node_heartbeat(&mut self, node_id: NodeId, now: u64) {
        if let Some(cap) = self.capabilities.get_mut(&node_id) {
            cap.last_seen = now;
            cap.update_availability(true);
        }
    }

    /// Get resource estimate for a workload
    pub fn estimate(&self, workload: &Workload) -> ResourceEstimate {
        ResourceEstimate::compute(workload, &self.capabilities, &self.config.estimate_config)
    }

    /// Submit a new workload
    pub fn submit(&mut self, mut workload: Workload, now: u64) -> Result<WorkloadId, CoordinatorError> {
        if self.workloads.len() >= self.config.max_workloads {
            return Err(CoordinatorError::MaxWorkloadsReached);
        }

        // Assign ID
        let id = WorkloadId(self.next_workload_id);
        self.next_workload_id += 1;
        workload.id = id;
        workload.created_at = now;

        // Decompose into tasks
        let tasks = self.decompose_workload(&workload)?;
        workload.tasks = tasks.iter().map(|t| t.id).collect();

        // Store tasks
        for task in tasks {
            self.tasks.insert(task.id, task);
        }

        self.stats.workloads_submitted += 1;
        self.workloads.insert(id, workload);

        Ok(id)
    }

    /// Decompose workload into tasks
    fn decompose_workload(&mut self, workload: &Workload) -> Result<Vec<Task>, CoordinatorError> {
        let mut tasks = Vec::new();

        match workload.workload_type {
            WorkloadType::ProteinFolding => {
                // Stage 1: MSA (can be parallelized)
                let msa_task = self.create_task(
                    workload.id,
                    "MSA Search".into(),
                    workload.input_data.clone(),
                    4, // 4GB VRAM
                    workload.requirements.compute_hours as f32 * 0.2,
                );
                tasks.push(msa_task);

                // Stage 2: Attention (depends on MSA)
                let attention_task = self.create_task(
                    workload.id,
                    "Attention".into(),
                    vec![], // Will be filled with MSA output
                    workload.requirements.min_vram_gb,
                    workload.requirements.compute_hours as f32 * 0.5,
                );
                let mut attention = attention_task;
                attention.dependencies = vec![tasks[0].id];
                tasks.push(attention);

                // Stage 3: Structure prediction (depends on Attention)
                let structure_task = self.create_task(
                    workload.id,
                    "Structure".into(),
                    vec![],
                    workload.requirements.min_vram_gb,
                    workload.requirements.compute_hours as f32 * 0.3,
                );
                let mut structure = structure_task;
                structure.dependencies = vec![tasks[1].id];
                tasks.push(structure);
            }

            WorkloadType::Visualization => {
                // Split into parallel frame rendering tasks
                let frame_count = (workload.requirements.compute_hours * 100.0) as u32;
                let frames_per_task = 10;
                let task_count = (frame_count / frames_per_task).max(1);

                for i in 0..task_count {
                    let task = self.create_task(
                        workload.id,
                        alloc::format!("Render frames {}-{}", i * frames_per_task, (i + 1) * frames_per_task),
                        vec![], // Frame range encoded here
                        workload.requirements.min_vram_gb,
                        workload.requirements.compute_hours as f32 / task_count as f32,
                    );
                    tasks.push(task);
                }
            }

            _ => {
                // Generic single task
                let task = self.create_task(
                    workload.id,
                    workload.name.clone(),
                    workload.input_data.clone(),
                    workload.requirements.min_vram_gb,
                    workload.requirements.compute_hours as f32,
                );
                tasks.push(task);
            }
        }

        // Add verification tasks if required
        if workload.requirements.requires_verification && self.config.enable_verification {
            let original_len = tasks.len();
            for i in 0..original_len {
                let original = &tasks[i];
                let mut verification = original.clone();
                verification.id = TaskId(self.next_task_id);
                self.next_task_id += 1;
                verification.name = alloc::format!("{} (verify)", original.name);
                verification.is_verification = true;
                tasks.push(verification);
            }
        }

        self.stats.tasks_created += tasks.len() as u64;
        Ok(tasks)
    }

    /// Create a new task
    fn create_task(
        &mut self,
        workload_id: WorkloadId,
        name: String,
        input: Vec<u8>,
        required_vram_gb: u32,
        estimated_compute: f32,
    ) -> Task {
        let id = TaskId(self.next_task_id);
        self.next_task_id += 1;
        Task::new(id, workload_id, name, input, required_vram_gb, estimated_compute)
    }

    /// Start processing a workload
    pub fn start(&mut self, workload_id: WorkloadId, now: u64) -> Result<(), CoordinatorError> {
        let workload = self.workloads.get_mut(&workload_id)
            .ok_or(CoordinatorError::WorkloadNotFound(workload_id))?;

        if workload.state != WorkloadState::Pending {
            return Err(CoordinatorError::InvalidStateTransition(
                "Can only start pending workloads".into()
            ));
        }

        workload.state = WorkloadState::Distributing;
        workload.started_at = Some(now);
        Ok(())
    }

    /// Get next task ready for assignment
    pub fn get_ready_task(&self, workload_id: WorkloadId) -> Option<&Task> {
        let workload = self.workloads.get(&workload_id)?;
        let completed: Vec<TaskId> = workload.tasks.iter()
            .filter_map(|tid| {
                self.tasks.get(tid)
                    .filter(|t| t.state == TaskState::Completed)
                    .map(|_| *tid)
            })
            .collect();

        workload.tasks.iter()
            .filter_map(|tid| self.tasks.get(tid))
            .find(|task| task.is_ready(&completed))
    }

    /// Assign a task to a node
    pub fn assign_task(
        &mut self,
        task_id: TaskId,
        node_id: NodeId,
        now: u64,
    ) -> Result<(), CoordinatorError> {
        // Check node is registered and available
        let cap = self.capabilities.get(&node_id)
            .ok_or(CoordinatorError::NodeNotRegistered(node_id))?;

        let task_count = self.node_task_count.get(&node_id).copied().unwrap_or(0);
        if task_count >= self.config.max_tasks_per_node {
            return Err(CoordinatorError::NoAvailableNodes);
        }

        // Check task exists and can be assigned
        let task = self.tasks.get_mut(&task_id)
            .ok_or(CoordinatorError::TaskNotFound(task_id))?;

        if task.state != TaskState::Pending {
            return Err(CoordinatorError::InvalidStateTransition(
                "Can only assign pending tasks".into()
            ));
        }

        // Check node can handle task
        if !cap.can_handle(task.required_vram_gb, task.estimated_compute) {
            return Err(CoordinatorError::InsufficientResources(
                alloc::format!(
                    "Node {} cannot handle task (VRAM: {} < {}, TFLOPS: {} < {})",
                    node_id,
                    cap.vram_gb,
                    task.required_vram_gb,
                    cap.compute_tflops,
                    task.estimated_compute
                )
            ));
        }

        // Assign
        task.assign(node_id, now);
        self.task_assignments.insert(task_id, node_id);
        *self.node_task_count.entry(node_id).or_insert(0) += 1;

        // Update workload state
        if let Some(workload) = self.workloads.get_mut(&task.workload_id) {
            if workload.state == WorkloadState::Distributing {
                workload.state = WorkloadState::Running;
            }
        }

        Ok(())
    }

    /// Mark task as started (execution began)
    pub fn task_started(&mut self, task_id: TaskId, now: u64) -> Result<(), CoordinatorError> {
        let task = self.tasks.get_mut(&task_id)
            .ok_or(CoordinatorError::TaskNotFound(task_id))?;
        task.start(now);
        Ok(())
    }

    /// Complete a task
    pub fn complete_task(
        &mut self,
        task_id: TaskId,
        result: TaskResult,
        now: u64,
    ) -> Result<(), CoordinatorError> {
        let task = self.tasks.get_mut(&task_id)
            .ok_or(CoordinatorError::TaskNotFound(task_id))?;

        let workload_id = task.workload_id;
        let success = result.success;
        let exec_time = result.execution_time_ms;

        task.complete(result, now);

        // Update node task count
        if let Some(node_id) = self.task_assignments.remove(&task_id) {
            if let Some(count) = self.node_task_count.get_mut(&node_id) {
                *count = count.saturating_sub(1);
            }
        }

        // Update stats
        if success {
            self.stats.tasks_completed += 1;
            // Update average execution time
            let total = self.stats.avg_task_time_ms * (self.stats.tasks_completed - 1);
            self.stats.avg_task_time_ms = (total + exec_time) / self.stats.tasks_completed;
        } else {
            self.stats.tasks_failed += 1;
        }

        // Update workload
        if let Some(workload) = self.workloads.get_mut(&workload_id) {
            if success {
                workload.completed_tasks += 1;
            } else {
                workload.failed_tasks += 1;
            }

            // Check if workload is complete
            let all_done = workload.tasks.iter()
                .filter_map(|tid| self.tasks.get(tid))
                .all(|t| t.is_terminal());

            if all_done {
                let any_failed = workload.tasks.iter()
                    .filter_map(|tid| self.tasks.get(tid))
                    .any(|t| t.state == TaskState::Failed);

                workload.state = if any_failed {
                    self.stats.workloads_failed += 1;
                    WorkloadState::Failed
                } else {
                    self.stats.workloads_completed += 1;
                    WorkloadState::Completed
                };
                workload.completed_at = Some(now);
            }
        }

        Ok(())
    }

    /// Find best node for a task
    pub fn find_best_node(&self, task: &Task, now: u64) -> Option<NodeId> {
        let available = self.capabilities.find_available(
            self.config.max_tasks_per_node,
            self.config.node_stale_threshold_secs,
            now,
        );

        // Filter by capability
        let capable: Vec<_> = available.into_iter()
            .filter(|cap| cap.can_handle(task.required_vram_gb, task.estimated_compute))
            .collect();

        if capable.is_empty() {
            return None;
        }

        // Sort by: least loaded, highest trust, most compute
        let mut candidates: Vec<_> = capable.into_iter()
            .map(|cap| {
                let load = self.node_task_count.get(&cap.node_id).copied().unwrap_or(0);
                (cap, load)
            })
            .collect();

        candidates.sort_by(|(a, load_a), (b, load_b)| {
            // Prefer lower load
            match load_a.cmp(load_b) {
                core::cmp::Ordering::Equal => {
                    // Then prefer higher compute
                    b.compute_tflops.partial_cmp(&a.compute_tflops)
                        .unwrap_or(core::cmp::Ordering::Equal)
                }
                other => other,
            }
        });

        candidates.first().map(|(cap, _)| cap.node_id)
    }

    /// Get workload status
    pub fn get_workload(&self, id: WorkloadId) -> Option<&Workload> {
        self.workloads.get(&id)
    }

    /// Get task status
    pub fn get_task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.get(&id)
    }

    /// Get coordinator stats
    pub fn stats(&self) -> &CoordinatorStats {
        &self.stats
    }

    /// Get capability database
    pub fn capabilities(&self) -> &CapabilityDatabase {
        &self.capabilities
    }

    /// List active workloads
    pub fn active_workloads(&self) -> Vec<&Workload> {
        self.workloads.values()
            .filter(|w| w.is_active())
            .collect()
    }

    /// Cleanup completed workloads older than threshold
    pub fn cleanup(&mut self, older_than_secs: u64, now: u64) {
        let to_remove: Vec<WorkloadId> = self.workloads.iter()
            .filter(|(_, w)| {
                w.is_terminal() &&
                w.completed_at.map(|t| now - t > older_than_secs).unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            if let Some(workload) = self.workloads.remove(&id) {
                for task_id in workload.tasks {
                    self.tasks.remove(&task_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::GpuType;

    fn test_node_id(n: u8) -> NodeId {
        NodeId::from_bytes([n; 32])
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_coordinator_basic() {
        let mut coord = Coordinator::new(test_node_id(0));

        // Register some nodes
        coord.register_node(NodeCapability::from_hal(
            test_node_id(1),
            "Desktop1".into(),
            GpuType::NvidiaConsumer,
            12,
            32,
            100,
        ));
        coord.register_node(NodeCapability::from_hal(
            test_node_id(2),
            "Desktop2".into(),
            GpuType::NvidiaConsumer,
            8,
            16,
            100,
        ));

        assert_eq!(coord.capabilities().node_count(), 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_workload_submission() {
        let mut coord = Coordinator::new(test_node_id(0));

        // Register a node
        let mut cap = NodeCapability::from_hal(
            test_node_id(1),
            "Desktop1".into(),
            GpuType::NvidiaConsumer,
            12,
            32,
            100,
        );
        cap.last_seen = 1000;
        coord.register_node(cap);

        // Submit workload
        let workload = Workload::protein_folding(WorkloadId(0), vec![], 100);
        let id = coord.submit(workload, 1000).unwrap();

        let w = coord.get_workload(id).unwrap();
        assert_eq!(w.state, WorkloadState::Pending);
        assert!(!w.tasks.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_task_assignment() {
        let mut coord = Coordinator::new(test_node_id(0));

        // Register a node
        let mut cap = NodeCapability::from_hal(
            test_node_id(1),
            "Desktop1".into(),
            GpuType::NvidiaConsumer,
            12,
            32,
            100,
        );
        cap.last_seen = 1000;
        coord.register_node(cap);

        // Submit and start workload
        let workload = Workload::protein_folding(WorkloadId(0), vec![], 100);
        let id = coord.submit(workload, 1000).unwrap();
        coord.start(id, 1000).unwrap();

        // Get ready task and assign
        let task = coord.get_ready_task(id).unwrap();
        let task_id = task.id;

        coord.assign_task(task_id, test_node_id(1), 1001).unwrap();

        let task = coord.get_task(task_id).unwrap();
        assert_eq!(task.state, TaskState::Assigned);
    }
}
