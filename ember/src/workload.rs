//! Workload definitions and requirements

use alloc::string::String;
use alloc::vec::Vec;
use crate::task::TaskId;

/// Type of distributed workload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadType {
    /// Protein structure prediction (AlphaFold-style)
    ProteinFolding,
    /// Genomic sequence analysis
    GenomicAnalysis,
    /// Climate/weather simulation
    ClimateSimulation,
    /// Distributed LLM inference
    LlmInference,
    /// Scientific visualization rendering
    Visualization,
    /// General tensor computation
    TensorCompute,
    /// Custom workload
    Custom,
}

impl WorkloadType {
    /// Get default parallel efficiency for this workload type
    pub fn default_parallel_efficiency(&self) -> f32 {
        match self {
            // Protein folding has sequential stages (MSA → Attention → Structure)
            WorkloadType::ProteinFolding => 0.6,
            // Genomic analysis is highly parallel
            WorkloadType::GenomicAnalysis => 0.85,
            // Climate simulation depends on grid coupling
            WorkloadType::ClimateSimulation => 0.7,
            // LLM inference limited by attention layers
            WorkloadType::LlmInference => 0.5,
            // Rendering is embarrassingly parallel
            WorkloadType::Visualization => 0.95,
            // General tensor ops vary
            WorkloadType::TensorCompute => 0.75,
            // Conservative for custom
            WorkloadType::Custom => 0.5,
        }
    }

    /// Get typical memory requirement multiplier (peak vs average)
    pub fn memory_peak_multiplier(&self) -> f32 {
        match self {
            WorkloadType::ProteinFolding => 2.0,    // Attention peaks
            WorkloadType::GenomicAnalysis => 1.5,
            WorkloadType::ClimateSimulation => 1.3,
            WorkloadType::LlmInference => 3.0,      // KV cache
            WorkloadType::Visualization => 1.2,
            WorkloadType::TensorCompute => 1.5,
            WorkloadType::Custom => 2.0,
        }
    }
}

/// Resource requirements for a workload
#[derive(Debug, Clone)]
pub struct WorkloadRequirements {
    /// Estimated TFLOP-hours needed
    pub compute_hours: f64,
    /// Minimum VRAM per node (GB)
    pub min_vram_gb: u32,
    /// Peak memory requirement (GB) - largest single task
    pub peak_memory_gb: u32,
    /// Total data transfer size (input + intermediate + output) in GB
    pub data_transfer_gb: f64,
    /// Parallelization efficiency (0.0-1.0)
    pub parallel_efficiency: f32,
    /// Deadline (hours from now, 0 = no deadline)
    pub deadline_hours: f64,
    /// Whether results need verification (compute twice, compare)
    pub requires_verification: bool,
    /// Checkpointing frequency (0 = no checkpoints)
    pub checkpoint_interval_minutes: u32,
}

impl Default for WorkloadRequirements {
    fn default() -> Self {
        Self {
            compute_hours: 0.0,
            min_vram_gb: 0,
            peak_memory_gb: 0,
            data_transfer_gb: 0.0,
            parallel_efficiency: 0.5,
            deadline_hours: 0.0,
            requires_verification: false,
            checkpoint_interval_minutes: 30,
        }
    }
}

/// Workload execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadState {
    /// Submitted but not started
    Pending,
    /// Tasks being distributed
    Distributing,
    /// Actively executing
    Running,
    /// Waiting for stragglers
    WaitingForCompletion,
    /// Aggregating results
    Aggregating,
    /// Completed successfully
    Completed,
    /// Failed (can be retried)
    Failed,
    /// Cancelled by user
    Cancelled,
}

/// A distributed workload
#[derive(Debug, Clone)]
pub struct Workload {
    /// Unique identifier
    pub id: WorkloadId,
    /// Workload type
    pub workload_type: WorkloadType,
    /// Human-readable name
    pub name: String,
    /// Resource requirements
    pub requirements: WorkloadRequirements,
    /// Current state
    pub state: WorkloadState,
    /// Input data (serialized)
    pub input_data: Vec<u8>,
    /// Created timestamp
    pub created_at: u64,
    /// Started timestamp (if started)
    pub started_at: Option<u64>,
    /// Completed timestamp (if completed)
    pub completed_at: Option<u64>,
    /// Child tasks
    pub tasks: Vec<TaskId>,
    /// Completed task count
    pub completed_tasks: u32,
    /// Failed task count
    pub failed_tasks: u32,
}

/// Workload identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkloadId(pub u64);

impl Workload {
    /// Create a new workload
    pub fn new(
        id: WorkloadId,
        workload_type: WorkloadType,
        name: String,
        requirements: WorkloadRequirements,
        input_data: Vec<u8>,
    ) -> Self {
        Self {
            id,
            workload_type,
            name,
            requirements,
            state: WorkloadState::Pending,
            input_data,
            created_at: 0,
            started_at: None,
            completed_at: None,
            tasks: Vec::new(),
            completed_tasks: 0,
            failed_tasks: 0,
        }
    }

    /// Create protein folding workload
    pub fn protein_folding(id: WorkloadId, sequence: Vec<u8>, residue_count: u32) -> Self {
        // Estimate based on residue count
        // ~2 TFLOP-hours per 100 residues base, scaling quadratically for attention
        let base_compute = 2.0 * (residue_count as f64 / 100.0);
        let attention_scaling = (residue_count as f64 / 100.0).powi(2);
        let compute_hours = base_compute + attention_scaling;

        // Memory scales with sequence length squared (attention matrix)
        let peak_memory = 4 + (residue_count / 50); // ~4GB base + scaling

        let requirements = WorkloadRequirements {
            compute_hours,
            min_vram_gb: 8,
            peak_memory_gb: peak_memory,
            data_transfer_gb: 0.5 + (residue_count as f64 * 0.002), // MSA data
            parallel_efficiency: 0.6,
            deadline_hours: 24.0,
            requires_verification: true,
            checkpoint_interval_minutes: 15,
        };

        Self::new(
            id,
            WorkloadType::ProteinFolding,
            alloc::format!("Protein_{}_residues", residue_count),
            requirements,
            sequence,
        )
    }

    /// Create LLM inference workload
    pub fn llm_inference(id: WorkloadId, prompt: Vec<u8>, model_params_b: f32) -> Self {
        // Estimate based on model size
        // Larger models need more VRAM and compute
        let compute_hours = model_params_b as f64 * 0.1; // Rough estimate
        let min_vram = (model_params_b * 2.0) as u32; // FP16, ~2 bytes per param

        let requirements = WorkloadRequirements {
            compute_hours,
            min_vram_gb: min_vram.max(8),
            peak_memory_gb: min_vram * 3, // KV cache
            data_transfer_gb: model_params_b as f64 * 0.01,
            parallel_efficiency: 0.5,
            deadline_hours: 1.0,
            requires_verification: false,
            checkpoint_interval_minutes: 0, // No checkpointing for inference
        };

        Self::new(
            id,
            WorkloadType::LlmInference,
            alloc::format!("LLM_{}B", model_params_b),
            requirements,
            prompt,
        )
    }

    /// Create visualization rendering workload
    pub fn visualization(id: WorkloadId, scene_data: Vec<u8>, frame_count: u32) -> Self {
        // Rendering is embarrassingly parallel
        let compute_hours = frame_count as f64 * 0.01; // ~36 seconds per frame

        let requirements = WorkloadRequirements {
            compute_hours,
            min_vram_gb: 4,
            peak_memory_gb: 8,
            data_transfer_gb: frame_count as f64 * 0.02, // ~20MB per frame output
            parallel_efficiency: 0.95,
            deadline_hours: compute_hours * 2.0, // Generous deadline
            requires_verification: false,
            checkpoint_interval_minutes: 10,
        };

        Self::new(
            id,
            WorkloadType::Visualization,
            alloc::format!("Render_{}_frames", frame_count),
            requirements,
            scene_data,
        )
    }

    /// Progress as percentage (0-100)
    pub fn progress_percent(&self) -> u8 {
        if self.tasks.is_empty() {
            return 0;
        }
        ((self.completed_tasks as f32 / self.tasks.len() as f32) * 100.0) as u8
    }

    /// Is the workload still active?
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            WorkloadState::Distributing
                | WorkloadState::Running
                | WorkloadState::WaitingForCompletion
                | WorkloadState::Aggregating
        )
    }

    /// Is the workload done (success or failure)?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            WorkloadState::Completed | WorkloadState::Failed | WorkloadState::Cancelled
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protein_folding_workload() {
        let workload = Workload::protein_folding(
            WorkloadId(1),
            b"MKTAYIAKQRQISFVKSH".to_vec(), // Sample sequence
            500,
        );

        assert_eq!(workload.workload_type, WorkloadType::ProteinFolding);
        assert!(workload.requirements.compute_hours > 0.0);
        assert!(workload.requirements.min_vram_gb >= 8);
        assert!(workload.requirements.parallel_efficiency <= 1.0);
    }

    #[test]
    fn test_workload_progress() {
        let mut workload = Workload::protein_folding(WorkloadId(1), vec![], 100);

        // Add tasks
        workload.tasks = vec![TaskId(1), TaskId(2), TaskId(3), TaskId(4)];
        workload.completed_tasks = 2;

        assert_eq!(workload.progress_percent(), 50);
    }

    #[test]
    fn test_workload_states() {
        let workload = Workload::protein_folding(WorkloadId(1), vec![], 100);
        assert!(!workload.is_active());
        assert!(!workload.is_terminal());

        let mut running = workload.clone();
        running.state = WorkloadState::Running;
        assert!(running.is_active());
        assert!(!running.is_terminal());

        let mut completed = workload.clone();
        completed.state = WorkloadState::Completed;
        assert!(!completed.is_active());
        assert!(completed.is_terminal());
    }
}
