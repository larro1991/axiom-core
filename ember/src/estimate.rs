//! Resource estimation for distributed workloads

use crate::capability::CapabilityDatabase;
use crate::workload::{Workload, WorkloadRequirements};

/// Configuration for estimation
#[derive(Debug, Clone)]
pub struct EstimateConfig {
    /// Redundancy factor for fault tolerance (1.0 = no redundancy)
    pub redundancy_factor: f32,
    /// Overhead factor for coordination (1.0 = no overhead)
    pub coordination_overhead: f32,
    /// Minimum nodes regardless of calculation
    pub min_nodes: u32,
    /// Maximum nodes to consider
    pub max_nodes: u32,
}

impl Default for EstimateConfig {
    fn default() -> Self {
        Self {
            redundancy_factor: 1.2,      // 20% extra for fault tolerance
            coordination_overhead: 1.1,   // 10% for coordination
            min_nodes: 1,
            max_nodes: 1000,
        }
    }
}

/// Result of resource estimation
#[derive(Debug, Clone)]
pub struct ResourceEstimate {
    /// Nodes required (compute-constrained)
    pub compute_nodes: u32,
    /// Nodes required (memory-constrained)
    pub memory_nodes: u32,
    /// Nodes required (bandwidth-constrained)
    pub bandwidth_nodes: u32,
    /// Final recommended nodes (max of constraints + redundancy)
    pub nodes_required: u32,
    /// Estimated time to complete (hours)
    pub time_hours: f64,
    /// Estimated cost savings vs cloud (0.0-1.0)
    pub cost_savings_ratio: f32,
    /// Confidence level (0.0-1.0)
    pub confidence: f32,
    /// Breakdown of compute allocation
    pub compute_breakdown: ComputeBreakdown,
    /// Warnings/notes
    pub warnings: alloc::vec::Vec<alloc::string::String>,
}

/// Breakdown of compute requirements
#[derive(Debug, Clone)]
pub struct ComputeBreakdown {
    /// Total TFLOP-hours needed
    pub total_tflop_hours: f64,
    /// Effective TFLOP-hours per node-hour
    pub tflop_hours_per_node: f64,
    /// Parallel stages
    pub parallel_stages: u32,
    /// Sequential stages
    pub sequential_stages: u32,
}

impl ResourceEstimate {
    /// Create estimate from requirements and available capability
    #[cfg(feature = "std")]
    pub fn compute(
        workload: &Workload,
        cap_db: &CapabilityDatabase,
        config: &EstimateConfig,
    ) -> Self {
        let req = &workload.requirements;
        let mut warnings = alloc::vec::Vec::new();

        // Get averages from capability database
        let avg_tflops = cap_db.avg_tflops().max(1.0); // Avoid division by zero
        let avg_vram = cap_db.avg_vram_gb().max(1);
        let avg_availability = cap_db.avg_availability().max(0.1);

        // Compute-constrained nodes
        let compute_nodes = Self::compute_constrained_nodes(
            req,
            avg_tflops,
            avg_availability,
        );

        // Memory-constrained nodes
        let memory_nodes = Self::memory_constrained_nodes(req, avg_vram);

        // Bandwidth-constrained nodes
        let bandwidth_nodes = Self::bandwidth_constrained_nodes(req, 100.0); // Assume 100 Mbps avg

        // Take maximum constraint
        let base_nodes = compute_nodes.max(memory_nodes).max(bandwidth_nodes);

        // Apply redundancy and overhead
        let with_redundancy = (base_nodes as f32 * config.redundancy_factor).ceil() as u32;
        let with_overhead = (with_redundancy as f32 * config.coordination_overhead).ceil() as u32;

        // Clamp to configured range
        let nodes_required = with_overhead.clamp(config.min_nodes, config.max_nodes);

        // Check if we have enough nodes
        if cap_db.node_count() < nodes_required as usize {
            warnings.push(alloc::format!(
                "Need {} nodes but only {} available in mesh",
                nodes_required,
                cap_db.node_count()
            ));
        }

        // Estimate time
        let effective_tflops = avg_tflops * avg_availability * req.parallel_efficiency;
        let time_hours = if nodes_required > 0 && effective_tflops > 0.0 {
            req.compute_hours / (nodes_required as f64 * effective_tflops as f64)
        } else {
            req.deadline_hours
        };

        // Check deadline
        if req.deadline_hours > 0.0 && time_hours > req.deadline_hours {
            warnings.push(alloc::format!(
                "Estimated time ({:.1}h) exceeds deadline ({:.1}h)",
                time_hours,
                req.deadline_hours
            ));
        }

        // Cost savings (rough: cloud A100 = $2/hr, desktop = $0.02/hr electricity)
        let cloud_cost = req.compute_hours * 2.0 / 312.0; // A100 is ~312 TFLOPS
        let ember_cost = nodes_required as f64 * time_hours * 0.02;
        let cost_savings_ratio = if cloud_cost > 0.0 {
            1.0 - (ember_cost / cloud_cost) as f32
        } else {
            0.0
        };

        // Confidence based on node count and availability
        let node_confidence = if cap_db.node_count() >= nodes_required as usize {
            1.0
        } else {
            cap_db.node_count() as f32 / nodes_required as f32
        };
        let availability_confidence = avg_availability;
        let confidence = (node_confidence * availability_confidence).clamp(0.0, 1.0);

        let compute_breakdown = ComputeBreakdown {
            total_tflop_hours: req.compute_hours,
            tflop_hours_per_node: effective_tflops as f64,
            parallel_stages: 1, // Simplified
            sequential_stages: 0,
        };

        Self {
            compute_nodes,
            memory_nodes,
            bandwidth_nodes,
            nodes_required,
            time_hours,
            cost_savings_ratio,
            confidence,
            compute_breakdown,
            warnings,
        }
    }

    /// Calculate compute-constrained node count
    fn compute_constrained_nodes(
        req: &WorkloadRequirements,
        avg_tflops: f32,
        avg_availability: f32,
    ) -> u32 {
        let deadline = if req.deadline_hours > 0.0 {
            req.deadline_hours
        } else {
            24.0 // Default 24 hours if no deadline
        };

        let effective_tflops_per_node = avg_tflops * avg_availability * req.parallel_efficiency;

        if effective_tflops_per_node > 0.0 {
            let node_hours = req.compute_hours / effective_tflops_per_node as f64;
            (node_hours / deadline).ceil() as u32
        } else {
            1
        }
    }

    /// Calculate memory-constrained node count
    fn memory_constrained_nodes(req: &WorkloadRequirements, avg_vram: u32) -> u32 {
        if avg_vram >= req.peak_memory_gb {
            1 // Single node can handle peak
        } else if avg_vram >= req.min_vram_gb {
            // Need to tile across nodes
            (req.peak_memory_gb / avg_vram).max(1)
        } else {
            // No node can handle minimum
            u32::MAX
        }
    }

    /// Calculate bandwidth-constrained node count
    fn bandwidth_constrained_nodes(req: &WorkloadRequirements, avg_bandwidth_mbps: f32) -> u32 {
        if req.data_transfer_gb <= 0.0 {
            return 1;
        }

        let deadline_hours = if req.deadline_hours > 0.0 {
            req.deadline_hours
        } else {
            24.0
        };

        // GB to transfer / (Mbps * hours * 3600 / 8000)
        let transfer_capacity_per_node = avg_bandwidth_mbps * deadline_hours as f32 * 3600.0 / 8000.0;

        if transfer_capacity_per_node > 0.0 {
            (req.data_transfer_gb as f32 / transfer_capacity_per_node).ceil() as u32
        } else {
            1
        }
    }

    /// Format as human-readable string
    pub fn summary(&self) -> alloc::string::String {
        alloc::format!(
            "EMBER Estimate:\n\
             - Nodes required: {}\n\
             - Estimated time: {:.1} hours\n\
             - Cost savings: {:.0}%\n\
             - Confidence: {:.0}%\n\
             - Constraints: compute={}, memory={}, bandwidth={}",
            self.nodes_required,
            self.time_hours,
            self.cost_savings_ratio * 100.0,
            self.confidence * 100.0,
            self.compute_nodes,
            self.memory_nodes,
            self.bandwidth_nodes,
        )
    }
}

/// Quick estimate without capability database (uses defaults)
pub fn quick_estimate(req: &WorkloadRequirements) -> ResourceEstimate {
    // Default assumptions
    let avg_tflops: f32 = 20.0; // RTX 3070 equivalent
    let avg_vram: u32 = 8;
    let avg_availability: f32 = 0.33; // 8 hours/day

    let compute_nodes = ResourceEstimate::compute_constrained_nodes(
        req,
        avg_tflops,
        avg_availability,
    );

    let memory_nodes = ResourceEstimate::memory_constrained_nodes(req, avg_vram);
    let bandwidth_nodes = ResourceEstimate::bandwidth_constrained_nodes(req, 100.0);

    let base_nodes = compute_nodes.max(memory_nodes).max(bandwidth_nodes);
    let nodes_required = ((base_nodes as f32) * 1.2).ceil() as u32; // 20% redundancy

    let deadline = if req.deadline_hours > 0.0 {
        req.deadline_hours
    } else {
        24.0
    };

    let effective_tflops = avg_tflops * avg_availability * req.parallel_efficiency;
    let time_hours = if nodes_required > 0 && effective_tflops > 0.0 {
        req.compute_hours / (nodes_required as f64 * effective_tflops as f64)
    } else {
        deadline
    };

    ResourceEstimate {
        compute_nodes,
        memory_nodes,
        bandwidth_nodes,
        nodes_required,
        time_hours,
        cost_savings_ratio: 0.9, // Assume 90% savings
        confidence: 0.5,          // Low confidence without real data
        compute_breakdown: ComputeBreakdown {
            total_tflop_hours: req.compute_hours,
            tflop_hours_per_node: effective_tflops as f64,
            parallel_stages: 1,
            sequential_stages: 0,
        },
        warnings: alloc::vec::Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::Workload;

    #[test]
    fn test_quick_estimate_protein_folding() {
        // 500 residue protein
        let workload = Workload::protein_folding(
            crate::workload::WorkloadId(1),
            vec![],
            500,
        );

        let estimate = quick_estimate(&workload.requirements);

        // Should need multiple nodes
        assert!(estimate.nodes_required > 1);

        // Should complete within 24 hours
        assert!(estimate.time_hours <= 24.0 || estimate.nodes_required >= 10);

        // Should show cost savings
        assert!(estimate.cost_savings_ratio > 0.5);
    }

    #[test]
    fn test_memory_constraint() {
        let req = WorkloadRequirements {
            compute_hours: 10.0,
            min_vram_gb: 8,
            peak_memory_gb: 40, // Large memory requirement
            data_transfer_gb: 1.0,
            parallel_efficiency: 0.8,
            deadline_hours: 24.0,
            requires_verification: false,
            checkpoint_interval_minutes: 0,
        };

        let estimate = quick_estimate(&req);

        // Memory constraint should dominate
        assert!(estimate.memory_nodes >= 5); // 40GB / 8GB = 5 nodes minimum
    }

    #[test]
    fn test_bandwidth_constraint() {
        let req = WorkloadRequirements {
            compute_hours: 1.0,
            min_vram_gb: 4,
            peak_memory_gb: 4,
            data_transfer_gb: 100.0, // 100GB to transfer
            parallel_efficiency: 0.9,
            deadline_hours: 1.0, // 1 hour deadline
            requires_verification: false,
            checkpoint_interval_minutes: 0,
        };

        let estimate = quick_estimate(&req);

        // Bandwidth should be a constraint
        assert!(estimate.bandwidth_nodes > 1);
    }
}
