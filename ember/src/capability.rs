//! Node capability discovery and tracking

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::NodeId;
use axiom_types::trust::TrustLevel;
use hashbrown::HashMap;

/// GPU type classification for compute estimation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    /// NVIDIA consumer (GeForce)
    NvidiaConsumer,
    /// NVIDIA professional (Quadro, RTX A-series)
    NvidiaProfessional,
    /// NVIDIA datacenter (A100, H100)
    NvidiaDatacenter,
    /// AMD consumer (RX series)
    AmdConsumer,
    /// AMD professional (Pro series)
    AmdProfessional,
    /// AMD datacenter (Instinct)
    AmdDatacenter,
    /// Intel Arc
    IntelArc,
    /// Apple Silicon (M1/M2/M3)
    AppleSilicon,
    /// CPU only (no discrete GPU)
    CpuOnly,
    /// Unknown GPU
    Unknown,
}

impl GpuType {
    /// Estimate tensor TFLOPS FP16 for common GPU models
    pub fn estimate_tflops(&self, vram_gb: u32) -> f32 {
        match self {
            // NVIDIA consumer - rough estimate based on VRAM tier
            GpuType::NvidiaConsumer => match vram_gb {
                0..=4 => 8.0,   // GTX 1650, etc.
                5..=8 => 16.0,  // RTX 3060, GTX 1080
                9..=12 => 25.0, // RTX 3080, 4070
                13..=16 => 35.0, // RTX 3090, 4080
                _ => 60.0,      // RTX 4090
            },
            // NVIDIA datacenter
            GpuType::NvidiaDatacenter => match vram_gb {
                0..=40 => 312.0,  // A100 40GB
                41..=80 => 624.0, // A100 80GB, H100
                _ => 1000.0,      // Future
            },
            // AMD consumer
            GpuType::AmdConsumer => match vram_gb {
                0..=8 => 12.0,
                9..=16 => 25.0,
                _ => 40.0,
            },
            // CPU only - minimal
            GpuType::CpuOnly => 0.5,
            // Apple Silicon
            GpuType::AppleSilicon => match vram_gb {
                0..=16 => 8.0,
                17..=32 => 14.0,
                _ => 20.0,
            },
            _ => 10.0, // Unknown, conservative estimate
        }
    }
}

/// Capability class for task routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityClass {
    /// High-end (datacenter, professional)
    High,
    /// Medium (good consumer GPU)
    Medium,
    /// Low (older GPU, low VRAM)
    Low,
    /// CPU only
    CpuOnly,
}

/// A node's compute capabilities
#[derive(Debug, Clone)]
pub struct NodeCapability {
    /// Node identity
    pub node_id: NodeId,
    /// Human-readable name
    pub name: String,
    /// GPU type classification
    pub gpu_type: GpuType,
    /// Estimated TFLOPS FP16 (tensor ops)
    pub compute_tflops: f32,
    /// GPU memory in GB
    pub vram_gb: u32,
    /// System memory in GB
    pub ram_gb: u32,
    /// Network bandwidth Mbps (measured or estimated)
    pub bandwidth_mbps: u32,
    /// Availability factor (0.0-1.0, avg hours online / 24)
    pub availability: f32,
    /// Trust level (affects task assignment priority)
    pub trust_level: TrustLevel,
    /// Last seen timestamp (seconds since epoch)
    pub last_seen: u64,
    /// Currently assigned tasks
    pub assigned_tasks: u32,
}

impl NodeCapability {
    /// Create capability from HAL discovery
    pub fn from_hal(
        node_id: NodeId,
        name: String,
        gpu_type: GpuType,
        vram_gb: u32,
        ram_gb: u32,
        bandwidth_mbps: u32,
    ) -> Self {
        let compute_tflops = gpu_type.estimate_tflops(vram_gb);

        Self {
            node_id,
            name,
            gpu_type,
            compute_tflops,
            vram_gb,
            ram_gb,
            bandwidth_mbps,
            availability: 0.5, // Default, updated over time
            trust_level: TrustLevel::Sig,
            last_seen: 0,
            assigned_tasks: 0,
        }
    }

    /// Get effective compute (TFLOPS * availability)
    pub fn effective_tflops(&self) -> f32 {
        self.compute_tflops * self.availability
    }

    /// Classify this node's capability tier
    pub fn classify(&self) -> CapabilityClass {
        if self.gpu_type == GpuType::CpuOnly {
            return CapabilityClass::CpuOnly;
        }

        match (self.compute_tflops as u32, self.vram_gb) {
            (t, v) if t >= 100 && v >= 40 => CapabilityClass::High,
            (t, v) if t >= 20 && v >= 8 => CapabilityClass::Medium,
            (t, v) if t >= 5 || v >= 4 => CapabilityClass::Low,
            _ => CapabilityClass::CpuOnly,
        }
    }

    /// Check if this node can handle a task with given requirements
    pub fn can_handle(&self, required_vram_gb: u32, required_tflops: f32) -> bool {
        self.vram_gb >= required_vram_gb && self.compute_tflops >= required_tflops
    }

    /// Update availability based on observation
    pub fn update_availability(&mut self, was_available: bool) {
        // Exponential moving average
        let alpha = 0.1;
        let sample = if was_available { 1.0 } else { 0.0 };
        self.availability = self.availability * (1.0 - alpha) + sample * alpha;
    }
}

/// Database of node capabilities across the mesh
#[cfg(feature = "std")]
pub struct CapabilityDatabase {
    /// Known nodes and their capabilities
    nodes: HashMap<NodeId, NodeCapability>,
    /// Total effective TFLOPS across all nodes
    total_tflops: f32,
    /// Total VRAM across all nodes
    total_vram_gb: u32,
}

#[cfg(feature = "std")]
impl CapabilityDatabase {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            total_tflops: 0.0,
            total_vram_gb: 0,
        }
    }

    /// Register or update a node's capabilities
    pub fn register(&mut self, cap: NodeCapability) {
        // Remove old contribution if exists
        if let Some(old) = self.nodes.get(&cap.node_id) {
            self.total_tflops -= old.effective_tflops();
            self.total_vram_gb -= old.vram_gb;
        }

        // Add new contribution
        self.total_tflops += cap.effective_tflops();
        self.total_vram_gb += cap.vram_gb;

        self.nodes.insert(cap.node_id, cap);
    }

    /// Remove a node
    pub fn remove(&mut self, node_id: &NodeId) -> Option<NodeCapability> {
        if let Some(cap) = self.nodes.remove(node_id) {
            self.total_tflops -= cap.effective_tflops();
            self.total_vram_gb -= cap.vram_gb;
            Some(cap)
        } else {
            None
        }
    }

    /// Get a node's capability
    pub fn get(&self, node_id: &NodeId) -> Option<&NodeCapability> {
        self.nodes.get(node_id)
    }

    /// Get mutable capability
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeCapability> {
        self.nodes.get_mut(node_id)
    }

    /// Total nodes in database
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total effective TFLOPS
    pub fn total_tflops(&self) -> f32 {
        self.total_tflops
    }

    /// Total VRAM in GB
    pub fn total_vram_gb(&self) -> u32 {
        self.total_vram_gb
    }

    /// Average TFLOPS per node
    pub fn avg_tflops(&self) -> f32 {
        if self.nodes.is_empty() {
            0.0
        } else {
            self.total_tflops / self.nodes.len() as f32
        }
    }

    /// Average VRAM per node
    pub fn avg_vram_gb(&self) -> u32 {
        if self.nodes.is_empty() {
            0
        } else {
            self.total_vram_gb / self.nodes.len() as u32
        }
    }

    /// Average availability
    pub fn avg_availability(&self) -> f32 {
        if self.nodes.is_empty() {
            0.0
        } else {
            self.nodes.values().map(|n| n.availability).sum::<f32>() / self.nodes.len() as f32
        }
    }

    /// Find nodes that can handle given requirements
    pub fn find_capable(&self, required_vram_gb: u32, required_tflops: f32) -> Vec<&NodeCapability> {
        self.nodes
            .values()
            .filter(|n| n.can_handle(required_vram_gb, required_tflops))
            .collect()
    }

    /// Find available nodes (seen recently, low task count)
    pub fn find_available(&self, max_tasks: u32, stale_threshold_secs: u64, now: u64) -> Vec<&NodeCapability> {
        self.nodes
            .values()
            .filter(|n| {
                n.assigned_tasks < max_tasks &&
                (now - n.last_seen) < stale_threshold_secs
            })
            .collect()
    }

    /// Iterate all nodes
    pub fn iter(&self) -> impl Iterator<Item = &NodeCapability> {
        self.nodes.values()
    }
}

#[cfg(feature = "std")]
impl Default for CapabilityDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(n: u8) -> NodeId {
        NodeId::from_bytes([n; 32])
    }

    #[test]
    fn test_gpu_tflops_estimate() {
        // RTX 3080 (10GB) should be around 25 TFLOPS
        let tflops = GpuType::NvidiaConsumer.estimate_tflops(10);
        assert!(tflops >= 20.0 && tflops <= 30.0);

        // A100 80GB should be high
        let tflops = GpuType::NvidiaDatacenter.estimate_tflops(80);
        assert!(tflops >= 500.0);

        // CPU only should be minimal
        let tflops = GpuType::CpuOnly.estimate_tflops(0);
        assert!(tflops < 2.0);
    }

    #[test]
    fn test_capability_classification() {
        let high = NodeCapability::from_hal(
            test_node_id(1),
            "A100".into(),
            GpuType::NvidiaDatacenter,
            80,
            256,
            10000,
        );
        assert_eq!(high.classify(), CapabilityClass::High);

        let medium = NodeCapability::from_hal(
            test_node_id(2),
            "RTX 3080".into(),
            GpuType::NvidiaConsumer,
            10,
            32,
            1000,
        );
        assert_eq!(medium.classify(), CapabilityClass::Medium);

        let cpu_only = NodeCapability::from_hal(
            test_node_id(3),
            "Server".into(),
            GpuType::CpuOnly,
            0,
            64,
            10000,
        );
        assert_eq!(cpu_only.classify(), CapabilityClass::CpuOnly);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_capability_database() {
        let mut db = CapabilityDatabase::new();

        let cap1 = NodeCapability::from_hal(
            test_node_id(1),
            "Desktop1".into(),
            GpuType::NvidiaConsumer,
            12,
            32,
            100,
        );
        let cap2 = NodeCapability::from_hal(
            test_node_id(2),
            "Desktop2".into(),
            GpuType::NvidiaConsumer,
            8,
            16,
            100,
        );

        db.register(cap1);
        db.register(cap2);

        assert_eq!(db.node_count(), 2);
        assert!(db.total_tflops() > 0.0);
        assert_eq!(db.total_vram_gb(), 20); // 12 + 8

        // Find capable
        let capable = db.find_capable(8, 10.0);
        assert!(!capable.is_empty());
    }
}
