//! Data Mover Capability - DMA and Zero-Copy Transfers
//!
//! For AI workloads, data movement is often the bottleneck.
//! Movers provide zero-copy, asynchronous data transfer between:
//! - Host ↔ Device (PCIe)
//! - Device ↔ Device (NVLink, Infinity Fabric)
//! - NUMA nodes

use alloc::vec::Vec;

/// A transfer path between two memory locations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferPath {
    /// Host to device (e.g., CPU → GPU over PCIe)
    HostToDevice,
    /// Device to host (e.g., GPU → CPU over PCIe)
    DeviceToHost,
    /// Within same device (on-chip)
    IntraDevice,
    /// Device to device (e.g., GPU → GPU over NVLink)
    DeviceToDevice {
        /// Source device ID
        src_device: u8,
        /// Destination device ID
        dst_device: u8,
    },
    /// NUMA node to node
    NumaToNuma {
        src_node: u8,
        dst_node: u8,
    },
    /// Network (via RDMA)
    Rdma,
}

impl TransferPath {
    /// Is this a cross-device transfer?
    pub fn is_cross_device(&self) -> bool {
        matches!(
            self,
            TransferPath::HostToDevice
                | TransferPath::DeviceToHost
                | TransferPath::DeviceToDevice { .. }
                | TransferPath::Rdma
        )
    }
}

/// State of a DMA transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Queued but not started
    Pending,
    /// Currently in progress
    InProgress,
    /// Completed successfully
    Complete,
    /// Failed with error
    Failed,
}

/// A DMA descriptor for a single transfer
#[derive(Debug, Clone)]
pub struct DmaDescriptor {
    /// Source address
    pub src_addr: u64,
    /// Destination address
    pub dst_addr: u64,
    /// Size in bytes
    pub size: u64,
    /// Transfer ID (for tracking)
    pub transfer_id: u64,
    /// Current state
    pub state: TransferState,
}

impl DmaDescriptor {
    /// Create a new DMA descriptor
    pub fn new(src: u64, dst: u64, size: u64) -> Self {
        // Generate transfer ID from addresses
        let hash = blake3::hash(&[
            &src.to_le_bytes()[..],
            &dst.to_le_bytes()[..],
            &size.to_le_bytes()[..],
        ].concat());
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&hash.as_bytes()[..8]);

        Self {
            src_addr: src,
            dst_addr: dst,
            size,
            transfer_id: u64::from_le_bytes(id_bytes),
            state: TransferState::Pending,
        }
    }
}

/// Data mover capability
#[derive(Debug, Clone)]
pub struct MoverCapability {
    /// Supported transfer paths
    pub paths: Vec<TransferPath>,
    /// Maximum transfer size (bytes)
    pub max_transfer_size: u64,
    /// Bandwidth in bytes/sec
    pub bandwidth: u64,
    /// Latency in nanoseconds (for small transfers)
    pub latency_ns: u64,
    /// Maximum concurrent transfers
    pub max_concurrent: u32,
    /// Minimum alignment requirement
    pub alignment: u64,
    /// Does this support scatter-gather?
    pub scatter_gather: bool,
    /// Does this support 2D/3D block copies?
    pub block_copy: bool,
}

impl MoverCapability {
    /// Create a new mover capability
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            max_transfer_size: u64::MAX,
            bandwidth: 0,
            latency_ns: 0,
            max_concurrent: 1,
            alignment: 4,
            scatter_gather: false,
            block_copy: false,
        }
    }

    /// Add a supported path
    pub fn with_path(mut self, path: TransferPath) -> Self {
        if !self.paths.contains(&path) {
            self.paths.push(path);
        }
        self
    }

    /// Set bandwidth
    pub fn with_bandwidth(mut self, bandwidth: u64) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    /// Set latency
    pub fn with_latency(mut self, latency_ns: u64) -> Self {
        self.latency_ns = latency_ns;
        self
    }

    /// Set max concurrent transfers
    pub fn with_max_concurrent(mut self, max: u32) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Enable scatter-gather
    pub fn with_scatter_gather(mut self) -> Self {
        self.scatter_gather = true;
        self
    }

    /// Enable block copy
    pub fn with_block_copy(mut self) -> Self {
        self.block_copy = true;
        self
    }

    /// Check if a path is supported
    pub fn supports_path(&self, path: &TransferPath) -> bool {
        self.paths.contains(path)
    }

    /// Estimate transfer time (seconds)
    pub fn estimate_time(&self, size: u64) -> f64 {
        if self.bandwidth == 0 {
            return f64::MAX;
        }
        let transfer_time = size as f64 / self.bandwidth as f64;
        let latency = self.latency_ns as f64 / 1e9;
        transfer_time + latency
    }

    /// Estimate throughput for a batch of transfers
    pub fn estimate_batch_throughput(&self, sizes: &[u64]) -> f64 {
        if sizes.is_empty() || self.bandwidth == 0 {
            return 0.0;
        }

        let total_bytes: u64 = sizes.iter().sum();
        let total_latency = (sizes.len() as f64) * (self.latency_ns as f64 / 1e9);

        // Account for concurrency
        let concurrent = self.max_concurrent.min(sizes.len() as u32) as f64;
        let effective_latency = total_latency / concurrent;

        let transfer_time = total_bytes as f64 / self.bandwidth as f64;
        total_bytes as f64 / (transfer_time + effective_latency)
    }
}

impl Default for MoverCapability {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for common mover configurations
pub struct MoverBuilder;

impl MoverBuilder {
    /// Create a PCIe mover (host ↔ device)
    pub fn pcie_gen4() -> MoverCapability {
        MoverCapability::new()
            .with_path(TransferPath::HostToDevice)
            .with_path(TransferPath::DeviceToHost)
            .with_bandwidth(32_000_000_000) // ~32 GB/s PCIe 4.0 x16
            .with_latency(1000) // ~1us
            .with_max_concurrent(8)
    }

    /// Create a PCIe Gen5 mover
    pub fn pcie_gen5() -> MoverCapability {
        MoverCapability::new()
            .with_path(TransferPath::HostToDevice)
            .with_path(TransferPath::DeviceToHost)
            .with_bandwidth(64_000_000_000) // ~64 GB/s PCIe 5.0 x16
            .with_latency(800) // Slightly lower latency
            .with_max_concurrent(16)
    }

    /// Create an NVLink mover (GPU ↔ GPU)
    pub fn nvlink4(src_device: u8, dst_device: u8) -> MoverCapability {
        MoverCapability::new()
            .with_path(TransferPath::DeviceToDevice { src_device, dst_device })
            .with_bandwidth(900_000_000_000) // ~900 GB/s NVLink 4.0
            .with_latency(500) // ~500ns
            .with_max_concurrent(32)
            .with_scatter_gather()
    }

    /// Create an intra-device mover (on-chip)
    pub fn on_chip() -> MoverCapability {
        MoverCapability::new()
            .with_path(TransferPath::IntraDevice)
            .with_bandwidth(4_000_000_000_000) // ~4 TB/s on-chip
            .with_latency(10) // ~10ns
            .with_max_concurrent(64)
            .with_scatter_gather()
            .with_block_copy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_path_properties() {
        assert!(TransferPath::HostToDevice.is_cross_device());
        assert!(!TransferPath::IntraDevice.is_cross_device());
    }

    #[test]
    fn test_dma_descriptor() {
        let desc = DmaDescriptor::new(0x1000, 0x2000, 4096);
        assert_eq!(desc.state, TransferState::Pending);
        assert_eq!(desc.size, 4096);
    }

    #[test]
    fn test_mover_capability() {
        let mover = MoverCapability::new()
            .with_path(TransferPath::HostToDevice)
            .with_bandwidth(32_000_000_000);

        assert!(mover.supports_path(&TransferPath::HostToDevice));
        assert!(!mover.supports_path(&TransferPath::DeviceToHost));
    }

    #[test]
    fn test_transfer_time_estimate() {
        let mover = MoverCapability::new()
            .with_bandwidth(32_000_000_000) // 32 GB/s
            .with_latency(1000); // 1us

        // 32GB at 32 GB/s = 1 second + 1us latency
        let time = mover.estimate_time(32_000_000_000);
        assert!((time - 1.000001).abs() < 0.001);
    }

    #[test]
    fn test_mover_builders() {
        let pcie4 = MoverBuilder::pcie_gen4();
        let pcie5 = MoverBuilder::pcie_gen5();
        let nvlink = MoverBuilder::nvlink4(0, 1);

        assert!(pcie5.bandwidth > pcie4.bandwidth);
        assert!(nvlink.bandwidth > pcie5.bandwidth);
    }
}
