//! Capability - What hardware CAN do
//!
//! A Capability describes what a piece of hardware is able to do,
//! expressed in terms AI understands (not device-specific quirks).

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::IntentHash;

/// Unique identifier for a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityId(pub [u8; 16]);

impl CapabilityId {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create from intent hash (capability as intent)
    pub fn from_intent(intent: IntentHash) -> Self {
        Self(*intent.as_bytes())
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// High-level capability class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CapabilityClass {
    /// Tensor/matrix computation (GPU, TPU, NPU)
    Compute = 0x01,
    /// Memory storage (HBM, GDDR, system RAM)
    Memory = 0x02,
    /// Data movement (DMA, copy engines)
    Mover = 0x03,
    /// Persistent storage (NVMe, etc)
    Storage = 0x04,
    /// Network (handled by AXIOM, but discoverable)
    Network = 0x05,
    /// Sensors (cameras, microphones - for multimodal)
    Sensor = 0x06,
    /// Custom/vendor-specific
    Custom = 0xFF,
}

impl CapabilityClass {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Compute),
            0x02 => Some(Self::Memory),
            0x03 => Some(Self::Mover),
            0x04 => Some(Self::Storage),
            0x05 => Some(Self::Network),
            0x06 => Some(Self::Sensor),
            0xFF => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Quantitative metrics for capability comparison
#[derive(Debug, Clone, Default)]
pub struct CapabilityMetrics {
    /// Throughput in operations per second (context-dependent)
    /// For compute: FLOPS, for memory: bytes/sec, for mover: bytes/sec
    pub throughput: u64,

    /// Latency in nanoseconds (typical operation)
    pub latency_ns: u64,

    /// Capacity (bytes for memory, queue depth for compute)
    pub capacity: u64,

    /// Power consumption in milliwatts (0 = unknown)
    pub power_mw: u32,

    /// Efficiency score (ops per watt, higher = better)
    pub efficiency: u32,
}

impl CapabilityMetrics {
    /// Create metrics for compute capability
    pub fn compute(tflops: f64, latency_us: u32) -> Self {
        Self {
            throughput: (tflops * 1e12) as u64,
            latency_ns: (latency_us as u64) * 1000,
            capacity: 0,
            power_mw: 0,
            efficiency: 0,
        }
    }

    /// Create metrics for memory capability
    pub fn memory(capacity_gb: u32, bandwidth_gbps: u32) -> Self {
        Self {
            throughput: (bandwidth_gbps as u64) * 1_000_000_000,
            latency_ns: 100, // Typical DRAM latency
            capacity: (capacity_gb as u64) * 1_000_000_000,
            power_mw: 0,
            efficiency: 0,
        }
    }

    /// Create metrics for data mover
    pub fn mover(bandwidth_gbps: u32, latency_ns: u64) -> Self {
        Self {
            throughput: (bandwidth_gbps as u64) * 1_000_000_000,
            latency_ns,
            capacity: 0,
            power_mw: 0,
            efficiency: 0,
        }
    }
}

/// A capability - what hardware can do
#[derive(Debug, Clone)]
pub struct Capability {
    /// Unique identifier
    pub id: CapabilityId,

    /// High-level class
    pub class: CapabilityClass,

    /// Semantic name (e.g., "compute:tensor:fp16")
    pub name: String,

    /// Detailed semantic tags for matching
    pub tags: Vec<String>,

    /// Quantitative metrics
    pub metrics: CapabilityMetrics,

    /// Specific capability data (class-dependent)
    pub specific: SpecificCapability,
}

/// Class-specific capability details
#[derive(Debug, Clone)]
pub enum SpecificCapability {
    /// Compute-specific details
    Compute(super::compute::ComputeCapability),
    /// Memory-specific details
    Memory(super::memory::MemoryCapability),
    /// Data mover details
    Mover(super::mover::MoverCapability),
    /// Generic (for Storage, Network, Sensor, Custom)
    Generic,
}

impl Capability {
    /// Create a new capability
    pub fn new(class: CapabilityClass, name: &str) -> Self {
        // Generate ID from name hash
        let hash = blake3::hash(name.as_bytes());
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);

        Self {
            id: CapabilityId(id_bytes),
            class,
            name: String::from(name),
            tags: Vec::new(),
            metrics: CapabilityMetrics::default(),
            specific: SpecificCapability::Generic,
        }
    }

    /// Add a semantic tag
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(String::from(tag));
        self
    }

    /// Set metrics
    pub fn with_metrics(mut self, metrics: CapabilityMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Set specific capability details
    pub fn with_specific(mut self, specific: SpecificCapability) -> Self {
        self.specific = specific;
        self
    }

    /// Check if capability matches a semantic query
    pub fn matches(&self, query: &str) -> bool {
        // Exact name match
        if self.name == query {
            return true;
        }

        // Prefix match (e.g., "compute" matches "compute:tensor:fp16")
        if self.name.starts_with(query) && self.name[query.len()..].starts_with(':') {
            return true;
        }

        // Tag match
        self.tags.iter().any(|t| t == query)
    }

    /// Check if capability satisfies minimum metrics
    pub fn satisfies_metrics(&self, min_throughput: u64, max_latency_ns: u64) -> bool {
        self.metrics.throughput >= min_throughput &&
        (max_latency_ns == 0 || self.metrics.latency_ns <= max_latency_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_matching() {
        let cap = Capability::new(CapabilityClass::Compute, "compute:tensor:fp16")
            .with_tag("gpu")
            .with_tag("nvidia");

        assert!(cap.matches("compute:tensor:fp16")); // Exact
        assert!(cap.matches("compute:tensor"));      // Prefix
        assert!(cap.matches("compute"));             // Prefix
        assert!(cap.matches("gpu"));                 // Tag
        assert!(!cap.matches("memory"));             // No match
    }

    #[test]
    fn test_capability_metrics() {
        let metrics = CapabilityMetrics::compute(100.0, 10); // 100 TFLOPS, 10us latency

        assert_eq!(metrics.throughput, 100_000_000_000_000); // 100 TFLOPS
        assert_eq!(metrics.latency_ns, 10_000); // 10us in ns
    }

    #[test]
    fn test_metrics_satisfaction() {
        let cap = Capability::new(CapabilityClass::Compute, "compute:tensor")
            .with_metrics(CapabilityMetrics::compute(50.0, 100));

        // 50 TFLOPS >= 10 TFLOPS, 100us <= 1000us
        assert!(cap.satisfies_metrics(10_000_000_000_000, 1_000_000));

        // 50 TFLOPS < 100 TFLOPS
        assert!(!cap.satisfies_metrics(100_000_000_000_000, 1_000_000));
    }
}
