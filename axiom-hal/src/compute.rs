//! Compute Capability - Tensor/Matrix Acceleration
//!
//! Describes what a compute resource can do:
//! - Supported data types (FP16, BF16, FP32, INT8, etc.)
//! - Supported operations (MatMul, Conv, Attention, etc.)
//! - Quantitative performance metrics

use alloc::vec::Vec;

/// Type of compute accelerator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ComputeType {
    /// General-purpose GPU (CUDA, ROCm)
    Gpu = 0x01,
    /// Tensor Processing Unit (Google TPU)
    Tpu = 0x02,
    /// Neural Processing Unit (specialized inference)
    Npu = 0x03,
    /// CPU SIMD (AVX, NEON)
    CpuSimd = 0x04,
    /// FPGA-based accelerator
    Fpga = 0x05,
    /// Custom ASIC
    Asic = 0x06,
}

/// Data type for tensor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DataType {
    /// 32-bit floating point
    Fp32 = 0x01,
    /// 16-bit floating point (IEEE)
    Fp16 = 0x02,
    /// Brain floating point (truncated FP32)
    Bf16 = 0x03,
    /// 8-bit floating point (E4M3 or E5M2)
    Fp8 = 0x04,
    /// 8-bit integer (signed)
    Int8 = 0x10,
    /// 4-bit integer (quantized)
    Int4 = 0x11,
    /// 32-bit integer
    Int32 = 0x12,
    /// 64-bit floating point
    Fp64 = 0x20,
}

impl DataType {
    /// Size in bits
    pub fn bits(&self) -> u32 {
        match self {
            DataType::Fp64 => 64,
            DataType::Fp32 | DataType::Int32 => 32,
            DataType::Fp16 | DataType::Bf16 => 16,
            DataType::Fp8 | DataType::Int8 => 8,
            DataType::Int4 => 4,
        }
    }

    /// Size in bytes (rounded up)
    pub fn bytes(&self) -> u32 {
        (self.bits() + 7) / 8
    }
}

/// Tensor operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TensorOp {
    /// Matrix multiplication (GEMM)
    MatMul = 0x01,
    /// Convolution (2D)
    Conv2d = 0x02,
    /// Attention mechanism (scaled dot-product)
    Attention = 0x03,
    /// Element-wise operations
    Elementwise = 0x04,
    /// Reduction operations (sum, max, mean)
    Reduce = 0x05,
    /// Batch normalization
    BatchNorm = 0x06,
    /// Layer normalization
    LayerNorm = 0x07,
    /// Softmax
    Softmax = 0x08,
    /// Activation functions (ReLU, GELU, etc.)
    Activation = 0x09,
    /// Embedding lookup
    Embedding = 0x0A,
    /// Flash attention (fused)
    FlashAttention = 0x0B,
}

/// Performance for a specific operation/dtype combination
#[derive(Debug, Clone, Copy)]
pub struct OpPerformance {
    /// Operation type
    pub op: TensorOp,
    /// Data type
    pub dtype: DataType,
    /// Peak throughput in TFLOPS (or TOPS for INT8)
    pub peak_tflops: f32,
    /// Typical utilization (0.0 - 1.0)
    pub typical_util: f32,
}

/// Compute-specific capability details
#[derive(Debug, Clone)]
pub struct ComputeCapability {
    /// Type of accelerator
    pub compute_type: ComputeType,
    /// Supported data types
    pub supported_dtypes: Vec<DataType>,
    /// Supported operations with performance
    pub operations: Vec<OpPerformance>,
    /// Total memory on device (bytes)
    pub memory_bytes: u64,
    /// Memory bandwidth (bytes/sec)
    pub memory_bandwidth: u64,
    /// Number of compute units (SMs, TPU cores, etc.)
    pub compute_units: u32,
    /// Max batch size supported
    pub max_batch_size: u32,
    /// Max sequence length (for transformers)
    pub max_seq_len: u32,
}

impl ComputeCapability {
    /// Create a new compute capability
    pub fn new(compute_type: ComputeType) -> Self {
        Self {
            compute_type,
            supported_dtypes: Vec::new(),
            operations: Vec::new(),
            memory_bytes: 0,
            memory_bandwidth: 0,
            compute_units: 0,
            max_batch_size: 0,
            max_seq_len: 0,
        }
    }

    /// Add supported data type
    pub fn with_dtype(mut self, dtype: DataType) -> Self {
        if !self.supported_dtypes.contains(&dtype) {
            self.supported_dtypes.push(dtype);
        }
        self
    }

    /// Add operation performance
    pub fn with_op(mut self, op: TensorOp, dtype: DataType, peak_tflops: f32) -> Self {
        self.operations.push(OpPerformance {
            op,
            dtype,
            peak_tflops,
            typical_util: 0.7, // Default 70% utilization
        });
        self
    }

    /// Set memory specs
    pub fn with_memory(mut self, bytes: u64, bandwidth: u64) -> Self {
        self.memory_bytes = bytes;
        self.memory_bandwidth = bandwidth;
        self
    }

    /// Set compute units
    pub fn with_compute_units(mut self, units: u32) -> Self {
        self.compute_units = units;
        self
    }

    /// Check if operation/dtype combination is supported
    pub fn supports(&self, op: TensorOp, dtype: DataType) -> bool {
        self.operations.iter().any(|p| p.op == op && p.dtype == dtype)
    }

    /// Get peak performance for operation/dtype
    pub fn peak_tflops(&self, op: TensorOp, dtype: DataType) -> Option<f32> {
        self.operations
            .iter()
            .find(|p| p.op == op && p.dtype == dtype)
            .map(|p| p.peak_tflops)
    }

    /// Get expected performance (peak * utilization)
    pub fn expected_tflops(&self, op: TensorOp, dtype: DataType) -> Option<f32> {
        self.operations
            .iter()
            .find(|p| p.op == op && p.dtype == dtype)
            .map(|p| p.peak_tflops * p.typical_util)
    }

    /// Estimate time to complete a matmul (seconds)
    pub fn estimate_matmul_time(&self, m: u64, n: u64, k: u64, dtype: DataType) -> Option<f64> {
        let tflops = self.expected_tflops(TensorOp::MatMul, dtype)?;

        // FLOPs for matmul: 2 * M * N * K
        let flops = 2.0 * (m as f64) * (n as f64) * (k as f64);

        // Time = FLOPs / (TFLOPS * 1e12)
        Some(flops / (tflops as f64 * 1e12))
    }
}

/// Builder for common GPU configurations
pub struct GpuBuilder;

impl GpuBuilder {
    /// Create an NVIDIA-like GPU capability
    pub fn nvidia_like(name: &str, sm_count: u32, memory_gb: u32) -> ComputeCapability {
        // Rough estimates for a modern NVIDIA GPU
        let fp16_tflops = (sm_count as f32) * 0.5; // ~0.5 TFLOPS per SM at FP16
        let fp32_tflops = fp16_tflops / 2.0;
        let int8_tops = fp16_tflops * 2.0;

        ComputeCapability::new(ComputeType::Gpu)
            .with_dtype(DataType::Fp32)
            .with_dtype(DataType::Fp16)
            .with_dtype(DataType::Bf16)
            .with_dtype(DataType::Int8)
            .with_op(TensorOp::MatMul, DataType::Fp16, fp16_tflops)
            .with_op(TensorOp::MatMul, DataType::Fp32, fp32_tflops)
            .with_op(TensorOp::Attention, DataType::Fp16, fp16_tflops * 0.8)
            .with_op(TensorOp::FlashAttention, DataType::Fp16, fp16_tflops * 0.9)
            .with_memory(
                (memory_gb as u64) * 1_000_000_000,
                900_000_000_000, // ~900 GB/s HBM
            )
            .with_compute_units(sm_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtype_sizes() {
        assert_eq!(DataType::Fp32.bits(), 32);
        assert_eq!(DataType::Fp16.bits(), 16);
        assert_eq!(DataType::Int4.bits(), 4);
        assert_eq!(DataType::Int4.bytes(), 1); // Rounded up
    }

    #[test]
    fn test_compute_capability() {
        let cap = ComputeCapability::new(ComputeType::Gpu)
            .with_dtype(DataType::Fp16)
            .with_op(TensorOp::MatMul, DataType::Fp16, 100.0)
            .with_memory(16_000_000_000, 900_000_000_000);

        assert!(cap.supports(TensorOp::MatMul, DataType::Fp16));
        assert!(!cap.supports(TensorOp::MatMul, DataType::Fp32));
        assert_eq!(cap.peak_tflops(TensorOp::MatMul, DataType::Fp16), Some(100.0));
    }

    #[test]
    fn test_matmul_estimate() {
        let cap = ComputeCapability::new(ComputeType::Gpu)
            .with_op(TensorOp::MatMul, DataType::Fp16, 100.0); // 100 TFLOPS

        // 1024x1024x1024 matmul = 2 * 1024^3 = 2B FLOPs
        // At 70 TFLOPS effective = 2e9 / 70e12 = ~28.5 microseconds
        let time = cap.estimate_matmul_time(1024, 1024, 1024, DataType::Fp16).unwrap();
        assert!(time > 0.00001 && time < 0.001); // Between 10us and 1ms
    }

    #[test]
    fn test_gpu_builder() {
        let gpu = GpuBuilder::nvidia_like("H100", 132, 80);

        assert_eq!(gpu.compute_type, ComputeType::Gpu);
        assert_eq!(gpu.compute_units, 132);
        assert!(gpu.supports(TensorOp::FlashAttention, DataType::Fp16));
    }
}
