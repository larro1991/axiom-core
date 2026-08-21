//! Payload type definitions

use alloc::vec::Vec;

/// Payload type identifier (4 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadType {
    /// Arbitrary bytes
    Raw = 0x0,
    /// Numeric array with shape
    Tensor = 0x1,
    /// Vector embedding
    Embed = 0x2,
    /// Diff against shared state
    Delta = 0x3,
    /// Intent descriptor
    IntentDesc = 0x4,
    /// Causal dependency graph
    Graph = 0x5,
    /// Encapsulated legacy protocol
    Legacy = 0x6,
    /// Reference to shared dictionary
    DictRef = 0x7,
    /// Key-value map
    Kv = 0x8,
    /// Error details
    Error = 0x9,
    /// Trust negotiation data
    Trust = 0xA,
    /// Routing information
    Route = 0xB,
    /// Flow control data
    Flow = 0xC,
    /// Reserved/unknown
    Reserved(u8),
}

impl PayloadType {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x0 => Self::Raw,
            0x1 => Self::Tensor,
            0x2 => Self::Embed,
            0x3 => Self::Delta,
            0x4 => Self::IntentDesc,
            0x5 => Self::Graph,
            0x6 => Self::Legacy,
            0x7 => Self::DictRef,
            0x8 => Self::Kv,
            0x9 => Self::Error,
            0xA => Self::Trust,
            0xB => Self::Route,
            0xC => Self::Flow,
            v => Self::Reserved(v),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Raw => 0x0,
            Self::Tensor => 0x1,
            Self::Embed => 0x2,
            Self::Delta => 0x3,
            Self::IntentDesc => 0x4,
            Self::Graph => 0x5,
            Self::Legacy => 0x6,
            Self::DictRef => 0x7,
            Self::Kv => 0x8,
            Self::Error => 0x9,
            Self::Trust => 0xA,
            Self::Route => 0xB,
            Self::Flow => 0xC,
            Self::Reserved(v) => v,
        }
    }
}

impl Default for PayloadType {
    fn default() -> Self {
        Self::Raw
    }
}

/// Numeric data types for tensors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DType {
    /// 16-bit float (IEEE 754)
    F16 = 0x00,
    /// 32-bit float (IEEE 754)
    F32 = 0x01,
    /// 64-bit float (IEEE 754)
    F64 = 0x02,
    /// Brain float 16
    BF16 = 0x03,
    /// Signed 8-bit integer
    I8 = 0x04,
    /// Signed 16-bit integer
    I16 = 0x05,
    /// Signed 32-bit integer
    I32 = 0x06,
    /// Signed 64-bit integer
    I64 = 0x07,
    /// Unsigned 8-bit integer
    U8 = 0x08,
    /// Unsigned 16-bit integer
    U16 = 0x09,
    /// Unsigned 32-bit integer
    U32 = 0x0A,
    /// Unsigned 64-bit integer
    U64 = 0x0B,
    /// Boolean (1 byte)
    Bool = 0x0C,
    /// Complex 64 (two f32)
    Complex64 = 0x0D,
    /// Complex 128 (two f64)
    Complex128 = 0x0E,
}

impl DType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::F16),
            0x01 => Some(Self::F32),
            0x02 => Some(Self::F64),
            0x03 => Some(Self::BF16),
            0x04 => Some(Self::I8),
            0x05 => Some(Self::I16),
            0x06 => Some(Self::I32),
            0x07 => Some(Self::I64),
            0x08 => Some(Self::U8),
            0x09 => Some(Self::U16),
            0x0A => Some(Self::U32),
            0x0B => Some(Self::U64),
            0x0C => Some(Self::Bool),
            0x0D => Some(Self::Complex64),
            0x0E => Some(Self::Complex128),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Size of one element in bytes
    pub fn element_size(self) -> usize {
        match self {
            Self::F16 | Self::BF16 | Self::I16 | Self::U16 => 2,
            Self::F32 | Self::I32 | Self::U32 => 4,
            Self::F64 | Self::I64 | Self::U64 | Self::Complex64 => 8,
            Self::I8 | Self::U8 | Self::Bool => 1,
            Self::Complex128 => 16,
        }
    }

    /// Check if this is a floating-point type
    pub fn is_float(self) -> bool {
        matches!(self, Self::F16 | Self::F32 | Self::F64 | Self::BF16)
    }

    /// Check if this is a signed integer type
    pub fn is_signed_int(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }

    /// Check if this is an unsigned integer type
    pub fn is_unsigned_int(self) -> bool {
        matches!(self, Self::U8 | Self::U16 | Self::U32 | Self::U64)
    }
}

impl Default for DType {
    fn default() -> Self {
        Self::F32
    }
}

/// Tensor payload structure
#[derive(Debug, Clone, PartialEq)]
pub struct TensorPayload {
    /// Number of dimensions (1-8)
    pub ndim: u8,
    /// Data type
    pub dtype: DType,
    /// Shape (dimension sizes)
    pub shape: Vec<u32>,
    /// Raw tensor data
    pub data: Vec<u8>,
}

impl TensorPayload {
    /// Create a new tensor payload
    pub fn new(dtype: DType, shape: Vec<u32>, data: Vec<u8>) -> Self {
        debug_assert!(shape.len() <= 8, "ndim must be <= 8");
        Self {
            ndim: shape.len() as u8,
            dtype,
            shape,
            data,
        }
    }

    /// Calculate expected data size from shape and dtype
    pub fn expected_data_size(&self) -> usize {
        let elements: usize = self.shape.iter().map(|&d| d as usize).product();
        elements * self.dtype.element_size()
    }

    /// Validate that data size matches shape and dtype
    pub fn is_valid(&self) -> bool {
        self.data.len() == self.expected_data_size()
    }

    /// Total number of elements
    pub fn num_elements(&self) -> usize {
        self.shape.iter().map(|&d| d as usize).product()
    }

    /// Create a 1D tensor (vector)
    pub fn vector(dtype: DType, data: Vec<u8>) -> Self {
        let elements = data.len() / dtype.element_size();
        Self {
            ndim: 1,
            dtype,
            shape: alloc::vec![elements as u32],
            data,
        }
    }

    /// Create a 2D tensor (matrix)
    pub fn matrix(dtype: DType, rows: u32, cols: u32, data: Vec<u8>) -> Self {
        Self {
            ndim: 2,
            dtype,
            shape: alloc::vec![rows, cols],
            data,
        }
    }
}

/// Embedding payload (specialized tensor)
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingPayload {
    /// Embedding dimension
    pub dim: u16,
    /// Data type (usually f16 or f32)
    pub dtype: DType,
    /// Optional hash of source model
    pub model_hash: u64,
    /// Raw embedding data
    pub data: Vec<u8>,
}

impl EmbeddingPayload {
    /// Create a new embedding
    pub fn new(dim: u16, dtype: DType, data: Vec<u8>) -> Self {
        Self {
            dim,
            dtype,
            model_hash: 0,
            data,
        }
    }

    /// Set the model hash
    pub fn with_model_hash(mut self, hash: u64) -> Self {
        self.model_hash = hash;
        self
    }

    /// Validate data size
    pub fn is_valid(&self) -> bool {
        self.data.len() == (self.dim as usize) * self.dtype.element_size()
    }
}

/// Legacy protocol codes for bridging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LegacyProtocol {
    TcpRaw = 0x00,
    Http1 = 0x01,
    Http2 = 0x02,
    Grpc = 0x03,
    WebSocket = 0x04,
    Mqtt = 0x05,
    Amqp = 0x06,
}

impl LegacyProtocol {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::TcpRaw),
            0x01 => Some(Self::Http1),
            0x02 => Some(Self::Http2),
            0x03 => Some(Self::Grpc),
            0x04 => Some(Self::WebSocket),
            0x05 => Some(Self::Mqtt),
            0x06 => Some(Self::Amqp),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Delta encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeltaEncoding {
    /// Simple XOR diff
    Xor = 0x00,
    /// Sparse update (index + value pairs)
    Sparse = 0x01,
    /// Quantized delta
    Quantized = 0x02,
    /// Application-defined
    Custom = 0x03,
}

impl DeltaEncoding {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Xor),
            0x01 => Some(Self::Sparse),
            0x02 => Some(Self::Quantized),
            0x03 => Some(Self::Custom),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtype_sizes() {
        assert_eq!(DType::F16.element_size(), 2);
        assert_eq!(DType::F32.element_size(), 4);
        assert_eq!(DType::F64.element_size(), 8);
        assert_eq!(DType::I8.element_size(), 1);
        assert_eq!(DType::Complex128.element_size(), 16);
    }

    #[test]
    fn test_tensor_validation() {
        let tensor = TensorPayload::new(
            DType::F32,
            alloc::vec![2, 3],
            alloc::vec![0u8; 24], // 2*3*4 = 24 bytes
        );
        assert!(tensor.is_valid());
        assert_eq!(tensor.num_elements(), 6);

        let invalid = TensorPayload::new(DType::F32, alloc::vec![2, 3], alloc::vec![0u8; 20]);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_embedding() {
        let embed = EmbeddingPayload::new(
            1024,
            DType::F16,
            alloc::vec![0u8; 2048], // 1024 * 2 = 2048 bytes
        );
        assert!(embed.is_valid());

        let embed_with_hash = embed.with_model_hash(0x1234567890ABCDEF);
        assert_eq!(embed_with_hash.model_hash, 0x1234567890ABCDEF);
    }

    #[test]
    fn test_payload_type_roundtrip() {
        for i in 0..=0x0C {
            let pt = PayloadType::from_u8(i);
            assert_eq!(pt.to_u8(), i);
        }
    }
}
