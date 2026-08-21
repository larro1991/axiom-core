//! HDL-Lite Type Definitions
//!
//! Defines the structure of hardware descriptions.

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

/// Complete hardware description
#[derive(Debug, Clone)]
pub struct HardwareDescription {
    /// Device identification
    pub device: DeviceInfo,
    /// Memory-mapped regions
    pub memory_map: Vec<MemoryRegion>,
    /// Interrupt configuration
    pub interrupts: InterruptConfig,
    /// Initialization sequence
    pub init_sequence: Vec<Operation>,
    /// Named operations
    pub operations: HashMap<String, OperationDef>,
    /// Hardware quirks
    pub quirks: Vec<Quirk>,
}

/// Device identification
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Human-readable name
    pub name: String,
    /// PCI/USB vendor ID
    pub vendor_id: u16,
    /// PCI/USB device ID
    pub device_id: u16,
    /// Device class
    pub class: DeviceClass,
    /// Subsystem vendor (optional)
    pub subsystem_vendor: Option<u16>,
    /// Subsystem device (optional)
    pub subsystem_device: Option<u16>,
    /// Revision (optional)
    pub revision: Option<u8>,
}

/// Device classes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    /// Network interface card
    Network,
    /// Storage controller
    Storage,
    /// Graphics processor
    Gpu,
    /// USB host controller
    UsbHost,
    /// Audio device
    Audio,
    /// Serial port
    Serial,
    /// Generic/other
    Generic,
}

impl DeviceClass {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "network" | "nic" | "ethernet" => Some(Self::Network),
            "storage" | "disk" | "nvme" | "sata" => Some(Self::Storage),
            "gpu" | "graphics" | "display" => Some(Self::Gpu),
            "usb_host" | "usb" | "xhci" | "ehci" => Some(Self::UsbHost),
            "audio" | "sound" | "hda" => Some(Self::Audio),
            "serial" | "uart" | "tty" => Some(Self::Serial),
            _ => Some(Self::Generic),
        }
    }
}

/// Memory-mapped I/O region (BAR)
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Region name (e.g., "bar0")
    pub name: String,
    /// Size in bytes
    pub size: usize,
    /// Registers in this region
    pub registers: Vec<Register>,
}

/// Hardware register definition
#[derive(Debug, Clone)]
pub struct Register {
    /// Register name
    pub name: String,
    /// Byte offset within region
    pub offset: usize,
    /// Width in bits (8, 16, 32, 64)
    pub width: u8,
    /// Access type
    pub access: AccessType,
    /// Bit fields (optional)
    pub bits: Vec<BitField>,
    /// Array count (1 = single register)
    pub array_size: usize,
}

/// Register access type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// Read only
    ReadOnly,
    /// Write only
    WriteOnly,
    /// Read and write
    ReadWrite,
    /// Write 1 to clear
    WriteToClear,
    /// Write 1 to set
    WriteToSet,
}

impl AccessType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read_only" | "ro" | "r" => Some(Self::ReadOnly),
            "write_only" | "wo" | "w" => Some(Self::WriteOnly),
            "read_write" | "rw" => Some(Self::ReadWrite),
            "write_to_clear" | "w1c" => Some(Self::WriteToClear),
            "write_to_set" | "w1s" => Some(Self::WriteToSet),
            _ => None,
        }
    }
}

/// Bit field within a register
#[derive(Debug, Clone)]
pub struct BitField {
    /// Field name
    pub name: String,
    /// Bit position (0-63)
    pub bit: u8,
    /// Bit width (default 1)
    pub width: u8,
}

/// Interrupt configuration
#[derive(Debug, Clone)]
pub struct InterruptConfig {
    /// Interrupt type
    pub irq_type: InterruptType,
    /// Interrupt handlers
    pub handlers: Vec<InterruptHandler>,
}

/// Interrupt delivery mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// Legacy pin-based
    Legacy,
    /// Message Signaled Interrupts
    Msi,
    /// MSI-X (extended)
    MsiX,
    /// Polling (no interrupts)
    Polling,
}

/// Interrupt handler definition
#[derive(Debug, Clone)]
pub struct InterruptHandler {
    /// Interrupt mask to match
    pub mask: u32,
    /// Handler name
    pub name: String,
    /// Action to take
    pub action: IrqAction,
}

/// Actions that can be triggered by interrupts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrqAction {
    /// Signal that RX data is ready
    SignalRxReady,
    /// Signal that TX completed
    SignalTxDone,
    /// Signal an error occurred
    SignalError,
    /// Execute named operation
    Execute(String),
    /// Set a state variable
    SetState { name: String, value: u64 },
    /// Acknowledge and clear
    Acknowledge,
}

/// Single operation step
#[derive(Debug, Clone)]
pub enum Operation {
    /// Write value to register
    Write { register: String, value: Value },
    /// Read from register
    Read { register: String, into: Option<String> },
    /// Wait for specified milliseconds
    WaitMs(u32),
    /// Wait for specified microseconds
    WaitUs(u32),
    /// Poll register until condition met
    Poll {
        register: String,
        expected: u64,
        mask: u64,
        timeout_ms: u32,
    },
    /// Increment state variable
    Increment { variable: String, modulo: Option<u64> },
    /// Extract bits from value
    Extract {
        from: String,
        high_bit: u8,
        low_bit: u8,
        into: String,
    },
    /// Conditional operation
    If {
        condition: Condition,
        then_ops: Vec<Operation>,
        else_ops: Vec<Operation>,
    },
    /// Memory barrier
    Barrier(BarrierType),
    /// DMA operation
    DmaSetup {
        direction: DmaDirection,
        buffer: String,
        length: String,
    },
}

/// Value that can be written to registers
#[derive(Debug, Clone)]
pub enum Value {
    /// Literal constant
    Literal(u64),
    /// State variable
    Variable(String),
    /// Parameter from caller
    Parameter(usize),
    /// Register reference
    Register(String),
    /// Bitwise OR of values
    Or(Box<Value>, Box<Value>),
    /// Bitwise AND of values
    And(Box<Value>, Box<Value>),
    /// Left shift
    Shl(Box<Value>, u8),
    /// Right shift
    Shr(Box<Value>, u8),
}

/// Condition for if statements
#[derive(Debug, Clone)]
pub enum Condition {
    /// Compare equal
    Eq(Value, Value),
    /// Compare not equal
    Ne(Value, Value),
    /// Compare less than
    Lt(Value, Value),
    /// Compare greater than
    Gt(Value, Value),
    /// Bit is set
    BitSet(Value, u8),
    /// Bit is clear
    BitClear(Value, u8),
    /// AND of conditions
    And(Box<Condition>, Box<Condition>),
    /// OR of conditions
    Or(Box<Condition>, Box<Condition>),
}

/// Memory barrier types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierType {
    /// Read barrier
    Read,
    /// Write barrier
    Write,
    /// Full memory barrier
    Full,
}

/// DMA transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Device to host
    ToHost,
    /// Host to device
    ToDevice,
    /// Bidirectional
    Bidirectional,
}

/// Named operation definition
#[derive(Debug, Clone)]
pub struct OperationDef {
    /// Operation name
    pub name: String,
    /// Parameter names
    pub params: Vec<String>,
    /// Return value names
    pub returns: Vec<String>,
    /// Optional trigger (interrupt, timer, etc.)
    pub trigger: Option<Trigger>,
    /// Operation steps
    pub steps: Vec<Operation>,
}

/// What triggers an operation
#[derive(Debug, Clone)]
pub enum Trigger {
    /// Triggered by interrupt
    Interrupt(String),
    /// Triggered by timer
    Timer { interval_ms: u32 },
    /// Triggered by state change
    StateChange { variable: String },
}

/// Hardware quirk definition
#[derive(Debug, Clone)]
pub struct Quirk {
    /// Condition when quirk applies
    pub condition: QuirkCondition,
    /// Description/note
    pub note: String,
    /// Modifications to apply
    pub apply: Vec<QuirkApply>,
}

/// When a quirk should apply
#[derive(Debug, Clone)]
pub enum QuirkCondition {
    /// Revision less than value
    RevisionLt(u8),
    /// Revision greater than or equal
    RevisionGe(u8),
    /// Specific subsystem vendor
    SubsystemVendor(u16),
    /// Specific subsystem device
    SubsystemDevice(u16),
    /// AND of conditions
    And(Box<QuirkCondition>, Box<QuirkCondition>),
    /// OR of conditions
    Or(Box<QuirkCondition>, Box<QuirkCondition>),
    /// Always apply
    Always,
}

/// What modification a quirk applies
#[derive(Debug, Clone)]
pub enum QuirkApply {
    /// Insert operation after step
    InsertAfter { step_index: usize, operation: Operation },
    /// Insert operation before step
    InsertBefore { step_index: usize, operation: Operation },
    /// Replace step
    Replace { step_index: usize, operation: Operation },
    /// Modify register definition
    ModifyRegister { name: String, offset_delta: i32 },
    /// Modify interrupt mask
    ModifyInterruptMask { handler_index: usize, new_mask: u32 },
    /// Add extra delay
    AddDelay { after_step: usize, delay_ms: u32 },
}

/// Parse errors
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Invalid syntax
    Syntax { line: usize, message: String },
    /// Unknown keyword
    UnknownKeyword { line: usize, keyword: String },
    /// Missing required field
    MissingField { field: String },
    /// Invalid value
    InvalidValue { field: String, value: String },
    /// Duplicate definition
    Duplicate { name: String },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax { line, message } => write!(f, "Line {}: {}", line, message),
            Self::UnknownKeyword { line, keyword } => {
                write!(f, "Line {}: Unknown keyword '{}'", line, keyword)
            }
            Self::MissingField { field } => write!(f, "Missing required field: {}", field),
            Self::InvalidValue { field, value } => {
                write!(f, "Invalid value for {}: {}", field, value)
            }
            Self::Duplicate { name } => write!(f, "Duplicate definition: {}", name),
        }
    }
}

/// Runtime errors
#[derive(Debug, Clone)]
pub enum DriverError {
    /// Device not found
    DeviceNotFound,
    /// Initialization failed
    InitFailed(String),
    /// Operation failed
    OperationFailed { op: String, reason: String },
    /// Timeout
    Timeout { operation: String },
    /// Invalid parameter
    InvalidParameter { name: String },
    /// Hardware error
    HardwareError { code: u32 },
    /// Not supported by this device
    NotSupported,
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "Device not found"),
            Self::InitFailed(msg) => write!(f, "Initialization failed: {}", msg),
            Self::OperationFailed { op, reason } => {
                write!(f, "Operation '{}' failed: {}", op, reason)
            }
            Self::Timeout { operation } => write!(f, "Timeout during: {}", operation),
            Self::InvalidParameter { name } => write!(f, "Invalid parameter: {}", name),
            Self::HardwareError { code } => write!(f, "Hardware error: 0x{:08x}", code),
            Self::NotSupported => write!(f, "Operation not supported"),
        }
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_class_from_str() {
        assert_eq!(DeviceClass::from_str("network"), Some(DeviceClass::Network));
        assert_eq!(DeviceClass::from_str("NIC"), Some(DeviceClass::Network));
        assert_eq!(DeviceClass::from_str("gpu"), Some(DeviceClass::Gpu));
        assert_eq!(DeviceClass::from_str("storage"), Some(DeviceClass::Storage));
        assert_eq!(DeviceClass::from_str("unknown"), Some(DeviceClass::Generic));
    }

    #[test]
    fn test_access_type_from_str() {
        assert_eq!(AccessType::from_str("read_only"), Some(AccessType::ReadOnly));
        assert_eq!(AccessType::from_str("RW"), Some(AccessType::ReadWrite));
        assert_eq!(AccessType::from_str("W1C"), Some(AccessType::WriteToClear));
    }

    #[test]
    fn test_parse_error_display() {
        let err = ParseError::Syntax {
            line: 42,
            message: "unexpected token".into(),
        };
        assert!(err.to_string().contains("42"));
        assert!(err.to_string().contains("unexpected token"));
    }

    #[test]
    fn test_driver_error_display() {
        let err = DriverError::Timeout {
            operation: "init".into(),
        };
        assert!(err.to_string().contains("Timeout"));
        assert!(err.to_string().contains("init"));
    }
}
