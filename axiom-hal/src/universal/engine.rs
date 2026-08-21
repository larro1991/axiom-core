//! Universal Driver Engine
//!
//! Executes hardware operations based on HDL descriptions.
//! This is the runtime that interprets HDL and talks to hardware.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use hashbrown::HashMap;

use super::types::*;
use super::parser::HdlParser;

/// Universal Driver - executes HDL descriptions
pub struct UniversalDriver {
    /// Parsed hardware description
    description: HardwareDescription,
    /// State variables
    state: HashMap<String, u64>,
    /// Register cache (for simulation/testing)
    register_cache: HashMap<String, u64>,
    /// Initialization complete flag
    initialized: bool,
    /// Statistics
    stats: DriverStats,
    /// MMIO accessor (abstracted for portability)
    mmio: Option<MmioWrapper>,
}

/// Driver statistics
#[derive(Debug, Default, Clone)]
pub struct DriverStats {
    /// Number of register reads
    pub reads: u64,
    /// Number of register writes
    pub writes: u64,
    /// Number of interrupts handled
    pub interrupts: u64,
    /// Number of operations executed
    pub operations: u64,
    /// Number of errors
    pub errors: u64,
}

/// MMIO accessor trait (implement for actual hardware)
pub trait MmioAccessor: Send + Sync {
    fn read8(&self, offset: usize) -> u8;
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;

    fn write8(&mut self, offset: usize, value: u8);
    fn write16(&mut self, offset: usize, value: u16);
    fn write32(&mut self, offset: usize, value: u32);
    fn write64(&mut self, offset: usize, value: u64);
}

/// Simulated MMIO for testing
#[derive(Debug, Default)]
pub struct SimulatedMmio {
    memory: HashMap<usize, u64>,
}

impl MmioAccessor for SimulatedMmio {
    fn read8(&self, offset: usize) -> u8 {
        (self.memory.get(&offset).copied().unwrap_or(0) & 0xFF) as u8
    }
    fn read16(&self, offset: usize) -> u16 {
        (self.memory.get(&offset).copied().unwrap_or(0) & 0xFFFF) as u16
    }
    fn read32(&self, offset: usize) -> u32 {
        (self.memory.get(&offset).copied().unwrap_or(0) & 0xFFFF_FFFF) as u32
    }
    fn read64(&self, offset: usize) -> u64 {
        self.memory.get(&offset).copied().unwrap_or(0)
    }

    fn write8(&mut self, offset: usize, value: u8) {
        self.memory.insert(offset, value as u64);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.memory.insert(offset, value as u64);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.memory.insert(offset, value as u64);
    }
    fn write64(&mut self, offset: usize, value: u64) {
        self.memory.insert(offset, value);
    }
}

impl UniversalDriver {
    /// Create driver from HDL text
    pub fn from_hdl(hdl: &str) -> Result<Self, ParseError> {
        let parser = HdlParser::new();
        let description = parser.parse(hdl)?;
        Ok(Self::from_description(description))
    }

    /// Create driver from parsed description
    pub fn from_description(description: HardwareDescription) -> Self {
        Self {
            description,
            state: HashMap::new(),
            register_cache: HashMap::new(),
            initialized: false,
            stats: DriverStats::default(),
            mmio: None,
        }
    }

    /// Attach MMIO accessor for real hardware
    pub fn attach_mmio(&mut self, mmio: Box<dyn MmioAccessor>) {
        self.mmio = Some(MmioWrapper(mmio));
    }

    /// Get device info
    pub fn device_info(&self) -> &DeviceInfo {
        &self.description.device
    }

    /// Get statistics
    pub fn stats(&self) -> &DriverStats {
        &self.stats
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Run initialization sequence
    pub fn initialize(&mut self) -> Result<(), DriverError> {
        if self.initialized {
            return Ok(());
        }

        // Apply quirks to init sequence if needed
        let init_ops = self.apply_quirks_to_sequence(
            self.description.init_sequence.clone()
        );

        // Execute init sequence
        for op in &init_ops {
            self.execute_operation(op)?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Execute a named operation
    pub fn execute(&mut self, op_name: &str, params: &[u64]) -> Result<Vec<u64>, DriverError> {
        let op_def = self.description.operations.get(op_name)
            .ok_or_else(|| DriverError::OperationFailed {
                op: op_name.into(),
                reason: "Unknown operation".into(),
            })?
            .clone();

        // Set up parameters
        for (i, value) in params.iter().enumerate() {
            self.state.insert(format!("$param{}", i), *value);
        }

        // Execute steps
        for step in &op_def.steps {
            self.execute_operation(step)?;
        }

        // Collect returns
        let returns: Vec<u64> = op_def.returns.iter()
            .filter_map(|name| self.state.get(name).copied())
            .collect();

        self.stats.operations += 1;
        Ok(returns)
    }

    /// Handle an interrupt
    pub fn handle_interrupt(&mut self, irq_status: u32) -> Vec<IrqAction> {
        self.stats.interrupts += 1;
        let mut actions = Vec::new();

        for handler in &self.description.interrupts.handlers {
            if irq_status & handler.mask != 0 {
                actions.push(handler.action.clone());
            }
        }

        actions
    }

    /// Execute a single operation
    fn execute_operation(&mut self, op: &Operation) -> Result<(), DriverError> {
        match op {
            Operation::Write { register, value } => {
                let val = self.evaluate_value(value)?;
                self.write_register(register, val)?;
            }
            Operation::Read { register, into } => {
                let val = self.read_register(register)?;
                if let Some(var) = into {
                    self.state.insert(var.clone(), val);
                }
            }
            Operation::WaitMs(ms) => {
                // In real implementation, this would sleep
                // For now, just track that we would wait
                let _ = ms;
            }
            Operation::WaitUs(us) => {
                let _ = us;
            }
            Operation::Poll { register, expected, mask, timeout_ms } => {
                // Simulate polling
                let mut attempts = 0;
                let max_attempts = (*timeout_ms / 10).max(1);

                loop {
                    let val = self.read_register(register)?;
                    if (val & mask) == (*expected & mask) {
                        break;
                    }
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(DriverError::Timeout {
                            operation: format!("poll {}", register),
                        });
                    }
                    // Would sleep here in real implementation
                }
            }
            Operation::Increment { variable, modulo } => {
                let current = self.state.get(variable).copied().unwrap_or(0);
                let next = if let Some(m) = modulo {
                    (current + 1) % m
                } else {
                    current + 1
                };
                self.state.insert(variable.clone(), next);
            }
            Operation::Extract { from, high_bit, low_bit, into } => {
                let val = self.state.get(from).copied().unwrap_or(0);
                let width = high_bit - low_bit + 1;
                let mask = (1u64 << width) - 1;
                let extracted = (val >> low_bit) & mask;
                self.state.insert(into.clone(), extracted);
            }
            Operation::If { condition, then_ops, else_ops } => {
                if self.evaluate_condition(condition)? {
                    for op in then_ops {
                        self.execute_operation(op)?;
                    }
                } else {
                    for op in else_ops {
                        self.execute_operation(op)?;
                    }
                }
            }
            Operation::Barrier(_) => {
                // Memory barrier - no-op in simulation
            }
            Operation::DmaSetup { direction: _, buffer: _, length: _ } => {
                // DMA setup - would configure DMA in real implementation
            }
        }
        Ok(())
    }

    /// Evaluate a value expression
    fn evaluate_value(&mut self, value: &Value) -> Result<u64, DriverError> {
        match value {
            Value::Literal(n) => Ok(*n),
            Value::Variable(name) => self.state.get(name).copied().ok_or_else(|| {
                DriverError::InvalidParameter { name: name.clone() }
            }),
            Value::Parameter(idx) => {
                let param_name = format!("$param{}", idx);
                self.state.get(&param_name).copied().ok_or_else(|| {
                    DriverError::InvalidParameter { name: param_name }
                })
            }
            Value::Register(name) => self.read_register(name),
            Value::Or(a, b) => Ok(self.evaluate_value(a)? | self.evaluate_value(b)?),
            Value::And(a, b) => Ok(self.evaluate_value(a)? & self.evaluate_value(b)?),
            Value::Shl(v, n) => Ok(self.evaluate_value(v)? << n),
            Value::Shr(v, n) => Ok(self.evaluate_value(v)? >> n),
        }
    }

    /// Evaluate a condition
    fn evaluate_condition(&mut self, cond: &Condition) -> Result<bool, DriverError> {
        match cond {
            Condition::Eq(a, b) => Ok(self.evaluate_value(a)? == self.evaluate_value(b)?),
            Condition::Ne(a, b) => Ok(self.evaluate_value(a)? != self.evaluate_value(b)?),
            Condition::Lt(a, b) => Ok(self.evaluate_value(a)? < self.evaluate_value(b)?),
            Condition::Gt(a, b) => Ok(self.evaluate_value(a)? > self.evaluate_value(b)?),
            Condition::BitSet(v, bit) => Ok((self.evaluate_value(v)? >> bit) & 1 == 1),
            Condition::BitClear(v, bit) => Ok((self.evaluate_value(v)? >> bit) & 1 == 0),
            Condition::And(a, b) => Ok(self.evaluate_condition(a)? && self.evaluate_condition(b)?),
            Condition::Or(a, b) => Ok(self.evaluate_condition(a)? || self.evaluate_condition(b)?),
        }
    }

    /// Read from a register
    fn read_register(&mut self, name: &str) -> Result<u64, DriverError> {
        self.stats.reads += 1;

        // Find register definition
        let (reg, _region) = self.find_register(name)?;

        // Use MMIO if available, otherwise use cache
        let value = if let Some(ref mmio) = self.mmio {
            match reg.width {
                8 => mmio.read8(reg.offset) as u64,
                16 => mmio.read16(reg.offset) as u64,
                32 => mmio.read32(reg.offset) as u64,
                64 => mmio.read64(reg.offset),
                _ => self.register_cache.get(name).copied().unwrap_or(0),
            }
        } else {
            self.register_cache.get(name).copied().unwrap_or(0)
        };

        Ok(value)
    }

    /// Write to a register
    fn write_register(&mut self, name: &str, value: u64) -> Result<(), DriverError> {
        self.stats.writes += 1;

        // Find register definition
        let (reg, _region) = self.find_register(name)?;

        // Check access type
        if reg.access == AccessType::ReadOnly {
            return Err(DriverError::OperationFailed {
                op: "write".into(),
                reason: format!("Register {} is read-only", name),
            });
        }

        // Update cache
        self.register_cache.insert(name.to_string(), value);

        // Write to MMIO if available
        if let Some(ref mut mmio) = self.mmio {
            match reg.width {
                8 => mmio.write8(reg.offset, value as u8),
                16 => mmio.write16(reg.offset, value as u16),
                32 => mmio.write32(reg.offset, value as u32),
                64 => mmio.write64(reg.offset, value),
                _ => {}
            }
        }

        Ok(())
    }

    /// Find register definition by name
    fn find_register(&self, name: &str) -> Result<(Register, &MemoryRegion), DriverError> {
        // Handle bitfield references like "COMMAND.RESET"
        let base_name = name.split('.').next().unwrap_or(name);

        for region in &self.description.memory_map {
            for reg in &region.registers {
                if reg.name == base_name {
                    return Ok((reg.clone(), region));
                }
            }
        }

        Err(DriverError::OperationFailed {
            op: "find_register".into(),
            reason: format!("Unknown register: {}", name),
        })
    }

    /// Apply quirks to a sequence of operations
    fn apply_quirks_to_sequence(&self, ops: Vec<Operation>) -> Vec<Operation> {
        let mut result = ops;

        for quirk in &self.description.quirks {
            if self.quirk_applies(&quirk.condition) {
                for apply in &quirk.apply {
                    match apply {
                        QuirkApply::InsertAfter { step_index, operation } => {
                            if *step_index < result.len() {
                                result.insert(step_index + 1, operation.clone());
                            }
                        }
                        QuirkApply::InsertBefore { step_index, operation } => {
                            if *step_index < result.len() {
                                result.insert(*step_index, operation.clone());
                            }
                        }
                        QuirkApply::Replace { step_index, operation } => {
                            if *step_index < result.len() {
                                result[*step_index] = operation.clone();
                            }
                        }
                        QuirkApply::AddDelay { after_step, delay_ms } => {
                            if *after_step < result.len() {
                                result.insert(after_step + 1, Operation::WaitMs(*delay_ms));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        result
    }

    /// Check if a quirk condition applies
    fn quirk_applies(&self, cond: &QuirkCondition) -> bool {
        match cond {
            QuirkCondition::Always => true,
            QuirkCondition::RevisionLt(rev) => {
                self.description.device.revision.map(|r| r < *rev).unwrap_or(false)
            }
            QuirkCondition::RevisionGe(rev) => {
                self.description.device.revision.map(|r| r >= *rev).unwrap_or(false)
            }
            QuirkCondition::SubsystemVendor(v) => {
                self.description.device.subsystem_vendor == Some(*v)
            }
            QuirkCondition::SubsystemDevice(d) => {
                self.description.device.subsystem_device == Some(*d)
            }
            QuirkCondition::And(a, b) => self.quirk_applies(a) && self.quirk_applies(b),
            QuirkCondition::Or(a, b) => self.quirk_applies(a) || self.quirk_applies(b),
        }
    }

    /// Set a state variable
    pub fn set_state(&mut self, name: &str, value: u64) {
        self.state.insert(name.to_string(), value);
    }

    /// Get a state variable
    pub fn get_state(&self, name: &str) -> Option<u64> {
        self.state.get(name).copied()
    }

    /// Get all state variables
    pub fn all_state(&self) -> &HashMap<String, u64> {
        &self.state
    }
}

/// Wrapper to allow Box<dyn MmioAccessor> in struct
struct MmioWrapper(Box<dyn MmioAccessor>);

impl MmioWrapper {
    fn read8(&self, offset: usize) -> u8 { self.0.read8(offset) }
    fn read16(&self, offset: usize) -> u16 { self.0.read16(offset) }
    fn read32(&self, offset: usize) -> u32 { self.0.read32(offset) }
    fn read64(&self, offset: usize) -> u64 { self.0.read64(offset) }

    fn write8(&mut self, offset: usize, value: u8) { self.0.write8(offset, value) }
    fn write16(&mut self, offset: usize, value: u16) { self.0.write16(offset, value) }
    fn write32(&mut self, offset: usize, value: u32) { self.0.write32(offset, value) }
    fn write64(&mut self, offset: usize, value: u64) { self.0.write64(offset, value) }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HDL: &str = r#"
device:
  name: "Test NIC"
  vendor_id: 0x10EC
  device_id: 0x8139
  class: network

memory_map:
  bar0:
    size: 256
    registers:
      - name: COMMAND
        offset: 0x37
        width: 8
        access: read_write
      - name: STATUS
        offset: 0x38
        width: 16
        access: read_only
      - name: TX_ADDR
        offset: 0x20
        width: 32
        access: read_write

init_sequence:
  - write: COMMAND, 0x10
  - wait_ms: 10

operations:
  send_packet:
    params: [buffer_addr, length]
    steps:
      - write: TX_ADDR, $0
      - increment: tx_index, mod: 4
"#;

    #[test]
    fn test_create_driver() {
        let driver = UniversalDriver::from_hdl(TEST_HDL);
        assert!(driver.is_ok());

        let driver = driver.unwrap();
        assert_eq!(driver.device_info().name, "Test NIC");
        assert_eq!(driver.device_info().vendor_id, 0x10EC);
        assert!(!driver.is_initialized());
    }

    #[test]
    fn test_initialize() {
        let mut driver = UniversalDriver::from_hdl(TEST_HDL).unwrap();
        let result = driver.initialize();
        assert!(result.is_ok());
        assert!(driver.is_initialized());

        // Check that COMMAND was written
        assert_eq!(driver.register_cache.get("COMMAND"), Some(&0x10));
    }

    #[test]
    fn test_execute_operation() {
        let mut driver = UniversalDriver::from_hdl(TEST_HDL).unwrap();
        driver.initialize().unwrap();

        let result = driver.execute("send_packet", &[0xDEADBEEF, 1500]);
        assert!(result.is_ok());

        // Check TX_ADDR was written
        assert_eq!(driver.register_cache.get("TX_ADDR"), Some(&0xDEADBEEF));

        // Check tx_index was incremented
        assert_eq!(driver.get_state("tx_index"), Some(1));
    }

    #[test]
    fn test_state_management() {
        let mut driver = UniversalDriver::from_hdl(TEST_HDL).unwrap();

        driver.set_state("counter", 42);
        assert_eq!(driver.get_state("counter"), Some(42));
        assert_eq!(driver.get_state("nonexistent"), None);
    }

    #[test]
    fn test_handle_interrupt() {
        let hdl = r#"
device:
  name: "Test"
  vendor_id: 0x1234
  device_id: 0x5678
  class: network

interrupts:
  type: msi
  handlers:
    - mask: 0x0001
      name: rx
      action: signal_rx_ready
    - mask: 0x0004
      name: tx
      action: signal_tx_done
"#;
        let mut driver = UniversalDriver::from_hdl(hdl).unwrap();

        // Test single interrupt
        let actions = driver.handle_interrupt(0x0001);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], IrqAction::SignalRxReady);

        // Test multiple interrupts
        let actions = driver.handle_interrupt(0x0005);
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_statistics() {
        let mut driver = UniversalDriver::from_hdl(TEST_HDL).unwrap();

        assert_eq!(driver.stats().writes, 0);

        driver.initialize().unwrap();
        assert!(driver.stats().writes > 0);

        driver.execute("send_packet", &[0x1000, 100]).unwrap();
        assert_eq!(driver.stats().operations, 1);
    }

    #[test]
    fn test_increment_with_modulo() {
        let mut driver = UniversalDriver::from_hdl(TEST_HDL).unwrap();
        driver.initialize().unwrap();

        // Execute send_packet 5 times - should wrap at 4
        for i in 0..5 {
            driver.execute("send_packet", &[0x1000 + i, 100]).unwrap();
        }

        // tx_index should be 1 (after wrapping from 4 -> 0 -> 1)
        assert_eq!(driver.get_state("tx_index"), Some(1));
    }
}
