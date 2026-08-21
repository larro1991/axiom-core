//! HDL-Lite Parser
//!
//! Parses hardware description files into structured data.
//! Uses a simple line-based format for easy parsing without YAML dependencies.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use hashbrown::HashMap;

use super::types::*;

/// HDL-Lite Parser
pub struct HdlParser {
    /// Current line number
    line_num: usize,
    /// Current section
    section: Option<Section>,
    /// Parsed result
    result: PartialDescription,
}

/// Parsing sections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Device,
    MemoryMap,
    Registers,
    Interrupts,
    InitSequence,
    Operations,
    Quirks,
}

/// Partial description during parsing
#[derive(Debug, Default)]
struct PartialDescription {
    device: Option<DeviceInfo>,
    memory_regions: Vec<MemoryRegion>,
    current_region: Option<MemoryRegion>,
    current_registers: Vec<Register>,
    interrupt_config: Option<InterruptConfig>,
    interrupt_handlers: Vec<InterruptHandler>,
    init_sequence: Vec<Operation>,
    operations: HashMap<String, OperationDef>,
    current_operation: Option<PartialOperation>,
    quirks: Vec<Quirk>,
}

#[derive(Debug, Default)]
struct PartialOperation {
    name: String,
    params: Vec<String>,
    returns: Vec<String>,
    trigger: Option<Trigger>,
    steps: Vec<Operation>,
}

impl HdlParser {
    /// Create a new parser
    pub fn new() -> Self {
        Self {
            line_num: 0,
            section: None,
            result: PartialDescription::default(),
        }
    }

    /// Parse HDL-Lite text into HardwareDescription
    pub fn parse(mut self, input: &str) -> Result<HardwareDescription, ParseError> {
        for line in input.lines() {
            self.line_num += 1;
            self.parse_line(line)?;
        }

        self.finalize()
    }

    /// Parse a single line
    fn parse_line(&mut self, line: &str) -> Result<(), ParseError> {
        // Skip empty lines and comments
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(());
        }

        // Calculate indentation
        let indent = line.len() - line.trim_start().len();

        // Check for list items FIRST (before key-value, as "- name: foo" would match key-value)
        if trimmed.starts_with('-') {
            let item = trimmed[1..].trim();
            self.handle_list_item(item)?;
            return Ok(());
        }

        // Parse key-value or section header
        let kv = Self::split_kv_static(trimmed);
        if let Some((key, value)) = kv {
            self.handle_kv(key, value, indent)?;
        } else if trimmed.ends_with(':') {
            // Section header
            let section_name = &trimmed[..trimmed.len() - 1];
            self.handle_section(section_name)?;
        }

        Ok(())
    }

    /// Split key: value pairs (static version to avoid borrow issues)
    fn split_kv_static(line: &str) -> Option<(&str, &str)> {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            if !value.is_empty() {
                return Some((key, value));
            }
        }
        None
    }


    /// Handle section headers
    fn handle_section(&mut self, name: &str) -> Result<(), ParseError> {
        // Check for subsection headers first (don't finalize parent section)
        match name {
            // Subsections within memory_map
            "registers" if self.section == Some(Section::MemoryMap) => {
                // Just switch to register parsing mode within memory map
                return Ok(());
            }
            // Subsections within interrupts
            "handlers" if self.section == Some(Section::Interrupts) => {
                // Stay in interrupts section, handlers are parsed as list items
                return Ok(());
            }
            // Subsections within operations
            "steps" if self.section == Some(Section::Operations) => {
                // Stay in operations section, steps are parsed as list items
                return Ok(());
            }
            _ => {}
        }

        // Finalize previous section for major section changes
        self.finalize_current_section();

        self.section = match name {
            "device" => Some(Section::Device),
            "memory_map" => Some(Section::MemoryMap),
            "registers" => Some(Section::Registers),
            "interrupts" => Some(Section::Interrupts),
            "init_sequence" => Some(Section::InitSequence),
            "operations" => Some(Section::Operations),
            "quirks" => Some(Section::Quirks),
            _ => {
                // Could be a memory region name like "bar0:"
                if self.section == Some(Section::MemoryMap) {
                    // Start new memory region
                    if let Some(region) = self.result.current_region.take() {
                        self.result.memory_regions.push(region);
                    }
                    self.result.current_region = Some(MemoryRegion {
                        name: name.to_string(),
                        size: 0,
                        registers: Vec::new(),
                    });
                    return Ok(());
                }
                // Could be an operation name
                if self.section == Some(Section::Operations) {
                    // Start new operation
                    if let Some(op) = self.result.current_operation.take() {
                        self.result.operations.insert(op.name.clone(), OperationDef {
                            name: op.name,
                            params: op.params,
                            returns: op.returns,
                            trigger: op.trigger,
                            steps: op.steps,
                        });
                    }
                    self.result.current_operation = Some(PartialOperation {
                        name: name.to_string(),
                        ..Default::default()
                    });
                    return Ok(());
                }
                return Err(ParseError::UnknownKeyword {
                    line: self.line_num,
                    keyword: name.to_string(),
                });
            }
        };
        Ok(())
    }

    /// Handle key-value pairs
    fn handle_kv(&mut self, key: &str, value: &str, _indent: usize) -> Result<(), ParseError> {
        match self.section {
            Some(Section::Device) => self.parse_device_field(key, value),
            Some(Section::MemoryMap) | Some(Section::Registers) => {
                self.parse_register_field(key, value)
            }
            Some(Section::Interrupts) => self.parse_interrupt_field(key, value),
            Some(Section::Operations) => self.parse_operation_field(key, value),
            None => Ok(()), // Ignore top-level key-values for now
            _ => Ok(()),
        }
    }

    /// Handle list items
    fn handle_list_item(&mut self, item: &str) -> Result<(), ParseError> {
        match self.section {
            Some(Section::InitSequence) => {
                if let Some(op) = self.parse_operation_step(item)? {
                    self.result.init_sequence.push(op);
                }
            }
            Some(Section::Operations) => {
                // Parse operation step first to avoid borrow conflict
                let op = self.parse_operation_step(item)?;
                if let Some(ref mut current) = self.result.current_operation {
                    if let Some(op) = op {
                        current.steps.push(op);
                    }
                }
            }
            Some(Section::Registers) | Some(Section::MemoryMap) => {
                // Start a new register definition
                // The item might be "name: REG_NAME"
                if let Some((key, value)) = Self::split_kv_static(item) {
                    if key == "name" {
                        let reg = Register {
                            name: value.to_string(),
                            offset: 0,
                            width: 32,
                            access: AccessType::ReadWrite,
                            bits: Vec::new(),
                            array_size: 1,
                        };
                        self.result.current_registers.push(reg);
                    }
                }
            }
            Some(Section::Interrupts) => {
                // Parse interrupt handler
                if let Some((key, value)) = Self::split_kv_static(item) {
                    match key {
                        "mask" => {
                            let mask = Self::parse_number_static(value)? as u32;
                            self.result.interrupt_handlers.push(InterruptHandler {
                                mask,
                                name: String::new(),
                                action: IrqAction::Acknowledge,
                            });
                        }
                        "name" => {
                            if let Some(handler) = self.result.interrupt_handlers.last_mut() {
                                handler.name = value.to_string();
                            }
                        }
                        "action" => {
                            // Parse action first to avoid borrow conflict
                            let action = Self::parse_irq_action_static(value)?;
                            if let Some(handler) = self.result.interrupt_handlers.last_mut() {
                                handler.action = action;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Parse device section fields
    fn parse_device_field(&mut self, key: &str, value: &str) -> Result<(), ParseError> {
        // Parse value first to avoid borrow conflicts
        let parsed_num = match key {
            "vendor_id" | "device_id" | "subsystem_vendor" | "subsystem_device" | "revision" => {
                Some(Self::parse_number_static(value)?)
            }
            _ => None,
        };
        let parsed_class = if key == "class" {
            Some(DeviceClass::from_str(value).ok_or_else(|| ParseError::InvalidValue {
                field: "class".into(),
                value: value.into(),
            })?)
        } else {
            None
        };

        let device = self.result.device.get_or_insert_with(|| DeviceInfo {
            name: String::new(),
            vendor_id: 0,
            device_id: 0,
            class: DeviceClass::Generic,
            subsystem_vendor: None,
            subsystem_device: None,
            revision: None,
        });

        match key {
            "name" => device.name = value.trim_matches('"').to_string(),
            "vendor_id" => device.vendor_id = parsed_num.unwrap() as u16,
            "device_id" => device.device_id = parsed_num.unwrap() as u16,
            "class" => device.class = parsed_class.unwrap(),
            "subsystem_vendor" => device.subsystem_vendor = Some(parsed_num.unwrap() as u16),
            "subsystem_device" => device.subsystem_device = Some(parsed_num.unwrap() as u16),
            "revision" => device.revision = Some(parsed_num.unwrap() as u8),
            _ => {}
        }
        Ok(())
    }

    /// Parse register section fields
    fn parse_register_field(&mut self, key: &str, value: &str) -> Result<(), ParseError> {
        // Parse values first to avoid borrow conflicts
        let parsed_num = match key {
            "size" | "offset" | "width" | "array" => Some(Self::parse_number_static(value)?),
            _ => None,
        };
        let parsed_access = if key == "access" {
            Some(AccessType::from_str(value).ok_or_else(|| ParseError::InvalidValue {
                field: "access".into(),
                value: value.into(),
            })?)
        } else {
            None
        };

        // Check if we're defining memory region properties
        if let Some(ref mut region) = self.result.current_region {
            if key == "size" {
                region.size = parsed_num.unwrap() as usize;
                return Ok(());
            }
        }

        // Check if we're defining register properties
        if let Some(reg) = self.result.current_registers.last_mut() {
            match key {
                "offset" => reg.offset = parsed_num.unwrap() as usize,
                "width" => reg.width = parsed_num.unwrap() as u8,
                "access" => reg.access = parsed_access.unwrap(),
                "array" => reg.array_size = parsed_num.unwrap() as usize,
                _ => {}
            }
        }
        Ok(())
    }

    /// Parse interrupt section fields
    fn parse_interrupt_field(&mut self, key: &str, value: &str) -> Result<(), ParseError> {
        match key {
            "type" => {
                let irq_type = match value {
                    "legacy" => InterruptType::Legacy,
                    "msi" => InterruptType::Msi,
                    "msi-x" | "msix" => InterruptType::MsiX,
                    "polling" => InterruptType::Polling,
                    _ => {
                        return Err(ParseError::InvalidValue {
                            field: "interrupt type".into(),
                            value: value.into(),
                        });
                    }
                };
                self.result.interrupt_config = Some(InterruptConfig {
                    irq_type,
                    handlers: Vec::new(),
                });
            }
            // Handler-level fields (after "- mask: ..." list item)
            "name" => {
                if let Some(handler) = self.result.interrupt_handlers.last_mut() {
                    handler.name = value.to_string();
                }
            }
            "action" => {
                let action = Self::parse_irq_action_static(value)?;
                if let Some(handler) = self.result.interrupt_handlers.last_mut() {
                    handler.action = action;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Parse operation section fields
    fn parse_operation_field(&mut self, key: &str, value: &str) -> Result<(), ParseError> {
        // Parse values first to avoid borrow conflicts
        let parsed_list = match key {
            "params" | "returns" => Some(Self::parse_string_list_static(value)),
            _ => None,
        };
        let parsed_trigger = if key == "trigger" && value.starts_with("interrupt.") {
            Some(Trigger::Interrupt(value[10..].to_string()))
        } else {
            None
        };

        if let Some(ref mut op) = self.result.current_operation {
            match key {
                "params" => op.params = parsed_list.unwrap(),
                "returns" => op.returns = parsed_list.unwrap(),
                "trigger" => {
                    if let Some(trigger) = parsed_trigger {
                        op.trigger = Some(trigger);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Parse an operation step
    fn parse_operation_step(&self, step: &str) -> Result<Option<Operation>, ParseError> {
        let step = step.trim();

        // write: REG, value
        if step.starts_with("write:") {
            let rest = step[6..].trim();
            if let Some((reg, val)) = rest.split_once(',') {
                return Ok(Some(Operation::Write {
                    register: reg.trim().to_string(),
                    value: self.parse_value(val.trim())?,
                }));
            }
        }

        // read: REG → var
        if step.starts_with("read:") {
            let rest = step[5..].trim();
            let (reg, into) = if let Some((r, v)) = rest.split_once('→') {
                (r.trim(), Some(v.trim().to_string()))
            } else if let Some((r, v)) = rest.split_once("->") {
                (r.trim(), Some(v.trim().to_string()))
            } else {
                (rest, None)
            };
            return Ok(Some(Operation::Read {
                register: reg.to_string(),
                into,
            }));
        }

        // wait_ms: N
        if step.starts_with("wait_ms:") {
            let ms: u32 = self.parse_number(step[8..].trim())? as u32;
            return Ok(Some(Operation::WaitMs(ms)));
        }

        // wait_us: N
        if step.starts_with("wait_us:") {
            let us: u32 = self.parse_number(step[8..].trim())? as u32;
            return Ok(Some(Operation::WaitUs(us)));
        }

        // poll: REG, expected, timeout: Nms
        if step.starts_with("poll:") {
            let rest = step[5..].trim();
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() >= 2 {
                let register = parts[0].trim().to_string();
                let expected = self.parse_number(parts[1].trim())?;
                let timeout_ms = if parts.len() >= 3 {
                    let timeout_str = parts[2].trim();
                    if let Some(t) = timeout_str.strip_prefix("timeout:") {
                        let t = t.trim().trim_end_matches("ms");
                        self.parse_number(t)? as u32
                    } else {
                        100
                    }
                } else {
                    100
                };
                return Ok(Some(Operation::Poll {
                    register,
                    expected,
                    mask: u64::MAX,
                    timeout_ms,
                }));
            }
        }

        // increment: var, mod: N
        if step.starts_with("increment:") {
            let rest = step[10..].trim();
            let (var, modulo) = if let Some((v, m)) = rest.split_once(',') {
                let m = m.trim().strip_prefix("mod:").unwrap_or(m).trim();
                (v.trim(), Some(self.parse_number(m)?))
            } else {
                (rest, None)
            };
            return Ok(Some(Operation::Increment {
                variable: var.to_string(),
                modulo,
            }));
        }

        // barrier: read|write|full
        if step.starts_with("barrier:") {
            let kind = step[8..].trim();
            let barrier_type = match kind {
                "read" => BarrierType::Read,
                "write" => BarrierType::Write,
                "full" | "mb" => BarrierType::Full,
                _ => BarrierType::Full,
            };
            return Ok(Some(Operation::Barrier(barrier_type)));
        }

        Ok(None)
    }

    /// Parse a value expression
    fn parse_value(&self, s: &str) -> Result<Value, ParseError> {
        let s = s.trim();

        // Check for literal number
        if s.starts_with("0x") || s.starts_with("0X") || s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Ok(Value::Literal(self.parse_number(s)?));
        }

        // Check for parameter reference $0, $1, etc.
        if let Some(stripped) = s.strip_prefix('$') {
            let idx: usize = stripped.parse().map_err(|_| ParseError::InvalidValue {
                field: "parameter".into(),
                value: s.into(),
            })?;
            return Ok(Value::Parameter(idx));
        }

        // Otherwise treat as variable/register reference
        Ok(Value::Variable(s.to_string()))
    }

    /// Parse a number (hex or decimal)
    fn parse_number(&self, s: &str) -> Result<u64, ParseError> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16)
        } else {
            s.parse()
        }
        .map_err(|_| ParseError::InvalidValue {
            field: "number".into(),
            value: s.into(),
        })
    }


    // =========================================================================
    // Static helper methods (avoid borrow conflicts)
    // =========================================================================

    /// Parse a number (hex or decimal) - static version
    fn parse_number_static(s: &str) -> Result<u64, ParseError> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16)
        } else {
            s.parse()
        }
        .map_err(|_| ParseError::InvalidValue {
            field: "number".into(),
            value: s.into(),
        })
    }

    /// Parse a string list [a, b, c] - static version
    fn parse_string_list_static(s: &str) -> Vec<String> {
        let s = s.trim().trim_start_matches('[').trim_end_matches(']');
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    }

    /// Parse IRQ action - static version
    fn parse_irq_action_static(s: &str) -> Result<IrqAction, ParseError> {
        match s {
            "signal_rx_ready" => Ok(IrqAction::SignalRxReady),
            "signal_tx_done" => Ok(IrqAction::SignalTxDone),
            "signal_error" => Ok(IrqAction::SignalError),
            "acknowledge" | "ack" => Ok(IrqAction::Acknowledge),
            _ if s.starts_with("execute:") => Ok(IrqAction::Execute(s[8..].trim().to_string())),
            _ => Err(ParseError::InvalidValue {
                field: "action".into(),
                value: s.into(),
            }),
        }
    }

    /// Finalize current section
    fn finalize_current_section(&mut self) {
        // Save current registers to current region
        if !self.result.current_registers.is_empty() {
            if let Some(ref mut region) = self.result.current_region {
                region.registers.append(&mut self.result.current_registers);
            }
        }

        // Save current region
        if let Some(region) = self.result.current_region.take() {
            self.result.memory_regions.push(region);
        }

        // Save current operation
        if let Some(op) = self.result.current_operation.take() {
            self.result.operations.insert(op.name.clone(), OperationDef {
                name: op.name,
                params: op.params,
                returns: op.returns,
                trigger: op.trigger,
                steps: op.steps,
            });
        }

        // Save interrupt handlers
        if !self.result.interrupt_handlers.is_empty() {
            if let Some(ref mut config) = self.result.interrupt_config {
                config.handlers.append(&mut self.result.interrupt_handlers);
            }
        }
    }

    /// Finalize parsing and produce result
    fn finalize(mut self) -> Result<HardwareDescription, ParseError> {
        self.finalize_current_section();

        let device = self.result.device.ok_or_else(|| ParseError::MissingField {
            field: "device".into(),
        })?;

        Ok(HardwareDescription {
            device,
            memory_map: self.result.memory_regions,
            interrupts: self.result.interrupt_config.unwrap_or(InterruptConfig {
                irq_type: InterruptType::Polling,
                handlers: Vec::new(),
            }),
            init_sequence: self.result.init_sequence,
            operations: self.result.operations,
            quirks: self.result.quirks,
        })
    }
}

impl Default for HdlParser {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_HDL: &str = r#"
device:
  name: "Test NIC"
  vendor_id: 0x10EC
  device_id: 0x8139
  class: network

memory_map:
  bar0:
    size: 256
    registers:
      - name: MAC0
        offset: 0x00
        width: 32
        access: read_write
      - name: COMMAND
        offset: 0x37
        width: 8
        access: read_write

interrupts:
  type: msi
  handlers:
    - mask: 0x0001
      name: rx_complete
      action: signal_rx_ready

init_sequence:
  - write: COMMAND, 0x10
  - wait_ms: 10
  - poll: COMMAND, 0, timeout: 100ms
"#;

    #[test]
    fn test_parse_simple_hdl() {
        let parser = HdlParser::new();
        let result = parser.parse(SIMPLE_HDL);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let desc = result.unwrap();
        assert_eq!(desc.device.name, "Test NIC");
        assert_eq!(desc.device.vendor_id, 0x10EC);
        assert_eq!(desc.device.device_id, 0x8139);
        assert_eq!(desc.device.class, DeviceClass::Network);
    }

    #[test]
    fn test_parse_memory_map() {
        let parser = HdlParser::new();
        let desc = parser.parse(SIMPLE_HDL).unwrap();

        assert_eq!(desc.memory_map.len(), 1);
        let bar0 = &desc.memory_map[0];
        assert_eq!(bar0.name, "bar0");
        assert_eq!(bar0.size, 256);
        assert!(bar0.registers.len() >= 1);
    }

    #[test]
    fn test_parse_init_sequence() {
        let parser = HdlParser::new();
        let desc = parser.parse(SIMPLE_HDL).unwrap();

        assert_eq!(desc.init_sequence.len(), 3);

        match &desc.init_sequence[0] {
            Operation::Write { register, value } => {
                assert_eq!(register, "COMMAND");
                assert!(matches!(value, Value::Literal(0x10)));
            }
            _ => panic!("Expected Write operation"),
        }

        match &desc.init_sequence[1] {
            Operation::WaitMs(10) => {}
            _ => panic!("Expected WaitMs(10)"),
        }

        match &desc.init_sequence[2] {
            Operation::Poll { register, expected, timeout_ms, .. } => {
                assert_eq!(register, "COMMAND");
                assert_eq!(*expected, 0);
                assert_eq!(*timeout_ms, 100);
            }
            _ => panic!("Expected Poll operation"),
        }
    }

    #[test]
    fn test_parse_interrupts() {
        let parser = HdlParser::new();
        let desc = parser.parse(SIMPLE_HDL).unwrap();

        assert_eq!(desc.interrupts.irq_type, InterruptType::Msi);
        assert_eq!(desc.interrupts.handlers.len(), 1);

        let handler = &desc.interrupts.handlers[0];
        assert_eq!(handler.mask, 0x0001);
        assert_eq!(handler.name, "rx_complete");
        assert_eq!(handler.action, IrqAction::SignalRxReady);
    }

    #[test]
    fn test_parse_number() {
        let parser = HdlParser::new();
        assert_eq!(parser.parse_number("42").unwrap(), 42);
        assert_eq!(parser.parse_number("0x10").unwrap(), 16);
        assert_eq!(parser.parse_number("0xFF").unwrap(), 255);
        assert_eq!(parser.parse_number("0x10EC").unwrap(), 0x10EC);
    }

    #[test]
    fn test_parse_operations() {
        let hdl = r#"
device:
  name: "Test"
  vendor_id: 0x1234
  device_id: 0x5678
  class: network

operations:
  send_packet:
    params: [buffer_addr, length]
    steps:
      - write: TX_ADDR, $0
      - write: TX_LEN, $1
      - increment: tx_index, mod: 4
"#;

        let parser = HdlParser::new();
        let desc = parser.parse(hdl).unwrap();

        assert!(desc.operations.contains_key("send_packet"));
        let op = &desc.operations["send_packet"];
        assert_eq!(op.params, vec!["buffer_addr", "length"]);
        assert_eq!(op.steps.len(), 3);
    }
}
