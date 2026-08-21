//! Driver Pattern Database
//!
//! Registry of known hardware devices and their HDL descriptions.
//! Allows auto-detection and configuration of hardware based on PCI IDs.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use hashbrown::HashMap;

use super::types::*;
use super::parser::HdlParser;

/// PCI device identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor: Option<u16>,
    pub subsystem_device: Option<u16>,
}

impl PciId {
    pub fn new(vendor_id: u16, device_id: u16) -> Self {
        Self {
            vendor_id,
            device_id,
            subsystem_vendor: None,
            subsystem_device: None,
        }
    }

    pub fn with_subsystem(mut self, vendor: u16, device: u16) -> Self {
        self.subsystem_vendor = Some(vendor);
        self.subsystem_device = Some(device);
        self
    }

    /// Check if this ID matches another (with wildcard support)
    pub fn matches(&self, other: &PciId) -> bool {
        if self.vendor_id != other.vendor_id || self.device_id != other.device_id {
            return false;
        }

        // Subsystem matching is optional
        match (self.subsystem_vendor, other.subsystem_vendor) {
            (Some(a), Some(b)) if a != b => return false,
            _ => {}
        }
        match (self.subsystem_device, other.subsystem_device) {
            (Some(a), Some(b)) if a != b => return false,
            _ => {}
        }

        true
    }
}

/// Database entry for a device driver
#[derive(Debug, Clone)]
pub struct DriverEntry {
    /// Device identifier
    pub id: PciId,
    /// Device name
    pub name: String,
    /// Device class
    pub class: DeviceClass,
    /// HDL description (parsed or raw)
    hdl: DriverHdl,
}

#[derive(Debug, Clone)]
enum DriverHdl {
    /// Raw HDL text (not yet parsed)
    Raw(String),
    /// Parsed description
    Parsed(HardwareDescription),
}

impl DriverEntry {
    /// Create entry from HDL text
    pub fn from_hdl(id: PciId, name: &str, class: DeviceClass, hdl: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            class,
            hdl: DriverHdl::Raw(hdl.to_string()),
        }
    }

    /// Create entry from parsed description
    pub fn from_description(id: PciId, desc: HardwareDescription) -> Self {
        Self {
            id,
            name: desc.device.name.clone(),
            class: desc.device.class,
            hdl: DriverHdl::Parsed(desc),
        }
    }

    /// Get the hardware description, parsing if necessary
    pub fn description(&self) -> Result<HardwareDescription, ParseError> {
        match &self.hdl {
            DriverHdl::Parsed(desc) => Ok(desc.clone()),
            DriverHdl::Raw(hdl) => {
                let parser = HdlParser::new();
                parser.parse(hdl)
            }
        }
    }
}

/// Driver pattern database
#[derive(Debug, Default)]
pub struct DriverDatabase {
    /// Drivers indexed by PCI ID
    by_id: HashMap<(u16, u16), Vec<DriverEntry>>,
    /// Drivers indexed by name
    by_name: HashMap<String, DriverEntry>,
    /// Generic drivers by class (fallback)
    by_class: HashMap<DeviceClass, DriverEntry>,
}

impl DriverDatabase {
    /// Create empty database
    pub fn new() -> Self {
        Self::default()
    }

    /// Create database with built-in device patterns
    pub fn with_builtin() -> Self {
        let mut db = Self::new();
        db.register_builtin_devices();
        db
    }

    /// Register a driver entry
    pub fn register(&mut self, entry: DriverEntry) {
        // Index by PCI ID
        let key = (entry.id.vendor_id, entry.id.device_id);
        self.by_id.entry(key).or_default().push(entry.clone());

        // Index by name
        self.by_name.insert(entry.name.clone(), entry);
    }

    /// Register a generic driver for a device class
    pub fn register_generic(&mut self, class: DeviceClass, entry: DriverEntry) {
        self.by_class.insert(class, entry);
    }

    /// Look up driver by PCI ID
    pub fn lookup(&self, id: &PciId) -> Option<&DriverEntry> {
        let key = (id.vendor_id, id.device_id);
        let entries = self.by_id.get(&key)?;

        // Find best match (with subsystem if available)
        entries.iter().find(|e| e.id.matches(id))
    }

    /// Look up driver by name
    pub fn lookup_by_name(&self, name: &str) -> Option<&DriverEntry> {
        self.by_name.get(name)
    }

    /// Look up generic driver by class
    pub fn lookup_generic(&self, class: DeviceClass) -> Option<&DriverEntry> {
        self.by_class.get(&class)
    }

    /// Get driver for device, falling back to generic if needed
    pub fn get_driver(&self, id: &PciId, class: DeviceClass) -> Option<&DriverEntry> {
        self.lookup(id).or_else(|| self.lookup_generic(class))
    }

    /// List all registered drivers
    pub fn list(&self) -> impl Iterator<Item = &DriverEntry> {
        self.by_name.values()
    }

    /// Number of registered drivers
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Is database empty
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Register built-in device patterns
    fn register_builtin_devices(&mut self) {
        // RTL8139 (common NIC)
        self.register(DriverEntry::from_hdl(
            PciId::new(0x10EC, 0x8139),
            "RTL8139",
            DeviceClass::Network,
            include_str!("patterns/rtl8139.hdl"),
        ));

        // Generic network device
        self.register_generic(
            DeviceClass::Network,
            DriverEntry::from_hdl(
                PciId::new(0xFFFF, 0xFFFF), // Wildcard
                "Generic NIC",
                DeviceClass::Network,
                include_str!("patterns/generic_nic.hdl"),
            ),
        );
    }
}

// =========================================================================
// Well-known vendor IDs
// =========================================================================

/// Common vendor IDs
pub mod vendors {
    pub const INTEL: u16 = 0x8086;
    pub const REALTEK: u16 = 0x10EC;
    pub const BROADCOM: u16 = 0x14E4;
    pub const MELLANOX: u16 = 0x15B3;
    pub const NVIDIA: u16 = 0x10DE;
    pub const AMD: u16 = 0x1022;
    pub const QUALCOMM: u16 = 0x17CB;
    pub const MARVELL: u16 = 0x1B4B;
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_id_matching() {
        let id1 = PciId::new(0x10EC, 0x8139);
        let id2 = PciId::new(0x10EC, 0x8139).with_subsystem(0x1234, 0x5678);
        let id3 = PciId::new(0x10EC, 0x8140);

        assert!(id1.matches(&id1));
        assert!(id1.matches(&id2)); // Base ID matches subsystem ID
        assert!(!id1.matches(&id3)); // Different device ID
    }

    #[test]
    fn test_database_operations() {
        let mut db = DriverDatabase::new();

        let entry = DriverEntry::from_hdl(
            PciId::new(0x10EC, 0x8139),
            "RTL8139",
            DeviceClass::Network,
            r#"
device:
  name: "RTL8139"
  vendor_id: 0x10EC
  device_id: 0x8139
  class: network
"#,
        );

        db.register(entry);

        assert_eq!(db.len(), 1);
        assert!(db.lookup(&PciId::new(0x10EC, 0x8139)).is_some());
        assert!(db.lookup(&PciId::new(0x8086, 0x1234)).is_none());
        assert!(db.lookup_by_name("RTL8139").is_some());
    }

    #[test]
    fn test_generic_fallback() {
        let mut db = DriverDatabase::new();

        let generic = DriverEntry::from_hdl(
            PciId::new(0xFFFF, 0xFFFF),
            "Generic NIC",
            DeviceClass::Network,
            r#"
device:
  name: "Generic NIC"
  vendor_id: 0xFFFF
  device_id: 0xFFFF
  class: network
"#,
        );

        db.register_generic(DeviceClass::Network, generic);

        // Unknown device should fall back to generic
        let unknown = PciId::new(0x1234, 0x5678);
        assert!(db.lookup(&unknown).is_none());
        assert!(db.get_driver(&unknown, DeviceClass::Network).is_some());
    }
}
