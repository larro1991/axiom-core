//! Network Hardware Capability
//!
//! Exposes NIC hardware as a capability using the Universal Driver system.
//! This is the HAL's interface to network hardware - FORGE NIC consumes this.

use alloc::string::String;
use alloc::vec::Vec;

use crate::capability::{CapabilityClass, CapabilityMetrics};
use crate::universal::{UniversalDriver, DriverDatabase, PciId, HardwareDescription, DriverError};

/// Network capability - HAL's abstraction over NIC hardware
pub struct NetworkCapability {
    /// Universal driver instance for this NIC
    driver: UniversalDriver,
    /// Hardware info
    info: NicInfo,
    /// Capability metrics
    metrics: NicMetrics,
}

/// Information about detected NIC hardware
#[derive(Debug, Clone)]
pub struct NicInfo {
    /// Device name from HDL pattern
    pub name: String,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// MAC address (if available)
    pub mac_address: Option<[u8; 6]>,
    /// Maximum MTU supported
    pub max_mtu: u16,
    /// Number of TX queues
    pub tx_queues: u8,
    /// Number of RX queues
    pub rx_queues: u8,
    /// Supported features
    pub features: NicFeatures,
}

/// NIC feature flags
#[derive(Debug, Clone, Copy, Default)]
pub struct NicFeatures {
    /// Hardware checksum offload
    pub checksum_offload: bool,
    /// TCP segmentation offload
    pub tso: bool,
    /// Large receive offload
    pub lro: bool,
    /// VLAN tagging
    pub vlan: bool,
    /// Receive side scaling
    pub rss: bool,
    /// Scatter-gather I/O
    pub scatter_gather: bool,
}

/// NIC performance metrics
#[derive(Debug, Clone, Default)]
pub struct NicMetrics {
    /// Link speed in Mbps
    pub link_speed_mbps: u32,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// TX bytes
    pub tx_bytes: u64,
    /// RX bytes
    pub rx_bytes: u64,
    /// TX errors
    pub tx_errors: u64,
    /// RX errors
    pub rx_errors: u64,
    /// Packets dropped
    pub dropped: u64,
}

/// Errors from network operations
#[derive(Debug, Clone)]
pub enum NetworkError {
    /// No driver pattern found for this hardware
    NoDriver,
    /// Driver initialization failed
    InitFailed(String),
    /// Hardware not responding
    HardwareTimeout,
    /// TX queue full
    TxQueueFull,
    /// Invalid packet
    InvalidPacket,
    /// Link down
    LinkDown,
    /// DMA error
    DmaError,
    /// Driver error
    DriverError(String),
}

impl From<DriverError> for NetworkError {
    fn from(e: DriverError) -> Self {
        NetworkError::DriverError(format!("{:?}", e))
    }
}

impl NetworkCapability {
    /// Create from Universal Driver and hardware description
    pub fn new(driver: UniversalDriver, desc: &HardwareDescription) -> Self {
        let info = NicInfo {
            name: desc.device.name.clone(),
            vendor_id: 0, // Set during probe
            device_id: 0,
            mac_address: None,
            max_mtu: 1500,
            tx_queues: 1,
            rx_queues: 1,
            features: NicFeatures::default(),
        };

        Self {
            driver,
            info,
            metrics: NicMetrics::default(),
        }
    }

    /// Probe and create from PCI ID using driver database
    pub fn from_pci(pci_id: PciId, db: &DriverDatabase) -> Result<Self, NetworkError> {
        let entry = db.lookup(&pci_id).ok_or(NetworkError::NoDriver)?;
        let desc = entry.description().map_err(|e| NetworkError::InitFailed(e.to_string()))?;
        let driver = UniversalDriver::from_description(desc.clone());

        let mut cap = Self::new(driver, &desc);
        cap.info.vendor_id = pci_id.vendor_id;
        cap.info.device_id = pci_id.device_id;

        Ok(cap)
    }

    /// Initialize the NIC hardware
    pub fn init(&mut self) -> Result<(), NetworkError> {
        self.driver.initialize()?;

        // Read MAC address via operation if available
        if let Ok(result) = self.driver.execute("read_mac", &[]) {
            if result.len() >= 2 {
                let mut mac = [0u8; 6];
                let low = result[0].to_le_bytes();
                let high = result[1].to_le_bytes();
                mac[0..4].copy_from_slice(&low[0..4]);
                mac[4..6].copy_from_slice(&high[0..2]);
                self.info.mac_address = Some(mac);
            }
        }

        Ok(())
    }

    /// Transmit a packet using the driver's TX operation
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), NetworkError> {
        if packet.len() > self.info.max_mtu as usize + 14 {
            return Err(NetworkError::InvalidPacket);
        }

        // Pass packet data as parameters (simplified - real impl would use DMA)
        // The driver would set up descriptors and trigger TX
        let _result = self.driver.execute("tx", &[packet.len() as u64])?;

        self.metrics.tx_packets += 1;
        self.metrics.tx_bytes += packet.len() as u64;
        Ok(())
    }

    /// Receive a packet (non-blocking)
    pub fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize, NetworkError> {
        // Execute RX poll operation
        let result = self.driver.execute("rx_poll", &[])
            .map_err(|_| NetworkError::HardwareTimeout)?;

        let len = result.first().copied().unwrap_or(0) as usize;
        if len > 0 {
            self.metrics.rx_packets += 1;
            self.metrics.rx_bytes += len as u64;
        }
        Ok(len)
    }

    /// Check if link is up
    pub fn link_up(&self) -> bool {
        // Would query link status register
        // For now, assume link is up if driver is initialized
        self.driver.is_initialized()
    }

    /// Get NIC info
    pub fn info(&self) -> &NicInfo {
        &self.info
    }

    /// Get current metrics
    pub fn metrics(&self) -> &NicMetrics {
        &self.metrics
    }

    /// Get reference to underlying driver
    pub fn driver(&self) -> &UniversalDriver {
        &self.driver
    }

    /// Get mutable driver access
    pub fn driver_mut(&mut self) -> &mut UniversalDriver {
        &mut self.driver
    }

    /// Get capability class
    pub fn class(&self) -> CapabilityClass {
        CapabilityClass::Network
    }

    /// Get capability metrics
    pub fn capability_metrics(&self) -> CapabilityMetrics {
        let error_rate = if self.metrics.tx_packets > 0 {
            ((self.metrics.tx_errors * 1000) / self.metrics.tx_packets) as u32
        } else {
            0
        };

        CapabilityMetrics {
            throughput: self.metrics.tx_bytes + self.metrics.rx_bytes,
            latency_ns: 1000, // ~1μs typical NIC latency
            capacity: 0,
            power_mw: 5000, // Typical NIC power
            efficiency: error_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::universal::HdlParser;

    fn create_test_nic() -> NetworkCapability {
        let hdl = r#"
device:
  name: TestNIC
  class: network
  version: "1.0"

registers:
  - name: MAC0
    offset: 0x00
    size: 4
    access: rw
  - name: MAC1
    offset: 0x04
    size: 4
    access: rw
  - name: STATUS
    offset: 0x08
    size: 4
    access: ro

operations:
  - name: tx
    type: dma_write
    steps:
      - write: TX_DESC
  - name: rx_poll
    type: dma_read
    steps:
      - read: RX_DESC
"#;
        let mut parser = HdlParser::new();
        let desc = parser.parse(hdl).unwrap();
        let driver = UniversalDriver::from_description(desc.clone());
        NetworkCapability::new(driver, &desc)
    }

    #[test]
    fn test_nic_creation() {
        let nic = create_test_nic();
        assert_eq!(nic.info().name, "TestNIC");
        assert_eq!(nic.info().max_mtu, 1500);
    }

    #[test]
    fn test_nic_metrics() {
        let nic = create_test_nic();
        assert_eq!(nic.metrics().tx_packets, 0);
        assert_eq!(nic.metrics().rx_packets, 0);
    }

    #[test]
    fn test_capability_class() {
        let nic = create_test_nic();
        assert!(matches!(nic.class(), CapabilityClass::Network));
    }

    #[test]
    fn test_nic_features_default() {
        let features = NicFeatures::default();
        assert!(!features.checksum_offload);
        assert!(!features.tso);
        assert!(!features.rss);
    }
}
