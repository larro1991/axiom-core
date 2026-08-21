//! FORGE NIC Core
//!
//! The main NIC abstraction that ties together all components.
//! FORGE NIC consumes NetworkCapability from the HAL - it doesn't embed drivers directly.

use alloc::string::String;

use axiom_hal::{NetworkCapability, DriverDatabase, PciId};
use axiom_transport::bridge::{Gateway, GatewayConfig};
use axiom_types::NodeId;

use crate::monitor::PacketMonitor;
use crate::trust::TrustEngine;

/// FORGE NIC configuration
#[derive(Debug, Clone)]
pub struct ForgeNicConfig {
    /// Local node identity
    pub local_id: NodeId,
    /// Enable packet capture
    pub enable_capture: bool,
    /// Enable threat detection
    pub enable_threat_detection: bool,
    /// Enable IPv4 bridging
    pub enable_ipv4_bridge: bool,
    /// Maximum packets per second (0 = unlimited)
    pub max_pps: u64,
    /// Gateway configuration (if bridging enabled)
    pub gateway_config: Option<GatewayConfig>,
}

impl Default for ForgeNicConfig {
    fn default() -> Self {
        Self {
            local_id: NodeId::zero(),
            enable_capture: true,
            enable_threat_detection: true,
            enable_ipv4_bridge: false,
            max_pps: 0,
            gateway_config: None,
        }
    }
}

/// FORGE NIC state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicState {
    /// Not initialized
    Uninitialized,
    /// Initialized but not active
    Ready,
    /// Active and processing packets
    Active,
    /// Temporarily paused
    Paused,
    /// Error state
    Error,
}

/// FORGE NIC statistics
#[derive(Debug, Default, Clone)]
pub struct NicStats {
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets dropped (trust/security)
    pub dropped_untrusted: u64,
    /// Packets dropped (rate limit)
    pub dropped_rate_limit: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// Tier 1 decisions (fast path)
    pub tier1_decisions: u64,
    /// Tier 2 decisions (smart agent)
    pub tier2_decisions: u64,
    /// Tier 3 escalations (AI)
    pub tier3_escalations: u64,
}

/// FORGE NIC - The AI-native network interface
pub struct ForgeNic {
    /// Configuration
    config: ForgeNicConfig,
    /// Current state
    state: NicState,
    /// Network capability from HAL (hardware abstraction)
    nic_cap: Option<NetworkCapability>,
    /// Trust engine
    trust: TrustEngine,
    /// Packet monitor
    monitor: PacketMonitor,
    /// IPv4 Gateway (if bridging enabled)
    gateway: Option<Gateway>,
    /// Statistics
    stats: NicStats,
}

impl ForgeNic {
    /// Create new FORGE NIC with configuration
    pub fn new(config: ForgeNicConfig) -> Self {
        let trust = TrustEngine::new();
        let monitor = PacketMonitor::new(config.enable_capture);

        let gateway = config.gateway_config.clone().map(Gateway::new);

        Self {
            config,
            state: NicState::Uninitialized,
            nic_cap: None,
            trust,
            monitor,
            gateway,
            stats: NicStats::default(),
        }
    }

    /// Initialize with auto-detected hardware
    pub fn init_auto(&mut self) -> Result<(), NicError> {
        // In real implementation, this would probe PCI bus
        // For now, we just mark as ready without hardware
        self.state = NicState::Ready;
        Ok(())
    }

    /// Initialize with specific hardware via HAL's NetworkCapability
    pub fn init_hardware(&mut self, pci_id: PciId, db: &DriverDatabase) -> Result<(), NicError> {
        // Create NetworkCapability from HAL - HAL owns the driver abstraction
        let mut nic_cap = NetworkCapability::from_pci(pci_id, db)
            .map_err(|_| NicError::DriverNotFound)?;

        // Initialize the hardware through HAL
        nic_cap.init().map_err(|_| NicError::DriverLoadFailed)?;

        self.nic_cap = Some(nic_cap);
        self.state = NicState::Ready;
        Ok(())
    }

    /// Start the NIC
    pub fn start(&mut self) -> Result<(), NicError> {
        match self.state {
            NicState::Ready | NicState::Paused => {
                self.state = NicState::Active;
                Ok(())
            }
            NicState::Active => Ok(()), // Already active
            _ => Err(NicError::InvalidState),
        }
    }

    /// Stop the NIC
    pub fn stop(&mut self) -> Result<(), NicError> {
        match self.state {
            NicState::Active => {
                self.state = NicState::Paused;
                Ok(())
            }
            NicState::Paused => Ok(()), // Already paused
            _ => Err(NicError::InvalidState),
        }
    }

    /// Process incoming packet
    pub fn receive(&mut self, packet: &[u8], now: u64) -> PacketAction {
        if self.state != NicState::Active {
            return PacketAction::Drop;
        }

        self.stats.rx_packets += 1;
        self.stats.rx_bytes += packet.len() as u64;

        // Record in monitor
        self.monitor.record_packet(packet, now);

        // Extract source identity (simplified - real impl would parse AXIOM header)
        let source = self.extract_source(packet);

        // Tier 1: Fast trust check
        let trust_level = self.trust.quick_check(&source);
        self.stats.tier1_decisions += 1;

        if trust_level.is_blocked() {
            self.stats.dropped_untrusted += 1;
            return PacketAction::Drop;
        }

        // Check for threats if enabled
        if self.config.enable_threat_detection {
            if let Some(threat) = self.monitor.check_threat(packet) {
                self.stats.threats_detected += 1;
                self.stats.tier2_decisions += 1;
                return PacketAction::Alert(threat);
            }
        }

        // Extract destination (simplified)
        let dest = self.extract_destination(packet);

        // Check if it's for us
        if dest == self.config.local_id {
            PacketAction::Deliver
        } else if dest.is_zero() {
            // Broadcast
            PacketAction::Deliver
        } else {
            // Forward decision - in real impl would check routing table
            PacketAction::Forward(dest)
        }
    }

    /// Send packet
    pub fn send(&mut self, dest: NodeId, payload: &[u8]) -> Result<(), NicError> {
        if self.state != NicState::Active {
            return Err(NicError::InvalidState);
        }

        self.stats.tx_packets += 1;
        self.stats.tx_bytes += payload.len() as u64;

        // In real implementation, this would:
        // 1. Build AXIOM frame
        // 2. Apply trust/encryption
        // 3. Write to hardware

        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> NicState {
        self.state
    }

    /// Get statistics
    pub fn stats(&self) -> &NicStats {
        &self.stats
    }

    /// Get trust engine
    pub fn trust(&self) -> &TrustEngine {
        &self.trust
    }

    /// Get mutable trust engine
    pub fn trust_mut(&mut self) -> &mut TrustEngine {
        &mut self.trust
    }

    /// Get gateway (if bridging enabled)
    pub fn gateway(&self) -> Option<&Gateway> {
        self.gateway.as_ref()
    }

    /// Get mutable gateway
    pub fn gateway_mut(&mut self) -> Option<&mut Gateway> {
        self.gateway.as_mut()
    }

    /// Extract source identity from packet (simplified)
    fn extract_source(&self, packet: &[u8]) -> NodeId {
        if packet.len() >= 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&packet[0..32]);
            NodeId::from_bytes(id)
        } else {
            NodeId::zero()
        }
    }

    /// Extract destination identity from packet (simplified)
    fn extract_destination(&self, packet: &[u8]) -> NodeId {
        if packet.len() >= 64 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&packet[32..64]);
            NodeId::from_bytes(id)
        } else {
            NodeId::zero()
        }
    }
}

/// Packet processing action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketAction {
    /// Deliver to local application
    Deliver,
    /// Forward to another node
    Forward(NodeId),
    /// Drop the packet
    Drop,
    /// Alert: threat detected
    Alert(String),
}

/// NIC errors
#[derive(Debug, thiserror::Error)]
pub enum NicError {
    #[error("Driver not found in database")]
    DriverNotFound,

    #[error("Failed to load driver")]
    DriverLoadFailed,

    #[error("Invalid state for this operation")]
    InvalidState,

    #[error("Hardware error: {0}")]
    Hardware(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(n: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = n;
        NodeId::from_bytes(id)
    }

    #[test]
    fn test_nic_lifecycle() {
        let config = ForgeNicConfig {
            local_id: test_node_id(1),
            ..Default::default()
        };

        let mut nic = ForgeNic::new(config);
        assert_eq!(nic.state(), NicState::Uninitialized);

        nic.init_auto().unwrap();
        assert_eq!(nic.state(), NicState::Ready);

        nic.start().unwrap();
        assert_eq!(nic.state(), NicState::Active);

        nic.stop().unwrap();
        assert_eq!(nic.state(), NicState::Paused);
    }

    #[test]
    fn test_packet_receive() {
        let config = ForgeNicConfig {
            local_id: test_node_id(1),
            enable_threat_detection: false,
            ..Default::default()
        };

        let mut nic = ForgeNic::new(config);
        nic.init_auto().unwrap();
        nic.start().unwrap();

        // Create fake packet with source ID
        let mut packet = vec![0u8; 64];
        packet[0] = 1; // Source ID matches local

        let action = nic.receive(&packet, 1000);
        assert!(matches!(action, PacketAction::Deliver | PacketAction::Forward(_) | PacketAction::Drop));

        assert_eq!(nic.stats().rx_packets, 1);
    }

    #[test]
    fn test_stats_accumulation() {
        let config = ForgeNicConfig {
            local_id: test_node_id(1),
            ..Default::default()
        };

        let mut nic = ForgeNic::new(config);
        nic.init_auto().unwrap();
        nic.start().unwrap();

        // Receive multiple packets
        for i in 0..100 {
            let packet = vec![0u8; 100];
            nic.receive(&packet, i);
        }

        assert_eq!(nic.stats().rx_packets, 100);
        assert_eq!(nic.stats().rx_bytes, 10000);
    }
}
