//! Gateway Bridge
//!
//! Provides bidirectional translation between AXIOM and legacy IP networks.

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use axiom_types::NodeId;
use super::ipv4::Ipv4Address;

/// Gateway operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayMode {
    /// AXIOM → IP only (outbound gateway)
    AxiomToIp,
    /// IP → AXIOM only (inbound gateway)
    IpToAxiom,
    /// Full bidirectional (NAT-like)
    Bidirectional,
}

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Operating mode
    pub mode: GatewayMode,
    /// Public IP address for outbound traffic
    pub external_ip: Ipv4Address,
    /// AXIOM subnet we're bridging
    pub axiom_prefix: [u8; 16],
    /// Prefix length for AXIOM subnet
    pub axiom_prefix_len: u8,
    /// IP subnet for internal AXIOM-mapped addresses
    pub internal_subnet: Ipv4Address,
    /// Subnet mask (e.g., 24 for /24)
    pub subnet_mask: u8,
    /// Maximum concurrent translations
    pub max_translations: usize,
    /// Translation timeout (seconds)
    pub translation_timeout_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Bidirectional,
            external_ip: Ipv4Address::new([0, 0, 0, 0]),
            axiom_prefix: [0; 16],
            axiom_prefix_len: 0,
            internal_subnet: Ipv4Address::new([10, 0, 0, 0]),
            subnet_mask: 8,
            max_translations: 65536,
            translation_timeout_secs: 300,
        }
    }
}

/// Address translation entry
#[derive(Debug, Clone)]
pub struct TranslationEntry {
    /// AXIOM node ID
    pub node_id: NodeId,
    /// Mapped IPv4 address
    pub ipv4_addr: Ipv4Address,
    /// Port translations (AXIOM port -> IP port)
    pub port_map: HashMap<u16, u16>,
    /// Last activity timestamp (seconds since epoch)
    pub last_seen: u64,
    /// Bytes sent through this translation
    pub bytes_sent: u64,
    /// Bytes received through this translation
    pub bytes_received: u64,
}

/// Gateway for AXIOM ↔ IP translation
#[derive(Debug)]
pub struct Gateway {
    /// Configuration
    config: GatewayConfig,
    /// NodeId → Translation
    by_node: HashMap<NodeId, TranslationEntry>,
    /// IPv4 → NodeId
    by_ip: HashMap<Ipv4Address, NodeId>,
    /// Next available IP address (offset from subnet)
    next_ip_offset: u32,
    /// Statistics
    stats: GatewayStats,
}

/// Gateway statistics
#[derive(Debug, Default, Clone)]
pub struct GatewayStats {
    /// Packets translated AXIOM → IP
    pub axiom_to_ip_packets: u64,
    /// Packets translated IP → AXIOM
    pub ip_to_axiom_packets: u64,
    /// Bytes translated AXIOM → IP
    pub axiom_to_ip_bytes: u64,
    /// Bytes translated IP → AXIOM
    pub ip_to_axiom_bytes: u64,
    /// Active translations
    pub active_translations: usize,
    /// Translations expired
    pub translations_expired: u64,
    /// Translation table full events
    pub table_full_events: u64,
}

impl Gateway {
    /// Create new gateway with config
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            by_node: HashMap::new(),
            by_ip: HashMap::new(),
            next_ip_offset: 1,
            stats: GatewayStats::default(),
        }
    }

    /// Get or create translation for AXIOM node
    /// Returns true if entry already existed, false if newly created
    pub fn get_or_create_translation(&mut self, node_id: NodeId, now: u64) -> bool {
        // Check if already exists
        if self.by_node.contains_key(&node_id) {
            if let Some(entry) = self.by_node.get_mut(&node_id) {
                entry.last_seen = now;
            }
            return true;
        }

        // Check if table is full
        if self.by_node.len() >= self.config.max_translations {
            self.stats.table_full_events += 1;
            // Try to expire old entries
            self.expire_old_entries(now);
            if self.by_node.len() >= self.config.max_translations {
                return false;
            }
        }

        // Allocate new IP
        let ip = match self.allocate_ip() {
            Some(ip) => ip,
            None => return false,
        };

        let entry = TranslationEntry {
            node_id,
            ipv4_addr: ip,
            port_map: HashMap::new(),
            last_seen: now,
            bytes_sent: 0,
            bytes_received: 0,
        };

        self.by_ip.insert(ip, node_id);
        self.by_node.insert(node_id, entry);
        self.stats.active_translations = self.by_node.len();

        true
    }

    /// Ensure translation exists and return reference to it
    pub fn ensure_translation(&mut self, node_id: NodeId, now: u64) -> Option<&TranslationEntry> {
        if self.get_or_create_translation(node_id, now) {
            self.by_node.get(&node_id)
        } else {
            None
        }
    }

    /// Look up translation by AXIOM node
    pub fn lookup_by_node(&self, node_id: &NodeId) -> Option<&TranslationEntry> {
        self.by_node.get(node_id)
    }

    /// Look up translation by IPv4 address
    pub fn lookup_by_ip(&self, ip: &Ipv4Address) -> Option<&TranslationEntry> {
        let node_id = self.by_ip.get(ip)?;
        self.by_node.get(node_id)
    }

    /// Record outgoing (AXIOM → IP) traffic
    pub fn record_outgoing(&mut self, node_id: &NodeId, bytes: u64) {
        if let Some(entry) = self.by_node.get_mut(node_id) {
            entry.bytes_sent += bytes;
        }
        self.stats.axiom_to_ip_packets += 1;
        self.stats.axiom_to_ip_bytes += bytes;
    }

    /// Record incoming (IP → AXIOM) traffic
    pub fn record_incoming(&mut self, node_id: &NodeId, bytes: u64) {
        if let Some(entry) = self.by_node.get_mut(node_id) {
            entry.bytes_received += bytes;
        }
        self.stats.ip_to_axiom_packets += 1;
        self.stats.ip_to_axiom_bytes += bytes;
    }

    /// Get gateway statistics
    pub fn stats(&self) -> &GatewayStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Number of active translations
    pub fn active_translations(&self) -> usize {
        self.by_node.len()
    }

    /// Expire old translation entries
    fn expire_old_entries(&mut self, now: u64) {
        let timeout = self.config.translation_timeout_secs;
        let expired: Vec<NodeId> = self.by_node
            .iter()
            .filter(|(_, entry)| now - entry.last_seen > timeout)
            .map(|(id, _)| *id)
            .collect();

        for node_id in expired {
            if let Some(entry) = self.by_node.remove(&node_id) {
                self.by_ip.remove(&entry.ipv4_addr);
                self.stats.translations_expired += 1;
            }
        }
        self.stats.active_translations = self.by_node.len();
    }

    /// Allocate next available IP in subnet
    fn allocate_ip(&mut self) -> Option<Ipv4Address> {
        // Calculate max hosts in subnet
        let max_hosts = 1u32 << (32 - self.config.subnet_mask as u32);

        // Try to find unused IP
        for _ in 0..max_hosts {
            let offset = self.next_ip_offset;
            self.next_ip_offset = (self.next_ip_offset + 1) % max_hosts;
            if self.next_ip_offset == 0 {
                self.next_ip_offset = 1; // Skip network address
            }

            let ip = self.config.internal_subnet.with_offset(offset);
            if !self.by_ip.contains_key(&ip) {
                return Some(ip);
            }
        }

        None
    }
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
    fn test_gateway_basic() {
        let config = GatewayConfig {
            internal_subnet: Ipv4Address::new([10, 0, 0, 0]),
            subnet_mask: 24,
            ..Default::default()
        };

        let mut gateway = Gateway::new(config);
        let node = test_node_id(1);

        // Create translation
        assert!(gateway.get_or_create_translation(node, 1000));

        // Lookup should return entry
        let entry = gateway.lookup_by_node(&node).unwrap();
        assert_eq!(entry.node_id, node);

        // Can also lookup by IP
        let by_ip = gateway.lookup_by_ip(&entry.ipv4_addr).unwrap();
        assert_eq!(by_ip.node_id, node);
    }

    #[test]
    fn test_gateway_multiple_nodes() {
        let config = GatewayConfig {
            internal_subnet: Ipv4Address::new([192, 168, 1, 0]),
            subnet_mask: 24,
            ..Default::default()
        };

        let mut gateway = Gateway::new(config);

        // Create translations for multiple nodes
        for i in 1..=10 {
            let node = test_node_id(i);
            assert!(gateway.get_or_create_translation(node, 1000));
            let entry = gateway.lookup_by_node(&node).unwrap();
            assert_eq!(entry.node_id, node);
        }

        assert_eq!(gateway.active_translations(), 10);
    }

    #[test]
    fn test_gateway_expiration() {
        let config = GatewayConfig {
            internal_subnet: Ipv4Address::new([10, 0, 0, 0]),
            subnet_mask: 24,
            translation_timeout_secs: 100,
            ..Default::default()
        };

        let mut gateway = Gateway::new(config);
        let node = test_node_id(1);

        // Create at time 0
        gateway.get_or_create_translation(node, 0);
        assert_eq!(gateway.active_translations(), 1);

        // Should still exist at time 50
        gateway.expire_old_entries(50);
        assert_eq!(gateway.active_translations(), 1);

        // Should be expired at time 200
        gateway.expire_old_entries(200);
        assert_eq!(gateway.active_translations(), 0);
    }

    #[test]
    fn test_gateway_stats() {
        let config = GatewayConfig::default();
        let mut gateway = Gateway::new(config);
        let node = test_node_id(1);

        gateway.get_or_create_translation(node, 1000);
        gateway.record_outgoing(&node, 100);
        gateway.record_outgoing(&node, 200);
        gateway.record_incoming(&node, 50);

        let stats = gateway.stats();
        assert_eq!(stats.axiom_to_ip_packets, 2);
        assert_eq!(stats.axiom_to_ip_bytes, 300);
        assert_eq!(stats.ip_to_axiom_packets, 1);
        assert_eq!(stats.ip_to_axiom_bytes, 50);
    }
}
