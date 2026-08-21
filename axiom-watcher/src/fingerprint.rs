//! Host fingerprinting
//!
//! Identifies hosts by their traffic behavior patterns.

use alloc::string::String;
use alloc::vec::Vec;

/// Operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    /// Windows
    Windows,
    /// Linux
    Linux,
    /// macOS
    MacOs,
    /// iOS
    Ios,
    /// Android
    Android,
    /// Network device
    NetworkDevice,
    /// IoT device
    IoT,
    /// Unknown
    Unknown,
}

/// Device role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    /// Workstation
    Workstation,
    /// Server
    Server,
    /// Mobile device
    Mobile,
    /// Network infrastructure
    Infrastructure,
    /// IoT/Embedded
    IoT,
    /// Unknown
    Unknown,
}

/// A host fingerprint
#[derive(Debug, Clone)]
pub struct HostFingerprint {
    /// IP address
    pub ip: [u8; 4],
    /// Likely OS type
    pub os_type: OsType,
    /// OS confidence (0.0-1.0)
    pub os_confidence: f64,
    /// Device role
    pub role: DeviceRole,
    /// Role confidence
    pub role_confidence: f64,
    /// Common ports accessed (client behavior)
    pub client_ports: Vec<u16>,
    /// Ports listening on (server behavior)
    pub server_ports: Vec<u16>,
    /// Average TTL observed
    pub avg_ttl: u8,
    /// Common protocols
    pub protocols: Vec<u8>,
    /// Traffic volume (bytes)
    pub traffic_volume: u64,
    /// First seen
    pub first_seen: u64,
    /// Last seen
    pub last_seen: u64,
    /// Observation count
    pub observations: u64,
}

impl HostFingerprint {
    /// Create new fingerprint
    pub fn new(ip: [u8; 4], timestamp: u64) -> Self {
        Self {
            ip,
            os_type: OsType::Unknown,
            os_confidence: 0.0,
            role: DeviceRole::Unknown,
            role_confidence: 0.0,
            client_ports: Vec::new(),
            server_ports: Vec::new(),
            avg_ttl: 0,
            protocols: Vec::new(),
            traffic_volume: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            observations: 0,
        }
    }

    /// Get fingerprint signature (for comparison)
    pub fn signature(&self) -> String {
        alloc::format!(
            "{:?}|{:?}|ttl:{}|ports:{:?}",
            self.os_type,
            self.role,
            self.avg_ttl,
            &self.client_ports[..self.client_ports.len().min(5)]
        )
    }
}

/// Fingerprint observation (raw data)
#[derive(Debug, Clone)]
struct FpObservation {
    /// Destination port
    dst_port: u16,
    /// Protocol
    protocol: u8,
    /// Packet size
    size: usize,
    /// Timestamp
    timestamp: u64,
    /// Is this host the source (client) or destination (server)
    is_source: bool,
}

/// Host fingerprinting database
#[cfg(feature = "std")]
pub struct FingerprintDatabase {
    /// Fingerprints by IP
    fingerprints: hashbrown::HashMap<[u8; 4], HostFingerprint>,
    /// Raw observations for analysis
    observations: hashbrown::HashMap<[u8; 4], Vec<FpObservation>>,
    /// Max observations to keep per host
    max_observations: usize,
    /// Port counts for role detection
    port_counts: hashbrown::HashMap<[u8; 4], hashbrown::HashMap<u16, u32>>,
    /// TTL observations
    ttl_observations: hashbrown::HashMap<[u8; 4], Vec<u8>>,
}

#[cfg(feature = "std")]
impl FingerprintDatabase {
    /// Create new database
    pub fn new() -> Self {
        Self {
            fingerprints: hashbrown::HashMap::new(),
            observations: hashbrown::HashMap::new(),
            max_observations: 1000,
            port_counts: hashbrown::HashMap::new(),
            ttl_observations: hashbrown::HashMap::new(),
        }
    }

    /// Observe traffic from/to a host
    pub fn observe(
        &mut self,
        src_ip: [u8; 4],
        dst_port: u16,
        protocol: u8,
        size: usize,
        timestamp: u64,
    ) {
        // Get or create fingerprint
        let fp = self.fingerprints
            .entry(src_ip)
            .or_insert_with(|| HostFingerprint::new(src_ip, timestamp));
        fp.last_seen = timestamp;
        fp.observations += 1;
        fp.traffic_volume += size as u64;

        // Record observation
        let obs = self.observations.entry(src_ip).or_insert_with(Vec::new);
        obs.push(FpObservation {
            dst_port,
            protocol,
            size,
            timestamp,
            is_source: true,
        });
        if obs.len() > self.max_observations {
            obs.remove(0);
        }

        // Track port access (client behavior)
        let ports = self.port_counts.entry(src_ip).or_insert_with(hashbrown::HashMap::new);
        *ports.entry(dst_port).or_insert(0) += 1;

        // Periodically update fingerprint
        if fp.observations % 50 == 0 {
            self.update_fingerprint(src_ip);
        }
    }

    /// Observe TTL (from IP header)
    pub fn observe_ttl(&mut self, ip: [u8; 4], ttl: u8) {
        let ttls = self.ttl_observations.entry(ip).or_insert_with(Vec::new);
        ttls.push(ttl);
        if ttls.len() > 100 {
            ttls.remove(0);
        }
    }

    /// Mark a port as server port (when we see incoming connections)
    pub fn mark_server_port(&mut self, ip: [u8; 4], port: u16, timestamp: u64) {
        let fp = self.fingerprints
            .entry(ip)
            .or_insert_with(|| HostFingerprint::new(ip, timestamp));

        if !fp.server_ports.contains(&port) {
            fp.server_ports.push(port);
            fp.server_ports.sort();
        }
    }

    /// Update fingerprint analysis
    fn update_fingerprint(&mut self, ip: [u8; 4]) {
        // Gather data first to avoid borrow issues
        let client_ports: Option<Vec<u16>> = self.port_counts.get(&ip).map(|ports| {
            let mut sorted: Vec<_> = ports.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            sorted.iter().take(10).map(|(&p, _)| p).collect()
        });

        let ttl_data: Option<u8> = self.ttl_observations.get(&ip).and_then(|ttls| {
            if ttls.is_empty() {
                None
            } else {
                let sum: u32 = ttls.iter().map(|&t| t as u32).sum();
                Some((sum / ttls.len() as u32) as u8)
            }
        });

        let protocols: Option<Vec<u8>> = self.observations.get(&ip).map(|obs| {
            let mut proto_counts: hashbrown::HashMap<u8, u32> = hashbrown::HashMap::new();
            for o in obs {
                *proto_counts.entry(o.protocol).or_insert(0) += 1;
            }
            let mut sorted: Vec<_> = proto_counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            sorted.iter().map(|(&p, _)| p).collect()
        });

        // Now update fingerprint
        let fp = match self.fingerprints.get_mut(&ip) {
            Some(f) => f,
            None => return,
        };

        // Update client ports
        if let Some(ports) = client_ports {
            fp.client_ports = ports;
        }

        // Update TTL and infer OS
        if let Some(avg_ttl) = ttl_data {
            fp.avg_ttl = avg_ttl;
            let (os, conf) = Self::infer_os_from_ttl_static(avg_ttl);
            fp.os_type = os;
            fp.os_confidence = conf;
        }

        // Infer role from behavior (clone needed data for static method)
        let role_data = (fp.server_ports.clone(), fp.client_ports.clone(), fp.observations);
        let (role, conf) = Self::infer_role_static(role_data);
        fp.role = role;
        fp.role_confidence = conf;

        // Update protocols
        if let Some(protos) = protocols {
            fp.protocols = protos;
        }
    }

    /// Infer OS from TTL value (static version)
    fn infer_os_from_ttl_static(ttl: u8) -> (OsType, f64) {
        // Common initial TTLs:
        // - Windows: 128
        // - Linux/Android: 64
        // - macOS/iOS: 64
        // - Network devices: 255 or 64
        match ttl {
            120..=128 => (OsType::Windows, 0.7),
            55..=64 => (OsType::Linux, 0.5), // Could be Linux, macOS, or Android
            248..=255 => (OsType::NetworkDevice, 0.6),
            _ => (OsType::Unknown, 0.2),
        }
    }

    /// Infer device role from behavior (static version)
    /// Takes (server_ports, client_ports, observations)
    fn infer_role_static(data: (Vec<u16>, Vec<u16>, u64)) -> (DeviceRole, f64) {
        let (server_ports, client_ports, observations) = data;

        // Server indicators
        if !server_ports.is_empty() {
            // Check for common server ports
            let common_server_ports = [22, 80, 443, 445, 3306, 5432, 6379, 8080, 8443];
            let has_server_port = server_ports.iter()
                .any(|p| common_server_ports.contains(p));
            if has_server_port {
                return (DeviceRole::Server, 0.8);
            }
            return (DeviceRole::Server, 0.6);
        }

        // Mobile indicators
        let mobile_ports = [5223, 5228, 5229, 443]; // APNs, FCM
        let mobile_hits = client_ports.iter()
            .filter(|p| mobile_ports.contains(p))
            .count();
        if mobile_hits >= 2 {
            return (DeviceRole::Mobile, 0.6);
        }

        // IoT indicators (limited port diversity)
        if client_ports.len() <= 3 && observations > 100 {
            return (DeviceRole::IoT, 0.5);
        }

        // Workstation (diverse client activity)
        if client_ports.len() > 5 {
            return (DeviceRole::Workstation, 0.6);
        }

        (DeviceRole::Unknown, 0.2)
    }

    /// Get fingerprint for IP
    pub fn get(&self, ip: &[u8; 4]) -> Option<&HostFingerprint> {
        self.fingerprints.get(ip)
    }

    /// Get all fingerprints
    pub fn all(&self) -> impl Iterator<Item = &HostFingerprint> {
        self.fingerprints.values()
    }

    /// Count of fingerprinted hosts
    pub fn count(&self) -> usize {
        self.fingerprints.len()
    }

    /// Find similar hosts (potential clones/spoofs)
    pub fn find_similar(&self, ip: &[u8; 4]) -> Vec<[u8; 4]> {
        let target = match self.fingerprints.get(ip) {
            Some(f) => f,
            None => return Vec::new(),
        };

        let target_sig = target.signature();
        let mut similar = Vec::new();

        for (other_ip, fp) in &self.fingerprints {
            if other_ip == ip {
                continue;
            }
            if fp.signature() == target_sig {
                similar.push(*other_ip);
            }
        }

        similar
    }

    /// Detect anomalous fingerprint change
    pub fn check_fingerprint_change(
        &self,
        ip: &[u8; 4],
        new_ttl: u8,
    ) -> Option<String> {
        let fp = self.fingerprints.get(ip)?;

        // Check for significant TTL change (could indicate spoofing)
        if fp.avg_ttl > 0 && fp.observations > 50 {
            let diff = (new_ttl as i16 - fp.avg_ttl as i16).unsigned_abs();
            if diff > 30 {
                return Some(alloc::format!(
                    "TTL change for {:?}: {} -> {} (possible spoof)",
                    ip, fp.avg_ttl, new_ttl
                ));
            }
        }

        None
    }
}

#[cfg(feature = "std")]
impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_creation() {
        let fp = HostFingerprint::new([192, 168, 1, 10], 1000);
        assert_eq!(fp.os_type, OsType::Unknown);
        assert_eq!(fp.observations, 0);
    }

    #[test]
    fn test_database_observation() {
        let mut db = FingerprintDatabase::new();

        // Observe some traffic
        for i in 0..100 {
            db.observe([192, 168, 1, 10], 443, 6, 100, 1000 + i);
        }

        let fp = db.get(&[192, 168, 1, 10]).unwrap();
        assert!(fp.observations >= 100);
        assert!(fp.client_ports.contains(&443));
    }

    #[test]
    fn test_ttl_based_os_detection() {
        let mut db = FingerprintDatabase::new();

        // Observe traffic
        for i in 0..60 {
            db.observe([192, 168, 1, 10], 443, 6, 100, 1000 + i);
            db.observe_ttl([192, 168, 1, 10], 128); // Windows TTL
        }

        let fp = db.get(&[192, 168, 1, 10]).unwrap();
        assert_eq!(fp.os_type, OsType::Windows);
        assert!(fp.os_confidence > 0.5);
    }

    #[test]
    fn test_server_role_detection() {
        let mut db = FingerprintDatabase::new();

        // Mark as server
        db.mark_server_port([192, 168, 1, 10], 80, 1000);
        db.mark_server_port([192, 168, 1, 10], 443, 1000);

        // Observe enough traffic to trigger update
        for i in 0..60 {
            db.observe([192, 168, 1, 10], 80, 6, 100, 1000 + i);
        }

        let fp = db.get(&[192, 168, 1, 10]).unwrap();
        assert_eq!(fp.role, DeviceRole::Server);
    }

    #[test]
    fn test_ttl_change_detection() {
        let mut db = FingerprintDatabase::new();

        // Build baseline with TTL 64 (Linux)
        for i in 0..60 {
            db.observe([192, 168, 1, 10], 443, 6, 100, 1000 + i);
            db.observe_ttl([192, 168, 1, 10], 64);
        }

        // Check for dramatic TTL change
        let result = db.check_fingerprint_change(&[192, 168, 1, 10], 128);
        assert!(result.is_some());
    }

    #[test]
    fn test_similar_host_detection() {
        let mut db = FingerprintDatabase::new();

        // Create two hosts with same behavior
        for i in 0..60 {
            db.observe([192, 168, 1, 10], 443, 6, 100, 1000 + i);
            db.observe_ttl([192, 168, 1, 10], 64);

            db.observe([192, 168, 1, 20], 443, 6, 100, 1000 + i);
            db.observe_ttl([192, 168, 1, 20], 64);
        }

        let similar = db.find_similar(&[192, 168, 1, 10]);
        assert!(similar.contains(&[192, 168, 1, 20]));
    }
}
