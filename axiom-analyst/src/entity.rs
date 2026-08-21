//! Entity resolution and tracking
//!
//! Maintains a unified view of network entities (hosts, users, services).

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

/// Entity type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    /// Network host (IP)
    Host,
    /// MAC address
    MacAddress,
    /// User account
    User,
    /// Service/port
    Service,
    /// Network segment
    Segment,
}

/// A network entity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entity {
    /// Entity type
    pub entity_type: EntityType,
    /// Identifier (IP, MAC, username, etc.)
    pub identifier: String,
}

impl Entity {
    /// Create new entity
    pub fn new(entity_type: EntityType, identifier: String) -> Self {
        Self { entity_type, identifier }
    }

    /// Create from IP address
    pub fn from_ip(ip: [u8; 4]) -> Self {
        Self {
            entity_type: EntityType::Host,
            identifier: alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        }
    }

    /// Create from MAC address
    pub fn from_mac(mac: &[u8]) -> Self {
        if mac.len() >= 6 {
            Self {
                entity_type: EntityType::MacAddress,
                identifier: alloc::format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ),
            }
        } else {
            Self {
                entity_type: EntityType::MacAddress,
                identifier: "unknown".into(),
            }
        }
    }

    /// Create from user
    pub fn from_user(username: &str) -> Self {
        Self {
            entity_type: EntityType::User,
            identifier: username.into(),
        }
    }

    /// Create from service
    pub fn from_service(protocol: &str, port: u16) -> Self {
        Self {
            entity_type: EntityType::Service,
            identifier: alloc::format!("{}:{}", protocol, port),
        }
    }
}

/// Entity information
#[derive(Debug, Clone)]
pub struct EntityInfo {
    /// Entity
    pub entity: Entity,
    /// First seen
    pub first_seen: u64,
    /// Last seen
    pub last_seen: u64,
    /// Event count
    pub event_count: u64,
    /// Risk score (0-100)
    pub risk_score: f64,
    /// Related entities
    pub related: Vec<Entity>,
    /// Tags/labels
    pub tags: Vec<String>,
}

impl EntityInfo {
    /// Create new entity info
    pub fn new(entity: Entity, timestamp: u64) -> Self {
        Self {
            entity,
            first_seen: timestamp,
            last_seen: timestamp,
            event_count: 1,
            risk_score: 0.0,
            related: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Update info with new observation
    pub fn observe(&mut self, timestamp: u64) {
        self.last_seen = timestamp;
        self.event_count += 1;
    }

    /// Add related entity
    pub fn add_related(&mut self, entity: Entity) {
        if !self.related.contains(&entity) {
            self.related.push(entity);
        }
    }

    /// Add tag
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Update risk score
    pub fn update_risk(&mut self, delta: f64) {
        self.risk_score = (self.risk_score + delta).clamp(0.0, 100.0);
    }
}

/// Entity resolver - maintains unified view of entities
#[cfg(feature = "std")]
pub struct EntityResolver {
    /// Entity info by identifier
    entities: HashMap<String, EntityInfo>,
    /// IP to MAC mapping
    ip_to_mac: HashMap<String, String>,
    /// MAC to IP mapping
    mac_to_ip: HashMap<String, Vec<String>>,
}

#[cfg(feature = "std")]
impl EntityResolver {
    /// Create new resolver
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            ip_to_mac: HashMap::new(),
            mac_to_ip: HashMap::new(),
        }
    }

    /// Observe an entity
    pub fn observe_entity(&mut self, entity: Entity, timestamp: u64) {
        let key = entity.identifier.clone();
        if let Some(info) = self.entities.get_mut(&key) {
            info.observe(timestamp);
        } else {
            self.entities.insert(key, EntityInfo::new(entity, timestamp));
        }
    }

    /// Link IP to MAC
    pub fn link_ip_mac(&mut self, ip: &str, mac: &str) {
        self.ip_to_mac.insert(ip.into(), mac.into());
        self.mac_to_ip.entry(mac.into()).or_default().push(ip.into());
    }

    /// Get entity info
    pub fn get_info(&self, entity: &Entity) -> Option<&EntityInfo> {
        self.entities.get(&entity.identifier)
    }

    /// Get entity info mutable
    pub fn get_info_mut(&mut self, entity: &Entity) -> Option<&mut EntityInfo> {
        self.entities.get_mut(&entity.identifier)
    }

    /// Get MAC for IP
    pub fn mac_for_ip(&self, ip: &str) -> Option<&String> {
        self.ip_to_mac.get(ip)
    }

    /// Get IPs for MAC
    pub fn ips_for_mac(&self, mac: &str) -> Option<&Vec<String>> {
        self.mac_to_ip.get(mac)
    }

    /// Get all high-risk entities
    pub fn high_risk_entities(&self, threshold: f64) -> Vec<&EntityInfo> {
        self.entities.values()
            .filter(|e| e.risk_score >= threshold)
            .collect()
    }

    /// Update risk score for entity
    pub fn update_risk(&mut self, entity: &Entity, delta: f64) {
        if let Some(info) = self.entities.get_mut(&entity.identifier) {
            info.update_risk(delta);
        }
    }

    /// Add relationship between entities
    pub fn add_relationship(&mut self, entity1: &Entity, entity2: &Entity) {
        if let Some(info) = self.entities.get_mut(&entity1.identifier) {
            info.add_related(entity2.clone());
        }
        if let Some(info) = self.entities.get_mut(&entity2.identifier) {
            info.add_related(entity1.clone());
        }
    }

    /// Get entity count
    pub fn count(&self) -> usize {
        self.entities.len()
    }
}

#[cfg(feature = "std")]
impl Default for EntityResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_creation() {
        let ip_entity = Entity::from_ip([192, 168, 1, 10]);
        assert_eq!(ip_entity.entity_type, EntityType::Host);
        assert_eq!(ip_entity.identifier, "192.168.1.10");
    }

    #[test]
    fn test_mac_entity() {
        let mac = [0x00, 0x50, 0x56, 0x01, 0x02, 0x03];
        let entity = Entity::from_mac(&mac);
        assert_eq!(entity.entity_type, EntityType::MacAddress);
        assert_eq!(entity.identifier, "00:50:56:01:02:03");
    }

    #[test]
    fn test_entity_resolver() {
        let mut resolver = EntityResolver::new();
        let entity = Entity::from_ip([192, 168, 1, 10]);

        resolver.observe_entity(entity.clone(), 1000);
        resolver.observe_entity(entity.clone(), 2000);

        let info = resolver.get_info(&entity).unwrap();
        assert_eq!(info.event_count, 2);
        assert_eq!(info.first_seen, 1000);
        assert_eq!(info.last_seen, 2000);
    }

    #[test]
    fn test_risk_tracking() {
        let mut resolver = EntityResolver::new();
        let entity = Entity::from_ip([192, 168, 1, 10]);

        resolver.observe_entity(entity.clone(), 1000);
        resolver.update_risk(&entity, 50.0);

        let info = resolver.get_info(&entity).unwrap();
        assert_eq!(info.risk_score, 50.0);
    }
}
