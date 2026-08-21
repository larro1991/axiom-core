//! Protocol detection and classification
//!
//! Identifies application-layer protocols regardless of port number.

use alloc::string::String;
use alloc::vec::Vec;

/// Detected protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP (plaintext)
    Http,
    /// HTTPS/TLS
    Https,
    /// DNS
    Dns,
    /// SSH
    Ssh,
    /// SMTP
    Smtp,
    /// FTP
    Ftp,
    /// SMB/CIFS
    Smb,
    /// RDP
    Rdp,
    /// MySQL
    MySql,
    /// PostgreSQL
    PostgreSql,
    /// Redis
    Redis,
    /// LDAP
    Ldap,
    /// Kerberos
    Kerberos,
    /// NTP
    Ntp,
    /// SNMP
    Snmp,
    /// Unknown
    Unknown,
}

impl Protocol {
    /// Get default port for this protocol
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::Https => 443,
            Protocol::Dns => 53,
            Protocol::Ssh => 22,
            Protocol::Smtp => 25,
            Protocol::Ftp => 21,
            Protocol::Smb => 445,
            Protocol::Rdp => 3389,
            Protocol::MySql => 3306,
            Protocol::PostgreSql => 5432,
            Protocol::Redis => 6379,
            Protocol::Ldap => 389,
            Protocol::Kerberos => 88,
            Protocol::Ntp => 123,
            Protocol::Snmp => 161,
            Protocol::Unknown => 0,
        }
    }

    /// Check if this is an encrypted protocol
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Protocol::Https | Protocol::Ssh)
    }

    /// Check if this is a database protocol
    pub fn is_database(&self) -> bool {
        matches!(self, Protocol::MySql | Protocol::PostgreSql | Protocol::Redis)
    }
}

/// Protocol features extracted during detection
#[derive(Debug, Clone, Default)]
pub struct ProtocolFeatures {
    /// Protocol detected
    pub protocol: Option<Protocol>,
    /// Version if detected
    pub version: Option<String>,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
}

/// Protocol detector
pub struct ProtocolDetector {
    /// Enable deep inspection
    deep_inspection: bool,
}

impl ProtocolDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            deep_inspection: true,
        }
    }

    /// Detect protocol from payload
    pub fn detect(&self, payload: &[u8], port_hint: u16) -> Option<Protocol> {
        if payload.is_empty() {
            return None;
        }

        // Try signature-based detection first
        if let Some(proto) = self.detect_by_signature(payload) {
            return Some(proto);
        }

        // Fall back to port-based heuristics
        self.detect_by_port(port_hint)
    }

    /// Detect by payload signature
    fn detect_by_signature(&self, payload: &[u8]) -> Option<Protocol> {
        if payload.len() < 4 {
            return None;
        }

        // HTTP detection
        if self.is_http(payload) {
            return Some(Protocol::Http);
        }

        // TLS/HTTPS detection
        if self.is_tls(payload) {
            return Some(Protocol::Https);
        }

        // SSH detection
        if payload.starts_with(b"SSH-") {
            return Some(Protocol::Ssh);
        }

        // DNS detection (simple heuristic)
        if self.is_dns(payload) {
            return Some(Protocol::Dns);
        }

        // SMTP detection
        if payload.starts_with(b"220 ") ||
           payload.starts_with(b"EHLO") ||
           payload.starts_with(b"HELO") ||
           payload.starts_with(b"MAIL FROM") {
            return Some(Protocol::Smtp);
        }

        // FTP detection
        if payload.starts_with(b"220-") || payload.starts_with(b"USER ") {
            return Some(Protocol::Ftp);
        }

        // SMB detection
        if payload.len() >= 4 && payload[0..4] == [0xFF, b'S', b'M', b'B'] {
            return Some(Protocol::Smb);
        }
        // SMB2/3
        if payload.len() >= 4 && payload[0..4] == [0xFE, b'S', b'M', b'B'] {
            return Some(Protocol::Smb);
        }

        // MySQL detection
        if self.is_mysql(payload) {
            return Some(Protocol::MySql);
        }

        // PostgreSQL detection
        if self.is_postgresql(payload) {
            return Some(Protocol::PostgreSql);
        }

        // Redis detection
        if payload.starts_with(b"*") || payload.starts_with(b"+OK") || payload.starts_with(b"-ERR") {
            return Some(Protocol::Redis);
        }

        // LDAP detection (BER encoded)
        if payload.len() >= 2 && payload[0] == 0x30 {
            // Could be LDAP - would need deeper inspection
        }

        None
    }

    /// Check if payload looks like HTTP
    fn is_http(&self, payload: &[u8]) -> bool {
        // HTTP request methods
        let methods = [
            b"GET ".as_slice(),
            b"POST ".as_slice(),
            b"PUT ".as_slice(),
            b"DELETE ".as_slice(),
            b"HEAD ".as_slice(),
            b"OPTIONS ".as_slice(),
            b"PATCH ".as_slice(),
            b"CONNECT ".as_slice(),
        ];

        for method in methods {
            if payload.starts_with(method) {
                return true;
            }
        }

        // HTTP response
        if payload.starts_with(b"HTTP/") {
            return true;
        }

        false
    }

    /// Check if payload looks like TLS
    fn is_tls(&self, payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }

        // TLS record types
        let record_type = payload[0];
        let version_major = payload[1];
        let version_minor = payload[2];

        // Content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application
        if record_type >= 20 && record_type <= 23 {
            // TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303, TLS 1.3 = 0x0303
            if version_major == 0x03 && version_minor <= 0x04 {
                return true;
            }
        }

        false
    }

    /// Check if payload looks like DNS
    fn is_dns(&self, payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }

        // DNS header: ID (2) + Flags (2) + QCount (2) + ANCount (2) + NSCount (2) + ARCount (2)
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qcount = u16::from_be_bytes([payload[4], payload[5]]);

        // Check for reasonable DNS flags
        // QR bit (bit 15) determines query (0) or response (1)
        // OPCODE (bits 11-14) should be 0 for standard query
        let opcode = (flags >> 11) & 0x0F;
        if opcode > 2 {
            return false;
        }

        // Should have at least 1 question for queries
        if flags & 0x8000 == 0 && qcount == 0 {
            return false;
        }

        // Reasonable question count
        qcount > 0 && qcount < 20
    }

    /// Check if payload looks like MySQL
    fn is_mysql(&self, payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }

        // MySQL packet: 3-byte length + 1-byte sequence + payload
        // Server greeting starts with protocol version (usually 10)
        let _length = u32::from_le_bytes([payload[0], payload[1], payload[2], 0]);
        let _seq = payload[3];

        // Protocol version 10 is most common
        if payload.len() > 4 && payload[4] == 10 {
            return true;
        }

        false
    }

    /// Check if payload looks like PostgreSQL
    fn is_postgresql(&self, payload: &[u8]) -> bool {
        if payload.len() < 8 {
            return false;
        }

        // PostgreSQL startup message starts with length (4) + protocol version (4)
        // Protocol version 3.0 = 0x00030000
        let version = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if version == 0x00030000 {
            return true;
        }

        // Or it could be SSL request (special version)
        if version == 80877103 {
            return true;
        }

        false
    }

    /// Detect by port (fallback)
    fn detect_by_port(&self, port: u16) -> Option<Protocol> {
        match port {
            80 | 8080 | 8000 => Some(Protocol::Http),
            443 | 8443 => Some(Protocol::Https),
            53 => Some(Protocol::Dns),
            22 => Some(Protocol::Ssh),
            25 | 465 | 587 => Some(Protocol::Smtp),
            21 => Some(Protocol::Ftp),
            445 | 139 => Some(Protocol::Smb),
            3389 => Some(Protocol::Rdp),
            3306 => Some(Protocol::MySql),
            5432 => Some(Protocol::PostgreSql),
            6379 => Some(Protocol::Redis),
            389 | 636 => Some(Protocol::Ldap),
            88 => Some(Protocol::Kerberos),
            123 => Some(Protocol::Ntp),
            161 | 162 => Some(Protocol::Snmp),
            _ => None,
        }
    }

    /// Extract features from payload
    pub fn extract_features(&self, payload: &[u8], protocol: Protocol) -> ProtocolFeatures {
        let mut features = ProtocolFeatures {
            protocol: Some(protocol),
            version: None,
            metadata: Vec::new(),
        };

        if !self.deep_inspection {
            return features;
        }

        match protocol {
            Protocol::Http => self.extract_http_features(payload, &mut features),
            Protocol::Https => self.extract_tls_features(payload, &mut features),
            Protocol::Ssh => self.extract_ssh_features(payload, &mut features),
            Protocol::Dns => self.extract_dns_features(payload, &mut features),
            _ => {}
        }

        features
    }

    fn extract_http_features(&self, payload: &[u8], features: &mut ProtocolFeatures) {
        // Try to extract HTTP version and method
        if let Ok(text) = core::str::from_utf8(payload) {
            if let Some(line) = text.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if parts[0].starts_with("HTTP/") {
                        features.version = Some(parts[0].to_string());
                    } else {
                        features.metadata.push(("method".into(), parts[0].to_string()));
                        if parts.len() > 2 {
                            features.version = Some(parts[2].to_string());
                        }
                    }
                }
            }
        }
    }

    fn extract_tls_features(&self, payload: &[u8], features: &mut ProtocolFeatures) {
        if payload.len() >= 3 {
            let version = match (payload[1], payload[2]) {
                (0x03, 0x01) => "TLS 1.0",
                (0x03, 0x02) => "TLS 1.1",
                (0x03, 0x03) => "TLS 1.2/1.3",
                _ => "Unknown",
            };
            features.version = Some(version.into());
        }
    }

    fn extract_ssh_features(&self, payload: &[u8], features: &mut ProtocolFeatures) {
        if payload.starts_with(b"SSH-") {
            if let Ok(text) = core::str::from_utf8(payload) {
                if let Some(line) = text.lines().next() {
                    features.version = Some(line.to_string());
                }
            }
        }
    }

    fn extract_dns_features(&self, payload: &[u8], features: &mut ProtocolFeatures) {
        if payload.len() >= 12 {
            let flags = u16::from_be_bytes([payload[2], payload[3]]);
            let is_response = (flags & 0x8000) != 0;
            features.metadata.push(
                ("type".into(), if is_response { "response" } else { "query" }.into())
            );
        }
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection() {
        let detector = ProtocolDetector::new();

        assert_eq!(
            detector.detect(b"GET /index.html HTTP/1.1\r\n", 80),
            Some(Protocol::Http)
        );
        assert_eq!(
            detector.detect(b"POST /api/data HTTP/1.1\r\n", 8080),
            Some(Protocol::Http)
        );
        assert_eq!(
            detector.detect(b"HTTP/1.1 200 OK\r\n", 80),
            Some(Protocol::Http)
        );
    }

    #[test]
    fn test_ssh_detection() {
        let detector = ProtocolDetector::new();

        assert_eq!(
            detector.detect(b"SSH-2.0-OpenSSH_8.9\r\n", 22),
            Some(Protocol::Ssh)
        );
    }

    #[test]
    fn test_tls_detection() {
        let detector = ProtocolDetector::new();

        // TLS ClientHello (handshake type 22, version 3.1)
        let tls_hello = [0x16, 0x03, 0x01, 0x00, 0x05];
        assert_eq!(
            detector.detect(&tls_hello, 443),
            Some(Protocol::Https)
        );
    }

    #[test]
    fn test_port_fallback() {
        let detector = ProtocolDetector::new();

        // Unknown payload but known port
        assert_eq!(
            detector.detect(b"random data", 22),
            Some(Protocol::Ssh)
        );
        assert_eq!(
            detector.detect(b"random data", 3306),
            Some(Protocol::MySql)
        );
    }

    #[test]
    fn test_protocol_properties() {
        assert!(Protocol::Https.is_encrypted());
        assert!(!Protocol::Http.is_encrypted());
        assert!(Protocol::MySql.is_database());
        assert!(!Protocol::Http.is_database());
    }
}
