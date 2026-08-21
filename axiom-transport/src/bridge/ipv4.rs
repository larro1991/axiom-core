//! IPv4 Bridge
//!
//! Provides IPv4 packet parsing and construction for legacy network bridging.

use alloc::vec::Vec;
use core::fmt;

/// IPv4 address (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create address with offset from base
    pub fn with_offset(&self, offset: u32) -> Self {
        let base = u32::from_be_bytes(self.0);
        Self((base + offset).to_be_bytes())
    }

    /// Check if address is in subnet
    pub fn in_subnet(&self, subnet: &Ipv4Address, mask_bits: u8) -> bool {
        let mask = if mask_bits >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - mask_bits)
        };

        let self_val = u32::from_be_bytes(self.0);
        let subnet_val = u32::from_be_bytes(subnet.0);

        (self_val & mask) == (subnet_val & mask)
    }

    /// Is this a private IP address?
    pub fn is_private(&self) -> bool {
        // 10.0.0.0/8
        self.0[0] == 10 ||
        // 172.16.0.0/12
        (self.0[0] == 172 && (self.0[1] & 0xF0) == 16) ||
        // 192.168.0.0/16
        (self.0[0] == 192 && self.0[1] == 168)
    }

    /// Is this a loopback address?
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// IPv4 protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            n => Self::Unknown(n),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(p: IpProtocol) -> u8 {
        match p {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Unknown(n) => n,
        }
    }
}

/// Parsed IPv4 packet header
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    /// Version (should be 4)
    pub version: u8,
    /// Header length in 32-bit words
    pub ihl: u8,
    /// Differentiated Services Code Point
    pub dscp: u8,
    /// Explicit Congestion Notification
    pub ecn: u8,
    /// Total length including header
    pub total_length: u16,
    /// Identification
    pub identification: u16,
    /// Flags (3 bits)
    pub flags: u8,
    /// Fragment offset (13 bits)
    pub fragment_offset: u16,
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub protocol: IpProtocol,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src_addr: Ipv4Address,
    /// Destination address
    pub dst_addr: Ipv4Address,
}

impl Ipv4Header {
    /// Minimum header size (no options)
    pub const MIN_SIZE: usize = 20;

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        let ihl = data[0] & 0x0F;
        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return None;
        }

        Some(Self {
            version,
            ihl,
            dscp: (data[1] >> 2) & 0x3F,
            ecn: data[1] & 0x03,
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: (data[6] >> 5) & 0x07,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: IpProtocol::from(data[9]),
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_addr: Ipv4Address::new([data[12], data[13], data[14], data[15]]),
            dst_addr: Ipv4Address::new([data[16], data[17], data[18], data[19]]),
        })
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];

        buf[0] = (self.version << 4) | (self.ihl & 0x0F);
        buf[1] = (self.dscp << 2) | (self.ecn & 0x03);
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        buf[6] = (self.flags << 5) | ((self.fragment_offset >> 8) as u8 & 0x1F);
        buf[7] = (self.fragment_offset & 0xFF) as u8;
        buf[8] = self.ttl;
        buf[9] = self.protocol.into();
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(self.src_addr.as_bytes());
        buf[16..20].copy_from_slice(self.dst_addr.as_bytes());

        buf
    }

    /// Calculate header checksum
    pub fn calculate_checksum(&self) -> u16 {
        let data = self.serialize();
        let mut sum: u32 = 0;

        // Sum all 16-bit words, skipping checksum field
        for i in (0..20).step_by(2) {
            if i == 10 {
                continue; // Skip checksum field
            }
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        }

        // Fold carries
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }
}

/// Full IPv4 packet
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    /// Parse packet from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = Ipv4Header::parse(data)?;
        let header_len = header.header_len();

        // `total_length` is read straight off the wire in
        // `Ipv4Header::parse` with no relationship enforced to `header_len`
        // (itself derived from the also-attacker-controlled IHL field). A
        // crafted header with, e.g., IHL=5 (header_len=20) and
        // total_length=0 previously slid straight through the
        // `data.len() < total_length` check below (0 is never less than
        // data.len()) and then panicked a few lines down on
        // `data[header_len..header.total_length as usize]` -
        // `data[20..0]`, a slice with start > end. Peer-triggerable process
        // kill under this workspace's panic=abort - reject it here instead.
        if (header.total_length as usize) < header_len {
            return None;
        }

        if data.len() < header.total_length as usize {
            return None;
        }

        let options = if header_len > Ipv4Header::MIN_SIZE {
            data[Ipv4Header::MIN_SIZE..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = data[header_len..header.total_length as usize].to_vec();

        Some(Self {
            header,
            options,
            payload,
        })
    }

    /// Create a new packet
    pub fn new(src: Ipv4Address, dst: Ipv4Address, protocol: IpProtocol, payload: Vec<u8>) -> Self {
        let total_length = (Ipv4Header::MIN_SIZE + payload.len()) as u16;

        let mut header = Ipv4Header {
            version: 4,
            ihl: 5, // No options
            dscp: 0,
            ecn: 0,
            total_length,
            identification: 0,
            flags: 0x02, // Don't fragment
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_addr: src,
            dst_addr: dst,
        };

        header.checksum = header.calculate_checksum();

        Self {
            header,
            options: Vec::new(),
            payload,
        }
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.header.total_length as usize);
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.options);
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// IPv4 bridge for AXIOM integration
#[derive(Debug)]
pub struct Ipv4Bridge {
    /// Local address for bridge
    local_addr: Ipv4Address,
    /// Subnet mask
    subnet_mask: u8,
    /// Gateway address
    gateway: Option<Ipv4Address>,
    /// MTU
    mtu: u16,
}

impl Ipv4Bridge {
    pub fn new(local_addr: Ipv4Address, subnet_mask: u8) -> Self {
        Self {
            local_addr,
            subnet_mask,
            gateway: None,
            mtu: 1500,
        }
    }

    pub fn with_gateway(mut self, gateway: Ipv4Address) -> Self {
        self.gateway = Some(gateway);
        self
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Check if address is in local subnet
    pub fn is_local(&self, addr: &Ipv4Address) -> bool {
        addr.in_subnet(&self.local_addr, self.subnet_mask)
    }

    /// Get next hop for destination
    pub fn next_hop(&self, dst: &Ipv4Address) -> Option<Ipv4Address> {
        if self.is_local(dst) {
            Some(*dst) // Direct delivery
        } else {
            self.gateway // Via gateway
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> Ipv4Address {
        self.local_addr
    }

    /// Get MTU
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address() {
        let addr = Ipv4Address::new([192, 168, 1, 100]);
        assert_eq!(addr.octets(), [192, 168, 1, 100]);
        assert!(addr.is_private());
        assert!(!addr.is_loopback());

        let loopback = Ipv4Address::LOCALHOST;
        assert!(loopback.is_loopback());
    }

    #[test]
    fn test_ipv4_subnet() {
        let addr = Ipv4Address::new([192, 168, 1, 100]);
        let subnet = Ipv4Address::new([192, 168, 1, 0]);

        assert!(addr.in_subnet(&subnet, 24));
        assert!(addr.in_subnet(&subnet, 16));
        assert!(!Ipv4Address::new([192, 168, 2, 100]).in_subnet(&subnet, 24));
    }

    #[test]
    fn test_ipv4_offset() {
        let base = Ipv4Address::new([10, 0, 0, 0]);
        let addr = base.with_offset(42);
        assert_eq!(addr.octets(), [10, 0, 0, 42]);

        let addr2 = base.with_offset(256);
        assert_eq!(addr2.octets(), [10, 0, 1, 0]);
    }

    #[test]
    fn test_header_parse() {
        // Minimal IPv4 header
        let data = [
            0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, ECN, Total Length
            0x00, 0x01, 0x40, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum
            0xC0, 0xA8, 0x01, 0x01, // Source: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // Dest: 192.168.1.2
        ];

        let header = Ipv4Header::parse(&data).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.ihl, 5);
        assert_eq!(header.total_length, 40);
        assert_eq!(header.ttl, 64);
        assert!(matches!(header.protocol, IpProtocol::Tcp));
        assert_eq!(header.src_addr.octets(), [192, 168, 1, 1]);
        assert_eq!(header.dst_addr.octets(), [192, 168, 1, 2]);
    }

    #[test]
    fn test_packet_roundtrip() {
        let packet = Ipv4Packet::new(
            Ipv4Address::new([10, 0, 0, 1]),
            Ipv4Address::new([10, 0, 0, 2]),
            IpProtocol::Udp,
            vec![1, 2, 3, 4, 5],
        );

        let serialized = packet.serialize();
        let parsed = Ipv4Packet::parse(&serialized).unwrap();

        assert_eq!(parsed.header.src_addr, packet.header.src_addr);
        assert_eq!(parsed.header.dst_addr, packet.header.dst_addr);
        assert_eq!(parsed.payload, packet.payload);
    }

    #[test]
    fn test_bridge_routing() {
        let bridge = Ipv4Bridge::new(Ipv4Address::new([192, 168, 1, 100]), 24)
            .with_gateway(Ipv4Address::new([192, 168, 1, 1]));

        // Local address - direct delivery
        let local = Ipv4Address::new([192, 168, 1, 50]);
        assert!(bridge.is_local(&local));
        assert_eq!(bridge.next_hop(&local), Some(local));

        // Remote address - via gateway
        let remote = Ipv4Address::new([8, 8, 8, 8]);
        assert!(!bridge.is_local(&remote));
        assert_eq!(bridge.next_hop(&remote), Some(Ipv4Address::new([192, 168, 1, 1])));
    }

    /// B2: `Ipv4Packet::parse` must reject (not panic on) a crafted header
    /// where `total_length` is smaller than the header's own length -
    /// previously `data[header_len..total_length]` panicked with start >
    /// end (e.g. `data[20..0]`), a peer-triggerable process kill under this
    /// workspace's panic=abort.
    #[test]
    fn test_parse_rejects_total_length_shorter_than_header() {
        // IHL=5 -> header_len=20, total_length=0.
        let mut data = [
            0x45, 0x00, 0x00, 0x00, // Version/IHL, DSCP/ECN, Total Length = 0
            0x00, 0x01, 0x40, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum
            0xC0, 0xA8, 0x01, 0x01, // Source: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // Dest: 192.168.1.2
        ];
        assert!(
            Ipv4Packet::parse(&data).is_none(),
            "total_length=0 (< header_len=20) must be rejected, not panic"
        );

        // total_length = 10: positive, still shorter than the 20-byte
        // minimum header - same class of bug, different magnitude.
        data[2] = 0x00;
        data[3] = 0x0A;
        assert!(
            Ipv4Packet::parse(&data).is_none(),
            "total_length=10 (< header_len=20) must be rejected, not panic"
        );
    }
}
