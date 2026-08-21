//! Frame types and header definitions

use crate::clock::HybridClock;
use crate::crypto::{IntentHash, NodeId, SessionToken, Signature, TraceId};
use crate::payload::PayloadType;
use crate::trust::TrustLevel;

/// Frame type identifier (5 bits, 0-31)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Request a capability
    Intent = 0x00,
    /// Response to an intent
    Fulfill = 0x01,
    /// Continuous data transfer
    Stream = 0x02,
    /// Clock synchronization
    Sync = 0x03,
    /// Trust negotiation
    Trust = 0x04,
    /// Routing table update
    Route = 0x05,
    /// Compression negotiation
    Compress = 0x06,
    /// Legacy protocol encapsulation
    Bridge = 0x07,
    /// Capability advertisement
    Announce = 0x08,
    /// Flow control / back-pressure
    Flow = 0x09,
    /// Error notification
    Error = 0x0A,
    /// Large payload fragment
    Fragment = 0x0B,
    /// Liveness check
    Ping = 0x0C,
    /// Liveness response
    Pong = 0x0D,
    /// Acknowledgment (reliability layer)
    Ack = 0x0E,
    /// Negative acknowledgment / retransmit request
    Nack = 0x0F,
    /// Mesh join request/response
    Join = 0x10,
    /// Mesh leave notification
    Leave = 0x11,
    /// Unknown/reserved frame type
    Reserved(u8),
}

impl FrameType {
    /// Convert from raw u8 value
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::Intent,
            0x01 => Self::Fulfill,
            0x02 => Self::Stream,
            0x03 => Self::Sync,
            0x04 => Self::Trust,
            0x05 => Self::Route,
            0x06 => Self::Compress,
            0x07 => Self::Bridge,
            0x08 => Self::Announce,
            0x09 => Self::Flow,
            0x0A => Self::Error,
            0x0B => Self::Fragment,
            0x0C => Self::Ping,
            0x0D => Self::Pong,
            0x0E => Self::Ack,
            0x0F => Self::Nack,
            0x10 => Self::Join,
            0x11 => Self::Leave,
            v => Self::Reserved(v),
        }
    }

    /// Convert to raw u8 value
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Intent => 0x00,
            Self::Fulfill => 0x01,
            Self::Stream => 0x02,
            Self::Sync => 0x03,
            Self::Trust => 0x04,
            Self::Route => 0x05,
            Self::Compress => 0x06,
            Self::Bridge => 0x07,
            Self::Announce => 0x08,
            Self::Flow => 0x09,
            Self::Error => 0x0A,
            Self::Fragment => 0x0B,
            Self::Ping => 0x0C,
            Self::Pong => 0x0D,
            Self::Ack => 0x0E,
            Self::Nack => 0x0F,
            Self::Join => 0x10,
            Self::Leave => 0x11,
            Self::Reserved(v) => v,
        }
    }

    /// Check if this frame type requires an intent hash
    pub fn requires_intent_hash(self) -> bool {
        matches!(
            self,
            Self::Intent | Self::Fulfill | Self::Stream | Self::Flow
        )
    }

    /// Check if this is a control frame (vs data frame)
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::Sync
                | Self::Trust
                | Self::Route
                | Self::Compress
                | Self::Announce
                | Self::Flow
                | Self::Error
                | Self::Ping
                | Self::Pong
                | Self::Ack
                | Self::Nack
                | Self::Join
                | Self::Leave
        )
    }
}

/// Priority level (2 bits, 0-3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    /// Background traffic
    Low = 0,
    /// Standard priority
    Normal = 1,
    /// Elevated priority
    High = 2,
    /// Highest priority
    Critical = 3,
}

impl Priority {
    /// Convert from raw u8 value
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::Low,
            1 => Self::Normal,
            2 => Self::High,
            3 => Self::Critical,
            _ => unreachable!(),
        }
    }

    /// Convert to raw u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Frame flags (3 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FrameFlags {
    /// Payload is encrypted
    pub encrypted: bool,
    /// Payload is compressed
    pub compressed: bool,
    /// Frame is fragmented
    pub fragmented: bool,
}

impl FrameFlags {
    /// Create flags from raw u8 (uses lower 3 bits)
    pub fn from_u8(value: u8) -> Self {
        Self {
            encrypted: (value & 0b001) != 0,
            compressed: (value & 0b010) != 0,
            fragmented: (value & 0b100) != 0,
        }
    }

    /// Convert to raw u8
    pub fn to_u8(self) -> u8 {
        let mut value = 0u8;
        if self.encrypted {
            value |= 0b001;
        }
        if self.compressed {
            value |= 0b010;
        }
        if self.fragmented {
            value |= 0b100;
        }
        value
    }
}

/// Fragment information (present when FrameFlags::fragmented is true)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentInfo {
    /// Fragment sequence number (0-indexed)
    pub sequence: u16,
    /// Total number of fragments
    pub total: u16,
}

impl FragmentInfo {
    pub fn new(sequence: u16, total: u16) -> Self {
        Self { sequence, total }
    }

    /// Check if this is the first fragment
    pub fn is_first(&self) -> bool {
        self.sequence == 0
    }

    /// Check if this is the last fragment
    pub fn is_last(&self) -> bool {
        self.sequence + 1 == self.total
    }
}

/// Multi-hop routing extension (AXIOM-14 Cycle 1a) - present when a frame
/// should be forwarded toward a specific node rather than handled/answered
/// by whichever direct peer receives it first (the existing, still-default
/// behavior when this extension is absent). Wire-only in this cycle: no
/// forwarding logic reads or acts on this yet (Cycle 1b).
///
/// `ttl` is deliberately EXCLUDED from what gets signed (see
/// `axiom_codec::Encoder::signature_data`) - a relay must be able to
/// decrement it without invalidating the original sender's signature.
/// `destination` stays signed - a relay must not be able to silently
/// redirect a frame to a different destination without detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingExt {
    /// The node this frame is ultimately addressed to.
    pub destination: NodeId,
    /// Hop budget. A relay forwarding this frame must decrement it and
    /// drop the frame instead of forwarding once it reaches 0.
    pub ttl: u8,
}

impl RoutingExt {
    pub fn new(destination: NodeId, ttl: u8) -> Self {
        Self { destination, ttl }
    }
}

/// Fixed frame header (58 bytes on wire)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version (1 for current)
    pub version: u8,
    /// Type of frame
    pub frame_type: FrameType,
    /// Frame flags (encrypted, compressed, fragmented)
    pub flags: FrameFlags,
    /// Trust level for authentication
    pub trust_level: TrustLevel,
    /// Priority for routing/queuing
    pub priority: Priority,
    /// Causal clock timestamp
    pub clock: HybridClock,
    /// Hash of the intent descriptor (or zero)
    pub intent_hash: IntentHash,
    /// Sender's node identity
    pub sender_id: NodeId,
}

impl FrameHeader {
    /// Create a new frame header with defaults
    pub fn new(frame_type: FrameType, sender_id: NodeId) -> Self {
        Self {
            version: crate::PROTOCOL_VERSION,
            frame_type,
            flags: FrameFlags::default(),
            trust_level: TrustLevel::default(),
            priority: Priority::default(),
            clock: HybridClock::zero(),
            intent_hash: IntentHash::zero(),
            sender_id,
        }
    }

    /// Set the intent hash
    pub fn with_intent(mut self, intent_hash: IntentHash) -> Self {
        self.intent_hash = intent_hash;
        self
    }

    /// Set the clock
    pub fn with_clock(mut self, clock: HybridClock) -> Self {
        self.clock = clock;
        self
    }

    /// Set the trust level
    pub fn with_trust_level(mut self, trust_level: TrustLevel) -> Self {
        self.trust_level = trust_level;
        self
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Set flags
    pub fn with_flags(mut self, flags: FrameFlags) -> Self {
        self.flags = flags;
        self
    }
}

impl Default for FrameHeader {
    fn default() -> Self {
        Self {
            version: crate::PROTOCOL_VERSION,
            frame_type: FrameType::Intent,
            flags: FrameFlags::default(),
            trust_level: TrustLevel::default(),
            priority: Priority::default(),
            clock: HybridClock::zero(),
            intent_hash: IntentHash::zero(),
            sender_id: NodeId::zero(),
        }
    }
}

/// Payload header (4 bytes on wire)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Type of payload
    pub payload_type: PayloadType,
    /// Length of payload in bytes (up to 16 MB)
    pub length: u32,
    /// Type-specific flags
    pub flags: u8,
}

impl PayloadHeader {
    pub fn new(payload_type: PayloadType, length: u32) -> Self {
        Self {
            payload_type,
            length,
            flags: 0,
        }
    }

    /// Check if trace ID is present (flag bit 0)
    pub fn has_trace_id(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Set trace ID flag
    pub fn with_trace_id(mut self) -> Self {
        self.flags |= 0x01;
        self
    }
}

/// Authentication data appended to frames
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// Full signature (TrustLevel 0 or 1)
    Signature(Signature),
    /// Compressed token (TrustLevel 2)
    Token(SessionToken),
    /// No authentication (TrustLevel 3)
    None,
}

impl Authentication {
    /// Get the wire size of this authentication
    pub fn wire_size(&self) -> usize {
        match self {
            Self::Signature(_) => crate::SIGNATURE_SIZE,
            Self::Token(_) => crate::SESSION_TOKEN_SIZE,
            Self::None => 0,
        }
    }
}

/// Complete AXIOM frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Fixed header fields
    pub header: FrameHeader,
    /// Optional trace ID
    pub trace_id: Option<TraceId>,
    /// Optional multi-hop routing extension - absent means today's existing
    /// "any directly-capable peer" semantics, unchanged. See `RoutingExt`.
    pub routing: Option<RoutingExt>,
    /// Optional fragment info
    pub fragment_info: Option<FragmentInfo>,
    /// Payload header
    pub payload_header: PayloadHeader,
    /// Raw payload bytes
    pub payload: alloc::vec::Vec<u8>,
    /// Authentication
    pub auth: Authentication,
}

impl Frame {
    /// Create a new frame
    pub fn new(header: FrameHeader, payload_type: PayloadType, payload: alloc::vec::Vec<u8>) -> Self {
        let auth = match header.trust_level {
            TrustLevel::Full | TrustLevel::Sig => Authentication::Signature(Signature::zero()),
            TrustLevel::Compress => Authentication::Token(SessionToken::zero()),
            TrustLevel::Raw => Authentication::None,
        };

        Self {
            header,
            trace_id: None,
            routing: None,
            fragment_info: None,
            payload_header: PayloadHeader::new(payload_type, payload.len() as u32),
            payload,
            auth,
        }
    }

    /// Set a multi-hop routing destination and TTL. See `RoutingExt`.
    pub fn with_routing(mut self, destination: NodeId, ttl: u8) -> Self {
        self.routing = Some(RoutingExt::new(destination, ttl));
        self
    }

    /// Calculate total wire size of this frame
    pub fn wire_size(&self) -> usize {
        let mut size = crate::FIXED_HEADER_SIZE; // 58 bytes

        // Extended header
        if self.trace_id.is_some() {
            size += crate::TRACE_ID_SIZE;
        }
        if self.routing.is_some() {
            size += crate::ROUTING_EXT_SIZE;
        }
        if self.fragment_info.is_some() {
            size += 4; // FragSeq (2) + FragTotal (2)
        }

        // Payload header + payload
        size += 4; // PayloadHeader
        size += self.payload.len();

        // Authentication
        size += self.auth.wire_size();

        size
    }

    /// Set trace ID
    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self.payload_header = self.payload_header.with_trace_id();
        self
    }

    /// Set fragment info
    pub fn with_fragment_info(mut self, info: FragmentInfo) -> Self {
        self.fragment_info = Some(info);
        self.header.flags.fragmented = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        for i in 0..=0x0F {
            let ft = FrameType::from_u8(i);
            assert_eq!(ft.to_u8(), i);
        }
    }

    #[test]
    fn test_frame_flags_roundtrip() {
        for i in 0..8 {
            let flags = FrameFlags::from_u8(i);
            assert_eq!(flags.to_u8(), i);
        }
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::Critical);
    }

    #[test]
    fn test_frame_wire_size() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![0u8; 100]);

        // 58 (fixed header) + 4 (payload header) + 100 (payload) + 0 (auth) = 162
        assert_eq!(frame.wire_size(), 162);
    }

    #[test]
    fn test_frame_wire_size_with_sig() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::zero())
            .with_trust_level(TrustLevel::Sig);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![0u8; 100]);

        // 58 + 4 + 100 + 64 (signature) = 226
        assert_eq!(frame.wire_size(), 226);
    }
}
