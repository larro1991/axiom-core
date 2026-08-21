//! AXIOM Protocol Frame Codec
//!
//! Zero-copy encoding and decoding of AXIOM frames.
//!
//! # Example
//!
//! ```ignore
//! use axiom_codec::{Encoder, Decoder};
//! use axiom_types::*;
//!
//! // Encode a frame
//! let mut buffer = vec![0u8; 1024];
//! let frame = Frame::new(
//!     FrameHeader::new(FrameType::Intent, NodeId::zero()),
//!     PayloadType::Raw,
//!     vec![1, 2, 3],
//! );
//! let size = Encoder::encode(&frame, &mut buffer)?;
//!
//! // Decode a frame
//! let decoded = Decoder::decode(&buffer[..size])?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod decoder;
mod encoder;

pub use decoder::{Decoder, DecodedFrame};
pub use encoder::Encoder;

use axiom_types::error::CodecError;

/// Result type for codec operations
pub type CodecResult<T> = Result<T, CodecError>;

/// Minimum valid frame size (header + minimal payload header)
pub const MIN_FRAME_SIZE: usize = axiom_types::FIXED_HEADER_SIZE + 4;

/// Calculate the wire size for a frame
pub fn wire_size(
    payload_len: usize,
    trust_level: axiom_types::TrustLevel,
    has_trace_id: bool,
    is_fragmented: bool,
) -> usize {
    let mut size = axiom_types::FIXED_HEADER_SIZE;

    if has_trace_id {
        size += axiom_types::TRACE_ID_SIZE;
    }
    if is_fragmented {
        size += 4; // FragSeq + FragTotal
    }

    size += 4; // Payload header
    size += payload_len;
    size += trust_level.auth_overhead();

    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::*;
    use axiom_types::frame::{Authentication, FragmentInfo};

    #[test]
    fn test_roundtrip_minimal() {
        let header = FrameHeader::new(FrameType::Ping, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![]);

        let mut buffer = alloc::vec![0u8; 1024];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = Decoder::decode(&buffer[..size]).unwrap();
        assert_eq!(decoded.header.frame_type, FrameType::Ping);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_roundtrip_with_payload() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::zero())
            .with_trust_level(TrustLevel::Raw)
            .with_clock(HybridClock::new(1700000000, 42));

        let payload = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = Frame::new(header, PayloadType::Raw, payload.clone());

        let mut buffer = alloc::vec![0u8; 1024];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = Decoder::decode(&buffer[..size]).unwrap();
        assert_eq!(decoded.header.frame_type, FrameType::Intent);
        assert_eq!(decoded.header.clock.physical, 1700000000);
        assert_eq!(decoded.header.clock.logical, 42);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_roundtrip_with_signature() {
        let header = FrameHeader::new(FrameType::Fulfill, NodeId::zero())
            .with_trust_level(TrustLevel::Sig);

        let payload = alloc::vec![1, 2, 3, 4, 5];
        let mut frame = Frame::new(header, PayloadType::Tensor, payload.clone());
        frame.auth = Authentication::Signature(Signature::from_bytes([0xAB; 64]));

        let mut buffer = alloc::vec![0u8; 1024];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = Decoder::decode(&buffer[..size]).unwrap();
        assert_eq!(decoded.header.trust_level, TrustLevel::Sig);
        match decoded.auth {
            Authentication::Signature(sig) => {
                assert_eq!(sig.as_bytes()[0], 0xAB);
            }
            _ => panic!("Expected signature"),
        }
    }

    #[test]
    fn test_roundtrip_with_trace_id() {
        let header = FrameHeader::new(FrameType::Stream, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);

        let frame = Frame::new(header, PayloadType::Embed, alloc::vec![0u8; 100])
            .with_trace_id(TraceId::from_u64(0x123456789ABCDEF0));

        let mut buffer = alloc::vec![0u8; 1024];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = Decoder::decode(&buffer[..size]).unwrap();
        assert_eq!(
            decoded.trace_id,
            Some(TraceId::from_u64(0x123456789ABCDEF0))
        );
    }

    #[test]
    fn test_roundtrip_fragmented() {
        let header = FrameHeader::new(FrameType::Fragment, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);

        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![0u8; 50])
            .with_fragment_info(FragmentInfo::new(3, 10));

        let mut buffer = alloc::vec![0u8; 1024];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = Decoder::decode(&buffer[..size]).unwrap();
        assert!(decoded.header.flags.fragmented);
        let frag = decoded.fragment_info.unwrap();
        assert_eq!(frag.sequence, 3);
        assert_eq!(frag.total, 10);
    }

    #[test]
    fn test_wire_size_calculation() {
        // Minimal: 58 (header) + 4 (payload header) + 0 (payload) + 0 (auth) = 62
        assert_eq!(wire_size(0, TrustLevel::Raw, false, false), 62);

        // With 100 byte payload: 62 + 100 = 162
        assert_eq!(wire_size(100, TrustLevel::Raw, false, false), 162);

        // With signature: 162 + 64 = 226
        assert_eq!(wire_size(100, TrustLevel::Sig, false, false), 226);

        // With trace ID: 162 + 8 = 170
        assert_eq!(wire_size(100, TrustLevel::Raw, true, false), 170);

        // With fragmentation: 162 + 4 = 166
        assert_eq!(wire_size(100, TrustLevel::Raw, false, true), 166);

        // All options: 62 + 8 + 4 + 100 + 64 = 238
        assert_eq!(wire_size(100, TrustLevel::Sig, true, true), 238);
    }
}
