//! Frame decoder

use crate::{CodecResult, MIN_FRAME_SIZE};
use alloc::vec::Vec;
use axiom_types::clock::HybridClock;
use axiom_types::crypto::{IntentHash, NodeId, SessionToken, Signature, TraceId};
use axiom_types::error::CodecError;
use axiom_types::frame::{
    Authentication, FragmentInfo, FrameFlags, FrameHeader, FrameType, PayloadHeader, Priority,
    RoutingExt,
};
use axiom_types::payload::PayloadType;
use axiom_types::trust::TrustLevel;
use axiom_types::{
    CLOCK_SIZE, FIXED_HEADER_SIZE, INTENT_HASH_SIZE, MAGIC, NODE_ID_SIZE, PROTOCOL_VERSION,
    SESSION_TOKEN_SIZE, SIGNATURE_SIZE, TRACE_ID_SIZE,
};

/// Decoded frame with zero-copy payload reference option
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub header: FrameHeader,
    pub trace_id: Option<TraceId>,
    pub routing: Option<RoutingExt>,
    pub fragment_info: Option<FragmentInfo>,
    pub payload_header: PayloadHeader,
    pub payload: Vec<u8>,
    pub auth: Authentication,
}

/// Frame decoder with zero-copy support
pub struct Decoder;

impl Decoder {
    /// Decode a frame from the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns various `CodecError` variants for invalid frames.
    pub fn decode(buffer: &[u8]) -> CodecResult<DecodedFrame> {
        if buffer.len() < MIN_FRAME_SIZE {
            return Err(CodecError::BufferTooSmall {
                needed: MIN_FRAME_SIZE,
                have: buffer.len(),
            });
        }

        let mut offset = 0;

        // Decode fixed header (returns header, trace ID flag, routing flag)
        let (header, has_trace_id, has_routing) =
            Self::decode_fixed_header(&buffer[offset..offset + FIXED_HEADER_SIZE])?;
        offset += FIXED_HEADER_SIZE;

        let is_fragmented = header.flags.fragmented;

        // Decode trace ID if present
        let trace_id = if has_trace_id {
            if buffer.len() < offset + TRACE_ID_SIZE {
                return Err(CodecError::TruncatedFrame);
            }
            let mut trace_bytes = [0u8; TRACE_ID_SIZE];
            trace_bytes.copy_from_slice(&buffer[offset..offset + TRACE_ID_SIZE]);
            offset += TRACE_ID_SIZE;
            Some(TraceId::from_bytes(trace_bytes))
        } else {
            None
        };

        // Decode routing extension if present (AXIOM-14 Cycle 1a)
        let routing = if has_routing {
            if buffer.len() < offset + NODE_ID_SIZE + 1 {
                return Err(CodecError::TruncatedFrame);
            }
            let mut dest_bytes = [0u8; NODE_ID_SIZE];
            dest_bytes.copy_from_slice(&buffer[offset..offset + NODE_ID_SIZE]);
            offset += NODE_ID_SIZE;
            let ttl = buffer[offset];
            offset += 1;
            Some(RoutingExt::new(NodeId::from_bytes(dest_bytes), ttl))
        } else {
            None
        };

        // Decode fragment info if present
        let fragment_info = if is_fragmented {
            if buffer.len() < offset + 4 {
                return Err(CodecError::TruncatedFrame);
            }
            let sequence = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
            let total = u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]);
            offset += 4;
            Some(FragmentInfo::new(sequence, total))
        } else {
            None
        };

        // Decode payload header
        if buffer.len() < offset + 4 {
            return Err(CodecError::TruncatedFrame);
        }
        let payload_header = Self::decode_payload_header(&buffer[offset..offset + 4])?;
        offset += 4;

        // Validate payload length
        let payload_len = payload_header.length as usize;
        if payload_len > axiom_types::MAX_PAYLOAD_SIZE {
            return Err(CodecError::PayloadTooLarge(payload_len));
        }

        // Calculate expected auth size
        let auth_size = header.trust_level.auth_overhead();

        // Check total frame size
        let expected_total = offset + payload_len + auth_size;
        if buffer.len() < expected_total {
            return Err(CodecError::TruncatedFrame);
        }

        // Extract payload
        let payload = buffer[offset..offset + payload_len].to_vec();
        offset += payload_len;

        // Decode authentication
        let auth = Self::decode_auth(header.trust_level, &buffer[offset..offset + auth_size])?;

        Ok(DecodedFrame {
            header,
            trace_id,
            routing,
            fragment_info,
            payload_header,
            payload,
            auth,
        })
    }

    /// Decode only the header (useful for routing decisions)
    pub fn decode_header(buffer: &[u8]) -> CodecResult<FrameHeader> {
        if buffer.len() < FIXED_HEADER_SIZE {
            return Err(CodecError::BufferTooSmall {
                needed: FIXED_HEADER_SIZE,
                have: buffer.len(),
            });
        }
        let (header, _has_trace_id, _has_routing) =
            Self::decode_fixed_header(&buffer[..FIXED_HEADER_SIZE])?;
        Ok(header)
    }

    /// Decode the fixed header (58 bytes)
    /// Returns (header, has_trace_id, has_routing)
    fn decode_fixed_header(buffer: &[u8]) -> CodecResult<(FrameHeader, bool, bool)> {
        // Bytes 0-2: Packed fields
        let byte0 = buffer[0];
        let byte1 = buffer[1];
        let byte2 = buffer[2];

        // Extract magic
        let magic = byte0 >> 6;
        if magic != MAGIC {
            return Err(CodecError::InvalidMagic);
        }

        // Extract version
        let version = (byte0 >> 2) & 0x0F;
        if version != PROTOCOL_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }

        // Extract frame type (5 bits across byte0 and byte1)
        let frame_type_raw = ((byte0 & 0x03) << 3) | ((byte1 >> 5) & 0x07);
        let frame_type = FrameType::from_u8(frame_type_raw);

        // Extract flags (3 bits)
        let flags = FrameFlags::from_u8((byte1 >> 2) & 0x07);

        // Extract trust level (2 bits)
        let trust_level = TrustLevel::from_u8(byte1 & 0x03);

        // Extract priority (2 bits)
        let priority = Priority::from_u8(byte2 >> 6);

        // Extract trace ID flag (bit 5)
        let has_trace_id = (byte2 & 0x20) != 0;

        // Extract routing extension flag (bit 4) - AXIOM-14 Cycle 1a
        let has_routing = (byte2 & 0x10) != 0;

        // Bytes 3-9: CausalClock (7 bytes)
        let mut clock_bytes = [0u8; CLOCK_SIZE];
        clock_bytes.copy_from_slice(&buffer[3..3 + CLOCK_SIZE]);
        let clock = HybridClock::from_bytes(&clock_bytes);

        // Bytes 10-25: IntentHash (16 bytes)
        let mut intent_bytes = [0u8; INTENT_HASH_SIZE];
        intent_bytes.copy_from_slice(&buffer[10..10 + INTENT_HASH_SIZE]);
        let intent_hash = IntentHash::from_bytes(intent_bytes);

        // Bytes 26-57: SenderID (32 bytes)
        let mut sender_bytes = [0u8; NODE_ID_SIZE];
        sender_bytes.copy_from_slice(&buffer[26..26 + NODE_ID_SIZE]);
        let sender_id = NodeId::from_bytes(sender_bytes);

        Ok((
            FrameHeader {
                version,
                frame_type,
                flags,
                trust_level,
                priority,
                clock,
                intent_hash,
                sender_id,
            },
            has_trace_id,
            has_routing,
        ))
    }

    /// Decode payload header (4 bytes)
    fn decode_payload_header(buffer: &[u8]) -> CodecResult<PayloadHeader> {
        // Decode the packed format from encoder
        let type_and_len_high = buffer[0];
        let len_mid = buffer[1];
        let len_low_and_flags_high = buffer[2];
        let len_lowest_and_flags = buffer[3];

        let payload_type = PayloadType::from_u8(type_and_len_high >> 4);

        // Reconstruct 24-bit length
        let length = ((type_and_len_high as u32 & 0x0F) << 20)
            | ((len_mid as u32) << 12)
            | ((len_low_and_flags_high as u32) << 4)
            | ((len_lowest_and_flags as u32) >> 4);

        let flags = len_lowest_and_flags & 0x0F;

        Ok(PayloadHeader {
            payload_type,
            length,
            flags,
        })
    }

    /// Decode authentication
    fn decode_auth(trust_level: TrustLevel, buffer: &[u8]) -> CodecResult<Authentication> {
        match trust_level {
            TrustLevel::Full | TrustLevel::Sig => {
                if buffer.len() < SIGNATURE_SIZE {
                    return Err(CodecError::TruncatedFrame);
                }
                let mut sig_bytes = [0u8; SIGNATURE_SIZE];
                sig_bytes.copy_from_slice(&buffer[..SIGNATURE_SIZE]);
                Ok(Authentication::Signature(Signature::from_bytes(sig_bytes)))
            }
            TrustLevel::Compress => {
                if buffer.len() < SESSION_TOKEN_SIZE {
                    return Err(CodecError::TruncatedFrame);
                }
                let mut token_bytes = [0u8; SESSION_TOKEN_SIZE];
                token_bytes.copy_from_slice(&buffer[..SESSION_TOKEN_SIZE]);
                Ok(Authentication::Token(SessionToken::from_bytes(token_bytes)))
            }
            TrustLevel::Raw => Ok(Authentication::None),
        }
    }

    /// Get the payload as a slice without copying (for zero-copy scenarios)
    pub fn payload_slice(buffer: &[u8]) -> CodecResult<&[u8]> {
        if buffer.len() < MIN_FRAME_SIZE {
            return Err(CodecError::BufferTooSmall {
                needed: MIN_FRAME_SIZE,
                have: buffer.len(),
            });
        }

        // Decode header to get trust level, flags, and trace ID/routing presence
        let (header, has_trace_id, has_routing) =
            Self::decode_fixed_header(&buffer[..FIXED_HEADER_SIZE])?;

        let mut offset = FIXED_HEADER_SIZE;

        // Skip trace ID if present
        if has_trace_id {
            offset += TRACE_ID_SIZE;
        }

        // Skip routing extension if present (AXIOM-14 Cycle 1a)
        if has_routing {
            offset += NODE_ID_SIZE + 1;
        }

        // Skip fragment info if present
        if header.flags.fragmented {
            offset += 4;
        }

        // Read payload header
        if buffer.len() < offset + 4 {
            return Err(CodecError::TruncatedFrame);
        }
        let payload_header = Self::decode_payload_header(&buffer[offset..offset + 4])?;
        offset += 4;

        let payload_len = payload_header.length as usize;
        if buffer.len() < offset + payload_len {
            return Err(CodecError::TruncatedFrame);
        }

        Ok(&buffer[offset..offset + payload_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Encoder;
    use axiom_types::Frame;

    #[test]
    fn test_decode_invalid_magic() {
        let mut buffer = [0u8; 128];
        // Set invalid magic (should be 0b10, using 0b11)
        buffer[0] = 0xC0; // Magic = 11 instead of 10

        let result = Decoder::decode(&buffer);
        assert!(matches!(result, Err(CodecError::InvalidMagic)));
    }

    #[test]
    fn test_decode_invalid_version() {
        let mut buffer = [0u8; 128];
        // Valid magic but invalid version
        buffer[0] = (MAGIC << 6) | (0x0F << 2); // Version 15

        let result = Decoder::decode(&buffer);
        assert!(matches!(result, Err(CodecError::UnsupportedVersion(15))));
    }

    #[test]
    fn test_decode_buffer_too_small() {
        let buffer = [0u8; 32]; // Way too small

        let result = Decoder::decode(&buffer);
        assert!(matches!(result, Err(CodecError::BufferTooSmall { .. })));
    }

    #[test]
    fn test_decode_header_only() {
        let header = FrameHeader::new(FrameType::Route, NodeId::from_bytes([0x55; 32]))
            .with_trust_level(TrustLevel::Compress)
            .with_priority(Priority::Critical);

        let frame = Frame::new(header, PayloadType::Route, alloc::vec![1, 2, 3]);

        let mut buffer = alloc::vec![0u8; 256];
        let _ = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded_header = Decoder::decode_header(&buffer).unwrap();
        assert_eq!(decoded_header.frame_type, FrameType::Route);
        assert_eq!(decoded_header.trust_level, TrustLevel::Compress);
        assert_eq!(decoded_header.priority, Priority::Critical);
        assert_eq!(decoded_header.sender_id.as_bytes(), &[0x55; 32]);
    }

    #[test]
    fn test_payload_slice_zero_copy() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);

        let payload = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let frame = Frame::new(header, PayloadType::Raw, payload.clone());

        let mut buffer = alloc::vec![0u8; 256];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let slice = Decoder::payload_slice(&buffer[..size]).unwrap();
        assert_eq!(slice, &payload[..]);
    }
}
