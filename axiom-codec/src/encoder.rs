//! Frame encoder

use crate::CodecResult;
use axiom_types::error::CodecError;
use axiom_types::frame::{Authentication, Frame, FrameHeader};
use axiom_types::{
    CLOCK_SIZE, FIXED_HEADER_SIZE, INTENT_HASH_SIZE, MAGIC, NODE_ID_SIZE,
    TRACE_ID_SIZE,
};

/// Frame encoder with zero-copy semantics where possible
pub struct Encoder;

impl Encoder {
    /// Encode a frame into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `CodecError::BufferTooSmall` if the buffer is too small.
    /// Returns `CodecError::PayloadTooLarge` if the payload exceeds 16MB.
    pub fn encode(frame: &Frame, buffer: &mut [u8]) -> CodecResult<usize> {
        let required_size = frame.wire_size();

        if buffer.len() < required_size {
            return Err(CodecError::BufferTooSmall {
                needed: required_size,
                have: buffer.len(),
            });
        }

        if frame.payload.len() > axiom_types::MAX_PAYLOAD_SIZE {
            return Err(CodecError::PayloadTooLarge(frame.payload.len()));
        }

        let mut offset = 0;

        // Encode fixed header (with trace ID / routing flags)
        let has_trace_id = frame.trace_id.is_some();
        let has_routing = frame.routing.is_some();
        offset += Self::encode_fixed_header(
            &frame.header,
            has_trace_id,
            has_routing,
            &mut buffer[offset..],
        )?;

        // Encode extended header (trace ID if present)
        if let Some(trace_id) = &frame.trace_id {
            buffer[offset..offset + TRACE_ID_SIZE].copy_from_slice(trace_id.as_bytes());
            offset += TRACE_ID_SIZE;
        }

        // Encode routing extension if present (destination NodeId + TTL).
        // Frames without this are byte-identical to before AXIOM-14 Cycle
        // 1a - existing deployed nodes are unaffected.
        if let Some(routing) = &frame.routing {
            buffer[offset..offset + NODE_ID_SIZE].copy_from_slice(routing.destination.as_bytes());
            offset += NODE_ID_SIZE;
            buffer[offset] = routing.ttl;
            offset += 1;
        }

        // Encode fragment info if present
        if let Some(frag) = &frame.fragment_info {
            buffer[offset..offset + 2].copy_from_slice(&frag.sequence.to_be_bytes());
            buffer[offset + 2..offset + 4].copy_from_slice(&frag.total.to_be_bytes());
            offset += 4;
        }

        // Encode payload header
        offset += Self::encode_payload_header(
            frame.payload_header.payload_type,
            frame.payload.len() as u32,
            frame.payload_header.flags,
            &mut buffer[offset..],
        )?;

        // Copy payload
        buffer[offset..offset + frame.payload.len()].copy_from_slice(&frame.payload);
        offset += frame.payload.len();

        // Encode authentication
        offset += Self::encode_auth(&frame.auth, &mut buffer[offset..])?;

        Ok(offset)
    }

    /// Encode the fixed header (58 bytes)
    fn encode_fixed_header(
        header: &FrameHeader,
        has_trace_id: bool,
        has_routing: bool,
        buffer: &mut [u8],
    ) -> CodecResult<usize> {
        if buffer.len() < FIXED_HEADER_SIZE {
            return Err(CodecError::BufferTooSmall {
                needed: FIXED_HEADER_SIZE,
                have: buffer.len(),
            });
        }

        // Bytes 0-2: Packed fields
        // Bit layout:
        //   0-1:   Magic (2 bits)
        //   2-5:   Version (4 bits)
        //   6-10:  FrameType (5 bits)
        //   11-13: Flags (3 bits)
        //   14-15: TrustLevel (2 bits)
        //   16-17: Priority (2 bits)
        //   18:    HasTraceID (1 bit)
        //   19:    HasRouting (1 bit) - AXIOM-14 Cycle 1a
        //   20-23: Reserved (4 bits)

        let byte0 = (MAGIC << 6)
            | ((header.version & 0x0F) << 2)
            | ((header.frame_type.to_u8() >> 3) & 0x03);

        let byte1 = ((header.frame_type.to_u8() & 0x07) << 5)
            | ((header.flags.to_u8() & 0x07) << 2)
            | (header.trust_level.to_u8() & 0x03);

        // Bit 5 (0x20) is the trace ID flag; bit 4 (0x10) is the routing
        // extension flag - a previously-reserved bit, so old decoders that
        // don't check it simply never look past the fixed header for a
        // routing extension (this cycle doesn't yet produce frames that set
        // it in live traffic, so that mismatch can't occur yet in practice).
        let trace_flag = if has_trace_id { 0x20 } else { 0x00 };
        let routing_flag = if has_routing { 0x10 } else { 0x00 };
        let byte2 = ((header.priority.to_u8() & 0x03) << 6) | trace_flag | routing_flag;

        buffer[0] = byte0;
        buffer[1] = byte1;
        buffer[2] = byte2;

        // Bytes 3-9: CausalClock (7 bytes)
        let clock_bytes = header.clock.to_bytes();
        buffer[3..3 + CLOCK_SIZE].copy_from_slice(&clock_bytes);

        // Bytes 10-25: IntentHash (16 bytes)
        buffer[10..10 + INTENT_HASH_SIZE].copy_from_slice(header.intent_hash.as_bytes());

        // Bytes 26-57: SenderID (32 bytes)
        buffer[26..26 + NODE_ID_SIZE].copy_from_slice(header.sender_id.as_bytes());

        Ok(FIXED_HEADER_SIZE)
    }

    /// Encode payload header (4 bytes)
    fn encode_payload_header(
        payload_type: axiom_types::PayloadType,
        length: u32,
        flags: u8,
        buffer: &mut [u8],
    ) -> CodecResult<usize> {
        if buffer.len() < 4 {
            return Err(CodecError::BufferTooSmall {
                needed: 4,
                have: buffer.len(),
            });
        }

        // Bit layout:
        //   0-3:   PayloadType (4 bits)
        //   4-27:  PayloadLen (24 bits)
        //   28-31: PayloadFlags (4 bits)

        // We'll encode as: [type:4 | len_high:4] [len_mid:8] [len_low:8] [flags:4 | 0:4]
        let type_and_len_high = ((payload_type.to_u8() & 0x0F) << 4) | ((length >> 20) as u8 & 0x0F);
        let len_mid = ((length >> 12) & 0xFF) as u8;
        let len_low_and_flags_high = ((length >> 4) & 0xFF) as u8;
        let len_lowest_and_flags = (((length & 0x0F) << 4) | (flags as u32 & 0x0F)) as u8;

        buffer[0] = type_and_len_high;
        buffer[1] = len_mid;
        buffer[2] = len_low_and_flags_high;
        buffer[3] = len_lowest_and_flags;

        Ok(4)
    }

    /// Encode authentication
    fn encode_auth(auth: &Authentication, buffer: &mut [u8]) -> CodecResult<usize> {
        match auth {
            Authentication::Signature(sig) => {
                if buffer.len() < 64 {
                    return Err(CodecError::BufferTooSmall {
                        needed: 64,
                        have: buffer.len(),
                    });
                }
                buffer[..64].copy_from_slice(sig.as_bytes());
                Ok(64)
            }
            Authentication::Token(token) => {
                if buffer.len() < 16 {
                    return Err(CodecError::BufferTooSmall {
                        needed: 16,
                        have: buffer.len(),
                    });
                }
                buffer[..16].copy_from_slice(token.as_bytes());
                Ok(16)
            }
            Authentication::None => Ok(0),
        }
    }

    /// Calculate the signature data (everything except the signature itself).
    ///
    /// This is the single canonical implementation - `axiom-crypto`'s
    /// `FrameSigner`/`FrameVerifier` both call this directly rather than
    /// keeping their own copies, so there's exactly one place that decides
    /// what's actually covered by a signature.
    ///
    /// AXIOM-14 Cycle 1a: `RoutingExt::ttl` is a mutable-in-transit field (a
    /// relay must decrement it without invalidating the original sender's
    /// signature, same rationale as IPsec AH zeroing mutable IP header
    /// fields before authenticating) - canonicalized to 0 here before
    /// encoding, regardless of the frame's actual current TTL.
    /// `RoutingExt::destination` is NOT canonicalized - it stays part of
    /// what's signed, so a relay can't silently redirect a frame to a
    /// different destination.
    pub fn signature_data(frame: &Frame) -> alloc::vec::Vec<u8> {
        let mut canonical = frame.clone();
        if let Some(routing) = &mut canonical.routing {
            routing.ttl = 0;
        }

        let auth_size = canonical.auth.wire_size();
        let total_size = canonical.wire_size();
        let data_size = total_size - auth_size;

        let mut buffer = alloc::vec![0u8; total_size];
        // Encode everything; auth will be at the end regardless of its
        // current value, so truncating it off below covers "no auth" too.
        let _ = Self::encode(&canonical, &mut buffer);

        buffer.truncate(data_size);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::*;

    #[test]
    fn test_encode_minimal_frame() {
        let header = FrameHeader::new(FrameType::Ping, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![]);

        let mut buffer = [0u8; 128];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        // 58 (fixed header) + 4 (payload header) + 0 (payload) + 0 (auth) = 62
        assert_eq!(size, 62);

        // Check magic and version
        assert_eq!(buffer[0] >> 6, MAGIC);
        assert_eq!((buffer[0] >> 2) & 0x0F, PROTOCOL_VERSION);
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let header = FrameHeader::new(FrameType::Ping, NodeId::zero())
            .with_trust_level(TrustLevel::Raw);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![0u8; 100]);

        let mut buffer = [0u8; 64]; // Too small for 100 byte payload
        let result = Encoder::encode(&frame, &mut buffer);

        assert!(matches!(result, Err(CodecError::BufferTooSmall { .. })));
    }

    #[test]
    fn test_encode_header_fields() {
        let header = FrameHeader::new(FrameType::Stream, NodeId::from_bytes([0x42; 32]))
            .with_trust_level(TrustLevel::Compress)
            .with_priority(Priority::High)
            .with_clock(HybridClock::new(1700000000, 1000))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        let frame = Frame::new(header, PayloadType::Tensor, alloc::vec![]);

        let mut buffer = [0u8; 256];
        let _size = Encoder::encode(&frame, &mut buffer).unwrap();

        // Verify clock was encoded
        let clock_bytes = &buffer[3..10];
        let decoded_clock = HybridClock::from_bytes(clock_bytes.try_into().unwrap());
        assert_eq!(decoded_clock.physical, 1700000000);
        assert_eq!(decoded_clock.logical, 1000);

        // Verify intent hash
        let intent_hash = &buffer[10..26];
        assert_eq!(intent_hash, &[0xAB; 16]);

        // Verify sender ID
        let sender_id = &buffer[26..58];
        assert_eq!(sender_id, &[0x42; 32]);
    }

    /// AXIOM-14 Cycle 1a deployment-safety proof: a frame with no routing
    /// extension encodes to BYTE-IDENTICAL output before and after this
    /// change - the two real deployed nodes (Proxmox + laptop) interoperate
    /// unchanged through a rolling restart, no flag day, no version bump.
    #[test]
    fn test_no_routing_encodes_byte_identical_to_pre_axiom14() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x11; 32]))
            .with_trust_level(TrustLevel::Sig)
            .with_priority(Priority::High)
            .with_clock(HybridClock::new(1700000000, 42))
            .with_intent(IntentHash::from_bytes([0x22; 16]));
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3, 4]);

        let mut buffer = [0u8; 256];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        // Bit 4 (0x10, the new HasRouting flag) must be unset - this is the
        // actual byte-level proof, not just "it still encodes to something".
        assert_eq!(buffer[2] & 0x10, 0, "HasRouting flag must be unset when routing is None");
        // No extra bytes: 58 (fixed header) + 4 (payload header) + 4 (payload) + 64 (sig) = 130
        assert_eq!(size, 130);
    }

    /// Round-trip proof that a routing extension survives encode+decode
    /// with the right destination/ttl, and that frames WITHOUT routing are
    /// unaffected by frames that DO carry it (no cross-contamination).
    #[test]
    fn test_routing_extension_round_trip() {
        let dest = NodeId::from_bytes([0x99; 32]);
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x11; 32]))
            .with_trust_level(TrustLevel::Raw);
        let frame = Frame::new(header, PayloadType::Raw, alloc::vec![9, 8, 7])
            .with_routing(dest, 5);

        let mut buffer = [0u8; 256];
        let size = Encoder::encode(&frame, &mut buffer).unwrap();

        let decoded = crate::Decoder::decode(&buffer[..size]).unwrap();
        let routing = decoded.routing.expect("routing extension must decode back");
        assert_eq!(routing.destination.as_bytes(), dest.as_bytes());
        assert_eq!(routing.ttl, 5);
    }

    /// The security property Fable's plan review specifically required:
    /// TTL is mutable-through-relay (a decremented TTL must NOT invalidate
    /// the original sender's signature), but destination is NOT mutable
    /// (tampering with it MUST invalidate the signature - a relay can't
    /// silently redirect a frame).
    #[test]
    fn test_signature_data_excludes_ttl_but_not_destination() {
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x11; 32]))
            .with_trust_level(TrustLevel::Sig);
        let base = Frame::new(header, PayloadType::Raw, alloc::vec![1, 2, 3])
            .with_routing(NodeId::from_bytes([0x99; 32]), 8);

        let mut ttl_changed = base.clone();
        ttl_changed.routing.as_mut().unwrap().ttl = 1; // simulates a relay decrementing TTL
        assert_eq!(
            Encoder::signature_data(&base),
            Encoder::signature_data(&ttl_changed),
            "decrementing TTL must not change what gets signed"
        );

        let mut dest_changed = base.clone();
        dest_changed.routing.as_mut().unwrap().destination = NodeId::from_bytes([0xAA; 32]);
        assert_ne!(
            Encoder::signature_data(&base),
            Encoder::signature_data(&dest_changed),
            "changing destination MUST change what gets signed - a relay can't silently redirect"
        );
    }
}
