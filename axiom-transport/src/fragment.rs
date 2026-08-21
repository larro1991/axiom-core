//! Frame fragmentation and reassembly
//!
//! Handles splitting large frames into MTU-sized chunks and reassembling them.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use axiom_types::clock::HybridClock;
use axiom_types::crypto::{IntentHash, NodeId, TraceId};
use axiom_types::frame::{
    Authentication, Frame, FrameHeader, FragmentInfo, PayloadHeader, RoutingExt,
};
use axiom_types::payload::PayloadType;
use hashbrown::HashMap;
use thiserror::Error;

/// Reassembly errors
#[derive(Debug, Error)]
pub enum ReassemblyError {
    #[error("Duplicate fragment: seq {seq} of {total}")]
    DuplicateFragment { seq: u16, total: u16 },

    #[error("Fragment mismatch: expected {expected} total, got {got}")]
    TotalMismatch { expected: u16, got: u16 },

    #[error("Reassembly timeout for key {0:?}")]
    Timeout(ReassemblyKey),

    #[error("Too many pending reassemblies: {0}")]
    TooManyPending(usize),

    #[error("Missing fragments: received {received} of {total}")]
    Incomplete { received: usize, total: u16 },

    #[error("Invalid fragment sequence: {seq} >= {total}")]
    InvalidSequence { seq: u16, total: u16 },
}

/// Key for identifying a fragmented frame
///
/// # Known limitation (logged, not fixed here)
///
/// Every field here (`sender_id`, `intent_hash`, `clock`) is taken directly
/// from the unauthenticated wire header of the FIRST fragment seen for this
/// key - fragments aren't individually signed or otherwise bound to a
/// verified sender identity (only the reassembled whole is, once A1's
/// signature fix is in place). A forged fragment with a spoofed
/// `sender_id`/`intent_hash`/`clock` can therefore collide with - and
/// poison - another sender's in-progress reassembly buffer: the victim's
/// legitimate fragment for the same key then gets rejected as a
/// `DuplicateFragment`, or (once reassembled) the frame's signature check
/// simply fails because the payload is a mix of the victim's and the
/// attacker's bytes. Fixing this needs fragment-level sender authentication
/// (e.g. per-fragment MACs keyed off a session established at a higher
/// layer) that doesn't exist yet anywhere in this crate - left for whoever
/// eventually adds it, not addressed by this cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReassemblyKey {
    pub sender_id: NodeId,
    pub intent_hash: IntentHash,
    pub clock: HybridClock,
}

/// Fragment buffer for reassembly
#[derive(Debug)]
struct FragmentBuffer {
    /// Expected total number of fragments
    total: u16,
    /// Received fragments indexed by sequence number
    fragments: BTreeMap<u16, Vec<u8>>,
    /// Original frame header (from first fragment). `header.frame_type` is
    /// the frame's REAL type (Intent, Stream, ...) - fragments no longer
    /// overwrite it to `FrameType::Fragment` (see `Fragmenter::fragment`),
    /// so this is exactly what a signature check needs to reproduce.
    header: Option<FrameHeader>,
    /// Original frame's payload header (from first fragment) - captured
    /// whole, not just `payload_type`, because `payload_header.flags` (the
    /// has-trace-id bit) is itself part of what `Encoder::signature_data`
    /// signs. `Frame::new` always constructs a fresh `PayloadHeader` with
    /// `flags = 0`, so without capturing the original's flags here (and
    /// restoring them in `reassemble`), a reassembled frame from an
    /// original that had `with_trace_id()` called on it would sign
    /// differently than the original and fail verification even with
    /// everything else preserved. `length` gets recomputed at reassembly
    /// time regardless (this stored value only ever reflected fragment 0's
    /// own chunk length, not the reassembled total).
    payload_header: Option<PayloadHeader>,
    /// Original frame's trace ID (from first fragment) - `Frame::new` would
    /// otherwise default this away on reassembly.
    trace_id: Option<TraceId>,
    /// Original frame's multi-hop routing extension (from first fragment) -
    /// same rationale as `trace_id`.
    routing: Option<RoutingExt>,
    /// Original frame's authentication (signature/token), carried
    /// identically on every fragment by `Fragmenter::fragment`. Needed here
    /// because `Frame::new` would otherwise reconstruct a zeroed
    /// placeholder instead of the real signature.
    auth: Option<Authentication>,
    /// Creation timestamp for timeout
    created_at: u64,
}

impl FragmentBuffer {
    fn new(total: u16, created_at: u64) -> Self {
        Self {
            total,
            fragments: BTreeMap::new(),
            header: None,
            payload_header: None,
            trace_id: None,
            routing: None,
            auth: None,
            created_at,
        }
    }

    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total as usize
    }

    #[allow(clippy::too_many_arguments)]
    fn add_fragment(
        &mut self,
        seq: u16,
        total: u16,
        payload: Vec<u8>,
        header: FrameHeader,
        payload_header: PayloadHeader,
        trace_id: Option<TraceId>,
        routing: Option<RoutingExt>,
        auth: Authentication,
    ) -> Result<(), ReassemblyError> {
        if total != self.total {
            return Err(ReassemblyError::TotalMismatch {
                expected: self.total,
                got: total,
            });
        }

        if seq >= total {
            return Err(ReassemblyError::InvalidSequence { seq, total });
        }

        if self.fragments.contains_key(&seq) {
            return Err(ReassemblyError::DuplicateFragment { seq, total });
        }

        // Store the original frame's metadata from the first fragment. Every
        // fragment carries an identical copy of trace_id/routing/auth (see
        // `Fragmenter::fragment`), so any fragment would do, but the first
        // one is the natural choice and matches how `header` is already
        // captured below.
        if seq == 0 {
            self.header = Some(header);
            self.payload_header = Some(payload_header);
            self.trace_id = trace_id;
            self.routing = routing;
            self.auth = Some(auth);
        }

        self.fragments.insert(seq, payload);
        Ok(())
    }

    fn reassemble(self) -> Result<Frame, ReassemblyError> {
        if !self.is_complete() {
            return Err(ReassemblyError::Incomplete {
                received: self.fragments.len(),
                total: self.total,
            });
        }

        // Concatenate payloads in order
        let mut payload = Vec::new();
        for seq in 0..self.total {
            if let Some(fragment_payload) = self.fragments.get(&seq) {
                payload.extend_from_slice(fragment_payload);
            }
        }

        // Fragment sequence 0..total is guaranteed present at this point
        // (is_complete() means `fragments.len() == total` with keys drawn
        // from add_fragment's `seq < total` check and no duplicates, so by
        // pigeonhole the keys are exactly {0, ..., total-1}), so seq 0 was
        // always processed and these are always populated.
        let mut header = self.header.unwrap();
        let orig_payload_header = self.payload_header.unwrap();
        let auth = self.auth.unwrap();

        header.flags.fragmented = false;

        // Recompute `length` for the reassembled total, but keep
        // `payload_type` and - critically - `flags` from the original (see
        // this struct's `payload_header` field doc comment for why `flags`
        // matters for signature verification).
        let mut payload_header =
            PayloadHeader::new(orig_payload_header.payload_type, payload.len() as u32);
        payload_header.flags = orig_payload_header.flags;

        // Construct the reassembled frame explicitly, field by field,
        // rather than via `Frame::new` - `Frame::new` resets `trace_id`,
        // `routing`, and `auth` to their defaults (None / None / a zeroed
        // placeholder derived from trust_level), which would silently
        // discard the original frame's real signature and extended-header
        // fields even if `header` itself were perfectly preserved.
        Ok(Frame {
            header,
            trace_id: self.trace_id,
            routing: self.routing,
            fragment_info: None,
            payload_header,
            payload,
            auth,
        })
    }
}

/// Fragmenter for splitting large frames
pub struct Fragmenter {
    mtu: usize,
}

impl Fragmenter {
    /// Create a new fragmenter with the given MTU
    pub fn new(mtu: usize) -> Self {
        Self { mtu }
    }

    /// Calculate the maximum payload size per fragment
    /// Account for: fixed header (58) + fragment info (4) + payload header (4) + auth (variable)
    fn max_payload_per_fragment(&self, auth_overhead: usize) -> usize {
        self.mtu.saturating_sub(58 + 4 + 4 + auth_overhead)
    }

    /// Check if a frame needs fragmentation
    pub fn needs_fragmentation(&self, frame: &Frame) -> bool {
        frame.wire_size() > self.mtu
    }

    /// Fragment a frame into multiple smaller frames
    pub fn fragment(&self, frame: &Frame) -> Vec<Frame> {
        let auth_overhead = frame.auth.wire_size();
        let max_payload = self.max_payload_per_fragment(auth_overhead);

        if max_payload == 0 || frame.payload.len() <= max_payload {
            // No fragmentation needed or MTU too small
            return vec![frame.clone()];
        }

        let total_fragments = (frame.payload.len() + max_payload - 1) / max_payload;
        if total_fragments > u16::MAX as usize {
            // Too many fragments, return as-is (will fail at transport)
            return vec![frame.clone()];
        }

        let total = total_fragments as u16;
        let mut fragments = Vec::with_capacity(total_fragments);

        for seq in 0..total {
            let start = seq as usize * max_payload;
            let end = ((seq as usize + 1) * max_payload).min(frame.payload.len());
            let chunk = frame.payload[start..end].to_vec();

            // Create fragment frame. Deliberately do NOT overwrite
            // `frag_header.frame_type` to `FrameType::Fragment` (as this
            // used to do) - `frame_type` is part of what
            // `Encoder::signature_data` signs, so a reassembled frame's
            // signature could never verify against the caller's ORIGINAL
            // signature if fragments carried a different `frame_type` than
            // the frame they were cut from. "This is a fragment" is signaled
            // by `flags.fragmented` / the presence of `fragment_info`
            // instead - which is exactly what `Reassembler::process` already
            // keys off of, not `frame_type`.
            let mut frag_header = frame.header.clone();
            frag_header.flags.fragmented = true;

            let mut frag_frame = Frame::new(
                frag_header,
                frame.payload_header.payload_type,
                chunk,
            );
            frag_frame.fragment_info = Some(FragmentInfo::new(seq, total));
            frag_frame.trace_id = frame.trace_id;
            // Routing must also be copied onto every fragment, same as
            // trace_id and auth just below - previously dropped here
            // entirely (not just at reassembly), so even a
            // perfectly-preserving reassemble() would have had nothing to
            // recover it from.
            frag_frame.routing = frame.routing;
            frag_frame.auth = frame.auth.clone();
            // `Frame::new` always builds a fresh `PayloadHeader` with
            // `flags = 0`, discarding the original's has-trace-id bit -
            // which is itself part of what gets signed. Restore it so
            // reassembly has something correct to recover (see
            // `FragmentBuffer::payload_header`'s doc comment).
            frag_frame.payload_header.flags = frame.payload_header.flags;

            fragments.push(frag_frame);
        }

        fragments
    }
}

/// Reassembler for collecting and reassembling fragmented frames
pub struct Reassembler {
    buffers: HashMap<ReassemblyKey, FragmentBuffer>,
    max_buffers: usize,
    timeout_ms: u64,
}

impl Reassembler {
    /// Create a new reassembler
    pub fn new(max_buffers: usize, timeout_ms: u64) -> Self {
        Self {
            buffers: HashMap::new(),
            max_buffers,
            timeout_ms,
        }
    }

    /// Process a received frame
    ///
    /// Returns Some(frame) if the frame is complete (either non-fragmented or fully reassembled)
    /// Returns None if the frame is a fragment and reassembly is still in progress
    pub fn process(
        &mut self,
        frame: Frame,
        current_time_ms: u64,
    ) -> Result<Option<Frame>, ReassemblyError> {
        // Clean up timed-out buffers first
        self.cleanup_expired(current_time_ms);

        // If not fragmented, return as-is. Detection is via flags/fragment
        // metadata, never frame_type - see `Fragmenter::fragment`'s doc
        // comment on why frame_type can't be (and no longer is) used for
        // this.
        if !frame.header.flags.fragmented || frame.fragment_info.is_none() {
            return Ok(Some(frame));
        }

        let frag_info = frame.fragment_info.unwrap();
        let key = ReassemblyKey {
            sender_id: frame.header.sender_id,
            intent_hash: frame.header.intent_hash,
            clock: frame.header.clock,
        };

        // Get or create buffer
        let buffer = if let Some(buffer) = self.buffers.get_mut(&key) {
            buffer
        } else {
            // Check limit
            if self.buffers.len() >= self.max_buffers {
                return Err(ReassemblyError::TooManyPending(self.buffers.len()));
            }
            self.buffers.insert(
                key,
                FragmentBuffer::new(frag_info.total, current_time_ms),
            );
            self.buffers.get_mut(&key).unwrap()
        };

        // Add fragment
        buffer.add_fragment(
            frag_info.sequence,
            frag_info.total,
            frame.payload,
            frame.header,
            frame.payload_header,
            frame.trace_id,
            frame.routing,
            frame.auth,
        )?;

        // Check if complete
        if buffer.is_complete() {
            let buffer = self.buffers.remove(&key).unwrap();
            Ok(Some(buffer.reassemble()?))
        } else {
            Ok(None)
        }
    }

    /// Remove timed-out reassembly buffers
    fn cleanup_expired(&mut self, current_time_ms: u64) {
        self.buffers.retain(|_, buffer| {
            current_time_ms.saturating_sub(buffer.created_at) < self.timeout_ms
        });
    }

    /// Get the number of pending reassemblies
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }

    /// Clear all pending reassemblies
    pub fn clear(&mut self) {
        self.buffers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::frame::FrameType;
    use axiom_types::trust::TrustLevel;

    fn create_test_frame(payload_size: usize) -> Frame {
        let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x42; 32]))
            .with_trust_level(TrustLevel::Raw)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        Frame::new(header, PayloadType::Raw, vec![0xDE; payload_size])
    }

    #[test]
    fn test_no_fragmentation_needed() {
        let fragmenter = Fragmenter::new(1400);
        let frame = create_test_frame(100);

        assert!(!fragmenter.needs_fragmentation(&frame));

        let fragments = fragmenter.fragment(&frame);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].payload.len(), 100);
    }

    #[test]
    fn test_fragmentation() {
        let fragmenter = Fragmenter::new(200);
        let frame = create_test_frame(500);

        assert!(fragmenter.needs_fragmentation(&frame));

        let fragments = fragmenter.fragment(&frame);
        assert!(fragments.len() > 1);

        // Check all fragments have the fragmented flag
        for frag in &fragments {
            assert!(frag.header.flags.fragmented);
            assert!(frag.fragment_info.is_some());
        }

        // Check total payload size matches
        let total_payload: usize = fragments.iter().map(|f| f.payload.len()).sum();
        assert_eq!(total_payload, 500);
    }

    /// Fragments must preserve the ORIGINAL frame_type, not overwrite it to
    /// `FrameType::Fragment` - that overwrite is exactly what made a
    /// reassembled signed frame's signature unverifiable (see
    /// `test_fragmented_signed_frame_reassembles_and_verifies` below for the
    /// end-to-end proof). This test pins down the narrower claim directly.
    #[test]
    fn test_fragment_preserves_original_frame_type() {
        let fragmenter = Fragmenter::new(200);
        let header = FrameHeader::new(FrameType::Stream, NodeId::from_bytes([0x42; 32]))
            .with_trust_level(TrustLevel::Raw)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));
        let frame = Frame::new(header, PayloadType::Raw, vec![0xDE; 500]);

        let fragments = fragmenter.fragment(&frame);
        assert!(fragments.len() > 1);

        for frag in &fragments {
            assert_eq!(
                frag.header.frame_type,
                FrameType::Stream,
                "fragment must keep the original frame_type, not FrameType::Fragment"
            );
        }
    }

    #[test]
    fn test_reassembly() {
        let fragmenter = Fragmenter::new(200);
        let original = create_test_frame(500);
        let original_payload = original.payload.clone();

        let fragments = fragmenter.fragment(&original);
        let mut reassembler = Reassembler::new(100, 30000);

        let mut result = None;
        for frag in fragments {
            result = reassembler.process(frag, 1000).unwrap();
        }

        let reassembled = result.expect("Should have reassembled frame");
        assert_eq!(reassembled.payload, original_payload);
        assert!(!reassembled.header.flags.fragmented);
    }

    /// The actual acceptance bar for A1: a real signed frame (TrustLevel::Sig),
    /// larger than the MTU so it genuinely gets fragmented, must reassemble
    /// into something that passes `FrameVerifier::verify`. Field-by-field
    /// equality checks aren't sufficient proof by themselves (the signature
    /// covers frame_type too, per `Encoder::signature_data`), so this is the
    /// one that actually matters.
    #[test]
    fn test_fragmented_signed_frame_reassembles_and_verifies() {
        use axiom_crypto::frame_sign::{FrameSigner, FrameVerifier};
        use axiom_crypto::identity::Keypair;
        use axiom_types::crypto::TraceId;

        let keypair = Keypair::generate();
        let signer = FrameSigner::new(Keypair::from_bytes(&keypair.secret_bytes()));

        let header = FrameHeader::new(FrameType::Intent, keypair.node_id())
            .with_trust_level(TrustLevel::Sig)
            .with_clock(HybridClock::new(1700000000, 1))
            .with_intent(IntentHash::from_bytes([0xAB; 16]));

        let mut original = Frame::new(header, PayloadType::Raw, vec![0xCD; 2000])
            .with_routing(NodeId::from_bytes([0x99; 32]), 5)
            .with_trace_id(TraceId::from_u64(0xABCD_1234));

        signer.sign(&mut original).expect("signing a Sig-level frame must succeed");
        assert_eq!(
            FrameVerifier::verify(&original),
            Ok(true),
            "sanity check: the original, unfragmented frame must verify"
        );

        let fragmenter = Fragmenter::new(200);
        assert!(fragmenter.needs_fragmentation(&original));
        let fragments = fragmenter.fragment(&original);
        assert!(fragments.len() > 1, "test payload must actually fragment");

        let mut reassembler = Reassembler::new(100, 30_000);
        let mut result = None;
        for frag in fragments {
            result = reassembler
                .process(frag, 1_000)
                .expect("reassembly of well-formed fragments must not error");
        }
        let reassembled = result.expect("all fragments delivered - must be reassembled");

        assert_eq!(reassembled.payload, original.payload);
        assert_eq!(reassembled.header.frame_type, FrameType::Intent);
        assert_eq!(reassembled.trace_id, original.trace_id);
        assert_eq!(reassembled.routing, original.routing);
        assert_eq!(
            FrameVerifier::verify(&reassembled),
            Ok(true),
            "reassembled signed frame must pass signature verification - the actual A1 bar"
        );
    }

    #[test]
    fn test_non_fragmented_passthrough() {
        let mut reassembler = Reassembler::new(100, 30000);
        let frame = create_test_frame(100);
        let original_payload = frame.payload.clone();

        let result = reassembler.process(frame, 1000).unwrap();
        let frame = result.expect("Should return frame immediately");
        assert_eq!(frame.payload, original_payload);
    }

    #[test]
    fn test_duplicate_fragment() {
        let fragmenter = Fragmenter::new(200);
        let original = create_test_frame(500);

        let fragments = fragmenter.fragment(&original);
        let mut reassembler = Reassembler::new(100, 30000);

        // Process first fragment twice
        let first = fragments[0].clone();
        reassembler.process(first.clone(), 1000).unwrap();

        let result = reassembler.process(first, 1000);
        assert!(matches!(result, Err(ReassemblyError::DuplicateFragment { .. })));
    }

    #[test]
    fn test_reassembly_timeout() {
        let fragmenter = Fragmenter::new(200);
        let original = create_test_frame(500);

        let fragments = fragmenter.fragment(&original);
        let mut reassembler = Reassembler::new(100, 1000); // 1 second timeout

        // Process first fragment at t=0
        reassembler.process(fragments[0].clone(), 0).unwrap();
        assert_eq!(reassembler.pending_count(), 1);

        // Process second fragment at t=2000 (after timeout)
        reassembler.process(fragments[1].clone(), 2000).unwrap();
        // The old buffer should be cleaned up, new one created
        assert_eq!(reassembler.pending_count(), 1);
    }
}
