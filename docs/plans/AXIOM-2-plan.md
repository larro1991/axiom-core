# AXIOM-2 Plan: Wire discovered/handshaken peers to real application traffic

**Revision 2** — incorporates Fable's plan review. Changes from v1: split into two
build-test-fix cycles instead of one (Ping/Pong ships to real hardware before
Intent/Fulfill starts), added mandatory Frame-signature verification (the codec
decoder verifies nothing on its own — confirmed real gap), corrected two API
signatures, tightened the pending-request design, expanded failure modes.

## Goal
Right now `forge-node` finds peers (link-local IPv6 discovery) and verifies their
identity (HELLO/HELLO_ACK handshake) — both proven on real hardware — but
`handle_message`/`PeerConnected` are no-ops. Nothing happens after a connection
exists. AXIOM-2 makes something real happen: peers exchange actual AXIOM protocol
`Frame`s and can ask each other to do something (starting with the simplest
possible capability: echo).

## Deliberate scope cuts (why, not just what)
- **No multi-hop forwarding.** `axiom_router::forward::ForwardingEngine::decide()`
  requires the caller to already know `next_hops` (forward.rs:144-148) — it does
  loop detection, not route computation. This plan only ever sends Frames
  directly to an already-discovered/handshaken peer.
- **Not touching `axiom_router::node.rs`.** Not declared in `axiom-router/src/lib.rs`'s
  module list (lines 11-16 only declare `ai, announce, bootstrap, forward,
  registry, semantic`) — not compiled, not part of the public API. Confirmed it
  calls `RoutingTable` methods (`get_nodes_for_intent`, `upgrade_trust`,
  `apply_announcement`, `cleanup_stale`) that don't exist on the real
  `RoutingTable` — would not compile if added as-is. Ignoring it entirely.
- **Not touching `ember::Coordinator`.** Real task-decomposition/scheduling logic,
  zero networking (confirmed by grep) — dispatching a decomposed task across
  peers is its own project once basic Frame exchange exists.
- **Not swapping `forge-node`'s raw `UdpSocket` for `axiom_transport::SecureTransport`.**
  SecureTransport is real and more capable, but swapping means rewriting the
  discovery/handshake logic just proven on real hardware today. Adding a
  *second*, additional message channel on the *same* UDP socket instead,
  demultiplexed from HELLO by wire format — **confirmed provably safe, not
  coincidentally**: HELLO's magic byte 0 is `0x41` ('A', top 2 bits `01`);
  codec-encoded frames always pack `0b10` into byte 0's top 2 bits
  (encoder.rs:98, decoder.rs:141-143), landing in `0x80-0xBF`. The two formats
  are disjoint in both directions by construction, not by luck.
- **Not wiring `axiom-guardian`/`axiom-watcher`.** Their real entry points
  (`Guardian::process_frame` at guardian/lib.rs:270, `Watcher::process_packet`
  at watcher/lib.rs:214) expect raw Ethernet/IPv4 packets, not AXIOM Frames —
  built for a legacy-network bridge/gateway path. `node.rs`'s commented-out
  `guardian.inspect(&data)` call refers to a method that doesn't exist anywhere
  in that crate. Wiring belongs on the bridge path, a different feature.

## Build order — two cycles, not one
**Cycle A ships and gets tested on real hardware before Cycle B starts.**
Rationale (Fable): Cycle A alone validates the demux and the pending-request
machinery Cycle B reuses, with zero dependency on the three never-before-integrated
`axiom_router` crates (registry/semantic/announce) that carry the real
authentication-gap risk. Smaller blast radius per real-hardware test pass.

### Cycle A: wire-level demux + Frame authentication + Ping/Pong

1. **Demux.** `start_receive_loop` tries the existing HELLO magic check
   (`b"AXIO"`, byte 0 = `0x41`) first; on mismatch, attempt
   `axiom_codec::Decoder::decode`. Malformed/neither → drop silently (already
   today's behavior for garbage).

2. **Mandatory Frame authentication — this is not optional.** The codec decoder
   verifies nothing by itself. Every decoded Frame MUST pass
   `axiom_crypto::frame_sign::FrameVerifier::verify(&frame)` (checks the Ed25519
   signature against `frame.header.sender_id`, same self-authenticating pattern
   as the HELLO layer) before any of its contents are trusted or acted on.
   Frames are built with `TrustLevel::Sig` and signed via
   `FrameSigner::new(identity).sign(&mut frame)` before sending. An unverified
   frame is dropped exactly like a signature-failed HELLO already is (with the
   same debug-log treatment added there).

3. **Ping/Pong.** `FrameType::Ping`/`FrameType::Pong` already exist
   (frame.rs:37-39), unused until now.
   - `NetworkManager::ping(peer_id) -> Result<Duration>`: build a signed `Ping`
     Frame (`TrustLevel::Sig`, empty payload, fresh random `trace_id`), send to
     the peer's known addr, await a matching `Pong` with a timeout, return
     measured RTT.
   - **Pending-request design** (`Arc<Mutex<HashMap<TraceId, PendingPing>>>`,
     parallel to but distinct from `pending_connects`):
     - `PendingPing { expected_sender: NodeId, tx: oneshot::Sender<Duration> }`
       — keyed by `trace_id`, but ALSO records which peer we expect the reply
       from. A verified `Pong` with a matching `trace_id` but a DIFFERENT
       `sender_id` than expected is rejected, not accepted — trace_id alone
       isn't authorization.
     - A verified `Pong` frame: look up `trace_id`, confirm `sender_id`
       matches `expected_sender`, fulfill the oneshot.
     - Timeout path removes the pending entry same as `connect()` already does;
       a late `Pong` arriving after that finds no entry and is silently
       dropped (oneshot send on a vanished receiver is already a no-op
       elsewhere in this codebase — same discipline here).
   - Receive side: any verified `Ping` frame gets an immediate signed `Pong`
     reply carrying the same `trace_id`.

4. **Cycle A failure modes to actually test:**
   - `ping()` to an unreachable/dead peer → timeout, no crash, pending entry
     cleaned up.
   - A `Ping`/`Pong` frame with a bad/forged signature → dropped, never reaches
     application logic, logged at debug level same as a bad HELLO.
   - A late `Pong` arriving after `ping()` already timed out → dropped
     silently, no panic, no stale state left behind.
   - A `Pong` with the right `trace_id` but from the WRONG peer (simulate by
     having a third node reuse/guess a trace_id) → rejected, original `ping()`
     still times out normally rather than falsely succeeding.

**Cycle A real-hardware test:** same Proxmox + GamingPC (WSL2 mirrored
networking) setup as the discovery work. Measure real Ping/Pong RTT both
directions. Deliberately run all four failure modes above against real (not
mocked) peers. Full `cargo build --workspace` + `cargo test --workspace
--no-fail-fast`, zero new regressions against the 4 known pre-existing
unrelated failures. **Fable reviews Cycle A's actual results before Cycle B
starts.**

### Cycle B: capability registry + Intent/Fulfill (starts only after Cycle A ships clean)

5. **Local capability registry per node** (not distributed routing — just "what
   do I/my known peers offer"). Each node has a config-driven capability list
   (`NodeConfig::capabilities: Vec<String>`, default `["echo"]`). Right after a
   handshake completes (`connect()`'s success path and `register_peer()`'s
   discovery path), send a signed `Announce` frame
   (`axiom_router::announce::AnnouncePayload`/`AnnouncedCapability`, real and
   tested) advertising local capabilities. **Announce frames go through the
   same mandatory verification as everything else in Cycle A — an unverified
   Announce is a registry-poisoning vector and must be dropped, not just
   logged.** Receiving a verified Announce feeds one
   `axiom_router::registry::NodeRegistry` + `axiom_router::semantic::SemanticRouter`
   instance per `NetworkManager` (in-memory, no persistence).

6. **Intent → Fulfill.** Built-in capability: `"echo"` (given payload bytes,
   returns the same bytes).
   - Correct API usage (verified against source, not guessed):
     `IntentHasher::hash_intent` takes `&IntentDescriptor`, not a raw string —
     build a minimal `IntentDescriptor` for `"echo"` first.
     `SemanticRouter::discover` takes `&ai::Intent` (semantic.rs:206), not an
     `IntentHash` directly — construct the `Intent` type it actually expects.
   - `NetworkManager::request_intent(capability: &str, payload: Vec<u8>) ->
     Result<Vec<u8>>`: build the `Intent`, call `SemanticRouter::discover` against
     the local registry → candidate peer(s) → **if the chosen `NodeId` has no
     known transport address in `NodeRegistry` (a real gap Fable flagged - a
     peer can be "discovered" via Announce relay before its address is known),
     fail cleanly here rather than trying to send to nothing.** Otherwise build
     a signed `Intent` Frame (`PayloadType::IntentDesc`), send directly (no
     forwarding), await a matching `Fulfill` (same trace_id + sender_id-checked
     pending-request pattern as Cycle A's Ping/Pong) with a timeout.
   - Receive side: verified `Intent` frame → look up capability locally → known
     (`"echo"`) → signed `Fulfill` with the result payload; unknown →
     signed `FrameType::Error` reply. **The `Error` reply must also wake the
     trace_id waiter** — otherwise "capability not found" silently degrades
     into the caller waiting for the full timeout instead of failing fast,
     which Fable specifically flagged as a real gap in the v1 draft.

7. **Cycle B failure modes to actually test** (Cycle A's four, plus):
   - `Intent` for a capability nobody's announced → `discover` returns empty →
     clean "no provider found" error, no frame sent.
   - `Intent` for `"echo"` sent to a peer that's announced it but goes
     unresponsive → timeout on the `Fulfill` wait.
   - Two peers announcing the same capability → `discover_multi` picks one, no
     crash, no double-dispatch.
   - A capable peer replies with `Error` (unknown capability on their end,
     race with a stale local registry entry) → caller gets a fast clean
     failure, not a full timeout.
   - A forged/unverified `Announce` frame → registry unaffected, confirmed via
     log (nothing silently accepted).
   - `discover` resolves a `NodeId` with no known address in `NodeRegistry` →
     clean local failure, no frame sent to nowhere.

**Cycle B real-hardware test:** same setup, same build+test bar. Verify Announce
frames actually populate each side's registry (log line), run a real
Intent→echo→Fulfill round trip between the two machines confirming byte-for-byte
payload integrity, run every failure mode above against real peers. **Fable
reviews Cycle B's actual results before this is called done.**

## What AXIOM-2 explicitly does NOT deliver (next steps after this, not now)
- Multi-hop routing/forwarding through intermediate peers.
- Any EMBER/`Coordinator` task distribution.
- Persistence of the capability registry across restarts.
- Guardian/Watcher integration on the native AXIOM path.
- Anything beyond the one built-in `"echo"` capability.
