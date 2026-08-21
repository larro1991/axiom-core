# AXIOM Architecture

## Transport & Discovery (Phase 1.6)

AXIOM (`forge-node`) reaches other nodes over three independent paths. All
three feed the same protocol core (`axiom-codec` framing, `axiom-crypto`
signed HELLO handshake, `CapabilityPolicy` dispatch in
`forge-node/src/policy.rs`) — the transport a request arrived over does not
change what it's allowed to do.

### 1. LAN discovery — IPv6 link-local multicast

`forge-node/src/discovery.rs`. Same-L2-segment peers are found with zero
configuration and zero dependency on any bootstrap/relay infrastructure:

- Every `fe80::/64` (link-local) interface the kernel has brought up is
  enumerated (`enumerate_link_local_interfaces`, via `/proc/net/if_inet6`).
- On each trusted interface (gated by `NodeConfig::link_local_trusted_subnets`,
  a CIDR allowlist), the node joins `ff02::1` — the standard IPv6 all-nodes
  link-local multicast group — rather than a custom group, so no extra
  multicast group management is needed beyond what the kernel already does
  for `ff02::1`.
- Nodes periodically broadcast a signed HELLO (identity + timestamp,
  Ed25519-signed) into that group and register any peer whose HELLO they
  hear back. HELLOs are rejected if older than `MAX_HELLO_AGE_SECS` (60s) or
  timestamped further in the future than the allowed clock-skew window —
  see `hello_is_fresh` in `discovery.rs`.
- This mechanism is inherently confined to the local link: `ff02::1` is not
  forwarded by routers, so it only ever discovers peers actually on the same
  physical/virtual L2 segment. It has no bearing on cross-network (WAN)
  reachability at all — that's the iroh path below.

### 2. WAN transport — iroh (dial-by-key)

`axiom-transport/src/wan.rs`, wired into `forge-node/src/node.rs`. For peers
that are not on the same L2 segment, AXIOM uses iroh, a QUIC-based transport
where the peer's identity key doubles as its dial address (`EndpointId` is
the same 32-byte Ed25519 public key as AXIOM's own `NodeId` — no second
identity system to reconcile).

- **Off by default.** Controlled by `NodeConfig::wan_enabled` (default
  `false`). When enabled, `node.rs::start()` binds a separate
  `iroh::Endpoint` alongside (not instead of) the LAN `NetworkManager` — a
  distinct transport with its own allowlist, unrelated to the link-local
  socket above.
- **Dial-by-key.** `WanEndpoint::connect_and_verify_liveness` dials a peer by
  `NodeId` alone and lets iroh's discovery/relay resolve how to reach them;
  `connect_direct_and_verify_liveness` exists for the direct-address case
  (a statically-reachable peer, or tests) that bypasses discovery entirely.
- **Signed liveness, not just a completed handshake.** A QUIC/TLS handshake
  succeeding only proves *some* holder of the expected private key answered
  the connection *at that moment* — per the module's design notes, it is
  never on its own treated as a trust/liveness signal. Every connection is
  followed by a signed ping/pong exchange (`SignedPing`/`SignedPong`,
  domain-separated via `PONG_SIGNING_CONTEXT` so a signature minted for this
  purpose can't be replayed as valid for anything else AXIOM signs), bounded
  by `LIVENESS_FRESHNESS_WINDOW_SECS` (30s) and an overall
  `LIVENESS_EXCHANGE_TIMEOUT` (10s) so a wedged-but-allowlisted peer can't
  hang the exchange indefinitely.
- **`wan_allowed_peers` — a separate, fail-closed allowlist.** This is
  distinct from Phase 1.1's `CapabilityPolicy` (which governs *what* an
  already-connected peer may call); this one governs whether a peer can
  complete a WAN connection at all. `WanAllowlist::check` is consulted both
  before dialing out and on every inbound connection (`connect_and_verify_
  liveness`, `accept_with_liveness` in `wan.rs`). Empty allowlist means
  nobody — not "any known peer" — matching the same fail-closed convention
  Phase 1.1 established for capability policy. `node.rs::start()` parses
  `wan_allowed_peers` (hex-encoded 32-byte NodeIds) at startup and logs a
  loud warning (not a silent no-op) if `wan_enabled=true` but zero entries
  parsed: the endpoint still binds and listens, it just rejects every
  inbound connection by design.
- **Relay/discovery preset.** Production `WanEndpoint::bind()` uses
  `iroh::endpoint::presets::N0` — n0's public relay + discovery
  infrastructure — for NAT traversal and peer resolution. This was a
  deliberate, ratified decision, not an oversight: see `DECISIONS.md`
  ("iroh relay dependency — Option A accepted now, migration triggers
  defined") for the full rationale, the metadata-only exposure it carries,
  and the two conditions that trigger a migration to a self-hosted relay.
  This document doesn't re-litigate that call — it just records that
  `bind()` is exactly what ships: n0's preset, no direct-address-only
  fallback in the production path (that variant, `bind_local_only`, is
  test-only, gated behind `#[cfg(any(test, feature = "test-utils"))]`).
- **Discovery scope vs. connection scope — not the same gate.** n0's
  discovery makes a node's *existence* metadata-discoverable (node ID, IP,
  timing) to anyone who can query it. That is strictly weaker than being
  able to talk to the node: `WanAllowlist::check` runs before any handshake
  completes, on both the dial and accept paths, so an unallowlisted peer
  that learns a node exists via discovery still cannot complete a
  connection, full stop. Discoverability and reachability are independently
  gated.
- **Multi-hop relay, reverse-path breadcrumbs, gossip discovery.** The
  shared `NetworkManager`/dispatch layer that WAN connections plug into
  (`forge-node/src/network.rs`) carries AXIOM-14's multi-hop intent
  forwarding (origin-signed `Announce` gossip, per-request reverse-path
  breadcrumbs in `reverse_routes` with TTL-based eviction, origin-admission
  rate limiting, and hop-budget-bounded relay) — this applies over WAN
  connections exactly as it does over LAN ones, since both feed the same
  dispatch context. None of this is new for Phase 1.6; it's recorded here
  because it's in scope for the freeze below.

### 3. Manual escape hatch — `bootstrap_nodes`

`NodeConfig::bootstrap_nodes` (a plain list of `SocketAddr`s) is the
explicit, manually-configured fallback for any peer that neither of the
above reaches automatically — not on the local link, and either WAN is
disabled or the peer isn't the kind of thing discovery/dial-by-key applies
to. `node.rs::start()` connects to every configured bootstrap node on
startup, independent of both link-local discovery and the WAN endpoint.
This existed before the WAN transport did and is unaffected by it.

### No overlay VPN dependency

AXIOM does not require, assume, or integrate with any VPN/overlay layer.
Tailscale was evaluated as a candidate WAN answer and explicitly declined
by the owner (`DECISIONS.md`, "Tailscale — DECLINED, removed from the
roadmap entirely") once the iroh transport above was confirmed to already
cover the WAN case — an overlay VPN would have been a second, overlapping
transport/identity layer for no architectural gain. If a VPN is ever used
on hosts that happen to also run AXIOM, that's an operator choice made
outside AXIOM and AXIOM neither depends on nor is aware of it.

## The Phase 1 transport freeze (`v0-transport-frozen`)

As of tag `v0-transport-frozen`, the following protocol/transport surface is
**frozen** — no behavioral changes without an explicit owner decision to
unfreeze:

- **LAN discovery** — the link-local multicast mechanism in
  `discovery.rs`: the `ff02::1`/`fe80::/64` approach, the HELLO
  freshness/skew windows, and the signed-HELLO format itself.
- **Wire framing** — `axiom-codec`'s encode/decode format (`encoder.rs`,
  `decoder.rs`) and the frame types/semantics defined on top of it
  (`FrameType`, `RoutingExt`, etc. in `axiom-types`).
- **The HELLO / identity handshake** — the signed-HELLO crypto construction
  used both for LAN discovery and WAN liveness verification.
- **The iroh WAN transport exactly as shipped** — dial-by-key connection
  establishment, the signed ping/pong liveness exchange and its
  freshness/timeout bounds, the `wan_allowed_peers` fail-closed allowlist
  gating both dial and accept, the `presets::N0` relay/discovery
  dependency, and the multi-hop relay / reverse-path-breadcrumb / gossip
  discovery behavior it plugs into via the shared dispatch layer.

**Explicitly frozen means:** no new frame types, no new discovery modes, no
new relay features, ever, without an explicit owner decision to unfreeze —
recorded in `DECISIONS.md` the same way the iroh-keep-vs-Tailscale-drop call
was.

**Not frozen** — these can continue to change without revisiting the
freeze, because they sit around the protocol/transport surface rather than
inside it:

- Config parsing and validation (`config.rs`), including adding new config
  fields.
- `bootstrap_nodes` handling — connection *policy* (retry, ordering,
  concurrency) around the existing manual escape hatch, as opposed to the
  wire protocol used once connected.
- `CapabilityPolicy` (`policy.rs`) — which peers may call which
  capabilities is a policy-file concern, orthogonal to the transport/framing
  surface above it.
- Documentation and deployment surroundings (`deploy/forge-node.service`,
  `SECURITY.md`, this file).

If a future phase needs a new frame type, a new discovery mode, or a change
to the iroh integration, that requires an owner decision recorded in
`DECISIONS.md` before implementation — the same bar Phase 1's Tailscale and
iroh-relay calls were held to.
