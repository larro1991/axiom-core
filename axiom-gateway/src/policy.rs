//! AXIOM Phase 1.1: a versioned, fail-closed access-control policy covering
//! every capability a node can serve (`echo`, `sysinfo`,
//! `network_clients`, and any future one) - not just `network_clients`,
//! which used to be the only capability with any allowlist at all (see
//! forge-node's old, now-removed `network_clients_allowed_peers` field).
//!
//! Before this, `echo`/`sysinfo` were gated purely by `known_peers` (a
//! completed signed HELLO handshake) inside `handle_axiom_frame`'s
//! `FrameType::Intent` arm - any peer that could complete a handshake could
//! call either capability, full stop. That's gone now: a handshake proves
//! identity, not authorization. `CapabilityPolicy` is the SOLE authority on
//! who may call what, for every capability, checked uniformly inside
//! `dispatch_intent` regardless of which transport (LAN UDP, WAN QUIC) the
//! request arrived over. `known_peers` still gates other things it always
//! did (Ping/Pong liveness replies, Announce/gossip trust) - this module
//! doesn't touch those.
//!
//! Loaded once at startup from a TOML file at `NodeConfig::capability_policy_path`
//! - deliberately a SEPARATE file from `config.toml`, not a field embedded
//! in it. This matters for a later phase's "the management plane stays
//! outside AXIOM's own reach" invariant: the deployed copy of this file is
//! meant to live at a path the running node's own service user cannot
//! write to (root-owned `/etc/forge/`, the same directory `config.toml`
//! itself lives in - NOT `data_dir`, which the service does own and write
//! into for `node.key`/discovery state). Nothing in this module ever
//! attempts to write this file - `load()` only reads - and no capability
//! this build implements is a write path to it either; that's a property
//! this module preserves by omission, not a check it enforces itself.
//!
//! Fail-closed, not fail-open, at every level:
//! - The file doesn't exist, or fails to parse as TOML at all: EVERY
//!   capability serves NO ONE.
//! - The file parses but declares a `version` this build doesn't
//!   understand: EVERY capability serves NO ONE (see `POLICY_SCHEMA_VERSION`).
//!   This is also how an old schema-v1 file (see below) is handled - it's
//!   syntactically valid TOML, and still parses fine as far as `toml::from_str`
//!   is concerned, it just declares `version = 1` where this build requires
//!   exactly 2, so it hits this exact case, not a parse failure.
//! - A capability this build knows how to serve (`echo`, `sysinfo`,
//!   `network_clients`) has no `[capability.<name>]` entry in an otherwise
//!   valid file: that ONE capability serves no one (others with entries
//!   are unaffected).
//! - A capability's entry exists but `allowed_peers` is empty: that
//!   capability serves no one - same as a missing entry, not a different
//!   case.
//! - AXIOM Phase 3.1/3.2: a capability's entry exists in a valid v2 file
//!   but has no valid `tier` (the field is missing, or its value isn't one
//!   of `"tier0"`/`"tier1"`/`"tier2"`): that ONE capability serves no one -
//!   same granularity as a missing `[capability.<name>]` entry, and
//!   implemented the SAME way (the entry is simply never inserted into
//!   `CapabilityPolicy::entries`, so `check_and_acquire` sees it as if it
//!   didn't exist). See `RawCapabilityEntry::tier`'s doc comment for the one
//!   documented exception (a `tier` value of the wrong TOML *type*, not just
//!   the wrong string, fails the WHOLE file closed instead).
//! None of these crash the node - `load()` never returns `Err`, it logs
//! loudly (`tracing::error!`) and returns a policy that authorizes nothing.
//! Discovery, handshaking, and liveness (Ping/Pong) don't depend on this
//! module at all and keep working regardless; only capability dispatch is
//! affected.
//!
//! AXIOM Phase 3.0: relocated from `forge-node/src/policy.rs` into this
//! standalone `axiom-gateway` crate - a mechanical move, not a rewrite.
//! Same types, same function signatures, same fail-closed behavior, same
//! tests. `pub(crate)` items became `pub` (this module's "crate" is now
//! `axiom-gateway`, consumed by forge-node as a dependency instead of
//! living inside forge-node's own crate) - see DECISIONS.md's "ecosystem
//! positioning" section for why this crate has zero dependency on AXIOM's
//! own discovery/transport/frame code: Burr Phase 2 (Conduit) is intended
//! to consume the same grammar later.
//!
//! AXIOM Phase 3.1/3.2 (2026-08-06): schema v2 - a mandatory `tier` field
//! per capability entry (`Tier::Tier0`/`Tier1`/`Tier2`, ratified in
//! DECISIONS.md's "Tier model" section - defined by worst-case impact and
//! required controls, NOT by read-vs-write). This is exactly the extension
//! `POLICY_SCHEMA_VERSION`'s doc comment anticipated back in Phase 1.1:
//! bump the constant, add the field, no retrofit of the fail-closed
//! machinery needed. Tier assignment and registration-gating land here;
//! the CONTROLS a tier implies beyond allowlist+rate/concurrency (Tier1's
//! mandatory audit logging, Tier2's mandatory human approval) are Phase
//! 3.4 and 3.3 respectively - not built yet, deliberately out of scope for
//! this change. A capability can be correctly tiered here today without
//! either of those enforcement mechanisms existing.
//!
//! AXIOM Phase 3.6 (2026-08-06): the ratified protected-resource list
//! (`DECISIONS.md`'s "Protected-resource list" section - every physical
//! interface's MAC, IP secondary/informational, for every management-plane
//! device: the Proxmox host itself, the desktop, the router, the Omada
//! controller, the laptop) lands in this SAME file, as an optional
//! top-level `[[protected_resource]]` array-of-tables, sitting alongside
//! (not replacing) the existing `[capability.*]` tables - same file, same
//! not-writable-by-service-user lockdown already established since Phase
//! 1.1, still schema v2 (extended, not bumped - nothing about this addition
//! changes how an EXISTING file without it parses, so there's no reason to
//! invalidate every already-deployed v2 file the way the 1->2 bump
//! correctly did for the mandatory-tier change).
//!
//! Two independent enforcement points, deliberately NOT one:
//! 1. **Fail-closed registration gate, here in `try_load`**: a `Tier1` or
//!    `Tier2` capability entry in a file with NO `[[protected_resource]]`
//!    section AT ALL (the key entirely absent, not merely an empty array -
//!    see `RawPolicyFile::protected_resources`'s doc comment for why that
//!    distinction is deliberate) simply never gets inserted into
//!    `entries` - the exact same mechanism an untiered capability already
//!    uses (see `try_load`'s `tier` handling above), reused rather than
//!    reinvented. This is what makes "no protected-resource section ->
//!    every Tier1+ capability denies everyone" true through
//!    `check_and_acquire` - the SAME central check `dispatch_intent`
//!    (forge-node) already calls, unconditionally, before any capability
//!    handler runs, for every capability that will ever exist. `Tier0` is
//!    untouched by this - it has no external target to protect against in
//!    the first place (see `Tier::Tier0`'s own doc comment).
//! 2. **Parameter-level matching, `find_protected_match`/
//!    `protected_resources_configured`**: does THIS specific call's
//!    parameters actually reference a protected MAC/IP? Needs the call's
//!    parameters in a checkable shape to answer - which, as of this phase,
//!    only exists for `approval::Intent`'s `Vec<Constraint>` model (Phase
//!    3.3). `approval::Tier2ApprovalFlow::propose`/`propose_with_expiry`
//!    is this check's real, mandatory, structurally-can't-skip-it call
//!    site (a `Tier2ApprovalFlow` cannot even be constructed without an
//!    `Arc<CapabilityPolicy>` to check against) - see that module's own
//!    doc comment for the full "rejected before the owner ever sees an
//!    approval prompt" contract. `forge-node`'s real, LIVE capability
//!    dispatch (`dispatch_intent`) does NOT yet pass structured
//!    `Vec<Constraint>` parameters for any capability - every capability
//!    implemented so far (`echo`/`sysinfo`/`network_clients`) takes a raw
//!    `Vec<u8>` payload, and `network_clients` specifically takes no
//!    caller-supplied parameters at all (see `SECURITY.md`/`DECISIONS.md`'s
//!    "AXIOM->UAI credential scope" section - its own inputs come from
//!    node config, not the request). So mechanism 2 above has no live
//!    Tier1 call site to attach to today; mechanism 1 (this file's
//!    registration gate) is what actually protects today's real Tier1+
//!    dispatch path, fail-closed, independent of whether any given
//!    capability's parameters are even checkable yet.
//!
//! Detection mechanism for #2: a generic scan of every `String`/`OneOf`
//! constraint value for a MAC-shaped (`xx:xx:xx:xx:xx:xx` /
//! `xx-xx-xx-xx-xx-xx`) or IPv4-shaped (dotted-quad) substring, cross-
//! checked against the protected list - see `scan_mac_candidates`/
//! `scan_ipv4_candidates`. Chosen over requiring each capability to
//! explicitly declare which parameter is a "target": a scan can't be
//! bypassed by a capability author forgetting to declare one (matches this
//! phase's own "structurally impossible to bypass, not opt-in" mandate),
//! at the cost of a false positive being theoretically possible for an
//! unrelated string that happens to look like a MAC/IP - an acceptable
//! trade given this whole project's fail-closed-by-default prime
//! directive (a wrongly-blocked benign intent costs a human re-proposing
//! it; a wrongly-allowed protected-resource intent costs the resource).
//!
//! Also lands here (see `RawCapabilityEntry::denied_param_substrings`):
//! the roadmap's "minimal per-capability argument constraint" ask - an
//! OPTIONAL, per-capability, case-insensitive denylist of substrings a
//! parameter value must not contain. Deliberately not mandatory/fail-
//! closed like the protected-resource list above (the roadmap's own
//! framing: "start minimal... rich constraint syntax can grow later") -
//! an empty or absent list simply adds no extra constraint, unlike a
//! missing protected-resource SECTION, which does fail closed.
//!
//! AXIOM Phase 3.8 (2026-08-06): two independent additions, the last two
//! sub-items of the capability-gateway roadmap's Phase 3.
//!
//! 1. **Kill switch** (`KillSwitch`, embedded as `CapabilityPolicy::
//!    kill_switch`): local-only, runtime-MUTABLE state - NOT the on-disk
//!    policy file this module otherwise only ever reads (`load`/`try_load`
//!    never write). Two independent levers, both checked inside
//!    `check_and_acquire` - the one central gate every real capability call
//!    already passes through (`forge-node/src/capability_isolation.rs`'s own
//!    `check_and_acquire_runs_before_any_capability_handler_in_dispatch_intent`
//!    test proves this structurally) - so a mutation here takes effect on
//!    the very next in-flight request boundary, no process restart, no
//!    second enforcement point to keep in sync:
//!    - `freeze`/`unfreeze`: a single global flag. Freezing stops ALL
//!      `Tier1`+ execution immediately; `Tier0` (`echo`/`sysinfo` - no
//!      external target to protect in the first place, see `Tier::Tier0`'s
//!      own doc comment) keeps working, and the audit log itself is
//!      untouched by this policy entirely (it has zero dependency on
//!      `CapabilityPolicy`/`KillSwitch` - see `audit.rs`), so freeze events
//!      themselves can still be logged. Un-freeze is a separate, explicit
//!      call - never an implicit timeout.
//!    - `suspend_peer`/`unsuspend_peer`: denies ONE specific peer identity,
//!      for EVERY tier including `Tier0` - the more conservative of two
//!      readings the roadmap leaves open (only the ALL-freeze level's own
//!      wording says "Tier1+"; per-pubkey suspend doesn't say that at all).
//!      Chosen deliberately per this project's fail-closed prime directive:
//!      suspending a specific key is a narrower, stronger statement ("I
//!      don't trust THIS identity right now") than an operational freeze,
//!      and leaving a suspended key able to keep making even `Tier0` calls
//!      would leave a live, authenticated channel open to an identity the
//!      operator just decided to cut off entirely.
//!
//!    Reachable ONLY via `forge-node`'s local admin control socket
//!    (`forge-node/src/control.rs`) - never as a capability, never over the
//!    network. See `capability_isolation.rs`'s
//!    `capability_dispatch_has_zero_references_to_kill_switch_mutators_today`
//!    and `kill_switch_names_are_not_registered_as_capabilities` tests for
//!    the enforced proof, and `capability_policy_public_api_has_no_destructive_method`'s
//!    updated allowlist for why `freeze`/`unfreeze`/`suspend_peer`/
//!    `unsuspend_peer` existing on this type's public API is a deliberately
//!    reviewed exception, not an oversight.
//!
//! 2. **Allowlist expiry** (`RawAllowedPeer`, `CapabilityEntry::
//!    allowed_peers` widened from `HashSet<NodeId>` to
//!    `HashMap<NodeId, Option<u64>>`): an OPTIONAL, per-peer, unix-seconds
//!    `expires` - backward compatible with every already-deployed v2 policy
//!    file (a bare hex string, this schema's only shape before this phase,
//!    still parses exactly as before, as a permanent/`None`-expiry entry).
//!    Checked LIVE, on every `check_and_acquire`/`allows`/`capability_summary`
//!    call, against the real wall clock (`now_unix_secs`, the same
//!    `SystemTime::now().duration_since(UNIX_EPOCH)` pattern `forge-node`'s
//!    HELLO-freshness check and `axiom-gateway::audit`'s own timestamps
//!    already use) - NOT filtered once at `try_load` time. This matters:
//!    this crate has no policy-FILE hot-reload (Phase 3.1's own documented
//!    limitation - the file is read once at startup), but expiry here is a
//!    live re-evaluation of data already loaded into memory, not a file
//!    re-read, so an entry that was valid when the policy loaded correctly
//!    stops being effective the instant its `expires` timestamp passes,
//!    without needing (or fighting) a file hot-reload at all. An expired
//!    entry is indistinguishable, at every observation point (`check_and_acquire`,
//!    `allows`, `capability_summary`'s reported list), from a peer that was
//!    never allowlisted - no separate error, no separate warning.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, info, warn};

use axiom_types::intent::{Constraint, ConstraintValue};
use axiom_types::NodeId;

/// Schema version this build understands - the only value `version` may
/// currently hold for a policy file to load at all (see the module doc
/// comment's "unsupported version" case).
///
/// AXIOM Phase 3.1/3.2: bumped 1 -> 2 for the mandatory per-capability
/// `tier` field. Because `version` is checked against an exact constant
/// (not "is it <= what we support"), this bump alone is what makes an old
/// v1 file fail closed under this build - it doesn't silently keep
/// granting access under a schema this build no longer considers
/// complete, it hits the exact same "unsupported version" path as any
/// other version mismatch, with no separate v1-specific code needed. This
/// is exactly the extension this constant's doc comment anticipated back
/// in Phase 1.1 (`RawCapabilityEntry` was deliberately a real named struct,
/// not a loose `HashMap<String, toml::Value>`, specifically so a required
/// field could be added here without a rewrite).
const POLICY_SCHEMA_VERSION: u32 = 2;

/// Raw on-disk shape, deserialized once by `try_load` then converted into
/// `CapabilityPolicy` (hex peer strings parsed to `NodeId`, raw seconds
/// built into a `Duration`, a `Semaphore` constructed per entry). Kept
/// separate from `CapabilityPolicy` itself so the conversion step can
/// reject an individual bad `allowed_peers` entry without that alone
/// invalidating the whole file - see `try_load`'s handling of it.
#[derive(Debug, Deserialize)]
struct RawPolicyFile {
    version: u32,
    /// `[capability.<name>]` tables, keyed by capability name (`"echo"`,
    /// `"sysinfo"`, `"network_clients"`, ...). `#[serde(default)]` so a
    /// syntactically valid file with zero capability tables still parses
    /// (as "every capability denied", the same as if each one were simply
    /// missing its own entry) rather than erroring - there's no reason to
    /// treat an empty policy any more harshly than a file that's merely
    /// incomplete.
    #[serde(default)]
    capability: HashMap<String, RawCapabilityEntry>,
    /// AXIOM Phase 3.6: the ratified protected-resource list, as
    /// `[[protected_resource]]` array-of-tables. `Option`, NOT
    /// `#[serde(default)]`-into-`Vec` - deliberately distinguishes the key
    /// being ABSENT entirely (`None`, fails Tier1+ registration closed -
    /// see `try_load`) from being PRESENT but explicitly empty
    /// (`Some(vec![])`, a legitimate if unusual "nothing is protected yet"
    /// operator choice that does NOT fail closed). `#[serde(default)]`
    /// still applies to the `Option` itself (so a file with no
    /// `protected_resource` key at all parses as `None` rather than a
    /// missing-field error), it just doesn't collapse `None` and
    /// `Some(vec![])` into the same thing the way a bare `Vec` field's
    /// default would.
    #[serde(default)]
    protected_resource: Option<Vec<RawProtectedResource>>,
}

/// AXIOM Phase 3.6: one `[[protected_resource]]` table's raw on-disk shape.
/// `mac` is the mandatory primary key (see `DECISIONS.md`'s "Protected-
/// resource list" section: "MAC address is the mandatory primary key, IP
/// is secondary" - documented IP-drift history in this environment makes
/// IP-only unreliable). `ip` is optional/informational only - several
/// ratified entries (dormant wifi adapters, a disconnected laptop
/// ethernet port) have no current IP at all and are still fully protected
/// by MAC alone.
#[derive(Debug, Deserialize)]
struct RawProtectedResource {
    /// Human-readable label for logs/error messages - not itself checked
    /// against anything. `None` renders as "<unnamed>" wherever a match is
    /// reported (see `ProtectedMatch`'s `Display`).
    #[serde(default)]
    name: Option<String>,
    mac: String,
    #[serde(default)]
    ip: Option<String>,
}

/// A capability's risk tier - AXIOM Phase 3.1 (tier model, ratified
/// 2026-08-06; see `DECISIONS.md`'s "Tier model" section for the exact
/// ratified wording this enum implements). Tiers are defined by
/// worst-case impact and required controls, NOT by read-vs-write: a
/// read-only capability that exercises real credentials against an
/// external system (`network_clients`) is `Tier1`, not `Tier0`, despite
/// never writing anything itself.
///
/// MANDATORY as of schema v2 (`POLICY_SCHEMA_VERSION` = 2) - see
/// `RawCapabilityEntry::tier`'s doc comment for exactly how an untiered
/// entry fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Side-effect-free, local-only, low-sensitivity. Controls: allowlist
    /// + rate limit (both already enforced by `check_and_acquire`,
    /// tier-independent). Today: `echo`, `sysinfo`.
    Tier0,
    /// Reaches an external system, exercises credentials, or performs a
    /// reversible write - regardless of read-only status. Controls:
    /// `Tier0`'s controls PLUS mandatory full-context audit logging
    /// (caller, intent, parameters, result - Phase 3.4, NOT built by this
    /// change) and per-capability rate/concurrency limits (already
    /// enforced). Today: `network_clients` - read-only, but `Tier1`
    /// because it exercises real credentials against external infra.
    Tier1,
    /// Destructive/security-relevant - firewall rules, VLAN changes,
    /// deletions, anything touching connectivity or auth. Controls:
    /// `Tier1`'s controls PLUS explicit human approval per invocation, no
    /// standing approvals, no wildcards (Phase 3.3, NOT built by this
    /// change). Nothing in this codebase is `Tier2` yet - this variant
    /// exists so the model can express it the moment one is added; see
    /// this module's `tier2_capability_is_declarable_and_parseable` test
    /// for proof the schema already accepts it even though nothing
    /// enforces the approval requirement.
    Tier2,
}

impl Tier {
    /// Parses the on-disk string form used in `[capability.*].tier`
    /// (`"tier0"`/`"tier1"`/`"tier2"`, anything else is invalid). A plain
    /// associated function rather than a `serde` derive on this enum
    /// directly - see `RawCapabilityEntry::tier`'s doc comment for why: an
    /// unrecognized tier NAME must fail closed for just that one
    /// capability entry, not abort parsing the whole file, and a derived
    /// `Deserialize` on an enum embedded in a struct can't degrade that
    /// gracefully - it fails the whole surrounding struct's deserialize.
    fn from_toml_str(s: &str) -> Option<Tier> {
        match s {
            "tier0" => Some(Tier::Tier0),
            "tier1" => Some(Tier::Tier1),
            "tier2" => Some(Tier::Tier2),
            _ => None,
        }
    }

    /// Inverse of `from_toml_str` - the exact on-disk string form
    /// (`"tier0"`/`"tier1"`/`"tier2"`). AXIOM Phase 3.2 (access resolver
    /// CLI): lets a reporting consumer print the same vocabulary the
    /// policy file itself uses, rather than inventing a second display
    /// format for the same three values.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Tier0 => "tier0",
            Tier::Tier1 => "tier1",
            Tier::Tier2 => "tier2",
        }
    }
}

/// AXIOM Phase 3.8: one raw on-disk `allowed_peers` array element - either
/// a bare hex `NodeId` string (this schema's ONLY shape before this phase,
/// still parses exactly as before - a permanent entry, no expiry) or a
/// table carrying the same peer plus an OPTIONAL `expires` (unix seconds).
/// `#[serde(untagged)]` tries each variant in array-element order: a bare
/// TOML string (`"aa..bb"`) only ever matches `Bare`, a table
/// (`{ peer = "aa..bb", expires = 1234 }`) only ever matches `WithExpiry` -
/// so `allowed_peers = ["<hex>", { peer = "<hex>", expires = 1234 }]` mixing
/// both shapes in the same array is valid, and every already-deployed v2
/// policy file (bare-string-only) keeps parsing completely unchanged.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawAllowedPeer {
    Bare(String),
    WithExpiry {
        peer: String,
        /// Unix seconds. `None`/absent = permanent, same as `Bare`. NOT
        /// validated against "now" here - see `try_load`'s handling of
        /// this field and this module's Phase 3.8 doc-comment section for
        /// why expiry is checked live, not filtered at load time.
        #[serde(default)]
        expires: Option<u64>,
    },
}

impl RawAllowedPeer {
    fn peer_str(&self) -> &str {
        match self {
            RawAllowedPeer::Bare(s) => s,
            RawAllowedPeer::WithExpiry { peer, .. } => peer,
        }
    }

    fn expires(&self) -> Option<u64> {
        match self {
            RawAllowedPeer::Bare(_) => None,
            RawAllowedPeer::WithExpiry { expires, .. } => *expires,
        }
    }
}

/// One capability's on-disk policy entry. A real named struct, not a
/// loose map of primitives - see `POLICY_SCHEMA_VERSION`'s doc comment for
/// why that matters for a clean v2 extension later.
#[derive(Debug, Deserialize)]
struct RawCapabilityEntry {
    /// Hex-encoded 32-byte Ed25519 `NodeId`s, NOT IP addresses - IPs are
    /// unauthenticated on this transport (anyone can claim any source
    /// address), while a `NodeId` here is only ever reached after
    /// `decode_verified_frame` has already proven the request was signed
    /// by the matching private key. Empty (or omitted - `serde(default)`)
    /// means fail CLOSED for this capability, not "allow everyone" -
    /// exactly the same default `network_clients_allowed_peers` used
    /// before this module existed. AXIOM Phase 3.8: each element is now
    /// `RawAllowedPeer` (bare string OR `{peer, expires}` table) - see that
    /// type's own doc comment for the backward-compatibility contract.
    #[serde(default)]
    allowed_peers: Vec<RawAllowedPeer>,
    /// Minimum gap, in seconds, between two served requests from the same
    /// allowed peer for this capability. `0` imposes no rate limit in
    /// practice (two requests would have to land at the exact same
    /// `Instant` to collide) - a legitimate value for a cheap, frequently-
    /// useful capability like `echo`, not a special-cased sentinel.
    rate_limit_secs: u64,
    /// Total in-flight requests for this capability allowed across ALL
    /// allowed peers at once - bounds worst-case concurrent load
    /// regardless of how many peers are allowlisted. Only `network_clients`
    /// has a real reason to keep this tight today (it drives a real HTTP
    /// round trip to the UAI broker/Omada controller), but every
    /// capability carries the field - a future capability with its own
    /// real backing cost shouldn't need a schema change just to get one.
    concurrency: usize,
    /// AXIOM Phase 3.1/3.2: MANDATORY as of schema v2 - `"tier0"`,
    /// `"tier1"`, or `"tier2"` (see `Tier::from_toml_str`). Typed as
    /// `Option<String>` rather than `Option<Tier>` deliberately: this
    /// keeps the field's TOML *type* permissive (any string parses fine at
    /// the TOML layer), so a MISSING field or an unrecognized tier NAME is
    /// a semantic-validation failure handled per-entry in `try_load` (log
    /// + skip that one entry - same precedent as an invalid
    /// `allowed_peers` hex string a few lines below) rather than a
    /// struct-level deserialize error that would fail the WHOLE file
    /// closed.
    ///
    /// One deliberate, documented exception to that per-entry granularity:
    /// a `tier` value of the wrong TOML *type* (e.g. `tier = 3` instead of
    /// a quoted string) is NOT a semantic-validation failure caught here -
    /// it's a type mismatch at the `toml::from_str::<RawPolicyFile>` layer
    /// itself, which (like any other syntactically-malformed entry in this
    /// file, e.g. an `allowed_peers` that isn't an array of strings) fails
    /// the WHOLE file closed via `try_load`'s top-level `?`. Chosen over
    /// building a fully custom `Deserialize` impl just to catch this one
    /// edge case at per-entry granularity too - not worth the complexity
    /// for a malformed-TOML-type case that was already whole-file-fatal
    /// before this field existed. See this module's
    /// `capability_missing_tier_denies_only_that_capability`,
    /// `capability_invalid_tier_name_denies_only_that_capability`, and
    /// `capability_tier_wrong_toml_type_fails_whole_file_closed` tests for
    /// all three cases proven separately.
    #[serde(default)]
    tier: Option<String>,
    /// AXIOM Phase 3.6: OPTIONAL, minimal per-capability argument
    /// constraint - a case-insensitive denylist of substrings that must
    /// not appear in any `String`/`OneOf` parameter value proposed for
    /// this capability (checked the same way, and at the same call site,
    /// as the protected-resource scan - see `CapabilityPolicy::
    /// check_denied_param_substrings`). Empty/absent (the default) adds no
    /// constraint at all - unlike the protected-resource list, this is
    /// deliberately NOT fail-closed-if-absent; the roadmap's own framing
    /// for this piece is "start minimal... rich constraint syntax can grow
    /// later," not "mandatory like the protected-resource check."
    #[serde(default)]
    denied_param_substrings: Vec<String>,
}

/// One capability's fully-parsed, ready-to-check policy entry.
#[derive(Debug)]
struct CapabilityEntry {
    /// AXIOM Phase 3.8: widened from `HashSet<NodeId>` to
    /// `HashMap<NodeId, Option<u64>>` - the value is this peer's `expires`
    /// (unix seconds), `None` meaning permanent (every entry before this
    /// phase, and every bare-string entry since). See this module's
    /// top-of-file Phase 3.8 doc-comment section for why expiry is checked
    /// LIVE against `now_unix_secs()` wherever this map is consulted,
    /// rather than filtered once here at load time.
    allowed_peers: HashMap<NodeId, Option<u64>>,
    rate_limit: Duration,
    /// Shared owned-permit semaphore for this capability - `dispatch_intent`
    /// holds a permit for the duration of one request/reply cycle (dropped
    /// automatically when that call returns), so this is never touched
    /// directly outside `CapabilityPolicy::check_and_acquire`.
    semaphore: std::sync::Arc<Semaphore>,
    /// The raw `concurrency` this entry was configured with - the same
    /// value `semaphore` was constructed with (`Semaphore::new(concurrency)`).
    /// Kept as its own field, redundant with the semaphore's own permit
    /// count, deliberately: AXIOM Phase 3.2 (access resolver CLI) needs to
    /// REPORT the configured limit without depending on the semaphore
    /// having never been touched (`Semaphore::available_permits()` would
    /// only coincidentally equal this on a freshly-loaded policy that
    /// nothing has called `check_and_acquire` against yet - fragile to
    /// build a read-only reporting API on top of).
    concurrency: usize,
    /// AXIOM Phase 3.1/3.2: this entry's mandatory tier - see `Tier`. Only
    /// ever `None` in the sense that an untiered raw entry never becomes a
    /// `CapabilityEntry` at all (see `try_load`); by the time one exists
    /// here, it always has a valid tier.
    tier: Tier,
    /// AXIOM Phase 3.6: lower-cased copy of `RawCapabilityEntry::
    /// denied_param_substrings` - lower-cased once here rather than on
    /// every `check_denied_param_substrings` call, matching this struct's
    /// existing "do the conversion once at load time" precedent
    /// (`rate_limit_secs` -> `Duration`, `concurrency` -> a constructed
    /// `Semaphore`).
    denied_param_substrings: Vec<String>,
}

/// AXIOM Phase 3.6: one entry off the ratified protected-resource list
/// (`DECISIONS.md`'s "Protected-resource list" section) - a device's MAC
/// (mandatory, primary key, normalized to lower-case colon-separated
/// bytes) plus an optional, secondary/informational IP. See `policy.rs`'s
/// module doc comment for the two independent places this is enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResource {
    pub name: Option<String>,
    mac: [u8; 6],
    /// Lower-case colon-separated display form of `mac` - computed once at
    /// parse time (`format_mac`), not recomputed on every match check or
    /// every `Display`.
    mac_display: String,
    pub ip: Option<String>,
}

impl ProtectedResource {
    /// Build one directly (no TOML file involved) - the same parsing
    /// `try_load` applies to a `[[protected_resource]]` table's `mac`
    /// field, exposed as a real constructor (not test-gated) since
    /// building a policy programmatically is a reasonable thing for an
    /// embedding consumer to want (see `DECISIONS.md`'s "ecosystem
    /// positioning" section - this crate is meant to be embeddable
    /// standalone). `None` if `mac` isn't a valid 6-octet colon/hyphen hex
    /// MAC - same fail-closed-by-omission precedent as an invalid
    /// `allowed_peers` hex entry: the caller gets nothing to insert rather
    /// than a silently-wrong partial value.
    pub fn new(name: Option<String>, mac: &str, ip: Option<String>) -> Option<Self> {
        parse_mac(mac).map(|bytes| Self { name, mac_display: format_mac(&bytes), mac: bytes, ip })
    }

    pub fn mac_display(&self) -> &str {
        &self.mac_display
    }
}

/// AXIOM Phase 3.6: one intent-parameter match against the protected-
/// resource list - what matched, which protected device it matched, and
/// which parameter carried it. Returned by `CapabilityPolicy::
/// find_protected_match`; consumed by `approval::Tier2ApprovalFlow::
/// propose_with_expiry` to build a `ProposeError::TargetsProtectedResource`
/// a caller/human can actually read, not just a bare bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedMatch {
    pub resource_name: Option<String>,
    pub resource_mac: String,
    pub resource_ip: Option<String>,
    /// The exact substring found in the parameter's value that triggered
    /// this match (a MAC in its scanned form, or the matched IP) - NOT
    /// necessarily byte-identical to `resource_mac`'s canonical lower-case
    /// form if the parameter itself used a different case/separator (e.g.
    /// `AA-BB-CC-11-22-01` matching `AA:BB:CC:11:22:01`) - kept separately
    /// so an error message can show the caller exactly what THEY wrote,
    /// not a silently-normalized version of it.
    pub matched_value: String,
    pub parameter_key: String,
}

impl std::fmt::Display for ProtectedMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "parameter '{}' (value {:?}) references protected resource {} (mac {}{})",
            self.parameter_key,
            self.matched_value,
            self.resource_name.as_deref().unwrap_or("<unnamed>"),
            self.resource_mac,
            self.resource_ip.as_ref().map(|ip| format!(", ip {ip}")).unwrap_or_default(),
        )
    }
}

/// Parse a MAC address string as exactly six colon- OR hyphen-separated
/// hex byte pairs (not a mix of both within one string) - `"30:c5:99:5e:
/// 34:4d"` or `"30-c5-99-5e-34-4d"`, case-insensitive. `None` for anything
/// else (wrong octet count, non-hex digits, wrong separator, extra
/// whitespace not already trimmed by the caller).
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return None;
    };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        out[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// AXIOM Phase 3.8: real wall-clock unix seconds - the same
/// `SystemTime::now().duration_since(UNIX_EPOCH)` pattern already used by
/// `forge-node::discovery`'s HELLO-timestamp freshness check and by
/// `axiom-gateway::audit`'s own entry timestamps, reused here rather than
/// inventing a third clock convention. Saturates to 0 on a clock error
/// (pre-1970 system clock) rather than panicking - same defensive
/// precedent `audit.rs::now_ms` already sets.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// AXIOM Phase 3.8: is `sender_id` currently (as of THIS call, not load
/// time) an effective member of `allowed_peers`? `None` (absent) and
/// `Some(expires)` where `expires <= now` are indistinguishable here by
/// design - both simply return `false` - see this module's top-of-file
/// Phase 3.8 doc-comment section ("expired = treated identically to
/// absent").
fn peer_currently_allowed(allowed_peers: &HashMap<NodeId, Option<u64>>, sender_id: NodeId) -> bool {
    match allowed_peers.get(&sender_id) {
        None => false,
        Some(None) => true,
        Some(Some(expires_at)) => now_unix_secs() < *expires_at,
    }
}

/// AXIOM Phase 3.8: local-only, runtime-mutable kill-switch state. See this
/// module's top-of-file Phase 3.8 doc-comment section for the full design
/// (why `frozen` is Tier1+-only but `suspended` is every-tier, and why both
/// live here rather than as a file-backed setting). `std::sync::Mutex`/
/// `AtomicBool`, not tokio's - every access is a quick check-or-flip, never
/// held across an `.await`, same precedent `CapabilityPolicy::
/// rate_limit_state` already established in this same struct.
#[derive(Debug)]
struct KillSwitch {
    frozen: std::sync::atomic::AtomicBool,
    suspended: Mutex<std::collections::HashSet<NodeId>>,
}

impl KillSwitch {
    fn new() -> Self {
        Self {
            frozen: std::sync::atomic::AtomicBool::new(false),
            suspended: Mutex::new(std::collections::HashSet::new()),
        }
    }
}

/// Scan `haystack` for every MAC-shaped substring (a 17-byte window of
/// `xx:xx:xx:xx:xx:xx` or `xx-xx-xx-xx-xx-xx`, consistent separator
/// within one match) and return each one's parsed bytes. Operates
/// entirely on byte indices into `haystack.as_bytes()` (never slices
/// `haystack` itself as a `str`) specifically so it can never panic on a
/// UTF-8 char-boundary mismatch, no matter what arbitrary caller-supplied
/// text this runs against - a parameter value is untrusted input, and
/// this scan must never be the thing that turns an untrusted string into
/// a node crash.
fn scan_mac_candidates(haystack: &str) -> Vec<[u8; 6]> {
    let bytes = haystack.as_bytes();
    let n = bytes.len();
    let mut found = Vec::new();
    if n < 17 {
        return found;
    }
    let mut i = 0;
    while i + 17 <= n {
        match parse_mac_window(&bytes[i..i + 17]) {
            Some(mac) => {
                found.push(mac);
                i += 17;
            }
            None => i += 1,
        }
    }
    found
}

/// Parse a fixed 17-byte window as a MAC address - same shape `parse_mac`
/// accepts, just over a byte slice already known to be exactly 17 bytes
/// (an already-validated window from `scan_mac_candidates`) rather than an
/// arbitrary-length `&str`.
fn parse_mac_window(w: &[u8]) -> Option<[u8; 6]> {
    debug_assert_eq!(w.len(), 17);
    let sep = w[2];
    if sep != b':' && sep != b'-' {
        return None;
    }
    let mut out = [0u8; 6];
    for octet in 0..6 {
        let base = octet * 3;
        if octet < 5 && w[base + 2] != sep {
            return None;
        }
        let hi = hex_val(w[base])?;
        let lo = hex_val(w[base + 1])?;
        out[octet] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Scan `haystack` for every IPv4-dotted-quad-shaped substring (a maximal
/// run of ASCII digits/`.` that splits into exactly four 0-255 octets) and
/// return each one verbatim (as found, not re-normalized - an IP is
/// compared against the protected list by exact string equality, see
/// `CapabilityPolicy::find_protected_match`, since `DECISIONS.md` already
/// treats IP as secondary/informational only). Byte-index-only, same
/// panic-safety reasoning as `scan_mac_candidates` - digit/`.` runs are
/// pure ASCII, so slicing at their boundaries can never land mid-character
/// even for arbitrary UTF-8 input surrounding them.
fn scan_ipv4_candidates(haystack: &str) -> Vec<String> {
    let bytes = haystack.as_bytes();
    let n = bytes.len();
    let mut found = Vec::new();
    let mut i = 0;
    while i < n {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < n && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let token = &haystack[start..j];
            if is_ipv4_shaped(token) {
                found.push(token.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    found
}

fn is_ipv4_shaped(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in &parts {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        match p.parse::<u16>() {
            Ok(v) if v <= 255 => {}
            _ => return false,
        }
    }
    true
}

/// AXIOM adversarial-test finding (see `TESTING.md`): `scan_mac_candidates`'s
/// fixed 17-byte window requires a MAC's separators to sit at their exact
/// canonical byte offsets - `"aa:bb:cc:11:22:01"`. A parameter value that
/// spells out the SAME MAC with extra ASCII whitespace inserted around its
/// separators (e.g. `"aa : bb : cc : 11 : 22 : 01"` - still unambiguously
/// the same MAC to a human reading it, and to any future capability's own
/// target-parsing code that trims whitespace before using it) slides every
/// possible 17-byte window off alignment and is missed entirely by the
/// exact-width scan. Confirmed as a real gap during this project's own
/// adversarial test pass, not a hypothetical - see
/// `find_protected_match_detects_a_mac_obfuscated_with_internal_whitespace`
/// below, which fails without this function.
///
/// Closed with a second pass over a whitespace-STRIPPED copy of `haystack`,
/// rather than by rewriting `scan_mac_candidates` itself to tolerate
/// whitespace mid-window - the original exact scan stays simple and its
/// existing byte-index behavior (relied on by `scan_mac_candidates_finds_
/// colon_and_hyphen_forms` and friends) is unchanged; this wrapper is what
/// `find_protected_match` actually calls. Deliberately biased toward MORE
/// detection, not less: stripping whitespace from arbitrary text and
/// re-scanning could in principle manufacture a coincidental MAC-shaped
/// match out of unrelated content, but this module's whole fail-closed
/// philosophy (see the module doc comment on `scan_mac_candidates`) already
/// accepts that trade - "a wrongly-blocked benign intent costs a human
/// re-proposing it; a wrongly-allowed protected-resource intent costs the
/// resource."
fn scan_mac_candidates_including_whitespace_obfuscated(haystack: &str) -> Vec<[u8; 6]> {
    let mut found = scan_mac_candidates(haystack);
    let stripped: String = haystack.chars().filter(|c| !c.is_whitespace()).collect();
    if stripped != haystack {
        found.extend(scan_mac_candidates(&stripped));
    }
    found
}

/// Every `String`/`OneOf` value out of a `Constraint` that could plausibly
/// carry a MAC/IP-shaped substring - `Int`/`Float`/`Bool`/`Range` are
/// structurally incapable of representing one (see `policy.rs`'s module
/// doc comment on why the scan targets these two variants specifically).
fn scannable_strings(value: &ConstraintValue) -> Vec<String> {
    match value {
        ConstraintValue::String(s) => vec![s.clone()],
        ConstraintValue::OneOf(values) => values.clone(),
        ConstraintValue::Int(_) | ConstraintValue::Float(_) | ConstraintValue::Bool(_) | ConstraintValue::Range { .. } => Vec::new(),
    }
}

/// Read-only, point-in-time snapshot of one capability's resolved policy
/// metadata - AXIOM Phase 3.2 (`axiom access` CLI). A plain data struct,
/// deliberately decoupled from `CapabilityEntry`'s live `Semaphore`/rate-
/// limit-state machinery: a reporting consumer (the access resolver) has
/// no business acquiring permits or mutating rate-limit timestamps, only
/// reading configuration, so this type can't accidentally be used to do
/// either. `allowed_peers` is hex-encoded and sorted for stable,
/// deterministic output - the underlying `HashSet<NodeId>` iteration order
/// is not.
#[derive(Debug, Clone)]
pub struct CapabilitySummary {
    pub tier: Tier,
    pub rate_limit_secs: u64,
    pub concurrency: usize,
    /// AXIOM Phase 3.8: widened from `Vec<String>` to `Vec<(String, Option<u64>)>`
    /// - hex peer paired with its `expires` (unix seconds), `None` for a
    /// permanent entry. Sorted by hex string for stable output (same "no
    /// natural ordering from the underlying map" rationale the pre-3.8
    /// `Vec<String>` already had). Only CURRENTLY-effective peers appear -
    /// an already-expired entry is indistinguishable from "never
    /// allowlisted" here too, same as everywhere else this field's data
    /// is consulted (see `CapabilityEntry::allowed_peers`'s own doc
    /// comment).
    pub allowed_peers: Vec<(String, Option<u64>)>,
}

/// Outcome of `CapabilityPolicy::check_and_acquire` - four DISTINCT
/// failure/success shapes, never conflated into a single bool or a shared
/// error string. In particular `NotAuthorized` (a validly-signed,
/// correctly-identified peer that simply isn't on this capability's
/// allowlist) must never be confused with a signature failure - that's a
/// wire-format-level distinction `decode_verified_frame` already enforces
/// upstream (an unverifiable frame is dropped before it ever reaches this
/// check at all, producing no reply whatsoever), and this enum preserves
/// the same "don't conflate different failure classes" discipline at this
/// layer: `NotAuthorized`, `RateLimited`, and `AtConcurrencyLimit` each get
/// their own distinct reply text in `dispatch_intent`, not a shared generic
/// "denied".
pub enum PolicyOutcome {
    /// Permit held for the duration of the request - dropped (releasing
    /// the concurrency slot) when the caller's request/reply cycle ends.
    Allowed(OwnedSemaphorePermit),
    /// No entry for this capability at all, or an entry whose
    /// `allowed_peers` doesn't include this sender - these two cases are
    /// deliberately NOT distinguished from each other (both are "fail
    /// closed for this capability"), only from the other outcomes below.
    NotAuthorized,
    RateLimited,
    AtConcurrencyLimit,
    /// AXIOM Phase 3.8: `sender_id` has been suspended by the local kill
    /// switch - denied for EVERY tier (see `KillSwitch`'s own doc comment).
    /// Deliberately distinct from `NotAuthorized` - an allowlist miss and a
    /// kill-switched identity are different situations an operator/caller
    /// should be able to tell apart, same "don't conflate different
    /// failure classes" discipline this enum already applies to
    /// `RateLimited`/`AtConcurrencyLimit`.
    Suspended,
    /// AXIOM Phase 3.8: a global Tier1+ freeze is active and `capability`
    /// is not `Tier0` (`Tier0` is exempt - see `Tier::Tier0`'s own doc
    /// comment: no external target to protect against in the first
    /// place). Distinct from `NotAuthorized` for the same reason as
    /// `Suspended` above.
    Frozen,
}

/// The loaded, checkable policy - see the module doc comment for the full
/// fail-closed contract `load` implements.
pub struct CapabilityPolicy {
    entries: HashMap<String, CapabilityEntry>,
    /// Per-(capability, peer) last-served timestamp. A plain
    /// `std::sync::Mutex`, not tokio's - every access is a quick
    /// read-then-maybe-insert, never held across an `.await`, matching
    /// `NetworkClientsGuard`'s old rate-limit map this replaces.
    rate_limit_state: Mutex<HashMap<(String, NodeId), Instant>>,
    /// AXIOM Phase 3.6: `None` iff the loaded file had NO
    /// `[[protected_resource]]` key at all (see `RawPolicyFile::
    /// protected_resource`'s doc comment for why that's tracked separately
    /// from "present but empty"). Drives both enforcement points described
    /// in this module's doc comment.
    protected_resources: Option<Vec<ProtectedResource>>,
    /// AXIOM Phase 3.8: local-only kill-switch runtime state - see
    /// `KillSwitch`'s own doc comment. Lives alongside the loaded policy
    /// (not persisted, not part of the on-disk TOML this struct otherwise
    /// only ever reads) because `CapabilityPolicy` is already the one
    /// `Arc`-shared object every real capability call passes through
    /// `check_and_acquire` on, AND the one object `forge-node`'s local
    /// admin control socket already holds a shared handle to
    /// (`NetworkManager::policy()`) - no second Arc/shared-state plumbing
    /// needed for a mutation here to take effect on the live node.
    kill_switch: KillSwitch,
}

impl CapabilityPolicy {
    /// Fail-closed load: ANY error (missing file, malformed TOML,
    /// unsupported `version`, an `allowed_peers` entry that isn't valid
    /// hex) logs loudly via `tracing::error!` and returns a policy that
    /// authorizes NOTHING, rather than propagating the error up to fail
    /// node startup entirely - discovery/handshake/liveness must keep
    /// working even with a broken policy file; only capability dispatch is
    /// refused. Never panics, never returns `Result` - there is no caller
    /// that should ever need to handle this failing differently from "the
    /// policy denies everything for now."
    pub fn load(path: &Path) -> Self {
        match Self::try_load(path) {
            Ok(policy) => {
                info!(
                    "Loaded capability policy from {} ({} capability entr{} configured)",
                    path.display(),
                    policy.entries.len(),
                    if policy.entries.len() == 1 { "y" } else { "ies" },
                );
                policy
            }
            Err(e) => {
                error!(
                    "Capability policy {} failed to load: {:#} - FAILING CLOSED: no \
                     capability (echo/sysinfo/network_clients/etc) will serve ANY peer \
                     until this is fixed. Discovery, handshaking, and liveness (Ping/Pong) \
                     are unaffected - only capability dispatch is refused.",
                    path.display(),
                    e,
                );
                Self::deny_all()
            }
        }
    }

    /// A policy with zero capability entries - every `check_and_acquire`
    /// call against it returns `NotAuthorized`, for every capability and
    /// every peer, unconditionally.
    fn deny_all() -> Self {
        Self {
            entries: HashMap::new(),
            rate_limit_state: Mutex::new(HashMap::new()),
            protected_resources: None,
            kill_switch: KillSwitch::new(),
        }
    }

    fn try_load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let raw: RawPolicyFile = toml::from_str(&contents)
            .with_context(|| format!("failed to parse {} as TOML", path.display()))?;
        if raw.version != POLICY_SCHEMA_VERSION {
            anyhow::bail!(
                "policy file declares schema version {} but this build only understands version {}",
                raw.version, POLICY_SCHEMA_VERSION,
            );
        }

        // AXIOM Phase 3.6: parsed once, ahead of the per-capability loop
        // below, since the loop's own fail-closed decision (a Tier1/Tier2
        // entry with no protected-resource section registers as if it were
        // absent entirely) needs to know whether this is `None` (section
        // absent) before it can decide any individual capability's fate.
        // A malformed individual `[[protected_resource]]` entry (bad MAC)
        // is logged and skipped - same per-entry-not-whole-file precedent
        // `allowed_peers` already uses below - it does NOT turn a
        // `Some(vec![...])` into `None`; the section is still "present".
        let protected_resources: Option<Vec<ProtectedResource>> = raw.protected_resource.map(|raw_list| {
            let mut list = Vec::new();
            for raw_pr in raw_list {
                match ProtectedResource::new(raw_pr.name.clone(), &raw_pr.mac, raw_pr.ip.clone()) {
                    Some(pr) => list.push(pr),
                    None => warn!(
                        "capability policy: [[protected_resource]] entry '{}' has an invalid mac \
                         ('{}' is not a valid 6-octet colon/hyphen hex MAC) - skipped, other \
                         protected-resource entries are unaffected",
                        raw_pr.name.as_deref().unwrap_or("<unnamed>"), raw_pr.mac,
                    ),
                }
            }
            list
        });

        let mut entries = HashMap::new();
        for (name, raw_entry) in raw.capability {
            // AXIOM Phase 3.1/3.2: a missing or unrecognized `tier` fails
            // closed for THIS capability only - `continue` skips inserting
            // an entry for it at all, so `check_and_acquire` sees it
            // exactly as if `[capability.<name>]` were absent entirely
            // (the same fail-closed mechanism the module doc comment
            // already documents for that case - this is intentional
            // reuse, not a new mechanism). Other, correctly-tiered
            // capabilities in this same file are unaffected.
            let tier = match raw_entry.tier.as_deref().and_then(Tier::from_toml_str) {
                Some(tier) => tier,
                None => {
                    warn!(
                        "capability policy: [capability.{}].tier is missing or not one of \
                         \"tier0\"/\"tier1\"/\"tier2\" - schema v2 requires a valid tier per \
                         capability, so this capability fails closed (serves NO ONE) until \
                         fixed; other capabilities in this file are unaffected",
                        name,
                    );
                    continue;
                }
            };

            // AXIOM Phase 3.6: same fail-closed mechanism, reused again -
            // a Tier1/Tier2 capability in a file with NO protected-resource
            // section AT ALL never registers, so `check_and_acquire` (the
            // one central check every real capability call already passes
            // through, in `forge-node::network::dispatch_intent`) denies
            // it for everyone until a protected-resource section (even an
            // empty one) exists. Tier0 is untouched - see `Tier::Tier0`'s
            // own doc comment for why it has no external target to protect
            // against in the first place.
            if tier != Tier::Tier0 && protected_resources.is_none() {
                warn!(
                    "capability policy: [capability.{}] is {} but this policy file has NO \
                     [[protected_resource]] section at all - failing closed (serves NO ONE) \
                     until a protected-resource section (even an empty one, meaning \
                     'deliberately nothing protected yet') is added; other, Tier0 \
                     capabilities in this file are unaffected",
                    name, tier.as_str(),
                );
                continue;
            }

            // AXIOM Phase 3.8: `HashMap<NodeId, Option<u64>>` now, not a
            // `HashSet<NodeId>` - see `CapabilityEntry::allowed_peers`'s own
            // doc comment. `expires` is stored as-is, NOT compared against
            // "now" here - see this module's top-of-file Phase 3.8
            // doc-comment section for why expiry is evaluated live, not at
            // load time.
            let mut allowed_peers = HashMap::new();
            for raw_peer in &raw_entry.allowed_peers {
                let s = raw_peer.peer_str();
                match hex::decode(s).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                    Some(arr) => { allowed_peers.insert(NodeId::from_bytes(arr), raw_peer.expires()); }
                    // Same log-and-skip-this-one-entry precedent as the old
                    // network_clients_allowed_peers/wan_allowed_peers
                    // parsing - a typo'd peer entry degrades to "that one
                    // peer isn't allowed," not "the whole policy file (and
                    // therefore every OTHER capability's entries too) is
                    // untrustworthy." The capability entry itself still
                    // fails closed on its own if this leaves it empty.
                    None => warn!(
                        "capability policy: '{}' in [capability.{}].allowed_peers is not a valid 32-byte hex NodeId, skipped",
                        s, name,
                    ),
                }
            }
            entries.insert(name, CapabilityEntry {
                allowed_peers,
                rate_limit: Duration::from_secs(raw_entry.rate_limit_secs),
                semaphore: std::sync::Arc::new(Semaphore::new(raw_entry.concurrency)),
                concurrency: raw_entry.concurrency,
                tier,
                denied_param_substrings: raw_entry.denied_param_substrings.iter().map(|s| s.to_lowercase()).collect(),
            });
        }

        Ok(Self {
            entries,
            rate_limit_state: Mutex::new(HashMap::new()),
            protected_resources,
            kill_switch: KillSwitch::new(),
        })
    }

    /// Check whether `sender_id` may make one call to `capability` right
    /// now, and if so, reserve one of its concurrency slots for the
    /// duration of that call. Checked in a fixed order - allowlist, then
    /// rate limit, then concurrency - matching the order
    /// `dispatch_network_clients` always used before this module existed,
    /// so an unauthorized peer's request never even touches the rate-limit
    /// or concurrency bookkeeping (nothing to gain by letting it).
    pub fn check_and_acquire(&self, capability: &str, sender_id: NodeId) -> PolicyOutcome {
        let Some(entry) = self.entries.get(capability) else {
            return PolicyOutcome::NotAuthorized;
        };

        // AXIOM Phase 3.8: kill switch, checked ahead of the allowlist
        // itself, inside the SAME mandatory gate every real capability call
        // already passes through (see this module's top-of-file Phase 3.8
        // doc-comment section, and `forge-node/src/capability_isolation.rs`'s
        // `check_and_acquire_runs_before_any_capability_handler_in_dispatch_intent`
        // test, which proves this call runs before any handler for every
        // capability, LAN and WAN both). `Suspended` denies EVERY tier;
        // `Frozen` exempts `Tier0` - see `KillSwitch`'s own doc comment for
        // why the two levers have different scope.
        if self.kill_switch.suspended.lock().unwrap().contains(&sender_id) {
            return PolicyOutcome::Suspended;
        }
        if entry.tier != Tier::Tier0 && self.kill_switch.frozen.load(std::sync::atomic::Ordering::SeqCst) {
            return PolicyOutcome::Frozen;
        }

        if !peer_currently_allowed(&entry.allowed_peers, sender_id) {
            return PolicyOutcome::NotAuthorized;
        }

        {
            let mut rate_limit_state = self.rate_limit_state.lock().unwrap();
            let now = Instant::now();
            let key = (capability.to_string(), sender_id);
            if let Some(last) = rate_limit_state.get(&key) {
                if now.duration_since(*last) < entry.rate_limit {
                    return PolicyOutcome::RateLimited;
                }
            }
            rate_limit_state.insert(key, now);
        }

        match entry.semaphore.clone().try_acquire_owned() {
            Ok(permit) => PolicyOutcome::Allowed(permit),
            Err(_) => PolicyOutcome::AtConcurrencyLimit,
        }
    }

    /// AXIOM Phase 3.1/3.2: the tier a registered capability was loaded
    /// with, or `None` if this capability has no registered entry at all
    /// (missing `[capability.<name>]` table, or one that failed closed for
    /// lacking a valid `tier` - see `try_load`). Future Phase 3.3
    /// (approval flow) and 3.4 (audit log) consumers are expected to call
    /// this to decide whether their own tier-gated behavior applies to a
    /// given capability; nothing in this crate consumes it yet - Phase
    /// 3.1/3.2 is the tier MODEL and registration-gating only.
    pub fn tier(&self, capability: &str) -> Option<Tier> {
        self.entries.get(capability).map(|entry| entry.tier)
    }

    /// AXIOM Phase 3.2 (`axiom access` CLI): every capability with a
    /// registered (correctly-tiered, successfully-loaded) entry - i.e.
    /// exactly the set `tier()`/`capability_summary()` would return
    /// `Some(_)` for. Order is unspecified (backed by a `HashMap`) -
    /// callers that want stable output should sort it themselves, the same
    /// way `capability_summary`'s `allowed_peers` is pre-sorted because
    /// THAT ordering has no natural alternative a caller could impose
    /// itself as easily.
    pub fn capability_names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// AXIOM Phase 3.2 (`axiom access` CLI): read-only metadata for one
    /// capability - tier, rate limit, concurrency, and its full allowlist
    /// (hex-encoded, sorted). `None` if this capability has no registered
    /// entry - same "no entry" semantics as `tier()` (missing from the
    /// file entirely, or present but failed closed for lacking a valid
    /// `tier` - both cases are indistinguishable from the outside, by
    /// design, same as everywhere else in this module's fail-closed
    /// contract).
    pub fn capability_summary(&self, capability: &str) -> Option<CapabilitySummary> {
        self.entries.get(capability).map(|entry| {
            // AXIOM Phase 3.8: only currently-effective (non-expired)
            // peers are reported - checked live, same as `check_and_acquire`/
            // `allows` - so an expired entry never shows up here either
            // (see `CapabilitySummary::allowed_peers`'s own doc comment).
            let now = now_unix_secs();
            let mut allowed_peers: Vec<(String, Option<u64>)> = entry
                .allowed_peers
                .iter()
                .filter(|(_, expires)| expires.is_none_or(|e| now < e))
                .map(|(p, expires)| (hex::encode(p.as_bytes()), *expires))
                .collect();
            allowed_peers.sort_by(|a, b| a.0.cmp(&b.0));
            CapabilitySummary {
                tier: entry.tier,
                rate_limit_secs: entry.rate_limit.as_secs(),
                concurrency: entry.concurrency,
                allowed_peers,
            }
        })
    }

    /// AXIOM Phase 3.2 (`axiom access` CLI): true if `identity` is on
    /// `capability`'s allowlist - the same allowlist lookup
    /// `check_and_acquire` makes internally, exposed on its own for a
    /// read-only caller that wants to answer "can this identity call this
    /// capability" without acquiring a concurrency permit or touching
    /// rate-limit state the way `check_and_acquire` does as a side effect.
    /// `false` for a capability with no registered entry at all, same
    /// fail-closed default as everywhere else.
    pub fn allows(&self, capability: &str, identity: NodeId) -> bool {
        self.entries.get(capability).is_some_and(|entry| peer_currently_allowed(&entry.allowed_peers, identity))
    }

    // ---------------------------------------------------------------
    // AXIOM Phase 3.8: kill switch - local-only, runtime-mutable. See
    // `KillSwitch`'s own doc comment and this module's top-of-file Phase
    // 3.8 doc-comment section for the full design. Every method below is
    // reachable ONLY via `forge-node`'s local admin control socket - see
    // `forge-node/src/capability_isolation.rs`'s
    // `capability_dispatch_has_zero_references_to_kill_switch_mutators_today`
    // and `kill_switch_names_are_not_registered_as_capabilities` tests for
    // the enforced proof this never becomes reachable as a capability.
    // ---------------------------------------------------------------

    /// Freeze ALL Tier1+ capability execution, effective on the very next
    /// `check_and_acquire` call (no restart, no policy-file reload -
    /// runtime state, not the on-disk file). `Tier0` and the audit log
    /// itself are unaffected - see `KillSwitch`'s own doc comment.
    /// Idempotent - freezing an already-frozen policy is a no-op.
    pub fn freeze(&self) {
        self.kill_switch.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The explicit, primary un-freeze - see this module's top-of-file
    /// Phase 3.8 doc-comment section for why this is a deliberate, separate
    /// call rather than an implicit timeout. Idempotent.
    pub fn unfreeze(&self) {
        self.kill_switch.frozen.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_frozen(&self) -> bool {
        self.kill_switch.frozen.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Suspend one peer identity - denied for EVERY tier, including
    /// `Tier0` (see `KillSwitch`'s own doc comment for why this is the
    /// conservative reading chosen). Idempotent.
    pub fn suspend_peer(&self, peer: NodeId) {
        self.kill_switch.suspended.lock().unwrap().insert(peer);
    }

    /// Explicit un-suspend for one peer. Returns `true` if it was actually
    /// suspended (`false` if it was already clear - not an error either
    /// way, same "explicit action, not an error to repeat" precedent as
    /// `unfreeze`).
    pub fn unsuspend_peer(&self, peer: NodeId) -> bool {
        self.kill_switch.suspended.lock().unwrap().remove(&peer)
    }

    pub fn is_suspended(&self, peer: NodeId) -> bool {
        self.kill_switch.suspended.lock().unwrap().contains(&peer)
    }

    /// Every currently-suspended identity, hex-encoded and sorted - for
    /// reporting (mirrors `CapabilitySummary::allowed_peers`'s own
    /// hex-and-sorted convention).
    pub fn suspended_peers(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.kill_switch.suspended.lock().unwrap().iter().map(|p| hex::encode(p.as_bytes())).collect();
        v.sort();
        v
    }

    /// AXIOM Phase 3.6: true iff this policy's on-disk file had a
    /// `[[protected_resource]]` section AT ALL - present-but-empty counts
    /// as configured (see `RawPolicyFile::protected_resource`'s doc
    /// comment for why that distinction is deliberate). `approval::
    /// Tier2ApprovalFlow::propose_with_expiry` calls this FIRST, before
    /// even attempting `find_protected_match`, and fails closed
    /// (`ProposeError::ProtectedResourceSectionMissing`) if it's `false` -
    /// the same "no section at all -> deny" contract `try_load`'s
    /// registration gate already enforces for `check_and_acquire`, applied
    /// independently at this second enforcement point too (see this
    /// module's own doc comment for why there are two).
    pub fn protected_resources_configured(&self) -> bool {
        self.protected_resources.is_some()
    }

    /// Every successfully-parsed protected-resource entry, or an empty
    /// slice if the section is absent OR present-but-empty - callers that
    /// need to distinguish those two should use
    /// `protected_resources_configured` instead.
    pub fn protected_resources(&self) -> &[ProtectedResource] {
        self.protected_resources.as_deref().unwrap_or(&[])
    }

    /// AXIOM Phase 3.6: does ANY of `parameters` reference a protected
    /// resource? Scans every `String`/`OneOf` constraint value for a
    /// MAC-shaped or IPv4-shaped substring and cross-checks it against the
    /// protected list - see this module's doc comment for the full
    /// design rationale (generic scan over an explicit-target-declaration
    /// scheme). Returns the FIRST match found (parameter order, then
    /// MAC-before-IP within one value) - `None` means clean, including the
    /// trivial case where `protected_resources()` is empty.
    ///
    /// Deliberately does NOT itself consult `protected_resources_configured`
    /// - a caller with an empty-but-present list legitimately wants "no
    /// match, proceed" here, not a fail-closed denial; the fail-closed
    /// "no section at all" case is `protected_resources_configured`'s job,
    /// checked separately (and first) by callers like `Tier2ApprovalFlow`.
    pub fn find_protected_match(&self, parameters: &[Constraint]) -> Option<ProtectedMatch> {
        let protected = self.protected_resources();
        if protected.is_empty() {
            return None;
        }
        for constraint in parameters {
            for text in scannable_strings(&constraint.value) {
                for mac in scan_mac_candidates_including_whitespace_obfuscated(&text) {
                    if let Some(pr) = protected.iter().find(|p| p.mac == mac) {
                        return Some(ProtectedMatch {
                            resource_name: pr.name.clone(),
                            resource_mac: pr.mac_display.clone(),
                            resource_ip: pr.ip.clone(),
                            matched_value: format_mac(&mac),
                            parameter_key: constraint.key.clone(),
                        });
                    }
                }
                for ip in scan_ipv4_candidates(&text) {
                    if let Some(pr) = protected.iter().find(|p| p.ip.as_deref() == Some(ip.as_str())) {
                        return Some(ProtectedMatch {
                            resource_name: pr.name.clone(),
                            resource_mac: pr.mac_display.clone(),
                            resource_ip: pr.ip.clone(),
                            matched_value: ip,
                            parameter_key: constraint.key.clone(),
                        });
                    }
                }
            }
        }
        None
    }

    /// AXIOM Phase 3.6: the minimal per-capability argument constraint -
    /// does any of `parameters` contain (case-insensitively) one of
    /// `capability`'s configured `denied_param_substrings`? `None` if the
    /// capability isn't registered at all, has no denylist configured, or
    /// nothing matches - `Some(reason)` (human-readable, names the
    /// offending parameter key and pattern) on the first hit.
    pub fn check_denied_param_substrings(&self, capability: &str, parameters: &[Constraint]) -> Option<String> {
        let entry = self.entries.get(capability)?;
        if entry.denied_param_substrings.is_empty() {
            return None;
        }
        for constraint in parameters {
            for text in scannable_strings(&constraint.value) {
                let lower = text.to_lowercase();
                for pattern in &entry.denied_param_substrings {
                    if lower.contains(pattern.as_str()) {
                        return Some(format!(
                            "parameter '{}' value matches denied pattern '{}' configured for capability '{}'",
                            constraint.key, pattern, capability,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Test-only constructor: build a policy directly in memory (no TOML
    /// file involved) with the SAME `allowed_peers` set applied uniformly
    /// across every capability named in `capabilities`, no rate limit, and
    /// generous concurrency - real production policy is never this
    /// uniform, but most existing tests that consume this (in forge-node)
    /// exist to prove routing/forwarding/gossip behavior, not
    /// authorization, and need a policy that simply gets out of the way
    /// for whichever peers they name. Tests that specifically exercise
    /// `CapabilityPolicy` itself (fail-closed loading, empty allowlist,
    /// rate limit, concurrency) go through `try_load`/`load` instead, in
    /// this module's own test section below.
    ///
    /// Gated behind `test-utils` (in addition to `test`) rather than left
    /// unconditionally `pub` - `#[cfg(test)]` alone only applies when THIS
    /// crate is compiled in test mode, not when forge-node compiles ITS
    /// OWN tests against axiom-gateway as a normal dependency. Same
    /// pattern as axiom-transport's `test-utils` feature.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_test(capabilities: &[&str], allowed_peers: std::collections::HashSet<NodeId>) -> Self {
        // AXIOM Phase 3.8: every peer here is a permanent (`None`-expiry)
        // entry - this constructor's whole point is "get out of the way,"
        // and an expiring entry would make these tests' pass/fail depend
        // on wall-clock timing they were never meant to care about.
        let allowed_peers: HashMap<NodeId, Option<u64>> = allowed_peers.into_iter().map(|p| (p, None)).collect();
        let mut entries = HashMap::new();
        for name in capabilities {
            entries.insert((*name).to_string(), CapabilityEntry {
                allowed_peers: allowed_peers.clone(),
                rate_limit: Duration::ZERO,
                semaphore: std::sync::Arc::new(Semaphore::new(1024)),
                concurrency: 1024,
                // AXIOM Phase 3.1/3.2: a uniform Tier0 stand-in. The
                // callers of this constructor (forge-node's own routing/
                // forwarding/gossip tests) exist to prove request delivery,
                // not tier-based enforcement - which isn't wired into
                // `check_and_acquire` at all yet (Phase 3.3/3.4 future
                // work) - so the specific tier value here is inert.
                tier: Tier::Tier0,
                // AXIOM Phase 3.6: no argument constraints for this
                // uniform test fixture either - same "inert, unrelated to
                // what these tests actually exercise" reasoning as `tier`
                // above.
                denied_param_substrings: Vec::new(),
            });
        }
        // AXIOM Phase 3.6: `None` (no protected-resource section) is safe
        // here specifically BECAUSE every entry above is hard-coded
        // `Tier::Tier0` - the fail-closed "Tier1+ without a
        // protected-resource section doesn't register" rule this struct
        // otherwise enforces (see `try_load`) only ever applies to
        // Tier1/Tier2 entries, none of which this constructor ever builds.
        Self {
            entries,
            rate_limit_state: Mutex::new(HashMap::new()),
            protected_resources: None,
            kill_switch: KillSwitch::new(),
        }
    }

    /// AXIOM Phase 3.6, test-only: like `for_test`, but for exercising
    /// `approval::Tier2ApprovalFlow`'s protected-resource/argument-
    /// constraint gates directly, which don't consult `entries`/tier
    /// registration at all (see `Tier2ApprovalFlow::propose_with_expiry`) -
    /// only `protected_resources_configured`/`find_protected_match` (and,
    /// via `capability_entry_for_test`, `check_denied_param_substrings`).
    /// `protected_resources` mirrors `try_load`'s own `None`-vs-`Some(vec)`
    /// distinction - pass `None` to simulate "no protected-resource
    /// section at all" (fail-closed), `Some(vec![])` for "configured, empty".
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_test_with_protected_resources(protected_resources: Option<Vec<ProtectedResource>>) -> Self {
        Self {
            entries: HashMap::new(),
            rate_limit_state: Mutex::new(HashMap::new()),
            protected_resources,
            kill_switch: KillSwitch::new(),
        }
    }

    /// AXIOM Phase 3.6, test-only: like `for_test_with_protected_resources`,
    /// plus a single registered capability entry carrying
    /// `denied_param_substrings` - for exercising `Tier2ApprovalFlow`'s
    /// `check_denied_param_substrings` call, which DOES need a real
    /// `entries` lookup by capability name (unlike the protected-resource
    /// checks above).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_test_with_denied_substrings(
        capability: &str,
        protected_resources: Option<Vec<ProtectedResource>>,
        denied_param_substrings: Vec<&str>,
    ) -> Self {
        let mut entries = HashMap::new();
        entries.insert(capability.to_string(), CapabilityEntry {
            allowed_peers: HashMap::new(),
            rate_limit: Duration::ZERO,
            semaphore: std::sync::Arc::new(Semaphore::new(1024)),
            concurrency: 1024,
            tier: Tier::Tier2,
            denied_param_substrings: denied_param_substrings.into_iter().map(|s| s.to_lowercase()).collect(),
        });
        Self {
            entries,
            rate_limit_state: Mutex::new(HashMap::new()),
            protected_resources,
            kill_switch: KillSwitch::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_crypto::identity::Keypair;

    fn write_policy(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn missing_file_denies_every_capability() {
        let policy = CapabilityPolicy::load(std::path::Path::new("/nonexistent/does-not-exist.toml"));
        let peer = Keypair::generate().node_id();
        for cap in ["echo", "sysinfo", "network_clients"] {
            assert!(matches!(policy.check_and_acquire(cap, peer), PolicyOutcome::NotAuthorized));
        }
    }

    #[test]
    fn malformed_toml_denies_every_capability() {
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-malformed.toml", "this is not valid TOML {{{");
        let policy = CapabilityPolicy::load(&path);
        let peer = Keypair::generate().node_id();
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unsupported_schema_version_denies_every_capability() {
        // version = 3: a hypothetical FUTURE schema this build doesn't
        // understand either - version = 2 is no longer a good stand-in for
        // "unsupported" now that it's this build's own current schema
        // (see the dedicated `v1_schema_file_denies_every_capability` test
        // below for the specific, real "old schema" case).
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-badversion.toml", &format!(
            "version = 3\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized));
        let _ = std::fs::remove_file(&path);
    }

    /// AXIOM Phase 3.1/3.2's core new requirement: a real, well-formed
    /// schema-v1 file (the exact shape every file predating this change
    /// used, no `tier` field anywhere because that field didn't exist yet)
    /// must be recognized as valid TOML - `toml::from_str` succeeds, this
    /// is NOT the `malformed_toml_denies_every_capability` case - and then
    /// fail closed across every capability because this build's schema is
    /// v2, not because the file itself is broken. Distinguishing "parses
    /// fine, but this build doesn't trust an unmigrated file" from "doesn't
    /// even parse" is exactly what the module doc comment's fail-closed
    /// contract requires - see `unsupported_schema_version_denies_every_capability`
    /// just above for the closely-related generic case this specializes.
    #[test]
    fn v1_schema_file_denies_every_capability() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-v1schema.toml", &format!(
            "version = 1\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\n\n\
             [capability.network_clients]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        // load() must not panic and CapabilityPolicy::load never returns
        // Err (it has no Err variant) - reaching this line at all already
        // proves "service stays up." What's asserted below is that NOTHING
        // in this otherwise entirely-well-formed, fully-allowlisted v1
        // file is authorized under v2 code.
        let policy = CapabilityPolicy::load(&path);
        for cap in ["echo", "sysinfo", "network_clients"] {
            assert!(
                matches!(policy.check_and_acquire(cap, peer), PolicyOutcome::NotAuthorized),
                "v1 schema file must deny '{cap}' even though that peer is explicitly allowlisted in it",
            );
            assert_eq!(policy.tier(cap), None, "an untiered (pre-v2) capability must not register a tier at all");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn capability_with_no_entry_denies_everyone() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        // Valid file, but only "echo" gets an entry - "sysinfo" has none.
        let path = write_policy(&dir, "axiom-policy-test-partial.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        assert!(matches!(policy.check_and_acquire("sysinfo", peer), PolicyOutcome::NotAuthorized));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_allowlist_denies_everyone_for_that_capability() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-emptylist.toml",
            "version = 2\n\n[capability.echo]\nallowed_peers = []\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
        );
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn allowlisted_peer_is_allowed() {
        let peer = Keypair::generate().node_id();
        let stranger = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-allowed.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        assert!(matches!(policy.check_and_acquire("echo", stranger), PolicyOutcome::NotAuthorized));
        assert_eq!(policy.tier("echo"), Some(Tier::Tier0));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalid_hex_peer_entry_is_skipped_not_fatal() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-badhex.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"not-valid-hex\", \"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        // The malformed entry is skipped (logged), but the file as a whole
        // still loads and the OTHER, valid entry still works.
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rate_limit_rejects_second_call_within_window() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-ratelimit.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 30\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::RateLimited));
        let _ = std::fs::remove_file(&path);
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED:
    /// a DoS-shaped rapid-fire attempt - many requests fired back-to-back
    /// in a tight loop, not just the single extra call
    /// `rate_limit_rejects_second_call_within_window` already checks -
    /// confirms the limiter actually engages for every one of them (no
    /// off-by-one letting a second or third slip through), and that a real
    /// wait past the window correctly re-admits exactly one more call, not
    /// a burst of all the ones that were denied along the way (i.e. denied
    /// requests are not queued/replayed once the window reopens - they were
    /// simply refused).
    #[test]
    fn rapid_fire_requests_beyond_the_rate_limit_are_all_denied_until_the_window_passes() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-ratelimit-rapidfire.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 1\nconcurrency = 1000\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);

        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "the first call must succeed");
        // 50 rapid-fire follow-up attempts, all well inside the 1-second
        // window - every single one must be denied, none should slip
        // through due to an off-by-one in the rate-limit-state bookkeeping.
        for i in 0..50 {
            assert!(
                matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::RateLimited),
                "rapid-fire request #{i} must be rate-limited, not allowed",
            );
        }

        std::thread::sleep(Duration::from_millis(1100));
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "exactly one call must be re-admitted once the window has genuinely passed");
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::RateLimited), "and the window resets immediately - no burst of the previously-denied calls gets let through");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrency_limit_rejects_beyond_capacity() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-concurrency.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 1\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        let first = policy.check_and_acquire("echo", peer);
        assert!(matches!(first, PolicyOutcome::Allowed(_)));
        // First permit still held (not dropped) - the single concurrency
        // slot is exhausted, so a second call must be rejected distinctly
        // from a rate-limit rejection (rate_limit_secs is 0 here, so this
        // can only be the concurrency gate).
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::AtConcurrencyLimit));
        drop(first);
        // Releasing the permit frees the slot for the next call.
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// AXIOM Phase 3.1/3.2: a v2 file where one capability simply omits
    /// `tier` entirely - that ONE capability fails closed; a sibling
    /// capability in the SAME file with a valid tier is entirely
    /// unaffected. This is the chosen granularity for "untiered entry in
    /// an otherwise-v2 file" (see `RawCapabilityEntry::tier`'s doc comment
    /// for the one documented exception, tested separately below).
    #[test]
    fn capability_missing_tier_denies_only_that_capability() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-missingtier.toml", &format!(
            "version = 2\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "echo has a valid tier, must be unaffected");
        assert!(matches!(policy.check_and_acquire("sysinfo", peer), PolicyOutcome::NotAuthorized), "sysinfo has no tier field at all, must fail closed");
        assert_eq!(policy.tier("echo"), Some(Tier::Tier0));
        assert_eq!(policy.tier("sysinfo"), None, "an untiered entry must not register a tier");
        let _ = std::fs::remove_file(&path);
    }

    /// Same granularity claim as `capability_missing_tier_denies_only_that_capability`,
    /// but for a `tier` field that's PRESENT with a syntactically valid
    /// TOML string that just isn't a recognized tier name (a typo, e.g.)
    /// - as opposed to a `tier` field of the wrong TOML type entirely,
    /// which is a distinct, documented, whole-file-fatal case covered by
    /// `capability_tier_wrong_toml_type_fails_whole_file_closed` below.
    #[test]
    fn capability_invalid_tier_name_denies_only_that_capability() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-invalidtiername.toml", &format!(
            "version = 2\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"not-a-real-tier\"\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "echo has a valid tier, must be unaffected");
        assert!(matches!(policy.check_and_acquire("sysinfo", peer), PolicyOutcome::NotAuthorized), "sysinfo's tier name doesn't match tier0/tier1/tier2, must fail closed");
        let _ = std::fs::remove_file(&path);
    }

    /// The one documented exception to per-entry tier-failure granularity:
    /// a `tier` value that's the WRONG TOML TYPE (an integer literal here,
    /// not a quoted string at all) is a type mismatch at the
    /// `toml::from_str::<RawPolicyFile>` layer itself - it fails the WHOLE
    /// file closed, taking down `echo` (which is otherwise perfectly
    /// well-formed) along with the offending `sysinfo` entry. See
    /// `RawCapabilityEntry::tier`'s doc comment for why this specific case
    /// isn't caught at per-entry granularity like a missing field or an
    /// invalid tier NAME are.
    #[test]
    fn capability_tier_wrong_toml_type_fails_whole_file_closed() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-tierwrongtype.toml", &format!(
            "version = 2\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = 3\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(
            matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized),
            "a TOML type-mismatched tier value elsewhere in the file fails the WHOLE file closed - even echo's otherwise-perfectly-valid entry doesn't survive it",
        );
        assert!(matches!(policy.check_and_acquire("sysinfo", peer), PolicyOutcome::NotAuthorized));
        let _ = std::fs::remove_file(&path);
    }

    /// AXIOM Phase 3.1/3.2: proves the tier model SUPPORTS declaring a
    /// Tier2 (destructive/security-relevant) capability - it's parsed,
    /// registered, and its tier is queryable - even though nothing in this
    /// codebase is Tier2 yet and the human-approval enforcement that tier
    /// implies (Phase 3.3) isn't built. `check_and_acquire` still returns
    /// `Allowed` for an allowlisted peer here: this task is schema/tier-
    /// assignment plumbing only, NOT the approval gate itself - see this
    /// module's top-of-file doc comment.
    #[test]
    fn tier2_capability_is_declarable_and_parseable() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        // AXIOM Phase 3.6: this fixture now ALSO needs a [[protected_resource]]
        // section - without one, a Tier2 entry fails closed at registration
        // (see `try_load`'s new gate) and this test would be proving the
        // wrong thing entirely (a denied capability, not a declarable one).
        let path = write_policy(&dir, "axiom-policy-test-tier2.toml", &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.some_future_destructive_capability]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 1\ntier = \"tier2\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert_eq!(policy.tier("some_future_destructive_capability"), Some(Tier::Tier2));
        assert!(matches!(
            policy.check_and_acquire("some_future_destructive_capability", peer),
            PolicyOutcome::Allowed(_)
        ), "Phase 3.1/3.2 is registration/tier-assignment only - Tier2's approval gate is Phase 3.3, not yet enforced");
        let _ = std::fs::remove_file(&path);
    }

    /// A `Tier1` sanity check alongside the `Tier0`/`Tier2` coverage above
    /// - matches `network_clients`'s real ratified assignment (DECISIONS.md).
    #[test]
    fn tier1_capability_reports_correct_tier() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        // AXIOM Phase 3.6: needs a [[protected_resource]] section too - see
        // the identical note on `tier2_capability_is_declarable_and_parseable`.
        let path = write_policy(&dir, "axiom-policy-test-tier1.toml", &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.network_clients]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 30\nconcurrency = 2\ntier = \"tier1\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert_eq!(policy.tier("network_clients"), Some(Tier::Tier1));
        let _ = std::fs::remove_file(&path);
    }

    /// AXIOM Phase 3.1/3.2's live-migration verification, extended by
    /// Phase 3.6: this string is the EXACT content deployed to the live
    /// systemd-managed node's `/etc/forge/capability_policy.toml` as part
    /// of this same change (see the deploy notes in the commit this test
    /// ships in) - not a paraphrase or a re-derivation of it. Proves the
    /// actual migrated file parses under this build and preserves its
    /// pre-migration fail-closed posture: `echo`/`sysinfo` keep their
    /// empty allowlists (still deny everyone, exactly as before - this was
    /// an ADDITIVE migration, not a rewrite of the access rules) and now
    /// also report `tier0`; `network_clients` still has no entry at all
    /// (deliberately - see the embedded file's own header comment) and so
    /// still denies everyone and reports no tier, identical to its
    /// pre-migration state. Phase 3.6 adds the ratified
    /// `[[protected_resource]]` list (`DECISIONS.md`) - also purely
    /// additive; `echo`/`sysinfo` are `Tier0` and therefore untouched by
    /// the new fail-closed registration gate this section exists to
    /// satisfy for any FUTURE tier1/tier2 entry.
    const LIVE_MIGRATED_POLICY_TOML: &str = r#"
version = 2

[capability.echo]
allowed_peers = []
rate_limit_secs = 5
concurrency = 10
tier = "tier0"

[capability.sysinfo]
allowed_peers = []
rate_limit_secs = 5
concurrency = 10
tier = "tier0"

[[protected_resource]]
name = "proxmox-host-ethernet"
mac = "AA:BB:CC:11:22:01"
ip = "192.168.1.10"

[[protected_resource]]
name = "proxmox-host-wifi"
mac = "AA:BB:CC:11:22:02"

[[protected_resource]]
name = "desktop-desktop-ethernet"
mac = "AA:BB:CC:11:22:03"
ip = "192.168.1.11"

[[protected_resource]]
name = "desktop-desktop-wifi"
mac = "AA:BB:CC:11:22:04"

[[protected_resource]]
name = "router-gateway"
mac = "AA:BB:CC:11:22:05"
ip = "192.168.1.1"

[[protected_resource]]
name = "omada-controller"
mac = "AA:BB:CC:11:22:06"
ip = "192.168.1.14"

[[protected_resource]]
name = "laptop-larrys-laptop-wifi"
mac = "AA:BB:CC:11:22:07"
ip = "192.168.1.13"

[[protected_resource]]
name = "laptop-larrys-laptop-ethernet"
mac = "AA:BB:CC:11:22:08"
"#;

    #[test]
    fn live_migrated_policy_file_parses_and_preserves_deny_all() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-live-migrated.toml", LIVE_MIGRATED_POLICY_TOML);
        let policy = CapabilityPolicy::load(&path);

        // Tier is now correctly assigned for both real capabilities...
        assert_eq!(policy.tier("echo"), Some(Tier::Tier0));
        assert_eq!(policy.tier("sysinfo"), Some(Tier::Tier0));
        // ...network_clients still isn't in the file at all, unaffected by
        // this migration - see the embedded file's own header comment.
        assert_eq!(policy.tier("network_clients"), None);

        // ...but the empty allowed_peers lists (unchanged by this
        // migration) still mean nobody is actually authorized for
        // anything - additive tier metadata never loosens access control.
        for cap in ["echo", "sysinfo", "network_clients"] {
            assert!(
                matches!(policy.check_and_acquire(cap, peer), PolicyOutcome::NotAuthorized),
                "'{cap}' must still deny everyone after migration - this was an additive tier migration, not an access-rule change",
            );
        }

        // AXIOM Phase 3.6: the real ratified protected-resource list is
        // present and parses - spot-check a couple of entries rather than
        // every field of every one (DECISIONS.md is the source of truth
        // for the full list; this just proves THIS file matches it for
        // the mechanism to actually work).
        assert!(policy.protected_resources_configured());
        assert_eq!(policy.protected_resources().len(), 8, "DECISIONS.md's ratified list has 8 entries - every physical interface on every management-plane device");
        assert!(
            policy.protected_resources().iter().any(|pr| pr.mac_display() == "aa:bb:cc:11:22:01" && pr.ip.as_deref() == Some("192.168.1.10")),
            "the Proxmox host's own ethernet MAC must be in the migrated live file",
        );
        assert!(
            policy.protected_resources().iter().any(|pr| pr.mac_display() == "aa:bb:cc:11:22:06" && pr.ip.as_deref() == Some("192.168.1.14")),
            "the Omada controller's MAC must be in the migrated live file",
        );
        let _ = std::fs::remove_file(&path);
    }

    // --- AXIOM Phase 3.2: capability_names / capability_summary / allows
    // (the read-only surface `axiom access` is built on) ---

    #[test]
    fn capability_names_lists_only_registered_capabilities() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        // "echo" is valid and gets registered; "sysinfo" fails closed for
        // lacking a tier and must NOT show up in capability_names either -
        // same "no entry" equivalence `tier()`/`capability_summary()` already
        // document.
        let path = write_policy(&dir, "axiom-policy-test-names.toml", &format!(
            "version = 2\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.sysinfo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        let mut names = policy.capability_names();
        names.sort();
        assert_eq!(names, vec!["echo"], "sysinfo has no valid tier and must not be registered");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn capability_names_empty_for_deny_all_policy() {
        let policy = CapabilityPolicy::load(std::path::Path::new("/nonexistent/does-not-exist.toml"));
        assert!(policy.capability_names().is_empty());
    }

    #[test]
    fn capability_summary_reports_full_metadata_sorted_and_hex_encoded() {
        let peer_a = Keypair::generate().node_id();
        let peer_b = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        // AXIOM Phase 3.6: needs a [[protected_resource]] section too - see
        // the identical note on `tier2_capability_is_declarable_and_parseable`.
        let path = write_policy(&dir, "axiom-policy-test-summary.toml", &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated-device\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.network_clients]\nallowed_peers = [\"{a}\", \"{b}\"]\nrate_limit_secs = 30\nconcurrency = 2\ntier = \"tier1\"\n",
            a = hex::encode(peer_a.as_bytes()),
            b = hex::encode(peer_b.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        let summary = policy.capability_summary("network_clients").expect("registered capability");
        assert_eq!(summary.tier, Tier::Tier1);
        assert_eq!(summary.rate_limit_secs, 30);
        assert_eq!(summary.concurrency, 2);
        let mut expected: Vec<(String, Option<u64>)> =
            vec![(hex::encode(peer_a.as_bytes()), None), (hex::encode(peer_b.as_bytes()), None)];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(summary.allowed_peers, expected, "allowed_peers must be hex-encoded, sorted, and permanent (None expiry)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn capability_summary_none_for_absent_capability() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-summary-absent.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(policy.capability_summary("network_clients").is_none(), "network_clients has no entry in this file at all");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn capability_summary_concurrency_survives_a_prior_acquire() {
        // Guards the exact fragility CapabilityEntry::concurrency's doc
        // comment calls out: concurrency must still report the CONFIGURED
        // limit (2), not the semaphore's current available_permits (1),
        // after one permit has already been acquired and not yet released.
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-summary-afteracquire.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 2\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        // Bind (not `matches!`, which would drop the permit immediately as
        // part of its own match expression) so the concurrency slot stays
        // held while `capability_summary` is checked below.
        let _permit = match policy.check_and_acquire("echo", peer) {
            PolicyOutcome::Allowed(p) => p,
            _ => panic!("expected Allowed"),
        };
        let summary = policy.capability_summary("echo").expect("registered");
        assert_eq!(summary.concurrency, 2, "must report the configured limit, not available_permits()");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn allows_reflects_allowlist_membership() {
        let peer = Keypair::generate().node_id();
        let stranger = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-allows.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(policy.allows("echo", peer));
        assert!(!policy.allows("echo", stranger));
        assert!(!policy.allows("sysinfo", peer), "capability with no entry at all must deny everyone");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tier_as_str_matches_on_disk_vocabulary() {
        assert_eq!(Tier::Tier0.as_str(), "tier0");
        assert_eq!(Tier::Tier1.as_str(), "tier1");
        assert_eq!(Tier::Tier2.as_str(), "tier2");
        for tier in [Tier::Tier0, Tier::Tier1, Tier::Tier2] {
            assert_eq!(Tier::from_toml_str(tier.as_str()), Some(tier), "as_str/from_toml_str must round-trip");
        }
    }

    // --- AXIOM Phase 3.6: protected-resource list ---

    /// The task's own explicit fail-closed requirement, point 5: a policy
    /// file with NO `[[protected_resource]]` section at all must deny
    /// EVERY Tier1+ capability - `Tier0` is unaffected. Same granularity
    /// proof pattern as `capability_missing_tier_denies_only_that_capability`.
    #[test]
    fn missing_protected_resource_section_denies_all_tier1_plus_but_not_tier0() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-no-protected-section.toml", &format!(
            "version = 2\n\n\
             [capability.echo]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.network_clients]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier1\"\n\n\
             [capability.some_future_destructive_capability]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 1\ntier = \"tier2\"\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);

        assert!(!policy.protected_resources_configured());

        // Tier0 is untouched - registers and allows normally.
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "Tier0 must be unaffected by a missing protected-resource section");
        assert_eq!(policy.tier("echo"), Some(Tier::Tier0));

        // Tier1/Tier2 both fail closed - not registered at all, same
        // "no entry" fail-closed semantics as an untiered capability.
        for cap in ["network_clients", "some_future_destructive_capability"] {
            assert!(
                matches!(policy.check_and_acquire(cap, peer), PolicyOutcome::NotAuthorized),
                "'{cap}' is Tier1+ and the file has no [[protected_resource]] section at all - must fail closed even though the peer is explicitly allowlisted",
            );
            assert_eq!(policy.tier(cap), None, "a Tier1+ capability denied for a missing protected-resource section must not register a tier either");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The inverse of the above: a PRESENT but EMPTY `[[protected_resource]]`
    /// section (an explicit, deliberate "nothing protected yet" operator
    /// choice) does NOT trigger the missing-section fail-closed gate -
    /// Tier1/Tier2 capabilities register and are checkable normally
    /// (though nothing will ever match `find_protected_match` against an
    /// empty list, which is a separate, expected consequence, not this
    /// test's concern).
    #[test]
    fn present_but_empty_protected_resource_section_does_not_fail_closed() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-empty-protected-section.toml",
            &format!(
                "version = 2\nprotected_resource = []\n\n\
                 [capability.network_clients]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier1\"\n",
                peer = hex::encode(peer.as_bytes()),
            ),
        );
        let policy = CapabilityPolicy::load(&path);
        assert!(policy.protected_resources_configured(), "an explicit empty array is still 'configured' - distinct from the key being absent entirely");
        assert!(policy.protected_resources().is_empty());
        assert!(matches!(policy.check_and_acquire("network_clients", peer), PolicyOutcome::Allowed(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// A malformed individual `[[protected_resource]]` entry (bad MAC) is
    /// logged and skipped, same per-entry-not-whole-file precedent as an
    /// invalid `allowed_peers` hex string - it does NOT turn the section
    /// into "absent" (a sibling, well-formed entry, and any Tier1+
    /// capability relying on the section merely existing, are unaffected).
    #[test]
    fn invalid_protected_resource_mac_is_skipped_not_fatal() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-bad-protected-mac.toml", &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"bad\"\nmac = \"not-a-mac\"\n\n\
             [[protected_resource]]\nname = \"good\"\nmac = \"AA:BB:CC:11:22:01\"\n\n\
             [capability.network_clients]\nallowed_peers = [\"{peer}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier1\"\n",
            peer = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(policy.protected_resources_configured());
        assert_eq!(policy.protected_resources().len(), 1, "the malformed entry must be skipped, the well-formed sibling kept");
        assert_eq!(policy.protected_resources()[0].mac_display(), "aa:bb:cc:11:22:01");
        assert!(matches!(policy.check_and_acquire("network_clients", peer), PolicyOutcome::Allowed(_)));
        let _ = std::fs::remove_file(&path);
    }

    fn proxmox_protected_resources() -> Vec<ProtectedResource> {
        vec![
            ProtectedResource::new(Some("proxmox-host-ethernet".to_string()), "AA:BB:CC:11:22:01", Some("192.168.1.10".to_string())).unwrap(),
            ProtectedResource::new(Some("omada-controller".to_string()), "AA:BB:CC:11:22:06", Some("192.168.1.14".to_string())).unwrap(),
            ProtectedResource::new(Some("laptop-ethernet".to_string()), "AA:BB:CC:11:22:08", None).unwrap(),
        ]
    }

    #[test]
    fn find_protected_match_detects_exact_mac_value() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![Constraint::string("target_mac", "AA:BB:CC:11:22:01")];
        let m = policy.find_protected_match(&params).expect("must match the Proxmox host's protected MAC");
        assert_eq!(m.resource_name.as_deref(), Some("proxmox-host-ethernet"));
        assert_eq!(m.parameter_key, "target_mac");
    }

    #[test]
    fn find_protected_match_is_case_and_separator_insensitive_for_mac() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        for value in ["AA:BB:CC:11:22:01", "aa-bb-cc-11-22-01", "AA-BB-CC-11-22-01"] {
            let params = vec![Constraint::string("target", value)];
            assert!(policy.find_protected_match(&params).is_some(), "'{value}' must still match despite case/separator differences");
        }
    }

    #[test]
    fn find_protected_match_detects_mac_embedded_in_a_larger_string() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![Constraint::string("description", "please reconfigure device mac=AA:BB:CC:11:22:01 on vlan 10")];
        assert!(policy.find_protected_match(&params).is_some());
    }

    /// AXIOM adversarial-test finding, real gap (see `TESTING.md`): before
    /// `scan_mac_candidates_including_whitespace_obfuscated` existed,
    /// `find_protected_match` used the exact-17-byte-window scan directly -
    /// which requires a MAC's colons to sit at exact canonical offsets, so
    /// spelling out the SAME protected MAC with extra whitespace inserted
    /// around its separators slid every candidate window off alignment and
    /// bypassed detection entirely, even though the value is unambiguously
    /// the same MAC to a human (or to any future capability's own
    /// whitespace-trimming target parser). This test would fail against the
    /// pre-fix scan; it passes now that `find_protected_match` scans a
    /// whitespace-stripped copy too.
    #[test]
    fn find_protected_match_detects_a_mac_obfuscated_with_internal_whitespace() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        for obfuscated in [
            "aa : bb : cc : 11 : 22 : 01",
            "aa:bb : cc:11:22:01",
            "  aa:bb:cc:11:22:01  ",
            "aa\t:bb:cc:11:22:01",
        ] {
            let params = vec![Constraint::string("target", obfuscated)];
            let m = policy.find_protected_match(&params);
            assert!(m.is_some(), "whitespace-obfuscated protected MAC {obfuscated:?} must still be caught");
        }
    }

    /// Companion negative case: whitespace-stripping must not be so
    /// aggressive that it starts matching a MAC that ISN'T actually
    /// protected just because whitespace happens to be nearby - the second
    /// scan pass only ever looks for the SAME `[[protected_resource]]`
    /// entries, so an unrelated (unprotected) MAC-shaped value, spaced out
    /// or not, still reports no match.
    #[test]
    fn whitespace_stripped_scan_does_not_match_an_unrelated_mac() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![Constraint::string("target", "de : ad : be : ef : 00 : 01")];
        assert!(policy.find_protected_match(&params).is_none(), "an unprotected MAC must not match regardless of spacing");
    }

    #[test]
    fn find_protected_match_detects_protected_ip() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![Constraint::string("target_ip", "192.168.1.14")];
        let m = policy.find_protected_match(&params).expect("must match the Omada controller's protected IP");
        assert_eq!(m.resource_name.as_deref(), Some("omada-controller"));
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED:
    /// an IPv4-mapped IPv6 form (`::ffff:192.168.1.14`) embedding the same
    /// protected IPv4 address - `scan_ipv4_candidates` doesn't need any
    /// special IPv6 awareness to catch this: it scans for a dotted-quad
    /// digit run ANYWHERE in the haystack, so the `::ffff:` prefix (which
    /// contains no ASCII digits or `.`) is simply skipped over and the
    /// embedded `192.168.1.14` is found exactly like the plain-IPv4 case.
    #[test]
    fn find_protected_match_detects_protected_ip_inside_an_ipv6_mapped_form() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        for value in ["::ffff:192.168.1.14", "0:0:0:0:0:ffff:192.168.1.14", "please route via ::ffff:192.168.1.14 today"] {
            let params = vec![Constraint::string("target_ip", value)];
            let m = policy.find_protected_match(&params);
            assert!(m.is_some(), "an IPv4-mapped IPv6 form embedding the protected IP {value:?} must still be caught");
        }
    }

    #[test]
    fn find_protected_match_checks_one_of_values_too() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![Constraint::one_of("candidates", vec!["192.168.1.15".to_string(), "AA:BB:CC:11:22:01".to_string()])];
        assert!(policy.find_protected_match(&params).is_some(), "a OneOf constraint carrying a protected value anywhere in its list must match");
    }

    #[test]
    fn find_protected_match_none_for_unrelated_values() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        let params = vec![
            Constraint::string("target", "aa:bb:cc:dd:ee:ff"),
            Constraint::string("target_ip", "10.0.0.99"),
            Constraint::string("note", "nothing protected mentioned here"),
            Constraint::int("count", 42),
            Constraint::bool("enable", true),
        ];
        assert!(policy.find_protected_match(&params).is_none());
    }

    #[test]
    fn find_protected_match_none_for_empty_protected_list() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(Vec::new()));
        let params = vec![Constraint::string("target", "AA:BB:CC:11:22:01")];
        assert!(policy.find_protected_match(&params).is_none(), "an empty (but configured) protected list matches nothing - not the same as fail-closed");
    }

    #[test]
    fn find_protected_match_never_panics_on_adversarial_utf8_input() {
        let policy = CapabilityPolicy::for_test_with_protected_resources(Some(proxmox_protected_resources()));
        // Multi-byte UTF-8, short strings, strings ending mid-window, and a
        // string that's ALMOST MAC-shaped but one byte short - none of
        // these should panic the byte-index scan, matter how it's sliced.
        let adversarial = ["😀😀😀😀😀😀😀😀😀", "3", "AA:BB:CC:11:22:0", "híola múndo côm áçẽntos", ""];
        for value in adversarial {
            let params = vec![Constraint::string("x", value)];
            let _ = policy.find_protected_match(&params); // must not panic
        }
    }

    #[test]
    fn protected_resource_new_rejects_malformed_mac() {
        assert!(ProtectedResource::new(None, "not-a-mac", None).is_none());
        assert!(ProtectedResource::new(None, "AA:BB:CC:11:22", None).is_none(), "5 octets, too short");
        assert!(ProtectedResource::new(None, "AA:BB:CC:11:22:01:ff", None).is_none(), "7 octets, too long");
        assert!(ProtectedResource::new(None, "zz:c5:99:5e:34:4d", None).is_none(), "non-hex octet");
        assert!(ProtectedResource::new(None, "AA:BB:CC:11:22:01", None).is_some());
    }

    // --- AXIOM Phase 3.6: minimal per-capability argument constraints ---

    #[test]
    fn check_denied_param_substrings_flags_a_configured_pattern() {
        let policy = CapabilityPolicy::for_test_with_denied_substrings(
            "some_future_destructive_capability", Some(Vec::new()), vec!["vlan1", "guest-network"],
        );
        let params = vec![Constraint::string("target_vlan", "VLAN1")];
        let reason = policy.check_denied_param_substrings("some_future_destructive_capability", &params);
        assert!(reason.is_some(), "must match case-insensitively");
        assert!(reason.unwrap().contains("target_vlan"));
    }

    #[test]
    fn check_denied_param_substrings_none_when_nothing_configured_or_matches() {
        let policy = CapabilityPolicy::for_test_with_denied_substrings(
            "some_future_destructive_capability", Some(Vec::new()), vec!["vlan1"],
        );
        let clean_params = vec![Constraint::string("target_vlan", "vlan42")];
        assert!(policy.check_denied_param_substrings("some_future_destructive_capability", &clean_params).is_none());
        // Unregistered capability - no denylist to check against at all.
        assert!(policy.check_denied_param_substrings("unregistered", &clean_params).is_none());
    }

    // --- AXIOM Phase 3.6: raw MAC/IPv4 scanners (module-private helpers) ---

    #[test]
    fn scan_mac_candidates_finds_colon_and_hyphen_forms() {
        assert_eq!(scan_mac_candidates("AA:BB:CC:11:22:01"), vec![[0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x01]]);
        assert_eq!(scan_mac_candidates("aa-bb-cc-11-22-01"), vec![[0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x01]]);
        assert!(scan_mac_candidates("not a mac at all").is_empty());
        assert!(scan_mac_candidates("AA:BB:CC:11:22").is_empty(), "too short to be a full MAC");
    }

    #[test]
    fn scan_ipv4_candidates_finds_dotted_quads_and_rejects_out_of_range() {
        assert_eq!(scan_ipv4_candidates("target is 192.168.1.10 today"), vec!["192.168.1.10".to_string()]);
        assert!(scan_ipv4_candidates("999.168.110.185").is_empty(), "999 is not a valid octet");
        assert!(scan_ipv4_candidates("not an ip").is_empty());
    }

    // --- AXIOM Phase 3.8: kill switch ---

    #[test]
    fn freeze_denies_tier1_but_not_tier0_and_unfreeze_restores_tier1() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-freeze.toml", &format!(
            "version = 2\n\n\
             [[protected_resource]]\nname = \"unrelated\"\nmac = \"aa:bb:cc:dd:ee:ff\"\n\n\
             [capability.echo]\nallowed_peers = [\"{p}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n\n\
             [capability.network_clients]\nallowed_peers = [\"{p}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier1\"\n",
            p = hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);

        assert!(!policy.is_frozen());
        policy.freeze();
        assert!(policy.is_frozen());

        // Tier1 is denied, with a DISTINCT outcome from a plain
        // allowlist-miss.
        assert!(matches!(policy.check_and_acquire("network_clients", peer), PolicyOutcome::Frozen));
        // Tier0 is unaffected - "freeze ALL Tier1+ execution" exempts it.
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));

        // Explicit un-freeze restores Tier1.
        policy.unfreeze();
        assert!(!policy.is_frozen());
        assert!(matches!(policy.check_and_acquire("network_clients", peer), PolicyOutcome::Allowed(_)));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn suspended_peer_is_denied_on_every_tier_while_another_peer_is_unaffected() {
        let suspect = Keypair::generate().node_id();
        let innocent = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-suspend.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{a}\", \"{b}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            a = hex::encode(suspect.as_bytes()),
            b = hex::encode(innocent.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);

        assert!(matches!(policy.check_and_acquire("echo", suspect), PolicyOutcome::Allowed(_)));

        policy.suspend_peer(suspect);
        assert!(policy.is_suspended(suspect));
        assert!(!policy.is_suspended(innocent));

        // The suspended identity is denied - even for Tier0, the
        // conservative "every tier" reading this module's doc comment
        // documents - with a DISTINCT outcome from a plain allowlist-miss.
        assert!(matches!(policy.check_and_acquire("echo", suspect), PolicyOutcome::Suspended));
        // A second, non-suspended agent proceeds completely normally -
        // proves suspend is scoped to the one identity, not a global freeze.
        assert!(matches!(policy.check_and_acquire("echo", innocent), PolicyOutcome::Allowed(_)));

        // Explicit un-suspend restores the first identity.
        assert!(policy.unsuspend_peer(suspect));
        assert!(!policy.is_suspended(suspect));
        assert!(matches!(policy.check_and_acquire("echo", suspect), PolicyOutcome::Allowed(_)));
        // Un-suspending an already-clear identity is not an error, just a no-op report.
        assert!(!policy.unsuspend_peer(suspect));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn suspending_a_never_allowlisted_peer_is_still_a_distinct_denial() {
        // Suspend must be checked even for a capability the peer was never
        // going to pass anyway - `check_and_acquire` still reports
        // `Suspended`, not `NotAuthorized`, since the operator's intent
        // ("cut this identity off") is unambiguous regardless of what it
        // would otherwise have been authorized for.
        let peer = Keypair::generate().node_id();
        let policy = CapabilityPolicy::for_test(&["echo"], std::collections::HashSet::new());
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized));
        policy.suspend_peer(peer);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Suspended));
    }

    // --- AXIOM Phase 3.8: allowlist expiry ---

    #[test]
    fn permanent_bare_string_entry_is_backward_compatible_and_never_expires() {
        // The exact pre-3.8 shape (bare hex strings) must keep parsing and
        // granting access exactly as before - this is the live policy
        // file's shape today.
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let path = write_policy(&dir, "axiom-policy-test-expiry-bare.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{}\"]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            hex::encode(peer.as_bytes()),
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        let summary = policy.capability_summary("echo").unwrap();
        assert_eq!(summary.allowed_peers, vec![(hex::encode(peer.as_bytes()), None)], "bare entries are permanent (None expiry)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn future_expiry_entry_is_allowed_now() {
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let far_future = now_unix_secs() + 3600;
        let path = write_policy(&dir, "axiom-policy-test-expiry-future.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [{{ peer = \"{p}\", expires = {e} }}]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            p = hex::encode(peer.as_bytes()), e = far_future,
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)));
        assert!(policy.allows("echo", peer));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_entry_behaves_identically_to_a_never_allowlisted_peer() {
        // The core Phase 3.8 requirement: an expired entry must be
        // INDISTINGUISHABLE from absence - same PolicyOutcome variant, same
        // `allows()` result, same absence from `capability_summary`'s
        // reported list - not merely "both eventually fail" in different ways.
        let expired_peer = Keypair::generate().node_id();
        let never_allowlisted = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let past = now_unix_secs().saturating_sub(3600);
        let path = write_policy(&dir, "axiom-policy-test-expiry-past.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [{{ peer = \"{p}\", expires = {e} }}]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            p = hex::encode(expired_peer.as_bytes()), e = past,
        ));
        let policy = CapabilityPolicy::load(&path);

        let expired_outcome = policy.check_and_acquire("echo", expired_peer);
        let absent_outcome = policy.check_and_acquire("echo", never_allowlisted);
        assert!(matches!(expired_outcome, PolicyOutcome::NotAuthorized));
        assert!(matches!(absent_outcome, PolicyOutcome::NotAuthorized));

        assert_eq!(policy.allows("echo", expired_peer), policy.allows("echo", never_allowlisted));
        assert!(!policy.allows("echo", expired_peer));

        // Neither shows up in the reported allowlist.
        let summary = policy.capability_summary("echo").unwrap();
        assert!(summary.allowed_peers.is_empty(), "an expired entry must not appear in the reported allowlist, same as an entry that never existed");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expiry_is_evaluated_live_not_at_load_time() {
        // A policy loaded once, with an entry that expires shortly after
        // load, must stop granting access once real wall-clock time passes
        // that point - proving expiry isn't merely filtered once at
        // try_load and then frozen for the process's lifetime.
        let peer = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let soon = now_unix_secs() + 1;
        let path = write_policy(&dir, "axiom-policy-test-expiry-live.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [{{ peer = \"{p}\", expires = {e} }}]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            p = hex::encode(peer.as_bytes()), e = soon,
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::Allowed(_)), "must be allowed immediately after load, before expiry");

        std::thread::sleep(Duration::from_millis(1100));

        assert!(matches!(policy.check_and_acquire("echo", peer), PolicyOutcome::NotAuthorized), "must be denied once real wall-clock time passes `expires`, without any reload");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mixed_bare_and_expiring_entries_in_the_same_allowlist() {
        let permanent = Keypair::generate().node_id();
        let expiring = Keypair::generate().node_id();
        let dir = std::env::temp_dir();
        let far_future = now_unix_secs() + 3600;
        let path = write_policy(&dir, "axiom-policy-test-expiry-mixed.toml", &format!(
            "version = 2\n\n[capability.echo]\nallowed_peers = [\"{perm}\", {{ peer = \"{exp}\", expires = {e} }}]\nrate_limit_secs = 0\nconcurrency = 10\ntier = \"tier0\"\n",
            perm = hex::encode(permanent.as_bytes()), exp = hex::encode(expiring.as_bytes()), e = far_future,
        ));
        let policy = CapabilityPolicy::load(&path);
        assert!(matches!(policy.check_and_acquire("echo", permanent), PolicyOutcome::Allowed(_)));
        assert!(matches!(policy.check_and_acquire("echo", expiring), PolicyOutcome::Allowed(_)));
        let mut summary = policy.capability_summary("echo").unwrap().allowed_peers;
        summary.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected = vec![(hex::encode(permanent.as_bytes()), None), (hex::encode(expiring.as_bytes()), Some(far_future))];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(summary, expected);
        let _ = std::fs::remove_file(&path);
    }
}
