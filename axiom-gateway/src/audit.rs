//! AXIOM Phase 3.4: the append-only, hash-chained, tamper-evident audit
//! log for capability invocations.
//!
//! # What gets logged, per the ratified tier model (`policy::Tier`,
//! `DECISIONS.md`'s "Tier model" section)
//!
//! - **Tier 0**: nothing. Ratified controls are "allowlist + rate limit"
//!   only - no audit requirement. Logging every `echo`/`sysinfo` call would
//!   be over-building past what was actually ratified.
//! - **Tier 1**: every call, unconditionally - "mandatory full-context
//!   audit logging" per `policy::Tier::Tier1`'s own doc comment. Tier 1 has
//!   no approval step, so there's no propose/approve/execute state machine
//!   to hang a log entry off of - `AuditLog::log_tier1_call` is a direct,
//!   lightweight "record this invocation" entry point a future dispatch
//!   layer calls once, right after a Tier 1 capability returns.
//! - **Tier 2**: every completed `approval::Tier2ApprovalFlow` intent,
//!   whatever it terminated as (denied, expired, hash-mismatched, executed,
//!   or execution-failed) - `AuditLog::log_tier2_linked_record` consumes an
//!   `approval::LinkedRecord` directly. `LinkedRecord` was deliberately
//!   shaped (see its own doc comment) to hand off to this module without a
//!   redesign - this function is that handoff, not a reinvention of it.
//!
//! # Schema
//!
//! One `AuditEntry` per invocation: timestamp, caller (`NodeId`, hex),
//! capability name, tier, full parameters (redacted per-field - see
//! "Redaction" below), a `decision` (allowed/denied + a human-readable
//! reason - "not on allowlist" isn't produced by this module today since
//! Tier 1/2 logging both start after the policy allowlist check already
//! passed, but the field is shaped to carry that reason too, once a future
//! phase wires this log into the dispatch path itself and wants to record
//! Tier-0-adjacent denials as well), an `outcome` (success/failure detail,
//! `None` for anything that never reached execution), and `duration_ms`.
//!
//! # Redaction
//!
//! This codebase's only prior art for "don't persist a secret" is
//! `forge-node::network`'s `Zeroizing` wrapper around the Omada
//! credential - but that's an in-memory scrub, deliberately never written
//! anywhere (see that module's doc comment: "AXIOM never PERSISTS the
//! Omada password anywhere"). There's no existing convention for "this
//! field must still be written to a log, but redacted" - nothing in
//! `axiom_types::intent::Constraint` marks a key as sensitive, and this
//! module doesn't own that type (it's a shared, low-level type other
//! crates depend on; adding a sensitivity flag to it is a bigger, riskier
//! change than this phase needs). So: a simple, explicit, case-insensitive
//! substring denylist (`is_sensitive_param_key`) checked against every
//! parameter's KEY, independent of which capability is calling - this
//! means a future capability with a `password`/`token`/`secret`/etc.
//! parameter is redacted automatically, without its own dispatch code
//! needing to remember to wrap it. Deliberately biased toward
//! over-redaction (e.g. `"authorized_by"` would also get redacted, being
//! substring-matched against `"auth"`) - false positives here just mean an
//! operator sees `[REDACTED]` on a harmless field, which is recoverable by
//! renaming the parameter; false negatives mean a real secret in a log
//! nothing can un-write. See this module's own tests for the exact
//! denylist and the "redacted value never appears in the raw file bytes"
//! guarantee.
//!
//! # Hash chain
//!
//! Reuses `axiom_crypto::IntentHasher::hash_bytes` (BLAKE3) - the SAME
//! primitive `approval::Intent::compute_parameter_hash` already reuses -
//! rather than inventing a second hashing scheme, per this phase's own
//! instruction. Each entry's `entry_hash` is BLAKE3 over a canonical JSON
//! serialization of every OTHER field on the entry, including its own
//! `prev_hash` (so tampering `prev_hash` alone, not just the "visible"
//! fields, is caught as content tampering - see `verify_chain`). The
//! genesis entry (`sequence == 0`) chains to `GENESIS_HASH`, all zero
//! bytes - the same sentinel `axiom-audit::external::ExternalAuditWriter`
//! (an existing, unrelated, never-wired-in HIPAA/SOC2-flavored compliance
//! crate elsewhere in this workspace - see this phase's own build notes
//! for why this module doesn't build on it instead) already uses for the
//! same purpose, so this isn't even a novel choice inside this repo.
//!
//! # Storage
//!
//! One JSON object per line (JSON Lines) - `serde_json` is already a
//! dependency of `forge-node` (just not `axiom-gateway` until this
//! change), and a line-oriented format makes both "append one entry" and
//! "detect a truncated/corrupt tail" trivial compared to a single growing
//! TOML/JSON document. `AuditLog::open` creates the file at `0o600`
//! (owner-read-write only) if it doesn't exist, and re-asserts that mode
//! on every open even if it already existed - matching `node.key`'s own
//! permission convention (the strictest existing precedent in this
//! codebase for "sensitive, service-owned, nothing else should touch
//! this"), stricter than `capability_policy.toml`'s `640`-ish posture
//! (which is about the SERVICE not being allowed to write, the opposite
//! direction: this file, the service DOES need to write, so root-only
//! read+write is the closer analogue, not the read-only-to-service config
//! file). If a future phase runs `forge-node` as a dedicated non-root
//! service user, this is the file that user's own key material lives
//! next to (`data_dir`, not `/etc/forge`) - same directory, same
//! ownership model.
//!
//! `AuditLog::open` on an EXISTING file always verifies the whole chain
//! first (`verify_chain`) and refuses to open (returns
//! `AuditLogError::ExistingLogCorrupt`) if it's broken - fail-closed, same
//! discipline `policy::CapabilityPolicy::load` applies to a broken policy
//! file, rather than silently appending new, valid entries onto a chain
//! that's already been tampered with.
//!
//! # Prime directive: not a capability
//!
//! Per the roadmap's own instruction, this log is reachable ONLY via
//! `AuditLog`'s own Rust API (used by a future dispatch-layer integration
//! and by `approval`'s Tier 2 flow) or the `forge-node verify-audit` CLI
//! (local access to the box) - there is no `Tier0Capability`/
//! `Tier1Capability`/`Tier2Capability` implementation anywhere in this
//! crate or `forge-node` that reads, writes, or deletes audit entries
//! through the normal capability-dispatch grammar, and there must never
//! be one, even read-only, even Tier 2 (human-approved) gated. A future
//! dedicated audit-viewer is explicitly a separate breakout project, not
//! a capability.
//!
//! # AXIOM Phase 3.8: kill-switch/admin events
//!
//! `log_admin_event` is a THIRD entry point alongside `log_tier1_call`/
//! `log_tier2_linked_record`, for `forge-node`'s local admin kill switch
//! (freeze/unfreeze/suspend/unsuspend) - an action that is (a) not tied to
//! any capability TIER at all (the kill switch is explicitly not a
//! capability, see `forge-node/src/capability_isolation.rs`), and (b) not
//! attributable to a signed peer `NodeId` (the actor is whoever has local/
//! SSH access to the box that's running `forge-node`, the same "physical/
//! SSH access IS the authentication boundary" reasoning
//! `approval::CliApprovalChannel`'s own doc comment already uses for the
//! Tier 2 CLI-prompt channel). `caller` in the persisted `AuditEntry` is
//! the fixed sentinel `LOCAL_ADMIN_CALLER` ("local-admin") for these
//! entries, never a real NodeId hex string - `AuditEntry::caller` was
//! already a free-form `String`, not a parsed/typed `NodeId`, so this needs
//! no schema change, just a documented convention distinguishing these
//! entries from peer-attributed Tier 1/2 ones. `tier` is the fixed string
//! `"admin"` - deliberately NOT a `policy::Tier` variant (that enum models
//! the three ratified capability tiers a policy FILE entry can declare;
//! an admin/kill-switch action is a different kind of thing entirely, not
//! a fourth tier a capability could ever be assigned).
//!
//! Called directly by `forge-node/src/control.rs`'s FREEZE/UNFREEZE/
//! SUSPEND/UNSUSPEND handlers - the local admin control socket, NOT
//! capability dispatch (`forge-node/src/network.rs`'s `dispatch_intent`
//! has, and must keep, zero reference to `AuditLog` at all - see
//! `capability_isolation.rs`'s `capability_dispatch_has_zero_references_to_audit_log_today`
//! test, unaffected by this addition since it only scans `network.rs`).
//! Reachable ONLY that way; there is no capability, of any tier, that logs
//! an admin event.
//!
//! # A known, honest limitation: tail truncation
//!
//! A pure hash chain with no external anchor cannot distinguish "the log
//! legitimately ends here" from "the last N complete entries were cleanly
//! deleted" - every entry that remains is still internally self-consistent
//! and correctly linked to the one before it, so `verify_chain` correctly
//! reports a shorter-but-VALID chain in that case (same limitation as git
//! history, or a blockchain without checkpoints). What this module DOES
//! catch is a CORRUPT tail - a write interrupted mid-record (a crash, or a
//! deliberate partial truncation that doesn't land on a line boundary) -
//! since the final line then fails to parse as a complete `AuditEntry` at
//! all. See this module's tests for both cases proven separately, and this
//! phase's own build report for why a clean-drop external anchor (e.g. a
//! separately-stored "last known good" pointer) is out of scope here.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axiom_crypto::IntentHasher;
use axiom_types::crypto::NodeId;
use axiom_types::intent::Constraint;
use serde::{Deserialize, Serialize};

use crate::approval::{format_constraint_value, IntentStatus, LinkedRecord};
use crate::policy::Tier;

/// Genesis sentinel - the `prev_hash` every log's very first entry
/// (`sequence == 0`) chains to. All-zero, documented, fixed - see this
/// module's top-of-file doc comment for why this specific value (matches
/// existing, if unrelated, prior art already in this workspace).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// AXIOM Phase 3.8: fixed `AuditEntry::caller` sentinel for `log_admin_event`
/// entries - see this module's top-of-file "kill-switch/admin events"
/// section for why these entries are never attributed to a real peer
/// `NodeId`.
pub const LOCAL_ADMIN_CALLER: &str = "local-admin";

/// AXIOM Phase 3.8: fixed `AuditEntry::tier` value for `log_admin_event`
/// entries - deliberately not a `policy::Tier` variant, see this module's
/// top-of-file "kill-switch/admin events" section.
const ADMIN_ENTRY_TIER: &str = "admin";

/// Default audit-log path for a node's `data_dir` - mirrors
/// `forge-node/src/control.rs`'s own `default_path(data_dir) ->
/// data_dir.join("control.sock")` convention, and matches this module's
/// own top-of-file "Storage" section ("If a future phase runs forge-node
/// as a dedicated non-root service user, this is the file that user's own
/// key material lives next to (data_dir, not /etc/forge)"). A pure path
/// helper - does not open or touch the file.
pub fn default_path(data_dir: &Path) -> PathBuf {
    data_dir.join("audit.jsonl")
}

/// Case-insensitive substrings that mark a parameter KEY as sensitive -
/// its value is redacted to `[REDACTED]` in every audit entry regardless
/// of which capability submitted it. Deliberately biased toward
/// over-matching (see this module's top-of-file doc comment). Kept as a
/// `const` (not configurable) - the roadmap's ask was for a simple,
/// explicit, always-on mechanism, not a per-deployment policy surface;
/// widen this list in code review if a real capability's secret parameter
/// doesn't happen to match one of these substrings, rather than adding
/// runtime configuration for what should stay a small, auditable set.
const SENSITIVE_PARAM_KEY_MARKERS: &[&str] = &[
    "password", "passwd", "secret", "token", "credential", "cred",
    "api_key", "apikey", "private_key", "privatekey", "access_key",
    "auth", "pin", "ssn",
];

/// True if `key` (case-insensitively) contains any of
/// `SENSITIVE_PARAM_KEY_MARKERS` - see this module's top-of-file doc
/// comment ("Redaction") for the full rationale.
pub fn is_sensitive_param_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_PARAM_KEY_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// One parameter as recorded in an audit entry - always present (even when
/// redacted, so a reader can see WHICH parameters existed and that
/// something was hidden, not just silence), with `redacted` telling a
/// reader whether `value` is the real stringified value or the fixed
/// `[REDACTED]` marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditParam {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

impl AuditParam {
    fn from_constraint(c: &Constraint) -> Self {
        let redacted = is_sensitive_param_key(&c.key);
        let value = if redacted {
            // Fixed marker, not e.g. the real value's length or type -
            // leaking either is still leaking something about a secret
            // this module exists to keep out of the log entirely.
            "[REDACTED]".to_string()
        } else {
            format_constraint_value(&c.value)
        };
        Self { key: c.key.clone(), value, redacted }
    }
}

/// Allow/deny outcome of the capability-policy and (for Tier 2) approval
/// checks a logged call went through, plus a human-readable reason - see
/// this module's top-of-file doc comment for why `allowed == false` cases
/// aren't produced by `AuditLog`'s own methods today even though the field
/// can represent them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDecision {
    pub allowed: bool,
    pub reason: String,
}

/// Result of actually executing a capability - absent (`None` on
/// `AuditEntry::outcome`) for anything that never reached execution
/// (denied, expired, parameter-hash-mismatched).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Completed successfully. `detail` mirrors whatever human-readable
    /// summary the capability itself returned, if any (matches
    /// `approval::ExecutionResult`'s `Ok(String)` case, and Tier 1's own
    /// `Result<Option<String>, String>` outcome shape).
    Success { detail: Option<String> },
    /// Completed, but the capability itself reported failure (backend
    /// unreachable, etc - NOT a policy/approval denial, which never
    /// reaches this variant at all since `outcome` stays `None`).
    Failure { detail: String },
}

/// One append-only audit log entry - see this module's top-of-file doc
/// comment for the full schema rationale. `entry_hash` is BLAKE3 over the
/// canonical JSON serialization of every OTHER field (see
/// `recompute_entry_hash`) - never trust a stored `entry_hash` without
/// recomputing it, which is exactly what `verify_chain` does for every
/// entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// 0-indexed position in this log's chain - `sequence == 0` is the
    /// genesis entry, chained to `GENESIS_HASH`.
    pub sequence: u64,
    /// Wall-clock unix epoch milliseconds when this entry was recorded.
    pub timestamp_ms: u64,
    /// Hex-encoded 32-byte Ed25519 `NodeId` of the calling peer.
    pub caller: String,
    pub capability: String,
    /// `"tier1"` or `"tier2"` (`policy::Tier::as_str()`) - `tier0` never
    /// produces an entry at all, per the ratified model.
    pub tier: String,
    pub parameters: Vec<AuditParam>,
    pub decision: AuditDecision,
    /// `None` for anything that never reached execution.
    pub outcome: Option<AuditOutcome>,
    pub duration_ms: u64,
    /// `approval::IntentId` (hex), present only for Tier 2 entries -
    /// lets an operator correlate an audit entry back to the
    /// `Tier2ApprovalFlow` record it came from. `None` for Tier 1 entries,
    /// which have no `IntentId` concept at all.
    pub intent_id: Option<String>,
    /// Hex-encoded hash of the entry immediately before this one in the
    /// chain (`GENESIS_HASH` for `sequence == 0`).
    pub prev_hash: String,
    /// Hex-encoded BLAKE3 hash of this entry's own content (every field
    /// above, including `prev_hash`) - see `recompute_entry_hash`.
    pub entry_hash: String,
}

/// The exact fields `entry_hash` is computed over, borrowed rather than
/// owned so both `AuditLog::record` (building a brand-new entry) and
/// `recompute_entry_hash` (re-deriving from a parsed `AuditEntry`) hash
/// IDENTICAL content through the same serialization - two independent
/// implementations of "what does this entry hash to" would risk drifting
/// apart silently; this type exists so there's exactly one.
#[derive(Serialize)]
struct HashableContent<'a> {
    sequence: u64,
    timestamp_ms: u64,
    caller: &'a str,
    capability: &'a str,
    tier: &'a str,
    parameters: &'a [AuditParam],
    decision: &'a AuditDecision,
    outcome: &'a Option<AuditOutcome>,
    duration_ms: u64,
    intent_id: &'a Option<String>,
    prev_hash: &'a str,
}

/// BLAKE3 (via `IntentHasher::hash_bytes`, the same primitive
/// `approval::Intent` uses) over a canonical JSON serialization of every
/// field on `entry` except `entry_hash` itself. `serde_json`'s struct
/// serialization preserves declaration order deterministically (unlike a
/// `HashMap`), so this is a stable, canonical encoding without needing a
/// hand-rolled byte layout.
fn recompute_entry_hash(entry: &AuditEntry) -> [u8; 32] {
    let hashable = HashableContent {
        sequence: entry.sequence,
        timestamp_ms: entry.timestamp_ms,
        caller: &entry.caller,
        capability: &entry.capability,
        tier: &entry.tier,
        parameters: &entry.parameters,
        decision: &entry.decision,
        outcome: &entry.outcome,
        duration_ms: entry.duration_ms,
        intent_id: &entry.intent_id,
        prev_hash: &entry.prev_hash,
    };
    let bytes = serde_json::to_vec(&hashable).expect("HashableContent serialization cannot fail");
    IntentHasher::hash_bytes(&bytes)
}

fn decode_hash(s: &str) -> Result<[u8; 32], ()> {
    let bytes = hex::decode(s).map_err(|_| ())?;
    <[u8; 32]>::try_from(bytes).map_err(|_| ())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// Exactly where/how `verify_chain` found a broken chain - see this
/// module's top-of-file doc comment ("Hash chain") and each variant's own
/// doc comment for what produces it. Never a generic "invalid" - a caller
/// (in practice, `forge-node verify-audit`) can always report the exact
/// index and mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainBreak {
    /// The entry at `index` (0-indexed position among entries
    /// successfully parsed so far) could not even be parsed as a complete
    /// `AuditEntry` - malformed JSON, a missing field, or (most commonly)
    /// a write interrupted mid-record leaving a truncated final line.
    CorruptEntry { index: u64, detail: String },
    /// The entry at `index` parses fine, but recomputing its hash from its
    /// own stored content does not match its own stored `entry_hash` -
    /// the entry's fields were changed after it was written, without the
    /// hash being recomputed to match (exactly what tampering "without
    /// recomputing the chain" produces).
    ContentTampered { index: u64 },
    /// The entry at `index` is internally self-consistent (its own hash
    /// checks out) but its `prev_hash` doesn't match the actual hash of
    /// the entry immediately before it - something was inserted, deleted,
    /// or reordered between them.
    ChainLinkBroken { index: u64, expected_prev: String, found_prev: String },
    /// The entry at `index` has a `sequence` that isn't exactly one more
    /// than the previous entry's - a more human-legible symptom of the
    /// same underlying break `ChainLinkBroken` would also have caught.
    SequenceGap { index: u64, expected: u64, found: u64 },
}

impl fmt::Display for AuditChainBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorruptEntry { index, detail } => write!(
                f,
                "entry at index {index} is corrupt or truncated ({detail}) - this looks like a write \
                 interrupted mid-record (a crash) or a deliberate tail truncation, not a tampered-but-\
                 complete entry",
            ),
            Self::ContentTampered { index } => write!(
                f,
                "entry at index {index} has been tampered with - its recorded content does not match \
                 its own stored hash (the entry was edited after being written, without the hash being \
                 recomputed to match)",
            ),
            Self::ChainLinkBroken { index, expected_prev, found_prev } => write!(
                f,
                "entry at index {index} breaks the chain - its prev_hash ({found_prev}) does not match \
                 the previous entry's actual hash ({expected_prev}); an entry was inserted, deleted, or \
                 reordered between them",
            ),
            Self::SequenceGap { index, expected, found } => write!(
                f,
                "entry at index {index} has sequence {found}, expected {expected} - an entry is missing \
                 or out of order",
            ),
        }
    }
}

/// A successfully-verified chain's summary - how many entries, and the
/// last one's hash (so `AuditLog::open` can resume appending from exactly
/// where an existing, valid log left off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainState {
    pub entries: u64,
    pub last_hash: [u8; 32],
}

/// Read `path` as a JSON-Lines audit log and walk its entire hash chain
/// from the genesis entry, verifying every entry's self-consistency
/// (content hash) and linkage (prev_hash / sequence) to the one before it.
/// Pure and side-effect-free (no locking, doesn't touch `AuditLog`'s own
/// writer state) - used both by `AuditLog::open` (to fail closed on an
/// already-corrupt file before appending anything new to it) and by
/// `forge-node verify-audit` (to report to a human). An empty or
/// nonexistent file verifies as `Ok(ChainState { entries: 0, last_hash:
/// GENESIS_HASH })` - "no entries yet" is a valid, not broken, chain.
pub fn verify_chain(path: &Path) -> Result<ChainState, AuditChainBreak> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ChainState { entries: 0, last_hash: GENESIS_HASH });
        }
        Err(e) => {
            return Err(AuditChainBreak::CorruptEntry {
                index: 0,
                detail: format!("could not open {}: {e}", path.display()),
            })
        }
    };
    let reader = BufReader::new(file);

    let mut expected_prev = GENESIS_HASH;
    let mut expected_sequence = 0u64;

    for line in reader.lines() {
        let index = expected_sequence;
        let line = line.map_err(|e| AuditChainBreak::CorruptEntry {
            index,
            detail: format!("I/O error reading line: {e}"),
        })?;

        let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| AuditChainBreak::CorruptEntry {
            index,
            detail: format!("not a complete/valid audit entry: {e}"),
        })?;

        let recorded_hash = decode_hash(&entry.entry_hash).map_err(|_| AuditChainBreak::CorruptEntry {
            index,
            detail: "entry_hash is not valid 64-char hex".to_string(),
        })?;
        if recompute_entry_hash(&entry) != recorded_hash {
            return Err(AuditChainBreak::ContentTampered { index });
        }

        let found_prev = decode_hash(&entry.prev_hash).map_err(|_| AuditChainBreak::CorruptEntry {
            index,
            detail: "prev_hash is not valid 64-char hex".to_string(),
        })?;
        if found_prev != expected_prev {
            return Err(AuditChainBreak::ChainLinkBroken {
                index,
                expected_prev: hex::encode(expected_prev),
                found_prev: entry.prev_hash.clone(),
            });
        }

        if entry.sequence != expected_sequence {
            return Err(AuditChainBreak::SequenceGap {
                index,
                expected: expected_sequence,
                found: entry.sequence,
            });
        }

        expected_prev = recorded_hash;
        expected_sequence += 1;
    }

    Ok(ChainState { entries: expected_sequence, last_hash: expected_prev })
}

/// Errors `AuditLog::open` / the logging methods can return.
#[derive(Debug)]
pub enum AuditLogError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
    /// `AuditLog::open` found an existing file at the target path whose
    /// chain doesn't verify - refuses to open (fail-closed, matching
    /// `policy::CapabilityPolicy::load`'s own discipline for a broken
    /// policy file) rather than silently appending new entries onto a
    /// chain that's already broken.
    ExistingLogCorrupt(AuditChainBreak),
    /// `AuditLog::log_tier2_linked_record` was called with a
    /// `LinkedRecord` whose `status` is still `IntentStatus::Pending` -
    /// i.e. before `Tier2ApprovalFlow::decide_and_execute` has returned.
    /// Only a TERMINAL record (denied, expired, hash-mismatched, executed,
    /// or execution-failed) has enough information to produce one audit
    /// entry; call this after `decide_and_execute`, not instead of it.
    NotTerminal,
}

impl fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit log I/O error: {e}"),
            Self::Serialize(e) => write!(f, "audit log serialization error: {e}"),
            Self::ExistingLogCorrupt(b) => write!(f, "existing audit log failed to verify, refusing to open: {b}"),
            Self::NotTerminal => write!(f, "cannot log a Tier 2 intent that hasn't reached a terminal status yet"),
        }
    }
}

impl std::error::Error for AuditLogError {}

#[derive(Debug)]
struct WriterState {
    file: File,
    last_hash: [u8; 32],
    next_sequence: u64,
}

/// An open, append-only, hash-chained audit log backed by a JSON-Lines
/// file at a fixed path. See this module's top-of-file doc comment for
/// the full schema/chain/storage/redaction contract.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<WriterState>,
}

impl AuditLog {
    /// Open (creating if absent) the audit log at `path`. An existing file
    /// is fully chain-verified before anything is appended to it - see
    /// `AuditLogError::ExistingLogCorrupt`. Sets/re-asserts `0o600`
    /// permissions on Unix every time (see this module's top-of-file doc
    /// comment, "Storage").
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditLogError> {
        let path = path.into();

        let (last_hash, next_sequence) = match verify_chain(&path) {
            Ok(state) => (state.last_hash, state.entries),
            Err(broken) => return Err(AuditLogError::ExistingLogCorrupt(broken)),
        };

        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(AuditLogError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().map_err(AuditLogError::Io)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(AuditLogError::Io)?;
        }

        Ok(Self { path, state: Mutex::new(WriterState { file, last_hash, next_sequence }) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of entries appended so far (via THIS open handle plus
    /// whatever was already on disk when it was opened) - for
    /// tests/reporting.
    pub fn len(&self) -> u64 {
        self.state.lock().unwrap().next_sequence
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Core append: builds one `AuditEntry` chained to whatever this
    /// log's current tail is, serializes it as one JSON line, appends +
    /// `sync_all`s the file, and advances the writer's in-memory chain
    /// state. Private - `log_tier1_call`, `log_tier2_linked_record`, and
    /// (AXIOM Phase 3.8) `log_admin_event` are the only three ways to reach
    /// this.
    ///
    /// AXIOM Phase 3.8: `caller`/`tier` widened from `NodeId`/`Tier` to
    /// plain `&str` - `AuditEntry::caller`/`tier` were always free-form
    /// `String` fields on disk (never re-parsed back into `NodeId`/`Tier`
    /// by this module), so this is a pure internal refactor with no schema
    /// change: `log_tier1_call`/`log_tier2_linked_record` below now format
    /// their own `NodeId`/`Tier` argument into a string before calling
    /// this, instead of this function doing it - which is what lets
    /// `log_admin_event` (a caller with neither a real `NodeId` nor a real
    /// `Tier` to offer - see this module's top-of-file "kill-switch/admin
    /// events" section) reach the exact same append path without either
    /// type needing a synthetic/sentinel variant of its own.
    fn record(
        &self,
        caller: &str,
        capability: &str,
        tier: &str,
        parameters: &[Constraint],
        decision: AuditDecision,
        outcome: Option<AuditOutcome>,
        duration: Duration,
        intent_id: Option<String>,
    ) -> Result<(), AuditLogError> {
        let parameters: Vec<AuditParam> = parameters.iter().map(AuditParam::from_constraint).collect();

        let mut state = self.state.lock().unwrap();

        let mut entry = AuditEntry {
            sequence: state.next_sequence,
            timestamp_ms: now_ms(),
            caller: caller.to_string(),
            capability: capability.to_string(),
            tier: tier.to_string(),
            parameters,
            decision,
            outcome,
            duration_ms: duration.as_millis() as u64,
            intent_id,
            prev_hash: hex::encode(state.last_hash),
            entry_hash: String::new(),
        };
        let hash_bytes = recompute_entry_hash(&entry);
        entry.entry_hash = hex::encode(hash_bytes);

        let line = serde_json::to_string(&entry).map_err(AuditLogError::Serialize)?;
        writeln!(state.file, "{line}").map_err(AuditLogError::Io)?;
        state.file.sync_all().map_err(AuditLogError::Io)?;

        state.last_hash = hash_bytes;
        state.next_sequence += 1;
        Ok(())
    }

    /// Tier 1's lightweight direct-log entry point - "mandatory full-
    /// context audit logging" with no approval step to hang it off of (see
    /// this module's top-of-file doc comment). Call once, right after a
    /// Tier 1 capability call completes (or fails) - `outcome`'s shape
    /// (`Ok(detail)` / `Err(detail)`) mirrors
    /// `approval::Tier2Capability::execute`'s own `Result<String, String>`
    /// convention for consistency, widened to `Option<String>` on the `Ok`
    /// side since not every Tier 1 capability has a summary string to
    /// offer (unlike Tier 2's mock, which always does).
    pub fn log_tier1_call(
        &self,
        caller: NodeId,
        capability: &str,
        parameters: &[Constraint],
        outcome: Result<Option<String>, String>,
        duration: Duration,
    ) -> Result<(), AuditLogError> {
        let decision = AuditDecision {
            allowed: true,
            reason: "capability policy allowlist/rate-limit/concurrency check already passed; Tier 1 \
                     requires mandatory full-context audit logging on every call, with no separate \
                     approval gate"
                .to_string(),
        };
        let outcome = Some(match outcome {
            Ok(detail) => AuditOutcome::Success { detail },
            Err(detail) => AuditOutcome::Failure { detail },
        });
        self.record(&hex::encode(caller.as_bytes()), capability, Tier::Tier1.as_str(), parameters, decision, outcome, duration, None)
    }

    /// AXIOM Phase 3.8: `forge-node`'s local admin kill switch (freeze/
    /// unfreeze/suspend/unsuspend) - see this module's top-of-file
    /// "kill-switch/admin events" section for the full rationale. `action`
    /// is a short stable name (e.g. `"kill_switch_freeze"`), recorded as
    /// this entry's `capability` field (there is no real capability
    /// involved - the kill switch is explicitly not one - but reusing this
    /// field rather than adding a parallel one keeps `AuditEntry`'s schema
    /// unchanged). `detail`, if given, becomes this entry's `outcome`
    /// (always `Success` - a kill-switch action taken by a local admin
    /// with control-socket access does not have a "the action itself was
    /// denied" case the way a capability call does; the socket protocol's
    /// own `ERR` replies for a malformed command never reach this far).
    pub fn log_admin_event(&self, action: &str, detail: Option<String>, duration: Duration) -> Result<(), AuditLogError> {
        let decision = AuditDecision {
            allowed: true,
            reason: format!("local admin action '{action}' via forge-node's control socket (physical/SSH access to the box is the authentication boundary)"),
        };
        let outcome = Some(AuditOutcome::Success { detail });
        self.record(LOCAL_ADMIN_CALLER, action, ADMIN_ENTRY_TIER, &[], decision, outcome, duration, None)
    }

    /// Tier 2's entry point - consumes one TERMINAL `approval::LinkedRecord`
    /// (see `AuditLogError::NotTerminal`) and produces exactly one chained
    /// audit entry summarizing its whole propose/approve/execute lifecycle.
    /// This is literally what `LinkedRecord` was shaped for - see its own
    /// doc comment and this module's top-of-file doc comment.
    ///
    /// `duration_ms` is measured from `record.intent.submitted_at()`
    /// (proposal time) to `record.execution`'s `executed_at` when execution
    /// happened, or to "now" (this call is expected to run immediately
    /// after `Tier2ApprovalFlow::decide_and_execute` returns) for a
    /// terminal status that never reached execution - both are
    /// `Instant`-to-`Instant` diffs, valid regardless of wall-clock time.
    pub fn log_tier2_linked_record(&self, record: &LinkedRecord) -> Result<(), AuditLogError> {
        let channel_name = |r: &LinkedRecord| r.decision.map(|d| d.channel_name).unwrap_or("unknown channel");

        let (decision, outcome, duration) = match &record.status {
            IntentStatus::Pending | IntentStatus::InProgress => return Err(AuditLogError::NotTerminal),
            IntentStatus::Denied => (
                AuditDecision { allowed: false, reason: format!("denied by {}", channel_name(record)) },
                None,
                Instant::now().saturating_duration_since(record.intent.submitted_at()),
            ),
            IntentStatus::Expired => (
                AuditDecision {
                    allowed: false,
                    reason: "expired before an approval decision was reached".to_string(),
                },
                None,
                Instant::now().saturating_duration_since(record.intent.submitted_at()),
            ),
            IntentStatus::ParameterHashMismatch => (
                AuditDecision {
                    allowed: false,
                    reason: "parameters drifted from the hash captured at proposal time - rejected \
                             rather than approved against parameters that no longer match what was \
                             hashed"
                        .to_string(),
                },
                None,
                Instant::now().saturating_duration_since(record.intent.submitted_at()),
            ),
            IntentStatus::Executed | IntentStatus::ExecutionFailed => {
                let execution = record.execution.as_ref().ok_or(AuditLogError::NotTerminal)?;
                let outcome = Some(match &execution.outcome {
                    Ok(detail) => AuditOutcome::Success { detail: Some(detail.clone()) },
                    Err(detail) => AuditOutcome::Failure { detail: detail.clone() },
                });
                (
                    AuditDecision { allowed: true, reason: format!("approved by {}", channel_name(record)) },
                    outcome,
                    execution.executed_at.saturating_duration_since(record.intent.submitted_at()),
                )
            }
        };

        self.record(
            &hex::encode(record.intent.proposer.as_bytes()),
            &record.intent.capability,
            Tier::Tier2.as_str(),
            &record.intent.parameters,
            decision,
            outcome,
            duration,
            Some(record.intent.id.to_hex()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{CliApprovalChannel, MockDestructiveCapability, Tier2ApprovalFlow};
    use crate::policy::CapabilityPolicy;
    use axiom_crypto::identity::Keypair;
    use axiom_types::intent::Constraint as C;
    use std::io::Cursor;
    use std::sync::Arc;

    fn peer() -> NodeId {
        Keypair::generate().node_id()
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("axiom-audit-test-{name}-{}.jsonl", std::process::id()))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// AXIOM Phase 3.6: `Tier2ApprovalFlow::new` now requires an
    /// `Arc<CapabilityPolicy>` - this module's own tests exist to prove
    /// `AuditLog`'s Tier2-`LinkedRecord` wiring, not the protected-resource
    /// gate (that's `policy.rs`/`approval.rs`'s own test coverage), so a
    /// permissive (configured, empty) policy keeps every proposal below
    /// unblocked, same "get out of the way" role `approval.rs`'s own
    /// `permissive_policy` test helper plays there.
    fn permissive_policy() -> Arc<CapabilityPolicy> {
        Arc::new(CapabilityPolicy::for_test_with_protected_resources(Some(Vec::new())))
    }

    // --- is_sensitive_param_key ---

    #[test]
    fn sensitive_key_denylist_catches_common_secret_names() {
        for key in ["password", "Password", "PASSWORD", "api_key", "apiKey", "secret_token", "auth_header", "user_pin"] {
            assert!(is_sensitive_param_key(key), "'{key}' should be flagged sensitive");
        }
    }

    #[test]
    fn sensitive_key_denylist_does_not_flag_ordinary_keys() {
        for key in ["target", "enable", "vlan_id", "device_name", "count"] {
            assert!(!is_sensitive_param_key(key), "'{key}' should NOT be flagged sensitive");
        }
    }

    // --- basic append + verify ---

    #[test]
    fn append_n_entries_then_verify_chain_valid() {
        let path = temp_path("append-n");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        for i in 0..5 {
            log.log_tier1_call(
                peer(),
                "network_clients",
                &[C::string("target", format!("device-{i}"))],
                Ok(Some("3 clients".to_string())),
                Duration::from_millis(10),
            )
            .unwrap();
        }

        let state = verify_chain(&path).expect("chain must verify");
        assert_eq!(state.entries, 5);
        cleanup(&path);
    }

    #[test]
    fn empty_or_missing_file_verifies_as_zero_entries() {
        let path = temp_path("missing");
        cleanup(&path);
        let state = verify_chain(&path).expect("a nonexistent file is a valid empty chain");
        assert_eq!(state.entries, 0);
        assert_eq!(state.last_hash, GENESIS_HASH);
    }

    #[test]
    fn genesis_entry_chains_to_the_documented_sentinel() {
        let path = temp_path("genesis");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        log.log_tier1_call(peer(), "echo", &[], Ok(None), Duration::from_millis(1)).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let first_line = contents.lines().next().unwrap();
        let entry: AuditEntry = serde_json::from_str(first_line).unwrap();
        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.prev_hash, hex::encode(GENESIS_HASH));
        cleanup(&path);
    }

    // --- tamper detection ---

    #[test]
    fn tampered_middle_entry_content_is_detected_at_its_exact_index() {
        let path = temp_path("tamper-middle");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        for i in 0..4 {
            log.log_tier1_call(peer(), "network_clients", &[C::int("n", i)], Ok(None), Duration::from_millis(1)).unwrap();
        }
        drop(log);

        // Tamper entry index 2's content WITHOUT recomputing entry_hash -
        // exactly the threat model this module exists for.
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[2]).unwrap();
        entry.capability = "something_else_entirely".to_string();
        lines[2] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&path);
        assert_eq!(result, Err(AuditChainBreak::ContentTampered { index: 2 }));
        cleanup(&path);
    }

    #[test]
    fn deleted_middle_entry_breaks_the_chain_link() {
        let path = temp_path("delete-middle");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        for i in 0..4 {
            log.log_tier1_call(peer(), "network_clients", &[C::int("n", i)], Ok(None), Duration::from_millis(1)).unwrap();
        }
        drop(log);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // Remove index 1 entirely - index 2 (now second in the file) still
        // hashes correctly on its own, but its prev_hash no longer matches
        // the (now-different) entry immediately before it in the file.
        let mut kept: Vec<&str> = Vec::new();
        kept.push(lines[0]);
        kept.extend_from_slice(&lines[2..]);
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        let result = verify_chain(&path);
        assert!(matches!(result, Err(AuditChainBreak::ChainLinkBroken { index: 1, .. })), "got {result:?}");
        cleanup(&path);
    }

    #[test]
    fn truncated_tail_mid_record_is_detected_as_corrupt() {
        let path = temp_path("truncate-tail");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        for i in 0..3 {
            log.log_tier1_call(peer(), "network_clients", &[C::int("n", i)], Ok(None), Duration::from_millis(1)).unwrap();
        }
        drop(log);

        // Simulate a crash mid-write: cut the file off partway through the
        // last line, not on a line boundary.
        let contents = std::fs::read_to_string(&path).unwrap();
        let cut_at = contents.len() - 10;
        std::fs::write(&path, &contents[..cut_at]).unwrap();

        let result = verify_chain(&path);
        assert!(matches!(result, Err(AuditChainBreak::CorruptEntry { index: 2, .. })), "got {result:?}");
        cleanup(&path);
    }

    #[test]
    fn cleanly_dropping_the_last_entry_is_a_valid_shorter_chain() {
        // Documented, honest limitation (see this module's top-of-file doc
        // comment): a pure hash chain with no external anchor cannot tell
        // "the log legitimately has 2 entries" apart from "someone deleted
        // the 3rd entry cleanly." This test proves verify_chain doesn't
        // lie about it either way - it correctly reports a valid 2-entry
        // chain, it does not falsely claim tampering it cannot actually
        // detect.
        let path = temp_path("clean-drop-tail");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        for i in 0..3 {
            log.log_tier1_call(peer(), "network_clients", &[C::int("n", i)], Ok(None), Duration::from_millis(1)).unwrap();
        }
        drop(log);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        std::fs::write(&path, lines[..2].join("\n") + "\n").unwrap();

        let state = verify_chain(&path).expect("a cleanly-shortened prefix chain is still internally valid");
        assert_eq!(state.entries, 2);
        cleanup(&path);
    }

    #[test]
    fn open_refuses_to_append_to_an_already_corrupt_file() {
        let path = temp_path("open-refuses");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        log.log_tier1_call(peer(), "echo", &[], Ok(None), Duration::from_millis(1)).unwrap();
        drop(log);

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, contents.replace("echo", "tampered")).unwrap();

        let result = AuditLog::open(&path);
        assert!(matches!(result, Err(AuditLogError::ExistingLogCorrupt(_))), "got {result:?}");
        cleanup(&path);
    }

    // --- redaction ---

    #[test]
    fn sensitive_parameter_never_appears_in_plaintext_in_the_raw_file() {
        let path = temp_path("redact");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        let secret_value = "sup3r-s3cret-omada-password-xyz";
        log.log_tier1_call(
            peer(),
            "network_clients",
            &[C::string("password", secret_value), C::string("target", "controller-1")],
            Ok(Some("ok".to_string())),
            Duration::from_millis(5),
        )
        .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(secret_value), "the raw secret value must never appear in the audit log file");
        assert!(raw.contains("[REDACTED]"), "the redaction marker must appear in place of the secret");
        assert!(raw.contains("controller-1"), "a non-sensitive parameter must still appear in plaintext");

        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        let password_param = entry.parameters.iter().find(|p| p.key == "password").unwrap();
        assert!(password_param.redacted);
        assert_eq!(password_param.value, "[REDACTED]");
        cleanup(&path);
    }

    // --- Tier 1 direct-log path ---

    #[test]
    fn tier1_direct_log_produces_a_correctly_chained_entry_with_required_fields() {
        let path = temp_path("tier1");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        let caller = peer();
        log.log_tier1_call(
            caller,
            "network_clients",
            &[C::string("controller", "omada-1")],
            Ok(Some("5 clients".to_string())),
            Duration::from_millis(42),
        )
        .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(entry.tier, "tier1");
        assert_eq!(entry.capability, "network_clients");
        assert_eq!(entry.caller, hex::encode(caller.as_bytes()));
        assert!(entry.decision.allowed);
        assert_eq!(entry.outcome, Some(AuditOutcome::Success { detail: Some("5 clients".to_string()) }));
        assert_eq!(entry.duration_ms, 42);
        assert!(entry.intent_id.is_none(), "Tier 1 entries have no IntentId concept");
        assert_eq!(entry.prev_hash, hex::encode(GENESIS_HASH));

        verify_chain(&path).expect("must be a valid chain");
        cleanup(&path);
    }

    #[test]
    fn tier1_failure_outcome_is_recorded_distinctly_from_a_denial() {
        let path = temp_path("tier1-fail");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();
        log.log_tier1_call(peer(), "network_clients", &[], Err("UAI broker unreachable".to_string()), Duration::from_millis(9))
            .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(entry.decision.allowed, "the call WAS allowed/dispatched - only its outcome failed");
        assert_eq!(entry.outcome, Some(AuditOutcome::Failure { detail: "UAI broker unreachable".to_string() }));
        cleanup(&path);
    }

    // --- Tier 2 LinkedRecord wiring ---

    fn cli_with_input(input: &str) -> CliApprovalChannel<Cursor<Vec<u8>>, Vec<u8>> {
        CliApprovalChannel::new(Cursor::new(input.as_bytes().to_vec()), Vec::new())
    }

    #[test]
    fn tier2_executed_linked_record_produces_a_correctly_chained_entry() {
        let path = temp_path("tier2-executed");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        let proposer = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let params = vec![C::string("target", "test-device"), C::bool("enable", true)];
        let id = flow.propose(proposer, &cap, params).expect("permissive_policy has no protected resources configured");
        let status = flow.decide_and_execute(id, &cap).unwrap();
        assert_eq!(status, crate::approval::IntentStatus::Executed);
        let record = flow.record(id).unwrap();

        log.log_tier2_linked_record(&record).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(entry.tier, "tier2");
        assert_eq!(entry.capability, "mock_destructive_action");
        assert_eq!(entry.caller, hex::encode(proposer.as_bytes()));
        assert!(entry.decision.allowed);
        assert!(entry.decision.reason.contains("cli-prompt"));
        assert_eq!(entry.intent_id, Some(id.to_hex()));
        assert!(matches!(entry.outcome, Some(AuditOutcome::Success { .. })));
        let target_param = entry.parameters.iter().find(|p| p.key == "target").unwrap();
        assert_eq!(target_param.value, "\"test-device\"");

        verify_chain(&path).expect("must be a valid chain");
        cleanup(&path);
    }

    #[test]
    fn tier2_denied_linked_record_produces_an_entry_with_no_outcome() {
        let path = temp_path("tier2-denied");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        let proposer = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("n\n"), permissive_policy());
        let id = flow.propose(proposer, &cap, vec![]).expect("permissive_policy has no protected resources configured");
        flow.decide_and_execute(id, &cap).unwrap();
        let record = flow.record(id).unwrap();

        log.log_tier2_linked_record(&record).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(!entry.decision.allowed);
        assert!(entry.decision.reason.contains("denied"));
        assert!(entry.outcome.is_none(), "a denied intent never executed - there is no outcome to record");
        cleanup(&path);
    }

    #[test]
    fn tier2_expired_linked_record_is_logged_with_no_channel_consulted() {
        let path = temp_path("tier2-expired");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        let proposer = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::with_expiry(cli_with_input("y\n"), Duration::from_millis(10), permissive_policy());
        let id = flow.propose(proposer, &cap, vec![]).expect("permissive_policy has no protected resources configured");
        std::thread::sleep(Duration::from_millis(50));
        let result = flow.decide_and_execute(id, &cap);
        assert!(result.is_err());
        let record = flow.record(id).unwrap();

        log.log_tier2_linked_record(&record).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(!entry.decision.allowed);
        assert!(entry.decision.reason.contains("expired"));
        cleanup(&path);
    }

    #[test]
    fn pending_linked_record_cannot_be_logged() {
        let path = temp_path("tier2-pending");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        let proposer = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(proposer, &cap, vec![]).expect("permissive_policy has no protected resources configured");
        let record = flow.record(id).unwrap();
        assert_eq!(record.status, crate::approval::IntentStatus::Pending);

        let result = log.log_tier2_linked_record(&record);
        assert!(matches!(result, Err(AuditLogError::NotTerminal)));
        assert!(log.is_empty(), "a rejected pending-record log call must not have appended anything");
        cleanup(&path);
    }

    // --- multiple entries stay correctly chained across mixed tiers ---

    #[test]
    fn mixed_tier1_and_tier2_entries_stay_correctly_chained() {
        let path = temp_path("mixed");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        log.log_tier1_call(peer(), "network_clients", &[], Ok(None), Duration::from_millis(1)).unwrap();

        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(peer(), &cap, vec![]).expect("permissive_policy has no protected resources configured");
        flow.decide_and_execute(id, &cap).unwrap();
        log.log_tier2_linked_record(&flow.record(id).unwrap()).unwrap();

        log.log_tier1_call(peer(), "network_clients", &[], Ok(None), Duration::from_millis(1)).unwrap();

        let state = verify_chain(&path).expect("mixed-tier chain must still verify");
        assert_eq!(state.entries, 3);
        cleanup(&path);
    }

    // --- AXIOM Phase 3.8: kill-switch/admin events ---

    #[test]
    fn admin_event_produces_a_correctly_chained_entry_with_the_local_admin_sentinel() {
        let path = temp_path("admin-freeze");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        log.log_admin_event("kill_switch_freeze", Some("all Tier1+ execution frozen".to_string()), Duration::from_millis(1)).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(entry.caller, LOCAL_ADMIN_CALLER);
        assert_eq!(entry.capability, "kill_switch_freeze");
        assert_eq!(entry.tier, "admin");
        assert!(entry.decision.allowed);
        assert_eq!(entry.outcome, Some(AuditOutcome::Success { detail: Some("all Tier1+ execution frozen".to_string()) }));
        assert!(entry.intent_id.is_none());

        verify_chain(&path).expect("must be a valid chain");
        cleanup(&path);
    }

    #[test]
    fn admin_events_stay_correctly_chained_alongside_tier1_entries() {
        let path = temp_path("admin-mixed");
        cleanup(&path);
        let log = AuditLog::open(&path).unwrap();

        log.log_admin_event("kill_switch_freeze", None, Duration::from_millis(1)).unwrap();
        log.log_tier1_call(peer(), "echo", &[], Ok(None), Duration::from_millis(1)).unwrap();
        log.log_admin_event("kill_switch_unfreeze", None, Duration::from_millis(1)).unwrap();

        let state = verify_chain(&path).expect("mixed admin/tier1 chain must still verify");
        assert_eq!(state.entries, 3);
        cleanup(&path);
    }
}
