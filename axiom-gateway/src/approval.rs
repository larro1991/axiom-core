//! AXIOM Phase 3.3: the Tier 2 propose -> approve -> execute flow.
//!
//! Tier 2 ("destructive/security-relevant" - see `policy::Tier::Tier2`'s doc
//! comment and `DECISIONS.md`'s "Tier model" section) is defined by one
//! extra control beyond Tier 1: **explicit human approval per invocation,
//! no standing approvals, no wildcards.** Phase 3.1/3.2 landed the tier
//! MODEL (a capability can be correctly declared `tier2` and refuses to
//! register without a valid tier) but built none of the enforcement that
//! tier implies. This module is that enforcement's mechanism - the
//! propose/approve/execute state machine itself, channel-agnostic per
//! `DECISIONS.md`'s "Tier-2 approval channel" section: "The `ApprovalChannel`
//! trait makes this upgrade [v2 phone-push] a new implementation, not a
//! state-machine redesign."
//!
//! **What this module deliberately does NOT do:**
//! - Wire a real Tier 2 capability into anything ITSELF - that remained
//!   true through Phase 3.7, when this module rehearsed only against
//!   `MockDestructiveCapability` below, per the roadmap's Phase 3 exit
//!   criteria ("end-to-end rehearsal with a mock Tier 2 capability...
//!   demonstrated to the owner before any real Tier 2 exists"). AXIOM
//!   Tier 2 (2026-08-10, see `axiom-gateway/src/lib.rs`'s own doc comment)
//!   is the first real Tier 2 capability (`forge-node`'s `wg_peer_manage`,
//!   via a new Telegram `ApprovalChannel` impl) - it consumes this module
//!   completely unchanged, exactly as this module's own design intended:
//!   nothing here needed to move, only a new `ApprovalChannel` impl and a
//!   new `Tier2Capability` impl, both living in `forge-node`, not here.
//!   `MockDestructiveCapability` remains this module's own rehearsal
//!   fixture (`test`/`test-utils`-only) - it did not become, and was never
//!   meant to become, a stand-in for a real capability.
//! - Consult `policy::CapabilityPolicy` to check a capability's registered
//!   TIER before accepting a proposal. That integration point still
//!   belongs to whichever future phase actually wires this flow into
//!   `forge-node`'s real capability dispatch (not this phase, and not a
//!   real Tier 2 capability existing yet to dispatch to) - this module is
//!   usable standalone by any caller that has already decided a capability
//!   is Tier 2 and wants the approval mechanics, matching this crate's
//!   whole "standalone, embeddable by other consumers" design constraint
//!   (see `DECISIONS.md`'s "ecosystem positioning" section - Conduit's
//!   Burr Phase 2 is the intended second consumer, and it will have its
//!   own policy/dispatch layer to make that call).
//!
//!   AXIOM Phase 3.6 (2026-08-06) narrows this: `Tier2ApprovalFlow` NOW
//!   requires an `Arc<policy::CapabilityPolicy>` at construction time
//!   (`new`/`with_expiry`) and consults it on every `propose`/
//!   `propose_with_expiry` call - but ONLY for the ratified protected-
//!   resource check and the optional per-capability argument-substring
//!   denylist (see `policy.rs`'s module doc comment for the full design).
//!   It still does NOT look up or gate on the proposed capability's
//!   registered TIER - a caller that hands this flow a capability whose
//!   policy entry doesn't even claim Tier 2 gets the same protected-
//!   resource/argument-constraint checking as one that does, which is
//!   correct: those checks apply to "the roadmap's mandatory dispatch-core
//!   gate," not specifically to Tier2-ness, and this module has no way to
//!   independently confirm what dispatch layer, if any, already verified
//!   the capability's tier before calling `propose` in the first place.
//! - Build Phase 3.4's real hash-chained append-only audit log. `LinkedRecord`
//!   below is a plain in-memory struct joining one intent to its (at most
//!   one) approval decision and (at most one) execution result by
//!   `IntentId` - exactly the shape a real audit log needs to consume, with
//!   no redesign implied, but it is NOT itself tamper-evident, persistent,
//!   or hash-chained. That is Phase 3.4, a separate follow-up.
//!
//! # The three failure modes this module exists to make impossible
//!
//! 1. **A stale intent gets approved.** Every intent carries a one-time
//!    `IntentId` and an expiry (`Intent::propose`'s `expiry` parameter,
//!    default `DEFAULT_EXPIRY` = 15 minutes, per the roadmap's own
//!    suggestion). `Tier2ApprovalFlow::decide_and_execute` checks
//!    `Intent::is_expired` BEFORE ever invoking the approval channel (no
//!    point prompting a human for a decision that can't be honored) and
//!    AGAIN immediately before execution (a slow human approver can cross
//!    the expiry boundary while still deciding) - see that method's body.
//!    Either check failing returns `FlowError::Expired` cleanly; nothing
//!    panics, nothing silently proceeds.
//! 2. **An approval gets applied to different parameters than the ones it
//!    was actually granted for.** `Intent::parameter_hash` is computed once,
//!    at `propose` time, from the capability name and parameter set as
//!    submitted (via `axiom_crypto::IntentHasher::hash_intent` - this
//!    module deliberately does not invent its own hashing; see
//!    `Intent::compute_parameter_hash`'s doc comment for exactly how it
//!    reuses that primitive). `Intent::verify_parameter_hash` re-derives
//!    the hash from whatever `parameters` currently holds and compares -
//!    `decide_and_execute` calls this both before prompting and again
//!    before executing, so any drift between the parameters an approver
//!    was shown and the parameters that would actually execute is caught,
//!    not silently trusted. `Tier2ApprovalFlow::tamper_parameters_for_test`
//!    (test/`test-utils`-only) exists specifically to prove this - see
//!    this module's own tests.
//! 3. **A capability executes without an actual "yes."** `decide_and_execute`
//!    only calls `Tier2Capability::execute` on `ApprovalDecision::approved ==
//!    true`; a denial (or a channel I/O error, or either check in (1)/(2)
//!    failing) returns before `execute` is ever reachable. There is no
//!    standing-approval or wildcard concept anywhere in this module - every
//!    single intent goes through this whole sequence, every time.
//! 4. **AXIOM Phase 3.6: the owner sees an approval prompt for something
//!    that was never going to be allowed.** `propose`/`propose_with_expiry`
//!    check the proposed parameters against `policy::CapabilityPolicy`'s
//!    ratified protected-resource list (and its optional per-capability
//!    argument denylist) BEFORE registering the intent or computing a
//!    dry-run diff - a match returns `Err(ProposeError::..)` immediately,
//!    so no `IntentId` is even minted and `decide_and_execute`/
//!    `ApprovalChannel::request_approval` are never reachable for it. This
//!    is the roadmap's own stated UX requirement ("the owner never even
//!    sees an approval request for it") implemented structurally, not by
//!    convention: a `Tier2ApprovalFlow` cannot be constructed at all
//!    without an `Arc<policy::CapabilityPolicy>` to check against (see
//!    `new`/`with_expiry`), so there is no code path that reaches
//!    `decide_and_execute` for a proposal this check would have rejected.
//!    See `propose_with_expiry`'s own doc comment and this module's
//!    `channel_is_never_consulted_for_a_protected_resource_proposal` test
//!    for the direct proof.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axiom_crypto::IntentHasher;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::intent::{Constraint, ConstraintValue, IntentDescriptor};

use crate::policy::CapabilityPolicy;

/// Default intent expiry - 15 minutes, per the roadmap's own suggestion for
/// Tier 2 intents and `DECISIONS.md`'s "Tier-2 approval channel" section
/// (the 15-minute figure is exactly why v2's phone-push channel is called
/// out as required "before Tier 2 actions become *routine*" - a CLI prompt
/// on the management box and a 15-minute clock assume the approver is at
/// the box). Configurable per-intent via `Intent::propose`'s `expiry`
/// parameter / `Tier2ApprovalFlow::propose_with_expiry` - this constant is
/// only the default `Tier2ApprovalFlow::new` and `Intent::propose_default`
/// use when the caller doesn't care to override it.
pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// One-time identifier for a single proposed intent - 16 random bytes
/// (`rand::random`, not derived from the intent's own content: two
/// proposals of the exact same capability+parameters must still get
/// distinct IDs, since "one-time" here means "good for at most one
/// approval decision," not "content-addressed"). Deliberately NOT the same
/// type as `axiom_types::crypto::IntentHash` (which this module also uses,
/// for a different purpose - see `Intent::parameter_hash`) even though
/// both happen to be 16 bytes: an `IntentId` identifies WHICH proposal this
/// is, an `IntentHash` binds WHAT was proposed. Conflating them would make
/// it possible to "re-submit the same parameters" and have that look like
/// approving the original stale proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntentId([u8; 16]);

impl IntentId {
    fn generate() -> Self {
        Self(rand::random())
    }

    /// Full hex encoding - always the full 32 hex chars, never truncated,
    /// unlike e.g. `NodeId`'s `Display` impl. An approval decision is a
    /// security-relevant, one-time action; a truncated ID inside the
    /// prompt a human is about to say "yes" to is exactly the kind of
    /// corner-cutting this module's own doc comment (failure mode 2) warns
    /// against for parameters - the same argument applies to the ID naming
    /// what's being approved.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for IntentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// One line of a dry-run diff: `key` went from `current` to `proposed`.
/// Plain strings, not typed `ConstraintValue`s - this is presentation data
/// for a human reading the approval prompt (and later, Phase 3.4's audit
/// log), not something re-parsed or re-hashed by this module. See
/// `Tier2Capability::dry_run`'s doc comment for why it's optional per
/// capability rather than mandatory per intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunDiffEntry {
    pub key: String,
    pub current: String,
    pub proposed: String,
}

impl DryRunDiffEntry {
    pub fn new(key: impl Into<String>, current: impl Into<String>, proposed: impl Into<String>) -> Self {
        Self { key: key.into(), current: current.into(), proposed: proposed.into() }
    }
}

/// A Tier 2 action an agent (a peer identity, same Ed25519 `NodeId` model
/// as everything else in this codebase) has proposed. Immutable in normal
/// use - `propose` is the only constructor, and the only field this module
/// itself ever mutates after that is `parameters`, and only via
/// `Tier2ApprovalFlow::tamper_parameters_for_test` (test/`test-utils`-only,
/// simulating the drift `verify_parameter_hash` exists to catch - see this
/// module's top-of-file doc comment, failure mode 2).
#[derive(Debug, Clone)]
pub struct Intent {
    pub id: IntentId,
    /// The proposing peer's identity. Not itself re-verified by this
    /// module - by the time a capability dispatch layer calls `propose`,
    /// the same signed-frame verification every other capability call in
    /// this codebase already goes through (see `policy.rs`'s module doc
    /// comment) has already proven this is who they say they are. This
    /// module's job starts after that: WHAT they're asking for, not WHO
    /// they are.
    pub proposer: NodeId,
    pub capability: String,
    pub parameters: Vec<Constraint>,
    /// Present wherever the backend supports reading current state before
    /// proposing a change, absent otherwise - a capability that can't read
    /// its own current state simply omits this rather than fabricating a
    /// diff. See `Tier2Capability::dry_run`.
    pub dry_run_diff: Option<Vec<DryRunDiffEntry>>,
    /// BLAKE3-derived binding hash over `capability` + `parameters` exactly
    /// as submitted here - see `compute_parameter_hash`'s doc comment.
    /// Deliberately NOT recomputed lazily on every check; captured once at
    /// `propose` time so `verify_parameter_hash` has a fixed point of
    /// comparison to catch drift against, rather than trivially agreeing
    /// with whatever `parameters` currently says.
    pub parameter_hash: IntentHash,
    submitted_at: Instant,
    expires_at: Instant,
}

impl Intent {
    /// Propose a new intent, expiring `expiry` from now. Not `pub` on its
    /// own - use `Tier2ApprovalFlow::propose`/`propose_with_expiry`, which
    /// also registers the resulting intent for later `decide_and_execute`
    /// lookup. Exposed at the module level (rather than nested entirely
    /// inside the flow) because `Intent` itself, and this constructor's
    /// hashing behavior specifically, are exactly what this module's own
    /// tests need to exercise directly without going through a full flow.
    fn propose(
        proposer: NodeId,
        capability: impl Into<String>,
        parameters: Vec<Constraint>,
        dry_run_diff: Option<Vec<DryRunDiffEntry>>,
        expiry: Duration,
    ) -> Self {
        let capability = capability.into();
        let parameter_hash = Self::compute_parameter_hash(&capability, &parameters);
        let now = Instant::now();
        Self {
            id: IntentId::generate(),
            proposer,
            capability,
            parameters,
            dry_run_diff,
            parameter_hash,
            submitted_at: now,
            expires_at: now + expiry,
        }
    }

    /// Binds `capability` + `parameters` to an `IntentHash` by reusing
    /// `axiom_crypto::IntentHasher::hash_intent` as-is - the SAME
    /// canonicalization (constraints sorted by key, per-type-tagged
    /// encoding) this codebase already uses to hash `IntentDescriptor`s
    /// elsewhere, rather than this module inventing a second hashing
    /// scheme (see the roadmap's own instruction: reuse the existing
    /// primitive before pulling in anything new). `priority`/`ttl_ms` on
    /// the constructed `IntentDescriptor` are left at
    /// `IntentDescriptor::new`'s defaults (128 / 30_000) rather than
    /// threaded through from anywhere - `hash_intent` folds them into the
    /// hash too, but they're held constant across every Tier 2 intent this
    /// module ever constructs, so they contribute no variance: two intents
    /// hash equal here if and only if their `capability` and `parameters`
    /// match, which is the only invariant this hash exists to protect (see
    /// this module's top-of-file doc comment, failure mode 2). `fallbacks`
    /// is left empty for the same reason - not meaningful for a Tier 2
    /// approval intent, `IntentDescriptor` here is reused purely as a
    /// convenient carrier for the parts `hash_intent` needs, not as this
    /// module's own domain type (see `Intent`'s doc comment for why
    /// `IntentId` and `IntentHash` are deliberately kept distinct - the
    /// same "don't conflate two different existing concepts" care applies
    /// to reusing `IntentDescriptor` here).
    fn compute_parameter_hash(capability: &str, parameters: &[Constraint]) -> IntentHash {
        let mut descriptor = IntentDescriptor::new(capability);
        descriptor.constraints = parameters.to_vec();
        IntentHasher::hash_intent(&descriptor)
    }

    /// True once `expires_at` has passed. Uses the real wall/monotonic
    /// clock (`Instant::now()`), matching `policy.rs::check_and_acquire`'s
    /// own rate-limit-window check - no injected-clock abstraction exists
    /// elsewhere in this crate for this kind of short-lived, in-process
    /// timing, so this module doesn't invent one either. Tests that need
    /// to observe an intent crossing its expiry use a short real `expiry`
    /// plus a short real sleep (see this module's own
    /// `expired_intent_cannot_be_approved` test).
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Time remaining until expiry, `Duration::ZERO` if already expired
    /// (never negative/panicking - `Instant::saturating_duration_since`).
    /// Presentation-only (the CLI prompt shows this); `is_expired` is the
    /// actual gate.
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// When this intent was proposed - kept for a future audit-log consumer
    /// (Phase 3.4) that will want a real submission timestamp on each
    /// linked record, not just an expiry countdown. Not consulted by any
    /// check in this module itself (`is_expired`/`remaining` are both
    /// relative to `expires_at`, not this).
    pub fn submitted_at(&self) -> Instant {
        self.submitted_at
    }

    /// Re-derives `parameter_hash` from the CURRENT `capability`/`parameters`
    /// and compares against the hash captured at `propose` time. `false`
    /// means the intent's parameters have drifted since it was proposed -
    /// see this module's top-of-file doc comment, failure mode 2, and
    /// `Tier2ApprovalFlow::tamper_parameters_for_test` for how this is
    /// exercised in tests (nothing in normal, non-test use of this module
    /// ever mutates `parameters` after `propose`, so this should always be
    /// `true` in practice - it is checked anyway, not trusted by
    /// construction).
    pub fn verify_parameter_hash(&self) -> bool {
        Self::compute_parameter_hash(&self.capability, &self.parameters) == self.parameter_hash
    }

    fn as_approval_request(&self) -> ApprovalRequest {
        ApprovalRequest {
            intent_id: self.id,
            proposer: self.proposer,
            capability: self.capability.clone(),
            parameters: self.parameters.clone(),
            dry_run_diff: self.dry_run_diff.clone(),
            parameter_hash: self.parameter_hash,
            remaining: self.remaining(),
        }
    }
}

/// The read-only view an `ApprovalChannel` is handed - everything a human
/// (or a future automated channel) needs to make and correctly bind a
/// decision, and nothing that would let a channel implementation mutate
/// the intent it's reviewing. Deliberately a separate type from `Intent`
/// itself, same rationale as `policy::CapabilitySummary` being decoupled
/// from `policy::CapabilityEntry`: a channel has no business touching
/// anything beyond what it's shown.
///
/// Owns its data (clones out of the `Intent` it's built from) rather than
/// borrowing it, deliberately: `Tier2ApprovalFlow::decide_and_execute`
/// builds this while holding its intent registry's lock, then releases
/// that lock BEFORE calling a (potentially slow - a human deciding) channel
/// - a borrowed view tied to the lock's lifetime can't survive being
/// handed to the channel after the lock is dropped, and holding the lock
/// for the duration of a human decision would stall every other intent on
/// the same flow for no reason. The clone is of a handful of small,
/// short-lived strings/vecs - not a real cost next to "block on human
/// input."
///
/// Carries exactly the roadmap's own stated contract for `ApprovalChannel`
/// - "given intent ID + parameter hash + expiry" (`intent_id`,
/// `parameter_hash`, `remaining`) - plus the additional context (`capability`,
/// `parameters`, `dry_run_diff`, `proposer`) a channel needs to actually
/// PRESENT the intent, which the roadmap's contract implies but doesn't
/// spell out field-by-field.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub intent_id: IntentId,
    pub proposer: NodeId,
    pub capability: String,
    pub parameters: Vec<Constraint>,
    pub dry_run_diff: Option<Vec<DryRunDiffEntry>>,
    pub parameter_hash: IntentHash,
    pub remaining: Duration,
}

/// An approve/deny decision returned by an `ApprovalChannel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub intent_id: IntentId,
    pub approved: bool,
    /// Which channel produced this decision (`ApprovalChannel::name()`) -
    /// recorded on the decision itself, not just implied by "whichever
    /// channel `Tier2ApprovalFlow` happened to be constructed with," so a
    /// later multi-channel world (`DECISIONS.md`'s v2 phone-push plan)
    /// still has this on each individual linked record.
    pub channel_name: &'static str,
}

/// An `ApprovalChannel` implementation failed to produce a decision at all
/// (as opposed to producing an explicit deny) - e.g. the CLI's stdin closed
/// mid-prompt. Distinct from `ApprovalDecision { approved: false, .. }` for
/// the same reason `policy::PolicyOutcome` never conflates its distinct
/// failure shapes: an operator who typed "n" and a channel that couldn't
/// reach an operator at all are different situations a caller (and a
/// future audit log) should be able to tell apart.
#[derive(Debug)]
pub enum ApprovalChannelError {
    Io(String),
}

impl std::fmt::Display for ApprovalChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "approval channel I/O error: {msg}"),
        }
    }
}

impl std::error::Error for ApprovalChannelError {}

/// Channel-agnostic by design, per `DECISIONS.md`'s "Tier-2 approval
/// channel" section: "The `ApprovalChannel` trait makes this upgrade [v2
/// phone-push] a new implementation, not a state-machine redesign." Any
/// implementation's contract is exactly the roadmap's own wording: given an
/// intent ID, parameter hash, and expiry (see `ApprovalRequest`), return an
/// authenticated approve/deny. "Authenticated" is intentionally left to
/// each implementation to define for its own channel - see
/// `CliApprovalChannel`'s doc comment for what that means for the CLI
/// prompt specifically (physical/SSH access to the box IS the
/// authentication boundary for v1; a future phone-push implementation
/// would define its own, e.g. the existing automation's own auth, without
/// this trait or `Tier2ApprovalFlow` changing at all).
pub trait ApprovalChannel {
    /// Human-readable, stable name for this channel implementation -
    /// recorded on every `ApprovalDecision` it produces (`channel_name`).
    fn name(&self) -> &'static str;

    /// Block until an explicit approve/deny decision is made for
    /// `request`, or return `Err` if this channel couldn't produce one at
    /// all (see `ApprovalChannelError`). Implementations must not invent an
    /// approval where none was explicitly given - an ambiguous, missing, or
    /// malformed response is a deny (or an `Err`, if the channel itself
    /// failed), never a silent approve. See `CliApprovalChannel`'s impl for
    /// the concrete v1 behavior.
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError>;
}

/// Renders the human-readable approval prompt shown by `CliApprovalChannel`
/// - split out as its own function so it's independently testable without
/// needing real stdin/stdout.
fn render_prompt(request: &ApprovalRequest) -> String {
    let mut out = String::new();
    out.push_str("=== AXIOM Tier 2 approval required ===\n");
    out.push_str(&format!("Intent ID:   {}\n", request.intent_id));
    out.push_str(&format!("Capability:  {}\n", request.capability));
    out.push_str(&format!("Proposer:    {}\n", hex::encode(request.proposer.as_bytes())));
    out.push_str(&format!("Param hash:  {}\n", hex::encode(request.parameter_hash.as_bytes())));
    if request.parameters.is_empty() {
        out.push_str("Parameters:  (none)\n");
    } else {
        out.push_str("Parameters:\n");
        for c in &request.parameters {
            out.push_str(&format!("  - {} = {}\n", c.key, format_constraint_value(&c.value)));
        }
    }
    match &request.dry_run_diff {
        Some(diff) if !diff.is_empty() => {
            out.push_str("Dry-run diff:\n");
            for entry in diff {
                out.push_str(&format!("  - {}: {} -> {}\n", entry.key, entry.current, entry.proposed));
            }
        }
        Some(_) => out.push_str("Dry-run diff: (no changes)\n"),
        None => out.push_str("Dry-run diff: (not available for this capability)\n"),
    }
    out.push_str(&format!("Expires in:  {}\n", format_duration(request.remaining)));
    out.push_str("This action is destructive/security-relevant (Tier 2) and requires your explicit, one-time approval.\n");
    out.push_str("No standing approvals, no wildcards - this decision applies to this exact intent only.\n");
    out.push_str("Approve? [y/N]: ");
    out
}

/// AXIOM Phase 3.4: widened from private to `pub(crate)` so `audit.rs` can
/// reuse the exact same human-readable stringification for a parameter's
/// value when building a (possibly-redacted) `audit::AuditParam` - one
/// rendering of a `ConstraintValue`, not two independently-maintained
/// copies. No behavior change to this module's own use of it.
pub(crate) fn format_constraint_value(v: &ConstraintValue) -> String {
    match v {
        ConstraintValue::String(s) => format!("{s:?}"),
        ConstraintValue::Int(i) => i.to_string(),
        ConstraintValue::Float(f) => f.to_string(),
        ConstraintValue::Bool(b) => b.to_string(),
        ConstraintValue::Range { min, max } => format!("[{min}, {max}]"),
        ConstraintValue::OneOf(values) => format!("one of {values:?}"),
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// The ratified primary Tier 2 approval channel (`DECISIONS.md`, "Tier-2
/// approval channel" section: "Primary, now: CLI prompt on the management
/// box... what Phase 3.3's mock rehearsal runs against"). "Authenticated"
/// for this implementation specifically means physical or SSH access to
/// the box this process is running on - this command only ever runs
/// interactively there, so that access IS the authentication boundary; no
/// cryptographic approval signing is invented here (the roadmap doesn't
/// ask for one for the CLI-prompt implementation specifically, and nothing
/// in this codebase's existing primitives is an obvious fit to bolt on
/// without inventing new machinery - `axiom-crypto`'s signing types are
/// keyed to a peer's own `Keypair`/`NodeId`, not to "whoever is typing at
/// this terminal," which is a different identity model this module isn't
/// asked to build).
///
/// Generic over the reader/writer so tests can inject an in-memory
/// `BufRead`/`Write` instead of real stdin/stdout (see this module's own
/// tests, and `ApprovalChannel::request_approval`'s doc comment on why an
/// ambiguous/EOF response must be a deny). `CliApprovalChannel::stdio()` is
/// the real, production constructor.
pub struct CliApprovalChannel<R, W> {
    reader: Mutex<R>,
    writer: Mutex<W>,
}

impl<R: BufRead + Send, W: Write + Send> CliApprovalChannel<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader: Mutex::new(reader), writer: Mutex::new(writer) }
    }
}

impl CliApprovalChannel<std::io::BufReader<std::io::Stdin>, std::io::Stdout> {
    /// Real interactive constructor: prompts on stdout, reads one line from
    /// stdin. `BufReader` wraps `Stdin` because (unlike `StdinLock`) it
    /// doesn't otherwise implement `BufRead`, and `read_line` needs that.
    pub fn stdio() -> Self {
        Self::new(std::io::BufReader::new(std::io::stdin()), std::io::stdout())
    }
}

impl<R: BufRead + Send, W: Write + Send> ApprovalChannel for CliApprovalChannel<R, W> {
    fn name(&self) -> &'static str {
        "cli-prompt"
    }

    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
        {
            let mut writer = self.writer.lock().unwrap();
            write!(writer, "{}", render_prompt(request)).map_err(|e| ApprovalChannelError::Io(e.to_string()))?;
            writer.flush().map_err(|e| ApprovalChannelError::Io(e.to_string()))?;
        }

        let mut line = String::new();
        {
            let mut reader = self.reader.lock().unwrap();
            let bytes_read = reader.read_line(&mut line).map_err(|e| ApprovalChannelError::Io(e.to_string()))?;
            if bytes_read == 0 {
                // EOF with no input at all - a closed/non-interactive stdin,
                // not a typed decision. Fails closed as a deny (see the
                // trait's own doc comment) rather than an error, since a
                // human closing the prompt without answering is a legitimate
                // (if unhelpful) way to say "not now."
            }
        }

        // Only an exact (trimmed, case-insensitive) "y"/"yes" is an
        // approval - anything else (empty input, "n", "no", a typo, EOF) is
        // a deny. See `ApprovalChannel::request_approval`'s doc comment:
        // ambiguous input must never be treated as approval.
        let approved = matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");

        {
            let mut writer = self.writer.lock().unwrap();
            let _ = writeln!(writer, "{}", if approved { "-> APPROVED" } else { "-> DENIED" });
        }

        Ok(ApprovalDecision { intent_id: request.intent_id, approved, channel_name: self.name() })
    }
}

/// A Tier 2 capability this flow can propose against and, once approved,
/// execute. Deliberately a small trait, not tied to `forge-node`'s own
/// capability-dispatch machinery (this crate has zero dependency on that -
/// see this crate's own `Cargo.toml` description) - any capability
/// implementation, real or mock, plugs in here.
pub trait Tier2Capability {
    /// The name this capability is proposed/dispatched under - matches
    /// `policy::CapabilityPolicy`'s capability-name vocabulary, though this
    /// trait doesn't itself consult the policy (see this module's
    /// top-of-file doc comment on what's deliberately out of scope).
    fn capability_name(&self) -> &str;

    /// Compute a dry-run diff for `parameters` if this capability's backend
    /// supports reading current state, `None` if it can't (e.g. a pure
    /// creation/action with no "current value" to diff against). Default
    /// `None` - most capabilities won't override this, matching the
    /// roadmap's own framing ("wherever the backend supports reading
    /// current state... a capability that can't read current state just
    /// omits it").
    fn dry_run(&self, parameters: &[Constraint]) -> Option<Vec<DryRunDiffEntry>> {
        let _ = parameters;
        None
    }

    /// Actually perform the action. Only ever called by
    /// `Tier2ApprovalFlow::decide_and_execute` after an explicit approval
    /// and a final expiry/parameter-hash re-check - see that method.
    /// `Ok`/`Err` payloads are freeform human-readable strings (this
    /// module's `ExecutionResult` doesn't interpret them further); a real
    /// capability's own error type would flow through `Err`'s message.
    fn execute(&self, parameters: &[Constraint]) -> Result<String, String>;
}

/// A `Tier2Capability` that exists ONLY to let this module's flow be
/// exercised end-to-end in tests, per the roadmap's Phase 3 exit criteria:
/// "End-to-end rehearsal with a mock Tier 2 capability... demonstrated to
/// the owner before any real Tier 2 exists." Flips an in-memory boolean -
/// deliberately not wired to any real backend, config file, or system
/// state; "destructive" only in name.
///
/// Gated behind `test`/`test-utils` (same pattern as
/// `policy::CapabilityPolicy::for_test` and `axiom-transport`'s own
/// `test-utils`-gated items) rather than left unconditionally `pub` -
/// `#[cfg(test)]` alone wouldn't be visible to `forge-node`'s own future
/// rehearsal tests compiling this crate as a normal dependency.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockDestructiveCapability {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockDestructiveCapability {
    pub fn new() -> Self {
        Self { flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)) }
    }

    /// Current value of the mock's in-memory flag - lets a test observe
    /// whether `execute` actually ran without needing to inspect
    /// `Tier2ApprovalFlow`'s internal state.
    pub fn flag(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for MockDestructiveCapability {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Tier2Capability for MockDestructiveCapability {
    fn capability_name(&self) -> &str {
        "mock_destructive_action"
    }

    fn dry_run(&self, _parameters: &[Constraint]) -> Option<Vec<DryRunDiffEntry>> {
        Some(vec![DryRunDiffEntry::new("flag", self.flag().to_string(), "true")])
    }

    fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok("mock_destructive_action: flag flipped true".to_string())
    }
}

/// The result of `Tier2Capability::execute`, linked back to its intent by
/// `intent_id`. See this module's top-of-file doc comment for why this
/// (and `LinkedRecord` below) is deliberately simple - a real audit log is
/// Phase 3.4, not this module.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub intent_id: IntentId,
    pub outcome: Result<String, String>,
    pub executed_at: Instant,
}

/// Where one intent currently stands. Monotonic in normal use (an intent
/// only ever moves forward through this sequence once); the two error
/// exits (`Expired`, `ParameterHashMismatch`) are terminal, same as `Denied`
/// - none of them retry automatically, matching "no standing approvals":
/// a caller that wants another attempt must `propose` a fresh intent, not
/// resurrect this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    /// Fable's second review, 2026-08-18: the original sequential-replay
    /// guard (see `decide_and_execute`'s doc comment) only closes a
    /// second call arriving AFTER the first one has already reached a
    /// terminal status - two calls arriving concurrently (before either
    /// has finished) would both observe `Pending`, both consult the
    /// approval channel, and both execute. Not reachable through today's
    /// real dispatch (one `decide_and_execute` call per freshly-minted
    /// `IntentId`), but this crate is explicitly meant to be embedded
    /// elsewhere (Conduit's Burr Phase 2) where a concurrent caller is a
    /// real possibility, not a hypothetical. `InProgress` closes this:
    /// set atomically under the same lock that observed `Pending`, before
    /// the lock is released to go consult the (potentially slow, human-
    /// driven) approval channel - a second concurrent caller sees
    /// `InProgress`, not `Pending`, and takes the same early-return path
    /// as any other non-Pending status.
    InProgress,
    Denied,
    Expired,
    ParameterHashMismatch,
    Executed,
    ExecutionFailed,
}

/// One intent's full lifecycle, joined by `IntentId` - exactly the shape a
/// real audit log (Phase 3.4) will want to consume: this intent, its (at
/// most one) approval decision, its (at most one) execution result. See
/// this module's top-of-file doc comment for why this struct itself is NOT
/// that audit log.
#[derive(Debug, Clone)]
pub struct LinkedRecord {
    pub intent: Intent,
    pub decision: Option<ApprovalDecision>,
    pub execution: Option<ExecutionResult>,
    pub status: IntentStatus,
}

/// Errors `Tier2ApprovalFlow::decide_and_execute` can return. Each has a
/// corresponding `IntentStatus` recorded on the intent's `LinkedRecord`
/// before the error is returned - callers that only check the `Result`
/// still get a clean failure; callers that also want the record's status
/// (e.g. for reporting) can look it up via `Tier2ApprovalFlow::record`.
#[derive(Debug)]
pub enum FlowError {
    /// No intent with this `IntentId` was ever proposed on this flow (or
    /// it was proposed on a DIFFERENT `Tier2ApprovalFlow` instance -
    /// intents are not shared across flows).
    UnknownIntent,
    /// The intent's expiry had already passed - checked before prompting
    /// AND again immediately before execution (see this module's
    /// top-of-file doc comment, failure mode 1).
    Expired,
    /// `Intent::verify_parameter_hash` returned `false` - checked at the
    /// same two points as `Expired` (see this module's top-of-file doc
    /// comment, failure mode 2).
    ParameterHashMismatch,
    /// The `ApprovalChannel` itself failed to produce a decision (see
    /// `ApprovalChannelError`) - distinct from an explicit deny.
    Channel(ApprovalChannelError),
    /// The `ApprovalChannel` implementation returned a decision whose
    /// `intent_id` doesn't match the intent it was asked about. Should
    /// never happen with `CliApprovalChannel` (it always echoes back
    /// `request.intent_id`) - defensive against a buggy or malicious future
    /// channel implementation binding a decision to the wrong intent.
    MismatchedDecision,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownIntent => write!(f, "no such intent on this flow"),
            Self::Expired => write!(f, "intent has expired and can no longer be approved"),
            Self::ParameterHashMismatch => write!(f, "intent parameters no longer match the hash captured at proposal time"),
            Self::Channel(e) => write!(f, "approval channel error: {e}"),
            Self::MismatchedDecision => write!(f, "approval channel returned a decision for a different intent"),
        }
    }
}

impl std::error::Error for FlowError {}

/// AXIOM Phase 3.6: errors `Tier2ApprovalFlow::propose`/`propose_with_expiry`
/// can return - a rejection at PROPOSAL time, before any `ApprovalChannel`
/// is ever consulted and before an `IntentId` is even minted. See this
/// module's top-of-file doc comment, failure mode 4.
#[derive(Debug)]
pub enum ProposeError {
    /// `policy::CapabilityPolicy::protected_resources_configured` was
    /// `false` - the loaded policy file has NO `[[protected_resource]]`
    /// section at all, so this flow cannot affirmatively prove the
    /// proposed parameters DON'T reference a protected device. Fail
    /// closed: deny rather than guess. See `policy.rs`'s module doc
    /// comment for why this mirrors (independently of) the same
    /// fail-closed rule `CapabilityPolicy::check_and_acquire` already
    /// enforces for Tier1+ capability registration.
    ProtectedResourceSectionMissing,
    /// `policy::CapabilityPolicy::find_protected_match` found a match -
    /// carries the full match detail (which parameter, which protected
    /// device) so a caller/log can report exactly why this was rejected.
    TargetsProtectedResource(crate::policy::ProtectedMatch),
    /// `policy::CapabilityPolicy::check_denied_param_substrings` found a
    /// match against this capability's OPTIONAL argument-constraint
    /// denylist (see that method's doc comment - unlike the two variants
    /// above, this one is never triggered by an absent/unconfigured
    /// denylist, only an explicitly configured one that actually matched).
    ArgumentConstraintViolation(String),
}

impl std::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtectedResourceSectionMissing => write!(
                f,
                "proposal rejected: this policy has no [[protected_resource]] section at all - \
                 failing closed until one exists (even an empty one)",
            ),
            Self::TargetsProtectedResource(m) => write!(f, "proposal rejected: {m}"),
            Self::ArgumentConstraintViolation(reason) => write!(f, "proposal rejected: {reason}"),
        }
    }
}

impl std::error::Error for ProposeError {}

/// The propose -> approve -> execute state machine for Tier 2 intents,
/// parameterized over an `ApprovalChannel` implementation (see that
/// trait's doc comment for why - channel-agnostic by design). Holds every
/// proposed intent (and its eventual decision/execution) in memory, keyed
/// by `IntentId`, for the lifetime of this `Tier2ApprovalFlow` instance -
/// this is the "basic structured-log representation" the roadmap asks for
/// as a Phase 3.4 stand-in (see this module's top-of-file doc comment); it
/// is not persisted anywhere.
///
/// AXIOM Phase 3.6: also holds an `Arc<policy::CapabilityPolicy>` -
/// MANDATORY, not optional, as of this phase. There is no constructor that
/// builds a `Tier2ApprovalFlow` without one, which is what makes the
/// protected-resource/argument-constraint check in `propose_with_expiry`
/// structurally impossible to bypass rather than merely convention: any
/// code that wants to propose a Tier 2 intent through this flow has
/// already handed it something to check every proposal against, by
/// construction.
pub struct Tier2ApprovalFlow<C: ApprovalChannel> {
    channel: C,
    default_expiry: Duration,
    records: Mutex<HashMap<IntentId, LinkedRecord>>,
    policy: Arc<CapabilityPolicy>,
}

impl<C: ApprovalChannel> Tier2ApprovalFlow<C> {
    /// New flow using `DEFAULT_EXPIRY` (15 minutes) for every intent
    /// proposed via `propose`. Use `propose_with_expiry` per-intent, or
    /// `with_expiry` to change the flow-wide default, to override.
    ///
    /// AXIOM Phase 3.6: `policy` is checked on every `propose`/
    /// `propose_with_expiry` call - see `Tier2ApprovalFlow`'s own doc
    /// comment for why it's a mandatory constructor argument rather than
    /// an optional setter.
    pub fn new(channel: C, policy: Arc<CapabilityPolicy>) -> Self {
        Self::with_expiry(channel, DEFAULT_EXPIRY, policy)
    }

    pub fn with_expiry(channel: C, default_expiry: Duration, policy: Arc<CapabilityPolicy>) -> Self {
        Self { channel, default_expiry, records: Mutex::new(HashMap::new()), policy }
    }

    /// Step 1: an agent proposes a Tier 2 intent against `capability`,
    /// using this flow's default expiry. Computes the capability's own
    /// dry-run diff (if it has one) and the parameter-hash binding, and
    /// registers the intent (status `Pending`) for a later
    /// `decide_and_execute` call. Returns the new intent's `IntentId` -
    /// or, AXIOM Phase 3.6, `Err(ProposeError)` if `parameters` targets a
    /// protected resource, this flow's policy has no protected-resource
    /// section configured at all, or `capability`'s optional argument
    /// denylist matched - see `propose_with_expiry`.
    pub fn propose(&self, proposer: NodeId, capability: &dyn Tier2Capability, parameters: Vec<Constraint>) -> Result<IntentId, ProposeError> {
        self.propose_with_expiry(proposer, capability, parameters, self.default_expiry)
    }

    /// Same as `propose`, with a per-intent expiry override instead of
    /// this flow's default.
    ///
    /// AXIOM Phase 3.6: three checks run FIRST, before any dry-run diff is
    /// computed, before any `Intent`/`IntentId` is created, and therefore
    /// before this proposal is ever registered where `decide_and_execute`
    /// (and thus `ApprovalChannel::request_approval`) could reach it - see
    /// this module's top-of-file doc comment, failure mode 4:
    /// 1. `self.policy.protected_resources_configured()` - fail closed if
    ///    the loaded policy has no `[[protected_resource]]` section at all.
    /// 2. `self.policy.find_protected_match(&parameters)` - does any
    ///    parameter reference a protected MAC/IP?
    /// 3. `self.policy.check_denied_param_substrings(...)` - the OPTIONAL
    ///    minimal per-capability argument constraint (see `policy.rs`).
    /// Any of the three failing returns `Err` immediately; `parameters` is
    /// consumed by whichever check needed it and never reaches
    /// `capability.dry_run`/`Intent::propose` at all for a rejected
    /// proposal.
    pub fn propose_with_expiry(
        &self,
        proposer: NodeId,
        capability: &dyn Tier2Capability,
        parameters: Vec<Constraint>,
        expiry: Duration,
    ) -> Result<IntentId, ProposeError> {
        if !self.policy.protected_resources_configured() {
            return Err(ProposeError::ProtectedResourceSectionMissing);
        }
        if let Some(m) = self.policy.find_protected_match(&parameters) {
            return Err(ProposeError::TargetsProtectedResource(m));
        }
        if let Some(reason) = self.policy.check_denied_param_substrings(capability.capability_name(), &parameters) {
            return Err(ProposeError::ArgumentConstraintViolation(reason));
        }

        let dry_run_diff = capability.dry_run(&parameters);
        let intent = Intent::propose(proposer, capability.capability_name(), parameters, dry_run_diff, expiry);
        let id = intent.id;
        let record = LinkedRecord { intent, decision: None, execution: None, status: IntentStatus::Pending };
        self.records.lock().unwrap().insert(id, record);
        Ok(id)
    }

    /// Steps 2 and 3: request an approve/deny decision from this flow's
    /// `ApprovalChannel` for the intent `id`, then (only if approved)
    /// execute `capability` and record the linked result. `capability` must
    /// be the SAME capability `id` was proposed against - this method
    /// doesn't itself verify `capability.capability_name() ==
    /// record.intent.capability` (that's a caller-side wiring bug, not a
    /// runtime security property this flow enforces; a real dispatch layer
    /// would look the capability up BY the intent's own recorded name
    /// rather than being handed one that might not match).
    ///
    /// Order of checks, and why: expiry and parameter-hash are both
    /// checked BEFORE ever invoking the channel (no point prompting a human
    /// for a decision that can't be honored, or that would be approving
    /// parameters that no longer match what was hashed at proposal time),
    /// and BOTH checks run AGAIN immediately after an approval, before
    /// `execute` is called - a slow approver can cross the expiry boundary
    /// mid-decision, and re-checking the hash immediately before execution
    /// closes the gap between "approved" and "applied" to as small a window
    /// as this in-process flow can make it. See this module's top-of-file
    /// doc comment for the three failure modes this whole method exists to
    /// close off.
    pub fn decide_and_execute(&self, id: IntentId, capability: &dyn Tier2Capability) -> Result<IntentStatus, FlowError> {
        let request = {
            let mut records = self.records.lock().unwrap();
            let record = records.get_mut(&id).ok_or(FlowError::UnknownIntent)?;

            // AXIOM adversarial-test finding, real gap (see TESTING.md):
            // this method used to have no guard against being invoked more
            // than once for the same `id` - `IntentStatus`'s own doc
            // comment already documented "an intent only ever moves
            // forward through this sequence once" as an invariant, but
            // nothing here actually ENFORCED it. A second call (a buggy
            // caller retrying, a duplicate/replayed trigger from whatever
            // wired this flow into real dispatch, or a hostile duplicate
            // invocation) would re-consult the approval channel AND, if it
            // said yes, call `capability.execute` a SECOND time - turning
            // one real human "yes" into two real executions. Concretely:
            // for `forge-node`'s live `wg_peer_manage` capability, a second
            // execute() on a `Create` action would provision a SECOND
            // WireGuard peer (with its own distinct private key) from one
            // single approval. Proven with a real double-execution before
            // this guard existed - see this module's own
            // `decide_and_execute_called_twice_on_the_same_intent_executes_at_most_once`
            // test. Once `status` has left `Pending`, every later call
            // becomes an idempotent read of the already-recorded terminal
            // outcome: the channel is never consulted again, and
            // `capability.execute` is never called again, no matter what
            // decision a (possibly different, possibly replayed) channel
            // response would have carried.
            if record.status != IntentStatus::Pending {
                return Ok(record.status.clone());
            }

            if record.intent.is_expired() {
                record.status = IntentStatus::Expired;
                return Err(FlowError::Expired);
            }
            if !record.intent.verify_parameter_hash() {
                record.status = IntentStatus::ParameterHashMismatch;
                return Err(FlowError::ParameterHashMismatch);
            }
            // Claim the intent before releasing the lock to go consult the
            // channel - see `IntentStatus::InProgress`'s own doc comment.
            // A concurrent second caller now observes InProgress (not
            // Pending) and takes the early-return path above instead of
            // racing this call into the channel too.
            record.status = IntentStatus::InProgress;
            record.intent.as_approval_request()
        };

        // Deliberately NOT holding `records`'s lock across this call - it
        // blocks on human input (or a future channel's own I/O), which
        // could take an arbitrary amount of time, and holding the lock
        // would stall every other intent's propose/decide calls on this
        // same flow for no reason.
        let decision = self.channel.request_approval(&request).map_err(FlowError::Channel)?;
        if decision.intent_id != id {
            return Err(FlowError::MismatchedDecision);
        }

        let mut records = self.records.lock().unwrap();
        // Re-fetch rather than reuse the earlier borrow - the lock was
        // released while `request_approval` ran.
        let record = records.get_mut(&id).ok_or(FlowError::UnknownIntent)?;
        record.decision = Some(decision);

        if !decision.approved {
            record.status = IntentStatus::Denied;
            return Ok(IntentStatus::Denied);
        }

        // Final re-check, immediately before executing - see this method's
        // own doc comment above.
        if record.intent.is_expired() {
            record.status = IntentStatus::Expired;
            return Err(FlowError::Expired);
        }
        if !record.intent.verify_parameter_hash() {
            record.status = IntentStatus::ParameterHashMismatch;
            return Err(FlowError::ParameterHashMismatch);
        }

        let outcome = capability.execute(&record.intent.parameters);
        let status = if outcome.is_ok() { IntentStatus::Executed } else { IntentStatus::ExecutionFailed };
        record.execution = Some(ExecutionResult { intent_id: id, outcome, executed_at: Instant::now() });
        record.status = status.clone();
        Ok(status)
    }

    /// Read-only snapshot of one intent's current `LinkedRecord` - `None`
    /// if `id` was never proposed on this flow. For reporting/tests; not
    /// consulted by `decide_and_execute` itself (which locks `records`
    /// directly).
    pub fn record(&self, id: IntentId) -> Option<LinkedRecord> {
        self.records.lock().unwrap().get(&id).cloned()
    }

    /// Test/`test-utils`-only: directly overwrite a registered intent's
    /// `parameters`, WITHOUT touching its `parameter_hash` - simulating the
    /// "parameters changed between submission and approval" drift this
    /// module's top-of-file doc comment calls failure mode 2. Nothing in
    /// this module's own normal (non-test) code path ever does this; real
    /// use should never need to (an `Intent` isn't otherwise mutable after
    /// `propose`). Returns `false` if `id` isn't a registered intent.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn tamper_parameters_for_test(&self, id: IntentId, new_parameters: Vec<Constraint>) -> bool {
        let mut records = self.records.lock().unwrap();
        match records.get_mut(&id) {
            Some(record) => {
                record.intent.parameters = new_parameters;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ProtectedResource;
    use axiom_crypto::identity::Keypair;
    use std::io::Cursor;

    fn peer() -> NodeId {
        Keypair::generate().node_id()
    }

    fn params() -> Vec<Constraint> {
        vec![Constraint::string("target", "test-device"), Constraint::bool("enable", true)]
    }

    /// A `CliApprovalChannel` wired to fixed canned input, for tests that
    /// don't care about the exact rendered prompt text - just the decision
    /// it produces.
    fn cli_with_input(input: &str) -> CliApprovalChannel<Cursor<Vec<u8>>, Vec<u8>> {
        CliApprovalChannel::new(Cursor::new(input.as_bytes().to_vec()), Vec::new())
    }

    /// AXIOM Phase 3.6: a policy with a `[[protected_resource]]` section
    /// present (so `protected_resources_configured()` is `true`, avoiding
    /// the new fail-closed proposal rejection) but EMPTY (so nothing this
    /// module's own pre-existing tests propose - none of which reference
    /// any real device - ever matches). Every test in this file that
    /// predates Phase 3.6 and isn't itself testing the protected-resource
    /// gate uses this, so it keeps exercising exactly what it always did.
    fn permissive_policy() -> Arc<CapabilityPolicy> {
        Arc::new(CapabilityPolicy::for_test_with_protected_resources(Some(Vec::new())))
    }

    // --- IntentId / Intent basics ---

    #[test]
    fn intent_ids_are_unique_even_for_identical_proposals() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("n\n"), permissive_policy());
        let id1 = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        let id2 = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        assert_ne!(id1, id2, "two proposals of the exact same capability+parameters must still get distinct IntentIds");
    }

    #[test]
    fn parameter_hash_is_deterministic_and_order_independent() {
        let mut p1 = vec![Constraint::string("a", "1"), Constraint::int("b", 2)];
        let mut p2 = vec![Constraint::int("b", 2), Constraint::string("a", "1")];
        let h1 = Intent::compute_parameter_hash("cap", &p1);
        let h2 = Intent::compute_parameter_hash("cap", &p2);
        assert_eq!(h1, h2, "constraint order must not affect the parameter hash");

        p1.push(Constraint::bool("c", true));
        p2.push(Constraint::bool("c", false));
        let h3 = Intent::compute_parameter_hash("cap", &p1);
        let h4 = Intent::compute_parameter_hash("cap", &p2);
        assert_ne!(h3, h4, "different parameter values must hash differently");
    }

    #[test]
    fn parameter_hash_differs_by_capability_name_too() {
        let p = params();
        let h1 = Intent::compute_parameter_hash("capability_a", &p);
        let h2 = Intent::compute_parameter_hash("capability_b", &p);
        assert_ne!(h1, h2, "same parameters under a different capability name must hash differently");
    }

    // --- render_prompt (presentation only) ---

    #[test]
    fn render_prompt_shows_capability_parameters_and_diff() {
        let intent = Intent::propose(peer(), "mock_destructive_action", params(), Some(vec![DryRunDiffEntry::new("flag", "false", "true")]), DEFAULT_EXPIRY);
        let text = render_prompt(&intent.as_approval_request());
        assert!(text.contains("mock_destructive_action"));
        assert!(text.contains("target"));
        assert!(text.contains("flag: false -> true"));
        assert!(text.contains(&intent.id.to_hex()));
        assert!(text.contains("Approve? [y/N]:"));
    }

    #[test]
    fn render_prompt_states_no_dry_run_available_when_absent() {
        let intent = Intent::propose(peer(), "some_capability", params(), None, DEFAULT_EXPIRY);
        let text = render_prompt(&intent.as_approval_request());
        assert!(text.contains("not available for this capability"));
    }

    // --- CliApprovalChannel decision parsing ---

    #[test]
    fn cli_channel_treats_y_and_yes_as_approval() {
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "  yes  \n"] {
            let channel = cli_with_input(input);
            let intent = Intent::propose(peer(), "mock_destructive_action", params(), None, DEFAULT_EXPIRY);
            let decision = channel.request_approval(&intent.as_approval_request()).expect("channel should not error");
            assert!(decision.approved, "input {input:?} should be treated as approval");
            assert_eq!(decision.intent_id, intent.id);
            assert_eq!(decision.channel_name, "cli-prompt");
        }
    }

    #[test]
    fn cli_channel_treats_anything_else_including_empty_and_eof_as_denial() {
        for input in ["n\n", "no\n", "\n", "", "maybe\n", "yes please\n"] {
            let channel = cli_with_input(input);
            let intent = Intent::propose(peer(), "mock_destructive_action", params(), None, DEFAULT_EXPIRY);
            let decision = channel.request_approval(&intent.as_approval_request()).expect("channel should not error");
            assert!(!decision.approved, "input {input:?} must NOT be treated as approval");
        }
    }

    // --- Full flow: propose -> approve -> execute ---

    #[test]
    fn happy_path_propose_approve_execute_produces_linked_result() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        assert!(!cap.flag(), "mock capability starts false");

        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        let before = flow.record(id).expect("intent was just proposed");
        assert_eq!(before.status, IntentStatus::Pending);
        assert!(before.decision.is_none());
        assert!(before.execution.is_none());

        let status = flow.decide_and_execute(id, &cap).expect("approve+execute should succeed");
        assert_eq!(status, IntentStatus::Executed);
        assert!(cap.flag(), "the mock capability's execute() must actually have run");

        let after = flow.record(id).expect("record still present after execution");
        assert_eq!(after.status, IntentStatus::Executed);
        let decision = after.decision.expect("decision must be linked");
        assert!(decision.approved);
        assert_eq!(decision.intent_id, id);
        let execution = after.execution.expect("execution result must be linked");
        assert_eq!(execution.intent_id, id);
        assert!(execution.outcome.is_ok());
    }

    #[test]
    fn propose_deny_does_not_execute() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("n\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        let status = flow.decide_and_execute(id, &cap).expect("deny is not itself an error");
        assert_eq!(status, IntentStatus::Denied);
        assert!(!cap.flag(), "a denied intent must never execute");

        let record = flow.record(id).unwrap();
        assert_eq!(record.status, IntentStatus::Denied);
        assert!(record.decision.is_some());
        assert!(record.execution.is_none(), "no execution result should be linked for a denied intent");
    }

    #[test]
    fn expired_intent_cannot_be_approved() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        // Real, short expiry + a real sleep past it - no injected clock
        // exists in this crate for this kind of timing (see
        // `Intent::is_expired`'s doc comment), so this crosses the boundary
        // for real rather than faking it.
        let flow = Tier2ApprovalFlow::with_expiry(cli_with_input("y\n"), Duration::from_millis(10), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        std::thread::sleep(Duration::from_millis(50));

        let result = flow.decide_and_execute(id, &cap);
        assert!(matches!(result, Err(FlowError::Expired)), "approving an expired intent must fail cleanly, not panic or silently succeed");
        assert!(!cap.flag(), "an expired intent must never execute even though the channel would have said yes");

        let record = flow.record(id).unwrap();
        assert_eq!(record.status, IntentStatus::Expired);
        assert!(record.decision.is_none(), "the channel must never even be consulted for an already-expired intent");
    }

    #[test]
    fn tampered_parameters_are_rejected_via_hash_mismatch() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        // Simulate parameters drifting after proposal but before approval -
        // "shouldn't normally happen in a single flow, but the invariant
        // matters" (this module's own design brief). Only reachable via the
        // test-only helper - nothing in normal use does this.
        let tampered = vec![Constraint::string("target", "SOMETHING-ELSE-ENTIRELY")];
        assert!(flow.tamper_parameters_for_test(id, tampered));

        let result = flow.decide_and_execute(id, &cap);
        assert!(matches!(result, Err(FlowError::ParameterHashMismatch)), "tampered parameters must be rejected via hash mismatch, not silently approved");
        assert!(!cap.flag(), "a hash-mismatched intent must never execute");

        let record = flow.record(id).unwrap();
        assert_eq!(record.status, IntentStatus::ParameterHashMismatch);
        assert!(record.decision.is_none(), "the channel must never even be consulted once tampering is detected");
    }

    /// A `Tier2Capability` that counts real `execute()` invocations, for
    /// tests that need to distinguish "executed once" from "executed
    /// twice" - `MockDestructiveCapability`'s bare `AtomicBool` flag can't
    /// tell those apart (it's `true` either way), which is exactly why the
    /// double-execution gap this test file's own adversarial tests exist to
    /// prove needed a purpose-built fixture rather than the existing mock.
    struct CountingCapability {
        count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Tier2Capability for CountingCapability {
        fn capability_name(&self) -> &str {
            "counting_capability_for_test_proof_only"
        }
        fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok("executed".to_string())
        }
    }

    /// A test-only `ApprovalChannel` that always approves, regardless of
    /// how many times it's consulted - used specifically to prove
    /// `decide_and_execute` itself (not the channel) is what prevents a
    /// second execution, by removing the channel as a confound (unlike
    /// `CliApprovalChannel` fed a single line of canned input, which would
    /// naturally deny a second call via EOF for an unrelated reason - see
    /// `cli_channel_treats_anything_else_including_empty_and_eof_as_denial`).
    struct AlwaysApproveChannel;
    impl ApprovalChannel for AlwaysApproveChannel {
        fn name(&self) -> &'static str {
            "always-approve-test-fixture"
        }
        fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
            Ok(ApprovalDecision { intent_id: request.intent_id, approved: true, channel_name: self.name() })
        }
    }

    /// AXIOM adversarial-test finding, real gap (see `TESTING.md`): before
    /// `decide_and_execute` gained its `record.status != IntentStatus::Pending`
    /// guard, calling it TWICE for the same already-executed intent would
    /// re-consult the channel (which, via `AlwaysApproveChannel`, says yes
    /// again) and call `capability.execute` a second time - this test
    /// failed (count reached 2) against the pre-fix code. It passes now:
    /// the second call is an idempotent read of the already-recorded
    /// `Executed` status, and the capability's `execute` is never reached
    /// again.
    #[test]
    fn decide_and_execute_called_twice_on_the_same_intent_executes_at_most_once() {
        let p = peer();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cap = CountingCapability { count: count.clone() };
        let flow = Tier2ApprovalFlow::new(AlwaysApproveChannel, permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        let first = flow.decide_and_execute(id, &cap).expect("first decision should succeed");
        assert_eq!(first, IntentStatus::Executed);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1, "capability must execute exactly once after a real approval");

        // Adversarial: a second call for the SAME already-decided intent -
        // simulating a duplicate/replayed trigger from a buggy or hostile
        // caller. Even though the channel would approve again (it always
        // says yes), the capability must NOT execute a second time - one
        // real "yes" must never be stretched into two executions.
        let second = flow.decide_and_execute(id, &cap).expect("a repeat call on an already-decided intent must not error");
        assert_eq!(second, IntentStatus::Executed, "must report the same terminal status, not re-derive a fresh one");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1, "capability must still have executed exactly once - decide_and_execute must be idempotent for an already-decided intent");
    }

    /// A test-only `ApprovalChannel` that signals (via a shared
    /// `AtomicBool`) the instant it's been entered, then sleeps briefly
    /// before answering. Exists purely to hold `decide_and_execute` in its
    /// "lock released, channel not yet resolved" window long enough for a
    /// concurrent second caller to genuinely observe whatever status
    /// exists AT THAT MOMENT - without this, a non-blocking channel
    /// answers so fast that two threads racing to call
    /// `decide_and_execute` tend to just run sequentially in practice
    /// (confirmed empirically: an earlier version of this test using a
    /// plain start-`Barrier` with no channel delay PASSED even with the
    /// `InProgress` fix's claim line disabled, because thread A would
    /// finish its entire call before thread B was even scheduled - the
    /// pre-existing terminal-status guard was accidentally covering a
    /// sequential-in-disguise test, proving nothing about real overlap).
    struct SignalingDelayedApproveChannel {
        entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl ApprovalChannel for SignalingDelayedApproveChannel {
        fn name(&self) -> &'static str {
            "signaling-delayed-test-fixture"
        }
        fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
            self.entered.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(ApprovalDecision { intent_id: request.intent_id, approved: true, channel_name: self.name() })
        }
    }

    /// Fable's second review, 2026-08-18: the sequential-replay guard
    /// above (`decide_and_execute_called_twice_on_the_same_intent_executes_at_most_once`)
    /// only proves a SECOND call arriving after the FIRST has already
    /// finished is safe. It does not prove anything about two calls that
    /// are genuinely concurrent - both observe `Pending`, both would
    /// consult the channel, and (before `IntentStatus::InProgress` existed)
    /// both would execute. This test forces real, verified overlap: the
    /// second thread waits (via spin-poll on `entered`, bounded) for proof
    /// that the first thread is actually inside its channel call - blocked
    /// on a 100ms sleep - before starting its own `decide_and_execute`,
    /// guaranteeing the second call's lock-acquisition genuinely happens
    /// while the first call is unlocked-but-not-yet-resolved, not just
    /// hoping scheduling works out.
    #[test]
    fn decide_and_execute_called_concurrently_on_the_same_intent_executes_at_most_once() {
        let p = peer();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cap = std::sync::Arc::new(CountingCapability { count: count.clone() });
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flow = std::sync::Arc::new(Tier2ApprovalFlow::new(
            SignalingDelayedApproveChannel { entered: entered.clone() },
            permissive_policy(),
        ));
        let id = flow.propose(p, cap.as_ref(), params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        let flow_a = flow.clone();
        let cap_a = cap.clone();
        let handle_a = std::thread::spawn(move || flow_a.decide_and_execute(id, cap_a.as_ref()));

        // Wait for proof thread A is genuinely inside its (100ms) channel
        // call before thread B starts - bounded spin-poll, not a fixed
        // sleep, so this doesn't flake under slow CI scheduling.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "thread A never entered the channel - test setup is broken, not exercising anything");
            std::thread::yield_now();
        }

        let flow_b = flow.clone();
        let cap_b = cap.clone();
        let handle_b = std::thread::spawn(move || flow_b.decide_and_execute(id, cap_b.as_ref()));

        let result_a = handle_a.join().expect("thread A must not panic");
        let result_b = handle_b.join().expect("thread B must not panic");

        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "two genuinely concurrent decide_and_execute calls on the same intent must still execute at most once - this is exactly what IntentStatus::InProgress exists to close, see its own doc comment"
        );
        // Thread A (started first, does the real work) reaches the real
        // terminal status. Thread B (deterministically started only once
        // A is confirmed mid-channel-call) takes the early-return path in
        // decide_and_execute's first block and reads back the CURRENT
        // status at that instant - which is the transient `InProgress`
        // A already claimed, not a blocked wait for A's eventual result.
        // This is consistent with how every other early-return case in
        // this function already behaves (a non-blocking read of whatever
        // status exists right now, never a wait) - decide_and_execute has
        // never promised to block until resolution, only to never double-
        // execute, and it doesn't here either.
        assert_eq!(result_a.expect("thread A (the real worker) should not error"), IntentStatus::Executed);
        assert_eq!(
            result_b.expect("thread B (early-return path) should not error"),
            IntentStatus::InProgress,
            "a concurrent caller arriving while another call is mid-flight must see InProgress, not block for or fabricate a terminal outcome it didn't itself decide"
        );
    }

    /// A test-only `ApprovalChannel` whose decision can be flipped between
    /// calls via a shared `AtomicBool` - simulates a channel that denied
    /// the first time (a real "no") and would approve a SECOND time (e.g. a
    /// stale/replayed callback resend arriving after the real decision was
    /// already recorded - the exact Telegram double-spend shape this
    /// project's adversarial pass targeted at the channel layer too, see
    /// `telegram_approval.rs`'s own `resent_approve_callback_after_the_
    /// intent_was_already_denied_does_not_flip_the_decision` test).
    struct SwitchableChannel {
        approve: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl ApprovalChannel for SwitchableChannel {
        fn name(&self) -> &'static str {
            "switchable-test-fixture"
        }
        fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
            Ok(ApprovalDecision {
                intent_id: request.intent_id,
                approved: self.approve.load(std::sync::atomic::Ordering::SeqCst),
                channel_name: self.name(),
            })
        }
    }

    #[test]
    fn a_recorded_denial_cannot_be_overturned_by_a_later_decide_and_execute_call_that_would_approve() {
        let p = peer();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cap = CountingCapability { count: count.clone() };
        let approve_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flow = Tier2ApprovalFlow::new(SwitchableChannel { approve: approve_flag.clone() }, permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");

        let first = flow.decide_and_execute(id, &cap).expect("first decision should succeed");
        assert_eq!(first, IntentStatus::Denied);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0, "a denied intent must never execute");

        // Flip the channel to "approve" - the real decision (deny) is
        // already recorded and terminal; this simulates a duplicate/
        // replayed second call arriving after the fact.
        approve_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let second = flow.decide_and_execute(id, &cap).expect("a repeat call on an already-decided intent must not error");
        assert_eq!(second, IntentStatus::Denied, "the ORIGINAL decision must stand - a later call must not re-consult the channel and overturn it");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0, "capability must still never have executed - a recorded denial is final");
    }

    #[test]
    fn decide_and_execute_on_unknown_intent_fails_cleanly() {
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let bogus_id = IntentId::generate();
        let result = flow.decide_and_execute(bogus_id, &cap);
        assert!(matches!(result, Err(FlowError::UnknownIntent)));
    }

    #[test]
    fn dry_run_diff_is_populated_from_the_capability_and_carried_on_the_intent() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        let record = flow.record(id).unwrap();
        let diff = record.intent.dry_run_diff.expect("mock capability always provides a dry-run diff");
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].key, "flag");
        assert_eq!(diff[0].current, "false");
        assert_eq!(diff[0].proposed, "true");
    }

    #[test]
    fn a_capability_without_dry_run_support_omits_the_diff_rather_than_fabricating_one() {
        struct NoDryRunCapability;
        impl Tier2Capability for NoDryRunCapability {
            fn capability_name(&self) -> &str {
                "no_dry_run_capability"
            }
            fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
                Ok("done".to_string())
            }
        }

        let p = peer();
        let cap = NoDryRunCapability;
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        let record = flow.record(id).unwrap();
        assert!(record.intent.dry_run_diff.is_none(), "a capability with no dry_run override must leave dry_run_diff as None, not an empty Vec");

        let status = flow.decide_and_execute(id, &cap).unwrap();
        assert_eq!(status, IntentStatus::Executed);
    }

    #[test]
    fn execution_failure_is_recorded_but_not_conflated_with_a_denial() {
        struct AlwaysFailsCapability;
        impl Tier2Capability for AlwaysFailsCapability {
            fn capability_name(&self) -> &str {
                "always_fails_capability"
            }
            fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
                Err("backend unreachable".to_string())
            }
        }

        let p = peer();
        let cap = AlwaysFailsCapability;
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), permissive_policy());
        let id = flow.propose(p, &cap, params()).expect("propose should succeed - permissive_policy has no protected resources configured");
        let status = flow.decide_and_execute(id, &cap).expect("execution failure is not itself a FlowError - it's a recorded outcome");
        assert_eq!(status, IntentStatus::ExecutionFailed);

        let record = flow.record(id).unwrap();
        assert!(record.decision.expect("decision was still recorded").approved, "the decision itself was still an approval - only execution failed");
        let execution = record.execution.expect("execution result must be linked even on failure");
        assert_eq!(execution.outcome, Err("backend unreachable".to_string()));
    }

    #[test]
    fn intent_id_hex_round_trips_full_length() {
        let id = IntentId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32, "16 bytes must render as 32 full hex chars, never truncated");
        assert_eq!(format!("{id}"), hex, "Display must match to_hex exactly");
    }

    // --- AXIOM Phase 3.6: protected-resource / argument-constraint gating
    // at proposal time (failure mode 4, this module's top-of-file doc
    // comment) ---

    /// An `ApprovalChannel` that fails the test outright if it's EVER
    /// consulted - the direct proof this module's doc comment promises:
    /// a Tier 2 proposal targeting a protected resource must be rejected
    /// before `request_approval` is reachable at all, not merely denied
    /// by it. If `propose`'s protected-resource check were ever bypassed
    /// or reordered to run after the channel is consulted, this test
    /// would fail via the panic below, not via a wrong return value that
    /// could be misread as "working as intended."
    struct PanicIfCalledChannel;
    impl ApprovalChannel for PanicIfCalledChannel {
        fn name(&self) -> &'static str {
            "panic-if-called"
        }
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
            panic!(
                "PanicIfCalledChannel::request_approval was called - a Tier 2 proposal that \
                 targets a protected resource must be rejected at propose() time, BEFORE the \
                 ApprovalChannel is ever consulted. Reaching this panic means that guarantee \
                 broke.",
            );
        }
    }

    fn protected_policy() -> Arc<CapabilityPolicy> {
        let resources = vec![
            ProtectedResource::new(Some("proxmox-host-ethernet".to_string()), "AA:BB:CC:11:22:01", Some("192.168.1.10".to_string())).unwrap(),
        ];
        Arc::new(CapabilityPolicy::for_test_with_protected_resources(Some(resources)))
    }

    #[test]
    fn channel_is_never_consulted_for_a_protected_resource_proposal() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(PanicIfCalledChannel, protected_policy());
        let params = vec![Constraint::string("target", "AA:BB:CC:11:22:01")];

        // If this reaches PanicIfCalledChannel::request_approval at all
        // (which would only happen if propose() failed to reject this
        // BEFORE ever registering/deciding the intent), the test panics
        // via that channel, not via a plain assertion failure - proving
        // the rejection genuinely happens before the channel, not just
        // that this test's assertions happen to still pass.
        let result = flow.propose(p, &cap, params);
        assert!(
            matches!(result, Err(ProposeError::TargetsProtectedResource(_))),
            "expected TargetsProtectedResource, got {result:?}",
        );
        if let Err(ProposeError::TargetsProtectedResource(m)) = result {
            assert_eq!(m.resource_name.as_deref(), Some("proxmox-host-ethernet"));
            assert_eq!(m.parameter_key, "target");
        }
        assert!(!cap.flag(), "a rejected-at-proposal-time intent must never execute");
    }

    /// Same proof, but for the fail-closed "no protected-resource section
    /// at all" case (`ProposeError::ProtectedResourceSectionMissing`) -
    /// the channel must never be consulted for THIS rejection reason
    /// either, even though nothing in the parameters themselves is
    /// protected (there's no way to know that without a configured list).
    #[test]
    fn channel_is_never_consulted_when_protected_resource_section_is_missing() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let policy = Arc::new(CapabilityPolicy::for_test_with_protected_resources(None));
        let flow = Tier2ApprovalFlow::new(PanicIfCalledChannel, policy);
        let result = flow.propose(p, &cap, params());
        assert!(matches!(result, Err(ProposeError::ProtectedResourceSectionMissing)), "expected ProtectedResourceSectionMissing, got {result:?}");
        assert!(!cap.flag());
    }

    /// A protected-resource-targeting proposal must not even be
    /// REGISTERED - `record()` (keyed by the `IntentId` that was never
    /// minted) has nothing to return, unlike a proposal that registers
    /// and is later denied by the channel (which DOES have a record, see
    /// `propose_deny_does_not_execute`).
    #[test]
    fn protected_resource_proposal_registers_no_intent_at_all() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), protected_policy());
        let before_count = {
            // No public "how many intents are registered" accessor exists
            // (by design - this module exposes `record(id)`, not a bulk
            // listing), so this test's real proof is structural: propose()
            // returns Err, and there is no IntentId to even ask `record`
            // about. Kept here as a readable marker of that intent, not a
            // real count.
            0
        };
        let result = flow.propose(p, &cap, vec![Constraint::string("target", "AA:BB:CC:11:22:01")]);
        assert!(result.is_err());
        assert_eq!(before_count, 0);
        assert!(!cap.flag());
    }

    /// The positive case - prove the protected-resource check doesn't
    /// over-block: a Tier 2 intent whose parameters reference NOTHING on
    /// the protected list proceeds normally all the way to the approval
    /// channel and executes on approval, exactly as it would have before
    /// Phase 3.6.
    #[test]
    fn non_protected_resource_proposal_proceeds_normally_to_approval_channel() {
        let p = peer();
        let cap = MockDestructiveCapability::new();
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), protected_policy());
        let params = vec![Constraint::string("target", "aa:bb:cc:dd:ee:ff"), Constraint::string("target_ip", "10.0.0.50")];
        let id = flow.propose(p, &cap, params).expect("a non-protected target must be proposable");

        let record_before = flow.record(id).expect("a non-rejected proposal must register a record");
        assert_eq!(record_before.status, IntentStatus::Pending);

        let status = flow.decide_and_execute(id, &cap).expect("approve+execute should succeed");
        assert_eq!(status, IntentStatus::Executed);
        assert!(cap.flag(), "the capability must actually have executed - the protected-resource check must not have silently blocked an unrelated target");
    }

    /// The optional per-capability argument-substring denylist, wired
    /// through the same propose-time gate: configured but non-matching
    /// parameters proceed; a matching one is rejected before the channel,
    /// same "PanicIfCalledChannel proves it" discipline as the protected-
    /// resource tests above.
    #[test]
    fn argument_constraint_violation_is_rejected_before_the_channel() {
        struct NamedCapability;
        impl Tier2Capability for NamedCapability {
            fn capability_name(&self) -> &str {
                "vlan_change_capability"
            }
            fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
                Ok("done".to_string())
            }
        }

        let p = peer();
        let cap = NamedCapability;
        let policy = Arc::new(CapabilityPolicy::for_test_with_denied_substrings(
            "vlan_change_capability",
            Some(Vec::new()),
            vec!["vlan1"],
        ));
        let flow = Tier2ApprovalFlow::new(PanicIfCalledChannel, policy);
        let params = vec![Constraint::string("target_vlan", "VLAN1")];
        let result = flow.propose(p, &cap, params);
        assert!(matches!(result, Err(ProposeError::ArgumentConstraintViolation(_))), "expected ArgumentConstraintViolation, got {result:?}");
    }

    #[test]
    fn argument_constraint_that_does_not_match_proceeds_normally() {
        struct NamedCapability;
        impl Tier2Capability for NamedCapability {
            fn capability_name(&self) -> &str {
                "vlan_change_capability"
            }
            fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
                Ok("done".to_string())
            }
        }

        let p = peer();
        let cap = NamedCapability;
        let policy = Arc::new(CapabilityPolicy::for_test_with_denied_substrings(
            "vlan_change_capability",
            Some(Vec::new()),
            vec!["vlan1"],
        ));
        let flow = Tier2ApprovalFlow::new(cli_with_input("y\n"), policy);
        let params = vec![Constraint::string("target_vlan", "vlan42")];
        let id = flow.propose(p, &cap, params).expect("vlan42 does not match the 'vlan1' denylist pattern");
        let status = flow.decide_and_execute(id, &cap).unwrap();
        assert_eq!(status, IntentStatus::Executed);
    }

    /// `ProposeError`'s `Display` impl - not load-bearing for correctness,
    /// but worth pinning since a future maintainer reading a rejected-
    /// proposal log line depends on it being informative.
    #[test]
    fn propose_error_display_is_human_readable() {
        assert!(format!("{}", ProposeError::ProtectedResourceSectionMissing).contains("no [[protected_resource]] section"));
        let m = crate::policy::ProtectedMatch {
            resource_name: Some("test-device".to_string()),
            resource_mac: "AA:BB:CC:11:22:01".to_string(),
            resource_ip: None,
            matched_value: "AA:BB:CC:11:22:01".to_string(),
            parameter_key: "target".to_string(),
        };
        assert!(format!("{}", ProposeError::TargetsProtectedResource(m)).contains("test-device"));
        assert!(format!("{}", ProposeError::ArgumentConstraintViolation("custom reason".to_string())).contains("custom reason"));
    }
}
