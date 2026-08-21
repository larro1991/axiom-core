//! `axiom-gateway`: AXIOM's capability-gateway policy engine.
//!
//! AXIOM Phase 3.0 - relocated here (mechanically, no behavior change) from
//! `forge-node/src/policy.rs`, where it shipped as Phase 1.1. Standalone
//! crate with zero dependency on AXIOM's own discovery/transport/frame
//! code, so it can be embedded by other consumers later (Conduit's Burr
//! Phase 2 is the intended second consumer) - see the repo's DECISIONS.md,
//! "ecosystem positioning" section.
//!
//! AXIOM Phase 3.1/3.2 (2026-08-06): the tier MODEL landed - schema v2,
//! mandatory per-capability `tier`, fail-closed registration for anything
//! untiered (see `policy.rs`'s module doc comment and `Tier`). Owner
//! confirmations (tier definitions + approval channel) were ratified in
//! DECISIONS.md, unblocking this.
//!
//! AXIOM Phase 3.3 (2026-08-06): Tier 2's propose/approve/execute flow
//! landed (`approval` module) - the `ApprovalChannel` trait, its
//! ratified-primary CLI-prompt implementation, and the intent/decision/
//! execution state machine intents move through. See `approval`'s own
//! module doc comment for the full contract and exactly what's still out
//! of scope (no real Tier 2 capability exists yet - this is rehearsed
//! against `approval::MockDestructiveCapability`, test/`test-utils`-only -
//! and Phase 3.4's real hash-chained audit log is a separate follow-up).
//!
//! AXIOM Phase 3.4 (2026-08-06): the append-only, hash-chained,
//! tamper-evident audit log landed (`audit` module) - Tier 1's mandatory
//! full-context audit logging (direct `AuditLog::log_tier1_call`) and
//! Tier 2's `approval::LinkedRecord` -> real audit entry wiring
//! (`AuditLog::log_tier2_linked_record`), plus `forge-node verify-audit`.
//! See `audit`'s own module doc comment for the full schema/chain/
//! redaction/storage contract and exactly why this log is reachable ONLY
//! via this crate's own API or that CLI - never as a capability.
//!
//! AXIOM Phase 3.6 (2026-08-06): the ratified protected-resource list
//! (`DECISIONS.md`'s "Protected-resource list" section) and its two
//! enforcement points land - `policy::CapabilityPolicy`'s new
//! `[[protected_resource]]` schema section (mandatory-if-any-Tier1+-
//! capability-exists, fail-closed if absent entirely - the same
//! registration-gate mechanism `try_load` already used for a missing
//! `tier`) and `approval::Tier2ApprovalFlow::propose`/`propose_with_expiry`
//! now REQUIRING an `Arc<CapabilityPolicy>` and checking every proposal's
//! parameters against it before an `IntentId` is ever minted or the
//! `ApprovalChannel` is ever consulted. Also lands the roadmap's minimal
//! optional per-capability argument-substring denylist (`policy.rs`'s
//! `RawCapabilityEntry::denied_param_substrings`). See `policy.rs`'s own
//! module doc comment for the full two-enforcement-point design and why
//! there are two.
//!
//! Still explicitly OUT of this crate (as of Phase 3.7): wiring `AuditLog`/
//! `log_tier1_call` OR `Tier2ApprovalFlow` into `forge-node`'s actual
//! real-time capability-dispatch path (this phase's protected-resource
//! check is fully mandatory/live wherever it CAN attach today -
//! `CapabilityPolicy::check_and_acquire`, the one central gate every real
//! capability call already passes through in `dispatch_intent` - but
//! `Tier2ApprovalFlow`/`AuditLog` themselves remain standalone,
//! independently-testable pieces not yet reachable from `forge-node`'s
//! real dispatch; see `forge-node/src/capability_isolation.rs` for the
//! enforced proof of that boundary).
//!
//! AXIOM Phase 3.7 (2026-08-06): untrusted-content handling / confused-
//! deputy defense (`sanitize` module) - length-capping, control-character/
//! terminal-escape-sequence stripping (flagged, never silently hidden),
//! and a structural (JSON-envelope, not text-prefix) "this is data, not
//! instructions" wrapper for any backend-returned content a capability
//! forwards outward. `forge-node::network::fetch_network_clients` (the
//! Omada-via-UAI bridge, this codebase's one real capability that ingests
//! untrusted external data - device hostnames/SSIDs/etc, attacker-
//! choosable by anything on the LAN) is the first, and so far only,
//! caller. See `sanitize`'s own module doc comment for the full threat
//! model and design rationale, and `SECURITY.md`'s "Untrusted-content
//! handling" section for the deployed-system writeup.
//!
//! AXIOM Phase 3.8 (2026-08-06): the capability-gateway roadmap's final
//! Phase 3 sub-item - the kill switch and allowlist expiry, closing out
//! this doc comment's own "still explicitly OUT of this crate" note above
//! (which named the kill switch by name as future work).
//!
//! - **Kill switch**: `policy::CapabilityPolicy::freeze`/`unfreeze`/
//!   `is_frozen`/`suspend_peer`/`unsuspend_peer`/`is_suspended`/
//!   `suspended_peers` - local-only, runtime-mutable state (NOT the
//!   on-disk policy file, which this crate still only ever reads once at
//!   startup), checked inside `check_and_acquire` itself so a mutation
//!   takes effect on the very next in-flight request boundary, no
//!   restart. Two new `PolicyOutcome` variants (`Suspended`/`Frozen`)
//!   report it distinctly from a plain allowlist miss. Reachable ONLY via
//!   `forge-node`'s local admin control socket
//!   (`forge-node/src/control.rs`) - never as a capability; see
//!   `policy`'s own Phase 3.8 doc-comment section and
//!   `forge-node/src/capability_isolation.rs`'s companion tests for the
//!   full design and the enforced non-capability proof.
//! - **Allowlist expiry**: an OPTIONAL, per-peer, unix-seconds `expires`
//!   on `[capability.*].allowed_peers` entries - backward compatible with
//!   every already-deployed policy file (a bare hex string is still a
//!   valid, permanent entry). Checked live against the real wall clock,
//!   not filtered once at load time - see `policy`'s own Phase 3.8
//!   doc-comment section.
//! - `audit::AuditLog::log_admin_event`: the kill switch's own freeze/
//!   unfreeze/suspend/unsuspend events are audited through this crate's
//!   existing `AuditLog` API, called directly by `forge-node/src/control.rs`
//!   - see `audit`'s own "kill-switch/admin events" doc-comment section.
//!
//! AXIOM Tier 2 (2026-08-10): `Tier2ApprovalFlow`/`AuditLog::
//! log_tier2_linked_record` are now wired into `forge-node`'s real
//! capability dispatch - the "still explicitly OUT of this crate" note
//! above (Phase 3.7) is superseded for this specific path. The new
//! `ApprovalChannel` implementation (Telegram, via PM's existing bot -
//! `forge-node/src/telegram_approval.rs`) lives in `forge-node`, not here:
//! it needs a full async HTTP client and a background long-polling task,
//! which would widen this crate's own tokio dependency beyond the `sync`
//! feature it deliberately limits itself to for embeddability (see this
//! crate's description above) - nothing in `approval.rs` itself changed to
//! support it, which is exactly the point of `ApprovalChannel` being a
//! trait (`DECISIONS.md`, "Tier-2 approval channel"). `forge-node/src/
//! network.rs`'s `wg_peer_manage` is the first real (non-mock) `Tier2Capability`.
//! `log_tier1_call` remains NOT wired into real dispatch - this change is
//! Tier 2-only; see `forge-node/src/capability_isolation.rs`'s narrowed
//! `capability_dispatch_reaches_the_audit_log_only_via_log_tier2_linked_record`
//! for the enforced proof of exactly that boundary.

pub mod approval;
pub mod audit;
pub mod policy;
pub mod sanitize;

pub use approval::{
    ApprovalChannel, ApprovalChannelError, ApprovalDecision, ApprovalRequest, CliApprovalChannel,
    DryRunDiffEntry, ExecutionResult, FlowError, Intent, IntentId, IntentStatus, LinkedRecord,
    ProposeError, Tier2ApprovalFlow, Tier2Capability, DEFAULT_EXPIRY,
};
#[cfg(any(test, feature = "test-utils"))]
pub use approval::MockDestructiveCapability;
pub use audit::{
    is_sensitive_param_key, verify_chain, AuditChainBreak, AuditDecision, AuditEntry, AuditLog,
    AuditLogError, AuditOutcome, AuditParam, ChainState, GENESIS_HASH,
};
pub use policy::{CapabilityPolicy, PolicyOutcome, ProtectedMatch, ProtectedResource, Tier};
pub use sanitize::{
    sanitize_and_wrap_untrusted_json, sanitize_json_strings, sanitize_str, wrap_untrusted_json,
    SanitizedString, MAX_UNTRUSTED_STRING_CHARS, UNTRUSTED_ENVELOPE_MARKER,
};
