//! AXIOM Phase 3.5: automated, recurring regression check for the
//! roadmap's prime directive 2 (verbatim): "The management plane stays
//! outside AXIOM's reach. AXIOM must never hold a capability that can
//! modify Tailscale, SSH access, its own policy file, its own audit log,
//! or the approval mechanism."
//!
//! Compiled ONLY in test builds - see `#[cfg(test)] mod capability_isolation;`
//! in `main.rs`. Adds zero surface/cost to the production binary; this
//! entire module (including the `include_str!` calls that embed real
//! source/config files into the test binary) simply doesn't exist outside
//! `cargo test`.
//!
//! # What this crate's actual architecture is (read this before trusting
//! any claim below)
//!
//! There is NO `Capability` trait/enum that every capability implements.
//! `axiom-gateway::approval::Tier2Capability` (Phase 3.3's Tier-2 propose/
//! approve/execute abstraction) WAS wired to nothing in real dispatch as of
//! Phase 3.7 - that changed with AXIOM Tier 2 (the Telegram approval
//! channel + `wg_peer_manage`): `network.rs`'s `WgPeerManageCapability` is
//! now a real, production `Tier2Capability` impl, proposed/decided/executed
//! through a real `Tier2ApprovalFlow<TelegramApprovalChannel>` -
//! `MockDestructiveCapability` remains what it always was (a Phase 3.3
//! rehearsal fixture, `test`/`test-utils`-only, never reachable from
//! production dispatch), but it is no longer the ONLY thing exercising this
//! machinery. `capability_dispatch_reaches_the_audit_log_only_via_log_
//! tier2_linked_record` (this module) is the enforced, narrowed proof of
//! exactly what changed and what didn't - see its own doc comment. Checked
//! deliberately before writing this module's original version, per that
//! task's own instruction not to assume; re-verified again for this update.
//!
//! What actually exists, found by reading `forge-node/src/network.rs`:
//! - `KNOWN_CAPABILITY_NAMES: &[&str]`, a hand-maintained const list.
//! - `dispatch_intent`, a single async fn whose `match name { ... }` block
//!   is the SOLE place a capability name resolves to real handler code -
//!   `"echo"` inline, `"sysinfo"` -> `collect_sysinfo()`, `"network_clients"`
//!   -> `dispatch_network_clients()` -> `fetch_network_clients()`.
//!
//! This is genuinely a hand-maintained list, not a compiler-enumerable
//! trait/enum - see this module's own doc comment further down
//! (`KNOWN_CAPABILITY_NAMES` cross-check) for exactly what "automatic"
//! means here and what it doesn't.
//!
//! # Mechanism (three independent layers, see each test's own doc comment)
//!
//! 1. **List-drift cross-check**: `KNOWN_CAPABILITY_NAMES` vs. the actual
//!    `match name { ... }` arms inside `dispatch_intent` are two
//!    independently hand-maintained lists in this codebase today (found,
//!    not assumed - see their respective doc comments in `network.rs`).
//!    This test parses BOTH straight out of the real source and asserts
//!    they name the same capabilities, so someone editing one without the
//!    other gets caught immediately instead of silently drifting.
//! 2. **Targeted per-capability scan**: for each of today's three
//!    capabilities, the exact function body/bodies that implement it are
//!    extracted (via a brace-matching source slicer, not fixed line
//!    numbers - see `extract_braced_block`) and scanned for a forbidden-
//!    pattern list covering every one of prime directive 2's five named
//!    targets (policy file, audit log, systemd/service control, Tailscale,
//!    SSH). New code added to any of these SAME functions is automatically
//!    covered; a brand new capability implemented as a brand new named
//!    helper function is NOT automatically discovered by this layer alone
//!    - see the honest limitation called out in
//!    `every_known_capability_has_no_forbidden_pattern_in_its_implementation`'s
//!    doc comment.
//! 3. **Whole-file backstop scan**: independent of any per-capability
//!    function list, the ENTIRE production (non-test) portion of
//!    `network.rs` - the one file that holds `dispatch_intent` and every
//!    capability handler that exists today - is scanned for the same
//!    forbidden-pattern list. This is genuinely "automatic" for anything
//!    added anywhere in this file, including a brand-new capability
//!    implemented as a brand-new function, AS LONG AS its implementation
//!    lands in this same file (matching how every capability so far has
//!    been added). It would NOT catch a future capability whose handler
//!    logic lives in some other crate/file entirely. That gap is real and
//!    is called out explicitly rather than papered over - see this
//!    module's top-of-file doc comment section further down and the final
//!    report this check's author gave alongside shipping it.
//!
//! Plus, independent of scanning capability code at all:
//! - The protected resources' OWN public API surfaces
//!   (`axiom_gateway::CapabilityPolicy`, `axiom_gateway::AuditLog`) are
//!   checked to have no destructive method in the first place - so even a
//!   hypothetical future capability that somehow obtained a live handle to
//!   either type still has nothing destructive to call.
//! - The REAL deployed systemd unit (`deploy/forge-node.service`, loaded
//!   via `include_str!` - not a paraphrase) is checked to grant no write
//!   access outside `data_dir` and to run as a non-root dedicated user.
//!
//! # Proving the check can actually fail (not just "inspection with extra
//! steps")
//!
//! `scanner_catches_*` tests below run the exact same scan function this
//! module uses on real source against small synthetic bad-string fixtures
//! (never compiled as real capability code, never touching production
//! source) and assert violations ARE reported. This is this module's
//! negative-test proof, matching Phase 3.3's own `MockDestructiveCapability`
//! precedent of "rehearse the mechanism against a fixture" rather than
//! trusting it by construction.

// ---------------------------------------------------------------------
// Real source, embedded verbatim (not summarized/hand-copied) at compile
// time. If any of these paths move, this simply fails to compile - a
// loud, immediate signal, not a silently-stale check.
// ---------------------------------------------------------------------

const NETWORK_RS: &str = include_str!("network.rs");
const POLICY_RS: &str = include_str!("../../axiom-gateway/src/policy.rs");
const AUDIT_RS: &str = include_str!("../../axiom-gateway/src/audit.rs");
const APPROVAL_RS: &str = include_str!("../../axiom-gateway/src/approval.rs");
const SERVICE_UNIT: &str = include_str!("../../deploy/forge-node.service");
const FORGE_NODE_CARGO_TOML: &str = include_str!("../Cargo.toml");
const AXIOM_GATEWAY_CARGO_TOML: &str = include_str!("../../axiom-gateway/Cargo.toml");

// ---------------------------------------------------------------------
// Source-slicing helpers
// ---------------------------------------------------------------------

/// Returns everything in `source` BEFORE the first line that is exactly
/// `#[cfg(test)]` (no leading whitespace - a real top-level attribute, not
/// prose inside a doc comment that happens to mention the literal text
/// `#[cfg(test)]`, e.g. `axiom-gateway/src/policy.rs` line ~552 does
/// exactly that inside a `///` comment - a naive substring search over the
/// whole file would misfire on it, which is why this matches whole lines,
/// not substrings).
///
/// Every file this module scans for forbidden patterns (`network.rs`,
/// `policy.rs`, `audit.rs`, `approval.rs`) follows this codebase's own
/// consistent "tests live at the bottom, behind a bare `#[cfg(test)]`"
/// convention - verified by hand against all four before relying on it
/// here. Panics loudly rather than silently scanning the whole file
/// (tests included) or an empty slice if that convention ever stops
/// holding for a given file - see `production_scope_finds_the_real_boundary_not_a_doc_comment_mention`
/// below for this function's own self-test.
fn production_scope<'a>(source: &'a str, file_label: &str) -> &'a str {
    let marker = "#[cfg(test)]";
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        if line.trim_end_matches('\n') == marker {
            return &source[..offset];
        }
        offset += line.len();
    }
    panic!(
        "capability isolation check: no bare `#[cfg(test)]` line found in {file_label} - \
         this check's file-scoping assumption (\"production code precedes a bare \
         `#[cfg(test)]` line\") no longer holds for this file. Update `production_scope`'s \
         caller for {file_label} before trusting this check again.",
    );
}

/// Slice `source` from `open_brace_byte_idx` (which MUST point at a `{`)
/// to its matching `}`, inclusive - a brace-depth counter that skips the
/// contents of `"..."` string literals (honoring `\"` escapes) and `//`
/// line comments so braces/quote-like characters inside either don't
/// perturb the count. Handles a bare `'x'`/`'\n'` char literal
/// defensively (vs. a lifetime `'a`, which has no closing quote) even
/// though none of the specific functions this module extracts today
/// contain one - verified by hand, and re-verified structurally by
/// `extract_braced_block_is_not_confused_by_strings_or_comments` below.
///
/// Deliberately NOT a general Rust parser (no raw strings, no block
/// comments) - this codebase doesn't use either inside the specific
/// functions this module targets (verified by hand before relying on
/// this), and a full tokenizer would be a lot of machinery for a test-only
/// helper. Panics loudly on anything that leaves it unbalanced, rather
/// than silently returning a wrong/truncated slice.
fn extract_braced_block(source: &str, open_brace_byte_idx: usize) -> &str {
    let bytes = source.as_bytes();
    assert_eq!(
        bytes[open_brace_byte_idx], b'{',
        "extract_braced_block: caller must pass the byte index of an opening `{{`",
    );
    let mut depth: i32 = 0;
    let mut i = open_brace_byte_idx;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return &source[open_brace_byte_idx..i];
                }
            }
            b'"' => {
                // Skip the string literal's contents, honoring `\"`.
                i += 1;
                while i < n && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // consume the closing quote
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'/' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'\'' => {
                // Try to consume a char literal (`'x'` or `'\n'`); if the
                // lookahead doesn't find a closing `'` within the next
                // couple of bytes, this was a lifetime (`'a`) or something
                // else entirely - back off to just past the opening `'`
                // and let normal scanning continue.
                let save = i;
                i += 1;
                if i < n && bytes[i] == b'\\' {
                    i += 1;
                }
                if i < n {
                    i += 1;
                }
                if i < n && bytes[i] == b'\'' {
                    i += 1;
                } else {
                    i = save + 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    panic!(
        "extract_braced_block: reached end of source with depth {depth} still open - \
         unbalanced braces, or this source uses a construct (raw string, block comment) \
         this helper doesn't understand. Source near the open brace: {:?}",
        &source[open_brace_byte_idx..(open_brace_byte_idx + 120).min(n)],
    );
}

/// Find `fn <name>` (as a real function definition, not a call site or a
/// mention in a comment - requires whitespace before `(`/`<` and a `{`
/// reachable without crossing a `;`) in `source` and return its full body,
/// braces included. Panics with a clear message (not silently `None`) if
/// the function can't be found - a capability handler being renamed or
/// removed without updating this check is exactly the kind of drift this
/// module exists to catch, not swallow.
fn extract_fn_body<'a>(source: &'a str, fn_name: &str) -> &'a str {
    let marker = format!("fn {fn_name}(");
    let start = source.find(&marker).unwrap_or_else(|| {
        panic!(
            "capability isolation check: could not find `fn {fn_name}(` - has it been \
             renamed, removed, or does it now take generics (`fn {fn_name}<...>(`, not \
             handled by this simple search)? Update capability_isolation.rs's function list.",
        )
    });
    let open_brace = source[start..].find('{').map(|i| start + i).unwrap_or_else(|| {
        panic!("capability isolation check: found `fn {fn_name}(` but no `{{` after it")
    });
    extract_braced_block(source, open_brace)
}

/// AXIOM Phase 3.6: like `extract_fn_body`, but returns the SIGNATURE
/// (`fn name(params...) -> ReturnType`) rather than the body - the slice
/// from `fn <name>(` up to (not including) the opening `{`. A parameter's
/// TYPE (e.g. `policy: Arc<CapabilityPolicy>`) lives in the signature, not
/// the body - `extract_fn_body` alone can't prove a constructor REQUIRES a
/// particular parameter type, only that its body mentions something,
/// which for a thin constructor that just forwards to another function
/// (see `Tier2ApprovalFlow::new` delegating to `with_expiry`) may not
/// mention the type at all even though the signature does.
fn extract_fn_signature<'a>(source: &'a str, fn_name: &str) -> &'a str {
    let marker = format!("fn {fn_name}(");
    let start = source.find(&marker).unwrap_or_else(|| {
        panic!(
            "capability isolation check: could not find `fn {fn_name}(` - has it been \
             renamed, removed, or does it now take generics (`fn {fn_name}<...>(`, not \
             handled by this simple search)? Update capability_isolation.rs's function list.",
        )
    });
    let open_brace = source[start..].find('{').map(|i| start + i).unwrap_or_else(|| {
        panic!("capability isolation check: found `fn {fn_name}(` but no `{{` after it")
    });
    &source[start..open_brace]
}

/// Parse the `&[&str]` literal body of `const KNOWN_CAPABILITY_NAMES` (see
/// `network.rs`'s own doc comment on it: "every capability name this build
/// understands how to resolve an Announce's hash back to") straight out of
/// the real source, rather than hand-copying `["echo", "sysinfo",
/// "network_clients"]` into this test file as a THIRD independent list
/// that could itself drift from the other two.
fn known_capability_names() -> Vec<String> {
    let marker = "const KNOWN_CAPABILITY_NAMES: &[&str] = &[";
    let start = NETWORK_RS.find(marker).unwrap_or_else(|| {
        panic!(
            "capability isolation check: KNOWN_CAPABILITY_NAMES not found with the exact \
             signature this check expects - if it was renamed/retyped, update the marker \
             string in `known_capability_names()`.",
        )
    }) + marker.len();
    let rest = &NETWORK_RS[start..];
    let end = rest.find(']').unwrap_or_else(|| {
        panic!("capability isolation check: KNOWN_CAPABILITY_NAMES has no closing `]`")
    });
    let names: Vec<String> = rest[..end]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    assert!(
        !names.is_empty(),
        "capability isolation check: parsed zero names out of KNOWN_CAPABILITY_NAMES - \
         parsing broke, this isn't a legitimately-empty-capability build",
    );
    names
}

/// Parse the capability-name string literals out of `dispatch_intent`'s
/// own `match name { ... }` block - the actual set of capabilities that
/// resolve to real handler code today, straight from source, independent
/// of `known_capability_names()` above (see this module's top-of-file doc
/// comment on why these are checked against each other rather than
/// assumed to agree).
fn dispatch_intent_match_arm_names() -> Vec<String> {
    let body = extract_fn_body(NETWORK_RS, "dispatch_intent");
    let match_marker = "match name {";
    let match_start = body.find(match_marker).unwrap_or_else(|| {
        panic!(
            "capability isolation check: dispatch_intent no longer has a `match name {{` \
             block this check recognizes - if the dispatch mechanism was restructured, \
             update `dispatch_intent_match_arm_names()`.",
        )
    });
    let open_brace = match_start + match_marker.len() - 1;
    let match_body = extract_braced_block(body, open_brace);

    // Each real arm looks like `"echo" => ...,` - a leading `"` at the
    // start of a (trimmed) line is what distinguishes a capability-name
    // arm from the trailing `_ => ...` fallback arm, which this
    // deliberately excludes (it has no name to check - see
    // `dispatch_intent`'s own final arm, "capability recognized but has
    // no handler").
    match_body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('"'))
        .filter_map(|line| {
            let rest = &line[1..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------
// Forbidden-pattern scanner
// ---------------------------------------------------------------------

struct ForbiddenPattern {
    needle: &'static str,
    case_insensitive: bool,
    /// Which of prime directive 2's five named targets this pattern
    /// guards against, plus why this specific string/API is the tell.
    reason: &'static str,
}

/// Every pattern here maps directly to one of prime directive 2's five
/// named targets: the policy file, the audit log, systemd/service control,
/// Tailscale, SSH. The filesystem-write/process-spawn primitives are the
/// strongest single layer - a function with NO way to write a file or
/// spawn a process cannot modify the policy file, the audit log, a
/// systemd unit, or `~/.ssh/authorized_keys` no matter what path string it
/// might otherwise construct - which is why they're listed first and why
/// `every_known_capability_has_no_forbidden_pattern_in_its_implementation`
/// leans on them as the primary signal. The literal-string patterns below
/// them are a second, independent layer (catches a mention/reference even
/// if it wouldn't currently compile into a real write, e.g. a future
/// capability that shells out to `sh -c` with an interpolated string
/// instead of calling `Command::new("systemctl")` directly).
const FORBIDDEN_PATTERNS: &[ForbiddenPattern] = &[
    ForbiddenPattern {
        needle: "process::Command",
        case_insensitive: false,
        reason: "spawns an external process - the only realistic way Rust code reaches \
                 `systemctl`/`tailscale` as CLI tools, or an `ssh`/`scp` invocation",
    },
    ForbiddenPattern {
        needle: "Command::new(",
        case_insensitive: false,
        reason: "spawns an external process (same concern as `process::Command` above, \
                 caught as its own pattern in case only this shorter form is imported)",
    },
    // AXIOM adversarial-test finding, real gap (see TESTING.md): the two
    // patterns above are literal-SUBSTRING matches, and Rust lets a `use`
    // statement rename anything on import. `use std::process::{Command as
    // Cmd};` followed by a call site written `Cmd::new(bin)` contains
    // NEITHER `"process::Command"` (broken by the `{` introduced by braced
    // import syntax) NOR `"Command::new("` (the type itself was renamed) -
    // so both patterns above miss it completely, even though the resulting
    // code spawns a process exactly as directly as `Command::new(...)`
    // would have. Confirmed as a real, constructible bypass during this
    // project's own adversarial test pass, not a hypothetical - see
    // `scanner_catches_aliased_process_import_that_defeats_the_command_new_pattern`
    // below, which fails without this pattern. Closed with a broader,
    // import-statement-level pattern: legitimate capability handler code
    // (everything here goes through `uai_dispatch`'s `reqwest` HTTP client,
    // never a local process) has zero legitimate reason to import ANYTHING
    // from ANY `process` module, `std::process` or otherwise (e.g.
    // `tokio::process`) - so this doesn't need "process::Command"
    // specifically to fire, just "process::" appearing anywhere at all,
    // which a `use` line cannot avoid no matter what alias it assigns the
    // imported item afterward. Verified against this file's own `include_str!`
    // sources (`network.rs`/`policy.rs`/`audit.rs`/`approval.rs`) to
    // introduce no false positive - their only `process::` mentions
    // (`std::process::id()`, for unique temp-file names) live in `#[cfg(test)]`
    // code, outside every scan `production_scope` covers.
    ForbiddenPattern {
        needle: "process::",
        case_insensitive: true,
        reason: "imports or references something from a `process` module (`std::process`, \
                 `tokio::process`, ...) under any name - a capability handler has no \
                 legitimate reason to import anything from a process-spawning module at all, \
                 regardless of what alias a `use ... as` might give it afterward",
    },
    ForbiddenPattern {
        needle: "fs::write(",
        case_insensitive: false,
        reason: "filesystem write primitive - a capability with zero write primitives at \
                 all cannot write the policy file, the audit log, an SSH key/config file, \
                 or a systemd unit file, regardless of what path it's handed",
    },
    ForbiddenPattern {
        needle: "fs::remove_file(",
        case_insensitive: false,
        reason: "filesystem delete primitive - could delete the audit log or an SSH key",
    },
    ForbiddenPattern {
        needle: "fs::remove_dir",
        case_insensitive: false,
        reason: "filesystem delete primitive",
    },
    ForbiddenPattern {
        needle: "fs::rename(",
        case_insensitive: false,
        reason: "filesystem move/overwrite primitive",
    },
    ForbiddenPattern {
        needle: "fs::set_permissions(",
        case_insensitive: false,
        reason: "filesystem permission-change primitive - could loosen the policy file's \
                 own read-only-to-service posture",
    },
    ForbiddenPattern {
        needle: "fs::create_dir",
        case_insensitive: false,
        reason: "filesystem create primitive",
    },
    ForbiddenPattern {
        needle: "OpenOptions",
        case_insensitive: false,
        reason: "generic file-open builder that can request write/create/truncate access",
    },
    ForbiddenPattern {
        needle: "systemctl",
        case_insensitive: true,
        reason: "names the systemd control tool directly - forbidden regardless of how \
                 it would be invoked (prime directive 2: \"control systemd/the service \
                 itself\")",
    },
    ForbiddenPattern {
        needle: "/etc/systemd",
        case_insensitive: true,
        reason: "systemd unit-file directory - forge-node's own unit file lives here",
    },
    ForbiddenPattern {
        needle: "tailscale",
        case_insensitive: true,
        reason: "prime directive 2 names Tailscale explicitly, independent of DECISIONS.md's \
                 separate decision that AXIOM itself doesn't depend on Tailscale for \
                 transport - Larry's own personal Tailscale instance (see DECISIONS.md's \
                 'Protected-resource list' section) is still off limits",
    },
    ForbiddenPattern {
        needle: "authorized_keys",
        case_insensitive: true,
        reason: "SSH access-control file",
    },
    ForbiddenPattern {
        needle: ".ssh/",
        case_insensitive: true,
        reason: "SSH config/key directory",
    },
    ForbiddenPattern {
        needle: "id_ed25519",
        case_insensitive: true,
        reason: "SSH private key filename (this repo's own admin key is id_ed25519)",
    },
    ForbiddenPattern {
        needle: "id_rsa",
        case_insensitive: true,
        reason: "SSH private key filename",
    },
    ForbiddenPattern {
        needle: "/etc/ssh",
        case_insensitive: true,
        reason: "sshd system config directory",
    },
];

/// Scan `source` for every `FORBIDDEN_PATTERNS` entry, returning one
/// human-readable violation string per match (empty = clean). Pure
/// function over a string - the same logic runs against real production
/// source (expect empty) and synthetic bad fixtures (expect non-empty, see
/// the `scanner_catches_*` tests) so the negative-test proof exercises the
/// EXACT mechanism the real checks rely on, not a paraphrase of it.
fn scan_for_forbidden_patterns(source: &str) -> Vec<String> {
    let lower = source.to_lowercase();
    FORBIDDEN_PATTERNS
        .iter()
        .filter(|p| {
            if p.case_insensitive {
                lower.contains(&p.needle.to_lowercase())
            } else {
                source.contains(p.needle)
            }
        })
        .map(|p| format!("forbidden pattern `{}` found ({})", p.needle, p.reason))
        .collect()
}

// ---------------------------------------------------------------------
// Layer 1: list-drift cross-check
// ---------------------------------------------------------------------

/// `KNOWN_CAPABILITY_NAMES` and `dispatch_intent`'s own match arms are two
/// independently hand-maintained lists in `network.rs` today (confirmed by
/// reading the source, not assumed) - nothing enforces they stay in sync.
/// This fails loudly the moment they don't, which is exactly the "new
/// capability quietly added to only one of them" drift this module exists
/// to prevent.
#[test]
fn known_capability_names_matches_dispatch_intent_match_arms() {
    let mut from_const = known_capability_names();
    let mut from_match = dispatch_intent_match_arm_names();
    from_const.sort();
    from_match.sort();
    assert_eq!(
        from_const, from_match,
        "KNOWN_CAPABILITY_NAMES and dispatch_intent's `match name {{ ... }}` arms have \
         drifted apart - every capability this build can resolve an Announce hash for \
         (KNOWN_CAPABILITY_NAMES) must also be an arm dispatch_intent actually knows how \
         to serve, and vice versa. If you just added a new capability to one of these, \
         add it to the other before this check will pass again.",
    );
}

// ---------------------------------------------------------------------
// AXIOM Phase 3.6: protected-resource check sits in the SAME mandatory
// gate every capability call already passes through
// ---------------------------------------------------------------------

/// AXIOM Phase 3.6's protected-resource enforcement lands in
/// `axiom_gateway::policy::CapabilityPolicy` (see that module's own doc
/// comment) - a Tier1/Tier2 capability entry simply never registers at
/// all if the loaded policy file has no `[[protected_resource]]` section,
/// which means `check_and_acquire` (called here, in `dispatch_intent`,
/// for EVERY capability, LAN and WAN both - see `DispatchContext`'s own
/// doc comment) denies it before ANY capability handler in the `match
/// name { ... }` block below can run. This test proves that ordering
/// structurally, straight from source: `check_and_acquire(` must appear
/// BEFORE `match name {` inside `dispatch_intent`'s own body. If a future
/// edit ever moved a capability handler to run before this check (or
/// introduced a second capability-dispatch entry point that skipped it),
/// this test - not a runtime one - is what would catch it, the same
/// "prove it structurally, not by trusting the current call graph"
/// discipline the rest of this module already applies to prime directive
/// 2.
#[test]
fn check_and_acquire_runs_before_any_capability_handler_in_dispatch_intent() {
    let body = extract_fn_body(NETWORK_RS, "dispatch_intent");
    let check_pos = body.find("check_and_acquire(").unwrap_or_else(|| {
        panic!(
            "capability isolation check: dispatch_intent no longer calls check_and_acquire( \
             at all - this is the mandatory policy gate (which, as of AXIOM Phase 3.6, is \
             also what enforces protected-resource fail-closed registration for Tier1+ \
             capabilities) every capability call must pass through. If dispatch now gates \
             through a differently-named method, update this test's marker string.",
        )
    });
    let match_pos = body.find("match name {").unwrap_or_else(|| {
        panic!("capability isolation check: dispatch_intent no longer has a `match name {{` dispatch block this check recognizes")
    });
    assert!(
        check_pos < match_pos,
        "check_and_acquire must run BEFORE dispatch_intent's `match name` capability-handler \
         dispatch - found check_and_acquire at byte {check_pos}, match name at byte {match_pos}. \
         If this ordering changed, a capability handler could now run without ever passing \
         through the policy/protected-resource gate.",
    );
}

/// `axiom_gateway::policy::CapabilityPolicy`'s own public API is scanned
/// here too (same "check the SURFACE, not just today's call sites, for a
/// bypass" discipline as `capability_policy_public_api_has_no_destructive_method`
/// above) - specifically, that `find_protected_match`/
/// `protected_resources_configured`/`protected_resources` are real,
/// present methods on the EXACT source this binary compiles against
/// (embedded via `include_str!` at the top of this file), not a stale
/// claim in a doc comment.
#[test]
fn capability_policy_exposes_the_protected_resource_check_surface() {
    let scope = production_scope(POLICY_RS, "axiom-gateway/src/policy.rs");
    for marker in ["pub fn protected_resources_configured(", "pub fn find_protected_match(", "pub fn protected_resources("] {
        assert!(
            scope.contains(marker),
            "axiom-gateway/src/policy.rs's CapabilityPolicy no longer exposes `{marker}` - \
             AXIOM Phase 3.6's protected-resource check depends on this method existing",
        );
    }
}

/// `approval::Tier2ApprovalFlow` must be structurally incapable of being
/// constructed without a policy to check proposals against - scans
/// `approval.rs`'s own source for `new`/`with_expiry`'s signatures and
/// confirms both take a `CapabilityPolicy` parameter. This is what backs
/// this module's (and `approval.rs`'s own) claim that the protected-
/// resource check at proposal time can't be skipped by a caller simply
/// not passing one in - there is no such constructor to call.
#[test]
fn tier2_approval_flow_constructors_require_a_capability_policy() {
    let scope = production_scope(APPROVAL_RS, "axiom-gateway/src/approval.rs");
    // Several OTHER types in this file also define their own `fn new(`
    // (`DryRunDiffEntry`, `CliApprovalChannel`, `MockDestructiveCapability`)
    // - a bare `extract_fn_body(scope, "new")` would find the FIRST one in
    // the file, not necessarily `Tier2ApprovalFlow`'s. Scope to
    // `Tier2ApprovalFlow`'s own `impl` block first, so `fn new`/
    // `fn with_expiry` are found unambiguously within it.
    let impl_marker = "impl<C: ApprovalChannel> Tier2ApprovalFlow<C> {";
    let impl_start = scope.find(impl_marker).unwrap_or_else(|| {
        panic!(
            "capability isolation check: `{impl_marker}` not found in approval.rs - has \
             Tier2ApprovalFlow's impl block moved, been renamed, or changed its generic bounds? \
             Update this test's impl_marker to match.",
        )
    }) + impl_marker.len() - 1;
    let impl_body = extract_braced_block(scope, impl_start);

    for fn_name in ["new", "with_expiry"] {
        // The SIGNATURE, not the body - `new` is a thin one-line forward
        // to `with_expiry` (`Self::with_expiry(channel, DEFAULT_EXPIRY,
        // policy)`), whose body doesn't literally mention the type name
        // `CapabilityPolicy` even though its parameter's TYPE requires
        // one. The signature is where a parameter's type actually lives.
        let signature = extract_fn_signature(impl_body, fn_name);
        assert!(
            signature.contains("CapabilityPolicy"),
            "approval.rs's Tier2ApprovalFlow::{fn_name}'s signature no longer mentions \
             CapabilityPolicy at all ({signature:?}) - AXIOM Phase 3.6 requires every \
             Tier2ApprovalFlow constructor to take an Arc<CapabilityPolicy> so the \
             protected-resource check can't be constructed around",
        );
    }
}

// ---------------------------------------------------------------------
// Layer 2: targeted per-capability scan
// ---------------------------------------------------------------------

/// Explicit map from today's capability names to the function(s) that
/// implement them, beyond `dispatch_intent`'s own match arm (which is
/// always scanned in full regardless - see below). This is the
/// HAND-MAINTAINED part of this check: a brand-new capability implemented
/// as a brand-new named helper function (following the existing
/// `dispatch_network_clients`-style pattern) needs an entry added here for
/// its body to get this targeted scan. `dispatch_intent`'s own body is
/// always scanned in full independent of this map, so a new match arm's
/// INLINE logic (e.g. a hypothetical `"foo" => do_the_thing_inline()`)
/// is still covered even before this map is updated - only logic that
/// lives inside a SEPARATE new function is missed until this map catches
/// up. And `every_capability_dispatch_source_has_no_forbidden_patterns`
/// below is a whole-file backstop that doesn't depend on this map at all.
fn capability_implementation_functions(capability: &str) -> &'static [&'static str] {
    match capability {
        "echo" => &[],
        "sysinfo" => &["collect_sysinfo"],
        "network_clients" => &["dispatch_network_clients", "fetch_network_clients", "uai_dispatch"],
        // AXIOM notify_send: `uai_dispatch` is shared with network_clients
        // (extracted as its own module-level function specifically so
        // both capabilities call the same, singly-scanned UAI HTTP-POST
        // helper rather than each hand-rolling their own - see
        // `uai_dispatch`'s own doc comment in network.rs) - listed here
        // too so this scan covers it for notify_send independently of
        // whether it's also reachable via network_clients's own list.
        "notify_send" => &["dispatch_notify_send", "send_notification", "prepare_notify_message", "uai_dispatch"],
        // AXIOM proxmox_restart: `uai_dispatch` shared again, same reason
        // as notify_send's own entry above. `parse_proxmox_restart_target`
        // is pure/sync (no network, no filesystem) but included anyway for
        // complete coverage of everything this capability's dispatch path
        // touches.
        "proxmox_restart" => &["dispatch_proxmox_restart", "restart_proxmox_resource", "parse_proxmox_restart_target", "uai_dispatch"],
        // AXIOM home_assistant_toggle: `uai_dispatch` shared again, same
        // reason as notify_send/proxmox_restart above.
        // `parse_ha_toggle_target` is pure/sync (no network, no
        // filesystem) but included anyway for complete coverage - it's
        // also where this capability's domain hard-deny actually lives,
        // so scanning it is a real check, not just a formality.
        "home_assistant_toggle" => &["dispatch_home_assistant_toggle", "call_ha_action", "parse_ha_toggle_target", "uai_dispatch"],
        // AXIOM docker_restart: `uai_dispatch` shared again, same reason
        // as every prior UAI-backed capability above.
        // `parse_docker_restart_target` is pure/sync (no network, no
        // filesystem) but included anyway for complete coverage - it's
        // also where this capability's allowlist AND hard-deny actually
        // live, so scanning it is a real check, not just a formality.
        "docker_restart" => &["dispatch_docker_restart", "restart_docker_container", "parse_docker_restart_target", "uai_dispatch"],
        // AXIOM wg_peers_list: `uai_dispatch` shared again, same reason as
        // every prior UAI-backed capability above. No target-parsing
        // function exists for this one (it's payload-less, like
        // network_clients/sysinfo) - `dispatch_wg_peers_list`/
        // `fetch_wg_peers_list` are its whole implementation.
        "wg_peers_list" => &["dispatch_wg_peers_list", "fetch_wg_peers_list", "uai_dispatch"],
        // AXIOM Tier 2 wg_peer_manage: the first REAL (non-mock) Tier 2
        // capability - `resolve_wg_peer_by_name`/`perform`/`execute`/
        // `dry_run`/`parse_wg_peer_manage_target` are its whole
        // implementation, plus the shared `uai_dispatch` (via
        // `resolve_wg_peer_by_name` and `perform`, same reason every prior
        // UAI-backed capability's own entry lists it). `dispatch_wg_peer_manage`
        // itself is always scanned (every capability's dispatch_intent
        // match-arm body is - see this function's own doc comment), so it
        // is deliberately NOT repeated here.
        "wg_peer_manage" => &["resolve_wg_peer_by_name", "perform", "execute", "dry_run", "parse_wg_peer_manage_target", "uai_dispatch"],
        _ => &[],
    }
}

/// For each capability `KNOWN_CAPABILITY_NAMES` declares, scan
/// `dispatch_intent`'s own body plus every function
/// `capability_implementation_functions` names for it, and assert none of
/// `FORBIDDEN_PATTERNS` appear anywhere in that combined source. This is
/// the check that would actually fail if `sysinfo` or `network_clients`
/// (or a future capability correctly added to the map above) grew a call
/// to `Command::new("systemctl")` or a literal `.ssh/authorized_keys`
/// path tomorrow.
///
/// Honest limitation (see this module's top-of-file doc comment): a
/// BRAND NEW capability whose implementation lives in a function not yet
/// added to `capability_implementation_functions` only gets its
/// `dispatch_intent` match-arm line scanned by THIS test - full coverage
/// of its own function body needs that map updated. The whole-file
/// backstop test right after this one does not have that gap for
/// anything landing in `network.rs`, which is where every capability
/// implemented so far lives.
#[test]
fn every_known_capability_has_no_forbidden_pattern_in_its_implementation() {
    let dispatch_body = extract_fn_body(NETWORK_RS, "dispatch_intent");
    for capability in known_capability_names() {
        let mut combined = dispatch_body.to_string();
        for func in capability_implementation_functions(&capability) {
            combined.push('\n');
            combined.push_str(extract_fn_body(NETWORK_RS, func));
        }
        let violations = scan_for_forbidden_patterns(&combined);
        assert!(
            violations.is_empty(),
            "capability `{capability}` (scanned: dispatch_intent + {:?}) violates prime \
             directive 2:\n{}",
            capability_implementation_functions(&capability),
            violations.join("\n"),
        );
    }
}

// ---------------------------------------------------------------------
// Layer 3: whole-file backstop
// ---------------------------------------------------------------------

/// Independent of `capability_implementation_functions`'s hand-maintained
/// map, and independent of `KNOWN_CAPABILITY_NAMES` entirely: scans the
/// FULL production (non-test) body of `network.rs` - the one file that
/// contains `dispatch_intent` and every capability handler that exists
/// today - for the same forbidden-pattern list. Genuinely automatic for
/// any future capability whose implementation lands in this file, which
/// is where every capability so far has been added, following the
/// existing `collect_sysinfo`/`dispatch_network_clients` pattern.
///
/// What this does NOT cover (stated plainly, not glossed over): a future
/// capability whose handler logic lives in some OTHER file/crate entirely
/// (rather than following the existing convention of living in
/// `network.rs` alongside `dispatch_intent`) would not be swept in by
/// this scan. Nothing in this codebase's current architecture makes that
/// scenario impossible - there's no compiler-enforced boundary requiring
/// capability implementations to live here, only convention. Layer 1's
/// list-drift check would still catch it being registered
/// (`KNOWN_CAPABILITY_NAMES`/match arms), just not its forbidden-pattern
/// exposure.
#[test]
fn production_capability_dispatch_source_has_no_forbidden_patterns() {
    let scope = production_scope(NETWORK_RS, "forge-node/src/network.rs");
    let violations = scan_for_forbidden_patterns(scope);
    assert!(
        violations.is_empty(),
        "forge-node/src/network.rs's production (non-test) code violates prime directive \
         2:\n{}",
        violations.join("\n"),
    );
}

/// Belt-and-suspenders on the crate that actually HOLDS the policy file
/// and audit log machinery: `policy.rs`/`audit.rs`/`approval.rs`'s
/// production code shouldn't reference systemd/Tailscale/SSH either
/// (their legitimate job is reading/writing THEIR OWN designated files -
/// the policy file's path and the audit log's path, both passed in as
/// parameters - never a systemd/Tailscale/SSH path). Deliberately does
/// NOT include the filesystem-write-primitive patterns here (unlike the
/// `network.rs` scan above) - `audit.rs`'s `AuditLog::open` legitimately
/// uses `OpenOptions`/`fs::set_permissions` to manage ITS OWN log file,
/// which would be a false positive under that stricter check. The
/// literal-string patterns (systemctl/tailscale/ssh paths) are the right
/// check for this module: it should never even MENTION those, write
/// primitives or not.
#[test]
fn axiom_gateway_policy_audit_approval_modules_never_mention_forbidden_systems() {
    for (label, source) in [
        ("axiom-gateway/src/policy.rs", POLICY_RS),
        ("axiom-gateway/src/audit.rs", AUDIT_RS),
        ("axiom-gateway/src/approval.rs", APPROVAL_RS),
    ] {
        let scope = production_scope(source, label);
        let string_only_violations: Vec<String> = FORBIDDEN_PATTERNS
            .iter()
            .filter(|p| {
                // Skip the generic filesystem-write-primitive patterns for
                // this check - see this test's own doc comment above for why.
                !matches!(
                    p.needle,
                    "fs::write(" | "fs::remove_file(" | "fs::remove_dir" | "fs::rename("
                        | "fs::set_permissions(" | "fs::create_dir" | "OpenOptions"
                )
            })
            .filter(|p| {
                let lower = scope.to_lowercase();
                if p.case_insensitive {
                    lower.contains(&p.needle.to_lowercase())
                } else {
                    scope.contains(p.needle)
                }
            })
            .map(|p| format!("forbidden pattern `{}` found ({})", p.needle, p.reason))
            .collect();
        assert!(
            string_only_violations.is_empty(),
            "{label}'s production code mentions a forbidden system:\n{}",
            string_only_violations.join("\n"),
        );
    }
}

// ---------------------------------------------------------------------
// Protected resources' own API surface
// ---------------------------------------------------------------------

/// Even if some future capability somehow obtained a live
/// `&CapabilityPolicy`, it has nothing destructive to call on it: the
/// type's entire public method surface, parsed straight from
/// `policy.rs`'s `impl CapabilityPolicy` block, must contain no method
/// whose name suggests it could write/mutate/delete the underlying policy
/// file (the type's only `load`/`try_load` methods READ; there is no
/// `save`/`write`/`update`/`set_*`/`delete`/`remove_*` method at all
/// today - confirmed by reading the module, not assumed).
#[test]
fn capability_policy_public_api_has_no_destructive_method() {
    let scope = production_scope(POLICY_RS, "axiom-gateway/src/policy.rs");
    let impl_marker = "impl CapabilityPolicy {";
    let start = scope.find(impl_marker).expect(
        "capability isolation check: `impl CapabilityPolicy {` not found - has \
         CapabilityPolicy's impl block moved or been renamed?",
    ) + impl_marker.len() - 1;
    let impl_body = extract_braced_block(scope, start);

    // AXIOM Phase 3.8: `freeze`/`suspend` added to the fragment list -
    // the kill switch's own mutators are real, reviewed, in-memory-only
    // mutations (never touch the policy FILE prime directive 2 actually
    // names) - see the allowlist immediately below for why they're
    // deliberately, individually reviewed rather than silently exempted.
    let destructive_name_fragments = [
        "save", "write", "delete", "remove", "truncate", "overwrite", "set_", "update", "mutate", "freeze",
        "suspend",
    ];
    // AXIOM Phase 3.8: these seven kill-switch methods DO match a
    // destructive-sounding fragment above (`freeze`/`unfreeze`/
    // `suspend_peer`/`unsuspend_peer`) or would otherwise look like
    // mutation (`is_frozen`/`is_suspended`/`suspended_peers` don't match
    // any fragment, listed here anyway for a single complete, reviewed
    // roster) - a DELIBERATE, reviewed exception: they mutate ONLY
    // `KillSwitch`'s in-memory runtime state, never the on-disk policy
    // FILE prime directive 2 is actually about, and are proven NOT
    // reachable via capability dispatch by
    // `capability_dispatch_has_zero_references_to_kill_switch_mutators_today`
    // and `kill_switch_names_are_not_registered_as_capabilities` below -
    // same "allowlist by exact name after review" pattern
    // `audit_log_public_api_has_no_destructive_method` already uses for
    // AuditLog's own append-only methods.
    let kill_switch_allowlist = ["freeze", "unfreeze", "suspend_peer", "unsuspend_peer", "is_frozen", "is_suspended", "suspended_peers"];
    let mut hits = Vec::new();
    for line in impl_body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub fn ").or_else(|| trimmed.strip_prefix("pub(crate) fn ")) {
            let name_end = rest.find(['(', '<']).unwrap_or(rest.len());
            let name = &rest[..name_end];
            if kill_switch_allowlist.contains(&name) {
                continue;
            }
            for fragment in destructive_name_fragments {
                if name.contains(fragment) {
                    hits.push(format!("public method `{name}` matches destructive-sounding fragment `{fragment}`"));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "CapabilityPolicy's public API grew a method that sounds destructive - review \
         whether it can actually write/modify/delete the policy file, which would break \
         prime directive 2's \"AXIOM must never hold a capability that can modify ... its \
         own policy file\" - or, if it's a reviewed kill-switch runtime-state mutator (see \
         AXIOM Phase 3.8), add it to this test's kill_switch_allowlist deliberately:\n{}",
        hits.join("\n"),
    );
}

/// Same check, same reasoning, for `AuditLog`: its public API today is
/// `open` (creates-or-resumes, chain-verifies before appending anything),
/// `path`, `len`, `is_empty`, `log_tier1_call`, `log_tier2_linked_record`
/// - append-only by name and by the module's own documented contract
/// ("this log is reachable ONLY via this crate's own API or that CLI -
/// never as a capability" - `axiom-gateway/src/lib.rs`). No
/// delete/truncate/rewrite method exists to call even if something
/// reached this type.
#[test]
fn audit_log_public_api_has_no_destructive_method() {
    let scope = production_scope(AUDIT_RS, "axiom-gateway/src/audit.rs");
    let impl_marker = "impl AuditLog {";
    let start = scope.find(impl_marker).expect(
        "capability isolation check: `impl AuditLog {` not found - has AuditLog's impl \
         block moved or been renamed?",
    ) + impl_marker.len() - 1;
    let impl_body = extract_braced_block(scope, start);

    // `log_tier1_call`/`log_tier2_linked_record` legitimately contain
    // "log" and are append-only by contract (see this test's own doc
    // comment) - allowlisted by exact name rather than excluded from the
    // destructive-fragment scan entirely, so a FUTURE method named
    // similarly but doing something else doesn't slip through unnoticed.
    // AXIOM Phase 3.8: `log_admin_event` added, same append-only contract -
    // `forge-node/src/control.rs`'s kill-switch handlers are its only
    // caller, reviewed alongside this allowlist entry (see
    // `audit.rs`'s own "kill-switch/admin events" doc-comment section).
    let allowlisted_methods = ["open", "path", "len", "is_empty", "log_tier1_call", "log_tier2_linked_record", "log_admin_event"];
    let destructive_name_fragments =
        ["delete", "remove", "truncate", "overwrite", "rewrite", "clear", "reset", "purge"];
    let mut hits = Vec::new();
    for line in impl_body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub fn ") {
            let name_end = rest.find(['(', '<']).unwrap_or(rest.len());
            let name = &rest[..name_end];
            if allowlisted_methods.contains(&name) {
                continue;
            }
            for fragment in destructive_name_fragments {
                if name.contains(fragment) {
                    hits.push(format!("public method `{name}` matches destructive-sounding fragment `{fragment}`, and is not one of this test's allowlisted append-only methods"));
                }
            }
            if !allowlisted_methods.contains(&name) {
                hits.push(format!(
                    "public method `{name}` is not in this test's allowlist ({allowlisted_methods:?}) - \
                     add it there deliberately (after confirming it's read-only or append-only) \
                     rather than letting AuditLog's public surface grow unreviewed",
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "AuditLog's public API changed in a way this check hasn't reviewed - see \
         prime directive 2's \"AXIOM must never hold a capability that can modify ... its \
         own audit log\":\n{}",
        hits.join("\n"),
    );
}

/// `axiom-gateway/src/lib.rs`'s own module doc comment used to state that
/// wiring `AuditLog` into `forge-node`'s real dispatch path was NOT done
/// yet - AXIOM Tier 2 (this build) is exactly that planned future phase,
/// and per this test's OWN prior doc comment ("that's this test doing its
/// job... it forces whoever wires it in to consciously re-examine... and
/// presumably narrow this check"), this is that deliberate narrowing, not
/// a deletion.
///
/// What's actually reachable from `forge-node/src/network.rs`'s production
/// code now, and what this test proves about it:
/// - `log_tier2_linked_record` - reachable, exactly once, from
///   `dispatch_wg_peer_manage`'s own detached background task (the ONLY
///   place in this file that calls it - checked directly below, not just
///   asserted). This is the append-only Tier 2 entry point
///   `audit_log_public_api_has_no_destructive_method` (above) already
///   proves `AuditLog`'s own surface allows.
/// - `log_tier1_call` - still NOT reachable. This build does not touch
///   Tier 1's own audit-logging gap; narrowing this check for Tier 2 must
///   not silently also open the door for Tier 1 without a deliberate
///   decision to do so.
/// - `log_admin_event` - already established as reachable via
///   `control.rs`, not `network.rs` (a DIFFERENT file, out of this test's
///   scope) - restated here as a boundary, not re-proven.
#[test]
fn capability_dispatch_reaches_the_audit_log_only_via_log_tier2_linked_record() {
    let scope = production_scope(NETWORK_RS, "forge-node/src/network.rs");

    assert!(
        !scope.contains("log_tier1_call"),
        "forge-node/src/network.rs now references `log_tier1_call` - Tier 1 audit-log wiring is \
         still explicitly out of scope for the change that narrowed this test (AXIOM Tier 2's \
         wg_peer_manage). If Tier 1 wiring is now landing too, review deliberately and update this \
         test's own doc comment to describe that decision, rather than letting it happen silently \
         alongside an unrelated Tier 2 change.",
    );

    let occurrences = scope.matches("log_tier2_linked_record").count();
    assert_eq!(
        occurrences, 1,
        "expected exactly ONE reference to `log_tier2_linked_record` in forge-node/src/network.rs's \
         production code (inside dispatch_wg_peer_manage's background task) - found {occurrences}. \
         A second, independent call site increases the audited-append surface beyond what this test \
         has reviewed - update this test deliberately if that's an intentional new capability.",
    );

    // The one call must live inside dispatch_wg_peer_manage's own body -
    // not some other function that could reach the audit log through a
    // path this module hasn't reviewed.
    let dispatch_body = extract_fn_body(NETWORK_RS, "dispatch_wg_peer_manage");
    assert!(
        dispatch_body.contains("log_tier2_linked_record"),
        "log_tier2_linked_record's one reference must be inside dispatch_wg_peer_manage - it appears \
         to have moved elsewhere, which this test has not reviewed",
    );
}

// ---------------------------------------------------------------------
// AXIOM Phase 3.8: kill switch - NOT a capability
// ---------------------------------------------------------------------

/// The kill switch (`axiom_gateway::policy::CapabilityPolicy::freeze`/
/// `unfreeze`/`suspend_peer`/`unsuspend_peer`) must never be a
/// dispatchable capability - same list-drift discipline
/// `known_capability_names_matches_dispatch_intent_match_arms` already
/// applies above, just checked in the other direction: none of the kill
/// switch's own vocabulary should ever show up in
/// `KNOWN_CAPABILITY_NAMES`/`dispatch_intent`'s match arms.
#[test]
fn kill_switch_names_are_not_registered_as_capabilities() {
    let names = known_capability_names();
    for forbidden in ["freeze", "unfreeze", "suspend", "unsuspend", "kill_switch", "killswitch", "kill-switch"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "`{forbidden}` must never be a registered capability name - the kill switch is \
             admin-only/local, reachable ONLY via forge-node's control socket, per AXIOM \
             Phase 3.8's own design",
        );
    }
}

/// The stronger, structural version of the check above: `forge-node/src/
/// network.rs`'s production (non-test) code - the one file that holds
/// `dispatch_intent` and every real capability handler - must have ZERO
/// reference to the kill switch's own mutating method names at all. This
/// is what actually proves the kill switch isn't reachable from
/// capability-dispatch code even indirectly (e.g. a future capability
/// handler calling `ctx.policy.freeze()` directly, without ever
/// registering `"freeze"` as a capability NAME, which the test above
/// alone would not catch). `dispatch_intent` DOES reference the two new
/// `PolicyOutcome::Suspended`/`Frozen` enum variants (it has to, to
/// produce their distinct Error replies) - that's reading an opaque
/// outcome from the SAME `check_and_acquire` call every capability
/// already goes through, not calling a mutator, so it's deliberately not
/// in this needle list. Same "prove it structurally, not by trusting the
/// current call graph" discipline as
/// `capability_dispatch_has_zero_references_to_audit_log_today` just
/// above - and, like that test, EXPECTED to need a deliberate update if a
/// future phase ever wires a real capability into these methods (it
/// should not - see this module's own top-of-file doc comment on prime
/// directive 2's spirit extending to any self-referential control
/// surface, not just its five literally-named targets).
#[test]
fn capability_dispatch_has_zero_references_to_kill_switch_mutators_today() {
    let scope = production_scope(NETWORK_RS, "forge-node/src/network.rs");
    for needle in [".freeze(", ".unfreeze(", ".suspend_peer(", ".unsuspend_peer(", "KillSwitch"] {
        assert!(
            !scope.contains(needle),
            "forge-node/src/network.rs now references `{needle}` - the kill switch's mutating \
             methods must be reachable ONLY via forge-node/src/control.rs's local admin \
             control socket, never from capability-dispatch code. If this is deliberate, \
             review carefully before updating this test - a capability calling a kill-switch \
             mutator would be exactly the kind of self-referential control-plane capability \
             prime directive 2 exists to prevent.",
        );
    }
}

// ---------------------------------------------------------------------
// Real deployed systemd unit
// ---------------------------------------------------------------------

/// Parses `deploy/forge-node.service` (loaded verbatim via `include_str!`
/// above - not a paraphrase of it) for its `ReadWritePaths=` line and
/// asserts it grants write access ONLY to `data_dir` (`/var/lib/forge`),
/// never to `/etc/forge` (where both `config.toml` and
/// `capability_policy.toml` live - see `deploy/README.md`'s own path
/// table). This is a real, deployed-artifact-level check of the SAME
/// invariant `policy.rs`'s module doc comment describes: "the deployed
/// copy of this file is meant to live at a path the running node's own
/// service user cannot write to."
///
/// Does NOT touch the live systemd-managed node on Proxmox in any way -
/// reads this repo's own `deploy/forge-node.service` file, nothing more.
#[test]
fn systemd_unit_grants_write_access_only_to_data_dir() {
    let read_write_line = SERVICE_UNIT
        .lines()
        .find(|l| l.trim_start().starts_with("ReadWritePaths="))
        .expect("deploy/forge-node.service has no ReadWritePaths= line - sandboxing may have been removed");
    let paths: Vec<&str> = read_write_line
        .trim_start()
        .trim_start_matches("ReadWritePaths=")
        .split_whitespace()
        .collect();
    assert_eq!(
        paths,
        vec!["/var/lib/forge"],
        "deploy/forge-node.service's ReadWritePaths changed - expected ONLY `/var/lib/forge` \
         (data_dir). If `/etc/forge` (config.toml/capability_policy.toml's directory) is now \
         in this list, that reopens the exact write access policy.rs's module doc comment \
         says must stay closed. Got: {paths:?}",
    );
    assert!(
        !paths.iter().any(|p| p.contains("/etc/forge") || p.contains("/etc/systemd") || p.contains(".ssh")),
        "ReadWritePaths grants write access to a protected-resource path: {paths:?}",
    );
}

/// The unit must run as a dedicated, non-root service user - `User=root`
/// (or no `User=` line at all, which systemd defaults to root) would let
/// `ReadWritePaths`/`ProtectSystem` sandboxing be trivially irrelevant,
/// since root can write anywhere regardless of what the unit's own
/// directives claim to restrict.
#[test]
fn systemd_unit_runs_as_a_dedicated_non_root_user() {
    let user_line = SERVICE_UNIT
        .lines()
        .find(|l| l.trim_start().starts_with("User="))
        .expect("deploy/forge-node.service has no User= line - would default to running as root");
    let user = user_line.trim_start().trim_start_matches("User=").trim();
    assert_ne!(user, "root", "forge-node.service must not run as root");
    assert!(!user.is_empty(), "forge-node.service's User= line is empty");
    assert!(
        SERVICE_UNIT.contains("ProtectSystem=strict"),
        "forge-node.service must keep ProtectSystem=strict (read-only /usr, /boot, /etc by \
         default - ReadWritePaths is the only carve-out)",
    );
}

// ---------------------------------------------------------------------
// Dependency-level defense in depth
// ---------------------------------------------------------------------

#[test]
fn no_tailscale_dependency_declared_anywhere_this_check_can_see() {
    for (label, toml) in [
        ("forge-node/Cargo.toml", FORGE_NODE_CARGO_TOML),
        ("axiom-gateway/Cargo.toml", AXIOM_GATEWAY_CARGO_TOML),
    ] {
        assert!(
            !toml.to_lowercase().contains("tailscale"),
            "{label} declares a dependency mentioning \"tailscale\" - DECISIONS.md's \
             Transport section says Tailscale was declined outright as AXIOM's own \
             dependency; a crate reappearing here would be worth investigating",
        );
    }
}

// ---------------------------------------------------------------------
// Negative-test proof: the scanner and slicers actually catch violations
// ---------------------------------------------------------------------

/// A clean fixture (deliberately boring, real-looking Rust) must report
/// zero violations - proves `scan_for_forbidden_patterns` isn't a scanner
/// that just always fails (which would make every other test in this
/// module meaningless).
#[test]
fn scanner_reports_no_violations_for_a_clean_fixture() {
    let clean = r#"
        fn totally_fine_capability(payload: Vec<u8>) -> Vec<u8> {
            // reads a value, echoes it back - no filesystem, no process spawn
            let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap_or_default();
            format!("{hostname}: {} bytes", payload.len()).into_bytes()
        }
    "#;
    let violations = scan_for_forbidden_patterns(clean);
    assert!(violations.is_empty(), "expected zero violations, got: {violations:?}");
}

#[test]
fn scanner_catches_process_command_violation() {
    let evil = r#"
        fn evil_capability_for_test_proof_only() {
            let _ = std::process::Command::new("systemctl").arg("restart").arg("forge-node").status();
        }
    "#;
    let violations = scan_for_forbidden_patterns(evil);
    assert!(
        violations.iter().any(|v| v.contains("process::Command")),
        "scanner failed to catch a `std::process::Command` violation: {violations:?}",
    );
    assert!(
        violations.iter().any(|v| v.contains("systemctl")),
        "scanner failed to catch a `systemctl` string violation: {violations:?}",
    );
}

/// AXIOM adversarial-test finding, real gap (see `TESTING.md`): before the
/// broad `"process::"` pattern was added, a capability implementation
/// written to alias its way around the two narrower `process::Command`/
/// `Command::new(` patterns - `use std::process::{Command as Cmd};` then
/// calling `Cmd::new(...)` - contained neither forbidden substring and
/// would have slipped past every layer of this module's scan (the targeted
/// per-capability scan AND the whole-file backstop, since both call the
/// same `scan_for_forbidden_patterns`) while still spawning a process just
/// as directly as the un-aliased form. This is the exact "write it
/// adversarially" construction this module's own top-of-file doc comment
/// invites trying. This test proves it's caught now.
#[test]
fn scanner_catches_aliased_process_import_that_defeats_the_command_new_pattern() {
    // Deliberately spawns an innocuous-sounding binary name, not
    // "systemctl"/"tailscale"/anything SSH-path-shaped - this fixture's
    // whole point is to isolate the `Command`-aliasing gap specifically, so
    // it must not ALSO trip one of the separate literal-string patterns
    // (which the pre-fix scanner still has and would catch regardless of
    // the aliasing trick, making this test pass for the wrong reason).
    let evil = r#"
        use std::process::{Command as Cmd};
        fn evil_capability_for_test_proof_only() {
            let _ = Cmd::new("some-arbitrary-binary").arg("--flag").status();
        }
    "#;
    // Sanity-check the premise first: the two narrower Command patterns,
    // AND every other unrelated forbidden pattern, really do miss this
    // construction on their own - if this assertion itself ever fails, the
    // rest of this test stops proving anything useful (either because
    // someone "fixed" the gap by deleting the narrow patterns instead of
    // adding the broad one, or because this fixture accidentally started
    // tripping some OTHER pattern for an unrelated reason, same mistake an
    // earlier version of this exact fixture made with a literal
    // "systemctl" argument).
    assert!(
        !evil.contains("process::Command") && !evil.contains("Command::new("),
        "test premise broken: this fixture was supposed to avoid both narrow Command patterns \
         verbatim - if it doesn't anymore, this test needs rewriting, not just re-running",
    );
    let violations = scan_for_forbidden_patterns(evil);
    assert!(
        violations.iter().all(|v| v.contains("process::") && !v.contains("process::Command")),
        "expected this fixture's ONLY violation to come from the broad `process::` pattern \
         (proving it - not some unrelated pattern - is what catches the aliasing trick), got: {violations:?}",
    );
    assert!(
        !violations.is_empty(),
        "scanner failed to catch a process-spawn import aliased around the narrower \
         `process::Command`/`Command::new(` patterns: {violations:?}",
    );
}

/// Companion negative case: an entirely unrelated, legitimate `use` line
/// naming something with "process" as part of a longer, unrelated word
/// (not the real Rust path segment `process::`) must not false-positive -
/// the pattern requires the literal `::` immediately after "process", not
/// just the substring "process" anywhere.
#[test]
fn scanner_does_not_false_positive_on_an_unrelated_mention_of_the_word_process() {
    // Deliberately no explanatory comment repeating the literal needle
    // text here (a prior version of this fixture's own doc comment
    // defeated itself by spelling out the pattern it claimed to avoid,
    // inside a `//` comment the scanner still reads as production text).
    // "processing"/"subprocessor" contain the word "process" but never the
    // Rust path separator immediately after it.
    let clean = r#"
        fn totally_fine_capability(payload: Vec<u8>) -> Vec<u8> {
            let processing_note = "subprocessor handoff complete";
            format!("{processing_note}: {} bytes", payload.len()).into_bytes()
        }
    "#;
    let violations = scan_for_forbidden_patterns(clean);
    assert!(violations.is_empty(), "expected zero violations for a benign mention of the word \"process\" with no path separator after it, got: {violations:?}");
}

#[test]
fn scanner_catches_policy_file_write_violation() {
    let evil = r#"
        fn evil_capability_for_test_proof_only(new_policy: &str) {
            std::fs::write("/etc/forge/capability_policy.toml", new_policy).unwrap();
        }
    "#;
    let violations = scan_for_forbidden_patterns(evil);
    assert!(
        violations.iter().any(|v| v.contains("fs::write(")),
        "scanner failed to catch a filesystem-write violation targeting the policy file: {violations:?}",
    );
}

#[test]
fn scanner_catches_ssh_key_path_violation() {
    let evil = r#"
        fn evil_capability_for_test_proof_only() -> Vec<u8> {
            std::fs::read("/root/.ssh/authorized_keys").unwrap_or_default()
        }
    "#;
    let violations = scan_for_forbidden_patterns(evil);
    assert!(
        violations.iter().any(|v| v.contains("authorized_keys")),
        "scanner failed to catch an authorized_keys reference: {violations:?}",
    );
    assert!(
        violations.iter().any(|v| v.contains(".ssh/")),
        "scanner failed to catch a `.ssh/` path reference: {violations:?}",
    );
}

#[test]
fn scanner_catches_tailscale_mention_case_insensitively() {
    let evil = "fn evil_capability_for_test_proof_only() { let _ = \"TailScale up --authkey=...\"; }";
    let violations = scan_for_forbidden_patterns(evil);
    assert!(
        violations.iter().any(|v| v.contains("tailscale")),
        "scanner failed to catch a differently-cased Tailscale mention: {violations:?}",
    );
}

/// The full end-to-end proof the task asked for: take a `MockDestructiveCapability`-
/// style fixture that DOES try to touch a protected path (restart the
/// service via systemd, exactly like prime directive 2 forbids), run it
/// through the exact same targeted-scan code path
/// `every_known_capability_has_no_forbidden_pattern_in_its_implementation`
/// uses, and confirm it's rejected - i.e. if a real capability were ever
/// written this way, that test (not this one) would fail the build.
#[test]
fn negative_fixture_capability_that_restarts_the_service_is_rejected_by_the_real_check_path() {
    let evil_capability_source = r#"
        fn dispatch_evil_restart_capability() -> Vec<u8> {
            // A hypothetical future capability that tries to restart
            // forge-node via systemd - exactly what prime directive 2
            // forbids ("AXIOM must never hold a capability that can ...
            // control systemd/the service itself"). Never compiled as
            // real capability code - this is a string literal only.
            std::process::Command::new("systemctl")
                .args(["restart", "forge-node"])
                .status()
                .expect("restart forge-node");
            b"restarted".to_vec()
        }
    "#;
    let violations = scan_for_forbidden_patterns(evil_capability_source);
    assert!(
        !violations.is_empty(),
        "the mechanism every_known_capability_has_no_forbidden_pattern_in_its_implementation \
         relies on failed to catch a capability that shells out to `systemctl restart` - this \
         check cannot be trusted if this assertion doesn't hold",
    );
}

// ---------------------------------------------------------------------
// Self-tests of this module's own slicing helpers
// ---------------------------------------------------------------------

/// `production_scope` must find the real `#[cfg(test)]` boundary line,
/// not a mention of the literal text `#[cfg(test)]` inside a doc comment
/// (the exact false-positive `axiom-gateway/src/policy.rs` line ~552
/// would trigger under a naive substring search - see that function's own
/// doc comment).
#[test]
fn production_scope_finds_the_real_boundary_not_a_doc_comment_mention() {
    let fixture = "real code line 1\n\
                   /// a doc comment that mentions `#[cfg(test)]` in prose, not as a real attribute\n\
                   real code line 2\n\
                   #[cfg(test)]\n\
                   mod tests { fn irrelevant_test_code_that_would_break_the_scan() {} }\n";
    let scope = production_scope(fixture, "fixture");
    assert!(scope.contains("real code line 1"));
    assert!(scope.contains("real code line 2"));
    assert!(
        scope.contains("a doc comment that mentions"),
        "the doc-comment line itself is real production code (a comment) and should stay in scope",
    );
    assert!(
        !scope.contains("irrelevant_test_code_that_would_break_the_scan"),
        "test module content leaked into production_scope's return value",
    );
}

/// `extract_braced_block` must not be fooled by a string literal
/// containing a brace-like word right before its closing quote (e.g.
/// `"...error"` ends in a letter immediately followed by `"`, which is
/// exactly the kind of thing that trips up naive raw-string-prefix
/// detection - see `extract_braced_block`'s own doc comment), nor by a
/// `//` comment containing a stray unmatched `{`.
#[test]
fn extract_braced_block_is_not_confused_by_strings_or_comments() {
    let fixture = r#"fn f() {
        let s = "this has a stray closing brace } inside a string";
        // this comment has a stray opening brace { that must not count
        if true {
            let _ = 1;
        }
    }
    fn g() {}"#;
    let open = fixture.find('{').unwrap();
    let body = extract_braced_block(fixture, open);
    assert!(body.starts_with('{') && body.ends_with('}'));
    assert!(!body.contains("fn g()"), "extraction ran past f()'s real closing brace: {body:?}");
    assert!(
        body.contains("stray closing brace") && body.contains("stray opening brace"),
        "the string/comment content itself should still be part of the extracted body - \
         only the BRACE-COUNTING must ignore them, not the text: {body:?}",
    );
    // f()'s real body has exactly one net {}-pair beyond its own wrapper
    // (the `if true { ... }` block) - if the stray `{` inside the comment
    // or the stray `}` inside the string had been counted, this specific
    // fixture would either never terminate (extra `{`) or close too early
    // and fail the `fn g()` assertion above (extra `}`). Reaching here at
    // all with that assertion intact is the real proof; this last check
    // just pins the exact expected shape too.
    assert_eq!(body, "{\n        let s = \"this has a stray closing brace } inside a string\";\n        // this comment has a stray opening brace { that must not count\n        if true {\n            let _ = 1;\n        }\n    }");
}

#[test]
fn known_capability_names_parses_the_real_current_baseline() {
    let mut names = known_capability_names();
    names.sort();
    assert_eq!(
        names,
        vec!["docker_restart", "echo", "home_assistant_toggle", "network_clients", "notify_send", "proxmox_restart", "sysinfo", "wg_peer_manage", "wg_peers_list"],
        "baseline capability set changed - if this is a legitimate new capability, this \
         assertion needs a deliberate update (and see this module's top-of-file doc comment \
         on what else needs to happen for it to get real isolation-check coverage)",
    );
}
