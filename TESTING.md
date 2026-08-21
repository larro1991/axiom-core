# AXIOM adversarial test suite

This document is evidence, not marketing copy. It lists every adversarial
scenario attempted against AXIOM's claimed security guarantees, the real
Rust test that attempts it, and the actual result — including the cases
where the attempt found something and a fix was required. If you're
evaluating whether this project's security claims (`SECURITY.md`,
`DECISIONS.md`) are real, this is where you check.

**Method.** For every scenario below, the test tries to make the claimed
guarantee fail — bypass an allowlist, defeat a scanner, replay an approval,
smuggle a control character — and asserts the attack is blocked. A test
that only re-verifies documented happy-path behavior is not listed here as
an "adversarial" result; several already existed in the codebase before
this pass and are noted as prior art rather than re-claimed.

**Result of this pass, stated plainly up front:** three genuine gaps were
found. All three were confirmed real (the new test was run against the
pre-fix code and observed to fail, not just written and assumed to catch
something) and fixed in the same change that adds this document. Everything
else attempted was already correctly blocked. A test suite that only ever
reports green either found nothing real or is hiding something — this one
found three real things and is not hiding them.

| # | Fix | Severity if left unfixed |
|---|-----|---------------------------|
| 1 | Protected-resource MAC scanner missed whitespace-obfuscated MACs | Low today (no live capability accepts a raw MAC parameter yet) — real for any future one that does |
| 2 | Capability-isolation scanner's `Command::new(` check could be defeated by import aliasing | Would have let a hostile capability addition spawn an arbitrary process undetected by the automated regression check |
| 3 | `Tier2ApprovalFlow::decide_and_execute` had no guard against being invoked twice for the same intent | **Real and serious**: a duplicate/replayed trigger could execute a Tier 2 action (e.g. `wg_peer_manage` create) a second time from one human approval, or overturn an already-recorded **denial** into an execution |

Full workspace build/test commands (what was actually run to produce every
result below):

```
cargo build --workspace --release
cargo test --workspace --release
```

Test counts, this exact change, `cargo test --workspace --release`:

| | Before | After |
|---|---|---|
| Unit tests passed | 841 | 855 (+14) |
| Unit tests failed | 0 | 0 |
| Unit tests ignored | 1 | 1 (unchanged) |
| `axiom-gateway` crate | 107 | 115 |
| `forge-node` crate | 187 | 193 |

---

## 1. Fail-closed policy loading

Claim (`axiom-gateway/src/policy.rs`): a policy file that doesn't exist,
doesn't parse, declares an unsupported schema version, or is missing a
required field for a given capability fails **that capability closed**, or
the **whole file** closed, per a documented, deliberate contract — never
silently permissive.

This machinery already had extensive real (not happy-path) tests before
this pass — malformed TOML, a real pre-v2 schema file, a missing `tier`
field, an invalid tier name, a TOML-type-mismatched `tier` (whole-file
fatal, deliberately, and tested as such), an empty `allowed_peers`, and a
Tier1/Tier2 capability with no `[[protected_resource]]` section at all.
Verified these are genuine (not decorative) by reading `try_load` and
confirming each documented failure path has a corresponding assertion, not
just a docstring claim.

| Scenario | Result |
|---|---|
| Missing policy file | Blocked — every capability denies (prior test) |
| Malformed TOML | Blocked — every capability denies (prior test) |
| Wrong schema version (`version = 3`, and a real pre-v2 file) | Blocked, both cases distinguished (prior tests) |
| Capability with no `[capability.<name>]` entry | Blocked, only that capability (prior test) |
| Capability entry with empty `allowed_peers` | Blocked, only that capability (prior test) |
| Capability with no `tier` field | Blocked, only that capability (prior test) |
| Capability with an invalid tier name | Blocked, only that capability (prior test) |
| Tier1/Tier2 capability with no `[[protected_resource]]` section at all | Blocked, only Tier1+ (Tier0 unaffected) (prior test) |
| Rapid-fire requests beyond a capability's rate limit (DoS-shaped) | **New adversarial test**, `policy::tests::rapid_fire_requests_beyond_the_rate_limit_are_all_denied_until_the_window_passes` — 50 rapid-fire calls inside a 1-second window all denied, no off-by-one; re-admits exactly one call once the window genuinely passes, no burst of previously-denied calls let through |

No gap found here — the existing fail-closed machinery is exactly as
strict as documented.

## 2. Protected-resource list bypass attempts

Claim: a Tier 2 proposal whose parameters reference a protected device (by
MAC, primary key, or secondary IP) is rejected before a human ever sees an
approval prompt — regardless of case, separator, or embedding in a larger
string.

Prior tests already covered case-insensitivity (`aa:bb:cc` vs `AA:BB:CC`),
separator-insensitivity (`:` vs `-`), a MAC embedded inside a longer
description string, and adversarial UTF-8 input that must not panic the
byte-index scanner.

**Real gap found and fixed (#1 above).** `scan_mac_candidates` matches a
MAC only in an exact 17-byte window (`xx:xx:xx:xx:xx:xx`). A value that
spells out the *same* protected MAC with extra ASCII whitespace inserted
around its separators — `"aa : bb : cc : 11 : 22 : 01"`, still
unambiguously the same MAC to a human, or to a future capability's own
whitespace-trimming parser — slides every candidate window off alignment
and was missed entirely.

Confirmed real by writing the test first, running it against the
unmodified code, and observing it fail:

```
test policy::tests::find_protected_match_detects_a_mac_obfuscated_with_internal_whitespace ... FAILED
panicked: whitespace-obfuscated protected MAC "aa : bb : cc : 11 : 22 : 01" must still be caught
```

Fixed by adding a second scan pass over a whitespace-stripped copy of the
haystack (`scan_mac_candidates_including_whitespace_obfuscated`, in
`axiom-gateway/src/policy.rs`), deliberately biased toward *more*
detection — a false-positive protected-resource match costs a human
re-proposing; a missed one costs the resource. A negative test
(`whitespace_stripped_scan_does_not_match_an_unrelated_mac`) confirms this
doesn't turn into a blunt "match everything" filter.

Practical severity today: **low**. No live capability currently accepts a
raw MAC address as a caller-supplied parameter (`wg_peer_manage` takes a
peer *name*, `docker_restart` a container name, `home_assistant_toggle` an
entity ID) — this scanner is forward-looking infrastructure for a future
capability that would. Fixed anyway, since it's cheap, correct, and the
next capability that does take a MAC parameter shouldn't inherit a known
gap silently.

| Scenario | Result |
|---|---|
| Case variation (`AA:BB:CC` vs `aa:bb:cc`) | Blocked (prior test) |
| Separator variation (`:` vs `-`, mixed within a value) | Blocked (prior test) |
| MAC embedded in a longer string | Blocked (prior test) |
| **MAC obfuscated with internal whitespace around separators** | **Was a real bypass — now fixed**, see above |
| IPv4-mapped IPv6 form (`::ffff:192.168.1.14`) embedding a protected IP | Blocked — **new adversarial test**, `find_protected_match_detects_protected_ip_inside_an_ipv6_mapped_form`; the dotted-quad scanner finds the embedded IPv4 form regardless of the IPv6 prefix, no special-casing needed |
| Adversarial/malformed UTF-8 (emoji, truncated windows, near-miss lengths) | Never panics (prior test) |

## 3. Tier 2 approval flow attacks

Claim (`axiom-gateway/src/approval.rs`): an intent that expires mid-approval
cannot execute; tampered parameters are caught via a hash bound at proposal
time; a denial or channel failure never executes; no standing approvals.

Prior tests already covered: expiry crossing mid-decision, tampered
parameters rejected via hash mismatch, decision on an unknown intent,
execution failure recorded distinctly from denial, a protected-resource
proposal never reaching the approval channel at all.

**Real gap found and fixed (#3 above, the most serious of the three).**
`decide_and_execute` had no guard against being invoked more than once for
the same `IntentId`. `IntentStatus`'s own doc comment already *documented*
"an intent only ever moves forward through this sequence once, none of
these retry automatically" as an invariant — but nothing enforced it. A
second call would re-consult the approval channel and, if it returned
`approved: true`, call `capability.execute` a **second time**.

Confirmed real with two tests, both run against the pre-fix code and
observed to fail before the fix was applied:

```
test approval::tests::decide_and_execute_called_twice_on_the_same_intent_executes_at_most_once ... FAILED
  assertion `left == right` failed: capability must still have executed exactly once
  left: 2   (it executed twice)
  right: 1

test approval::tests::a_recorded_denial_cannot_be_overturned_by_a_later_decide_and_execute_call_that_would_approve ... FAILED
  assertion `left == right` failed: the ORIGINAL decision must stand
  left: Executed   (a recorded DENIAL was overturned into an execution)
  right: Denied
```

The second result is the one worth sitting with: a real "no" from the
approver, already recorded as `Denied`, got silently converted into
`Executed` on a second call. For the live `wg_peer_manage` capability, a
double-execution of the `Create` action would provision a **second**
WireGuard peer — with its own distinct private key — from a single human
approval.

Fixed with a guard at the top of `decide_and_execute`: once an intent's
status has left `Pending`, every later call is an idempotent read of the
already-recorded terminal status — the channel is never consulted again,
and `capability.execute` is never reached again, no matter what a second
(possibly different, possibly replayed) channel response would say.

This wasn't reachable through today's real dispatch path — `forge-node`'s
`dispatch_wg_peer_manage` calls `propose` (which mints a fresh random
`IntentId` every time) immediately followed by exactly one
`decide_and_execute` call in the same spawned task, so no live code path
currently invokes it twice. It matters anyway: `axiom-gateway` is
explicitly designed as a standalone, embeddable crate (`DECISIONS.md`'s
"ecosystem positioning" — Conduit's Burr Phase 2 is the named future
consumer), and an API whose safety property is "don't call this twice,
because nothing stops you if you do" is not actually safe by construction.
It is now.

**Second real gap found and fixed, 2026-08-18 (Fable's independent second review).** The fix above
only closed the *sequential* replay case — a second call arriving after the first has already
finished. It did not close the *concurrent* case: two calls for the same `IntentId` arriving before
either has finished would both observe `Pending`, both consult the channel, and both execute. Not
reachable through today's real dispatch path (same reasoning as above), but the same
"designed-to-be-embedded" argument applies just as directly to concurrent callers as it does to
retrying ones.

Confirmed real with a genuinely concurrent test — not just two calls in quick succession, which
turned out to be a real trap: an early version of this test used a plain synchronization barrier
before both threads called `decide_and_execute`, with no artificial delay in the channel. It PASSED
even with the fix's claim line disabled, because the non-blocking test channel answered so fast that
the two threads simply ran sequentially in practice — the *existing* terminal-status guard was
accidentally covering a test that wasn't actually testing concurrent overlap at all. Fixed by making
the test channel signal the instant it's entered and then sleep, so a second thread can be held back
(bounded spin-poll, not a fixed sleep) until it has *verified proof* the first call is genuinely
mid-flight before starting its own call:

```
test approval::tests::decide_and_execute_called_concurrently_on_the_same_intent_executes_at_most_once ... FAILED
  assertion `left == right` failed: two genuinely concurrent decide_and_execute calls on the same
  intent must still execute at most once
  left: 2   (it executed twice)
  right: 1
```

Fixed with an `IntentStatus::InProgress` state, claimed atomically (under the same lock that
observes `Pending`) before the lock is released to consult the channel. A concurrent second caller
now sees `InProgress`, not `Pending`, and takes the same early-return path any other non-`Pending`
status already took — reading back the current status non-blocking, consistent with how this
function has always behaved, rather than blocking to wait for the first call's eventual result.

| Scenario | Result |
|---|---|
| Intent expires mid-approval, then a late "approve" arrives | Blocked (prior test) |
| Replay of an already-consumed intent ID | Blocked — see finding #3 above (now fixed) |
| Two concurrent proposals for the same target | Independent — each gets its own random `IntentId`; approving one cannot resolve the other (prior test, `Tier2ApprovalFlow` records keyed by `IntentId`; separately re-proven at the Telegram channel layer, see §4) |
| Tampered parameters between proposal and approval | Blocked via hash mismatch (prior test) |
| **A denial followed by a resend of the same approve callback / a repeat `decide_and_execute` call** | **Was a real bypass at the state-machine layer — now fixed**, see above. Confirmed separately blocked at the Telegram channel layer (§4) |
| Decision on an unknown/unregistered intent | Clean error, no panic (prior test) |

## 4. Telegram approval channel attacks

Claim (`forge-node/src/telegram_approval.rs`): only a `callback_query` from
the configured `chat_id` is ever honored; a reply is matched to its exact
intent via the full intent ID embedded in `callback_data`, never "whichever
message is most recent."

Prior tests covered: authorized approve/deny, an unauthorized `chat_id`
correctly ignored (and not consuming the real waiter), two concurrent
pending intents resolving independently, a reply to an intent this node
never registered.

**New adversarial test, attack confirmed blocked (no fix needed):** the
exact double-spend shape named in this project's adversarial test brief —
deny an intent for real, then immediately resend the *identical* `approve`
callback_data for that same intent (a Telegram client retry, duplicate
delivery, or deliberate replay).

```
test telegram_approval::tests::resent_approve_callback_after_the_intent_was_already_denied_does_not_flip_the_decision ... ok
```

`process_update` removes the pending waiter's channel the first time it
resolves an intent; the replayed callback finds nothing left to resolve and
is treated identically to a reply for an intent that was never registered
— logged, acknowledged to the Telegram user as "no longer pending," and
otherwise a no-op. The original `Denied` decision, already delivered,
cannot be overwritten.

| Scenario | Result |
|---|---|
| Chat-id authentication (wrong Telegram user tapping the button) | Blocked, real waiter untouched, later real reply still resolves it (prior test) |
| Two concurrent pending intents don't cross-resolve | Blocked (prior test) |
| Reply to an unknown/never-registered intent | Safe no-op (prior test) |
| **Denial followed by an immediate resend of the same approve callback (double-spend)** | **Blocked — new adversarial test**, confirmed above |

## 5. Capability isolation / self-modification attempts

Claim (`forge-node/src/capability_isolation.rs`): no capability can touch
the policy file, the audit log, spawn a shell, or write outside its
declared scope — enforced by an automated forbidden-pattern scan over every
capability's real source, run on every `cargo test`.

**Real gap found and fixed (#2 above).** The task brief explicitly invited
constructing a capability addition "written adversarially" to see if it
would slip past the scanner. It does, for one specific technique: the
scanner's process-spawn detection was two literal-substring patterns,
`"process::Command"` and `"Command::new("`. Rust's `use ... as` import
aliasing defeats both at once:

```rust
use std::process::{Command as Cmd};
fn evil_capability() {
    let _ = Cmd::new("some-arbitrary-binary").arg("--flag").status();
}
```

This contains neither `"process::Command"` (broken by the `{` of braced
import syntax) nor `"Command::new("` (the type was renamed) — while
spawning a process exactly as directly as the un-aliased form would.
Confirmed real by running the new test against the pattern list *before*
adding the fix:

```
test capability_isolation::scanner_catches_aliased_process_import_that_defeats_the_command_new_pattern ... FAILED
panicked: scanner failed to catch a process-spawn import aliased around the
narrower `process::Command`/`Command::new(` patterns: []
```

(The fixture was deliberately checked for contamination from other
patterns — an earlier draft used `"systemctl"` as the spawned binary name
and accidentally passed for the wrong reason, caught by that pattern
instead of the one under test. The final fixture spawns an
innocuous-sounding binary name and asserts the *specific* pattern that
fires.)

Fixed by adding a broader pattern — `"process::"`, case-insensitive, no
`Command` required — on the reasoning that legitimate capability handler
code (everything here goes through `uai_dispatch`'s `reqwest` HTTP client)
has zero legitimate reason to import anything from *any* process module
under *any* alias. Verified this introduces no false positive against the
real embedded source files (their only `process::` mentions —
`std::process::id()`, for unique test temp-file names — live inside
`#[cfg(test)]`, outside every scope this scanner covers) and added a
negative test confirming an unrelated mention of the word "process" (with
no path separator after it) doesn't trip the new pattern.

| Scenario | Result |
|---|---|
| Direct `Command::new(...)` / `process::Command` in capability code | Blocked (prior test) |
| Direct filesystem write/delete primitives (`fs::write`, `OpenOptions`, ...) targeting the policy file | Blocked (prior test) |
| Direct mention of `systemctl`, `/etc/systemd`, `tailscale`, SSH key paths | Blocked, case-insensitively (prior test) |
| **Import-aliased process spawn (`use ... as Cmd`) evading the `Command::new(` pattern** | **Was a real, constructible bypass — now fixed**, see above |
| `CapabilityPolicy`/`AuditLog`'s own public API surfaces for a destructive method | None exists (prior test) |
| Real deployed systemd unit file: write access outside `data_dir`, running as root | Neither (prior test) |

**Honest, unfixed residual note** (not something this pass claims to have
closed, stated rather than hidden): this scanner is still a literal-pattern
scan, not a real parser. It doesn't (and structurally can't, without a full
Rust AST) catch a process spawned via a completely different crate (e.g.
`libc::execve` or `nix::unistd::execv`) — but neither `libc` nor `nix` is a
dependency of `forge-node` today (`forge-node/Cargo.toml` has no
`[dependencies]` entry for either), and adding one would itself be a
visible, reviewable diff. The scanner's own documented limitation — a
brand-new capability whose handler lives in a file other than
`network.rs` only gets Layer 1's list-drift check, not the forbidden-
pattern scan — is unchanged by this pass and was already honestly stated
before it.

## 6. Sanitization bypass attempts

Claim (`axiom-gateway/src/sanitize.rs`): every string field in untrusted
external content (device hostnames, SSIDs) is length-capped, stripped of
control characters and ANSI/terminal escape sequences and Unicode
bidi-override tricks, and wrapped in a structural (not textual) envelope
before it can reach an AI's context or a log file.

Prior tests already covered: oversized fields flagged not silently
truncated (including the exact boundary), C0 control characters and DEL,
CSI escape sequences removed as whole units (not just the leading ESC),
OSC sequences terminated by BEL, bidi-override characters, injection-style
text preserved as inert data rather than specially parsed, recursive
sanitization through nested arrays/objects, and a hostile string that
cannot spoof the structural envelope boundary.

No exploitable gap found. Two adversarial gaps in **test coverage** (not in
the mechanism itself — read the implementation directly to confirm before
writing these) were closed:

| Scenario | Result |
|---|---|
| Oversized payload just under/at/over the length cap | Blocked, flagged not silently truncated (prior test) |
| Nested/double-encoded control characters via JSON escapes | Inert — JSON escapes decode to real characters before this module ever sees them; the module strips the real character regardless of how it was encoded upstream (implied by existing control-char tests, JSON decoding happens once, in `serde_json`, before `sanitize_json_strings` runs) |
| Right-to-left override / bidi Unicode tricks | Stripped (prior test) |
| ANSI CSI escape sequence | Removed as a whole unit (prior test) |
| ANSI OSC sequence, BEL-terminated | Removed as a whole unit (prior test) |
| **ANSI OSC sequence, ST (`ESC \`) terminated — the OTHER documented terminator, previously untested** | Removed as a whole unit — **new adversarial test**, `ansi_osc_escape_sequence_terminated_by_st_is_removed` |
| **Payload built entirely from an unterminated CSI/OSC sequence (no final byte / no BEL / no ST anywhere) — DoS-shaped, targeting the escape-stripping scan's loop termination** | Fully consumed without panicking or looping — **new adversarial test**, `unterminated_escape_sequences_are_fully_consumed_without_panicking_or_looping` |
| Payload crafted to look like valid JSON structure to a naive downstream parser | Inert — the structural envelope (a real JSON object boundary, not a text prefix) means a compliant JSON parser treats embedded quotes/braces as literal string content, never as siblings of the envelope (prior test, `a_hostile_string_cannot_spoof_the_envelope_boundary`) |

## 7. Hard-coded allowlist bypass attempts

Claim: `docker_restart`'s 4-container allowlist and `home_assistant_toggle`'s
5-domain allowlist cannot be defeated by case variation, whitespace,
Unicode homoglyphs, path-traversal-shaped strings, or injection-shaped
strings (even though this isn't a shell/SQL context).

Prior tests already covered: injection-shaped payloads (`"infra-watchtower;
rm -rf /"`), path-traversal-shaped payloads (`"../etc/passwd"`), and
case-insensitive matching for the two `HARD_DENIED_*` blocklists
(`docker_restart`'s `ai-uai`/`forge-node`, `wg_peer_manage`'s
`larry-laptop`/`phone` — both deliberately case-insensitive, since a
blocklist should err toward denying more, not less).

New adversarial tests target the **inverse** direction — the allowlists
themselves, which use case-sensitive exact-string matching — confirming a
case-varied or homoglyph spelling of a genuinely-allowed name is correctly
**rejected**, not fuzzy-matched into a false positive:

| Scenario | Result |
|---|---|
| Case-varied spelling of an allowlisted container name (`"Infra-Watchtower"`, `"INFRA-WATCHTOWER"`) | Rejected — **new adversarial test**, `parse_rejects_case_varied_spelling_of_an_allowlisted_name` |
| Case-varied spelling of an allowed Home Assistant domain (`"Light"`, `"LIGHT"`) — and, symmetrically, a case-varied *forbidden* domain (`"LOCK"`) | Both rejected (allowlist, not blocklist — no case-sensitivity direction is exploitable) — **new adversarial test**, `parse_rejects_case_varied_domain_even_for_an_otherwise_allowed_domain_name` |
| Unicode homoglyph domain (Cyrillic `і` U+0456 standing in for Latin `i` in `"light"`) | Rejected — **new adversarial test**, `parse_rejects_unicode_homoglyph_domain_that_visually_resembles_an_allowed_domain` — Rust string equality compares exact Unicode scalar values, not visual rendering |
| Injection-shaped container name (`"infra-watchtower; rm -rf /"`) | Rejected by charset validation before the allowlist is even consulted (prior test) |
| Path-traversal-shaped container name (`"../etc/passwd"`) | Rejected by charset validation (prior test) |
| Hard-denied name case variation (`"AI-UAI"`, `"LARRY-LAPTOP"`) | Denied regardless of case (prior tests, both capabilities) |

## 8. Key-material leakage attempts for `wg_peer_manage`

Claim: no code path returns, logs, or forwards the raw response from
`wg_client_config`/`wg_client_qr` (which embed WireGuard private keys) —
`wg_peer_manage` calls only `wg_create_client`/`wg_delete_client`/
`wg_enable_client`/`wg_disable_client`, and even `wg_create_client`'s own
response (which *does* embed the new peer's private key, as an unavoidable
consequence of how wg-easy's provisioning API works) is never forwarded
wholesale.

This was already covered by real, structural (not string-eyeballing)
regression tests in `forge-node/src/network.rs`'s own test module — not
`capability_isolation.rs` as one internal doc comment slightly imprecisely
points to; the tests exist, just in the neighboring file:

- `fetch_wg_peers_list_never_calls_a_key_bearing_or_mutating_wg_easy_tool` —
  confirms the read-only capability never references
  `wg_client_config`/`wg_client_qr`/any mutating tool.
- `wg_peer_manage_perform_never_calls_a_key_bearing_wg_easy_tool` — confirms
  the write capability never references the two key-bearing tools either.
- `wg_peer_manage_perform_never_forwards_the_raw_create_response_wholesale`
  — confirms `perform()` contains no logging-macro call at all, and pulls
  only the `id` field out of the create response (never `{:?}`-debug-
  formats the full reply).

No gap found. No new test added here beyond what already existed — these
were read in full and confirmed to be real structural checks (they extract
the actual function body from the real source and scan it, the same
technique `capability_isolation.rs` uses), not just asserting a claim.

## 9. Rate-limit / DoS-shaped attempts

Covered under §1 (rapid-fire requests beyond a capability's configured
rate limit) — see that section's table. No off-by-one found; the limiter
correctly denies every request inside the window and re-admits exactly one
once it genuinely passes.

One property intentionally **not** treated as a bug: rate-limit state
(`CapabilityPolicy::rate_limit_state`) is in-memory and reset on process
restart. This is inherent to the current design (no persistent rate-limit
store exists anywhere in this codebase) and is a reliability/DoS-shaped
property, not an authorization boundary — restarting `forge-node` doesn't
grant any capability access it didn't already have, it just resets a
courtesy throttle. Worth knowing, not worth fixing as part of this pass.

---

## What this pass did not attempt, and why

- **Live network round-trips against real infrastructure** (a real
  Telegram bot, a real UAI broker, a real WireGuard/Omada backend) — out of
  scope per this task's own instruction not to disrupt the live
  `forge-node.service`. Every test above runs offline, against pure
  functions or in-memory fixtures, the same pattern the pre-existing test
  suite already established.
- **Fuzzing** — not attempted as an automated campaign; the adversarial
  inputs above were chosen by reading the implementation and reasoning
  about its parsing/scanning logic, not generated blindly. A dedicated
  fuzz harness (e.g. `cargo-fuzz` against `scan_mac_candidates`,
  `sanitize_str`, the TOML policy parser) would be a reasonable follow-up
  but is a different, larger effort than this pass.
- **`libc`/`nix`-based process spawning bypassing the capability-isolation
  scanner** — noted honestly in §5 as a real but currently-unreachable gap
  (neither crate is a dependency today); not fixed, since there's nothing
  live to fix yet and speculative pattern-list entries for dependencies
  that don't exist would be untested noise.

## Reproducing this from scratch

```
git clone <this repo>
cd axiom-core
cargo build --workspace --release
cargo test --workspace --release
```

Every test named above is a normal `#[test]`/`#[tokio::test]` in the
crate's own source (`axiom-gateway/src/policy.rs`,
`axiom-gateway/src/approval.rs`, `axiom-gateway/src/sanitize.rs`,
`forge-node/src/network.rs`, `forge-node/src/capability_isolation.rs`,
`forge-node/src/telegram_approval.rs`) — run individually with
`cargo test -p <crate> --release <test_name>`, no special harness or flag
required.
