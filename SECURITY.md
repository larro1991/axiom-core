# AXIOM Security Notes

This file tracks security-relevant properties of `forge-node` that aren't
obvious from reading any single source file in isolation - things an
operator or a future contributor needs to know before changing capability
policy, credential wiring, or dependency-facing trust assumptions. Add a
section per finding; don't delete old ones, mark them resolved instead.

## Reporting a vulnerability

Prefer this repo's Security tab -> "Report a vulnerability" (GitHub's private disclosure path) if it's available when you look - anything that isn't safe to make public before a fix ships belongs there, not in a public issue. If that option isn't there, open a [GitHub Issue](https://github.com/larro1991/axiom-core/issues) marked clearly as security-related in the title (e.g. `[SECURITY] ...`), and use judgment about how much detail is safe to include publicly before a fix exists.

What to expect: this is a single-owner personal project, not a company with an SLA. Reports get read and taken seriously, but response time depends on the owner's availability, not a contractual guarantee.

**Evidence, not just assertions**: **[TESTING.md](TESTING.md)** is a real, executable adversarial test suite that actively tries to defeat the guarantees this file claims — bypass the fail-closed policy loader, evade the capability-isolation scanner, replay a Tier 2 approval, smuggle content past the sanitizer — and records the actual result, including the cases where an attempt found a real gap and what was fixed. Read it if you want to verify these claims rather than take them on faith.

## Threat model, plainly

**Who this protects against**: an AI agent (or anything else with a valid signed identity) attempting to do something on your infrastructure beyond what you explicitly allowed it to do — accidentally, through a bug, or because it was manipulated by something it processed.

**What the wall actually is**: `capability_policy.toml`, evaluated fresh on every request, on the machine whose capabilities are being gated. It answers one question per request — "is this specific signed caller allowed to invoke this specific capability, right now" — and for Tier 2, adds "did a human just approve this exact request." Nothing bypasses this check; there is no capability that can grant itself more access.

**What it assumes**: a single trusted owner who controls the policy file and the approval channel. AXIOM does not implement multi-tenant isolation, RBAC, or any notion of "some humans are more trusted than others" — that's Conduit's problem when/if it embeds this gateway, not this project's.

**What it does NOT do**: AXIOM constrains what flows *through* the gateway on your own infrastructure. It does not audit, harden, or control the internal security of third-party backends a capability happens to call into (see "Known limitations" above for the concrete example — UAI's broker has no per-caller tool authorization of its own, and AXIOM's hard-coded allowlists are a mitigation for that gap, not a fix to it). If a capability's backend is itself compromised or misconfigured, AXIOM's guarantee is "only this specific allowlisted caller could have reached it, and this specific action was approved" — not "the backend itself is safe."

## Known limitations (read this first)

This project has real, honestly-documented open issues. None are silent — each is detailed in its own section below, but the short version for anyone evaluating this codebase:

1. **The UAI credential-scoping gap applies to every AXIOM capability that bridges to UAI, not just `network_clients`.** `notify_send`, `proxmox_restart`, `docker_restart`, `home_assistant_toggle`, `wg_peers_list`, and `wg_peer_manage` all dispatch through the same UAI broker whose `/registry/dispatch` endpoint has no per-caller tool authorization at all (see "AXIOM -> UAI credential scope" below). AXIOM's own defense-in-depth (hard-coded allowlists, protected-resource lists, Tier2 human approval) constrains what each *capability* can do once dispatched, but if the underlying UAI token itself were ever exfiltrated, it is not scoped by UAI's own broker to only the tools AXIOM intends to use. `network_clients` was hard-denied outright over this; the newer capabilities accept the residual risk with layered mitigations instead — read each capability's own reasoning before assuming any of them are immune to this.
2. ~~Tier 2 human approval has a cross-consumer race when its Telegram channel shares a bot token with another long-polling consumer~~ — **resolved 2026-08-15**: AXIOM now uses a dedicated bot token (`@AxiomApprovalBot`), not PM's shared one. See "Tier 2 credential/auth scope" below.
3. ~~The native Windows port has known gaps: no control socket, explicit-connect path broken, `bootstrap_nodes` broken through a VPN~~ — **resolved 2026-08-18**: named-pipe control socket built and live-verified; the explicit-connect and `bootstrap_nodes` failures were root-caused to a Windows host's WireGuard tunnel silently winning the route to the target over the intended LAN path, not a code defect — fixed with a persistent host route. Windows now has full parity with Linux for both passive reachability and originating actions.

None of this is unusual for a project at this stage — it's listed here because the alternative (silence) is worse. Contributions addressing any of the above are welcome.

## AXIOM -> UAI credential scope (AXIOM Phase 1.4)

**Status: unresolved, `network_clients` hard-disabled in code pending an
[OWNER GATE] decision. See "What changed in the code" below.**

### What credential AXIOM holds, and how

The only AXIOM capability that talks to anything outside its own peer
mesh is `network_clients` (`forge-node/src/network.rs`, AXIOM-10). It
bridges to a TP-Link Omada SDN controller via the UAI broker
(`http://<uai_base_url>`, e.g. `http://192.168.1.11:7700` - configured
per-node, never committed to source, see `NodeConfig::uai_base_url` /
`NodeConfig::uai_token` in `forge-node/src/config.rs`).

The credential AXIOM itself holds long-term is a single UAI broker
**caller token**, sent as the `X-UAI-Token` header on every request to
`{uai_base_url}/registry/dispatch` (`UaiConfig::token`,
`fetch_network_clients` in `network.rs`). This is a generic UAI *identity*
token, not an Omada-specific credential - UAI's `uai_broker.py`
(`_require_auth`) treats it exactly like any other registered caller
(`uai_callers` entries in UAI's `uai_secrets.json`; existing entries at
the time of this review: `mcp-local`, `pm-agent`, `conduit`,
`agent-library` - `forge-node`/`axiom` had no entry provisioned, i.e. this
capability has never actually been live-usable).

The *Omada controller* password is never held by AXIOM at all except for
the duration of a single `network_clients` call: on each call,
`fetch_network_clients` asks UAI's `keepass_lookup` tool for the "omada
controller (Local)" KeePass entry (with `password: true` - see the note
below on why that matters), gets back a username/password pair, uses it
for exactly one `omada_clients` call, and (as of this change) zeroes both
values out of memory before returning. AXIOM never writes the Omada
password to disk, config, or logs at any point.

**Correction to a pre-existing code comment**: `network.rs`'s doc comment
on `fetch_network_clients` used to say "AXIOM never sees the Omada
password directly." That's not accurate - the code passes
`{"password": true}` to `keepass_lookup`, which does return the plaintext
password, and AXIOM's process does briefly hold it. The comment has been
corrected in this change. The property that actually holds is narrower:
AXIOM never *persists* the password, and (as of this change) actively
zeroes its one in-memory copy after use. See "What changed in the code"
below.

### What the `X-UAI-Token` credential can actually do

This is the part that matters for scope, and it's worse than
`network_clients`'s own code path implies. Investigated directly against
UAI's own source (`/mnt/Main/appdata/uai/` on the Proxmox host - `uai`
is a separate platform from `axiom-core`, not this repo):

- `uai_broker.py`'s `_require_auth()` checks only *whether* the presented
  `X-UAI-Token` matches *any* registered caller in `uai_callers`. On a
  match it sets `request.uai_caller = <caller name>` and returns - it
  does not consult that value again anywhere.
- `POST /registry/dispatch` (`registry_dispatch()` in `uai_broker.py`)
  takes `{tool_name, input_args}` from the request body, checks only that
  `tool_name` exists in the registry (`REGISTRY.has_tool`), and calls
  `REGISTRY.dispatch(tool_name, input_args, DRIVERS)`
  (`uai_registry.py`). **`request.uai_caller` is never passed into this
  call, checked against `tool_name`, or checked against `input_args` in
  any way.** There is no code path anywhere in `uai_broker.py` or
  `uai_registry.py` that restricts which registered tools a given caller
  may invoke.
- `uai_secrets.json`'s `uai_callers` entries DO carry fields that look
  like a scoping mechanism - `allow_all` (boolean) and, for at least one
  caller (`conduit`), `allowed_drivers` (a list). **Neither field is read
  anywhere in the broker or registry code.** Grepping the entire UAI
  source tree for `allow_all`/`allowed_drivers` turns up only the
  `uai_secrets.json` schema itself and `uai_broker.py`'s definition of
  `_callers()` - never a comparison against `request.uai_caller` or
  `tool_name`. This is dead configuration: it documents an intent that
  was never wired up, not an enforced control.
- Confirmed via the live registry database (`uai_registry.db`, queried
  read-only through the running `ai-uai` container - no write attempted):
  **2008 registered tools across 206 drivers**, at the time of this
  review. For the `omada` driver specifically, only two tools are
  registered: `omada_clients` (read) and `omada_health` (read) - no
  write/action tool exists for Omada today. That's incidental, not
  enforced: nothing stops a future UAI driver update from registering a
  write-capable Omada tool (e.g. block/reconnect a client), and the
  moment that happens, ANY caller holding ANY valid `X-UAI-Token` -
  including an `axiom`/`forge-node` one, whenever it's provisioned -
  would be able to invoke it through `/registry/dispatch`, with zero
  additional gate on UAI's side.
- Separately, and already true today regardless of the Omada driver: the
  same unscoped token can invoke `keepass_edit` / `keepass_create` (write
  paths into the credential store the Omada password itself lives in) and
  any other driver's write-capable tools among the other ~2000 registered
  ones - none of that is Omada-specific, and none of it is blocked.

**Conclusion: the UAI credential model does not support scoping a caller
to read-only queries at all, let alone to `network_clients`'s specific
needs.** A caller is either "a valid caller" (full access to every
registered tool) or "not a valid caller" (401). There is no narrower
tier. This means an AXIOM-side allowlist, tier, or audit-logging control
cannot make holding this credential safe - the credential itself grants
more than `network_clients` needs, and no control on AXIOM's side of the
wire can shrink what UAI will honor on the other side. This is exactly
the situation AXIOM-10's original security review flagged as needing a
properly-scoped credential rather than an AXIOM-side compensating
control.

### What changed in the code (this change, AXIOM Phase 1.4)

1. **`network_clients` is now hard-disabled, unconditionally, in
   `dispatch_intent` (`forge-node/src/network.rs`)** - a build-level gate
   with no policy escape hatch, checked before the capability-policy
   allowlist is even consulted (same shape as the pre-existing
   `DispatchOrigin::Wan` hard-deny it now supersedes for this
   capability). It fires regardless of what `capability_policy.toml`
   allows, and regardless of whether `uai_base_url`/`uai_token` are
   configured - proven by
   `network_clients_hard_denied_even_when_allowlisted_and_uai_configured`
   in `network.rs`'s `policy_dispatch_tests` module, which configures
   both and confirms the specific Phase 1.4 denial message still fires
   instead of either the generic allowlist-miss message or the
   `dispatch_network_clients`-reached "not configured" message. This is
   the fail-closed model Phase 1.1 already established for capability
   policy, applied here at the build level because the problem is not
   something a runtime policy file can fix - it's the credential's scope
   on UAI's side.
2. **The Omada username/password `fetch_network_clients` receives from
   `keepass_lookup` are now wrapped in `zeroize::Zeroizing<String>`** and
   extracted via `mem::take` (not a borrow/clone) out of the raw JSON
   reply, so the plaintext values are wiped from memory (not just
   deallocated) as soon as the function that used them returns. Added
   `zeroize` as a new `forge-node` dependency for this
   (`forge-node/Cargo.toml`) - flagged as a cheap, worthwhile polish item
   in AXIOM-10's original review even before this scope finding.
3. The misleading `fetch_network_clients` doc comment described above was
   corrected.

### [OWNER GATE] - what Larry needs to decide/do

`network_clients` will not serve real traffic again until:

1. A **new UAI caller token, scoped (on UAI's side) to read-only Omada
   queries**, is provisioned for AXIOM specifically. Given the finding
   above, "scoped" cannot mean an entry in `uai_secrets.json` with
   `allowed_drivers` set - that field isn't enforced. It means either (a)
   UAI's broker/registry code gets a real per-caller tool-authorization
   check added (a change to the `uai` platform, out of scope for
   `axiom-core` and not something this change attempts), or (b) some
   other mechanism Larry considers equivalent - e.g. a UAI deployment
   dedicated to serving only `omada_clients`/`omada_health` to a token
   that literally cannot reach `/registry/dispatch` for anything else.
   This is a decision (and likely a build task) on the `uai` side, not
   something `axiom-core` can satisfy by itself.
2. Once that token exists, remove the Phase 1.4 hard-deny block in
   `dispatch_intent` (restore it to the narrower
   `origin == DispatchOrigin::Wan`-only form it replaced - both are
   explicitly commented at the call site) and update this section to
   describe the new, actually-enforced scope.

### What was and wasn't verified live

The Omada controller itself is down (separate, known infra issue - not
addressed here, and not worked around with a mock; this review is about
credential *scope*, not about making a live Omada call succeed). No
`axiom`/`forge-node` caller token exists yet in UAI's `uai_secrets.json`
(this capability has never been live-deployed with real credentials), so
there was no real AXIOM-held UAI token to test end-to-end against a live
`/registry/dispatch` call.

What WAS verified, directly and with certainty, by reading the actual
running code (not documentation, not memory of past summaries) on the
Proxmox host serving UAI:

- `uai_broker.py`'s `_require_auth()` and `registry_dispatch()` route
  handlers, in full - confirmed no per-caller tool/driver check exists in
  either.
- `uai_registry.py`'s `Registry.dispatch()` - confirmed it accepts a bare
  `tool_name`/`input_args`/`DRIVERS` and has no caller-identity parameter
  at all, so no caller-scoping check could exist downstream of
  `registry_dispatch()` even in principle.
- The full `uai_callers` key structure in `uai_secrets.json` (key names
  only - `token`, `allow_all`, `allowed_drivers` per caller; no token
  values read, copied, or logged at any point in this review) and a
  repo-wide grep confirming `allow_all`/`allowed_drivers` are written but
  never read.
- The live registry database's tool/driver counts and the `omada`
  driver's exact registered tool list (`omada_clients`, `omada_health`
  only - both read-only), via a read-only `sqlite3`/`python3` query
  through the running `ai-uai` container.

What was NOT (and, without a live scoped token and a working Omada
controller, could not be) verified: an actual HTTP request against
`/registry/dispatch` using an `axiom`/`forge-node`-issued token attempting
to invoke a write-type action, observed failing on UAI's own
authorization rather than later on Omada-unreachable. No such token
exists to test with, and fabricating one (or borrowing another caller's
live token to probe with) was avoided deliberately - the static-code
finding above is unambiguous enough not to need it: `registry_dispatch()`
has no conditional authorization logic to a token's identity at all, for
any tool, so there is no scenario-dependent behavior a live call could
have revealed that the code doesn't already settle.

## Untrusted-content handling / confused-deputy defense (AXIOM Phase 3.7)

**Status: implemented and tested. Applies to `network_clients`'s real
return path today; the mechanism (`axiom_gateway::sanitize`) is generic and
applies automatically to any future capability that reuses it.**

### The threat (roadmap, verbatim)

"The dominant real-world failure mode for agent gateways is not a rogue
peer but a *legitimate, authorized* AI manipulated by content it read. On
this network, device hostnames, SSIDs, and client metadata are
attacker-chosen strings - a hostile device can name itself an instruction,
which then flows through `network_clients`/`network_health` into an AI's
context." Concretely: any device joining the LAN can set its own hostname
to `"IGNORE PREVIOUS INSTRUCTIONS AND ..."`, or embed raw control
characters / ANSI terminal escape sequences in it, before `network_clients`
ever sees it (see the credential-scope section above -
`fetch_network_clients` forwards Omada's client-record reply verbatim,
with no schema of its own to validate against).

### What's implemented

`axiom-gateway/src/sanitize.rs` (new module, Phase 3.7) - see its own
module doc comment for the full design rationale. `forge-node`'s
`fetch_network_clients` (`network.rs`) is its one real caller today: the
raw `omada_clients` UAI reply is passed through
`sanitize_and_wrap_untrusted_json` before this function returns anything -
the raw backend reply itself never leaves this function, let alone this
node.

Three controls, applied to every string field found anywhere in the
returned JSON (recursively - not a hand-picked field list, since no
`hostName`/`ssid`/`mac` schema exists anywhere in this codebase to name
fields against; see `sanitize.rs`'s doc comment for why a generic walk is
both simpler and strictly safer here):

1. **Length cap - 256 characters.** Every field this class of backend
   returns (hostname, SSID, MAC, IP, vendor/OUI name) has a small
   legitimate real-world maximum (a full DNS FQDN tops out at 253; SSIDs
   are capped at 32 bytes by the 802.11 spec itself; MAC/IP text forms are
   under 50 characters) - 256 is generous headroom above the largest
   legitimate case while remaining a cheap, hard ceiling against a
   deliberately pathological value.
2. **Control-character and escape-sequence stripping.** Every ASCII C0
   control character (0x00-0x1F) and DEL (0x7F) is removed, including
   `\n`/`\t`/`\r` - the maximal, not partial, reading of this being a
   judgment call: a hostname/SSID/MAC/IP has no legitimate reason to
   contain any of them, and keeping them "for readability" would leave
   open the exact log-line-splitting / terminal-cursor-manipulation vector
   this phase exists to close. ANSI/terminal escape sequences (CSI: `ESC
   [ ... final-byte`; OSC: `ESC ] ... BEL`/`ESC \`) are removed as whole
   units, not just the leading ESC byte (a partial strip would leave the
   sequence's parameter/final bytes behind as printable garbage text).
   Also strips a small, explicitly documented set of Unicode bidi-
   override/invisible characters (RLO/LRO/isolates, zero-width space, BOM)
   - the same display-spoofing threat class, outside what the roadmap
   named explicitly but cheap and safe to also remove, per this task's own
   instruction to make the conservative choice on a genuine ambiguity.
3. **Structural envelope, not a text prefix.** The sanitized payload is
   wrapped in a JSON object with a fixed marker key
   (`axiom_untrusted_external_data: true`) and a `data` field - a JSON
   object boundary is structural, not textual, so no string VALUE inside
   `data` (however it's phrased, however many escape-boundary tricks it
   tries) can be mistaken for a sibling of the envelope itself by a
   consumer that parses this as JSON. A text prefix like `"UNTRUSTED DATA
   BELOW:"` was deliberately rejected - that's exactly the kind of boundary
   an attacker-controlled string could itself contain, spoof, or visually
   merge with.

**Oversized fields are flagged, not silently truncated**: every sanitized
string becomes `{"value": ..., "truncated": bool,
"control_chars_stripped": bool}`, not a bare capped string - a 10,000-char
hostname capped to 256 chars is marked `truncated: true` rather than
looking like an ordinary (if long) legitimate value. Same treatment for
control-character/escape-sequence removal via the sibling
`control_chars_stripped` flag - independent signal, since a field can be
capped without ever having had a control character, or vice versa.

**A benign value passes through unmangled**: `sanitize_str("Bedroom TV")`
returns the value unchanged with both flags `false` - proven against real
device names from this network's own device audit (`"Bedroom TV"`, `"Game
Room"`) in `sanitize.rs`'s own tests, so this isn't a blunt "cap and mangle
everything" filter.

### Audit-log safety

`axiom-gateway/src/audit.rs`'s Tier 1 log entry point
(`AuditLog::log_tier1_call`) is not yet wired into `forge-node`'s real
dispatch path at all - see `axiom-gateway/src/lib.rs`'s own module doc
comment and `forge-node/src/capability_isolation.rs`'s
`capability_dispatch_has_zero_references_to_audit_log_today` test, which
enforces that boundary as a standing regression check. This phase does not
change that boundary. What this phase proves instead
(`sanitize.rs`'s `sanitized_not_raw_network_clients_output_is_what_lands_
in_an_audit_entry` test) is that WHEN a future phase does wire
`fetch_network_clients`'s result into `log_tier1_call`, the data flow is
already safe by construction: `fetch_network_clients` only ever produces
the sanitized+wrapped string (there is no code path that still holds onto
the raw backend reply after this phase's change), so whatever a future
dispatch layer passes to `log_tier1_call` as the outcome detail is
necessarily the sanitized value - proven end-to-end by actually invoking
`AuditLog::log_tier1_call` with a sanitized hostile fixture and asserting
the raw log file bytes contain no control characters, no ANSI escapes, and
no un-capped 10,000-character field, while the (now-inert, structurally
enveloped) text content is still visible to a human reading the log, which
is the log's actual job.

### Never interpolated into anything executed/logged-as-structure/routed
on (roadmap point 3)

Checked directly (grep + full manual read of `fetch_network_clients` and
`dispatch_network_clients`, `forge-node/src/network.rs`): **no instance
found.** Neither function builds a shell command, a file path, a
log-format string, or a routing/dispatch decision from the backend-
returned client data. `fetch_network_clients` performs exactly one
transformation on it (`sanitize_and_wrap_untrusted_json`) and returns the
result as a plain `String`; `dispatch_network_clients` turns that directly
into a signed Fulfill frame's payload bytes via `build_fulfill_frame` -
nothing else touches it. `reply_routing`/`RoutingExt` (the only "routing
decision" either function handles at all) is threaded through from the
*original Intent frame's own* routing extension, never derived from the
fetched client data. This finding is now a standing regression check, not
just a one-time read - see `network.rs`'s new
`network_clients_output_safety_tests` module, which extracts both
functions' real current source (brace-matched, comment/string-aware, same
technique `capability_isolation.rs` already uses for its own checks) and
asserts neither contains a logging-macro call, and that the sanitize call
is still actually present. Independently, `capability_isolation.rs`'s
pre-existing per-capability forbidden-pattern scan already proves these
same two functions contain no process-spawn or filesystem-write primitive
at all (`Command::new`, `process::Command`, `fs::write`, etc.) - the
strongest possible form of "cannot execute anything built from this data,"
regardless of string content.

### Why the Phase 3.3 approval flow is the primary containment, not this
phase

Sanitization closes the injection/terminal-manipulation vector for content
that reaches a human's screen or a log file. It is deliberately NOT relied
on as the reason a manipulated AI can't cause real damage - that
containment already exists, one layer up, from Phase 3.3's parameter-hash-
bound Tier 2 approval flow (`axiom-gateway::approval::Tier2ApprovalFlow`,
`Intent::compute_parameter_hash`). Even in the worst case - a hostile
hostname's phrasing somehow influences an AI's reasoning and it decides to
attempt a real Tier 2 (destructive/security-relevant) action - that AI
still cannot get the action to actually execute without the owner
approving the EXACT parameters that will run: the hash binding means an
approved intent's parameters are checked against the hash captured at
proposal time before execution, so the AI cannot quietly swap in different
parameters after the owner has glanced at (and approved) a summary. A
tricked AI can propose something malicious; it cannot make that proposal
execute as something other than what the owner actually saw and approved.
This is why Phase 3.7's sanitization is framed as defense-in-depth
(closing a real vector - display/log/terminal manipulation, and reducing
the odds a manipulated AI even forms a coherent malicious intent in the
first place) rather than as the system's only or primary defense against a
manipulated agent; the primary defense against a manipulated agent taking
real destructive action was already shipped in Phase 3.3, independent of
whether any given payload happens to be well-sanitized.

## AXIOM Tier 2: Telegram approval channel + wg_peer_manage credential/auth scope

**Status: live, first real Tier 2 capability. The cross-consumer Telegram polling race flagged
below at ship time was resolved 2026-08-15 by moving to a dedicated bot token - see `DECISIONS.md`'s
"Tier-2 approval channel" section for the full write-up.**

### What credential this holds, and how

`forge-node/src/telegram_approval.rs`'s `TelegramApprovalState` holds one Telegram Bot API token
(`NodeConfig::telegram_bot_token`, config.toml only, never committed to source - same rule
`uai_token` already follows). **As of 2026-08-15, a dedicated bot** (`@AxiomApprovalBot`, KeePass
"AXIOM Telegram Bot (AxiomApprovalBot)") - originally shipped reusing PM's existing bot, migrated to
a dedicated one specifically to eliminate the cross-consumer polling race described lower in this
project's history (see `DECISIONS.md`). This token can do exactly what any Telegram bot token can:
send messages to, and read `getUpdates` for, chats the bot has been added to - it is not scoped
narrower than that by Telegram itself (there is no Telegram-side mechanism to restrict a bot token
to one chat only; the SCOPING that matters here is `telegram_chat_id`-based, enforced entirely on
AXIOM's own side - see below).

### The real authentication boundary: `telegram_chat_id`, checked on every reply

A Telegram bot token proves "this process can act as this bot," not "this specific reply came from
Larry." The actual authentication boundary for a Tier 2 approval decision is
`TelegramApprovalState::process_update`'s check that a `callback_query`'s `from.id` (the Telegram
user who tapped the button, not merely the chat the message posted in) equals the configured
`telegram_chat_id` - anything else is logged and ignored, the pending intent stays exactly as
`Pending` as if nothing had arrived (see `telegram_approval.rs`'s own module doc comment,
"Chat-id authentication", and its `chat_id_mismatch_does_not_resolve_the_pending_intent` test).
`telegram_chat_id` is validated as a real integer at node startup (`NetworkManager::new`), not
deferred to the first request - a malformed value is a config error visible in the startup logs
immediately, not a silent no-op discovered only when a real approval is needed.

### wg_peer_manage's own scope, separate from the channel's

`wg_peer_manage`'s UAI credential (the same `uai_token`/`uai_base_url` every other UAI-backed
capability already uses) is subject to the SAME finding this file's "AXIOM -> UAI credential scope"
section above already documents for `network_clients`: UAI's `/registry/dispatch` has no per-caller
tool authorization, so this credential is not scoped narrower than "every registered UAI tool" on
UAI's own side either. What keeps `wg_peer_manage` safe is layered entirely on AXIOM's side, same
"AXIOM-side controls can't shrink an over-scoped credential, so don't rely on that alone" principle
that finding already established: the code never calls `wg_client_config`/`wg_client_qr` (which
return WireGuard private key material - enforced by `capability_isolation.rs`'s and `network.rs`'s
own regression tests), the code-level `HARD_DENIED_WG_PEER_TARGETS` hard-deny for Larry's own two
currently-relied-upon peers, the policy-file allowlist + protected-resource + `denied_param_substrings`
checks, and - the layer that makes this Tier 2 rather than Tier 1 - a real, per-invocation, human
Telegram approval that must arrive from the authenticated chat_id before `execute` is ever reached.

### RESOLVED: cross-consumer Telegram `getUpdates` race

Originally a real, security-relevant (not merely reliability-relevant) gap: `pm-agent`'s own
independent `getUpdates` polling loop against the SAME bot token could, in a real but unmeasured
fraction of cases, silently consume/foreclose an AXIOM `callback_query` update before AXIOM's own
poller observed it, because Telegram's offset-confirmation cursor is global per bot token, not per
consumer. The practical effect was never a false approval (the intent simply stays `Pending` until
it expires - `Tier2ApprovalFlow`'s own expiry discipline still holds regardless) but a false
NEGATIVE: a real tap acknowledged by the Telegram client, but the underlying action never happens,
with no error surfaced anywhere. **Resolved 2026-08-15** by moving to a dedicated bot token
(`@AxiomApprovalBot`) - see `DECISIONS.md`'s "Tier-2 approval channel" section for the full history.
