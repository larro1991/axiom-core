# AXIOM — Owner Decisions

Record of decisions made by Larry during the capability-gateway roadmap planning phase
(2026-08-06). This file exists per the roadmap's own instruction to record `[OWNER GATE]`
answers here as they're made. Updated incrementally — not all Phase 0/3 gates are answered yet.

## Transport

**Tailscale — DECLINED, removed from the roadmap entirely.**
Decided 2026-08-06. iroh WAN transport (already shipped, `axiom-transport/src/wan.rs`) is
AXIOM's WAN answer. Tailscale would have added an overlapping layer — one more account, agent,
and management plane — for zero architectural gain once iroh was confirmed to stay. If Larry
wants Tailscale later for his own personal remote access, that's a standalone choice with no
AXIOM involvement.

**iroh relay dependency — Option A accepted now, migration triggers defined.**
Decided 2026-08-06. Production WAN transport uses n0's public relay + discovery infrastructure
(`iroh::endpoint::presets::N0`) — confirmed live in code, not assumed. Exposure is metadata-only
(node IDs, IPs, timing); content stays end-to-end encrypted regardless of relay. Accepted as-is
for now. **Migrate to Option B (self-hosted `iroh-relay` on a cheap VPS, endpoint-ID allowlist,
fail-closed) when EITHER trigger fires:**
1. Conduit lands its first paying client — client metadata shouldn't transit a free
   best-effort third-party relay, and the self-hosted relay would double as shared Conduit
   multi-site infrastructure at that point.
2. AXIOM becomes load-bearing enough that best-effort relay availability is unacceptable.

Option C (direct-address-only, no relay/discovery) was rejected as a destination — it would
regress WAN capability back to requiring explicit reachable addresses, undoing the point of
using iroh.

## Protected-resource list (roadmap 3.6)

MAC address is the mandatory primary key, IP is secondary (documented IP-drift history in this
environment — `feedback_network_address_drift.md` — makes IP-only unreliable). No capability may
target these, even with Tier 2 human approval; enforced in the gateway core before backend
dispatch.

**Every physical interface on every device is listed, not just the currently-active one** — a MAC-only
allowlist keyed to whatever's plugged in today breaks the moment a cable moves or wifi gets enabled.
Virtual/software adapters (VirtualBox host-only, Bluetooth PAN, Wi-Fi Direct virtual adapters, VPN
tun/tap interfaces) are excluded — not real network-attached hardware, not a "someone plugs in a
different cable" risk.

*(Values below are anonymized examples for public documentation — the real deployment's actual IPs/MACs live only in the live, untracked `capability_policy.toml` on the operator's own host, never committed to this repo.)*

| Resource | IP | MAC | Why untouchable |
|---|---|---|---|
| Proxmox host (self), ethernet | 192.168.1.10 | `AA:BB:CC:11:22:01` | Runs AXIOM itself, PM, most infra |
| Proxmox host (self), wifi | — (adapter down, unused) | `AA:BB:CC:11:22:02` | Same host, `wlp8s0` — dormant but real hardware |
| Desktop (desktop), ethernet | 192.168.1.11 | `AA:BB:CC:11:22:03` | UAI broker, KeePass, primary workstation |
| Desktop (desktop), wifi | — (adapter down, unused) | `AA:BB:CC:11:22:04` | Same host, Intel Wireless-AC 3168 — dormant but real hardware |
| Router/gateway | 192.168.1.1 | `AA:BB:CC:11:22:05` | Network backbone. Confirmed single device — Larry's own router, ISP's router sits upstream on the WAN side and is out of AXIOM's reach entirely (not on the LAN AXIOM operates on), so it's not a protected-resource entry. No separate AP unit exists on this network. |
| Omada controller | 192.168.1.14 | `AA:BB:CC:11:22:06` | NAC/enforcement — also the single-writer-rule resource (AXIOM is permanently read-only against it) |
| Laptop — laptop, wifi adapter | 192.168.1.13 | `AA:BB:CC:11:22:07` | Carries SSH/management access (MediaTek Wi-Fi 6E MT7922) |
| Laptop — laptop, ethernet adapter | — (disconnected, no IP) | `AA:BB:CC:11:22:08` | Same machine, second interface (Realtek Gaming GbE) — pulled via `ipconfig /all` over SSH, cable doesn't need to be plugged in for the MAC to be known |

**Note, not a MAC-keyed row (tunnel interfaces don't have MACs)**: Proxmox already runs `wg0`
(WireGuard server, UP — the laptop's `10.8.0.2` WireGuard client connects to this) and `tailscale0`
(UP). Both are pre-existing infrastructure, unrelated to AXIOM's own Tailscale decision above (which
was specifically about AXIOM's own WAN transport dependency, not personal remote-access VPNs Larry
already runs). Flagged here because both are management-plane-adjacent (remote access into the
network) even though they don't fit the MAC-based enforcement model — worth the gateway core being
aware these exist as an out-of-band access path, even if it can't technically protect them the same
way.

Protected-resource list complete as of 2026-08-06 — every physical interface on every known
management-plane device covered, not just active ones.

## Ecosystem positioning

**Sentinel/Lifeline stays separate from AXIOM — ratified via Fable's roadmap, 2026-08-06.**
Sentinel/Lifeline is transport survivability (break-glass RF/cellular reachability for Conduit
managed sites), not authorization — a different problem than AXIOM's capability-gateway role.
AXIOM already delegates transport (to iroh); Sentinel is just another transport, 12+ months out
and revenue-gated behind Conduit's own maturity bar. No merge, no shared crate. Only future
connection to re-ask if/when Lifeline resumes: whether its command *validation* (not its RNS/SPA
transport, which is not AXIOM's concern either way) embeds `axiom-gateway`.

**`axiom-gateway` will be a standalone crate, Burr Phase 2 is its second intended consumer.**
Phase 3's policy/tier/approval/audit machinery gets zero dependency on AXIOM's own discovery/
transport/frame code specifically so Conduit's Burr Phase 2 ("authenticated remote execution
inside the safety envelope") can consume the same grammar instead of reinventing it. Design
constraints even though AXIOM itself is single-tenant forever: no global singletons, owner/tenant
as an explicit parameter, operator/approver as distinct roles. Multi-tenant hardening itself stays
Conduit's job when it embeds the crate — not AXIOM's.

**Single-writer rule: Conduit NAC owns all Omada enforcement, AXIOM stays permanently read-only
against it.** AXIOM's Tier 2 flow may *route* an enforcement request to Conduit's playbook system
(its own audit/revert), never write to Omada directly. General principle for any future backend:
exactly one system owns writes per resource, recorded in `ARCHITECTURE.md` when a backend is added.

## Tier model — RATIFIED 2026-08-06

Ratified as written in the roadmap (amended 3.1, not a read/write split — worst-case impact and
required controls):
- **Tier 0 — Local read**: side-effect-free, local-only, low-sensitivity (`echo`, `sysinfo`).
  Controls: allowlist + rate limit.
- **Tier 1 — Elevated**: reaches an external system, exercises credentials, or performs a
  reversible write, regardless of read-only status. `network_clients` is Tier 1 despite being
  read-only. Controls: Tier 0 + mandatory full-context audit logging + rate/concurrency limits.
- **Tier 2 — Destructive/security-relevant**: firewall rules, VLAN changes, deletions, anything
  touching connectivity or auth. Controls: Tier 1 + explicit human approval per invocation, no
  standing approvals, no wildcards.

An untiered capability refuses to register — fail closed.

## Tier-2 approval channel — RATIFIED 2026-08-06

**Primary, now: CLI prompt on the management box.** This is what Phase 3.3's mock rehearsal runs
against.

**Planned v2: phone-push via Larry's existing automation** — required before Tier 2 actions become
*routine* (a 15-minute intent expiry and the owner being away from the desk don't mix), not
required before the mock rehearsal or before Phase 3 starts. The `ApprovalChannel` trait makes this
upgrade a new implementation, not a state-machine redesign — no Phase 3 work needs to wait on it.

**v2 SHIPPED 2026-08-10: Telegram, via PM's existing bot (`@ExampleBot`, KeePass "PM Telegram
Bot").** Not a new bot — the same one `pm-agent` already uses for other alerts, per explicit
instruction. Long-polling (`getUpdates`), not a webhook — no public endpoint needed on this home
network. Inline-keyboard Approve/Deny buttons, `callback_data` carrying the full intent id, so a
reply is matched to the exact pending proposal rather than "whichever message is most recent."
Authentication boundary: only a `callback_query` whose `from.id` equals the configured
`telegram_chat_id` is ever honored. Confirmed the `ApprovalChannel` trait needed ZERO changes to
support this second implementation — see `axiom-gateway/src/approval.rs`'s own updated doc comment.

**RESOLVED 2026-08-15 — option (a) chosen: dedicated bot token.** The gap above was real: PM's
`pm_agent.py` independently long-polls the same bot token's `getUpdates` with no `allowed_updates`
filter, and Telegram's offset-confirmation cursor is global per bot token, not per-consumer — two
independent long-pollers against the same token race for updates. Fixed by giving AXIOM its own
dedicated bot (`@AxiomApprovalBot`, created via @BotFather, token in KeePass as "AXIOM Telegram Bot
(AxiomApprovalBot)"), replacing the shared PM bot token in `telegram_bot_token` entirely. This closes
the race by construction, not by tuning poll intervals or update filters — a dedicated token has no
other consumer to race against, so there is no shared cursor to lose an update on. `telegram_chat_id`
is unchanged (Larry's own numeric Telegram id, constant across every bot). Confirmed live: the new
bot can send and the chat exists (`getChat`/`sendMessage` both succeeded against it). Historical
detail on why option (a) over (b) preserved below for context.

## AXIOM→UAI credential scope — VERIFIED 2026-08-06 (Phase 1.4), requirement NOT currently met

Requirement: read-only client queries only, no driver invocation rights. **Actual finding**: the
credential is over-scoped — UAI's `/registry/dispatch` has no per-caller driver authorization at
all (see `infra-issues.md` INF-085, confirmed against the real production broker). `network_clients`
is hard-denied unconditionally in code (commit `a9c0b2b`) pending Larry provisioning a properly-
scoped UAI token — no policy/allowlist escape hatch exists for it. This is not a gap in AXIOM's own
enforcement; it's AXIOM correctly refusing to trust a credential it can't verify the scope of.

## AXIOM-3 tail — CLOSED 2026-08-06

Deleted `/mnt/h-drive/appdata/forge-test/axiom-core` (2.9GB, mostly stale build artifacts) after
verifying the canonical copy (`/Main/build/axiom-core` on Proxmox) was clean (`git status` clean,
HEAD matches its own `origin` exactly). GitHub mirror was behind at delete time (pending its nightly
03:00 sync, not divergence) — Proxmox is the authoritative canonical copy per this file's own
definition, so that lag didn't block the decision. `todo.md`'s AXIOM-3 entry closed in the same
session.

## Phase 0 status: all four items answered — exit criteria met.
