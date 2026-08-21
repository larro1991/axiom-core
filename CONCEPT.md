# What is AXIOM?

AXIOM is a personal, self-hosted system that lets independent software agents on a home network safely request actions from each other — "safely" meaning every request is cryptographically identified, explicitly permissioned, and — for anything destructive — approved by a human before it runs. Think of it as a private, owner-controlled alternative to giving an AI assistant standing admin access to your infrastructure: instead of one god-mode credential, every capability is its own narrow, individually-gated door.

## The problem it solves

The owner runs a home lab: a Proxmox hypervisor, Home Assistant, Docker containers, a VPN server, various other services. AI agents (like the one that built this) are useful for automating tasks against that infrastructure — restarting a stuck container, toggling a light, sending an alert — but "useful automation" and "one compromised or buggy agent can do anything" are in tension. AXIOM's whole design is resolving that tension without giving up the automation.

## The core model

**Nodes.** Each machine on the network can run a `forge-node` — a small daemon with its own cryptographic identity (an Ed25519 keypair; the public key IS the node's address, there's no separate naming system to trust). Nodes find each other automatically on the local network (IPv6 link-local multicast — no configuration, no central directory) or connect over the internet via a peer-to-peer transport (dial-by-key, no VPN, no port-forwarding required).

**Capabilities.** A node advertises a set of named "capabilities" it's willing to perform for other nodes — e.g. `notify_send` (push a notification), `proxmox_restart` (restart a VM/container), `docker_restart`, `home_assistant_toggle`, `wg_peer_manage` (VPN access control). A peer that wants something done sends a signed request naming a capability and a payload; the receiving node checks whether that specific peer is allowed to call that specific capability, and if so, dispatches it.

**Tiers.** Capabilities are classified by blast radius, not by read/write:
- **Tier 0** — side-effect-free, local-only (e.g. echo, basic status).
- **Tier 1** — reaches an external system or exercises a credential, but the action itself is reversible (restart a container, toggle a light, send a message).
- **Tier 2** — destructive or security/access-relevant (delete something, change VPN access, anything touching connectivity or auth). Tier 2 requires **explicit human approval for every single invocation** — no standing approvals, no "trust this peer forever." The approval today goes out as a real Telegram message with Approve/Deny buttons; the request only executes if the owner taps Approve within a 15-minute window.

**Fail-closed by default.** Every capability ships with an empty allowlist. Nothing is reachable by anyone until the owner explicitly names which peer may call which capability. Building a capability and turning it on are two separate, deliberate steps — this is by design, not an oversight.

**Defense in depth, not just the front door.** For anything with real blast radius, there isn't one gate — there are several independent ones stacked (a hard-coded allowlist in the code itself, a policy file check, sometimes a server-side re-validation completely independent of the main program, and for Tier 2, the human-approval step on top of all of that). The idea is that a bug in any single layer shouldn't be enough on its own to do damage.

**Audit, not just enforcement.** Every Tier 2 action that actually executes is written to a tamper-evident, hash-chained log — each entry's hash covers the previous entry's hash, so a tampered or deleted entry is detectable, the same principle git commits or a blockchain use.

## What it deliberately does NOT do

- No always-on VPN/overlay network dependency — the transport is self-contained.
- No single powerful credential shared across every action — each capability's access to the underlying system (databases, other services, cloud credentials) is scoped as narrowly as the specific action needs, not inherited wholesale from some master key.
- No silent capability expansion — adding what a node can do is a deliberate, reviewed code change, not a runtime configuration toggle.
- No "trust once, act forever" — Tier 2 approval is per-request, with an expiry, not a standing grant.

## Current status (as of 2026-08-14)

The transport, discovery, and security/policy layers (tiering, audit logging, kill-switch, per-capability rate limits) are built and tested. Eight capabilities exist end-to-end, tested against real infrastructure. Every one of them is currently fail-closed — the system is fully built but deliberately not yet turned on for any real peer, pending the owner deciding which devices should be allowed to call which capabilities.
