# Contributing to AXIOM

## Scope check first

This is a single-owner homelab project, not a company with a roadmap or an
SLA. It's used for real, on real infrastructure, by one person - see
**[README.md](README.md)**'s Scope section for exactly which crates that
covers (`forge-node` and `axiom-gateway`; everything else in this workspace
is earlier/experimental and not part of any claim here). Use at your own
risk; read **[SECURITY.md](SECURITY.md)**'s "Known limitations" section
before relying on any of it.

## Reporting a security issue

Don't open a public issue for a vulnerability. See
**[SECURITY.md](SECURITY.md)**'s "Reporting a vulnerability" section for
the preferred private-disclosure path.

## Reporting a non-security bug

Open a [GitHub Issue](https://github.com/larro1991/axiom-core/issues).
Include what you ran, what you expected, what actually happened, and (if
it's a crash or a rejected request) the relevant log line or audit entry -
this project treats "prove it, don't just assert it" as a real standard for
itself (see **[TESTING.md](TESTING.md)**), and a bug report benefits from
the same discipline.

## Submitting a PR

- Keep it focused - one change, one PR. A driveby cleanup bundled with a
  real fix makes both harder to review.
- If you're touching `forge-node` or `axiom-gateway`, run
  `cargo test --workspace --release` before opening the PR. CI runs it
  again, but a red CI run on a first-time contribution isn't a great start.
- If you're adding or changing a capability, `capability_isolation.rs`'s
  regression checks (forbidden patterns: process spawn, filesystem writes
  outside what's declared) apply to you too - they're not owner-only rules.
- New Tier 2 (destructive) capabilities need a real dry-run diff
  implementation where the backend supports reading current state (see
  `Tier2Capability::dry_run`'s doc comment) - "just wire it up" without
  that isn't enough for anything destructive.
- Match the existing doc-comment style: comments explain *why*, not *what*
  - a reader can already see what a line of code does.

## What won't get merged

- Anything that weakens the fail-closed default (an empty `allowed_peers`
  list shipping non-empty, a capability that doesn't check policy before
  acting, a Tier 2 action that can execute without an explicit approval).
- Anything that makes a security claim the test suite doesn't back up.
