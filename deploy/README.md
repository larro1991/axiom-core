# Deploying forge-node as a systemd service

AXIOM Phase 1.5. This directory holds `forge-node.service`, a hardened
systemd unit for running `forge-node` as a long-running network service on
any systemd-based Linux host (this repo has no prior `deploy/` convention -
this establishes one; put future unit files / deploy configs here too).

This covers **installing the unit** on a host that already has a compiled
`forge-node` binary. Building/packaging the binary itself is a separate
concern, out of scope here.

## Paths this unit depends on

These come straight from `forge-node/src/config.rs` (`NodeConfig::default`)
and `forge-node/src/policy.rs` - don't change them here without checking
those first, the unit's `ReadWritePaths` sandboxing depends on getting them
right:

| Path | Owner | Purpose |
|---|---|---|
| `/etc/forge/config.toml` | root, read-only to service | Node config (`NodeConfig`). May contain `uai_token` - never put secrets in the unit file itself, only in this file. |
| `/etc/forge/capability_policy.toml` | root, read-only to service | Phase 1.1 capability access-control policy (`capability_policy_path`). **Must not** be writable by the `forge-node` user - see `forge-node/src/policy.rs`'s module doc comment: this file gating what the node can be asked to do is only meaningful if the node itself can't rewrite it. |
| `/var/lib/forge/` | `forge-node:forge-node`, read-write | `data_dir`. Holds `node.key` (Ed25519 identity, written 0600 by `forge-node init`), `control.sock` (local control socket), and link-local discovery state. This is the **only** path the unit grants write access to. |
| `/opt/forge-node/forge-node` | root, read-only, executable | Placeholder `ExecStart` path - see "Installing the binary" below. |

If a later phase adds a new on-disk state path to `NodeConfig`, add it to
`ReadWritePaths` in `forge-node.service` and to this table in the same
change - the sandboxing is only as correct as this list is complete.

## One-time host setup

```bash
# 1. Dedicated, unprivileged service user - no login shell, no home dir
#    login needed (ProtectHome=true keeps it out of other homes anyway).
groupadd --system forge-node
useradd --system --gid forge-node --no-create-home \
        --shell /usr/sbin/nologin forge-node

# 2. Config + policy directory - root-owned, NOT writable by forge-node.
#    (world-unreadable at the top level since config.toml can hold a UAI
#    token; forge-node group gets read access so the service can load it)
mkdir -p /etc/forge
chown root:forge-node /etc/forge
chmod 750 /etc/forge
# config.toml and capability_policy.toml themselves: root:forge-node, 0640,
# created by `forge-node init` or by hand - see forge-node --help.

# 3. State directory - owned by the service user, this is the ONLY path
#    the unit's ReadWritePaths grants write access to.
mkdir -p /var/lib/forge
chown forge-node:forge-node /var/lib/forge
chmod 750 /var/lib/forge
```

## Installing the binary

No compiled `forge-node` binary is produced by this task - there's no
`cargo` toolchain on the deploy target yet, that's a separate packaging
concern. The unit's `ExecStart` points at a placeholder path:

```
/opt/forge-node/forge-node
```

At actual deploy time: build (or copy a build artifact of) `forge-node`,
place it at that path, `chown root:root /opt/forge-node/forge-node`,
`chmod 755`. If the real deploy path ends up different, update
`ExecStart` in `forge-node.service` to match - everything else in the unit
is path-independent of where the binary itself lives.

## Generating node identity + initial config

Before first start, run `forge-node init` (as root, one-time) to generate
`/var/lib/forge/node.key`, `/etc/forge/config.toml`, and
`/etc/forge/capability_policy.toml`:

```bash
/opt/forge-node/forge-node init --output /etc/forge
chown -R root:forge-node /etc/forge
chmod 640 /etc/forge/config.toml /etc/forge/capability_policy.toml
chown forge-node:forge-node /var/lib/forge/node.key
chmod 600 /var/lib/forge/node.key
```

Edit `/etc/forge/capability_policy.toml` to actually allow the peers this
node should serve - it ships fail-closed (serves no one) by default.

## Installing the unit

```bash
cp deploy/forge-node.service /etc/systemd/system/forge-node.service
systemctl daemon-reload
systemctl enable forge-node
systemctl start forge-node
```

Check it came up clean:

```bash
systemctl status forge-node
journalctl -u forge-node -f
```

## Restart policy

`Restart=on-failure` (not `always`): restarts on crash or non-zero exit,
but does not loop-restart after a clean `systemctl stop` or a deliberate
exit(0) - the right default for a long-running network daemon where a
config-driven refusal to start (e.g. the Phase 1.1 fail-closed policy load,
or the identity-mismatch guard in `NodeConfig::load_or_generate_identity`)
should surface as a stopped/failed unit an operator notices, not silently
retry forever on a broken config. `RestartSec=5s` avoids a tight
crash-restart loop if something is actually wrong.

## Verification done for this change

- `systemd-analyze verify deploy/forge-node.service` - unit file syntax
  and directive validity checked directly on the Proxmox host.
- Sandboxing smoke-tested with a throwaway placeholder unit (not this one,
  and not installed as a real service) that ran as the `forge-node` user
  with the same `ProtectSystem=strict` / `ProtectHome=true` /
  `ReadWritePaths=/var/lib/forge` directives, confirming: writes inside
  `/var/lib/forge` succeed, writes to `/etc/forge` and elsewhere on the
  root filesystem fail. Test artifacts were removed and the throwaway
  service was disabled/removed after the test - nothing was left running
  or enabled.
- `forge-node.service` itself was **not** installed, enabled, or started -
  no compiled binary exists yet to run, so there is nothing to test against
  for real service startup. It's ready to install once a binary lands at
  `/opt/forge-node/forge-node`.

## Windows deployment notes (native `x86_64-pc-windows-gnu` port)

The Windows port runs as a Task Scheduler job (not a Windows Service) at
`C:\ProgramData\forge-node\forge-node.exe`, because a plain child process
launched over an SSH session is killed when that SSH session tears down -
Task Scheduler keeps it running detached. See `run-forge.bat` alongside the
binary for the exact invocation.

### Control socket is a named pipe, not a Unix socket

`control.rs`'s Windows `start()` binds `\\.\pipe\forge-node-control-<sanitized
data_dir>` (see `control::default_path`'s `#[cfg(windows)]` doc comment for
the exact sanitization) instead of a Unix domain socket, restricted to the
pipe's creator/owner, LOCAL_SYSTEM, and BUILTIN\Administrators via an
explicit DACL (same AXIOM-14 Cycle 4 rationale as the Unix socket's
0700/0600 permissions - see `control.rs`'s module doc comment).
`control-intent`/`kill-switch` work identically to Unix from an elevated
session.

### Known gotcha: a VPN/tunnel client can silently steal LAN routes

**Symptom**: `intent --bootstrap <lan-ip>:7777` (and the config file's
`bootstrap_nodes`, same underlying `NetworkManager::connect()` path) times
out waiting for HELLO_ACK, while link-local IPv6 discovery
(`discovery.rs`) keeps working fine on the same machine at the same time.

**Root cause found and fixed live 2026-08-18**: this is not a forge-node
bug - `network.rs`'s explicit-connect send path (`connect()`/`send_raw()`)
has zero platform-specific code and is identical on Linux and Windows. The
actual cause was a tunnel client (in the observed case, an always-on
"reach home remotely" WireGuard client, unrelated to whichever VPN full-
tunnel routing you'd normally suspect first - ExpressVPN specifically was
tested and is NOT the cause) advertising the **entire home LAN subnet**
(e.g. `192.168.110.0/24`) as one of its tunnel's `AllowedIPs`/routes, at a
lower (better) interface metric than the real LAN adapter - even while the
laptop is physically ON that LAN. Windows' own route resolution
(`Find-NetRoute -RemoteIPAddress <target>` in PowerShell - use this to
diagnose, not `route print`'s raw table, which doesn't show which route
actually wins) then sends every packet to that subnet, including the
bootstrap HELLO, into the tunnel instead of out the real LAN NIC. Link-local
IPv6 (`fe80::/10`) is immune to this entirely - it's never looked up in the
IPv4 routing table at all, which is why discovery kept working while
explicit connect didn't.

**Fix applied**: an explicit, more-specific `/32` host route for the
bootstrap peer's LAN IP via the real LAN adapter always wins over the
tunnel's broader `/24`, regardless of metric, and survives the tunnel
reconnecting:

```
route -p add <peer-lan-ip> mask 255.255.255.255 <this-machine's-lan-ip> metric 1 if <real-LAN-ifIndex>
```

(`netsh interface ipv4 show interfaces` to find `<real-LAN-ifIndex>`,
`ipconfig` for `<this-machine's-lan-ip>`.) This only covers the specific
peer(s) routed this way - any other LAN peer added to `bootstrap_nodes`
later would need its own host route, or (the more durable real fix, not
done here - it's the tunnel client's own config, out of this repo's scope)
the tunnel's `AllowedIPs` should be narrowed to exclude the home LAN
subnet entirely.

## notify_send deployment note

`notify_send`'s live config requires two values that are easy to forget since nothing fails loudly if they're missing — a node with `notify_send` in its `capabilities` list but no `notify_topic` set will silently never actually notify (found 2026-08-18: this was the case in production since the capability shipped, never caught because nothing exercised it end-to-end after the original build's throwaway test cleanup):

- `notify_topic` in `config.toml` — the ntfy topic this node posts to.
- `hosts.ntfy_url` in UAI's `uai_secrets.json` — defaults to public `ntfy.sh` if unset. Point this at a self-hosted instance if you have one; there's no reason to route personal notifications through a third party's free public service when a self-hosted alternative is one config line away.
