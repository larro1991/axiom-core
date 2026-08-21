//! IPv6 link-local peer discovery.
//!
//! fe80::/64 addresses are assigned by the kernel the moment a NIC comes up,
//! with no DHCP/router/ISP involvement, so this discovery path keeps working
//! even when the node's configured IPv4 `listen_addr` is unreachable (the
//! scenario the owner proved out over SSH before requesting this).

use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use axiom_crypto::identity::Keypair;
use axiom_router::announce::AnnouncementManager;
use axiom_router::semantic::SemanticRouter;
use axiom_types::NodeId;
use axiom_types::crypto::TraceId;

use crate::network::{
    build_hello_frame, decode_verified_frame, extract_sender_with_timestamp, handle_axiom_frame,
    ForwardedFrameCache, PendingIntent, PendingPing, Tier2Flow, UaiConfig,
};
use crate::node::NetworkEvent;
use axiom_gateway::CapabilityPolicy;

/// ff02::1 (all-nodes link-local multicast) instead of a custom group: every
/// IPv6 stack already maintains membership/routing state for it, so nodes
/// need no extra multicast group management beyond what the kernel does for
/// Neighbor Discovery.
const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Kept off the AXIOM protocol port (7777 by default) and the local API
/// port (7778) so discovery traffic can never collide with either.
const DISCOVERY_PORT: u16 = 7790;

const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15);

/// Minimum gap between processing two packets from the same source address,
/// applied before signature verification to bound flood cost.
const RATE_LIMIT_INTERVAL: Duration = Duration::from_millis(200);

/// Prune the per-source rate-limit map once it holds this many entries -
/// bounds memory against a flood of spoofed source addresses (each a
/// distinct HashMap key) rather than letting it grow without limit.
const MAX_RATE_LIMIT_ENTRIES: usize = 1024;

/// Reject HELLOs whose signed timestamp is older than this - bounds how long
/// a captured frame stays replayable even before the per-peer monotonic
/// check in `register_peer` runs.
const MAX_HELLO_AGE_SECS: u64 = 60;

/// Reject HELLOs timestamped further in the future than this - generous
/// enough for real clock drift, tight enough to catch a forged/corrupt
/// timestamp instead of just accepting it as "not stale yet".
const MAX_CLOCK_SKEW_SECS: u64 = 5;

/// Whether a HELLO's signed timestamp (`hello_ts`, unix seconds) is fresh
/// enough to accept, relative to `now_secs` - at most `MAX_HELLO_AGE_SECS`
/// old, and at most `MAX_CLOCK_SKEW_SECS` in the future. Pulled out of the
/// receive loop below as its own pure function (AXIOM Phase 1.2/AXIOM-15) so
/// the exact boundary - one tick inside passes, one tick outside fails - is
/// directly unit-testable, without needing a real socket round trip timed to
/// land on the boundary.
fn hello_timestamp_is_fresh(hello_ts: u64, now_secs: u64) -> bool {
    let age = now_secs.saturating_sub(hello_ts);
    let future_skew = hello_ts.saturating_sub(now_secs);
    age <= MAX_HELLO_AGE_SECS && future_skew <= MAX_CLOCK_SKEW_SECS
}

/// Whether `ip` should be rate-limited right now (dropped without
/// inspection), given `recently_failed` - true only if `ip` had a
/// decode/verification failure within the last `RATE_LIMIT_INTERVAL`. Pulled
/// out of the receive loop below as its own pure function (AXIOM Phase
/// 1.2/AXIOM-15) so the "gate on verification FAILURE, not mere traffic"
/// behavior (see the receive loop's own comment for the bug this fixed - two
/// legitimate frames from one source in the same instant used to collide on
/// this limit regardless of type) is directly testable against a `HashMap`
/// fixture, without a real socket or real flood of packets.
fn is_recently_failed(
    recently_failed: &HashMap<std::net::IpAddr, std::time::Instant>,
    ip: std::net::IpAddr,
    now: std::time::Instant,
) -> bool {
    match recently_failed.get(&ip) {
        Some(last_fail) => now.duration_since(*last_fail) < RATE_LIMIT_INTERVAL,
        None => false,
    }
}

/// A link-local (fe80::/64) address bound to a specific interface.
#[derive(Debug, Clone)]
struct LinkLocalIface {
    name: String,
    index: u32,
}

/// Virtual/container/VPN interface name prefixes excluded by default: joining
/// these bleeds discovery across boundaries the human considers isolated
/// (Docker bridges, veth pairs, WireGuard/other VPN tunnels, libvirt) even
/// though they carry a fe80 address like any real NIC.
#[cfg(target_os = "linux")]
const EXCLUDED_IFACE_PREFIXES: &[&str] = &[
    "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "vmnet", "tailscale",
];

#[cfg(target_os = "linux")]
fn is_excluded_iface(name: &str) -> bool {
    if name == "lo" || EXCLUDED_IFACE_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    is_point_to_point_iface(name)
}

/// True if the kernel flags `name` as point-to-point (IFF_POINTOPOINT, 0x10).
/// Catches tunnel-class interfaces generically - Tailscale, ZeroTier, Nebula,
/// and anything else that isn't in `EXCLUDED_IFACE_PREFIXES` by name but is
/// still a tunnel, not a real L2 segment. A HELLO sent down one of these
/// still only reaches this node's own tunnel endpoint (no multicast forwarding
/// on typical VPN interfaces), but excluding by kernel flag means new tunnel
/// software doesn't need its own prefix added here to be caught.
#[cfg(target_os = "linux")]
fn is_point_to_point_iface(name: &str) -> bool {
    const IFF_POINTOPOINT: u64 = 0x10;
    let Ok(flags_str) = fs::read_to_string(format!("/sys/class/net/{name}/flags")) else {
        return false;
    };
    let Ok(flags) = u64::from_str_radix(flags_str.trim().trim_start_matches("0x"), 16) else {
        return false;
    };
    flags & IFF_POINTOPOINT != 0
}

/// Windows port (2026-08-15): a second, name-based layer on top of
/// `enumerate_link_local_interfaces`'s own `OperStatus`/`IfType` filtering
/// below (which does the real, precise Win32-flag-based exclusion - see
/// that function's doc comment). This one is intentionally cruder (keyword
/// matching on the adapter's friendly name/description), kept as
/// defense-in-depth for whatever a vendor's adapter reports under a
/// "normal" IfType (e.g. some VPN clients' TAP adapters present as plain
/// Ethernet) - matches this codebase's own layered-defense pattern
/// elsewhere (see `docker_restart`'s 4-layer allowlist in `network.rs`).
#[cfg(windows)]
fn is_excluded_iface(name: &str) -> bool {
    const EXCLUDED_KEYWORDS: &[&str] = &[
        "loopback", "docker", "veth", "virtual", "vethernet", "vmware", "virtualbox",
        "hyper-v", "wsl", "tailscale", "wireguard", "zerotier", "nebula", "tap-", "tun",
        "npcap", "ppp", "vpn", "bluetooth",
    ];
    let lower = name.to_lowercase();
    EXCLUDED_KEYWORDS.iter().any(|k| lower.contains(k))
}

/// Very small IPv4 CIDR matcher - avoids pulling in the `ipnet` crate for one
/// comparison. `cidr` is "a.b.c.d/nn"; any parse error returns `false` - a
/// malformed trusted-subnet entry must fail closed, not open.
fn ipv4_in_cidr(addr: Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else { return false };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else { return false };
    let Ok(prefix) = prefix_str.parse::<u32>() else { return false };
    if prefix > 32 {
        return false;
    }
    let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

/// Current IPv4 addresses on `iface`. Shells out to `ip` rather than parsing
/// procfs by hand - unlike link-local v6 (one simple file, `/proc/net/if_inet6`),
/// IPv4 address+prefix isn't exposed in an equally trivial format, and
/// iproute2/busybox-ip is present on every target host.
#[cfg(target_os = "linux")]
fn iface_ipv4_addrs(iface: &str) -> Vec<Ipv4Addr> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let rest = line.split_once("inet ")?.1;
            let cidr = rest.split_whitespace().next()?;
            let (ip_str, _) = cidr.split_once('/')?;
            ip_str.parse::<Ipv4Addr>().ok()
        })
        .collect()
}

/// Windows port (2026-08-15): no `ip`/iproute2 equivalent to shell out to -
/// `if-addrs` (backed by `GetAdaptersAddresses`) already gives every
/// interface's addresses in one call, so this just filters that same
/// enumeration down to `iface`'s IPv4 entries instead of a second subprocess
/// call, which Windows has no standard equivalent of anyway.
#[cfg(windows)]
fn iface_ipv4_addrs(iface: &str) -> Vec<Ipv4Addr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .into_iter()
        .filter(|i| i.name == iface)
        .filter_map(|i| match i.addr.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

/// True if `iface` should be used for discovery, given `trusted_subnets`
/// (CIDR strings from `NodeConfig::link_local_trusted_subnets`).
///
/// An empty list means "no restriction configured" - preserves the original
/// zero-config behavior for stationary boxes. A non-empty list means the
/// operator has opted into network-aware gating (required before this ever
/// runs on a laptop/portable machine - see the beacon/tracking caveat in
/// project-sentry-fleet.md): the interface's *current* IPv4 address must
/// fall in one of the trusted subnets, or discovery stays silent on it. An
/// interface with no IPv4 at all, or on an unrecognized network (coffee
/// shop, conference wifi), fails closed rather than defaulting to trusted.
fn iface_is_trusted(iface: &str, trusted_subnets: &[String]) -> bool {
    if trusted_subnets.is_empty() {
        return true;
    }
    iface_ipv4_addrs(iface)
        .iter()
        .any(|addr| trusted_subnets.iter().any(|cidr| ipv4_in_cidr(*addr, cidr)))
}

/// Parse `/proc/net/if_inet6` for fe80::/64 addresses. Each line already
/// carries the kernel's interface index in column 2, so no separate
/// `if_nametoindex()` / `/sys/class/net` lookup (and no new libc/if-addrs
/// dependency) is needed.
#[cfg(target_os = "linux")]
fn enumerate_link_local_interfaces() -> io::Result<Vec<LinkLocalIface>> {
    let contents = fs::read_to_string("/proc/net/if_inet6")?;
    let mut out = Vec::new();

    for line in contents.lines() {
        // addr(32 hex) ifindex(hex) prefixlen(hex) scope(hex) flags(hex) name
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        let addr_hex = fields[0];
        if addr_hex.len() != 32 || &addr_hex[0..4] != "fe80" {
            continue;
        }

        let name = fields[5];
        if is_excluded_iface(name) {
            continue;
        }

        let index = match u32::from_str_radix(fields[1], 16) {
            Ok(i) => i,
            Err(_) => continue,
        };

        out.push(LinkLocalIface { name: name.to_string(), index });
    }

    Ok(out)
}

/// True if `addr` is a unicast link-local (fe80::/10) IPv6 address. Hand-
/// rolled the same way this module's own `ipv4_in_cidr` is (avoids pulling
/// in a dependency for one bitmask check) - equivalent to the still-unstable
/// `Ipv6Addr::is_unicast_link_local`.
#[cfg(windows)]
fn is_unicast_link_local_v6(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Windows port (2026-08-15) of `/proc/net/if_inet6` enumeration above -
/// there is no procfs here, so this is a genuinely different code path, not
/// a `#[cfg]` tweak of the Linux one.
///
/// The `if-addrs` crate (used below for `iface_ipv4_addrs`, where it works
/// fine) was tried here first and turned out NOT to work for this - live
/// testing on the real target laptop (2026-08-15) showed `if-addrs` never
/// returns fe80 addresses on Windows at all, only global/loopback ones -
/// confirmed empirically with a throwaway probe binary before writing any
/// of this, not assumed from docs. So this calls Win32's
/// `GetAdaptersAddresses` (the same API `ipconfig`/`if-addrs`/`ipconfig`
/// crate all sit on top of) directly via `windows-sys` instead - more code
/// than a wrapper crate, but every field used below was verified against a
/// real adapter list on the real target machine first, not guessed at.
#[cfg(windows)]
fn enumerate_link_local_interfaces() -> io::Result<Vec<LinkLocalIface>> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, AF_UNSPEC, SOCKADDR_IN6};

    // IF_OPER_STATUS_UP (iptypes.h) - only interfaces the OS itself
    // considers actually up. This alone is what separates the laptop's real
    // Wi-Fi adapter from the several disconnected/inactive pseudo-adapters
    // (Wi-Fi Direct virtual adapters, an idle wired port) Windows always
    // carries even when unused - confirmed on the real target laptop, where
    // 5 of 7 non-loopback adapters were down at any given moment.
    const IF_OPER_STATUS_UP: i32 = 1;
    // IFTYPE values (ifdef.h) excluded the same way Linux's IFF_POINTOPOINT
    // check excludes tunnel-class interfaces: loopback, PPP, generic
    // "tunnel", and IF_TYPE_PROP_VIRTUAL (53) - the type Windows reports
    // for OpenVPN/WireGuard-style TAP adapters, confirmed on the real
    // target laptop where the ExpressVPN TAP adapter (and an oddly-named
    // duplicate of it sharing the hostname as its "friendly name") both
    // reported IfType 53 while the real Wi-Fi adapter reported 71
    // (IF_TYPE_IEEE80211) - a far more reliable signal than trying to
    // pattern-match every VPN vendor's adapter name.
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_TUNNEL: u32 = 131;
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    const EXCLUDED_IFTYPES: &[u32] = &[
        IF_TYPE_SOFTWARE_LOOPBACK,
        IF_TYPE_PPP,
        IF_TYPE_TUNNEL,
        IF_TYPE_PROP_VIRTUAL,
    ];

    // Microsoft's own documented pattern for this API: try a reasonable
    // starting size, grow to whatever size the call itself reports back if
    // that wasn't enough, retry a bounded number of times rather than
    // looping forever against a pathological adapter count.
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 15_000;
    let mut buf: Vec<u8>;
    let mut attempts = 0;
    loop {
        buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        attempts += 1;
        if ret == 0 {
            break;
        }
        if ret == ERROR_BUFFER_OVERFLOW && attempts < 3 {
            continue; // `size` was updated in place to the required size
        }
        return Err(io::Error::from_raw_os_error(ret as i32));
    }

    let mut out = Vec::new();
    let mut seen_names = HashSet::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        // SAFETY: `cur` is either the buffer `GetAdaptersAddresses` just
        // filled in (still valid, `buf` is still alive) or a `Next` pointer
        // it wrote into that same buffer - never null when the loop
        // condition above lets us in.
        let adapter = unsafe { &*cur };

        let up_and_real_link = adapter.OperStatus == IF_OPER_STATUS_UP
            && !EXCLUDED_IFTYPES.contains(&adapter.IfType);

        if up_and_real_link {
            let name = adapter_friendly_name(adapter);
            if !is_excluded_iface(&name) {
                let mut ucur = adapter.FirstUnicastAddress;
                while !ucur.is_null() {
                    // SAFETY: same reasoning as `adapter` above - this
                    // walks a linked list Windows built inside the same
                    // still-alive `buf`.
                    let unicast = unsafe { &*ucur };
                    let sockaddr = unicast.Address.lpSockaddr;
                    if !sockaddr.is_null() {
                        // SAFETY: `GetAdaptersAddresses` guarantees
                        // `lpSockaddr` points at a real `SOCKADDR` for
                        // `iSockaddrLength` bytes; reading only the
                        // `sa_family` header field first (before
                        // reinterpreting as the larger IPv6-specific
                        // struct below) matches how every C caller of
                        // this API is documented to distinguish v4 from
                        // v6 entries.
                        let family = unsafe { (*sockaddr).sa_family };
                        if family == AF_INET6 {
                            let sin6 = sockaddr as *const SOCKADDR_IN6;
                            let addr_bytes: [u8; 16] = unsafe { (*sin6).sin6_addr.u.Byte };
                            let v6 = Ipv6Addr::from(addr_bytes);
                            if is_unicast_link_local_v6(&v6) && seen_names.insert(name.clone()) {
                                out.push(LinkLocalIface { name: name.clone(), index: adapter.Ipv6IfIndex });
                            }
                        }
                    }
                    ucur = unicast.Next;
                }
            }
        }

        cur = adapter.Next;
    }

    Ok(out)
}

/// Decode `IP_ADAPTER_ADDRESSES_LH::FriendlyName` (a NUL-terminated
/// `PWSTR`) into an owned `String`. Pulled out of
/// `enumerate_link_local_interfaces` on its own so the one block of raw
/// pointer-walking this port needs is isolated and named, not inlined into
/// the middle of the adapter-list loop above.
#[cfg(windows)]
fn adapter_friendly_name(adapter: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH) -> String {
    let p = adapter.FriendlyName;
    if p.is_null() {
        return String::from("<unnamed>");
    }
    // SAFETY: `FriendlyName` is documented as a NUL-terminated UTF-16
    // string owned by the same buffer `adapter` itself points into; walking
    // it to find the terminator before building the slice is the standard
    // pattern for a Win32 `PWSTR` with no length given separately.
    let len = unsafe {
        let mut n = 0usize;
        let mut cursor = p;
        while *cursor != 0 {
            n += 1;
            cursor = cursor.add(1);
        }
        n
    };
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// Bind the shared discovery socket and join the all-nodes group on every
/// link-local interface. One socket is enough for receiving from all of
/// them: on Linux, `recv_from` fills in the peer address's `sin6_scope_id`
/// with the *receiving* interface's index for any link-local source, even
/// on a socket bound to the unspecified address - no per-interface socket
/// needed to recover it.
async fn bind_discovery_socket(ifaces: &[LinkLocalIface]) -> io::Result<UdpSocket> {
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DISCOVERY_PORT, 0, 0));
    let socket = UdpSocket::bind(bind_addr).await?;

    for iface in ifaces {
        if let Err(e) = socket.join_multicast_v6(&MULTICAST_GROUP, iface.index) {
            warn!("Failed to join ff02::1 on {} (idx {}): {}", iface.name, iface.index, e);
        }
    }

    Ok(socket)
}

/// Start link-local discovery: periodically announce our HELLO on every
/// fe80 interface's all-nodes multicast group, and register any peer whose
/// HELLO we hear in return. Returns the bound socket so `NetworkManager` can
/// reuse it to actually reach discovered peers (a socket bound to an IPv4
/// address can't send AF_INET6 traffic).
///
/// Non-fatal if no link-local interfaces exist (e.g. a container with no
/// real NIC) - discovery just stays idle rather than failing node startup.
///
/// `trusted_subnets`: CIDR allowlist from `NodeConfig::link_local_trusted_subnets`.
/// Empty = unrestricted (stationary-box default). Non-empty = only announce/
/// listen on interfaces currently on one of those subnets - required before
/// this runs on a laptop or anything else that changes networks, otherwise
/// it broadcasts this node's permanent Ed25519 pubkey on every wifi it joins.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    identity: Keypair,
    main_socket: Arc<UdpSocket>,
    event_tx: mpsc::Sender<NetworkEvent>,
    trusted_subnets: Vec<String>,
    pending_pings: Arc<Mutex<HashMap<TraceId, PendingPing>>>,
    known_peers: Arc<std::sync::Mutex<HashSet<NodeId>>>,
    peer_addrs: Arc<std::sync::Mutex<HashMap<NodeId, SocketAddr>>>,
    forwarded_frames: Arc<std::sync::Mutex<ForwardedFrameCache>>,
    pending_intents: Arc<Mutex<HashMap<TraceId, PendingIntent>>>,
    semantic_router: Arc<Mutex<SemanticRouter>>,
    announcement_mgr: Arc<Mutex<AnnouncementManager>>,
    reachable_via: Arc<std::sync::Mutex<HashMap<NodeId, (NodeId, std::time::Instant)>>>,
    reverse_routes: Arc<std::sync::Mutex<HashMap<TraceId, (SocketAddr, std::time::Instant)>>>,
    origin_admission: Arc<std::sync::Mutex<HashMap<NodeId, (std::time::Instant, HashSet<NodeId>)>>>,
    local_capabilities: Arc<Vec<String>>,
    last_announce_from: Arc<std::sync::Mutex<HashMap<(NodeId, NodeId), std::time::Instant>>>,
    uai_config: Arc<Option<UaiConfig>>,
    notify_topic: Arc<Option<String>>,
    policy: Arc<CapabilityPolicy>,
    tier2_flow: Option<Arc<Tier2Flow>>,
    audit_log: Option<Arc<axiom_gateway::AuditLog>>,
) -> Option<Arc<UdpSocket>> {
    let ifaces = match enumerate_link_local_interfaces() {
        Ok(ifaces) if !ifaces.is_empty() => ifaces,
        Ok(_) => {
            info!("No link-local IPv6 interfaces found; link-local discovery idle");
            return None;
        }
        Err(e) => {
            warn!("Could not enumerate link-local interfaces: {}", e);
            return None;
        }
    };

    let ifaces: Vec<LinkLocalIface> = ifaces
        .into_iter()
        .filter(|iface| {
            let trusted = iface_is_trusted(&iface.name, &trusted_subnets);
            if !trusted {
                info!(
                    "Link-local discovery skipping {} - not on a trusted subnet (portable/roaming safety)",
                    iface.name
                );
            }
            trusted
        })
        .collect();

    if ifaces.is_empty() {
        info!("No trusted link-local interfaces; discovery idle (beacon suppressed)");
        return None;
    }

    let socket = match bind_discovery_socket(&ifaces).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("Failed to bind IPv6 link-local discovery socket: {}", e);
            return None;
        }
    };

    info!(
        "Link-local discovery active on {} interface(s): {}",
        ifaces.len(),
        ifaces.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ")
    );

    let local_id = identity.node_id();
    let identity_for_receive = identity.clone();

    // Announce loop: rebuild the HELLO each round so the timestamp/signature
    // stay fresh rather than replaying one frame forever.
    {
        let socket = socket.clone();
        let ifaces = ifaces.clone();
        tokio::spawn(async move {
            loop {
                let hello = build_hello_frame(&identity);
                for iface in &ifaces {
                    let dest = SocketAddr::V6(SocketAddrV6::new(MULTICAST_GROUP, DISCOVERY_PORT, 0, iface.index));
                    if let Err(e) = socket.send_to(&hello, dest).await {
                        debug!("Discovery announce on {} failed: {}", iface.name, e);
                    }
                }
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        });
    }

    // Receive loop
    {
        let socket = socket.clone();
        // AXIOM-14 Cycle 4 (Fable full-repo review finding #4): a frame
        // arriving on THIS (link-local) socket may need re-gossiping or
        // forwarding to an IPv4 peer, which `send_via` (in network.rs)
        // can't do over this socket - it needs the real main socket too,
        // not just this one relabeled.
        let main_socket = main_socket.clone();
        let identity = identity_for_receive;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            // Per-source-address rate limit - but only counts against a
            // source once it has actually sent something that fails BOTH
            // decode paths (neither a valid HELLO nor a signature-verified
            // Frame). It used to gate on source address alone, before even
            // looking at content: that broke the moment this socket started
            // carrying more than one legitimate message per discovery event
            // (Ping + Announce, fired back-to-back by the same peer on every
            // `PeerDiscovered`) - both packets arrive from the same source
            // within microseconds of each other, so the second one always
            // landed inside the window and was silently dropped, regardless
            // of which message it was. Gating on verification *failure*
            // instead keeps the original intent (bound the CPU a flooding/
            // spoofing source can force via repeated signature verification)
            // without penalizing a real peer for legitimately sending more
            // than one message at once.
            let mut recently_failed: HashMap<std::net::IpAddr, std::time::Instant> = HashMap::new();

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, from)) => {
                        let now_instant = std::time::Instant::now();
                        let ip = from.ip();
                        if is_recently_failed(&recently_failed, ip, now_instant) {
                            continue;
                        }

                        let Some((sender_id, hello_ts)) = extract_sender_with_timestamp(&buf[..len]) else {
                            // Not a HELLO - this socket is also where every
                            // Ping/Pong/Announce/Intent/Fulfill/Error to a
                            // link-local peer actually arrives (send_raw
                            // routes anything link-local here, and a socket
                            // bound to an IPv4 address can't receive AF_INET6
                            // traffic at all, so there's no other socket for
                            // it to land on). Provably disjoint from the
                            // HELLO family by wire format (HELLO magic byte 0
                            // is 0x41; codec frames always pack 0b10 into
                            // byte 0's top 2 bits, landing in 0x80-0xBF).
                            if let Some(frame) = decode_verified_frame(&buf[..len]) {
                                handle_axiom_frame(
                                    frame, from, &main_socket, &Some(socket.clone()), &pending_pings, &known_peers,
                                    &peer_addrs, &forwarded_frames,
                                    &pending_intents, &semantic_router, &announcement_mgr,
                                    &reachable_via, &reverse_routes, &origin_admission, &local_capabilities,
                                    &last_announce_from, &identity, &uai_config, &notify_topic,
                                    &policy, &tier2_flow, &audit_log,
                                ).await;
                            } else {
                                // Neither a HELLO nor a verified Frame - genuine
                                // garbage/spoofed traffic, the case the rate
                                // limit exists for. Bound memory against a
                                // flood of spoofed source addresses (each a
                                // distinct HashMap key) the same way the old
                                // code did, just scoped to actual failures now.
                                if recently_failed.len() >= MAX_RATE_LIMIT_ENTRIES {
                                    recently_failed.retain(|_, seen| now_instant.duration_since(*seen) < RATE_LIMIT_INTERVAL);
                                }
                                recently_failed.insert(ip, now_instant);
                                debug!("Discovery: dropping unrecognized/unverified packet from {}", from);
                            }
                            continue;
                        };
                        if sender_id == local_id {
                            continue; // our own announcement looped back
                        }

                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        // Bounds a captured-and-later-replayed HELLO to a short
                        // window; per-NodeId monotonicity (rejecting an exact or
                        // earlier replay within the window) is enforced downstream
                        // in `NetworkManager::register_peer`, which has the
                        // per-peer last-seen state this loop doesn't.
                        let age = now_secs.saturating_sub(hello_ts);
                        let future_skew = hello_ts.saturating_sub(now_secs);
                        if !hello_timestamp_is_fresh(hello_ts, now_secs) {
                            debug!(
                                "Rejecting HELLO from {} at {}: stale/skewed timestamp (age {}s, future {}s)",
                                hex::encode(sender_id.as_bytes()), from, age, future_skew
                            );
                            continue;
                        }

                        debug!("Discovered peer {} at {}", hex::encode(sender_id.as_bytes()), from);
                        let _ = event_tx.send(NetworkEvent::PeerDiscovered {
                            node_id: sender_id,
                            addr: from,
                            timestamp: hello_ts,
                        }).await;
                    }
                    Err(e) => {
                        warn!("Discovery receive error: {}", e);
                    }
                }
            }
        });
    }

    Some(socket)
}

/// AXIOM Phase 1.2 (AXIOM-15): unit coverage for the two pure functions
/// pulled out of the receive loop above - `enumerate_link_local_interfaces`/
/// `bind_discovery_socket` and the loop itself all need real fe80 interfaces
/// or a live socket to exercise (deliberately excluded from this codebase's
/// unit tests - see `network.rs`'s `multihop_tests` module doc comment for
/// why real interface-dependent behavior doesn't belong in a unit test), but
/// timestamp freshness and the rate limiter's own gating logic need neither
/// and are tested directly here instead.
#[cfg(test)]
mod tests {
    use super::*;

    // --- hello_timestamp_is_fresh: age boundary (MAX_HELLO_AGE_SECS = 60s) ---

    #[test]
    fn hello_fresh_at_zero_age_and_zero_skew() {
        assert!(hello_timestamp_is_fresh(1_000, 1_000));
    }

    #[test]
    fn hello_fresh_at_exact_max_age_boundary() {
        // age == MAX_HELLO_AGE_SECS exactly - one tick INSIDE the window,
        // must still pass (the check is `age > MAX_HELLO_AGE_SECS`, not `>=`).
        assert!(hello_timestamp_is_fresh(1_000, 1_000 + MAX_HELLO_AGE_SECS));
    }

    #[test]
    fn hello_stale_one_second_past_max_age_boundary() {
        // age == MAX_HELLO_AGE_SECS + 1 - one tick OUTSIDE the window, must fail.
        assert!(!hello_timestamp_is_fresh(1_000, 1_000 + MAX_HELLO_AGE_SECS + 1));
    }

    // --- hello_timestamp_is_fresh: future-skew boundary (MAX_CLOCK_SKEW_SECS = 5s) ---

    #[test]
    fn hello_fresh_at_exact_max_future_skew_boundary() {
        // hello_ts exactly MAX_CLOCK_SKEW_SECS ahead of now - one tick
        // INSIDE the window, must still pass.
        assert!(hello_timestamp_is_fresh(1_000 + MAX_CLOCK_SKEW_SECS, 1_000));
    }

    #[test]
    fn hello_stale_one_second_past_max_future_skew_boundary() {
        // hello_ts MAX_CLOCK_SKEW_SECS + 1 ahead of now - one tick OUTSIDE
        // the window, must fail.
        assert!(!hello_timestamp_is_fresh(1_000 + MAX_CLOCK_SKEW_SECS + 1, 1_000));
    }

    #[test]
    fn hello_stale_far_in_the_past_is_rejected() {
        assert!(!hello_timestamp_is_fresh(1_000, 1_000 + 3600));
    }

    // --- is_recently_failed: the actual regression this exists for ---

    /// THE regression this whole module's history section is about: two
    /// legitimate frames from the SAME source in the same instant (e.g. a
    /// Ping and an Announce, fired back-to-back on every `PeerDiscovered`)
    /// must not collide on this limit - it only ever gates on a source that
    /// has itself produced a decode/verification FAILURE, never on mere
    /// traffic volume/diversity from a source that's only ever sent
    /// legitimate frames.
    #[test]
    fn source_with_no_prior_failure_is_never_rate_limited() {
        let recently_failed = HashMap::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!is_recently_failed(&recently_failed, ip, std::time::Instant::now()));
    }

    #[test]
    fn source_with_recent_failure_is_rate_limited() {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mut recently_failed = HashMap::new();
        let now = std::time::Instant::now();
        recently_failed.insert(ip, now);
        assert!(is_recently_failed(&recently_failed, ip, now));
    }

    #[test]
    fn source_failure_past_the_interval_is_no_longer_rate_limited() {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mut recently_failed = HashMap::new();
        // Backdated well past RATE_LIMIT_INTERVAL (200ms) - the window has
        // genuinely elapsed, not just barely.
        let past_failure = std::time::Instant::now()
            .checked_sub(RATE_LIMIT_INTERVAL + Duration::from_secs(1))
            .expect("test host clock must support subtracting ~1.2s from now");
        recently_failed.insert(ip, past_failure);
        assert!(!is_recently_failed(&recently_failed, ip, std::time::Instant::now()));
    }

    #[test]
    fn rate_limit_is_scoped_per_source_ip_not_global() {
        let failed_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let other_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();
        let mut recently_failed = HashMap::new();
        let now = std::time::Instant::now();
        recently_failed.insert(failed_ip, now);

        assert!(
            is_recently_failed(&recently_failed, failed_ip, now),
            "the source that actually failed must be rate-limited"
        );
        assert!(
            !is_recently_failed(&recently_failed, other_ip, now),
            "a DIFFERENT source with no failure of its own must never be rate-limited by another source's failure"
        );
    }
}
