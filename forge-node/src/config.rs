//! Node configuration

use std::net::SocketAddr;
use std::path::PathBuf;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use axiom_crypto::identity::Keypair;

/// Configuration for a Forge node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Unique 32-byte node identifier
    #[serde(with = "hex_serde")]
    pub node_id: [u8; 32],

    /// Address to listen for AXIOM protocol connections
    pub listen_addr: SocketAddr,

    /// Address for the local management API
    pub api_addr: SocketAddr,

    /// Bootstrap nodes to connect to on startup
    pub bootstrap_nodes: Vec<SocketAddr>,

    /// Directory for persistent data
    pub data_dir: PathBuf,

    /// Maximum number of peer connections
    pub max_peers: usize,

    /// Enable the Guardian security module
    pub enable_guardian: bool,

    /// Enable the Watcher network monitoring module
    pub enable_watcher: bool,

    /// Discover same-subnet peers over IPv6 link-local multicast (ff02::1),
    /// with zero dependency on bootstrap/relay nodes. Falls back to
    /// `bootstrap_nodes` for anything not on the local link.
    ///
    /// `serde(default)` so config.toml files written before this field
    /// existed still load instead of erroring out.
    #[serde(default = "default_link_local_discovery")]
    pub enable_link_local_discovery: bool,

    /// CIDR allowlist (e.g. `["192.168.1.0/24"]`) gating which interfaces
    /// link-local discovery uses. Empty = unrestricted (fine for a
    /// stationary homelab box). REQUIRED before running this on a laptop or
    /// anything else that changes networks: without it, the node broadcasts
    /// its permanent Ed25519 pubkey + a timestamp every ~15s on every
    /// network its NIC joins - home, coffee shop, conference wifi, all
    /// treated identically. Set this to the home LAN subnet(s) so discovery
    /// goes silent everywhere else.
    #[serde(default)]
    pub link_local_trusted_subnets: Vec<String>,

    /// Capabilities this node offers, announced to peers after a handshake
    /// completes and looked up by name (via `axiom_router::ai::Intent::from_str`,
    /// which is what actually derives the wire `IntentHash` both sides agree
    /// on - see AXIOM-2's plan doc for why the wire `AnnouncedCapability`
    /// format can't carry the name itself). `"echo"` and `"sysinfo"` have real
    /// handlers (AXIOM-2 Cycle B, AXIOM-8 respectively); anything else here
    /// just gets announced with no way for a peer to actually fulfill it.
    #[serde(default = "default_capabilities")]
    pub capabilities: Vec<String>,

    /// AXIOM-10: base URL of a UAI broker this node can bridge the
    /// `"network_clients"` capability through (e.g. "http://192.168.1.11:7700").
    /// `None` disables the capability entirely rather than announcing
    /// something that can't actually be served. Deliberately NOT committed
    /// anywhere with a real value - this only ever lives in a runtime
    /// config.toml, never in source.
    #[serde(default)]
    pub uai_base_url: Option<String>,

    /// AXIOM-10: `X-UAI-Token` for the broker at `uai_base_url`. Same
    /// never-in-source rule as above - config.toml only.
    #[serde(default)]
    pub uai_token: Option<String>,

    /// AXIOM notify_send: the ntfy topic this node's `"notify_send"`
    /// capability posts to via the UAI broker's `ntfy_send` tool (the same
    /// `uai_base_url`/`uai_token` above carry the request there - this
    /// field is notify_send-specific because, unlike `network_clients`,
    /// notify_send needs a per-node "where do notifications go" knob and
    /// `network_clients` has no equivalent). `None` disables the
    /// capability entirely, same "don't announce something that can't
    /// actually be served" rule `uai_base_url`/`uai_token` already follow
    /// for `network_clients` - see `dispatch_notify_send` in `network.rs`.
    /// Not a secret (a topic name is not a credential - ntfy's own auth,
    /// if any, is resolved on UAI's side from UAI's own config, never
    /// supplied by AXIOM), but still config.toml-only, matching every
    /// other per-node capability knob in this struct.
    #[serde(default)]
    pub notify_topic: Option<String>,

    /// AXIOM Phase 1.1: path to a versioned, fail-closed capability
    /// access-control policy TOML file (schema `version = 2` as of Phase
    /// 3.1/3.2 - see `axiom_gateway::policy`'s module doc comment for the
    /// full contract), loaded once at startup and covering EVERY
    /// capability this node might serve (`echo`, `sysinfo`,
    /// `network_clients`, and any future one) - not just `network_clients`,
    /// which used to be the only capability with any allowlist at all
    /// (this field replaces the old `network_clients_allowed_peers:
    /// Vec<String>`, which only ever covered that one capability;
    /// `echo`/`sysinfo` used to be gated purely by `known_peers` - a
    /// completed signed HELLO handshake - which is not authorization,
    /// just proof of identity).
    ///
    /// Deliberately a SEPARATE file from this one (`config.toml`), not a
    /// field embedded here - the deployed copy is meant to live somewhere
    /// this node's own runtime service user cannot write to (see
    /// `axiom_gateway::policy`'s doc comment on why that matters for a later
    /// phase's "management plane stays outside AXIOM's own reach"
    /// invariant), same directory as `config.toml` itself
    /// (`/etc/forge/`), NOT `data_dir` (`/var/lib/forge/` by default,
    /// which the running service does own and write into for
    /// `node.key`/discovery state).
    ///
    /// Missing file, malformed TOML, an unsupported schema version
    /// (including a pre-v2 file with no `tier` field at all - it hits this
    /// exact case, not a parse failure), a capability with no entry, or a
    /// capability entry with no valid `tier`: that capability (or, for a
    /// whole-file failure, every capability) serves NO ONE. Never falls
    /// back to permissive, never falls back to the old known_peers-gates-it
    /// behavior - see `axiom_gateway::CapabilityPolicy::load`.
    #[serde(default = "default_capability_policy_path")]
    pub capability_policy_path: PathBuf,

    /// AXIOM-11.1: run a WAN accept loop (iroh, real internet, NOT the LAN
    /// link-local path above) alongside the normal LAN listener. Default
    /// false - most deployments should not be internet-reachable by
    /// default. See `axiom_transport::wan` for the transport itself.
    #[serde(default)]
    pub wan_enabled: bool,

    /// Hex-encoded `NodeId`s allowed to reach this node over the WAN.
    /// Same fail-closed default (empty = nobody, not "any known peer") and
    /// same log-and-skip-invalid-entries parsing as
    /// `capability_policy_path`'s `allowed_peers` entries above. Unlike the
    /// LAN path (which auto-accepts a HELLO from anyone on the segment), WAN has no such
    /// implicit trust - this allowlist is the ENTIRE gate, and there is no
    /// revocation system yet (see project-axiom.md), so changing this list
    /// requires restarting the node, not just editing config.toml live.
    #[serde(default)]
    pub wan_allowed_peers: Vec<String>,

    /// AXIOM Tier 2 Telegram approval channel: the bot token for PM's
    /// existing Telegram bot (`@ExampleBot`, KeePass entry "PM Telegram
    /// Bot") - the SAME bot `pm-agent`/`pm_agent.py` already uses for other
    /// alerts, per the owner's explicit decision not to stand up a second
    /// bot. `None` disables every Tier 2 capability entirely (they answer
    /// "not configured", same "don't announce something that can't
    /// actually be served" rule `uai_base_url`/`uai_token` already follow)
    /// rather than falling back to any other approval mechanism - never
    /// committed anywhere with a real value, config.toml only, same
    /// never-in-source rule as `uai_token`.
    #[serde(default)]
    pub telegram_bot_token: Option<String>,

    /// The ONE Telegram chat/user id whose replies (inline-keyboard
    /// Approve/Deny button presses) are ever honored as a real Tier 2
    /// approval decision - a real authentication boundary, not optional
    /// (see `telegram_approval`'s module doc comment). Matches PM's own
    /// `TELEGRAM_CHAT_ID` (KeePass "PM Telegram Bot" entry's notes field
    /// records this same id) - Larry's own chat with the bot. A plain
    /// decimal string (not `i64` directly) so a malformed value fails to
    /// parse loudly at startup (see `NetworkManager::new`) rather than
    /// silently truncating/wrapping.
    #[serde(default)]
    pub telegram_chat_id: Option<String>,
}

fn default_link_local_discovery() -> bool {
    true
}

fn default_capabilities() -> Vec<String> {
    vec!["echo".to_string(), "sysinfo".to_string()]
}

/// Same directory `config.toml` itself conventionally lives in
/// (`/etc/forge/`), not `data_dir` - see `capability_policy_path`'s doc
/// comment for why that separation matters.
fn default_capability_policy_path() -> PathBuf {
    PathBuf::from("/etc/forge/capability_policy.toml")
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: [0u8; 32], // Will be generated on init
            listen_addr: "0.0.0.0:7777".parse().unwrap(),
            api_addr: "127.0.0.1:7778".parse().unwrap(),
            bootstrap_nodes: vec![],
            data_dir: PathBuf::from("/var/lib/forge"),
            max_peers: 50,
            enable_guardian: true,
            enable_watcher: true,
            enable_link_local_discovery: true,
            link_local_trusted_subnets: vec![],
            capabilities: default_capabilities(),
            uai_base_url: None,
            uai_token: None,
            notify_topic: None,
            capability_policy_path: default_capability_policy_path(),
            wan_enabled: false,
            wan_allowed_peers: vec![],
            telegram_bot_token: None,
            telegram_chat_id: None,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a TOML file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .context("Failed to read config file")?;
        let config: NodeConfig = toml::from_str(&contents)
            .context("Failed to parse config file")?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        fs::write(path, contents)
            .context("Failed to write config file")?;
        Ok(())
    }

    /// Load this node's identity from `data_dir/node.key`, or generate a
    /// fresh ephemeral one if `node_id` was never configured
    /// (`[0u8; 32]` sentinel). Extracted here (2026-07-31) after this exact
    /// logic was found triplicated across `ForgeNode::new`,
    /// `request_intent_cmd`, and `wan_ping_cmd` - all three now call this
    /// instead of carrying their own copy.
    ///
    /// Identity is the address, in this protocol - a node silently running
    /// under a different key than `config.toml` declares is the worst class
    /// of bug this codebase can have (see project-axiom.md's AXIOM-11.2
    /// deploy incident: exactly this, invisible until caught via WAN-log
    /// forensics days later). If `node_id` is configured (non-zero) but the
    /// key file is missing, wrong size, or simply doesn't match what's
    /// declared, this returns an error instead of silently generating or
    /// loading a different identity - a coincidental match between a fresh
    /// random key and a specific configured node_id is astronomically
    /// unlikely, so this one check also covers the missing/wrong-size
    /// fallback paths for free.
    pub fn load_or_generate_identity(&self) -> Result<Keypair> {
        if self.node_id == [0u8; 32] {
            info!("Generating new node identity");
            return Ok(Keypair::generate());
        }

        let key_path = self.data_dir.join("node.key");
        let identity = if key_path.exists() {
            let key_bytes = fs::read(&key_path)?;
            if key_bytes.len() != 32 {
                warn!(
                    "Key file {} is {} bytes, expected 32 - generating ephemeral identity",
                    key_path.display(),
                    key_bytes.len()
                );
                Keypair::generate()
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                Keypair::from_bytes(&arr)
            }
        } else {
            warn!("Node ID configured but no key file found, generating ephemeral identity");
            Keypair::generate()
        };

        if identity.node_id().as_bytes() != &self.node_id {
            anyhow::bail!(
                "Identity mismatch: config.toml declares node_id {} but the node identity actually loaded/generated at startup is {} - refusing to start under a different identity than configured. Check {} exists and matches, or re-run `forge-node init --force` if this key was legitimately replaced.",
                hex::encode(self.node_id),
                hex::encode(identity.node_id().as_bytes()),
                key_path.display(),
            );
        }

        Ok(identity)
    }
}

/// Serde helper for hex-encoded byte arrays
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}
