# AXIOM Layer 3: Identity-Based Networking (IP-Free)

## Overview

This specification defines an IP-free networking layer for AI-to-AI communication. Instead of location-based addressing (IP), AXIOM uses cryptographic identity as the fundamental addressing primitive.

```
┌─────────────────────────────────────────────────────────────────┐
│                    AXIOM NETWORK STACK                           │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: APPLICATION                                            │
│           Intent requests, capability negotiation                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: TRUST                                                  │
│           Authentication, encryption, trust levels               │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: IDENTITY ROUTING  ← This specification                 │
│           NodeId-based addressing, semantic routing              │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: MESH TRANSPORT                                         │
│           Local broadcast, neighbor relay                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: PHYSICAL                                               │
│           Ethernet, wireless, serial, etc.                       │
└─────────────────────────────────────────────────────────────────┘
```

## Design Principles

1. **Identity IS Address** - Cryptographic public key is the only identifier needed
2. **Route by Capability** - Find nodes that CAN do something, not WHERE they are
3. **Trust as Firewall** - Cryptographic trust replaces network perimeters
4. **Zero Configuration** - Agents generate their own identity, no DHCP/DNS
5. **Location Agnostic** - Same identity works anywhere in the mesh

## Addressing

### NodeId (The Only Address You Need)

```
┌─────────────────────────────────────────────────────────────────┐
│                         NodeId (32 bytes)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Ed25519 Public Key = Network Address                          │
│                                                                  │
│   0x7a3f8b2c...9d2e4f1a (32 bytes / 256 bits)                   │
│                                                                  │
│   • Globally unique (256-bit keyspace)                          │
│   • Self-generated (no authority needed)                        │
│   • Cryptographically verifiable                                │
│   • Unforgeable                                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Address Generation

```rust
/// Generate a new network identity
pub fn generate_identity() -> (NodeId, Keypair) {
    let keypair = Keypair::generate();
    let node_id = NodeId::from(keypair.public());
    (node_id, keypair)
}

// That's it. No DHCP. No registration. No authority.
// The AI generates its own address and it's valid forever.
```

### Address Format

```
Full:     0x7a3f8b2c1d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
Short:    7a3f8b...8f9a (for display)
Base58:   AxM7kP9...Qr3 (human-friendly)
DID:      did:axiom:7a3f8b2c1d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
```

## Removed Concepts

| IP Concept | Status | Replacement |
|------------|--------|-------------|
| IP Address | ❌ Removed | NodeId (public key) |
| Port Numbers | ❌ Removed | Intent routing |
| Subnet | ❌ Removed | Trust domains |
| DNS | ❌ Removed | Semantic discovery |
| DHCP | ❌ Removed | Self-generation |
| NAT | ❌ Removed | Not needed |
| BGP | ❌ Removed | Gossip + trust |
| ARP | ❌ Removed | Identity broadcast |
| ICMP | ⚠️ Modified | Health frames |

## Routing

### Three Routing Modes

```
┌─────────────────────────────────────────────────────────────────┐
│                      ROUTING MODES                               │
└─────────────────────────────────────────────────────────────────┘

1. DIRECT ROUTING (I know exactly who I want)
   ┌──────┐                              ┌──────┐
   │Node A│ ─── "Send to NodeId 0xB" ───▶│Node B│
   └──────┘                              └──────┘

2. INTENT ROUTING (I know what I need, find someone)
   ┌──────┐                              ┌──────┐
   │Node A│ ─── "Need llm:completion" ──▶│  ??  │
   └──────┘         ↓                    └──────┘
              Mesh finds best match

3. BROADCAST ROUTING (Everyone needs to hear this)
   ┌──────┐       ┌──────┐  ┌──────┐  ┌──────┐
   │Node A│ ────▶ │Node B│  │Node C│  │Node D│
   └──────┘       └──────┘  └──────┘  └──────┘
              "Announcement to all"
```

### Routing Table Structure

```rust
/// Identity-based routing table (replaces IP routing table)
pub struct IdentityRoutingTable {
    /// Direct routes: NodeId → how to reach them
    direct: HashMap<NodeId, RouteInfo>,

    /// Intent routes: IntentHash → NodeIds that can fulfill
    intent: HashMap<IntentHash, Vec<NodeId>>,

    /// Trust routes: prefer paths through trusted nodes
    trust_weights: HashMap<NodeId, TrustLevel>,

    /// Neighbor table: directly connected peers
    neighbors: HashMap<NodeId, NeighborInfo>,
}

pub struct RouteInfo {
    /// Next hop to reach destination
    next_hop: NodeId,
    /// Number of hops
    hop_count: u8,
    /// Path trust score
    trust_score: f32,
    /// Latency estimate
    latency_ms: u16,
    /// Last update timestamp
    last_seen: u64,
}

pub struct NeighborInfo {
    /// Physical layer address (MAC, etc.)
    physical_addr: PhysicalAddress,
    /// Link quality
    link_quality: u8,
    /// Direct latency
    latency_ms: u16,
}
```

### Route Discovery

```
┌─────────────────────────────────────────────────────────────────┐
│                    ROUTE DISCOVERY PROTOCOL                      │
└─────────────────────────────────────────────────────────────────┘

Node A wants to reach Node D (doesn't know path):

Step 1: Check local routing table
        └── Not found

Step 2: Ask neighbors "Do you know route to 0xD?"
        ┌──────┐
        │Node A│──▶ Neighbor query
        └──────┘
             │
             ▼
        ┌──────┐     ┌──────┐
        │Node B│     │Node C│
        └──────┘     └──────┘
             │           │
        "I know D"   "No idea"
             │
             ▼
Step 3: B responds with route info
        Route: A → B → D (2 hops)

Step 4: A caches route, sends frame to B
        B forwards to D

Step 5: D responds, reverse path cached
```

### Intent-Based Route Discovery

```
Node A needs "llm:completion" capability:

Step 1: Hash intent → IntentHash
        "llm:completion" → 0x8f3a...

Step 2: Check intent routing table
        └── Found: [NodeId_X, NodeId_Y, NodeId_Z]

Step 3: Score candidates
        └── X: trust=high, latency=10ms, load=20%  ← Best
        └── Y: trust=med,  latency=50ms, load=10%
        └── Z: trust=low,  latency=5ms,  load=80%

Step 4: Route to best match (X)

No DNS. No service discovery protocol.
Just: "Who can do this?" → "That guy."
```

## Frame Format

### AXIOM Layer 3 Frame

```
┌─────────────────────────────────────────────────────────────────┐
│                    AXIOM L3 FRAME (no IP header!)               │
├─────────────────────────────────────────────────────────────────┤
│ Offset │ Size │ Field                                           │
├────────┼──────┼─────────────────────────────────────────────────┤
│   0    │  4   │ Magic: 0x4158494F ("AXIO")                      │
│   4    │  1   │ Version: 0x01                                   │
│   5    │  1   │ Frame Type                                      │
│   6    │  2   │ Flags                                           │
│   8    │  32  │ Source NodeId                                   │
│   40   │  32  │ Destination NodeId (or 0x00... for broadcast)   │
│   72   │  16  │ Intent Hash (for intent routing)                │
│   88   │  8   │ Frame ID (for dedup/ordering)                   │
│   96   │  2   │ TTL (hop limit)                                 │
│   98   │  2   │ Payload Length                                  │
│  100   │  N   │ Payload                                         │
│  100+N │  64  │ Signature (optional, based on trust level)      │
└─────────────────────────────────────────────────────────────────┘

Total header: 100 bytes (vs IP: 20-60 bytes, but we include identity!)
```

### Frame Types

```rust
pub enum FrameType {
    // Data frames
    Data = 0x00,              // Regular data
    DataFragment = 0x01,      // Fragment of larger frame
    DataAck = 0x02,           // Acknowledgment

    // Routing frames
    RouteQuery = 0x10,        // "How do I reach X?"
    RouteReply = 0x11,        // "Go through Y"
    RouteUpdate = 0x12,       // "My routes changed"

    // Discovery frames
    IntentAnnounce = 0x20,    // "I can do X"
    IntentQuery = 0x21,       // "Who can do X?"
    IntentReply = 0x22,       // "I can do X, here's my info"

    // Mesh management
    NeighborHello = 0x30,     // "I'm here"
    NeighborBye = 0x31,       // "I'm leaving"
    MeshSync = 0x32,          // Routing table sync

    // Health
    Ping = 0x40,              // Are you alive?
    Pong = 0x41,              // Yes
}
```

## Physical Layer Binding

### Ethernet Binding

```
┌─────────────────────────────────────────────────────────────────┐
│                  AXIOM OVER ETHERNET                             │
└─────────────────────────────────────────────────────────────────┘

Ethernet Frame:
┌──────────────┬──────────────┬──────────┬─────────────┬─────┐
│ Dst MAC (6B) │ Src MAC (6B) │ EtherType│ AXIOM Frame │ FCS │
└──────────────┴──────────────┴──────────┴─────────────┴─────┘
                               │
                               └── 0x8100 (proposed AXIOM EtherType)
                                   or 0x88B5 (local experimental)

For broadcast: Dst MAC = FF:FF:FF:FF:FF:FF
For unicast:   Dst MAC = neighbor's MAC (from neighbor table)
```

### NodeId to MAC Resolution

```rust
/// Resolve NodeId to physical MAC address
impl MeshTransport {
    /// Find MAC for a neighbor NodeId
    pub fn resolve_physical(&self, node_id: &NodeId) -> Option<MacAddress> {
        // Check neighbor table (like ARP, but simpler)
        self.neighbors.get(node_id).map(|n| n.mac_address)
    }

    /// If not neighbor, find next hop and resolve that
    pub fn resolve_next_hop(&self, dest: &NodeId) -> Option<MacAddress> {
        let route = self.routing_table.lookup(dest)?;
        self.resolve_physical(&route.next_hop)
    }
}
```

### Neighbor Discovery (Replaces ARP)

```
┌─────────────────────────────────────────────────────────────────┐
│                  NEIGHBOR DISCOVERY PROTOCOL                     │
└─────────────────────────────────────────────────────────────────┘

1. New node broadcasts NeighborHello:

   Ethernet: [FF:FF:FF:FF:FF:FF] [my MAC] [0x88B5]
   AXIOM:    [NeighborHello] [my NodeId] [my capabilities]

2. Existing nodes respond with NeighborHello:

   Ethernet: [new node MAC] [my MAC] [0x88B5]
   AXIOM:    [NeighborHello] [my NodeId] [my capabilities]

3. Both sides add to neighbor table:

   neighbor_table.insert(their_node_id, NeighborInfo {
       mac_address: their_mac,
       node_id: their_node_id,
       capabilities: their_caps,
       last_seen: now(),
   });

No ARP cache poisoning possible - NodeId is signed!
```

## Security Properties

### What's Eliminated

```
┌─────────────────────────────────────────────────────────────────┐
│               ATTACKS ELIMINATED BY DESIGN                       │
└─────────────────────────────────────────────────────────────────┘

IP Spoofing
├── IP World: Trivial to forge source IP
└── AXIOM: Source NodeId must be signed - unforgeable

ARP Poisoning
├── IP World: Redirect traffic by poisoning ARP cache
└── AXIOM: NodeId↔MAC binding is signed

BGP Hijacking
├── IP World: Announce false routes
└── AXIOM: Routes carry trust scores, signatures

DNS Spoofing
├── IP World: Return false DNS responses
└── AXIOM: No DNS - identity IS address

Port Scanning
├── IP World: Probe for open services
└── AXIOM: No ports - intent routing only

NAT Traversal Attacks
├── IP World: Exploit NAT state
└── AXIOM: No NAT needed

MITM on Route
├── IP World: Insert self in path
└── AXIOM: End-to-end signatures verify source
```

### Remaining Attack Surface

```
┌─────────────────────────────────────────────────────────────────┐
│               REMAINING CONSIDERATIONS                           │
└─────────────────────────────────────────────────────────────────┘

Physical Layer
├── Still vulnerable: wire tapping, jamming
└── Mitigation: encryption at L4

Sybil Attack
├── Risk: Generate many identities to influence routing
└── Mitigation: Trust scores, proof-of-work for new IDs

Eclipse Attack
├── Risk: Isolate node by controlling all neighbors
└── Mitigation: Multiple bootstrap paths, trust diversity

DoS
├── Risk: Flood with valid-looking frames
└── Mitigation: Rate limiting per NodeId, trust-based QoS

Key Compromise
├── Risk: Stolen private key = stolen identity
└── Mitigation: Key rotation, revocation broadcasts
```

## Bootstrap Process

### First Connection to Mesh

```
┌─────────────────────────────────────────────────────────────────┐
│                    MESH BOOTSTRAP                                │
└─────────────────────────────────────────────────────────────────┘

Option 1: Local Discovery (Zero Config)
    └── Broadcast NeighborHello on local network
    └── Any AXIOM node responds
    └── Join mesh through them

Option 2: Bootstrap Nodes (Known Entry Points)
    └── Hardcoded/configured NodeIds of stable nodes
    └── Connect to them first
    └── They introduce you to mesh

Option 3: Out-of-Band Introduction
    └── QR code with NodeId + physical hint
    └── Shared file with peer info
    └── Manual configuration

Option 4: Peer Exchange
    └── Existing peer shares their neighbor list
    └── Connect to multiple for redundancy
```

```rust
pub struct BootstrapConfig {
    /// Try local broadcast first
    pub local_discovery: bool,

    /// Known bootstrap nodes
    pub bootstrap_nodes: Vec<BootstrapNode>,

    /// Minimum peers before considering "connected"
    pub min_peers: usize,
}

pub struct BootstrapNode {
    /// Their NodeId (we verify this)
    pub node_id: NodeId,

    /// Hint for physical connection (optional)
    /// Could be: MAC address, IP:port (for legacy bridge), etc.
    pub physical_hint: Option<PhysicalHint>,
}
```

## Legacy Interoperability

### AXIOM-IP Bridge

For talking to legacy IP networks:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AXIOM-IP BRIDGE                               │
└─────────────────────────────────────────────────────────────────┘

AXIOM Mesh                          IP Network
┌──────────┐                        ┌──────────┐
│  Node A  │                        │ Server X │
│ (NodeId) │                        │ (IP addr)│
└────┬─────┘                        └────┬─────┘
     │                                   │
     │    ┌─────────────────────┐       │
     └───▶│    AXIOM-IP Bridge  │◀──────┘
          │                     │
          │ • Has NodeId (AXIOM)│
          │ • Has IP addr (legacy)│
          │ • Translates between │
          └─────────────────────┘

Bridge maintains mapping:
  NodeId_A ↔ 10.0.0.5:8080 (proxied)

AI agents don't need to know about IP.
Bridge handles legacy world.
```

## Implementation

### Core Types

```rust
/// Physical layer address (abstract)
pub enum PhysicalAddress {
    Ethernet(MacAddress),
    Wireless(WirelessAddr),
    Serial(SerialPort),
    Virtual(VirtualAddr),
}

/// Layer 3 frame
pub struct AxiomFrame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
    pub signature: Option<Signature>,
}

pub struct FrameHeader {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub source: NodeId,
    pub destination: NodeId,  // All zeros = broadcast
    pub intent_hash: IntentHash,
    pub frame_id: u64,
    pub ttl: u16,
    pub payload_len: u16,
}

/// The network interface
pub struct AxiomInterface {
    /// Our identity
    identity: Keypair,

    /// Physical layer binding
    physical: Box<dyn PhysicalLayer>,

    /// Routing table
    routing: IdentityRoutingTable,

    /// Neighbor management
    neighbors: NeighborTable,
}

impl AxiomInterface {
    /// Send to specific NodeId
    pub async fn send(&self, dest: NodeId, payload: &[u8]) -> Result<()>;

    /// Send to intent (let mesh route)
    pub async fn send_intent(&self, intent: IntentHash, payload: &[u8]) -> Result<()>;

    /// Broadcast to all
    pub async fn broadcast(&self, payload: &[u8]) -> Result<()>;

    /// Receive next frame for us
    pub async fn recv(&self) -> Result<AxiomFrame>;
}
```

## Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    IP vs AXIOM L3                                │
├─────────────────────────────────────────────────────────────────┤
│ Feature          │ IP                │ AXIOM                    │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Address size     │ 4 bytes (v4)      │ 32 bytes (but it's the   │
│                  │ 16 bytes (v6)     │ complete identity!)      │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Address meaning  │ Location          │ Identity                 │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Assignment       │ DHCP/Manual       │ Self-generated           │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Routing          │ By prefix         │ By identity or intent    │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Authentication   │ None (separate)   │ Built-in (signatures)    │
├──────────────────┼───────────────────┼──────────────────────────┤
│ NAT needed       │ Yes (IPv4)        │ No                       │
├──────────────────┼───────────────────┼──────────────────────────┤
│ DNS needed       │ Yes               │ No                       │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Spoofable        │ Yes               │ No                       │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Human readable   │ Sort of           │ No (but DIDs help)       │
├──────────────────┼───────────────────┼──────────────────────────┤
│ Configuration    │ Required          │ Zero-config possible     │
└──────────────────┴───────────────────┴──────────────────────────┘
```

## Summary

**AXIOM Layer 3 eliminates IP by making identity the address.**

- **No IP addresses** → NodeId (public key)
- **No ports** → Intent routing
- **No DNS** → Identity IS the name
- **No NAT** → Global identity space
- **No ARP** → Signed neighbor discovery
- **No BGP** → Trust-weighted gossip

The result: A network where AI agents are identified by WHO they are (cryptographically), not WHERE they are (physically). Attacks based on forging location become impossible.

```
"I am my key. My key is my address. Verify me or don't."
```
