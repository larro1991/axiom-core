# AXIOM Feasibility Assessment

## Overview

Honest assessment of what's buildable today vs. what needs future AI capabilities.

## Feasibility Matrix

### ✅ WORKS TODAY (Proven Tech)

| Component | How | Complexity |
|-----------|-----|------------|
| Cryptographic identity as address | Ed25519 public keys | Low |
| Intent-based routing | Hash-based lookup tables | Medium |
| Signed frames | Ed25519 signatures | Low |
| Encrypted payloads | XChaCha20-Poly1305 | Low |
| Multi-protocol nodes | Software codecs | Medium |
| Trust levels | State machine | Low |
| UDP transport | Standard sockets | Low |
| No DNS/DHCP/NAT | Just don't use them | Low |
| Capability announcements | Gossip protocol | Medium |

### ⚠️ WORKS WITH CONSTRAINTS

| Component | Constraint | Workaround |
|-----------|------------|------------|
| "No IP" networking | Still need physical transport | Run AXIOM over UDP/IP or raw Ethernet |
| Self-monitoring | Simple metrics only | Complex analysis needs slow path |
| Multi-protocol bridge | Per-node overhead | Acceptable for most cases |
| Bootstrap | Need initial peers | Bootstrap nodes, local broadcast |

### ❌ NEEDS FUTURE AI

| Component | Blocker | Timeline |
|-----------|---------|----------|
| Real-time AI routing | LLM too slow (100ms vs 1μs) | 3-5 years? |
| Protocol synthesis | AI not reliable enough | 2-4 years? |
| True self-healing | Can't fix novel failures | Unknown |
| Zero human oversight | Trust not established | 5-10 years? |
| Natural language ops | Latency too high for critical path | 2-3 years? |

## Architecture: Fast Path vs Slow Path

```
┌─────────────────────────────────────────────────────────────────┐
│                    REALISTIC ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │      SLOW PATH          │
                    │      (AI Brain)         │
                    │                         │
                    │  • Policy updates       │  ← Seconds to minutes
                    │  • Anomaly analysis     │
                    │  • Exception handling   │
                    │  • Human explanations   │
                    │  • Learning/adaptation  │
                    └───────────┬─────────────┘
                                │
                        Updates │ policies
                                │
                                ▼
                    ┌─────────────────────────┐
                    │      FAST PATH          │
                    │   (Deterministic)       │
                    │                         │
                    │  • Routing table lookup │  ← Microseconds
                    │  • Signature verify     │
                    │  • Trust check          │
                    │  • Protocol encode      │
                    │  • Forward decision     │
                    └─────────────────────────┘
```

## Security Claims: Verified

| Claim | Valid? | Caveat |
|-------|--------|--------|
| Eliminates IP spoofing | ✅ Yes | Source must be signed |
| Eliminates ARP poisoning | ✅ Yes | No ARP used |
| Eliminates port scanning | ✅ Yes | No ports exist |
| Eliminates DNS spoofing | ✅ Yes | No DNS used |
| Eliminates BGP hijacking | ✅ Yes | No BGP used |
| MITM prevention | ✅ Yes | End-to-end signatures |
| Eliminates ALL attacks | ❌ No | New attacks possible |

## New Attack Surfaces

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Sybil | Spam fake identities | Proof-of-work, reputation |
| Eclipse | Control all of target's peers | Peer diversity requirements |
| Resource exhaustion | Overwhelm AI components | Rate limiting, fast-path bypass |
| Key theft | Steal private key = steal identity | Key rotation, HSMs |
| Adversarial input | Confuse AI decision making | Input validation, fallbacks |

## What We're Actually Building

### Phase 1: Protocol Layer (NOW)
- AXIOM frame format ✅
- Cryptographic identity ✅
- Intent-based routing ✅
- Trust gradient ✅
- UDP transport ✅

### Phase 2: Smart Nodes (NEXT)
- Multi-protocol support
- Fast-path routing
- Basic self-monitoring
- Legacy bridges

### Phase 3: AI Assistance (FUTURE)
- Slow-path AI for policy
- Anomaly detection
- Human-friendly explanations
- Adaptive optimization

### Phase 4: Autonomous (FAR FUTURE)
- Real-time AI decisions
- Self-healing
- Zero oversight

## Revised Claims

**What we say:**
> "AI-native networking protocol"

**What we mean:**
> "Network protocol designed for AI agents, with AI-assisted management,
>  but deterministic fast-path for performance"

**What we DON'T mean:**
> "Every packet goes through an LLM"

## Implementation Reality

```rust
/// Realistic node architecture
pub struct AxiomNode {
    // FAST PATH - Deterministic, microsecond decisions
    fast_path: FastPath {
        routing_table: RoutingTable,      // Pre-computed by AI
        trust_cache: TrustCache,          // Pre-computed by AI
        protocol_codecs: CodecRegistry,   // Static
        signature_verifier: Verifier,     // Hardware accelerated
    },

    // SLOW PATH - AI-assisted, millisecond-second decisions
    slow_path: SlowPath {
        ai_brain: Option<AiBrain>,        // May not even be present
        policy_engine: PolicyEngine,      // AI-generated policies
        anomaly_detector: AnomalyDetector,
        human_interface: ExplainInterface,
    },
}

impl AxiomNode {
    /// Hot path - no AI involved
    fn handle_frame(&self, frame: &Frame) -> Action {
        // 1. Verify signature (crypto, fast)
        // 2. Check trust cache (lookup, fast)
        // 3. Route lookup (hash table, fast)
        // 4. Forward or deliver
        //
        // NO AI INVOLVED - pure deterministic
    }

    /// Exception path - AI may be consulted
    fn handle_exception(&self, exception: &Exception) -> Action {
        // This is where AI helps
        // But it's rare, not every packet
    }
}
```

## Conclusion

**The core innovation is real:**
- Identity-based addressing works
- Intent routing works
- Security improvements are genuine

**The AI vision is aspirational:**
- Current AI too slow for hot path
- Need fast/slow path separation
- Full autonomy is years away

**What to build now:**
- Solid protocol foundation
- Deterministic fast path
- AI-assisted slow path
- Clear upgrade path to more AI later
