//! AI-Native Networking API for AXIOM
//!
//! This module provides a pure AI-to-AI networking abstraction:
//! - **No ports**: Identity IS the address (NodeId = public key)
//! - **No firewalls**: Trust gradient replaces port-based security
//! - **Intent routing**: Find capabilities, not locations
//! - **Semantic addressing**: Route by what you need, not where it is
//!
//! # Philosophy
//!
//! Traditional networking was designed for humans:
//! - Ports multiplex services because humans can't evaluate every packet
//! - Firewalls block by IP/port because humans can't evaluate intent
//! - DNS maps names to IPs because humans can't remember numbers
//!
//! AI doesn't have these limitations. AXIOM is designed for AI:
//! - Identity = Address (32-byte public key)
//! - Trust gradient = Security (cryptographic, not topological)
//! - Intent hash = Service discovery (semantic, not syntactic)
//!
//! # Example
//!
//! ```ignore
//! // Create an AI agent
//! let agent = AiAgent::new();
//!
//! // Register what we can do (not where we are)
//! agent.provide(intent!("llm:completion"), my_handler);
//! agent.provide(intent!("embedding:text"), embed_handler);
//!
//! // Find and use capabilities (not addresses)
//! let response = agent.request(intent!("image:generation"), prompt).await?;
//!
//! // Trust is automatic - evaluated per-interaction
//! ```

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::{IntentHash, NodeId};
use axiom_types::trust::TrustLevel;

#[cfg(feature = "std")]
use std::future::Future;
#[cfg(feature = "std")]
use std::pin::Pin;

/// AI Agent identity - your public key IS your address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(pub NodeId);

impl AgentId {
    /// Generate a new random identity
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let keypair = axiom_crypto::Keypair::generate();
        Self(keypair.node_id())
    }

    /// Create from existing NodeId
    pub fn from_node_id(node_id: NodeId) -> Self {
        Self(node_id)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(NodeId::from_bytes(bytes))
    }

    /// Get as raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get the underlying NodeId
    pub fn node_id(&self) -> &NodeId {
        &self.0
    }

    /// Display as hex string (for debugging only - AI doesn't need this)
    pub fn to_hex(&self) -> String {
        let bytes = self.0.as_bytes();
        let mut s = String::with_capacity(64);
        for b in bytes {
            use core::fmt::Write;
            write!(s, "{:02x}", b).ok();
        }
        s
    }
}

impl From<NodeId> for AgentId {
    fn from(node_id: NodeId) -> Self {
        Self(node_id)
    }
}

/// Intent declaration - what capability you're looking for
#[derive(Debug, Clone)]
pub struct Intent {
    /// The hash that identifies this capability
    pub hash: IntentHash,
    /// Human-readable name (optional, for debugging)
    pub name: Option<String>,
    /// Constraints on the capability
    pub constraints: Vec<Constraint>,
}

impl Intent {
    /// Create from a capability string
    pub fn from_str(capability: &str) -> Self {
        Self {
            hash: IntentHash::from_bytes(blake3::hash(capability.as_bytes()).as_bytes()[..16].try_into().unwrap()),
            name: Some(String::from(capability)),
            constraints: Vec::new(),
        }
    }

    /// Create from raw hash
    pub fn from_hash(hash: IntentHash) -> Self {
        Self {
            hash,
            name: None,
            constraints: Vec::new(),
        }
    }

    /// Add a constraint
    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Require minimum trust level
    pub fn require_trust(self, level: TrustLevel) -> Self {
        self.with_constraint(Constraint::MinTrust(level))
    }

    /// Require maximum latency
    pub fn require_latency(self, max_ms: u16) -> Self {
        self.with_constraint(Constraint::MaxLatency(max_ms))
    }
}

/// Constraints on capability selection
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Minimum trust level required
    MinTrust(TrustLevel),
    /// Maximum acceptable latency (ms)
    MaxLatency(u16),
    /// Maximum acceptable load (0-255)
    MaxLoad(u8),
    /// Prefer specific agent (soft preference)
    PreferAgent(AgentId),
    /// Exclude specific agent
    ExcludeAgent(AgentId),
    /// Custom constraint (evaluated by AI)
    Custom(String),
}

/// Response from a capability request
#[derive(Debug)]
pub struct Response {
    /// The agent that fulfilled the request
    pub provider: AgentId,
    /// Trust level of the interaction
    pub trust_level: TrustLevel,
    /// The payload data
    pub payload: Vec<u8>,
    /// Round-trip time (microseconds)
    pub rtt_us: u64,
}

/// Error types for AI networking
#[derive(Debug, Clone)]
pub enum AgentError {
    /// No provider found for the requested capability
    NoProvider(IntentHash),
    /// Provider found but constraints not met
    ConstraintNotMet(String),
    /// Trust negotiation failed
    TrustFailed(String),
    /// Request timed out
    Timeout,
    /// Provider returned an error
    ProviderError(String),
    /// Internal error
    Internal(String),
}

/// Capability handler type
#[cfg(feature = "std")]
pub type CapabilityHandler = Box<
    dyn Fn(Vec<u8>, AgentId) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
        + Send
        + Sync,
>;

/// Configuration for AI agent networking
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Default timeout for requests (milliseconds)
    pub default_timeout_ms: u64,
    /// How often to announce capabilities (milliseconds)
    pub announce_interval_ms: u64,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// Trust negotiation timeout (milliseconds)
    pub trust_timeout_ms: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30000,
            announce_interval_ms: 30000,
            max_concurrent_requests: 1000,
            trust_timeout_ms: 5000,
        }
    }
}

/// Discovery result - agents that can fulfill an intent
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Agent that provides this capability
    pub agent: AgentId,
    /// Current trust level with this agent
    pub trust_level: TrustLevel,
    /// Reported latency (ms)
    pub latency_ms: u16,
    /// Reported load (0-255, lower is better)
    pub load: u8,
    /// Score (higher is better)
    pub score: u32,
}

/// The AI-native networking interface
///
/// This is what an AI agent uses to communicate.
/// No ports, no firewalls, no legacy concepts.
pub trait AiNetwork: Send + Sync {
    /// Discover agents that can fulfill an intent
    fn discover(&self, intent: &Intent) -> Vec<DiscoveryResult>;

    /// Send a request to any agent that can fulfill the intent
    #[cfg(feature = "std")]
    fn request(
        &self,
        intent: Intent,
        payload: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Response, AgentError>> + Send + '_>>;

    /// Send a request to a specific agent
    #[cfg(feature = "std")]
    fn request_to(
        &self,
        agent: &AgentId,
        intent: Intent,
        payload: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Response, AgentError>> + Send + '_>>;

    /// Register a capability we provide
    #[cfg(feature = "std")]
    fn provide(&mut self, intent: Intent, handler: CapabilityHandler);

    /// Unregister a capability
    fn unprovide(&mut self, intent: &IntentHash);

    /// Get our agent ID
    fn agent_id(&self) -> &AgentId;

    /// Get current trust level with another agent
    fn trust_with(&self, agent: &AgentId) -> TrustLevel;

    /// Explicitly set trust level with an agent (manual override)
    fn set_trust(&mut self, agent: &AgentId, level: TrustLevel);
}

/// Macro for creating intents from string literals
#[macro_export]
macro_rules! intent {
    ($s:expr) => {
        $crate::ai::Intent::from_str($s)
    };
}

/// Macro for intent hash from string (compile-time when possible)
#[macro_export]
macro_rules! intent_hash {
    ($s:expr) => {{
        let hash = blake3::hash($s.as_bytes());
        axiom_types::crypto::IntentHash::from_bytes(
            hash.as_bytes()[..16].try_into().unwrap()
        )
    }};
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_generation() {
        let id1 = AgentId::generate();
        let id2 = AgentId::generate();

        // Each agent should have unique identity
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn test_intent_from_string() {
        let intent1 = Intent::from_str("llm:completion");
        let intent2 = Intent::from_str("llm:completion");
        let intent3 = Intent::from_str("image:generation");

        // Same string = same hash
        assert_eq!(intent1.hash, intent2.hash);
        // Different string = different hash
        assert_ne!(intent1.hash, intent3.hash);
    }

    #[test]
    fn test_intent_constraints() {
        let intent = Intent::from_str("llm:completion")
            .require_trust(TrustLevel::Sig)
            .require_latency(100);

        assert_eq!(intent.constraints.len(), 2);
    }

    #[test]
    fn test_agent_id_hex() {
        let id = AgentId::from_node_id(NodeId::from_bytes([0xAB; 32]));
        let hex = id.to_hex();

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
