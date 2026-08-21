//! Agent - AI entity with identity and lifecycle
//!
//! An Agent is the fundamental unit of execution in AXIOM.
//! It has cryptographic identity, lifecycle state, and capabilities.

use alloc::string::String;
use alloc::vec::Vec;
use axiom_crypto::identity::Keypair;
use axiom_router::ai::AgentId;
use axiom_types::crypto::NodeId;
use axiom_types::trust::TrustLevel;

/// Agent lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Just created, not yet initialized
    Created,
    /// Initializing (claiming resources, connecting)
    Initializing,
    /// Ready to execute tasks
    Ready,
    /// Currently executing a task
    Running,
    /// Paused (resources held but not executing)
    Paused,
    /// Shutting down (releasing resources)
    ShuttingDown,
    /// Terminated
    Terminated,
}

impl AgentState {
    /// Check if state transition is valid
    pub fn can_transition_to(&self, new_state: AgentState) -> bool {
        use AgentState::*;
        match (self, new_state) {
            // From Created
            (Created, Initializing) => true,
            (Created, Terminated) => true,

            // From Initializing
            (Initializing, Ready) => true,
            (Initializing, Terminated) => true,

            // From Ready
            (Ready, Running) => true,
            (Ready, Paused) => true,
            (Ready, ShuttingDown) => true,

            // From Running
            (Running, Ready) => true,
            (Running, Paused) => true,
            (Running, ShuttingDown) => true,

            // From Paused
            (Paused, Ready) => true,
            (Paused, Running) => true,
            (Paused, ShuttingDown) => true,

            // From ShuttingDown
            (ShuttingDown, Terminated) => true,

            // No other transitions allowed
            _ => false,
        }
    }

    /// Is the agent able to execute tasks?
    pub fn can_execute(&self) -> bool {
        matches!(self, AgentState::Ready | AgentState::Running)
    }

    /// Is the agent holding resources?
    pub fn holds_resources(&self) -> bool {
        matches!(
            self,
            AgentState::Initializing
                | AgentState::Ready
                | AgentState::Running
                | AgentState::Paused
                | AgentState::ShuttingDown
        )
    }
}

/// Configuration for creating an agent
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Human-readable name
    pub name: String,
    /// Required capabilities (will fail init if not available)
    pub required_capabilities: Vec<String>,
    /// Preferred capabilities (nice to have)
    pub preferred_capabilities: Vec<String>,
    /// Trust level this agent operates at
    pub trust_level: TrustLevel,
    /// Maximum memory to claim (bytes)
    pub max_memory: u64,
    /// Maximum compute to claim (TFLOPS)
    pub max_compute_tflops: f32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: String::from("agent"),
            required_capabilities: Vec::new(),
            preferred_capabilities: Vec::new(),
            trust_level: TrustLevel::Sig,
            max_memory: 1_000_000_000, // 1GB default
            max_compute_tflops: 10.0,   // 10 TFLOPS default
        }
    }
}

impl AgentConfig {
    /// Create a new config with name
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            ..Default::default()
        }
    }

    /// Add required capability
    pub fn require(mut self, capability: &str) -> Self {
        self.required_capabilities.push(String::from(capability));
        self
    }

    /// Add preferred capability
    pub fn prefer(mut self, capability: &str) -> Self {
        self.preferred_capabilities.push(String::from(capability));
        self
    }

    /// Set trust level
    pub fn with_trust(mut self, level: TrustLevel) -> Self {
        self.trust_level = level;
        self
    }

    /// Set max memory
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }

    /// Set max compute
    pub fn with_max_compute(mut self, tflops: f32) -> Self {
        self.max_compute_tflops = tflops;
        self
    }
}

/// An AI agent with identity and state
pub struct Agent {
    /// Cryptographic keypair (identity)
    keypair: Keypair,
    /// Agent ID derived from public key
    id: AgentId,
    /// Configuration
    config: AgentConfig,
    /// Current state
    state: AgentState,
    /// Capabilities this agent provides to others
    provided_capabilities: Vec<String>,
}

impl Agent {
    /// Create a new agent with generated keypair
    pub fn new(config: AgentConfig) -> Self {
        let keypair = Keypair::generate();
        let node_id = NodeId::from_bytes(keypair.public_key_bytes());
        let id = AgentId::from_node_id(node_id);

        Self {
            keypair,
            id,
            config,
            state: AgentState::Created,
            provided_capabilities: Vec::new(),
        }
    }

    /// Create agent from existing keypair
    pub fn from_keypair(keypair: Keypair, config: AgentConfig) -> Self {
        let node_id = NodeId::from_bytes(keypair.public_key_bytes());
        let id = AgentId::from_node_id(node_id);

        Self {
            keypair,
            id,
            config,
            state: AgentState::Created,
            provided_capabilities: Vec::new(),
        }
    }

    /// Get agent ID
    pub fn id(&self) -> &AgentId {
        &self.id
    }

    /// Get node ID (for network operations)
    pub fn node_id(&self) -> &NodeId {
        self.id.node_id()
    }

    /// Get keypair (for signing)
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Get config
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Get current state
    pub fn state(&self) -> AgentState {
        self.state
    }

    /// Transition to new state
    pub fn transition(&mut self, new_state: AgentState) -> Result<(), (AgentState, AgentState)> {
        if self.state.can_transition_to(new_state) {
            self.state = new_state;
            Ok(())
        } else {
            Err((self.state, new_state))
        }
    }

    /// Register a capability this agent provides
    pub fn provide_capability(&mut self, capability: &str) {
        if !self.provided_capabilities.contains(&String::from(capability)) {
            self.provided_capabilities.push(String::from(capability));
        }
    }

    /// Get provided capabilities
    pub fn provided_capabilities(&self) -> &[String] {
        &self.provided_capabilities
    }

    /// Check if agent can execute tasks
    pub fn can_execute(&self) -> bool {
        self.state.can_execute()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let config = AgentConfig::new("test-agent")
            .require("compute:tensor")
            .with_max_memory(2_000_000_000);

        let agent = Agent::new(config);

        assert_eq!(agent.state(), AgentState::Created);
        assert_eq!(agent.config().name, "test-agent");
        assert!(agent.config().required_capabilities.contains(&String::from("compute:tensor")));
    }

    #[test]
    fn test_state_transitions() {
        let mut agent = Agent::new(AgentConfig::default());

        // Valid transitions
        assert!(agent.transition(AgentState::Initializing).is_ok());
        assert!(agent.transition(AgentState::Ready).is_ok());
        assert!(agent.transition(AgentState::Running).is_ok());
        assert!(agent.transition(AgentState::Ready).is_ok());
        assert!(agent.transition(AgentState::ShuttingDown).is_ok());
        assert!(agent.transition(AgentState::Terminated).is_ok());
    }

    #[test]
    fn test_invalid_transition() {
        let mut agent = Agent::new(AgentConfig::default());

        // Can't go directly from Created to Running
        assert!(agent.transition(AgentState::Running).is_err());
    }

    #[test]
    fn test_can_execute() {
        let mut agent = Agent::new(AgentConfig::default());

        assert!(!agent.can_execute()); // Created

        agent.transition(AgentState::Initializing).unwrap();
        assert!(!agent.can_execute()); // Initializing

        agent.transition(AgentState::Ready).unwrap();
        assert!(agent.can_execute()); // Ready

        agent.transition(AgentState::Running).unwrap();
        assert!(agent.can_execute()); // Running

        agent.transition(AgentState::Paused).unwrap();
        assert!(!agent.can_execute()); // Paused
    }

    #[test]
    fn test_provide_capability() {
        let mut agent = Agent::new(AgentConfig::default());

        agent.provide_capability("llm:completion");
        agent.provide_capability("llm:embedding");
        agent.provide_capability("llm:completion"); // Duplicate ignored

        assert_eq!(agent.provided_capabilities().len(), 2);
    }
}
