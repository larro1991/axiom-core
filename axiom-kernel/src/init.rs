//! Init Agent
//!
//! The init agent is the first agent spawned by the kernel.
//! It's responsible for bootstrapping the system and spawning other agents.
//! EMBER will implement this trait to become the system's init.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use axiom_runtime::{Agent, AgentConfig};
use thiserror::Error;

/// Init agent errors
#[derive(Debug, Error)]
pub enum InitError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),

    #[error("Agent spawn failed: {0}")]
    SpawnFailed(String),

    #[error("Resource unavailable: {0}")]
    ResourceUnavailable(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Trait for init agents (like EMBER)
pub trait InitAgent: Send {
    /// Get the init agent's name
    fn name(&self) -> &str;

    /// Initialize the agent (called before kernel is fully ready)
    fn init(&mut self) -> Result<(), InitError>;

    /// Called when kernel is fully booted and ready
    fn on_kernel_ready(&mut self) -> Result<(), InitError>;

    /// Called when kernel is shutting down
    fn on_shutdown(&mut self);

    /// Get the underlying agent
    fn agent(&self) -> &Agent;

    /// Get mutable access to the underlying agent
    fn agent_mut(&mut self) -> &mut Agent;

    /// Get agents to spawn at startup
    fn startup_agents(&self) -> Vec<AgentSpec> {
        Vec::new()
    }
}

/// Specification for an agent to spawn
#[derive(Debug, Clone)]
pub struct AgentSpec {
    /// Agent name
    pub name: String,
    /// Capabilities to announce
    pub capabilities: Vec<String>,
    /// Priority (higher = more important)
    pub priority: u8,
    /// Should restart on failure
    pub restart_on_failure: bool,
}

/// Default init agent for basic functionality
pub struct DefaultInitAgent {
    agent: Agent,
    name: String,
}

impl DefaultInitAgent {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            agent: Agent::new(AgentConfig::default()),
            name: name.into(),
        }
    }
}

impl InitAgent for DefaultInitAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn init(&mut self) -> Result<(), InitError> {
        Ok(())
    }

    fn on_kernel_ready(&mut self) -> Result<(), InitError> {
        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn agent(&self) -> &Agent {
        &self.agent
    }

    fn agent_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }
}

/// Custom init agent with callbacks
pub struct CustomInitAgent {
    agent: Agent,
    name: String,
    on_init: Option<Box<dyn FnMut(&mut Agent) -> Result<(), InitError> + Send>>,
    on_ready: Option<Box<dyn FnMut(&mut Agent) -> Result<(), InitError> + Send>>,
    on_shutdown: Option<Box<dyn FnMut(&mut Agent) + Send>>,
    startup_agents: Vec<AgentSpec>,
}

impl CustomInitAgent {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            agent: Agent::new(AgentConfig::default()),
            name: name.into(),
            on_init: None,
            on_ready: None,
            on_shutdown: None,
            startup_agents: Vec::new(),
        }
    }
}

impl InitAgent for CustomInitAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn init(&mut self) -> Result<(), InitError> {
        if let Some(ref mut f) = self.on_init {
            f(&mut self.agent)?;
        }
        Ok(())
    }

    fn on_kernel_ready(&mut self) -> Result<(), InitError> {
        if let Some(ref mut f) = self.on_ready {
            f(&mut self.agent)?;
        }
        Ok(())
    }

    fn on_shutdown(&mut self) {
        if let Some(ref mut f) = self.on_shutdown {
            f(&mut self.agent);
        }
    }

    fn agent(&self) -> &Agent {
        &self.agent
    }

    fn agent_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }

    fn startup_agents(&self) -> Vec<AgentSpec> {
        self.startup_agents.clone()
    }
}

/// Builder for custom init agents
pub struct InitAgentBuilder {
    agent: CustomInitAgent,
}

impl InitAgentBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            agent: CustomInitAgent::new(name),
        }
    }

    pub fn on_init<F>(mut self, f: F) -> Self
    where
        F: FnMut(&mut Agent) -> Result<(), InitError> + Send + 'static,
    {
        self.agent.on_init = Some(Box::new(f));
        self
    }

    pub fn on_ready<F>(mut self, f: F) -> Self
    where
        F: FnMut(&mut Agent) -> Result<(), InitError> + Send + 'static,
    {
        self.agent.on_ready = Some(Box::new(f));
        self
    }

    pub fn on_shutdown<F>(mut self, f: F) -> Self
    where
        F: FnMut(&mut Agent) + Send + 'static,
    {
        self.agent.on_shutdown = Some(Box::new(f));
        self
    }

    pub fn startup_agent(mut self, spec: AgentSpec) -> Self {
        self.agent.startup_agents.push(spec);
        self
    }

    pub fn build(self) -> CustomInitAgent {
        self.agent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_init_agent() {
        let mut init = DefaultInitAgent::new("test-init");
        assert_eq!(init.name(), "test-init");
        assert!(init.init().is_ok());
        assert!(init.on_kernel_ready().is_ok());
        init.on_shutdown();
    }

    #[test]
    fn test_custom_init_agent() {
        use core::sync::atomic::{AtomicBool, Ordering};
        use alloc::sync::Arc;

        let init_called = Arc::new(AtomicBool::new(false));
        let ready_called = Arc::new(AtomicBool::new(false));
        let shutdown_called = Arc::new(AtomicBool::new(false));

        let init_flag = init_called.clone();
        let ready_flag = ready_called.clone();
        let shutdown_flag = shutdown_called.clone();

        let mut init = InitAgentBuilder::new("custom-init")
            .on_init(move |_| {
                init_flag.store(true, Ordering::SeqCst);
                Ok(())
            })
            .on_ready(move |_| {
                ready_flag.store(true, Ordering::SeqCst);
                Ok(())
            })
            .on_shutdown(move |_| {
                shutdown_flag.store(true, Ordering::SeqCst);
            })
            .build();

        assert!(init.init().is_ok());
        assert!(init_called.load(Ordering::SeqCst));

        assert!(init.on_kernel_ready().is_ok());
        assert!(ready_called.load(Ordering::SeqCst));

        init.on_shutdown();
        assert!(shutdown_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_startup_agents() {
        let init = InitAgentBuilder::new("test")
            .startup_agent(AgentSpec {
                name: String::from("worker-1"),
                capabilities: vec![String::from("compute")],
                priority: 5,
                restart_on_failure: true,
            })
            .startup_agent(AgentSpec {
                name: String::from("worker-2"),
                capabilities: vec![String::from("storage")],
                priority: 3,
                restart_on_failure: false,
            })
            .build();

        let agents = init.startup_agents();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].name, "worker-1");
        assert_eq!(agents[1].name, "worker-2");
    }
}
