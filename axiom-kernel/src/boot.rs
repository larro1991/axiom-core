//! Kernel Boot Sequence
//!
//! Handles kernel initialization:
//! 1. Hardware discovery
//! 2. Scheduler configuration
//! 3. Network initialization
//! 4. Init agent launch

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use axiom_crypto::Keypair;
use axiom_hal::ResourceManager;
use axiom_router::{Endpoint, NodeRegistry, SemanticRouter};
use axiom_runtime::{Agent, AgentConfig, AgentState, CheckpointManager, LocalRouter, Scheduler};
use axiom_types::NodeId;
use thiserror::Error;

use crate::config::KernelConfig;
use crate::init::InitAgent;
use crate::shutdown::{ShutdownCoordinator, ShutdownPhase, ShutdownReason};

/// Boot errors
#[derive(Debug, Error)]
pub enum BootError {
    #[error("Hardware discovery failed: {0}")]
    HardwareDiscovery(String),

    #[error("Scheduler init failed: {0}")]
    SchedulerInit(String),

    #[error("Network init failed: {0}")]
    NetworkInit(String),

    #[error("Init agent failed: {0}")]
    InitAgent(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Boot configuration
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Skip hardware discovery (for testing)
    pub skip_hardware_discovery: bool,
    /// Skip network initialization
    pub skip_network: bool,
    /// Run in single-threaded mode
    pub single_threaded: bool,
    /// Verbose boot logging
    pub verbose: bool,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            skip_hardware_discovery: false,
            skip_network: false,
            single_threaded: false,
            verbose: false,
        }
    }
}

/// Kernel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelState {
    /// Not yet booted
    NotStarted,
    /// Discovering hardware
    DiscoveringHardware,
    /// Initializing scheduler
    InitializingScheduler,
    /// Initializing network
    InitializingNetwork,
    /// Running init agent
    RunningInit,
    /// Fully operational
    Running,
    /// Shutting down
    ShuttingDown,
    /// Halted
    Halted,
}

/// The AXIOM Kernel
pub struct Kernel {
    config: KernelConfig,
    boot_config: BootConfig,
    state: KernelState,
    node_id: NodeId,
    keypair: Keypair,
    hal: ResourceManager,
    router: SemanticRouter,
    registry: NodeRegistry,
    scheduler: Scheduler,
    ipc: LocalRouter,
    checkpoints: CheckpointManager,
    agents: HashMap<[u8; 32], Agent>,
    init_agent: Option<Box<dyn InitAgent>>,
    shutdown: ShutdownCoordinator,
}

impl Kernel {
    /// Create a new kernel with the given configuration
    pub fn new(config: KernelConfig) -> Self {
        let keypair = Keypair::generate();
        let node_id = NodeId::from_bytes(keypair.public_key_bytes());
        let local_endpoint = Endpoint::Local;

        Self {
            config,
            boot_config: BootConfig::default(),
            state: KernelState::NotStarted,
            node_id: node_id.clone(),
            keypair,
            hal: ResourceManager::new(node_id.clone()),
            router: SemanticRouter::new(node_id.clone()),
            registry: NodeRegistry::new(node_id, local_endpoint),
            scheduler: Scheduler::new(4), // Default 4 workers
            ipc: LocalRouter::new(),
            checkpoints: CheckpointManager::new(),
            agents: HashMap::new(),
            init_agent: None,
            shutdown: ShutdownCoordinator::new(),
        }
    }

    /// Create with boot configuration
    pub fn with_boot_config(config: KernelConfig, boot_config: BootConfig) -> Self {
        let mut kernel = Self::new(config);
        kernel.boot_config = boot_config;
        kernel
    }

    /// Set the init agent (e.g., EMBER)
    pub fn set_init_agent<I: InitAgent + 'static>(&mut self, init: I) {
        self.init_agent = Some(Box::new(init));
    }

    /// Get current state
    pub fn state(&self) -> KernelState {
        self.state
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Boot the kernel (synchronous)
    pub fn boot(&mut self) -> Result<(), BootError> {
        // Hardware discovery
        self.state = KernelState::DiscoveringHardware;
        if !self.boot_config.skip_hardware_discovery {
            self.discover_hardware()?;
        }

        // Scheduler initialization
        self.state = KernelState::InitializingScheduler;
        self.init_scheduler()?;

        // Network initialization (skipped in sync boot)
        if !self.boot_config.skip_network {
            self.state = KernelState::InitializingNetwork;
            // Network requires async, mark as needing async boot
        }

        // Init agent
        self.state = KernelState::RunningInit;
        self.run_init_agent()?;

        self.state = KernelState::Running;
        Ok(())
    }

    /// Boot with async network initialization
    #[cfg(feature = "std")]
    pub async fn boot_async(&mut self) -> Result<(), BootError> {
        // Synchronous parts
        self.state = KernelState::DiscoveringHardware;
        if !self.boot_config.skip_hardware_discovery {
            self.discover_hardware()?;
        }

        self.state = KernelState::InitializingScheduler;
        self.init_scheduler()?;

        // Async network initialization
        if !self.boot_config.skip_network {
            self.state = KernelState::InitializingNetwork;
            self.init_network().await?;
        }

        // Init agent
        self.state = KernelState::RunningInit;
        self.run_init_agent()?;

        self.state = KernelState::Running;
        Ok(())
    }

    fn discover_hardware(&mut self) -> Result<(), BootError> {
        // Probe for GPUs
        if self.config.hardware.gpu_enabled {
            // HAL will handle GPU detection
        }

        // Configure based on available resources
        let worker_count = if self.config.worker_threads == 0 {
            // Auto-detect: use number of CPU cores or default to 4
            4
        } else {
            self.config.worker_threads
        };

        self.scheduler = Scheduler::new(worker_count);
        Ok(())
    }

    fn init_scheduler(&mut self) -> Result<(), BootError> {
        // Scheduler is already created in discover_hardware
        // Additional configuration here
        Ok(())
    }

    #[cfg(feature = "std")]
    async fn init_network(&mut self) -> Result<(), BootError> {
        use axiom_transport::net::AxiomSocket;
        use std::net::SocketAddr;

        // Parse listen address
        let addr: SocketAddr = self.config.network.listen_addr
            .parse()
            .map_err(|e| BootError::NetworkInit(format!("Invalid listen address: {}", e)))?;

        // Create the main socket
        let _socket = AxiomSocket::bind(addr, self.node_id.clone())
            .await
            .map_err(|e| BootError::NetworkInit(e.to_string()))?;

        // Register with bootstrap peers
        for peer_addr in &self.config.network.bootstrap_peers {
            // Connect to peer and register
            let _ = peer_addr; // TODO: implement peer connection
        }

        Ok(())
    }

    fn run_init_agent(&mut self) -> Result<(), BootError> {
        if let Some(ref mut init) = self.init_agent {
            init.init()
                .map_err(|e| BootError::InitAgent(e.to_string()))?;

            // Spawn startup agents
            for spec in init.startup_agents() {
                let agent = Agent::new(AgentConfig::default());
                let id = *agent.id().as_bytes();
                self.agents.insert(id, agent);
                let _ = spec; // TODO: configure agent from spec
            }

            init.on_kernel_ready()
                .map_err(|e| BootError::InitAgent(e.to_string()))?;
        }
        Ok(())
    }

    /// Spawn a new agent
    pub fn spawn_agent(&mut self) -> [u8; 32] {
        let agent = Agent::new(AgentConfig::default());
        let id = *agent.id().as_bytes();
        self.agents.insert(id, agent);
        id
    }

    /// Get agent count
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Initiate shutdown
    pub fn shutdown(&mut self, reason: ShutdownReason) {
        self.state = KernelState::ShuttingDown;
        self.shutdown.start(reason, self.agents.len());

        // Notify init agent
        if let Some(ref mut init) = self.init_agent {
            init.on_shutdown();
        }
    }

    /// Process shutdown tick (call repeatedly until complete)
    pub fn shutdown_tick(&mut self) -> bool {
        match self.shutdown.phase() {
            ShutdownPhase::None => false,
            ShutdownPhase::StopAccepting => {
                // Stop accepting new work
                self.shutdown.advance();
                false
            }
            ShutdownPhase::NotifyingAgents => {
                // Notify all agents
                self.shutdown.advance();
                false
            }
            ShutdownPhase::Checkpointing => {
                if self.shutdown.skip_checkpoint() {
                    self.shutdown.advance();
                } else {
                    // Checkpoint all agents
                    for (id, agent) in &self.agents {
                        let _ = self.checkpoints.create(
                            axiom_runtime::AgentId::from_bytes(*id),
                            AgentState::ShuttingDown,
                            &agent.config().name,
                            agent.provided_capabilities().to_vec(),
                            None,
                            Vec::new(),
                            Vec::new(),
                        );
                    }
                    self.shutdown.checkpoint_done();
                    self.shutdown.advance();
                }
                false
            }
            ShutdownPhase::WaitingAgents => {
                // In real impl, wait for agents to terminate gracefully
                // For now, just clear them
                self.agents.clear();
                while !self.shutdown.all_agents_terminated() {
                    self.shutdown.agent_terminated();
                }
                self.shutdown.advance();
                false
            }
            ShutdownPhase::ReleasingResources => {
                // Release HAL resources
                self.shutdown.advance();
                false
            }
            ShutdownPhase::ClosingNetwork => {
                // Close network connections
                self.shutdown.network_done();
                self.shutdown.advance();
                false
            }
            ShutdownPhase::Complete => {
                self.state = KernelState::Halted;
                true
            }
        }
    }

    /// Get router for agent capability discovery
    pub fn router(&self) -> &SemanticRouter {
        &self.router
    }

    /// Get mutable router
    pub fn router_mut(&mut self) -> &mut SemanticRouter {
        &mut self.router
    }

    /// Get IPC router
    pub fn ipc(&self) -> &LocalRouter {
        &self.ipc
    }

    /// Get mutable IPC router
    pub fn ipc_mut(&mut self) -> &mut LocalRouter {
        &mut self.ipc
    }

    /// Get checkpoint manager
    pub fn checkpoints(&self) -> &CheckpointManager {
        &self.checkpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KernelConfigBuilder;
    use crate::init::DefaultInitAgent;

    #[test]
    fn test_kernel_creation() {
        let config = KernelConfig::default();
        let kernel = Kernel::new(config);
        assert_eq!(kernel.state(), KernelState::NotStarted);
    }

    #[test]
    fn test_kernel_boot() {
        let config = KernelConfigBuilder::new()
            .node_name("test-kernel")
            .build();

        let boot_config = BootConfig {
            skip_hardware_discovery: true,
            skip_network: true,
            single_threaded: true,
            verbose: false,
        };

        let mut kernel = Kernel::with_boot_config(config, boot_config);
        kernel.set_init_agent(DefaultInitAgent::new("test-init"));

        let result = kernel.boot();
        assert!(result.is_ok());
        assert_eq!(kernel.state(), KernelState::Running);
    }

    #[test]
    fn test_agent_spawn() {
        let config = KernelConfig::default();
        let boot_config = BootConfig {
            skip_hardware_discovery: true,
            skip_network: true,
            ..Default::default()
        };

        let mut kernel = Kernel::with_boot_config(config, boot_config);
        kernel.boot().unwrap();

        assert_eq!(kernel.agent_count(), 0);
        kernel.spawn_agent();
        assert_eq!(kernel.agent_count(), 1);
        kernel.spawn_agent();
        assert_eq!(kernel.agent_count(), 2);
    }

    #[test]
    fn test_shutdown_sequence() {
        let config = KernelConfig::default();
        let boot_config = BootConfig {
            skip_hardware_discovery: true,
            skip_network: true,
            ..Default::default()
        };

        let mut kernel = Kernel::with_boot_config(config, boot_config);
        kernel.boot().unwrap();

        kernel.spawn_agent();
        kernel.spawn_agent();

        kernel.shutdown(ShutdownReason::UserRequest);
        assert_eq!(kernel.state(), KernelState::ShuttingDown);

        // Process shutdown
        while !kernel.shutdown_tick() {}

        assert_eq!(kernel.state(), KernelState::Halted);
        assert_eq!(kernel.agent_count(), 0);
    }
}
