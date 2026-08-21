//! Kernel Configuration
//!
//! Configuration for all kernel subsystems.

use alloc::string::String;
use alloc::vec::Vec;

/// Main kernel configuration
#[derive(Debug, Clone)]
pub struct KernelConfig {
    /// Node name for identification
    pub node_name: String,
    /// Network configuration
    pub network: NetworkConfig,
    /// Hardware configuration
    pub hardware: HardwareConfig,
    /// Maximum number of agents
    pub max_agents: usize,
    /// Enable checkpointing
    pub checkpointing_enabled: bool,
    /// Checkpoint interval in seconds
    pub checkpoint_interval_secs: u64,
    /// Enable work stealing
    pub work_stealing_enabled: bool,
    /// Number of worker threads (0 = auto-detect)
    pub worker_threads: usize,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            node_name: String::from("axiom-node"),
            network: NetworkConfig::default(),
            hardware: HardwareConfig::default(),
            max_agents: 10000,
            checkpointing_enabled: true,
            checkpoint_interval_secs: 300,
            work_stealing_enabled: true,
            worker_threads: 0,
        }
    }
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Listen address (e.g., "0.0.0.0:9100")
    pub listen_addr: String,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,
    /// Enable discovery
    pub discovery_enabled: bool,
    /// Maximum peers
    pub max_peers: usize,
    /// MTU size
    pub mtu: usize,
    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Enable TLS
    pub tls_enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::from("0.0.0.0:9100"),
            bootstrap_peers: Vec::new(),
            discovery_enabled: true,
            max_peers: 100,
            mtu: 1400,
            connect_timeout_ms: 5000,
            tls_enabled: true,
        }
    }
}

/// Hardware configuration
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    /// Enable GPU acceleration
    pub gpu_enabled: bool,
    /// GPU device indices to use
    pub gpu_devices: Vec<usize>,
    /// Enable NUMA awareness
    pub numa_enabled: bool,
    /// Memory limit in bytes (0 = no limit)
    pub memory_limit: usize,
    /// CPU cores to use (empty = all)
    pub cpu_cores: Vec<usize>,
    /// Enable huge pages
    pub huge_pages: bool,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            gpu_enabled: true,
            gpu_devices: Vec::new(),
            numa_enabled: true,
            memory_limit: 0,
            cpu_cores: Vec::new(),
            huge_pages: false,
        }
    }
}

/// Builder for kernel configuration
pub struct KernelConfigBuilder {
    config: KernelConfig,
}

impl KernelConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: KernelConfig::default(),
        }
    }

    pub fn node_name(mut self, name: impl Into<String>) -> Self {
        self.config.node_name = name.into();
        self
    }

    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.network.listen_addr = addr.into();
        self
    }

    pub fn bootstrap_peer(mut self, peer: impl Into<String>) -> Self {
        self.config.network.bootstrap_peers.push(peer.into());
        self
    }

    pub fn max_agents(mut self, max: usize) -> Self {
        self.config.max_agents = max;
        self
    }

    pub fn worker_threads(mut self, threads: usize) -> Self {
        self.config.worker_threads = threads;
        self
    }

    pub fn enable_checkpointing(mut self, enabled: bool) -> Self {
        self.config.checkpointing_enabled = enabled;
        self
    }

    pub fn checkpoint_interval(mut self, secs: u64) -> Self {
        self.config.checkpoint_interval_secs = secs;
        self
    }

    pub fn enable_gpu(mut self, enabled: bool) -> Self {
        self.config.hardware.gpu_enabled = enabled;
        self
    }

    pub fn gpu_device(mut self, device: usize) -> Self {
        self.config.hardware.gpu_devices.push(device);
        self
    }

    pub fn enable_numa(mut self, enabled: bool) -> Self {
        self.config.hardware.numa_enabled = enabled;
        self
    }

    pub fn memory_limit(mut self, bytes: usize) -> Self {
        self.config.hardware.memory_limit = bytes;
        self
    }

    pub fn build(self) -> KernelConfig {
        self.config
    }
}

impl Default for KernelConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KernelConfig::default();
        assert_eq!(config.node_name, "axiom-node");
        assert_eq!(config.max_agents, 10000);
        assert!(config.checkpointing_enabled);
    }

    #[test]
    fn test_builder() {
        let config = KernelConfigBuilder::new()
            .node_name("test-node")
            .listen_addr("127.0.0.1:9100")
            .bootstrap_peer("192.168.1.1:9100")
            .max_agents(1000)
            .worker_threads(4)
            .enable_gpu(false)
            .build();

        assert_eq!(config.node_name, "test-node");
        assert_eq!(config.network.listen_addr, "127.0.0.1:9100");
        assert_eq!(config.network.bootstrap_peers.len(), 1);
        assert_eq!(config.max_agents, 1000);
        assert_eq!(config.worker_threads, 4);
        assert!(!config.hardware.gpu_enabled);
    }

    #[test]
    fn test_network_defaults() {
        let config = NetworkConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:9100");
        assert!(config.discovery_enabled);
        assert!(config.tls_enabled);
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_hardware_defaults() {
        let config = HardwareConfig::default();
        assert!(config.gpu_enabled);
        assert!(config.numa_enabled);
        assert!(!config.huge_pages);
    }
}
