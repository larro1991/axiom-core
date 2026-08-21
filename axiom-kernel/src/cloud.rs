//! AXIOM-Cloud Deployment Target
//!
//! For distributed multi-node deployments:
//! - Cluster membership and discovery
//! - Leader election for coordination
//! - Cross-node agent migration
//! - Distributed checkpointing
//! - Health monitoring and auto-healing

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::NodeId;
use hashbrown::{HashMap, HashSet};

use crate::config::KernelConfig;
use crate::shutdown::ShutdownReason;
use crate::{Kernel, KernelResult};

/// Cloud-specific configuration
#[derive(Debug, Clone)]
pub struct CloudConfig {
    /// Cluster name for multi-tenancy
    pub cluster_name: String,
    /// Discovery method
    pub discovery: DiscoveryMethod,
    /// Replication factor for agents
    pub replication_factor: usize,
    /// Enable automatic agent migration
    pub auto_migration: bool,
    /// Health check interval (seconds)
    pub health_check_interval_secs: u64,
    /// Node failure timeout (seconds)
    pub failure_timeout_secs: u64,
    /// Enable distributed checkpoints
    pub distributed_checkpoints: bool,
    /// Minimum nodes for quorum
    pub quorum_size: usize,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            cluster_name: String::from("axiom-cluster"),
            discovery: DiscoveryMethod::Bootstrap(Vec::new()),
            replication_factor: 3,
            auto_migration: true,
            health_check_interval_secs: 10,
            failure_timeout_secs: 30,
            distributed_checkpoints: true,
            quorum_size: 2,
        }
    }
}

/// Method for discovering cluster nodes
#[derive(Debug, Clone)]
pub enum DiscoveryMethod {
    /// Static list of bootstrap nodes
    Bootstrap(Vec<String>),
    /// DNS-based discovery
    Dns { service_name: String },
    /// Kubernetes API discovery
    Kubernetes { namespace: String, label_selector: String },
    /// Consul service discovery
    Consul { service: String, datacenter: Option<String> },
    /// etcd-based discovery
    Etcd { endpoints: Vec<String>, prefix: String },
}

/// Node status in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is joining the cluster
    Joining,
    /// Node is fully operational
    Active,
    /// Node is suspected to be down
    Suspect,
    /// Node is confirmed down
    Down,
    /// Node is gracefully leaving
    Leaving,
    /// Node has left the cluster
    Left,
}

/// Information about a cluster node
#[derive(Debug, Clone)]
pub struct ClusterNode {
    /// Node identifier
    pub node_id: NodeId,
    /// Human-readable name
    pub name: String,
    /// Network address
    pub address: String,
    /// Current status
    pub status: NodeStatus,
    /// Last heartbeat timestamp
    pub last_heartbeat: u64,
    /// Agents running on this node
    pub agent_count: usize,
    /// Load metric (0-100)
    pub load: u8,
    /// Whether this node is the leader
    pub is_leader: bool,
}

/// Cluster coordinator for multi-node deployments
pub struct ClusterCoordinator {
    /// Our node ID
    local_id: NodeId,
    /// Cluster configuration
    config: CloudConfig,
    /// Known cluster nodes
    nodes: HashMap<NodeId, ClusterNode>,
    /// Current leader (if known)
    leader: Option<NodeId>,
    /// Our current term (for leader election)
    term: u64,
    /// Nodes we've voted for in current term
    voted_for: Option<NodeId>,
    /// Pending migrations
    pending_migrations: Vec<MigrationTask>,
}

impl ClusterCoordinator {
    /// Create a new cluster coordinator
    pub fn new(local_id: NodeId, config: CloudConfig) -> Self {
        Self {
            local_id,
            config,
            nodes: HashMap::new(),
            leader: None,
            term: 0,
            voted_for: None,
            pending_migrations: Vec::new(),
        }
    }

    /// Register ourselves in the cluster
    pub fn register_self(&mut self, name: &str, address: &str) {
        let node = ClusterNode {
            node_id: self.local_id.clone(),
            name: String::from(name),
            address: String::from(address),
            status: NodeStatus::Joining,
            last_heartbeat: 0,
            agent_count: 0,
            load: 0,
            is_leader: false,
        };
        self.nodes.insert(self.local_id.clone(), node);
    }

    /// Mark a node as active
    pub fn activate_node(&mut self, node_id: &NodeId) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Active;
        }
    }

    /// Record a heartbeat from a node
    pub fn heartbeat(&mut self, node_id: &NodeId, timestamp: u64, agent_count: usize, load: u8) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.last_heartbeat = timestamp;
            node.agent_count = agent_count;
            node.load = load;
            if node.status == NodeStatus::Suspect {
                node.status = NodeStatus::Active;
            }
        }
    }

    /// Check for failed nodes (should be called periodically)
    pub fn check_failures(&mut self, now: u64) -> Vec<NodeId> {
        let timeout = self.config.failure_timeout_secs;
        let mut failed = Vec::new();

        for (id, node) in &mut self.nodes {
            if *id == self.local_id {
                continue; // Don't check ourselves
            }

            let age = now.saturating_sub(node.last_heartbeat);

            match node.status {
                NodeStatus::Active if age > timeout / 2 => {
                    node.status = NodeStatus::Suspect;
                }
                NodeStatus::Suspect if age > timeout => {
                    node.status = NodeStatus::Down;
                    failed.push(id.clone());
                }
                _ => {}
            }
        }

        failed
    }

    /// Get nodes suitable for agent placement
    pub fn get_placement_candidates(&self) -> Vec<&ClusterNode> {
        let mut candidates: Vec<_> = self.nodes.values()
            .filter(|n| n.status == NodeStatus::Active)
            .collect();

        // Sort by load (lowest first)
        candidates.sort_by_key(|n| n.load);
        candidates
    }

    /// Select nodes for replication
    pub fn select_replicas(&self, count: usize) -> Vec<NodeId> {
        self.get_placement_candidates()
            .into_iter()
            .take(count)
            .map(|n| n.node_id.clone())
            .collect()
    }

    /// Start a leader election
    pub fn start_election(&mut self) {
        self.term += 1;
        self.voted_for = Some(self.local_id.clone());
    }

    /// Receive a vote request
    pub fn request_vote(&mut self, candidate: NodeId, term: u64) -> bool {
        if term > self.term {
            self.term = term;
            self.voted_for = None;
            self.leader = None;
        }

        if term == self.term && self.voted_for.is_none() {
            self.voted_for = Some(candidate);
            true
        } else {
            false
        }
    }

    /// Record election victory
    pub fn become_leader(&mut self) {
        self.leader = Some(self.local_id.clone());
        if let Some(node) = self.nodes.get_mut(&self.local_id) {
            node.is_leader = true;
        }
    }

    /// Accept another node as leader
    pub fn accept_leader(&mut self, leader: NodeId, term: u64) {
        self.term = term;
        self.leader = Some(leader.clone());

        for node in self.nodes.values_mut() {
            node.is_leader = node.node_id == leader;
        }
    }

    /// Check if we are the leader
    pub fn is_leader(&self) -> bool {
        self.leader.as_ref() == Some(&self.local_id)
    }

    /// Get current leader
    pub fn leader(&self) -> Option<&NodeId> {
        self.leader.as_ref()
    }

    /// Check if we have quorum
    pub fn has_quorum(&self) -> bool {
        let active_count = self.nodes.values()
            .filter(|n| n.status == NodeStatus::Active)
            .count();
        active_count >= self.config.quorum_size
    }

    /// Schedule an agent migration
    pub fn schedule_migration(&mut self, agent_id: [u8; 32], from: NodeId, to: NodeId) {
        self.pending_migrations.push(MigrationTask {
            agent_id,
            from,
            to,
            status: MigrationStatus::Pending,
        });
    }

    /// Get active node count
    pub fn active_node_count(&self) -> usize {
        self.nodes.values()
            .filter(|n| n.status == NodeStatus::Active)
            .count()
    }

    /// Get total node count
    pub fn total_node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get node by ID
    pub fn get_node(&self, id: &NodeId) -> Option<&ClusterNode> {
        self.nodes.get(id)
    }
}

/// Agent migration task
#[derive(Debug, Clone)]
pub struct MigrationTask {
    /// Agent being migrated
    pub agent_id: [u8; 32],
    /// Source node
    pub from: NodeId,
    /// Destination node
    pub to: NodeId,
    /// Current status
    pub status: MigrationStatus,
}

/// Migration status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Waiting to start
    Pending,
    /// Checkpointing agent state
    Checkpointing,
    /// Transferring checkpoint
    Transferring,
    /// Restoring on target
    Restoring,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

/// Cloud kernel wrapper
pub struct CloudKernel {
    kernel: Kernel,
    cloud_config: CloudConfig,
    coordinator: ClusterCoordinator,
}

impl CloudKernel {
    /// Create a new cloud kernel
    pub fn new(config: KernelConfig, cloud_config: CloudConfig) -> Self {
        let kernel = Kernel::new(config);
        let local_id = kernel.node_id().clone();
        let coordinator = ClusterCoordinator::new(local_id, cloud_config.clone());

        Self {
            kernel,
            cloud_config,
            coordinator,
        }
    }

    /// Get the underlying kernel
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// Get mutable kernel
    pub fn kernel_mut(&mut self) -> &mut Kernel {
        &mut self.kernel
    }

    /// Get coordinator
    pub fn coordinator(&self) -> &ClusterCoordinator {
        &self.coordinator
    }

    /// Get mutable coordinator
    pub fn coordinator_mut(&mut self) -> &mut ClusterCoordinator {
        &mut self.coordinator
    }

    /// Boot the cloud kernel
    #[cfg(feature = "std")]
    pub async fn boot(&mut self, node_name: &str) -> KernelResult<()> {
        use crate::boot::BootConfig;

        // Register ourselves
        self.coordinator.register_self(
            node_name,
            &self.kernel.node_id().to_string(),
        );

        // Boot the kernel
        let mut boot_config = BootConfig::default();
        boot_config.skip_network = false;

        self.kernel.boot_async().await?;

        // Mark ourselves as active
        self.coordinator.activate_node(self.kernel.node_id());

        // Discover peers based on config
        self.discover_peers().await?;

        Ok(())
    }

    #[cfg(feature = "std")]
    async fn discover_peers(&mut self) -> KernelResult<()> {
        match &self.cloud_config.discovery {
            DiscoveryMethod::Bootstrap(peers) => {
                for peer_addr in peers {
                    // Would connect to peer and exchange node info
                    let _ = peer_addr;
                }
            }
            DiscoveryMethod::Dns { service_name } => {
                // Would do DNS SRV lookup
                let _ = service_name;
            }
            DiscoveryMethod::Kubernetes { namespace, label_selector } => {
                // Would call Kubernetes API
                let _ = (namespace, label_selector);
            }
            DiscoveryMethod::Consul { service, datacenter } => {
                // Would query Consul
                let _ = (service, datacenter);
            }
            DiscoveryMethod::Etcd { endpoints, prefix } => {
                // Would query etcd
                let _ = (endpoints, prefix);
            }
        }
        Ok(())
    }

    /// Run the cluster maintenance loop
    #[cfg(feature = "std")]
    pub async fn run(&mut self) -> KernelResult<()> {
        use tokio::time::{interval, Duration};

        let mut health_interval = interval(Duration::from_secs(
            self.cloud_config.health_check_interval_secs
        ));

        loop {
            health_interval.tick().await;

            // Get current time
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Send heartbeat (would broadcast to cluster)
            let agent_count = self.kernel.agent_count();
            self.coordinator.heartbeat(
                self.kernel.node_id(),
                now,
                agent_count,
                50, // TODO: calculate actual load
            );

            // Check for failures
            let failed = self.coordinator.check_failures(now);
            for failed_node in failed {
                self.handle_node_failure(&failed_node).await?;
            }

            // Check if we need to elect a leader
            if !self.coordinator.has_quorum() {
                // Can't operate without quorum
                continue;
            }

            if self.coordinator.leader().is_none() {
                self.coordinator.start_election();
                // Would broadcast vote requests
            }

            // Check for shutdown
            if matches!(self.kernel.state(), crate::boot::KernelState::ShuttingDown) {
                break;
            }
        }

        Ok(())
    }

    #[cfg(feature = "std")]
    async fn handle_node_failure(&mut self, _failed_node: &NodeId) -> KernelResult<()> {
        // Would:
        // 1. Identify agents that were on the failed node
        // 2. If we're the leader, redistribute them to healthy nodes
        // 3. Restore from distributed checkpoints
        Ok(())
    }

    /// Gracefully leave the cluster
    pub fn leave(&mut self) -> KernelResult<()> {
        self.kernel.shutdown(ShutdownReason::Migration);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_cloud_config_default() {
        let config = CloudConfig::default();
        assert_eq!(config.cluster_name, "axiom-cluster");
        assert_eq!(config.replication_factor, 3);
        assert!(config.auto_migration);
    }

    #[test]
    fn test_cluster_coordinator() {
        let local_id = test_node_id(0);
        let config = CloudConfig::default();
        let mut coord = ClusterCoordinator::new(local_id.clone(), config);

        coord.register_self("node-0", "10.0.0.1:9100");
        assert_eq!(coord.total_node_count(), 1);

        coord.activate_node(&local_id);
        assert_eq!(coord.active_node_count(), 1);
    }

    #[test]
    fn test_heartbeat() {
        let local_id = test_node_id(0);
        let mut coord = ClusterCoordinator::new(local_id.clone(), CloudConfig::default());

        coord.register_self("node-0", "10.0.0.1:9100");
        coord.activate_node(&local_id);

        coord.heartbeat(&local_id, 1000, 5, 50);

        let node = coord.get_node(&local_id).unwrap();
        assert_eq!(node.last_heartbeat, 1000);
        assert_eq!(node.agent_count, 5);
        assert_eq!(node.load, 50);
    }

    #[test]
    fn test_failure_detection() {
        let local_id = test_node_id(0);
        let peer_id = test_node_id(1);

        let mut config = CloudConfig::default();
        config.failure_timeout_secs = 30;

        let mut coord = ClusterCoordinator::new(local_id.clone(), config);

        coord.register_self("node-0", "10.0.0.1:9100");
        coord.activate_node(&local_id);

        // Add a peer
        coord.nodes.insert(peer_id.clone(), ClusterNode {
            node_id: peer_id.clone(),
            name: String::from("node-1"),
            address: String::from("10.0.0.2:9100"),
            status: NodeStatus::Active,
            last_heartbeat: 0,
            agent_count: 0,
            load: 0,
            is_leader: false,
        });

        // No failures yet
        let failed = coord.check_failures(10);
        assert!(failed.is_empty());

        // Suspect after half timeout
        coord.check_failures(20);
        assert_eq!(coord.get_node(&peer_id).unwrap().status, NodeStatus::Suspect);

        // Failed after full timeout
        let failed = coord.check_failures(40);
        assert_eq!(failed.len(), 1);
        assert_eq!(coord.get_node(&peer_id).unwrap().status, NodeStatus::Down);
    }

    #[test]
    fn test_leader_election() {
        let local_id = test_node_id(0);
        let mut coord = ClusterCoordinator::new(local_id.clone(), CloudConfig::default());

        assert!(!coord.is_leader());
        assert!(coord.leader().is_none());

        coord.start_election();
        assert_eq!(coord.term, 1);
        assert_eq!(coord.voted_for, Some(local_id.clone()));

        coord.become_leader();
        assert!(coord.is_leader());
        assert_eq!(coord.leader(), Some(&local_id));
    }

    #[test]
    fn test_vote_request() {
        let local_id = test_node_id(0);
        let candidate_id = test_node_id(1);
        let mut coord = ClusterCoordinator::new(local_id, CloudConfig::default());

        // Should grant vote in new term
        assert!(coord.request_vote(candidate_id.clone(), 1));
        assert_eq!(coord.voted_for, Some(candidate_id.clone()));

        // Should not grant second vote in same term
        let other_id = test_node_id(2);
        assert!(!coord.request_vote(other_id, 1));
    }

    #[test]
    fn test_quorum() {
        let local_id = test_node_id(0);
        let mut config = CloudConfig::default();
        config.quorum_size = 2;

        let mut coord = ClusterCoordinator::new(local_id.clone(), config);
        coord.register_self("node-0", "10.0.0.1:9100");
        coord.activate_node(&local_id);

        // Only 1 node, no quorum
        assert!(!coord.has_quorum());

        // Add second node
        let peer_id = test_node_id(1);
        coord.nodes.insert(peer_id.clone(), ClusterNode {
            node_id: peer_id.clone(),
            name: String::from("node-1"),
            address: String::from("10.0.0.2:9100"),
            status: NodeStatus::Active,
            last_heartbeat: 0,
            agent_count: 0,
            load: 0,
            is_leader: false,
        });

        // Now we have quorum
        assert!(coord.has_quorum());
    }

    #[test]
    fn test_placement_candidates() {
        let local_id = test_node_id(0);
        let mut coord = ClusterCoordinator::new(local_id.clone(), CloudConfig::default());

        // Add nodes with different loads
        for i in 0..3 {
            let id = test_node_id(i);
            coord.nodes.insert(id.clone(), ClusterNode {
                node_id: id,
                name: format!("node-{}", i),
                address: format!("10.0.0.{}:9100", i + 1),
                status: NodeStatus::Active,
                last_heartbeat: 0,
                agent_count: 0,
                load: (i * 30) as u8, // 0, 30, 60
                is_leader: false,
            });
        }

        let candidates = coord.get_placement_candidates();
        assert_eq!(candidates.len(), 3);
        // Should be sorted by load
        assert_eq!(candidates[0].load, 0);
        assert_eq!(candidates[1].load, 30);
        assert_eq!(candidates[2].load, 60);
    }

    #[test]
    fn test_select_replicas() {
        let local_id = test_node_id(0);
        let mut coord = ClusterCoordinator::new(local_id.clone(), CloudConfig::default());

        for i in 0..5 {
            let id = test_node_id(i);
            coord.nodes.insert(id.clone(), ClusterNode {
                node_id: id,
                name: format!("node-{}", i),
                address: format!("10.0.0.{}:9100", i + 1),
                status: NodeStatus::Active,
                last_heartbeat: 0,
                agent_count: 0,
                load: (i * 10) as u8,
                is_leader: false,
            });
        }

        let replicas = coord.select_replicas(3);
        assert_eq!(replicas.len(), 3);
    }
}
