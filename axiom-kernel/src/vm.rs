//! AXIOM-VM Deployment Target
//!
//! For hypervisor-based isolation of AI agents:
//! - VM-level isolation for untrusted agents
//! - Hardware resource partitioning
//! - GPU passthrough support
//! - Live migration between hosts
//! - Memory isolation and limits

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::NodeId;
use hashbrown::HashMap;

use crate::config::KernelConfig;
use crate::{Kernel, KernelResult};

/// VM-specific configuration
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// VM name
    pub name: String,
    /// Number of vCPUs
    pub vcpus: usize,
    /// Memory in megabytes
    pub memory_mb: usize,
    /// GPU passthrough configuration
    pub gpu_passthrough: Option<GpuPassthrough>,
    /// Network configuration
    pub network: VmNetworkConfig,
    /// Storage configuration
    pub storage: VmStorageConfig,
    /// Enable nested virtualization
    pub nested_virt: bool,
    /// Hypervisor type
    pub hypervisor: HypervisorType,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            name: String::from("axiom-vm"),
            vcpus: 4,
            memory_mb: 8192,
            gpu_passthrough: None,
            network: VmNetworkConfig::default(),
            storage: VmStorageConfig::default(),
            nested_virt: false,
            hypervisor: HypervisorType::Kvm,
        }
    }
}

/// GPU passthrough configuration
#[derive(Debug, Clone)]
pub struct GpuPassthrough {
    /// PCI device IDs (e.g., "10de:2204")
    pub device_ids: Vec<String>,
    /// IOMMU group
    pub iommu_group: Option<u32>,
    /// Enable vGPU instead of full passthrough
    pub use_vgpu: bool,
    /// vGPU profile (for vGPU mode)
    pub vgpu_profile: Option<String>,
}

/// VM network configuration
#[derive(Debug, Clone)]
pub struct VmNetworkConfig {
    /// Network mode
    pub mode: VmNetworkMode,
    /// Bridge name (for bridged mode)
    pub bridge: Option<String>,
    /// MAC address (auto-generated if None)
    pub mac_address: Option<String>,
    /// Enable host networking (less isolated)
    pub host_network: bool,
}

impl Default for VmNetworkConfig {
    fn default() -> Self {
        Self {
            mode: VmNetworkMode::Nat,
            bridge: None,
            mac_address: None,
            host_network: false,
        }
    }
}

/// VM network mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmNetworkMode {
    /// NAT (private network, host translation)
    Nat,
    /// Bridged (same network as host)
    Bridge,
    /// Host-only (isolated from external)
    HostOnly,
    /// User-mode networking (no root required)
    User,
}

/// VM storage configuration
#[derive(Debug, Clone)]
pub struct VmStorageConfig {
    /// Root disk size in gigabytes
    pub root_disk_gb: u32,
    /// Additional data disks
    pub data_disks: Vec<DiskSpec>,
    /// Use COW (copy-on-write) images
    pub use_cow: bool,
    /// Image format
    pub format: DiskFormat,
}

impl Default for VmStorageConfig {
    fn default() -> Self {
        Self {
            root_disk_gb: 20,
            data_disks: Vec::new(),
            use_cow: true,
            format: DiskFormat::Qcow2,
        }
    }
}

/// Additional disk specification
#[derive(Debug, Clone)]
pub struct DiskSpec {
    /// Disk name
    pub name: String,
    /// Size in gigabytes
    pub size_gb: u32,
    /// Mount point in VM
    pub mount_point: String,
}

/// Disk image format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskFormat {
    /// QEMU Copy-on-Write v2
    Qcow2,
    /// Raw disk image
    Raw,
    /// VMware VMDK
    Vmdk,
    /// VirtualBox VDI
    Vdi,
}

/// Hypervisor type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorType {
    /// KVM (Linux)
    Kvm,
    /// QEMU (userspace, portable)
    Qemu,
    /// Cloud Hypervisor (modern, minimal)
    CloudHypervisor,
    /// Firecracker (microVM)
    Firecracker,
}

/// VM state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM is not created
    NotCreated,
    /// VM is created but not running
    Stopped,
    /// VM is starting
    Starting,
    /// VM is running
    Running,
    /// VM is paused
    Paused,
    /// VM is being migrated
    Migrating,
    /// VM is stopping
    Stopping,
    /// VM crashed or errored
    Failed,
}

/// Resource limits for a VM
#[derive(Debug, Clone)]
pub struct VmResourceLimits {
    /// CPU quota (percentage, 100 = 1 full core)
    pub cpu_quota: u32,
    /// Memory limit in MB (hard limit)
    pub memory_limit_mb: usize,
    /// Memory soft limit in MB (target)
    pub memory_soft_limit_mb: usize,
    /// Disk I/O bandwidth limit (MB/s)
    pub disk_io_limit_mbps: Option<u32>,
    /// Network bandwidth limit (Mbps)
    pub network_limit_mbps: Option<u32>,
}

impl Default for VmResourceLimits {
    fn default() -> Self {
        Self {
            cpu_quota: 400, // 4 cores equivalent
            memory_limit_mb: 8192,
            memory_soft_limit_mb: 4096,
            disk_io_limit_mbps: None,
            network_limit_mbps: None,
        }
    }
}

/// VM manager for creating and managing VMs
pub struct VmManager {
    /// Known VMs
    vms: HashMap<String, VmInstance>,
    /// Default hypervisor
    hypervisor: HypervisorType,
    /// Base image path
    base_image_path: Option<String>,
}

impl VmManager {
    /// Create a new VM manager
    pub fn new(hypervisor: HypervisorType) -> Self {
        Self {
            vms: HashMap::new(),
            hypervisor,
            base_image_path: None,
        }
    }

    /// Set base image for new VMs
    pub fn set_base_image(&mut self, path: &str) {
        self.base_image_path = Some(String::from(path));
    }

    /// Create a new VM
    pub fn create(&mut self, config: VmConfig) -> Result<String, VmError> {
        if self.vms.contains_key(&config.name) {
            return Err(VmError::AlreadyExists(config.name.clone()));
        }

        let instance = VmInstance {
            config: config.clone(),
            state: VmState::Stopped,
            limits: VmResourceLimits::default(),
            pid: None,
            console_path: None,
        };

        let name = config.name.clone();
        self.vms.insert(name.clone(), instance);
        Ok(name)
    }

    /// Start a VM
    pub fn start(&mut self, name: &str) -> Result<(), VmError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;

        if vm.state != VmState::Stopped {
            return Err(VmError::InvalidState(vm.state));
        }

        vm.state = VmState::Starting;
        // Would actually launch hypervisor process here
        vm.state = VmState::Running;
        vm.pid = Some(12345); // Placeholder

        Ok(())
    }

    /// Stop a VM
    pub fn stop(&mut self, name: &str) -> Result<(), VmError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;

        if vm.state != VmState::Running && vm.state != VmState::Paused {
            return Err(VmError::InvalidState(vm.state));
        }

        vm.state = VmState::Stopping;
        // Would actually stop the process here
        vm.state = VmState::Stopped;
        vm.pid = None;

        Ok(())
    }

    /// Pause a VM
    pub fn pause(&mut self, name: &str) -> Result<(), VmError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;

        if vm.state != VmState::Running {
            return Err(VmError::InvalidState(vm.state));
        }

        vm.state = VmState::Paused;
        Ok(())
    }

    /// Resume a paused VM
    pub fn resume(&mut self, name: &str) -> Result<(), VmError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;

        if vm.state != VmState::Paused {
            return Err(VmError::InvalidState(vm.state));
        }

        vm.state = VmState::Running;
        Ok(())
    }

    /// Delete a VM
    pub fn delete(&mut self, name: &str) -> Result<(), VmError> {
        let vm = self.vms.get(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;

        if vm.state != VmState::Stopped {
            return Err(VmError::InvalidState(vm.state));
        }

        self.vms.remove(name);
        Ok(())
    }

    /// Get VM state
    pub fn state(&self, name: &str) -> Option<VmState> {
        self.vms.get(name).map(|vm| vm.state)
    }

    /// List all VMs
    pub fn list(&self) -> Vec<&str> {
        self.vms.keys().map(|s| s.as_str()).collect()
    }

    /// Get VM count
    pub fn count(&self) -> usize {
        self.vms.len()
    }

    /// Update resource limits for a VM
    pub fn set_limits(&mut self, name: &str, limits: VmResourceLimits) -> Result<(), VmError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| VmError::NotFound(String::from(name)))?;
        vm.limits = limits;
        Ok(())
    }
}

/// VM instance
#[derive(Debug)]
struct VmInstance {
    /// Configuration
    config: VmConfig,
    /// Current state
    state: VmState,
    /// Resource limits
    limits: VmResourceLimits,
    /// Process ID (if running)
    pid: Option<u32>,
    /// Console socket path
    console_path: Option<String>,
}

/// VM errors
#[derive(Debug, Clone)]
pub enum VmError {
    /// VM already exists
    AlreadyExists(String),
    /// VM not found
    NotFound(String),
    /// Invalid state for operation
    InvalidState(VmState),
    /// Hypervisor error
    Hypervisor(String),
    /// Resource error
    Resource(String),
}

/// VM kernel wrapper
pub struct VmKernel {
    kernel: Kernel,
    vm_config: VmConfig,
    vm_manager: VmManager,
}

impl VmKernel {
    /// Create a new VM kernel
    pub fn new(config: KernelConfig, vm_config: VmConfig) -> Self {
        let kernel = Kernel::new(config);
        let vm_manager = VmManager::new(vm_config.hypervisor);

        Self {
            kernel,
            vm_config,
            vm_manager,
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

    /// Get VM manager
    pub fn vm_manager(&self) -> &VmManager {
        &self.vm_manager
    }

    /// Get mutable VM manager
    pub fn vm_manager_mut(&mut self) -> &mut VmManager {
        &mut self.vm_manager
    }

    /// Boot the VM kernel
    pub fn boot(&mut self) -> KernelResult<()> {
        use crate::boot::BootConfig;

        let boot_config = BootConfig {
            skip_hardware_discovery: true, // VM handles hardware
            skip_network: true, // Will be configured by VM
            single_threaded: false,
            verbose: false,
        };

        let mut kernel = Kernel::with_boot_config(
            crate::config::KernelConfig::default(),
            boot_config,
        );
        kernel.boot()?;

        self.kernel = kernel;
        Ok(())
    }

    /// Create an isolated VM for an untrusted agent
    pub fn create_agent_vm(&mut self, name: &str, vcpus: usize, memory_mb: usize) -> Result<String, VmError> {
        let mut config = VmConfig::default();
        config.name = String::from(name);
        config.vcpus = vcpus;
        config.memory_mb = memory_mb;

        self.vm_manager.create(config)
    }

    /// Start an agent's VM
    pub fn start_agent_vm(&mut self, name: &str) -> Result<(), VmError> {
        self.vm_manager.start(name)
    }

    /// Stop an agent's VM
    pub fn stop_agent_vm(&mut self, name: &str) -> Result<(), VmError> {
        self.vm_manager.stop(name)
    }
}

/// Generate QEMU command line for a VM
pub fn generate_qemu_command(config: &VmConfig) -> Vec<String> {
    let mut args = Vec::new();

    // Basic settings
    args.push(String::from("-enable-kvm"));
    args.push(String::from("-m"));
    args.push(format!("{}M", config.memory_mb));
    args.push(String::from("-smp"));
    args.push(format!("{}", config.vcpus));

    // Machine type
    args.push(String::from("-machine"));
    args.push(String::from("q35,accel=kvm"));

    // CPU
    args.push(String::from("-cpu"));
    args.push(String::from("host"));

    // Network
    match config.network.mode {
        VmNetworkMode::Nat => {
            args.push(String::from("-netdev"));
            args.push(String::from("user,id=net0"));
            args.push(String::from("-device"));
            args.push(String::from("virtio-net-pci,netdev=net0"));
        }
        VmNetworkMode::Bridge => {
            if let Some(ref bridge) = config.network.bridge {
                args.push(String::from("-netdev"));
                args.push(format!("bridge,id=net0,br={}", bridge));
                args.push(String::from("-device"));
                args.push(String::from("virtio-net-pci,netdev=net0"));
            }
        }
        _ => {}
    }

    // GPU passthrough
    if let Some(ref gpu) = config.gpu_passthrough {
        for device_id in &gpu.device_ids {
            args.push(String::from("-device"));
            args.push(format!("vfio-pci,host={}", device_id));
        }
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_config_default() {
        let config = VmConfig::default();
        assert_eq!(config.name, "axiom-vm");
        assert_eq!(config.vcpus, 4);
        assert_eq!(config.memory_mb, 8192);
    }

    #[test]
    fn test_vm_manager_create() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        let config = VmConfig {
            name: String::from("test-vm"),
            ..Default::default()
        };

        let result = manager.create(config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-vm");
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn test_vm_manager_lifecycle() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        // Create
        let config = VmConfig {
            name: String::from("test-vm"),
            ..Default::default()
        };
        manager.create(config).unwrap();
        assert_eq!(manager.state("test-vm"), Some(VmState::Stopped));

        // Start
        manager.start("test-vm").unwrap();
        assert_eq!(manager.state("test-vm"), Some(VmState::Running));

        // Pause
        manager.pause("test-vm").unwrap();
        assert_eq!(manager.state("test-vm"), Some(VmState::Paused));

        // Resume
        manager.resume("test-vm").unwrap();
        assert_eq!(manager.state("test-vm"), Some(VmState::Running));

        // Stop
        manager.stop("test-vm").unwrap();
        assert_eq!(manager.state("test-vm"), Some(VmState::Stopped));

        // Delete
        manager.delete("test-vm").unwrap();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_vm_duplicate_create() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        let config = VmConfig {
            name: String::from("test-vm"),
            ..Default::default()
        };

        manager.create(config.clone()).unwrap();
        let result = manager.create(config);

        assert!(matches!(result, Err(VmError::AlreadyExists(_))));
    }

    #[test]
    fn test_vm_not_found() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        let result = manager.start("nonexistent");
        assert!(matches!(result, Err(VmError::NotFound(_))));
    }

    #[test]
    fn test_resource_limits() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        let config = VmConfig {
            name: String::from("test-vm"),
            ..Default::default()
        };
        manager.create(config).unwrap();

        let limits = VmResourceLimits {
            cpu_quota: 200,
            memory_limit_mb: 4096,
            memory_soft_limit_mb: 2048,
            disk_io_limit_mbps: Some(100),
            network_limit_mbps: Some(1000),
        };

        manager.set_limits("test-vm", limits).unwrap();
    }

    #[test]
    fn test_generate_qemu_command() {
        let config = VmConfig {
            name: String::from("test-vm"),
            vcpus: 4,
            memory_mb: 4096,
            ..Default::default()
        };

        let args = generate_qemu_command(&config);

        assert!(args.contains(&String::from("-enable-kvm")));
        assert!(args.contains(&String::from("4096M")));
        assert!(args.contains(&String::from("4")));
    }

    #[test]
    fn test_vm_list() {
        let mut manager = VmManager::new(HypervisorType::Kvm);

        for i in 0..3 {
            let config = VmConfig {
                name: format!("vm-{}", i),
                ..Default::default()
            };
            manager.create(config).unwrap();
        }

        let list = manager.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_gpu_passthrough_config() {
        let gpu = GpuPassthrough {
            device_ids: vec![String::from("10de:2204")],
            iommu_group: Some(15),
            use_vgpu: false,
            vgpu_profile: None,
        };

        let config = VmConfig {
            name: String::from("gpu-vm"),
            gpu_passthrough: Some(gpu),
            ..Default::default()
        };

        let args = generate_qemu_command(&config);
        assert!(args.iter().any(|a| a.contains("vfio-pci")));
    }
}
