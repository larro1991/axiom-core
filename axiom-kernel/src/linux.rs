//! AXIOM-Linux Deployment Target
//!
//! For development and single-node deployments.
//! Runs as a userspace process on Linux with:
//! - Systemd service integration
//! - Signal handling (SIGTERM, SIGINT, SIGHUP)
//! - Unix socket for local IPC
//! - D-Bus integration (optional)

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::KernelConfig;
use crate::shutdown::ShutdownReason;
use crate::{Kernel, KernelResult};

/// Linux-specific configuration
#[derive(Debug, Clone)]
pub struct LinuxConfig {
    /// Path to Unix socket for local control
    pub control_socket: String,
    /// Path to PID file
    pub pid_file: Option<String>,
    /// Run as daemon
    pub daemonize: bool,
    /// User to run as (after dropping privileges)
    pub run_as_user: Option<String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// Enable systemd notify
    pub systemd_notify: bool,
}

impl Default for LinuxConfig {
    fn default() -> Self {
        Self {
            control_socket: String::from("/run/axiom/control.sock"),
            pid_file: Some(String::from("/run/axiom/axiom.pid")),
            daemonize: false,
            run_as_user: None,
            working_dir: None,
            systemd_notify: true,
        }
    }
}

/// Linux kernel wrapper
pub struct LinuxKernel {
    kernel: Kernel,
    linux_config: LinuxConfig,
    signal_received: Option<i32>,
}

impl LinuxKernel {
    /// Create a new Linux kernel
    pub fn new(config: KernelConfig, linux_config: LinuxConfig) -> Self {
        Self {
            kernel: Kernel::new(config),
            linux_config,
            signal_received: None,
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

    /// Boot the Linux kernel
    #[cfg(feature = "std")]
    pub async fn boot(&mut self) -> KernelResult<()> {
        use crate::boot::BootError;

        // Setup signal handlers
        self.setup_signals();

        // Write PID file
        if let Some(ref pid_path) = self.linux_config.pid_file {
            self.write_pid_file(pid_path)
                .map_err(|e| crate::KernelError::Boot(BootError::Config(e)))?;
        }

        // Boot the kernel
        self.kernel.boot_async().await?;

        // Notify systemd we're ready
        if self.linux_config.systemd_notify {
            self.notify_systemd("READY=1");
        }

        Ok(())
    }

    /// Run the main loop
    #[cfg(feature = "std")]
    pub async fn run(&mut self) -> KernelResult<()> {
        use tokio::time::{interval, Duration};

        let mut tick = interval(Duration::from_millis(100));

        loop {
            tick.tick().await;

            // Check for signals
            if let Some(sig) = self.signal_received.take() {
                match sig {
                    15 | 2 => {
                        // SIGTERM or SIGINT
                        self.kernel.shutdown(ShutdownReason::Signal(sig));
                    }
                    1 => {
                        // SIGHUP - reload config (TODO)
                    }
                    _ => {}
                }
            }

            // Check if shutting down
            if self.kernel.state() == crate::boot::KernelState::ShuttingDown {
                if self.kernel.shutdown_tick() {
                    break;
                }
            }
        }

        // Notify systemd we're stopping
        if self.linux_config.systemd_notify {
            self.notify_systemd("STOPPING=1");
        }

        // Clean up PID file
        if let Some(ref pid_path) = self.linux_config.pid_file {
            let _ = std::fs::remove_file(pid_path);
        }

        Ok(())
    }

    fn setup_signals(&mut self) {
        // In a real implementation, we'd use signal-hook or tokio-signal
        // For now, this is a placeholder
    }

    #[cfg(feature = "std")]
    fn write_pid_file(&self, path: &str) -> Result<(), String> {
        use std::io::Write;

        let pid = std::process::id();
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Failed to create PID file: {}", e))?;
        write!(file, "{}", pid)
            .map_err(|e| format!("Failed to write PID: {}", e))?;
        Ok(())
    }

    fn notify_systemd(&self, msg: &str) {
        // In a real implementation, we'd use the systemd notify protocol
        // For now, this is a placeholder
        let _ = msg;
    }
}

/// Systemd service configuration generator
pub struct SystemdServiceConfig {
    /// Service description
    pub description: String,
    /// Service type (notify, simple, forking)
    pub service_type: String,
    /// Executable path
    pub exec_start: String,
    /// Arguments
    pub exec_args: Vec<String>,
    /// Restart policy
    pub restart: String,
    /// Restart delay
    pub restart_sec: u32,
    /// User to run as
    pub user: Option<String>,
    /// Group to run as
    pub group: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// Environment variables
    pub environment: Vec<(String, String)>,
    /// Dependencies (After=)
    pub after: Vec<String>,
    /// Wanted by
    pub wanted_by: Vec<String>,
}

impl Default for SystemdServiceConfig {
    fn default() -> Self {
        Self {
            description: String::from("AXIOM AI-Native Operating System"),
            service_type: String::from("notify"),
            exec_start: String::from("/usr/bin/axiom"),
            exec_args: Vec::new(),
            restart: String::from("on-failure"),
            restart_sec: 5,
            user: Some(String::from("axiom")),
            group: Some(String::from("axiom")),
            working_directory: Some(String::from("/var/lib/axiom")),
            environment: Vec::new(),
            after: vec![
                String::from("network.target"),
                String::from("network-online.target"),
            ],
            wanted_by: vec![String::from("multi-user.target")],
        }
    }
}

impl SystemdServiceConfig {
    /// Generate the systemd unit file content
    pub fn generate(&self) -> String {
        let mut output = String::new();

        // [Unit] section
        output.push_str("[Unit]\n");
        output.push_str(&format!("Description={}\n", self.description));
        for dep in &self.after {
            output.push_str(&format!("After={}\n", dep));
        }
        output.push('\n');

        // [Service] section
        output.push_str("[Service]\n");
        output.push_str(&format!("Type={}\n", self.service_type));

        let mut exec = self.exec_start.clone();
        for arg in &self.exec_args {
            exec.push(' ');
            exec.push_str(arg);
        }
        output.push_str(&format!("ExecStart={}\n", exec));

        output.push_str(&format!("Restart={}\n", self.restart));
        output.push_str(&format!("RestartSec={}\n", self.restart_sec));

        if let Some(ref user) = self.user {
            output.push_str(&format!("User={}\n", user));
        }
        if let Some(ref group) = self.group {
            output.push_str(&format!("Group={}\n", group));
        }
        if let Some(ref dir) = self.working_directory {
            output.push_str(&format!("WorkingDirectory={}\n", dir));
        }

        for (key, value) in &self.environment {
            output.push_str(&format!("Environment=\"{}={}\"\n", key, value));
        }
        output.push('\n');

        // [Install] section
        output.push_str("[Install]\n");
        for target in &self.wanted_by {
            output.push_str(&format!("WantedBy={}\n", target));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_config_default() {
        let config = LinuxConfig::default();
        assert_eq!(config.control_socket, "/run/axiom/control.sock");
        assert!(config.systemd_notify);
        assert!(!config.daemonize);
    }

    #[test]
    fn test_systemd_service_generate() {
        let config = SystemdServiceConfig::default();
        let unit = config.generate();

        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("AXIOM AI-Native Operating System"));
    }

    #[test]
    fn test_systemd_custom_config() {
        let mut config = SystemdServiceConfig::default();
        config.description = String::from("Custom AXIOM Instance");
        config.exec_args = vec![
            String::from("--config"),
            String::from("/etc/axiom/config.toml"),
        ];
        config.environment = vec![
            (String::from("RUST_LOG"), String::from("info")),
        ];

        let unit = config.generate();
        assert!(unit.contains("Custom AXIOM Instance"));
        assert!(unit.contains("--config /etc/axiom/config.toml"));
        assert!(unit.contains("Environment=\"RUST_LOG=info\""));
    }
}
