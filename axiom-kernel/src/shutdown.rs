//! Kernel Shutdown Handling
//!
//! Graceful shutdown sequence:
//! 1. Stop accepting new work
//! 2. Notify all agents
//! 3. Checkpoint agent state
//! 4. Wait for agents to terminate
//! 5. Release resources
//! 6. Close network connections

use alloc::string::String;

/// Reason for shutdown
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownReason {
    /// User requested shutdown
    UserRequest,
    /// Signal received (SIGTERM, SIGINT)
    Signal(i32),
    /// Fatal error
    FatalError(String),
    /// Resource exhaustion
    ResourceExhausted,
    /// Init agent crashed
    InitCrashed,
    /// Scheduled maintenance
    Maintenance,
    /// Migration to another node
    Migration,
    /// Unknown reason
    Unknown,
}

impl ShutdownReason {
    /// Is this an error condition?
    pub fn is_error(&self) -> bool {
        matches!(self,
            ShutdownReason::FatalError(_) |
            ShutdownReason::ResourceExhausted |
            ShutdownReason::InitCrashed
        )
    }

    /// Should we checkpoint before shutdown?
    pub fn should_checkpoint(&self) -> bool {
        !matches!(self, ShutdownReason::FatalError(_))
    }

    /// Should we notify peers?
    pub fn should_notify_peers(&self) -> bool {
        matches!(self,
            ShutdownReason::UserRequest |
            ShutdownReason::Maintenance |
            ShutdownReason::Migration
        )
    }
}

impl core::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShutdownReason::UserRequest => write!(f, "user request"),
            ShutdownReason::Signal(sig) => write!(f, "signal {}", sig),
            ShutdownReason::FatalError(e) => write!(f, "fatal error: {}", e),
            ShutdownReason::ResourceExhausted => write!(f, "resource exhausted"),
            ShutdownReason::InitCrashed => write!(f, "init agent crashed"),
            ShutdownReason::Maintenance => write!(f, "scheduled maintenance"),
            ShutdownReason::Migration => write!(f, "migration"),
            ShutdownReason::Unknown => write!(f, "unknown"),
        }
    }
}

/// Shutdown progress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Not shutting down
    None,
    /// Stop accepting new work
    StopAccepting,
    /// Notifying agents
    NotifyingAgents,
    /// Checkpointing state
    Checkpointing,
    /// Waiting for agents to terminate
    WaitingAgents,
    /// Releasing resources
    ReleasingResources,
    /// Closing network
    ClosingNetwork,
    /// Complete
    Complete,
}

/// Shutdown coordinator
pub struct ShutdownCoordinator {
    reason: Option<ShutdownReason>,
    phase: ShutdownPhase,
    agents_remaining: usize,
    checkpoint_complete: bool,
    network_closed: bool,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        Self {
            reason: None,
            phase: ShutdownPhase::None,
            agents_remaining: 0,
            checkpoint_complete: false,
            network_closed: false,
        }
    }

    /// Start shutdown
    pub fn start(&mut self, reason: ShutdownReason, agent_count: usize) {
        self.reason = Some(reason);
        self.phase = ShutdownPhase::StopAccepting;
        self.agents_remaining = agent_count;
    }

    /// Get current phase
    pub fn phase(&self) -> ShutdownPhase {
        self.phase
    }

    /// Get shutdown reason
    pub fn reason(&self) -> Option<&ShutdownReason> {
        self.reason.as_ref()
    }

    /// Advance to next phase
    pub fn advance(&mut self) {
        self.phase = match self.phase {
            ShutdownPhase::None => ShutdownPhase::None,
            ShutdownPhase::StopAccepting => ShutdownPhase::NotifyingAgents,
            ShutdownPhase::NotifyingAgents => ShutdownPhase::Checkpointing,
            ShutdownPhase::Checkpointing => ShutdownPhase::WaitingAgents,
            ShutdownPhase::WaitingAgents => ShutdownPhase::ReleasingResources,
            ShutdownPhase::ReleasingResources => ShutdownPhase::ClosingNetwork,
            ShutdownPhase::ClosingNetwork => ShutdownPhase::Complete,
            ShutdownPhase::Complete => ShutdownPhase::Complete,
        };
    }

    /// Mark an agent as terminated
    pub fn agent_terminated(&mut self) {
        if self.agents_remaining > 0 {
            self.agents_remaining -= 1;
        }
    }

    /// All agents terminated?
    pub fn all_agents_terminated(&self) -> bool {
        self.agents_remaining == 0
    }

    /// Mark checkpoint complete
    pub fn checkpoint_done(&mut self) {
        self.checkpoint_complete = true;
    }

    /// Mark network closed
    pub fn network_done(&mut self) {
        self.network_closed = true;
    }

    /// Is shutdown complete?
    pub fn is_complete(&self) -> bool {
        self.phase == ShutdownPhase::Complete
    }

    /// Can we skip checkpointing?
    pub fn skip_checkpoint(&self) -> bool {
        self.reason.as_ref()
            .map(|r| !r.should_checkpoint())
            .unwrap_or(false)
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_reason_display() {
        assert_eq!(ShutdownReason::UserRequest.to_string(), "user request");
        assert_eq!(ShutdownReason::Signal(15).to_string(), "signal 15");
        assert_eq!(
            ShutdownReason::FatalError("oops".into()).to_string(),
            "fatal error: oops"
        );
    }

    #[test]
    fn test_shutdown_reason_properties() {
        assert!(!ShutdownReason::UserRequest.is_error());
        assert!(ShutdownReason::FatalError("x".into()).is_error());

        assert!(ShutdownReason::UserRequest.should_checkpoint());
        assert!(!ShutdownReason::FatalError("x".into()).should_checkpoint());

        assert!(ShutdownReason::Maintenance.should_notify_peers());
        assert!(!ShutdownReason::FatalError("x".into()).should_notify_peers());
    }

    #[test]
    fn test_shutdown_coordinator() {
        let mut coord = ShutdownCoordinator::new();
        assert_eq!(coord.phase(), ShutdownPhase::None);

        coord.start(ShutdownReason::UserRequest, 5);
        assert_eq!(coord.phase(), ShutdownPhase::StopAccepting);
        assert_eq!(coord.agents_remaining, 5);

        coord.advance();
        assert_eq!(coord.phase(), ShutdownPhase::NotifyingAgents);

        coord.advance();
        assert_eq!(coord.phase(), ShutdownPhase::Checkpointing);

        coord.advance();
        assert_eq!(coord.phase(), ShutdownPhase::WaitingAgents);

        for _ in 0..5 {
            coord.agent_terminated();
        }
        assert!(coord.all_agents_terminated());
    }

    #[test]
    fn test_shutdown_phases() {
        let mut coord = ShutdownCoordinator::new();
        coord.start(ShutdownReason::Maintenance, 0);

        // Advance through all phases
        while coord.phase() != ShutdownPhase::Complete {
            coord.advance();
        }

        assert!(coord.is_complete());
    }
}
