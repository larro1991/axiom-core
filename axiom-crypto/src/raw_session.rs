//! RAW (Real-time Authenticated Workflow) Session Binding
//!
//! Implements continuous session verification for Level 3 trust (RAW mode).
//! This prevents session hijacking by requiring cryptographic heartbeats.
//!
//! # Security Model
//!
//! - Sessions bound to cryptographic proof-of-continuity
//! - Rolling keys prevent replay attacks
//! - Missed heartbeats trigger immediate downgrade
//! - Sequence numbers prevent reordering attacks
//!
//! # Protocol
//!
//! ```text
//! Node A ←→ Node B (RAW session established)
//!
//! Every heartbeat_interval_ms:
//!   A → B: Heartbeat(seq, timestamp, HMAC(session_key, seq || timestamp))
//!   B → A: HeartbeatAck(seq, HMAC(session_key, "ACK" || seq))
//!
//! If heartbeat missed:
//!   - Grace period (1-2 intervals)
//!   - Then automatic downgrade to Level 2
//! ```

use alloc::vec::Vec;
use alloc::collections::BTreeMap;

/// RAW session state
#[derive(Debug, Clone)]
pub struct RawSession {
    /// Session identifier
    pub session_id: [u8; 32],
    /// Peer node ID
    pub peer_id: [u8; 32],
    /// Current session key (rotates)
    session_key: [u8; 32],
    /// Previous session key (for in-flight messages)
    prev_session_key: Option<[u8; 32]>,
    /// Current sequence number (monotonic)
    sequence: u64,
    /// Last received sequence from peer
    peer_sequence: u64,
    /// Session established timestamp
    established_at_ms: u64,
    /// Last heartbeat sent timestamp
    last_heartbeat_sent_ms: u64,
    /// Last heartbeat received timestamp
    last_heartbeat_received_ms: u64,
    /// Missed heartbeat count
    missed_heartbeats: u32,
    /// Session state
    state: RawSessionState,
    /// Configuration
    config: RawSessionConfig,
    /// Last key rotation timestamp (for rate limiting)
    last_rotation_time_ms: u64,
    /// Total rotation count (for session lifetime limit)
    rotation_count: u32,
}

/// RAW session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSessionState {
    /// Session is active and healthy
    Active,
    /// Missed heartbeat, in grace period
    Degraded,
    /// Session terminated (must re-establish)
    Terminated,
}

/// RAW session configuration
#[derive(Debug, Clone)]
pub struct RawSessionConfig {
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    /// Grace period (number of missed heartbeats before termination)
    pub grace_heartbeats: u32,
    /// Key rotation interval (number of heartbeats)
    pub key_rotation_interval: u32,
    /// Maximum clock skew tolerance (ms)
    pub max_clock_skew_ms: u64,
    /// Sequence window for replay protection
    pub sequence_window: u64,
    /// Minimum interval between key rotations (ms) - prevents entropy exhaustion attacks
    pub min_rotation_interval_ms: u64,
    /// Maximum rotations per session - prevents DoS via rotation spam
    pub max_rotations_per_session: u32,
}

impl Default for RawSessionConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 1000,    // 1 second
            grace_heartbeats: 3,            // 3 missed = terminate
            key_rotation_interval: 60,      // Rotate every 60 heartbeats
            max_clock_skew_ms: 5000,        // 5 second tolerance
            sequence_window: 100,           // Accept seq within window
            min_rotation_interval_ms: 60_000, // 1 minute minimum between rotations
            max_rotations_per_session: 1000,  // Max 1000 rotations per session lifetime
        }
    }
}

/// Heartbeat message
#[derive(Debug, Clone)]
pub struct Heartbeat {
    /// Session ID
    pub session_id: [u8; 32],
    /// Sequence number
    pub sequence: u64,
    /// Timestamp (ms since epoch)
    pub timestamp_ms: u64,
    /// HMAC over (session_id || sequence || timestamp)
    pub hmac: [u8; 32],
    /// Key rotation flag (if true, contains new key material)
    pub key_rotation: Option<KeyRotation>,
}

/// Key rotation payload
#[derive(Debug, Clone)]
pub struct KeyRotation {
    /// New key contribution from sender
    pub key_contribution: [u8; 32],
    /// HMAC over key_contribution with current key
    pub contribution_hmac: [u8; 32],
}

/// Heartbeat acknowledgment
#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatAck {
    /// Session ID
    pub session_id: [u8; 32],
    /// Acknowledged sequence number
    pub ack_sequence: u64,
    /// HMAC over (session_id || "ACK" || ack_sequence)
    pub hmac: [u8; 32],
}

/// RAW session errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSessionError {
    /// Invalid HMAC
    InvalidHmac,
    /// Sequence number out of window
    SequenceOutOfWindow,
    /// Replay detected (sequence already seen)
    ReplayDetected,
    /// Timestamp out of tolerance
    TimestampOutOfRange,
    /// Session not found
    SessionNotFound,
    /// Session terminated
    SessionTerminated,
    /// Key rotation failed
    KeyRotationFailed,
    /// Key rotation attempted too frequently
    RotationTooFrequent,
    /// Maximum rotation limit exceeded for session
    RotationLimitExceeded,
}

impl core::fmt::Display for RawSessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidHmac => write!(f, "Invalid HMAC"),
            Self::SequenceOutOfWindow => write!(f, "Sequence number out of window"),
            Self::ReplayDetected => write!(f, "Replay attack detected"),
            Self::TimestampOutOfRange => write!(f, "Timestamp out of tolerance"),
            Self::SessionNotFound => write!(f, "Session not found"),
            Self::SessionTerminated => write!(f, "Session terminated"),
            Self::KeyRotationFailed => write!(f, "Key rotation failed"),
            Self::RotationTooFrequent => write!(f, "Key rotation attempted too frequently"),
            Self::RotationLimitExceeded => write!(f, "Maximum rotation limit exceeded"),
        }
    }
}

impl RawSession {
    /// Create new RAW session
    pub fn new(
        session_id: [u8; 32],
        peer_id: [u8; 32],
        initial_key: [u8; 32],
        current_time_ms: u64,
        config: RawSessionConfig,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            session_key: initial_key,
            prev_session_key: None,
            sequence: 0,
            peer_sequence: 0,
            established_at_ms: current_time_ms,
            last_heartbeat_sent_ms: current_time_ms,
            last_heartbeat_received_ms: current_time_ms,
            missed_heartbeats: 0,
            state: RawSessionState::Active,
            config,
            last_rotation_time_ms: 0,
            rotation_count: 0,
        }
    }

    /// Get session state
    pub fn state(&self) -> RawSessionState {
        self.state
    }

    /// Check if session is healthy
    pub fn is_active(&self) -> bool {
        self.state == RawSessionState::Active
    }

    /// Create heartbeat message
    pub fn create_heartbeat(&mut self, current_time_ms: u64) -> Heartbeat {
        self.sequence += 1;
        self.last_heartbeat_sent_ms = current_time_ms;

        let hmac = self.compute_heartbeat_hmac(self.sequence, current_time_ms);

        // Check if key rotation needed
        let key_rotation = if self.sequence % self.config.key_rotation_interval as u64 == 0 {
            Some(self.create_key_rotation())
        } else {
            None
        };

        Heartbeat {
            session_id: self.session_id,
            sequence: self.sequence,
            timestamp_ms: current_time_ms,
            hmac,
            key_rotation,
        }
    }

    /// Process received heartbeat
    pub fn process_heartbeat(
        &mut self,
        heartbeat: &Heartbeat,
        current_time_ms: u64,
    ) -> Result<HeartbeatAck, RawSessionError> {
        // Check session ID
        if heartbeat.session_id != self.session_id {
            return Err(RawSessionError::SessionNotFound);
        }

        // Check session state
        if self.state == RawSessionState::Terminated {
            return Err(RawSessionError::SessionTerminated);
        }

        // Verify timestamp within tolerance
        let time_diff = if heartbeat.timestamp_ms > current_time_ms {
            heartbeat.timestamp_ms - current_time_ms
        } else {
            current_time_ms - heartbeat.timestamp_ms
        };

        if time_diff > self.config.max_clock_skew_ms {
            return Err(RawSessionError::TimestampOutOfRange);
        }

        // Check sequence number
        if heartbeat.sequence <= self.peer_sequence {
            return Err(RawSessionError::ReplayDetected);
        }

        if heartbeat.sequence > self.peer_sequence + self.config.sequence_window {
            return Err(RawSessionError::SequenceOutOfWindow);
        }

        // Verify HMAC (try current key, then previous if rotation in progress)
        let expected_hmac = self.compute_heartbeat_hmac_with_key(
            &self.session_key,
            heartbeat.sequence,
            heartbeat.timestamp_ms,
        );

        let hmac_valid = heartbeat.hmac == expected_hmac
            || self.prev_session_key.map_or(false, |prev_key| {
                heartbeat.hmac == self.compute_heartbeat_hmac_with_key(
                    &prev_key,
                    heartbeat.sequence,
                    heartbeat.timestamp_ms,
                )
            });

        if !hmac_valid {
            return Err(RawSessionError::InvalidHmac);
        }

        // Process key rotation if present
        if let Some(ref rotation) = heartbeat.key_rotation {
            self.process_key_rotation(rotation, current_time_ms)?;
        }

        // Update state
        self.peer_sequence = heartbeat.sequence;
        self.last_heartbeat_received_ms = current_time_ms;
        self.missed_heartbeats = 0;
        self.state = RawSessionState::Active;

        // Create acknowledgment
        Ok(self.create_ack(heartbeat.sequence))
    }

    /// Create heartbeat acknowledgment
    fn create_ack(&self, ack_sequence: u64) -> HeartbeatAck {
        let hmac = self.compute_ack_hmac(ack_sequence);

        HeartbeatAck {
            session_id: self.session_id,
            ack_sequence,
            hmac,
        }
    }

    /// Process heartbeat acknowledgment
    pub fn process_ack(&mut self, ack: &HeartbeatAck) -> Result<(), RawSessionError> {
        // Verify session ID
        if ack.session_id != self.session_id {
            return Err(RawSessionError::SessionNotFound);
        }

        // Verify HMAC
        let expected_hmac = self.compute_ack_hmac(ack.ack_sequence);
        if ack.hmac != expected_hmac {
            // Try with previous key
            if let Some(prev_key) = self.prev_session_key {
                let prev_expected = self.compute_ack_hmac_with_key(&prev_key, ack.ack_sequence);
                if ack.hmac != prev_expected {
                    return Err(RawSessionError::InvalidHmac);
                }
            } else {
                return Err(RawSessionError::InvalidHmac);
            }
        }

        Ok(())
    }

    /// Check for missed heartbeats and update state
    pub fn check_heartbeat_timeout(&mut self, current_time_ms: u64) -> bool {
        let time_since_last = current_time_ms.saturating_sub(self.last_heartbeat_received_ms);
        let expected_heartbeats = time_since_last / self.config.heartbeat_interval_ms;

        if expected_heartbeats > 1 {
            self.missed_heartbeats = (expected_heartbeats - 1) as u32;

            if self.missed_heartbeats >= self.config.grace_heartbeats {
                self.state = RawSessionState::Terminated;
                return true; // Session terminated
            } else if self.missed_heartbeats > 0 {
                self.state = RawSessionState::Degraded;
            }
        }

        false // Session still valid
    }

    /// Create key rotation payload
    fn create_key_rotation(&self) -> KeyRotation {
        // Generate random key contribution
        let mut key_contribution = [0u8; 32];
        #[cfg(feature = "std")]
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key_contribution);
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std, would use hardware RNG
            key_contribution = [0x42u8; 32]; // Placeholder
        }

        let contribution_hmac = self.hmac(&key_contribution);

        KeyRotation {
            key_contribution,
            contribution_hmac,
        }
    }

    /// Process incoming key rotation with rate limiting
    fn process_key_rotation(&mut self, rotation: &KeyRotation, current_time_ms: u64) -> Result<(), RawSessionError> {
        // Check rotation rate limit
        if self.last_rotation_time_ms > 0 {
            let time_since_last = current_time_ms.saturating_sub(self.last_rotation_time_ms);
            if time_since_last < self.config.min_rotation_interval_ms {
                return Err(RawSessionError::RotationTooFrequent);
            }
        }

        // Check session lifetime rotation limit
        if self.rotation_count >= self.config.max_rotations_per_session {
            return Err(RawSessionError::RotationLimitExceeded);
        }

        // Verify contribution HMAC
        let expected_hmac = self.hmac(&rotation.key_contribution);
        if rotation.contribution_hmac != expected_hmac {
            return Err(RawSessionError::KeyRotationFailed);
        }

        // Derive new key: BLAKE3(current_key || their_contribution || our_contribution)
        let mut new_key = [0u8; 32];
        {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&self.session_key);
            hasher.update(&rotation.key_contribution);
            // Add our entropy
            hasher.update(&self.sequence.to_le_bytes());
            let hash = hasher.finalize();
            new_key.copy_from_slice(hash.as_bytes());
        }

        // Rotate keys
        self.prev_session_key = Some(self.session_key);
        self.session_key = new_key;

        // Update rotation tracking
        self.last_rotation_time_ms = current_time_ms;
        self.rotation_count += 1;

        Ok(())
    }

    /// Compute HMAC for heartbeat
    fn compute_heartbeat_hmac(&self, sequence: u64, timestamp_ms: u64) -> [u8; 32] {
        self.compute_heartbeat_hmac_with_key(&self.session_key, sequence, timestamp_ms)
    }

    fn compute_heartbeat_hmac_with_key(
        &self,
        key: &[u8; 32],
        sequence: u64,
        timestamp_ms: u64,
    ) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new_keyed(key);
        hasher.update(&self.session_id);
        hasher.update(&sequence.to_le_bytes());
        hasher.update(&timestamp_ms.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Compute HMAC for acknowledgment
    fn compute_ack_hmac(&self, ack_sequence: u64) -> [u8; 32] {
        self.compute_ack_hmac_with_key(&self.session_key, ack_sequence)
    }

    fn compute_ack_hmac_with_key(&self, key: &[u8; 32], ack_sequence: u64) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new_keyed(key);
        hasher.update(&self.session_id);
        hasher.update(b"ACK");
        hasher.update(&ack_sequence.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Generic HMAC with session key
    fn hmac(&self, data: &[u8]) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new_keyed(&self.session_key);
        hasher.update(data);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Get session key (for authorized operations only)
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Get time since last heartbeat
    pub fn time_since_last_heartbeat(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_heartbeat_received_ms)
    }

    /// Get missed heartbeat count
    pub fn missed_heartbeats(&self) -> u32 {
        self.missed_heartbeats
    }
}

/// RAW Session Manager - handles multiple sessions
pub struct RawSessionManager {
    /// Active sessions by session ID
    sessions: BTreeMap<[u8; 32], RawSession>,
    /// Sessions by peer ID (for lookup)
    peer_sessions: BTreeMap<[u8; 32], [u8; 32]>,
    /// Our node ID
    local_id: [u8; 32],
    /// Default configuration
    default_config: RawSessionConfig,
}

impl RawSessionManager {
    /// Create new session manager
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            sessions: BTreeMap::new(),
            peer_sessions: BTreeMap::new(),
            local_id,
            default_config: RawSessionConfig::default(),
        }
    }

    /// Establish new RAW session with peer
    pub fn establish_session(
        &mut self,
        peer_id: [u8; 32],
        shared_secret: [u8; 32],
        current_time_ms: u64,
    ) -> [u8; 32] {
        // Derive session ID from shared secret and node IDs
        let session_id = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&shared_secret);
            hasher.update(&self.local_id);
            hasher.update(&peer_id);
            hasher.update(b"RAW_SESSION_ID");
            let hash = hasher.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(hash.as_bytes());
            id
        };

        // Derive initial session key
        let initial_key = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&shared_secret);
            hasher.update(&session_id);
            hasher.update(b"RAW_SESSION_KEY");
            let hash = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(hash.as_bytes());
            key
        };

        let session = RawSession::new(
            session_id,
            peer_id,
            initial_key,
            current_time_ms,
            self.default_config.clone(),
        );

        self.sessions.insert(session_id, session);
        self.peer_sessions.insert(peer_id, session_id);

        session_id
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&RawSession> {
        self.sessions.get(session_id)
    }

    /// Get mutable session by ID
    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut RawSession> {
        self.sessions.get_mut(session_id)
    }

    /// Get session for peer
    pub fn get_session_for_peer(&self, peer_id: &[u8; 32]) -> Option<&RawSession> {
        self.peer_sessions
            .get(peer_id)
            .and_then(|sid| self.sessions.get(sid))
    }

    /// Terminate session
    pub fn terminate_session(&mut self, session_id: &[u8; 32]) {
        if let Some(session) = self.sessions.remove(session_id) {
            self.peer_sessions.remove(&session.peer_id);
        }
    }

    /// Check all sessions for timeouts
    pub fn check_timeouts(&mut self, current_time_ms: u64) -> Vec<[u8; 32]> {
        let mut terminated = Vec::new();

        for (session_id, session) in self.sessions.iter_mut() {
            if session.check_heartbeat_timeout(current_time_ms) {
                terminated.push(*session_id);
            }
        }

        // Remove terminated sessions
        for session_id in &terminated {
            self.terminate_session(session_id);
        }

        terminated
    }

    /// Get sessions needing heartbeat
    pub fn sessions_needing_heartbeat(&self, current_time_ms: u64) -> Vec<[u8; 32]> {
        self.sessions
            .iter()
            .filter(|(_, s)| {
                s.is_active()
                    && current_time_ms - s.last_heartbeat_sent_ms >= s.config.heartbeat_interval_ms
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Count active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_active()).count()
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig::default(),
        );

        assert!(session.is_active());
        assert_eq!(session.state(), RawSessionState::Active);
        assert_eq!(session.missed_heartbeats(), 0);
    }

    #[test]
    fn test_heartbeat_roundtrip() {
        let mut session_a = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig::default(),
        );

        let mut session_b = RawSession::new(
            [0xAA; 32],
            [0x11; 32], // Different peer ID but same session
            [0xCC; 32], // Same key
            1000,
            RawSessionConfig::default(),
        );

        // A sends heartbeat
        let heartbeat = session_a.create_heartbeat(2000);
        assert_eq!(heartbeat.sequence, 1);

        // B processes heartbeat
        let ack = session_b.process_heartbeat(&heartbeat, 2000).unwrap();
        assert_eq!(ack.ack_sequence, 1);

        // A processes ack
        session_a.process_ack(&ack).unwrap();
    }

    #[test]
    fn test_replay_detection() {
        let mut session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig::default(),
        );

        // First heartbeat
        let heartbeat = Heartbeat {
            session_id: [0xAA; 32],
            sequence: 1,
            timestamp_ms: 2000,
            hmac: session.compute_heartbeat_hmac(1, 2000),
            key_rotation: None,
        };

        session.process_heartbeat(&heartbeat, 2000).unwrap();

        // Replay same heartbeat
        let result = session.process_heartbeat(&heartbeat, 3000);
        assert_eq!(result, Err(RawSessionError::ReplayDetected));
    }

    #[test]
    fn test_invalid_hmac() {
        let mut session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig::default(),
        );

        let heartbeat = Heartbeat {
            session_id: [0xAA; 32],
            sequence: 1,
            timestamp_ms: 2000,
            hmac: [0xFF; 32], // Invalid HMAC
            key_rotation: None,
        };

        let result = session.process_heartbeat(&heartbeat, 2000);
        assert_eq!(result, Err(RawSessionError::InvalidHmac));
    }

    #[test]
    fn test_heartbeat_timeout() {
        let mut session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig {
                heartbeat_interval_ms: 1000,
                grace_heartbeats: 3,
                ..Default::default()
            },
        );

        // No timeout yet
        assert!(!session.check_heartbeat_timeout(2000));
        assert_eq!(session.state(), RawSessionState::Active);

        // 2 missed heartbeats - degraded
        assert!(!session.check_heartbeat_timeout(4000));
        assert_eq!(session.state(), RawSessionState::Degraded);

        // 4 missed heartbeats - terminated
        assert!(session.check_heartbeat_timeout(6000));
        assert_eq!(session.state(), RawSessionState::Terminated);
    }

    #[test]
    fn test_session_manager() {
        let mut manager = RawSessionManager::new([0x11; 32]);

        let session_id = manager.establish_session([0x22; 32], [0x33; 32], 1000);

        assert!(manager.get_session(&session_id).is_some());
        assert!(manager.get_session_for_peer(&[0x22; 32]).is_some());
        assert_eq!(manager.active_session_count(), 1);

        manager.terminate_session(&session_id);
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_timestamp_tolerance() {
        let mut session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig {
                max_clock_skew_ms: 5000,
                ..Default::default()
            },
        );

        // Timestamp too far in future
        let heartbeat = Heartbeat {
            session_id: [0xAA; 32],
            sequence: 1,
            timestamp_ms: 20000, // Way in future
            hmac: session.compute_heartbeat_hmac(1, 20000),
            key_rotation: None,
        };

        let result = session.process_heartbeat(&heartbeat, 2000);
        assert_eq!(result, Err(RawSessionError::TimestampOutOfRange));
    }

    #[test]
    fn test_rotation_rate_limiting() {
        let mut session = RawSession::new(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1000,
            RawSessionConfig {
                min_rotation_interval_ms: 60_000, // 1 minute minimum
                max_rotations_per_session: 3,
                ..Default::default()
            },
        );

        let rotation = KeyRotation {
            key_contribution: [0x11; 32],
            contribution_hmac: session.hmac(&[0x11; 32]),
        };

        // First rotation should succeed
        assert!(session.process_key_rotation(&rotation, 2000).is_ok());
        assert_eq!(session.rotation_count, 1);

        // Second rotation too soon should fail
        let result = session.process_key_rotation(&rotation, 3000);
        assert_eq!(result, Err(RawSessionError::RotationTooFrequent));

        // After waiting, rotation should succeed
        let rotation2 = KeyRotation {
            key_contribution: [0x22; 32],
            contribution_hmac: session.hmac(&[0x22; 32]),
        };
        assert!(session.process_key_rotation(&rotation2, 70_000).is_ok());
        assert_eq!(session.rotation_count, 2);

        // Third rotation
        let rotation3 = KeyRotation {
            key_contribution: [0x33; 32],
            contribution_hmac: session.hmac(&[0x33; 32]),
        };
        assert!(session.process_key_rotation(&rotation3, 140_000).is_ok());
        assert_eq!(session.rotation_count, 3);

        // Fourth rotation should exceed limit
        let rotation4 = KeyRotation {
            key_contribution: [0x44; 32],
            contribution_hmac: session.hmac(&[0x44; 32]),
        };
        let result = session.process_key_rotation(&rotation4, 210_000);
        assert_eq!(result, Err(RawSessionError::RotationLimitExceeded));
    }
}
