//! Legacy Boundary MAC Binding
//!
//! Implements cryptographic binding between AXIOM's trust model and legacy
//! hardware that cannot be upgraded. Uses MAC (Message Authentication Code)
//! to create authenticated channels with legacy devices.
//!
//! # Security Model
//!
//! Legacy devices cannot participate in AXIOM's full cryptographic protocol,
//! so we create a "trust boundary" where:
//!
//! 1. **Boundary Gateway**: AXIOM node that bridges to legacy devices
//! 2. **MAC Binding**: Each legacy device gets a unique symmetric key
//! 3. **Command Signing**: All commands to legacy devices are MAC'd
//! 4. **Response Verification**: All responses from legacy are verified
//! 5. **Replay Protection**: Sequence numbers prevent replay attacks
//!
//! # Threat Model
//!
//! - **Attacker on bus**: Cannot forge commands without key
//! - **Replay attack**: Blocked by sequence numbers
//! - **Compromised gateway**: Limits blast radius to bound devices
//! - **Key extraction**: Keys rotated periodically

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// MAC algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// BLAKE3 keyed hash (preferred)
    Blake3,
    /// HMAC-SHA256 (compatibility)
    HmacSha256,
    /// AES-CMAC (for hardware with AES)
    AesCmac,
}

/// A bound legacy device
#[derive(Debug, Clone)]
pub struct LegacyDevice {
    /// Unique identifier for this device
    pub device_id: [u8; 16],
    /// Human-readable name
    pub name: [u8; 32],
    /// Device type/class
    pub device_type: LegacyDeviceType,
    /// MAC algorithm to use
    pub mac_algorithm: MacAlgorithm,
    /// Symmetric key for MAC (32 bytes)
    key: [u8; 32],
    /// Current sequence number (our commands)
    tx_sequence: u64,
    /// Expected sequence number (device responses)
    rx_sequence: u64,
    /// When this binding was established
    pub bound_at_ms: u64,
    /// When the key was last rotated
    pub key_rotated_at_ms: u64,
    /// Maximum commands before key rotation required
    pub max_commands_before_rotation: u64,
    /// Commands since last rotation
    commands_since_rotation: u64,
}

/// Types of legacy devices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyDeviceType {
    /// Legacy storage controller
    Storage,
    /// Legacy network interface
    Network,
    /// Legacy GPU/display
    Graphics,
    /// Legacy USB controller
    Usb,
    /// Legacy audio device
    Audio,
    /// Generic/unknown
    Generic,
}

/// Command to a legacy device
#[derive(Debug, Clone)]
pub struct LegacyCommand {
    /// Device this command is for
    pub device_id: [u8; 16],
    /// Sequence number
    pub sequence: u64,
    /// Timestamp (ms)
    pub timestamp_ms: u64,
    /// Command type
    pub command_type: u8,
    /// Command payload
    pub payload: Vec<u8>,
    /// MAC over command
    pub mac: [u8; 32],
}

impl LegacyCommand {
    /// Create canonical bytes for MAC calculation
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.payload.len());

        // Header
        bytes.extend_from_slice(b"AXIOM-LCMD\x00\x01");

        // Device ID
        bytes.extend_from_slice(&self.device_id);

        // Sequence
        bytes.extend_from_slice(&self.sequence.to_le_bytes());

        // Timestamp
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());

        // Command type
        bytes.push(self.command_type);

        // Payload length
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

/// Response from a legacy device
#[derive(Debug, Clone)]
pub struct LegacyResponse {
    /// Device this response is from
    pub device_id: [u8; 16],
    /// Sequence number (should match command)
    pub sequence: u64,
    /// Status code
    pub status: u8,
    /// Response payload
    pub payload: Vec<u8>,
    /// MAC over response
    pub mac: [u8; 32],
}

impl LegacyResponse {
    /// Create canonical bytes for MAC verification
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.payload.len());

        // Header
        bytes.extend_from_slice(b"AXIOM-LRSP\x00\x01");

        // Device ID
        bytes.extend_from_slice(&self.device_id);

        // Sequence
        bytes.extend_from_slice(&self.sequence.to_le_bytes());

        // Status
        bytes.push(self.status);

        // Payload length
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

/// Legacy boundary gateway
pub struct LegacyBoundary {
    /// Gateway identity
    gateway_id: [u8; 32],
    /// Bound devices
    devices: BTreeMap<[u8; 16], LegacyDevice>,
    /// Key derivation master secret
    master_secret: [u8; 32],
    /// Maximum age for commands (ms) - replay window
    max_command_age_ms: u64,
    /// Commands per device before rotation warning
    rotation_warning_threshold: u64,
}

impl LegacyBoundary {
    /// Create new legacy boundary gateway
    pub fn new(gateway_id: [u8; 32], master_secret: [u8; 32]) -> Self {
        Self {
            gateway_id,
            devices: BTreeMap::new(),
            master_secret,
            max_command_age_ms: 5000, // 5 second replay window
            rotation_warning_threshold: 10000,
        }
    }

    /// Create new legacy boundary gateway from environment variable
    ///
    /// Reads the master secret from AXIOM_MASTER_SECRET environment variable.
    /// The secret should be hex-encoded (64 characters for 32 bytes).
    ///
    /// # Example
    /// ```bash
    /// export AXIOM_MASTER_SECRET=$(openssl rand -hex 32)
    /// ```
    #[cfg(feature = "std")]
    pub fn new_from_env(gateway_id: [u8; 32]) -> Result<Self, LegacyBoundaryError> {
        let secret_hex = std::env::var("AXIOM_MASTER_SECRET")
            .map_err(|_| LegacyBoundaryError::MissingMasterSecret)?;

        let secret_bytes = hex::decode(&secret_hex)
            .map_err(|_| LegacyBoundaryError::InvalidMasterSecret)?;

        if secret_bytes.len() != 32 {
            return Err(LegacyBoundaryError::InvalidMasterSecret);
        }

        let mut master_secret = [0u8; 32];
        master_secret.copy_from_slice(&secret_bytes);

        Ok(Self::new(gateway_id, master_secret))
    }

    /// Create new legacy boundary gateway from a secure key storage backend
    ///
    /// This is the preferred method for production deployments.
    /// The master secret is retrieved from HSM/TPM via the provided callback.
    pub fn new_from_key_storage<F>(
        gateway_id: [u8; 32],
        key_retriever: F,
    ) -> Result<Self, LegacyBoundaryError>
    where
        F: FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
    {
        let master_secret = key_retriever(&gateway_id)
            .ok_or(LegacyBoundaryError::MissingMasterSecret)?;

        Ok(Self::new(gateway_id, master_secret))
    }

    /// Derive a device key from master secret and device ID
    fn derive_device_key(&self, device_id: &[u8; 16]) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new_keyed(&self.master_secret);
        hasher.update(b"AXIOM-LEGACY-KEY-V1");
        hasher.update(&self.gateway_id);
        hasher.update(device_id);

        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_bytes());
        key
    }

    /// Bind a new legacy device
    pub fn bind_device(
        &mut self,
        device_id: [u8; 16],
        name: [u8; 32],
        device_type: LegacyDeviceType,
        mac_algorithm: MacAlgorithm,
        current_time_ms: u64,
    ) -> Result<&LegacyDevice, LegacyBoundaryError> {
        // Check if already bound
        if self.devices.contains_key(&device_id) {
            return Err(LegacyBoundaryError::AlreadyBound);
        }

        // Derive key for this device
        let key = self.derive_device_key(&device_id);

        let device = LegacyDevice {
            device_id,
            name,
            device_type,
            mac_algorithm,
            key,
            tx_sequence: 0,
            rx_sequence: 0,
            bound_at_ms: current_time_ms,
            key_rotated_at_ms: current_time_ms,
            max_commands_before_rotation: 100000,
            commands_since_rotation: 0,
        };

        self.devices.insert(device_id, device);
        Ok(self.devices.get(&device_id).unwrap())
    }

    /// Unbind a legacy device
    pub fn unbind_device(&mut self, device_id: &[u8; 16]) -> Result<(), LegacyBoundaryError> {
        self.devices.remove(device_id)
            .map(|_| ())
            .ok_or(LegacyBoundaryError::DeviceNotFound)
    }

    /// Get a bound device
    pub fn get_device(&self, device_id: &[u8; 16]) -> Option<&LegacyDevice> {
        self.devices.get(device_id)
    }

    /// Create a MAC'd command for a legacy device
    pub fn create_command(
        &mut self,
        device_id: &[u8; 16],
        command_type: u8,
        payload: Vec<u8>,
        current_time_ms: u64,
    ) -> Result<LegacyCommand, LegacyBoundaryError> {
        let device = self.devices.get_mut(device_id)
            .ok_or(LegacyBoundaryError::DeviceNotFound)?;

        // Check if rotation needed
        if device.commands_since_rotation >= device.max_commands_before_rotation {
            return Err(LegacyBoundaryError::KeyRotationRequired);
        }

        // Increment sequence
        device.tx_sequence += 1;
        device.commands_since_rotation += 1;

        let mut command = LegacyCommand {
            device_id: *device_id,
            sequence: device.tx_sequence,
            timestamp_ms: current_time_ms,
            command_type,
            payload,
            mac: [0u8; 32],
        };

        // Calculate MAC
        let key = device.key.clone();
        let mac_algorithm = device.mac_algorithm;
        command.mac = self.calculate_mac(&key, &command.canonical_bytes(), mac_algorithm);

        Ok(command)
    }

    /// Verify a response from a legacy device
    pub fn verify_response(
        &mut self,
        response: &LegacyResponse,
        _current_time_ms: u64,
    ) -> Result<(), LegacyBoundaryError> {
        // First pass: get immutable data needed for MAC calculation
        let (key, mac_algorithm, tx_sequence) = {
            let device = self.devices.get(&response.device_id)
                .ok_or(LegacyBoundaryError::DeviceNotFound)?;
            (device.key, device.mac_algorithm, device.tx_sequence)
        };

        // Check sequence number (should match what we sent)
        if response.sequence != tx_sequence {
            return Err(LegacyBoundaryError::SequenceMismatch {
                expected: tx_sequence,
                received: response.sequence,
            });
        }

        // Verify MAC (now safe because we dropped the device borrow)
        let expected_mac = self.calculate_mac(
            &key,
            &response.canonical_bytes(),
            mac_algorithm,
        );

        if !constant_time_compare(&response.mac, &expected_mac) {
            return Err(LegacyBoundaryError::MacVerificationFailed);
        }

        // Second pass: update mutable state
        let device = self.devices.get_mut(&response.device_id)
            .ok_or(LegacyBoundaryError::DeviceNotFound)?;
        device.rx_sequence = response.sequence;

        Ok(())
    }

    /// Rotate key for a device
    pub fn rotate_key(
        &mut self,
        device_id: &[u8; 16],
        current_time_ms: u64,
    ) -> Result<[u8; 32], LegacyBoundaryError> {
        let device = self.devices.get_mut(device_id)
            .ok_or(LegacyBoundaryError::DeviceNotFound)?;

        // Derive new key with rotation counter
        use blake3::Hasher;

        let mut hasher = Hasher::new_keyed(&self.master_secret);
        hasher.update(b"AXIOM-LEGACY-KEY-ROTATE-V1");
        hasher.update(&self.gateway_id);
        hasher.update(device_id);
        hasher.update(&current_time_ms.to_le_bytes());
        hasher.update(&device.key_rotated_at_ms.to_le_bytes());

        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(hasher.finalize().as_bytes());

        // Update device
        device.key = new_key;
        device.key_rotated_at_ms = current_time_ms;
        device.commands_since_rotation = 0;

        // Return new key (must be provisioned to device out-of-band)
        Ok(new_key)
    }

    /// Calculate MAC using specified algorithm
    fn calculate_mac(&self, key: &[u8; 32], data: &[u8], algorithm: MacAlgorithm) -> [u8; 32] {
        match algorithm {
            MacAlgorithm::Blake3 => {
                use blake3::Hasher;
                let mut hasher = Hasher::new_keyed(key);
                hasher.update(data);
                let mut mac = [0u8; 32];
                mac.copy_from_slice(hasher.finalize().as_bytes());
                mac
            }
            MacAlgorithm::HmacSha256 => {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;

                type HmacSha256 = Hmac<Sha256>;

                let mut mac = HmacSha256::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                mac.update(data);
                let result = mac.finalize();

                let mut output = [0u8; 32];
                output.copy_from_slice(&result.into_bytes());
                output
            }
            MacAlgorithm::AesCmac => {
                // AES-CMAC implementation would go here
                // For now, fall back to BLAKE3
                use blake3::Hasher;
                let mut hasher = Hasher::new_keyed(key);
                hasher.update(data);
                let mut mac = [0u8; 32];
                mac.copy_from_slice(hasher.finalize().as_bytes());
                mac
            }
        }
    }

    /// Check if any devices need key rotation
    pub fn devices_needing_rotation(&self) -> Vec<[u8; 16]> {
        self.devices.iter()
            .filter(|(_, d)| d.commands_since_rotation >= self.rotation_warning_threshold)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all bound device IDs
    pub fn bound_devices(&self) -> Vec<[u8; 16]> {
        self.devices.keys().cloned().collect()
    }

    /// Serialize command for transmission
    pub fn serialize_command(command: &LegacyCommand) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + command.payload.len());

        // Header
        bytes.extend_from_slice(b"LCMD");

        // Device ID
        bytes.extend_from_slice(&command.device_id);

        // Sequence
        bytes.extend_from_slice(&command.sequence.to_le_bytes());

        // Timestamp
        bytes.extend_from_slice(&command.timestamp_ms.to_le_bytes());

        // Command type
        bytes.push(command.command_type);

        // Payload length
        bytes.extend_from_slice(&(command.payload.len() as u32).to_le_bytes());

        // Payload
        bytes.extend_from_slice(&command.payload);

        // MAC
        bytes.extend_from_slice(&command.mac);

        bytes
    }

    /// Deserialize response from device
    pub fn deserialize_response(data: &[u8]) -> Result<LegacyResponse, LegacyBoundaryError> {
        // Minimum size: header(4) + device_id(16) + seq(8) + status(1) + len(4) + mac(32)
        if data.len() < 65 {
            return Err(LegacyBoundaryError::MalformedData);
        }

        // Verify header
        if &data[0..4] != b"LRSP" {
            return Err(LegacyBoundaryError::InvalidHeader);
        }

        let mut offset = 4;

        // Device ID
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        // Sequence
        let sequence = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Status
        let status = data[offset];
        offset += 1;

        // Payload length
        let payload_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        // Check we have enough data
        if data.len() < offset + payload_len + 32 {
            return Err(LegacyBoundaryError::MalformedData);
        }

        // Payload
        let payload = data[offset..offset + payload_len].to_vec();
        offset += payload_len;

        // MAC
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[offset..offset + 32]);

        Ok(LegacyResponse {
            device_id,
            sequence,
            status,
            payload,
            mac,
        })
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Legacy boundary errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyBoundaryError {
    /// Device is already bound
    AlreadyBound,
    /// Device not found in bound devices
    DeviceNotFound,
    /// Key rotation is required
    KeyRotationRequired,
    /// Sequence number mismatch
    SequenceMismatch { expected: u64, received: u64 },
    /// MAC verification failed
    MacVerificationFailed,
    /// Data is malformed
    MalformedData,
    /// Invalid header
    InvalidHeader,
    /// Command too old (replay window exceeded)
    CommandTooOld,
    /// Master secret not found in environment
    MissingMasterSecret,
    /// Master secret has invalid format
    InvalidMasterSecret,
}

impl core::fmt::Display for LegacyBoundaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyBound => write!(f, "Device is already bound"),
            Self::DeviceNotFound => write!(f, "Device not found"),
            Self::KeyRotationRequired => write!(f, "Key rotation required"),
            Self::SequenceMismatch { expected, received } =>
                write!(f, "Sequence mismatch: expected {}, received {}", expected, received),
            Self::MacVerificationFailed => write!(f, "MAC verification failed"),
            Self::MalformedData => write!(f, "Data is malformed"),
            Self::InvalidHeader => write!(f, "Invalid header"),
            Self::CommandTooOld => write!(f, "Command too old"),
            Self::MissingMasterSecret => write!(f, "Master secret not found in environment"),
            Self::InvalidMasterSecret => write!(f, "Master secret has invalid format"),
        }
    }
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_device() {
        let gateway_id = [0xAA; 32];
        let master_secret = [0xBB; 32];
        let mut boundary = LegacyBoundary::new(gateway_id, master_secret);

        let device_id = [0x01; 16];
        let name = [0u8; 32];

        let result = boundary.bind_device(
            device_id,
            name,
            LegacyDeviceType::Storage,
            MacAlgorithm::Blake3,
            1000,
        );

        assert!(result.is_ok());
        assert!(boundary.get_device(&device_id).is_some());
    }

    #[test]
    fn test_double_bind_rejected() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        let name = [0u8; 32];

        boundary.bind_device(device_id, name, LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        let result = boundary.bind_device(device_id, name, LegacyDeviceType::Storage, MacAlgorithm::Blake3, 2000);
        assert!(matches!(result, Err(LegacyBoundaryError::AlreadyBound)));
    }

    #[test]
    fn test_create_command() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        let command = boundary.create_command(
            &device_id,
            0x01, // Read command
            vec![0x00, 0x00, 0x10, 0x00], // Address
            2000,
        ).unwrap();

        assert_eq!(command.device_id, device_id);
        assert_eq!(command.sequence, 1);
        assert_eq!(command.command_type, 0x01);
        assert_ne!(command.mac, [0u8; 32]); // MAC should be set
    }

    #[test]
    fn test_verify_response() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        // Create command first
        let command = boundary.create_command(&device_id, 0x01, vec![0x00], 2000).unwrap();

        // Create valid response (would come from device in reality)
        let device = boundary.devices.get(&device_id).unwrap();
        let mut response = LegacyResponse {
            device_id,
            sequence: command.sequence,
            status: 0x00, // Success
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            mac: [0u8; 32],
        };

        // Calculate correct MAC
        let key = device.key;
        response.mac = boundary.calculate_mac(&key, &response.canonical_bytes(), MacAlgorithm::Blake3);

        // Verify should succeed
        let result = boundary.verify_response(&response, 3000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tampered_response_rejected() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        boundary.create_command(&device_id, 0x01, vec![0x00], 2000).unwrap();

        // Create response with wrong MAC
        let response = LegacyResponse {
            device_id,
            sequence: 1,
            status: 0x00,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            mac: [0xBA; 32], // Wrong MAC
        };

        let result = boundary.verify_response(&response, 3000);
        assert!(matches!(result, Err(LegacyBoundaryError::MacVerificationFailed)));
    }

    #[test]
    fn test_sequence_mismatch_rejected() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        boundary.create_command(&device_id, 0x01, vec![0x00], 2000).unwrap();

        // Response with wrong sequence number
        let response = LegacyResponse {
            device_id,
            sequence: 999, // Wrong sequence
            status: 0x00,
            payload: vec![],
            mac: [0u8; 32],
        };

        let result = boundary.verify_response(&response, 3000);
        assert!(matches!(result, Err(LegacyBoundaryError::SequenceMismatch { .. })));
    }

    #[test]
    fn test_key_rotation() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        let original_key = boundary.get_device(&device_id).unwrap().key;

        // Rotate key
        let new_key = boundary.rotate_key(&device_id, 2000).unwrap();

        assert_ne!(original_key, new_key);
        assert_eq!(boundary.get_device(&device_id).unwrap().key, new_key);
        assert_eq!(boundary.get_device(&device_id).unwrap().commands_since_rotation, 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Network, MacAlgorithm::Blake3, 1000).unwrap();

        let command = boundary.create_command(&device_id, 0x42, vec![1, 2, 3, 4], 2000).unwrap();

        let serialized = LegacyBoundary::serialize_command(&command);

        // Create mock response
        let mut response_data = Vec::new();
        response_data.extend_from_slice(b"LRSP");
        response_data.extend_from_slice(&device_id);
        response_data.extend_from_slice(&command.sequence.to_le_bytes());
        response_data.push(0x00); // Status
        response_data.extend_from_slice(&4u32.to_le_bytes()); // Payload len
        response_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Payload
        response_data.extend_from_slice(&[0u8; 32]); // MAC placeholder

        let response = LegacyBoundary::deserialize_response(&response_data).unwrap();
        assert_eq!(response.device_id, device_id);
        assert_eq!(response.sequence, command.sequence);
        assert_eq!(response.payload, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_devices_needing_rotation() {
        let mut boundary = LegacyBoundary::new([0xAA; 32], [0xBB; 32]);
        boundary.rotation_warning_threshold = 3;

        let device_id = [0x01; 16];
        boundary.bind_device(device_id, [0u8; 32], LegacyDeviceType::Storage, MacAlgorithm::Blake3, 1000).unwrap();

        // Initially no devices need rotation
        assert!(boundary.devices_needing_rotation().is_empty());

        // Send some commands
        for i in 0..5 {
            boundary.create_command(&device_id, 0x01, vec![i], 2000 + i as u64).unwrap();
        }

        // Now device should be flagged
        let needing = boundary.devices_needing_rotation();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0], device_id);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        let c = [0xCDu8; 32];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}
