//! Trust level definitions

/// Trust level determining authentication overhead
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustLevel {
    /// Full handshake with challenge-response (first contact)
    /// Wire overhead: 64 bytes (signature)
    Full = 0,
    /// Signature only (known peer)
    /// Wire overhead: 64 bytes (signature)
    Sig = 1,
    /// Compressed authentication token (trusted peer)
    /// Wire overhead: 16 bytes (session token)
    Compress = 2,
    /// No per-frame authentication (mesh-internal)
    /// Wire overhead: 0 bytes
    Raw = 3,
}

impl TrustLevel {
    /// Convert from raw u8 value
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::Full,
            1 => Self::Sig,
            2 => Self::Compress,
            3 => Self::Raw,
            _ => unreachable!(),
        }
    }

    /// Convert to raw u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get authentication overhead in bytes
    pub fn auth_overhead(self) -> usize {
        match self {
            Self::Full | Self::Sig => 64,
            Self::Compress => 16,
            Self::Raw => 0,
        }
    }

    /// Check if this level requires cryptographic verification
    pub fn requires_verification(self) -> bool {
        !matches!(self, Self::Raw)
    }

    /// Check if this level uses signatures (vs tokens)
    pub fn uses_signature(self) -> bool {
        matches!(self, Self::Full | Self::Sig)
    }

    /// Get the minimum trust level that can be upgraded to this level
    pub fn upgrade_from(self) -> Option<Self> {
        match self {
            Self::Full => None,
            Self::Sig => Some(Self::Full),
            Self::Compress => Some(Self::Sig),
            Self::Raw => Some(Self::Compress),
        }
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Full
    }
}

/// Trust action codes for TRUST frames
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustAction {
    /// Initial challenge with nonce
    Challenge = 0x00,
    /// Response to challenge with signature and capabilities
    Response = 0x01,
    /// Propose upgrade to higher trust level
    ProposeUpgrade = 0x02,
    /// Accept trust level upgrade
    AcceptUpgrade = 0x03,
    /// Reject trust negotiation
    Reject = 0x04,
    /// Downgrade trust level
    Downgrade = 0x05,
    /// Rotate session key material
    KeyRotate = 0x06,
}

impl TrustAction {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Challenge),
            0x01 => Some(Self::Response),
            0x02 => Some(Self::ProposeUpgrade),
            0x03 => Some(Self::AcceptUpgrade),
            0x04 => Some(Self::Reject),
            0x05 => Some(Self::Downgrade),
            0x06 => Some(Self::KeyRotate),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Reason codes for trust rejection/downgrade
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustRejectReason {
    /// Signature verification failed
    InvalidSignature = 0x00,
    /// Challenge response mismatch
    ChallengeFailed = 0x01,
    /// Requested level not supported
    UnsupportedLevel = 0x02,
    /// Node not authorized
    Unauthorized = 0x03,
    /// Session expired
    SessionExpired = 0x04,
    /// Too many failed attempts
    RateLimited = 0x05,
    /// Protocol version mismatch
    VersionMismatch = 0x06,
    /// Generic/unspecified reason
    Other = 0xFF,
}

impl TrustRejectReason {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::InvalidSignature,
            0x01 => Self::ChallengeFailed,
            0x02 => Self::UnsupportedLevel,
            0x03 => Self::Unauthorized,
            0x04 => Self::SessionExpired,
            0x05 => Self::RateLimited,
            0x06 => Self::VersionMismatch,
            _ => Self::Other,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Full < TrustLevel::Sig);
        assert!(TrustLevel::Sig < TrustLevel::Compress);
        assert!(TrustLevel::Compress < TrustLevel::Raw);
    }

    #[test]
    fn test_auth_overhead() {
        assert_eq!(TrustLevel::Full.auth_overhead(), 64);
        assert_eq!(TrustLevel::Sig.auth_overhead(), 64);
        assert_eq!(TrustLevel::Compress.auth_overhead(), 16);
        assert_eq!(TrustLevel::Raw.auth_overhead(), 0);
    }

    #[test]
    fn test_upgrade_chain() {
        assert_eq!(TrustLevel::Sig.upgrade_from(), Some(TrustLevel::Full));
        assert_eq!(TrustLevel::Compress.upgrade_from(), Some(TrustLevel::Sig));
        assert_eq!(TrustLevel::Raw.upgrade_from(), Some(TrustLevel::Compress));
        assert_eq!(TrustLevel::Full.upgrade_from(), None);
    }
}
