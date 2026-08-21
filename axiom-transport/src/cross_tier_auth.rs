//! Cross-Tier Authentication Tokens
//!
//! Implements authentication tokens that work across different trust tiers
//! in the AXIOM architecture. Tokens carry capability information and can
//! be delegated with attenuation.
//!
//! # Trust Tiers
//!
//! 1. **Tier 0 (Root)**: Hardware root of trust, TPM-backed
//! 2. **Tier 1 (Firmware)**: Verified firmware, measured boot
//! 3. **Tier 2 (Kernel)**: Verified kernel, secure boot chain
//! 4. **Tier 3 (Driver)**: Verified drivers (signed HDL)
//! 5. **Tier 4 (Application)**: Application-level, least privilege
//!
//! # Token Properties
//!
//! - **Signed**: Tokens are cryptographically signed
//! - **Scoped**: Tokens have specific capabilities
//! - **Time-bound**: Tokens have expiration
//! - **Delegatable**: Tokens can be delegated with reduced scope
//! - **Revocable**: Tokens can be revoked by issuer

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Maximum allowed delegation depth to prevent infinite chains
pub const MAX_DELEGATION_DEPTH: u8 = 5;

/// Trust tiers in the AXIOM architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustTier {
    /// Hardware root of trust
    Root = 0,
    /// Verified firmware
    Firmware = 1,
    /// Verified kernel
    Kernel = 2,
    /// Verified drivers
    Driver = 3,
    /// Applications
    Application = 4,
}

impl TrustTier {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Root),
            1 => Some(Self::Firmware),
            2 => Some(Self::Kernel),
            3 => Some(Self::Driver),
            4 => Some(Self::Application),
            _ => None,
        }
    }

    /// Check if this tier can issue tokens for target tier
    pub fn can_issue_for(&self, target: TrustTier) -> bool {
        // Can only issue tokens for same or lower tiers
        (*self as u8) <= (target as u8)
    }
}

/// Capabilities that can be granted by tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Capability {
    /// Read from memory region
    MemoryRead = 0x0001,
    /// Write to memory region
    MemoryWrite = 0x0002,
    /// Execute code
    Execute = 0x0003,
    /// Access DMA
    DmaAccess = 0x0004,
    /// Access interrupts
    InterruptAccess = 0x0005,
    /// Access I/O ports
    IoPortAccess = 0x0006,
    /// Access MMIO regions
    MmioAccess = 0x0007,
    /// Access network
    NetworkAccess = 0x0008,
    /// Access storage
    StorageAccess = 0x0009,
    /// Access cryptographic operations
    CryptoAccess = 0x000A,
    /// Issue sub-tokens (delegation)
    Delegate = 0x000B,
    /// Access audit logs
    AuditAccess = 0x000C,
    /// Administrative operations
    Admin = 0x00FF,
}

impl Capability {
    /// Parse from u16
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::MemoryRead),
            0x0002 => Some(Self::MemoryWrite),
            0x0003 => Some(Self::Execute),
            0x0004 => Some(Self::DmaAccess),
            0x0005 => Some(Self::InterruptAccess),
            0x0006 => Some(Self::IoPortAccess),
            0x0007 => Some(Self::MmioAccess),
            0x0008 => Some(Self::NetworkAccess),
            0x0009 => Some(Self::StorageAccess),
            0x000A => Some(Self::CryptoAccess),
            0x000B => Some(Self::Delegate),
            0x000C => Some(Self::AuditAccess),
            0x00FF => Some(Self::Admin),
            _ => None,
        }
    }
}

/// A cross-tier authentication token
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub struct AuthToken {
    /// Unique token identifier
    pub token_id: [u8; 16],
    /// Who issued this token
    pub issuer_id: [u8; 32],
    /// Who this token is for
    pub subject_id: [u8; 32],
    /// Trust tier this token grants
    pub tier: TrustTier,
    /// Capabilities granted
    pub capabilities: BTreeSet<Capability>,
    /// When token was issued (ms since epoch)
    pub issued_at_ms: u64,
    /// When token expires (ms since epoch)
    pub expires_at_ms: u64,
    /// Parent token ID (for delegated tokens)
    pub parent_token: Option<[u8; 16]>,
    /// Nonce for uniqueness
    pub nonce: [u8; 16],
    /// Signature over token data
    pub signature: [u8; 64],
    /// Delegation depth (0 for root tokens, increments for each delegation)
    pub delegation_depth: u8,
}

impl AuthToken {
    /// Check if token is expired
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.expires_at_ms
    }

    /// Check if token has capability
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Check if token can delegate
    pub fn can_delegate(&self) -> bool {
        self.capabilities.contains(&Capability::Delegate)
    }

    /// Create canonical bytes for signing/verification
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);

        // Header
        bytes.extend_from_slice(b"AXIOM-TOKEN\x00\x01");

        // Token ID
        bytes.extend_from_slice(&self.token_id);

        // Issuer
        bytes.extend_from_slice(&self.issuer_id);

        // Subject
        bytes.extend_from_slice(&self.subject_id);

        // Tier
        bytes.push(self.tier as u8);

        // Capabilities count
        bytes.extend_from_slice(&(self.capabilities.len() as u16).to_le_bytes());

        // Capabilities (sorted by Ord impl)
        for cap in &self.capabilities {
            bytes.extend_from_slice(&(*cap as u16).to_le_bytes());
        }

        // Timestamps
        bytes.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_le_bytes());

        // Parent token
        if let Some(ref parent) = self.parent_token {
            bytes.push(0x01);
            bytes.extend_from_slice(parent);
        } else {
            bytes.push(0x00);
        }

        // Nonce
        bytes.extend_from_slice(&self.nonce);

        // Delegation depth
        bytes.push(self.delegation_depth);

        bytes
    }

    /// Verify token signature
    pub fn verify(&self, issuer_public_key: &[u8; 32]) -> bool {
        let message = self.canonical_bytes();

        use ed25519_dalek::{Signature, VerifyingKey, Verifier};

        let Ok(verifying_key) = VerifyingKey::from_bytes(issuer_public_key) else {
            return false;
        };

        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };

        <VerifyingKey as Verifier<Signature>>::verify(&verifying_key, &message, &signature).is_ok()
    }
}

/// Token issuer for a specific tier
pub struct TokenIssuer {
    /// Issuer identity
    issuer_id: [u8; 32],
    /// Signing key
    signing_key: [u8; 32],
    /// Our trust tier
    tier: TrustTier,
    /// Maximum token lifetime (ms)
    max_lifetime_ms: u64,
    /// Token counter for unique IDs
    token_counter: u64,
}

impl TokenIssuer {
    /// Create new token issuer
    pub fn new(
        issuer_id: [u8; 32],
        signing_key: [u8; 32],
        tier: TrustTier,
        max_lifetime_ms: u64,
    ) -> Self {
        Self {
            issuer_id,
            signing_key,
            tier,
            max_lifetime_ms,
            token_counter: 0,
        }
    }

    /// Issue a new token
    pub fn issue_token(
        &mut self,
        subject_id: [u8; 32],
        tier: TrustTier,
        capabilities: BTreeSet<Capability>,
        lifetime_ms: u64,
        current_time_ms: u64,
    ) -> Result<AuthToken, TokenError> {
        // Can only issue for same or lower tiers
        if !self.tier.can_issue_for(tier) {
            return Err(TokenError::TierEscalation);
        }

        // Enforce maximum lifetime
        let actual_lifetime = lifetime_ms.min(self.max_lifetime_ms);

        // Generate token ID
        self.token_counter += 1;
        let mut token_id = [0u8; 16];
        token_id[0..8].copy_from_slice(&self.token_counter.to_le_bytes());
        token_id[8..16].copy_from_slice(&current_time_ms.to_le_bytes());

        // Generate nonce
        let mut nonce = [0u8; 16];
        // In production, use secure random
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = ((current_time_ms >> (i % 8)) ^ (self.token_counter >> (i % 8))) as u8;
        }

        let mut token = AuthToken {
            token_id,
            issuer_id: self.issuer_id,
            subject_id,
            tier,
            capabilities,
            issued_at_ms: current_time_ms,
            expires_at_ms: current_time_ms + actual_lifetime,
            parent_token: None,
            nonce,
            signature: [0u8; 64],
            delegation_depth: 0, // Root token
        };

        // Sign the token
        self.sign_token(&mut token);

        Ok(token)
    }

    /// Delegate a token (create sub-token with attenuated capabilities)
    pub fn delegate_token(
        &mut self,
        parent: &AuthToken,
        new_subject_id: [u8; 32],
        new_capabilities: BTreeSet<Capability>,
        new_lifetime_ms: u64,
        current_time_ms: u64,
        parent_issuer_key: &[u8; 32],
    ) -> Result<AuthToken, TokenError> {
        // Verify parent token
        if !parent.verify(parent_issuer_key) {
            return Err(TokenError::InvalidParent);
        }

        // Check parent is not expired
        if parent.is_expired(current_time_ms) {
            return Err(TokenError::ParentExpired);
        }

        // Check parent can delegate
        if !parent.can_delegate() {
            return Err(TokenError::DelegationNotAllowed);
        }

        // Check delegation depth limit
        if parent.delegation_depth >= MAX_DELEGATION_DEPTH {
            return Err(TokenError::MaxDelegationDepthExceeded);
        }

        // New capabilities must be subset of parent
        for cap in &new_capabilities {
            if !parent.has_capability(*cap) {
                return Err(TokenError::CapabilityEscalation);
            }
        }

        // New lifetime cannot exceed parent's remaining lifetime
        let parent_remaining = parent.expires_at_ms.saturating_sub(current_time_ms);
        let actual_lifetime = new_lifetime_ms.min(parent_remaining);

        // Cannot delegate to higher tier
        if !parent.tier.can_issue_for(parent.tier) {
            return Err(TokenError::TierEscalation);
        }

        // Generate token ID
        self.token_counter += 1;
        let mut token_id = [0u8; 16];
        token_id[0..8].copy_from_slice(&self.token_counter.to_le_bytes());
        token_id[8..16].copy_from_slice(&current_time_ms.to_le_bytes());

        // Generate nonce
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = ((current_time_ms >> (i % 8)) ^ (self.token_counter >> (i % 8))) as u8;
        }

        let mut token = AuthToken {
            token_id,
            issuer_id: self.issuer_id,
            subject_id: new_subject_id,
            tier: parent.tier, // Same or lower tier
            capabilities: new_capabilities,
            issued_at_ms: current_time_ms,
            expires_at_ms: current_time_ms + actual_lifetime,
            parent_token: Some(parent.token_id),
            nonce,
            signature: [0u8; 64],
            delegation_depth: parent.delegation_depth + 1,
        };

        // Sign the token
        self.sign_token(&mut token);

        Ok(token)
    }

    /// Sign a token
    fn sign_token(&self, token: &mut AuthToken) {
        let message = token.canonical_bytes();

        use ed25519_dalek::{SigningKey, Signer};
        let signing = SigningKey::from_bytes(&self.signing_key);
        token.signature = signing.sign(&message).to_bytes();
    }

    /// Get our issuer ID
    pub fn issuer_id(&self) -> [u8; 32] {
        self.issuer_id
    }

    /// Get our tier
    pub fn tier(&self) -> TrustTier {
        self.tier
    }
}

/// Token verifier
pub struct TokenVerifier {
    /// Known issuer public keys by issuer ID
    trusted_issuers: alloc::collections::BTreeMap<[u8; 32], TrustedIssuer>,
    /// Revoked token IDs
    revoked_tokens: BTreeSet<[u8; 16]>,
}

/// A trusted token issuer
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    /// Issuer's public key
    pub public_key: [u8; 32],
    /// Issuer's tier
    pub tier: TrustTier,
    /// When this issuer was added
    pub added_at_ms: u64,
}

impl TokenVerifier {
    /// Create new token verifier
    pub fn new() -> Self {
        Self {
            trusted_issuers: alloc::collections::BTreeMap::new(),
            revoked_tokens: BTreeSet::new(),
        }
    }

    /// Add a trusted issuer
    pub fn add_issuer(&mut self, issuer_id: [u8; 32], issuer: TrustedIssuer) {
        self.trusted_issuers.insert(issuer_id, issuer);
    }

    /// Remove a trusted issuer
    pub fn remove_issuer(&mut self, issuer_id: &[u8; 32]) {
        self.trusted_issuers.remove(issuer_id);
    }

    /// Revoke a token
    pub fn revoke_token(&mut self, token_id: [u8; 16]) {
        self.revoked_tokens.insert(token_id);
    }

    /// Check if a token is revoked
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool {
        self.revoked_tokens.contains(token_id)
    }

    /// Verify a token
    pub fn verify_token(
        &self,
        token: &AuthToken,
        required_tier: TrustTier,
        required_capabilities: &[Capability],
        current_time_ms: u64,
    ) -> Result<(), TokenError> {
        // Check if token is revoked
        if self.is_revoked(&token.token_id) {
            return Err(TokenError::Revoked);
        }

        // Check expiration
        if token.is_expired(current_time_ms) {
            return Err(TokenError::Expired);
        }

        // Get issuer
        let issuer = self.trusted_issuers.get(&token.issuer_id)
            .ok_or(TokenError::UntrustedIssuer)?;

        // Verify signature
        if !token.verify(&issuer.public_key) {
            return Err(TokenError::InvalidSignature);
        }

        // Check tier (token tier must be <= required tier for access)
        if (token.tier as u8) > (required_tier as u8) {
            return Err(TokenError::InsufficientTier);
        }

        // Check capabilities
        for cap in required_capabilities {
            if !token.has_capability(*cap) {
                return Err(TokenError::MissingCapability(*cap));
            }
        }

        Ok(())
    }

    /// Verify a delegated token chain
    pub fn verify_delegation_chain(
        &self,
        token: &AuthToken,
        parent_tokens: &[AuthToken],
        current_time_ms: u64,
    ) -> Result<(), TokenError> {
        self.verify_delegation_chain_bounded(token, parent_tokens, current_time_ms, 0)
    }

    /// Depth-bounded implementation backing `verify_delegation_chain`.
    ///
    /// A token whose `parent_token` refers back into a cycle - including
    /// the degenerate case `parent_token == token_id`, referencing itself,
    /// present in a `parent_tokens` slice that contains it - would
    /// otherwise recurse forever: the recursive call happens BEFORE any
    /// signature check below, and `deserialize_token` doesn't verify
    /// signatures at parse time either, so a crafted chain needs zero valid
    /// authentication to trigger a stack overflow (a peer-triggerable
    /// process kill under this workspace's panic=abort).
    ///
    /// `depth` is our own call-stack counter, NOT the wire-supplied
    /// `AuthToken::delegation_depth` field - that field is attacker
    /// controlled (via `deserialize_token`, which doesn't validate it
    /// against anything) and so isn't sound to trust as a recursion cap by
    /// itself; an attacker could set it to 0 on every token in a forged
    /// cycle. `depth` is capped so it can never exceed one more hop than
    /// `MAX_DELEGATION_DEPTH` - the same constant `TokenIssuer::delegate_token`
    /// already enforces at ISSUANCE time (a token may be issued with
    /// `delegation_depth` up to and including `MAX_DELEGATION_DEPTH`, so a
    /// full legitimate chain is `MAX_DELEGATION_DEPTH + 1` tokens long, and
    /// verifying it recurses `depth` 0..=MAX_DELEGATION_DEPTH inclusive).
    ///
    /// AXIOM-14 Cycle 8 (Fable diff review, required): this was originally
    /// `depth >= MAX_DELEGATION_DEPTH`, which is an off-by-one - it rejects
    /// the deepest chain `delegate_token` can legitimately issue, a real
    /// regression this cap introduced (the pre-cap code verified a
    /// full-depth chain fine). `>` still terminates a self-referencing
    /// cycle (at one hop past the legitimate maximum) while accepting every
    /// chain `delegate_token` could actually have produced.
    fn verify_delegation_chain_bounded(
        &self,
        token: &AuthToken,
        parent_tokens: &[AuthToken],
        current_time_ms: u64,
        depth: u8,
    ) -> Result<(), TokenError> {
        if depth > MAX_DELEGATION_DEPTH {
            return Err(TokenError::MaxDelegationDepthExceeded);
        }

        // If no parent, just verify the token itself
        let Some(parent_id) = token.parent_token else {
            return self.verify_token(token, TrustTier::Application, &[], current_time_ms);
        };

        // Find parent in provided chain
        let parent = parent_tokens.iter()
            .find(|t| t.token_id == parent_id)
            .ok_or(TokenError::ParentNotProvided)?;

        // Verify parent first (recursive)
        self.verify_delegation_chain_bounded(parent, parent_tokens, current_time_ms, depth + 1)?;

        // Verify current token is valid under parent
        // - Capabilities must be subset
        for cap in &token.capabilities {
            if !parent.has_capability(*cap) {
                return Err(TokenError::CapabilityEscalation);
            }
        }

        // - Expiration must not exceed parent
        if token.expires_at_ms > parent.expires_at_ms {
            return Err(TokenError::ExpirationExceedsParent);
        }

        // - Verify signature
        let issuer = self.trusted_issuers.get(&token.issuer_id)
            .ok_or(TokenError::UntrustedIssuer)?;

        if !token.verify(&issuer.public_key) {
            return Err(TokenError::InvalidSignature);
        }

        Ok(())
    }
}

impl Default for TokenVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Token errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Token has expired
    Expired,
    /// Token has been revoked
    Revoked,
    /// Token issuer is not trusted
    UntrustedIssuer,
    /// Token signature is invalid
    InvalidSignature,
    /// Token tier is insufficient
    InsufficientTier,
    /// Token is missing required capability
    MissingCapability(Capability),
    /// Attempted to escalate tier
    TierEscalation,
    /// Attempted to escalate capabilities
    CapabilityEscalation,
    /// Parent token is invalid
    InvalidParent,
    /// Parent token is expired
    ParentExpired,
    /// Token cannot be delegated
    DelegationNotAllowed,
    /// Parent token not provided in chain
    ParentNotProvided,
    /// Delegated token expires after parent
    ExpirationExceedsParent,
    /// Token data is malformed
    MalformedData,
    /// Maximum delegation depth exceeded
    MaxDelegationDepthExceeded,
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Expired => write!(f, "Token has expired"),
            Self::Revoked => write!(f, "Token has been revoked"),
            Self::UntrustedIssuer => write!(f, "Token issuer is not trusted"),
            Self::InvalidSignature => write!(f, "Token signature is invalid"),
            Self::InsufficientTier => write!(f, "Token tier is insufficient"),
            Self::MissingCapability(cap) => write!(f, "Token missing capability: {:?}", cap),
            Self::TierEscalation => write!(f, "Cannot escalate trust tier"),
            Self::CapabilityEscalation => write!(f, "Cannot escalate capabilities"),
            Self::InvalidParent => write!(f, "Parent token is invalid"),
            Self::ParentExpired => write!(f, "Parent token has expired"),
            Self::DelegationNotAllowed => write!(f, "Token cannot be delegated"),
            Self::ParentNotProvided => write!(f, "Parent token not provided"),
            Self::ExpirationExceedsParent => write!(f, "Token expiration exceeds parent"),
            Self::MalformedData => write!(f, "Token data is malformed"),
            Self::MaxDelegationDepthExceeded => write!(f, "Maximum delegation depth exceeded"),
        }
    }
}

/// Serialize token for transmission
pub fn serialize_token(token: &AuthToken) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);

    // Header
    bytes.extend_from_slice(b"ATKN");

    // Token ID
    bytes.extend_from_slice(&token.token_id);

    // Issuer
    bytes.extend_from_slice(&token.issuer_id);

    // Subject
    bytes.extend_from_slice(&token.subject_id);

    // Tier
    bytes.push(token.tier as u8);

    // Capabilities
    bytes.extend_from_slice(&(token.capabilities.len() as u16).to_le_bytes());
    for cap in &token.capabilities {
        bytes.extend_from_slice(&(*cap as u16).to_le_bytes());
    }

    // Timestamps
    bytes.extend_from_slice(&token.issued_at_ms.to_le_bytes());
    bytes.extend_from_slice(&token.expires_at_ms.to_le_bytes());

    // Parent token
    if let Some(ref parent) = token.parent_token {
        bytes.push(0x01);
        bytes.extend_from_slice(parent);
    } else {
        bytes.push(0x00);
    }

    // Nonce
    bytes.extend_from_slice(&token.nonce);

    // Signature
    bytes.extend_from_slice(&token.signature);

    // Delegation depth
    bytes.push(token.delegation_depth);

    bytes
}

/// Deserialize token from transmission
pub fn deserialize_token(data: &[u8]) -> Result<AuthToken, TokenError> {
    // Minimum size check
    if data.len() < 4 + 16 + 32 + 32 + 1 + 2 + 8 + 8 + 1 + 16 + 64 {
        return Err(TokenError::MalformedData);
    }

    // Verify header
    if &data[0..4] != b"ATKN" {
        return Err(TokenError::MalformedData);
    }

    let mut offset = 4;

    // Token ID
    let mut token_id = [0u8; 16];
    token_id.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;

    // Issuer
    let mut issuer_id = [0u8; 32];
    issuer_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Subject
    let mut subject_id = [0u8; 32];
    subject_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Tier
    let tier = TrustTier::from_byte(data[offset])
        .ok_or(TokenError::MalformedData)?;
    offset += 1;

    // Capabilities
    let cap_count = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    let mut capabilities = BTreeSet::new();
    for _ in 0..cap_count {
        if offset + 2 > data.len() {
            return Err(TokenError::MalformedData);
        }
        let cap_val = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        if let Some(cap) = Capability::from_u16(cap_val) {
            capabilities.insert(cap);
        }
        offset += 2;
    }

    // Timestamps. A large `cap_count` can walk `offset` past the point
    // where 8 more bytes actually exist even though every capability read
    // above was individually bounds-checked (the checks just don't say
    // anything about what comes AFTER the loop) - bounds-check these reads
    // too, matching the pattern already used for the nonce/signature reads
    // below. Previously these used `.try_into().unwrap()` directly with no
    // guard, unlike nonce/signature - a crafted `cap_count` in an
    // otherwise-short buffer panicked here instead of returning
    // `MalformedData`.
    if offset + 8 > data.len() {
        return Err(TokenError::MalformedData);
    }
    let issued_at_ms = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;

    if offset + 8 > data.len() {
        return Err(TokenError::MalformedData);
    }
    let expires_at_ms = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;

    // Parent token
    let parent_token = if data[offset] == 0x01 {
        offset += 1;
        if offset + 16 > data.len() {
            return Err(TokenError::MalformedData);
        }
        let mut parent = [0u8; 16];
        parent.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        Some(parent)
    } else {
        offset += 1;
        None
    };

    // Nonce
    if offset + 16 > data.len() {
        return Err(TokenError::MalformedData);
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;

    // Signature
    if offset + 64 > data.len() {
        return Err(TokenError::MalformedData);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[offset..offset + 64]);
    offset += 64;

    // Delegation depth
    let delegation_depth = if offset < data.len() {
        data[offset]
    } else {
        0 // Default for backwards compatibility
    };

    Ok(AuthToken {
        token_id,
        issuer_id,
        subject_id,
        tier,
        capabilities,
        issued_at_ms,
        expires_at_ms,
        parent_token,
        nonce,
        signature,
        delegation_depth,
    })
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let private = signing_key.to_bytes();
        let public = signing_key.verifying_key().to_bytes();

        (private, public)
    }

    #[test]
    fn test_issue_token() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Kernel,
            3600_000, // 1 hour max
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::NetworkAccess);

        let token = issuer.issue_token(
            [0xBB; 32], // subject
            TrustTier::Driver,
            caps,
            1800_000, // 30 minutes
            1000,
        ).unwrap();

        assert!(token.verify(&public_key));
        assert!(token.has_capability(Capability::MemoryRead));
        assert!(token.has_capability(Capability::NetworkAccess));
        assert!(!token.has_capability(Capability::Admin));
    }

    #[test]
    fn test_tier_escalation_prevented() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Driver, // We're a driver
            3600_000,
        );

        let caps = BTreeSet::new();

        // Try to issue kernel-level token (should fail)
        let result = issuer.issue_token(
            [0xBB; 32],
            TrustTier::Firmware, // Trying to escalate
            caps,
            1800_000,
            1000,
        );

        assert!(matches!(result, Err(TokenError::TierEscalation)));
    }

    #[test]
    fn test_token_verification() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);

        let token = issuer.issue_token(
            [0xBB; 32],
            TrustTier::Driver,
            caps,
            1800_000,
            1000,
        ).unwrap();

        let mut verifier = TokenVerifier::new();
        verifier.add_issuer(public_key, TrustedIssuer {
            public_key,
            tier: TrustTier::Kernel,
            added_at_ms: 0,
        });

        // Should verify successfully
        let result = verifier.verify_token(
            &token,
            TrustTier::Driver,
            &[Capability::MemoryRead],
            500, // Before expiration
        );
        assert!(result.is_ok());

        // Should fail for missing capability
        let result = verifier.verify_token(
            &token,
            TrustTier::Driver,
            &[Capability::MemoryWrite],
            500,
        );
        assert!(matches!(result, Err(TokenError::MissingCapability(_))));
    }

    #[test]
    fn test_token_expiration() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Kernel,
            3600_000,
        );

        let token = issuer.issue_token(
            [0xBB; 32],
            TrustTier::Driver,
            BTreeSet::new(),
            1000, // Very short lifetime
            1000, // Issued at 1000
        ).unwrap();

        let mut verifier = TokenVerifier::new();
        verifier.add_issuer(public_key, TrustedIssuer {
            public_key,
            tier: TrustTier::Kernel,
            added_at_ms: 0,
        });

        // Should fail - expired
        let result = verifier.verify_token(
            &token,
            TrustTier::Driver,
            &[],
            3000, // After expiration
        );
        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[test]
    fn test_token_revocation() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Kernel,
            3600_000,
        );

        let token = issuer.issue_token(
            [0xBB; 32],
            TrustTier::Driver,
            BTreeSet::new(),
            1800_000,
            1000,
        ).unwrap();

        let mut verifier = TokenVerifier::new();
        verifier.add_issuer(public_key, TrustedIssuer {
            public_key,
            tier: TrustTier::Kernel,
            added_at_ms: 0,
        });

        // Revoke the token
        verifier.revoke_token(token.token_id);

        // Should fail - revoked
        let result = verifier.verify_token(
            &token,
            TrustTier::Driver,
            &[],
            500,
        );
        assert!(matches!(result, Err(TokenError::Revoked)));
    }

    #[test]
    fn test_delegation() {
        let (issuer_private, issuer_public) = generate_keypair();
        let (delegator_private, delegator_public) = generate_keypair();

        // Create initial token with delegate capability
        let mut issuer = TokenIssuer::new(
            issuer_public,
            issuer_private,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::NetworkAccess);
        caps.insert(Capability::Delegate);

        let parent_token = issuer.issue_token(
            delegator_public,
            TrustTier::Driver,
            caps,
            1800_000,
            1000,
        ).unwrap();

        // Delegate with reduced capabilities
        let mut delegator = TokenIssuer::new(
            delegator_public,
            delegator_private,
            TrustTier::Driver,
            1800_000,
        );

        let mut sub_caps = BTreeSet::new();
        sub_caps.insert(Capability::MemoryRead); // Only memory read

        let child_token = delegator.delegate_token(
            &parent_token,
            [0xCC; 32], // New subject
            sub_caps,
            600_000, // Shorter lifetime
            1100,
            &issuer_public,
        ).unwrap();

        assert!(child_token.verify(&delegator_public));
        assert_eq!(child_token.parent_token, Some(parent_token.token_id));
        assert!(child_token.has_capability(Capability::MemoryRead));
        assert!(!child_token.has_capability(Capability::NetworkAccess));
    }

    #[test]
    fn test_delegation_capability_escalation_prevented() {
        let (issuer_private, issuer_public) = generate_keypair();
        let (delegator_private, delegator_public) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            issuer_public,
            issuer_private,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::Delegate);

        let parent_token = issuer.issue_token(
            delegator_public,
            TrustTier::Driver,
            caps,
            1800_000,
            1000,
        ).unwrap();

        let mut delegator = TokenIssuer::new(
            delegator_public,
            delegator_private,
            TrustTier::Driver,
            1800_000,
        );

        // Try to add capability parent doesn't have
        let mut sub_caps = BTreeSet::new();
        sub_caps.insert(Capability::MemoryRead);
        sub_caps.insert(Capability::MemoryWrite); // Parent doesn't have this!

        let result = delegator.delegate_token(
            &parent_token,
            [0xCC; 32],
            sub_caps,
            600_000,
            1100,
            &issuer_public,
        );

        assert!(matches!(result, Err(TokenError::CapabilityEscalation)));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (private_key, public_key) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            public_key,
            private_key,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::NetworkAccess);

        let original = issuer.issue_token(
            [0xBB; 32],
            TrustTier::Driver,
            caps,
            1800_000,
            1000,
        ).unwrap();

        let serialized = serialize_token(&original);
        let deserialized = deserialize_token(&serialized).unwrap();

        assert_eq!(original.token_id, deserialized.token_id);
        assert_eq!(original.issuer_id, deserialized.issuer_id);
        assert_eq!(original.subject_id, deserialized.subject_id);
        assert_eq!(original.tier, deserialized.tier);
        assert_eq!(original.capabilities, deserialized.capabilities);
        assert_eq!(original.issued_at_ms, deserialized.issued_at_ms);
        assert_eq!(original.expires_at_ms, deserialized.expires_at_ms);
        assert_eq!(original.signature, deserialized.signature);

        // Verify deserialized token still valid
        assert!(deserialized.verify(&public_key));
    }


    #[test]
    fn test_delegation_depth_limit() {
        // Create initial issuer
        let (issuer_private, issuer_public) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            issuer_public,
            issuer_private,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::Delegate);

        // Create initial token with depth 0
        let mut current_token = issuer.issue_token(
            issuer_public,
            TrustTier::Driver,
            caps.clone(),
            3600_000,
            1000,
        ).unwrap();

        assert_eq!(current_token.delegation_depth, 0);

        // Each delegated token is signed by that iteration's OWN fresh
        // issuer keypair, not the original root issuer - `verify()` inside
        // `delegate_token` needs whoever actually signed `current_token` at
        // this point, which after the first iteration is `new_public` from
        // the PREVIOUS loop pass, not the root `issuer_public`. Tracking it
        // here fixes a real bug: this test used to pass `&issuer_public` on
        // every iteration regardless, so it only worked for i==0 and failed
        // with `InvalidParent` from i==1 onward, before ever reaching the
        // depth-limit check the test is actually named for.
        let mut current_parent_key = issuer_public;

        // Delegate MAX_DELEGATION_DEPTH times (should all succeed)
        for i in 0..MAX_DELEGATION_DEPTH {
            let (new_private, new_public) = generate_keypair();
            let mut new_issuer = TokenIssuer::new(
                new_public,
                new_private,
                TrustTier::Driver,
                3600_000,
            );

            let delegated = new_issuer.delegate_token(
                &current_token,
                [0x10 + i; 32],
                caps.clone(),
                1800_000,
                2000 + i as u64 * 100,
                &current_parent_key,
            ).unwrap();

            assert_eq!(delegated.delegation_depth, i + 1);
            current_token = delegated;
            current_parent_key = new_public;
        }

        // One more delegation should fail
        let (final_private, final_public) = generate_keypair();
        let mut final_issuer = TokenIssuer::new(
            final_public,
            final_private,
            TrustTier::Driver,
            3600_000,
        );

        let result = final_issuer.delegate_token(
            &current_token,
            [0xFF; 32],
            caps,
            1800_000,
            10000,
            &current_parent_key,
        );

        assert_eq!(result, Err(TokenError::MaxDelegationDepthExceeded));
    }

    /// B1: a token whose `parent_token` points back to itself (a 1-cycle),
    /// present in the `parent_tokens` slice, must be rejected rather than
    /// recursing forever - `verify_delegation_chain`'s recursive call
    /// previously ran before any signature check, so this needed zero
    /// valid authentication to trigger (a peer-triggerable stack overflow
    /// / process kill under this workspace's panic=abort).
    #[test]
    fn test_verify_delegation_chain_rejects_self_referencing_cycle() {
        let (_issuer_private, issuer_public) = generate_keypair();

        let mut verifier = TokenVerifier::new();
        verifier.add_issuer(issuer_public, TrustedIssuer {
            public_key: issuer_public,
            tier: TrustTier::Kernel,
            added_at_ms: 0,
        });

        let token_id = [0x42; 16];
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Delegate);

        // Deliberately not properly signed - deserialize_token doesn't
        // verify signatures at parse time either, so a real attacker
        // wouldn't need a valid signature to construct this.
        let cyclic_token = AuthToken {
            token_id,
            issuer_id: issuer_public,
            subject_id: [0xBB; 32],
            tier: TrustTier::Application,
            capabilities: caps,
            issued_at_ms: 0,
            expires_at_ms: u64::MAX,
            parent_token: Some(token_id), // points to itself
            nonce: [0u8; 16],
            signature: [0u8; 64],
            delegation_depth: 0,
        };

        let parent_tokens = [cyclic_token.clone()];
        let result = verifier.verify_delegation_chain(&cyclic_token, &parent_tokens, 1000);

        assert_eq!(result, Err(TokenError::MaxDelegationDepthExceeded));
    }

    /// AXIOM-14 Cycle 8 (Fable diff review, required): the boundary
    /// test the off-by-one fix needed - a properly-signed chain at
    /// exactly `MAX_DELEGATION_DEPTH` delegations (the deepest
    /// `delegate_token` can legitimately issue, per
    /// `test_delegation_depth_limit` above) must still verify
    /// successfully end-to-end. Before this fix,
    /// `verify_delegation_chain_bounded`'s `depth >= MAX_DELEGATION_DEPTH`
    /// check rejected this exact chain with `MaxDelegationDepthExceeded`
    /// - a regression the uncapped pre-Cycle-8 code never had.
    #[test]
    fn test_verify_delegation_chain_accepts_full_depth_legitimate_chain() {
        let (issuer_private, issuer_public) = generate_keypair();

        let mut issuer = TokenIssuer::new(
            issuer_public,
            issuer_private,
            TrustTier::Kernel,
            3600_000,
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::MemoryRead);
        caps.insert(Capability::Delegate);

        let root_token = issuer.issue_token(
            issuer_public,
            TrustTier::Driver,
            caps.clone(),
            3600_000,
            1000,
        ).unwrap();

        let mut verifier = TokenVerifier::new();
        verifier.add_issuer(issuer_public, TrustedIssuer {
            public_key: issuer_public,
            tier: TrustTier::Kernel,
            added_at_ms: 0,
        });

        let mut chain_tokens = alloc::vec![root_token.clone()];
        let mut current_token = root_token;
        let mut current_parent_key = issuer_public;

        for i in 0..MAX_DELEGATION_DEPTH {
            let (new_private, new_public) = generate_keypair();
            let mut new_issuer = TokenIssuer::new(
                new_public,
                new_private,
                TrustTier::Driver,
                3600_000,
            );

            // Every issuer in the chain must be independently trusted -
            // verify_delegation_chain_bounded checks
            // trusted_issuers.get(&token.issuer_id) at EVERY level, not
            // just the root.
            verifier.add_issuer(new_public, TrustedIssuer {
                public_key: new_public,
                tier: TrustTier::Driver,
                added_at_ms: 0,
            });

            let delegated = new_issuer.delegate_token(
                &current_token,
                [0x10 + i; 32],
                caps.clone(),
                1800_000,
                2000 + i as u64 * 100,
                &current_parent_key,
            ).unwrap();

            current_token = delegated.clone();
            current_parent_key = new_public;
            chain_tokens.push(delegated);
        }

        // current_token is now the full MAX_DELEGATION_DEPTH-deep leaf.
        // parent_tokens must contain every ANCESTOR (not the leaf itself)
        // for the recursive parent lookup to succeed at each level.
        let leaf = chain_tokens.pop().unwrap();
        assert_eq!(leaf.delegation_depth, MAX_DELEGATION_DEPTH);

        let result = verifier.verify_delegation_chain(&leaf, &chain_tokens, 10000);
        assert_eq!(result, Ok(()), "a legitimately-issued full-depth chain must verify, not be rejected by the depth cap");
    }

    /// B1: a crafted `cap_count` that survives the (individually
    /// bounds-checked) capabilities loop must not leave `deserialize_token`
    /// reading the timestamp fields past the end of the buffer - previously
    /// `data[offset..offset+8].try_into().unwrap()` had no bounds check
    /// there, unlike the nonce/signature reads later in the same function.
    #[test]
    fn test_deserialize_token_rejects_truncated_timestamps_without_panicking() {
        // 184 bytes = exactly the minimum-size gate's cap_count=0 baseline.
        let mut data = alloc::vec![0u8; 184];
        data[0..4].copy_from_slice(b"ATKN");
        // token_id (16) / issuer_id (32) / subject_id (32) left zeroed.
        data[84] = TrustTier::Application as u8; // tier byte at offset 4+16+32+32
        // cap_count = 45: each 2-byte capability read is individually
        // bounds-checked and passes (87 + 2*45 = 177 <= 184), but that
        // leaves only 7 bytes for the 8-byte issued_at_ms read right after.
        data[85..87].copy_from_slice(&45u16.to_le_bytes());

        let result = deserialize_token(&data);
        assert!(
            matches!(result, Err(TokenError::MalformedData)),
            "must return MalformedData, not panic, on a cap_count-driven truncated buffer"
        );
    }
}
