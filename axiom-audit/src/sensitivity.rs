//! Data sensitivity classification
//!
//! Implements data classification for compliance with HIPAA, GDPR, and other regulations.

use alloc::string::String;
use alloc::vec::Vec;

/// Data sensitivity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// Public data - no restrictions
    Public = 0,
    /// Internal use only
    Internal = 1,
    /// Confidential business data
    Confidential = 2,
    /// Protected Health Information (HIPAA)
    Phi = 3,
    /// Personally Identifiable Information (GDPR, CCPA)
    Pii = 4,
    /// Restricted - highest sensitivity
    Restricted = 5,
}

impl Sensitivity {
    /// Check if this data requires encryption at rest
    pub fn requires_encryption_at_rest(&self) -> bool {
        *self >= Sensitivity::Confidential
    }

    /// Check if access must be logged
    pub fn requires_access_logging(&self) -> bool {
        *self >= Sensitivity::Confidential
    }

    /// Check if this is regulated data (HIPAA/GDPR)
    pub fn is_regulated(&self) -> bool {
        matches!(self, Sensitivity::Phi | Sensitivity::Pii)
    }

    /// Minimum retention period in days (regulatory requirement)
    pub fn min_retention_days(&self) -> u32 {
        match self {
            Sensitivity::Phi => 2190,      // 6 years (HIPAA)
            Sensitivity::Pii => 1095,      // 3 years (GDPR reasonable)
            Sensitivity::Restricted => 2555, // 7 years (financial)
            _ => 365,                       // 1 year default
        }
    }

    /// Maximum retention period in days (data minimization)
    pub fn max_retention_days(&self) -> Option<u32> {
        match self {
            Sensitivity::Pii => Some(1095), // GDPR data minimization
            _ => None,                       // No max for others
        }
    }
}

/// Types of Protected Health Information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhiType {
    /// Patient name
    Name,
    /// Geographic data smaller than state
    Geography,
    /// Dates (birth, admission, discharge, death)
    Dates,
    /// Phone numbers
    Phone,
    /// Fax numbers
    Fax,
    /// Email addresses
    Email,
    /// Social Security Number
    Ssn,
    /// Medical Record Number
    Mrn,
    /// Health Plan Beneficiary Number
    HealthPlanId,
    /// Account numbers
    AccountNumber,
    /// Certificate/license numbers
    LicenseNumber,
    /// Vehicle identifiers
    VehicleId,
    /// Device identifiers and serial numbers
    DeviceId,
    /// URLs
    Url,
    /// IP addresses
    IpAddress,
    /// Biometric identifiers
    Biometric,
    /// Photos
    Photo,
    /// Any other unique identifier
    Other,
}

impl PhiType {
    /// All 18 HIPAA identifiers
    pub fn all_hipaa_identifiers() -> &'static [PhiType] {
        &[
            PhiType::Name,
            PhiType::Geography,
            PhiType::Dates,
            PhiType::Phone,
            PhiType::Fax,
            PhiType::Email,
            PhiType::Ssn,
            PhiType::Mrn,
            PhiType::HealthPlanId,
            PhiType::AccountNumber,
            PhiType::LicenseNumber,
            PhiType::VehicleId,
            PhiType::DeviceId,
            PhiType::Url,
            PhiType::IpAddress,
            PhiType::Biometric,
            PhiType::Photo,
            PhiType::Other,
        ]
    }

    /// Check if this identifier can be used for Safe Harbor de-identification
    pub fn safe_harbor_removable(&self) -> bool {
        // All 18 identifiers must be removed for Safe Harbor
        true
    }
}

/// Complete data classification
#[derive(Debug, Clone)]
pub struct DataClassification {
    /// Overall sensitivity level
    pub sensitivity: Sensitivity,
    /// PHI types present (if any)
    pub phi_types: Vec<PhiType>,
    /// Data owner (NodeId as bytes)
    pub owner: [u8; 32],
    /// Classification timestamp
    pub classified_at: u64,
    /// Classification reason/source
    pub reason: Option<String>,
    /// Retention override (days)
    pub retention_override: Option<u32>,
}

impl DataClassification {
    /// Create a new classification
    pub fn new(sensitivity: Sensitivity, owner: [u8; 32], now: u64) -> Self {
        Self {
            sensitivity,
            phi_types: Vec::new(),
            owner,
            classified_at: now,
            reason: None,
            retention_override: None,
        }
    }

    /// Mark as PHI with specific identifiers
    pub fn with_phi(mut self, phi_types: Vec<PhiType>) -> Self {
        self.sensitivity = Sensitivity::Phi;
        self.phi_types = phi_types;
        self
    }

    /// Add classification reason
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Override retention period
    pub fn with_retention(mut self, days: u32) -> Self {
        self.retention_override = Some(days);
        self
    }

    /// Get effective retention period
    pub fn retention_days(&self) -> u32 {
        self.retention_override
            .unwrap_or_else(|| self.sensitivity.min_retention_days())
    }

    /// Check if data can be de-identified using Safe Harbor method
    pub fn can_safe_harbor_deidentify(&self) -> bool {
        // All PHI types are Safe Harbor removable
        self.sensitivity == Sensitivity::Phi
    }

    /// Check if this classification requires BAA (Business Associate Agreement)
    pub fn requires_baa(&self) -> bool {
        self.sensitivity == Sensitivity::Phi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitivity_ordering() {
        assert!(Sensitivity::Phi > Sensitivity::Confidential);
        assert!(Sensitivity::Restricted > Sensitivity::Phi);
        assert!(Sensitivity::Public < Sensitivity::Internal);
    }

    #[test]
    fn test_phi_retention() {
        assert_eq!(Sensitivity::Phi.min_retention_days(), 2190); // 6 years
    }

    #[test]
    fn test_classification() {
        let owner = [1u8; 32];
        let class = DataClassification::new(Sensitivity::Phi, owner, 1000)
            .with_phi(vec![PhiType::Name, PhiType::Mrn])
            .with_reason("Patient record".into());

        assert_eq!(class.sensitivity, Sensitivity::Phi);
        assert_eq!(class.phi_types.len(), 2);
        assert!(class.requires_baa());
    }

    #[test]
    fn test_hipaa_identifiers() {
        let identifiers = PhiType::all_hipaa_identifiers();
        assert_eq!(identifiers.len(), 18); // HIPAA defines 18 identifiers
    }
}
