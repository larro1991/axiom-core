//! AXIOM Audit & Compliance Module
//!
//! Provides HIPAA, SOC2, and HITRUST ready audit logging and compliance features.
//!
//! # Key Features
//!
//! - **Tamper-evident logging**: Hash-chained audit records
//! - **PHI tagging**: Mark sensitive data for special handling
//! - **Access tracking**: Who accessed what, when, from where
//! - **Retention policies**: Automatic data lifecycle management
//! - **Compliance reporting**: Generate audit reports
//!
//! # HIPAA Technical Safeguards Coverage
//!
//! | Requirement (§164.312) | Implementation |
//! |------------------------|----------------|
//! | Access Control | `AccessEvent`, capability-based |
//! | Audit Controls | `AuditLog`, hash-chained records |
//! | Integrity Controls | `AuditRecord` with BLAKE3 |
//! | Transmission Security | Handled by axiom-crypto |
//!
//! # Example
//!
//! ```ignore
//! use axiom_audit::{AuditLog, AuditEvent, Sensitivity};
//!
//! let mut log = AuditLog::new(node_id);
//!
//! // Log an access event
//! log.record(AuditEvent::access(
//!     subject_id,
//!     resource_id,
//!     AccessType::Read,
//!     Sensitivity::Phi,
//! ));
//!
//! // Verify integrity
//! assert!(log.verify_chain());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod event;
pub mod external;
pub mod log;
pub mod retention;
pub mod sensitivity;
pub mod report;

#[cfg(test)]

pub use event::{AuditEvent, EventType, AccessType, AccessOutcome};
pub use external::{
    ExternalAuditWriter, ExternalAuditEntry, ExternalAuditError,
    AuditEventType, WitnessReceipt, CollectorEndpoint, WriterConfig,
};
pub use log::{AuditLog, AuditRecord, AuditError, ChainVerification};
pub use retention::{RetentionPolicy, RetentionAction, DataLifecycle};
pub use sensitivity::{Sensitivity, PhiType, DataClassification};
pub use report::{ComplianceReport, ReportType, Finding, Severity};
