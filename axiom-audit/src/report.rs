//! Compliance reporting
//!
//! Generate audit reports for HIPAA, SOC2, and other compliance frameworks.

use alloc::string::String;
use alloc::vec::Vec;

use crate::event::EventType;
use crate::log::AuditLog;
use crate::sensitivity::Sensitivity;

/// Type of compliance report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    /// HIPAA Security Rule compliance
    HipaaSecurityRule,
    /// HIPAA Privacy Rule compliance
    HipaaPrivacyRule,
    /// SOC2 Type I
    Soc2Type1,
    /// SOC2 Type II
    Soc2Type2,
    /// HITRUST CSF
    HitrustCsf,
    /// General security audit
    SecurityAudit,
    /// Access audit (who accessed what)
    AccessAudit,
    /// Incident report
    IncidentReport,
}

/// Finding severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational
    Info = 0,
    /// Low severity
    Low = 1,
    /// Medium severity
    Medium = 2,
    /// High severity
    High = 3,
    /// Critical severity
    Critical = 4,
}

/// A compliance finding
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding ID
    pub id: String,
    /// Severity
    pub severity: Severity,
    /// Category (e.g., "Access Control", "Audit Logging")
    pub category: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Affected control (e.g., "164.312(a)(1)")
    pub control: Option<String>,
    /// Remediation recommendation
    pub remediation: Option<String>,
    /// Evidence (record references)
    pub evidence: Vec<u64>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        id: &str,
        severity: Severity,
        category: &str,
        title: &str,
        description: &str,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            category: category.into(),
            title: title.into(),
            description: description.into(),
            control: None,
            remediation: None,
            evidence: Vec::new(),
        }
    }

    /// Add control reference
    pub fn with_control(mut self, control: &str) -> Self {
        self.control = Some(control.into());
        self
    }

    /// Add remediation guidance
    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add evidence record
    pub fn with_evidence(mut self, record_seq: u64) -> Self {
        self.evidence.push(record_seq);
        self
    }
}

/// Statistics for a report section
#[derive(Debug, Clone, Default)]
pub struct ReportStats {
    /// Total events in period
    pub total_events: u64,
    /// Events by type
    pub by_type: hashbrown::HashMap<EventType, u64>,
    /// Events by sensitivity
    pub by_sensitivity: hashbrown::HashMap<Sensitivity, u64>,
    /// Successful access count
    pub access_granted: u64,
    /// Denied access count
    pub access_denied: u64,
    /// Security events
    pub security_events: u64,
    /// Unique subjects (users/nodes)
    pub unique_subjects: u64,
    /// Unique resources accessed
    pub unique_resources: u64,
}

/// A compliance report
#[derive(Debug, Clone)]
pub struct ComplianceReport {
    /// Report type
    pub report_type: ReportType,
    /// Report title
    pub title: String,
    /// Generated timestamp
    pub generated_at: u64,
    /// Reporting period start
    pub period_start: u64,
    /// Reporting period end
    pub period_end: u64,
    /// Node ID that generated this
    pub generated_by: [u8; 32],
    /// Executive summary
    pub summary: String,
    /// Statistics
    pub stats: ReportStats,
    /// Findings
    pub findings: Vec<Finding>,
    /// Overall compliance status
    pub compliant: bool,
    /// Report hash (for integrity)
    pub hash: [u8; 32],
}

impl ComplianceReport {
    /// Create a new report
    pub fn new(
        report_type: ReportType,
        title: String,
        period_start: u64,
        period_end: u64,
        generated_by: [u8; 32],
        generated_at: u64,
    ) -> Self {
        Self {
            report_type,
            title,
            generated_at,
            period_start,
            period_end,
            generated_by,
            summary: String::new(),
            stats: ReportStats::default(),
            findings: Vec::new(),
            compliant: true,
            hash: [0u8; 32],
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        if finding.severity >= Severity::High {
            self.compliant = false;
        }
        self.findings.push(finding);
    }

    /// Set summary
    pub fn set_summary(&mut self, summary: String) {
        self.summary = summary;
    }

    /// Finalize and compute hash
    pub fn finalize(&mut self) {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(self.title.as_bytes());
        hasher.update(&self.generated_at.to_le_bytes());
        hasher.update(&self.period_start.to_le_bytes());
        hasher.update(&self.period_end.to_le_bytes());
        hasher.update(&self.generated_by);
        hasher.update(&[self.compliant as u8]);
        hasher.update(&(self.findings.len() as u64).to_le_bytes());

        self.hash = *hasher.finalize().as_bytes();
    }

    /// Get critical findings count
    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    /// Get high severity findings count
    pub fn high_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count()
    }

    /// Generate report sections for HIPAA
    pub fn hipaa_sections(&self) -> Vec<(&str, &str)> {
        vec![
            ("164.312(a)(1)", "Access Control"),
            ("164.312(b)", "Audit Controls"),
            ("164.312(c)(1)", "Integrity Controls"),
            ("164.312(d)", "Person or Entity Authentication"),
            ("164.312(e)(1)", "Transmission Security"),
        ]
    }
}

/// Report generator
#[cfg(feature = "std")]
pub struct ReportGenerator {
    node_id: [u8; 32],
}

#[cfg(feature = "std")]
impl ReportGenerator {
    /// Create new generator
    pub fn new(node_id: [u8; 32]) -> Self {
        Self { node_id }
    }

    /// Generate HIPAA Security Rule report
    pub fn generate_hipaa_security(
        &self,
        log: &AuditLog,
        period_start: u64,
        period_end: u64,
        now: u64,
    ) -> ComplianceReport {
        let mut report = ComplianceReport::new(
            ReportType::HipaaSecurityRule,
            "HIPAA Security Rule Compliance Report".into(),
            period_start,
            period_end,
            self.node_id,
            now,
        );

        // Gather statistics
        let records = log.in_time_range(period_start, period_end);
        report.stats.total_events = records.len() as u64;

        let mut subjects = hashbrown::HashSet::new();
        let mut resources = hashbrown::HashSet::new();

        for record in &records {
            *report.stats.by_type.entry(record.event.event_type).or_insert(0) += 1;

            if let Some(sens) = record.event.sensitivity {
                *report.stats.by_sensitivity.entry(sens).or_insert(0) += 1;
            }

            subjects.insert(record.event.subject);
            if let Some(res) = record.event.resource {
                resources.insert(res);
            }

            if record.event.outcome.is_success() {
                report.stats.access_granted += 1;
            } else if record.event.outcome.is_denied() {
                report.stats.access_denied += 1;
            }

            if record.event.event_type == EventType::Security {
                report.stats.security_events += 1;
            }
        }

        report.stats.unique_subjects = subjects.len() as u64;
        report.stats.unique_resources = resources.len() as u64;

        // Check for findings

        // F1: Audit logging active?
        if report.stats.total_events == 0 {
            report.add_finding(
                Finding::new(
                    "HIPAA-001",
                    Severity::Critical,
                    "Audit Controls",
                    "No audit events recorded",
                    "No audit events were recorded during the reporting period. \
                     This may indicate audit logging is not functioning.",
                )
                .with_control("164.312(b)")
                .with_remediation("Verify audit logging is enabled and functioning."),
            );
        }

        // F2: PHI access logged?
        let phi_access = report.stats.by_sensitivity.get(&Sensitivity::Phi).copied().unwrap_or(0);
        if phi_access > 0 {
            // Good - we're tracking PHI access
        }

        // F3: Security events require review
        if report.stats.security_events > 0 {
            report.add_finding(
                Finding::new(
                    "HIPAA-002",
                    Severity::Medium,
                    "Security Management",
                    "Security events detected",
                    &alloc::format!(
                        "{} security events were detected during the reporting period. \
                         Review recommended.",
                        report.stats.security_events
                    ),
                )
                .with_control("164.308(a)(1)(ii)(D)")
                .with_remediation("Review security events and document response actions."),
            );
        }

        // F4: Denied access rate
        let total_access = report.stats.access_granted + report.stats.access_denied;
        if total_access > 0 {
            let denial_rate = report.stats.access_denied as f64 / total_access as f64;
            if denial_rate > 0.1 {
                report.add_finding(
                    Finding::new(
                        "HIPAA-003",
                        Severity::Low,
                        "Access Control",
                        "Elevated access denial rate",
                        &alloc::format!(
                            "Access denial rate is {:.1}%. This may indicate \
                             misconfigured permissions or unauthorized access attempts.",
                            denial_rate * 100.0
                        ),
                    )
                    .with_control("164.312(a)(1)")
                    .with_remediation("Review denied access attempts for patterns."),
                );
            }
        }

        // Verify chain integrity
        let verification = log.verify_chain();
        if !verification.valid {
            report.add_finding(
                Finding::new(
                    "HIPAA-004",
                    Severity::Critical,
                    "Integrity Controls",
                    "Audit log integrity violation",
                    &alloc::format!(
                        "Audit log hash chain verification failed at record {}. \
                         Log may have been tampered with.",
                        verification.first_invalid.unwrap_or(0)
                    ),
                )
                .with_control("164.312(c)(1)")
                .with_remediation(
                    "Investigate log tampering. Preserve evidence for incident response.",
                ),
            );
        }

        // Generate summary
        report.set_summary(alloc::format!(
            "HIPAA Security Rule compliance assessment for period {} to {}.\n\n\
             Total events: {}\n\
             PHI access events: {}\n\
             Security events: {}\n\
             Unique users: {}\n\
             Findings: {} ({} critical, {} high)\n\n\
             Overall status: {}",
            period_start,
            period_end,
            report.stats.total_events,
            phi_access,
            report.stats.security_events,
            report.stats.unique_subjects,
            report.findings.len(),
            report.critical_count(),
            report.high_count(),
            if report.compliant { "COMPLIANT" } else { "NON-COMPLIANT" }
        ));

        report.finalize();
        report
    }

    /// Generate access audit report
    pub fn generate_access_audit(
        &self,
        log: &AuditLog,
        subject: Option<[u8; 32]>,
        resource: Option<[u8; 32]>,
        period_start: u64,
        period_end: u64,
        now: u64,
    ) -> ComplianceReport {
        let mut report = ComplianceReport::new(
            ReportType::AccessAudit,
            "Access Audit Report".into(),
            period_start,
            period_end,
            self.node_id,
            now,
        );

        let records = if let Some(subj) = subject {
            log.by_subject(&subj)
                .into_iter()
                .filter(|r| r.event.timestamp >= period_start && r.event.timestamp <= period_end)
                .collect::<Vec<_>>()
        } else if let Some(res) = resource {
            log.by_resource(&res)
                .into_iter()
                .filter(|r| r.event.timestamp >= period_start && r.event.timestamp <= period_end)
                .collect::<Vec<_>>()
        } else {
            log.in_time_range(period_start, period_end)
        };

        report.stats.total_events = records.len() as u64;

        for record in &records {
            if record.event.event_type == EventType::Access {
                if record.event.outcome.is_success() {
                    report.stats.access_granted += 1;
                } else {
                    report.stats.access_denied += 1;
                }
            }
        }

        report.set_summary(alloc::format!(
            "Access audit for period {} to {}.\n\
             Total access events: {}\n\
             Access granted: {}\n\
             Access denied: {}",
            period_start,
            period_end,
            report.stats.total_events,
            report.stats.access_granted,
            report.stats.access_denied,
        ));

        report.finalize();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AccessOutcome, AccessType, AuditEvent, SecurityEventType};
    use crate::log::AuditLog;

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(
            "TEST-001",
            Severity::High,
            "Access Control",
            "Test Finding",
            "This is a test finding.",
        )
        .with_control("164.312(a)")
        .with_remediation("Fix the issue.");

        assert_eq!(finding.severity, Severity::High);
        assert!(finding.control.is_some());
    }

    #[test]
    fn test_hipaa_report_generation() {
        let mut log = AuditLog::new([0u8; 32]);

        // Add some events
        for i in 0..10 {
            let event = AuditEvent::access(
                [1u8; 32],
                [2u8; 32],
                AccessType::Read,
                AccessOutcome::Success,
                Sensitivity::Phi,
                i * 1000,
            );
            log.record(event).unwrap();
        }

        // Add a security event
        log.record(AuditEvent::security(
            [3u8; 32],
            SecurityEventType::Impersonation,
            "Test impersonation".into(),
            5000,
        ))
        .unwrap();

        let generator = ReportGenerator::new([0u8; 32]);
        let report = generator.generate_hipaa_security(&log, 0, 20000, 20001);

        assert_eq!(report.stats.total_events, 11);
        assert_eq!(report.stats.security_events, 1);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_empty_log_finding() {
        let log = AuditLog::new([0u8; 32]);
        let generator = ReportGenerator::new([0u8; 32]);
        let report = generator.generate_hipaa_security(&log, 0, 10000, 10001);

        // Should have critical finding for no events
        assert!(report.critical_count() > 0);
        assert!(!report.compliant);
    }
}
