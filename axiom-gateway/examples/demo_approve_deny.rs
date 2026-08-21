//! README demo asset only - NOT shipped/production code, NOT wired into
//! forge-node. Every type used here (`Tier2ApprovalFlow`, `CliApprovalChannel`,
//! `MockDestructiveCapability`, `AuditLog`) is real, shipped `axiom-gateway`
//! library code, gated behind the `test-utils` feature specifically for this
//! kind of end-to-end rehearsal - see `MockDestructiveCapability`'s own doc
//! comment. This just assembles them into a runnable terminal demo instead
//! of a test assertion. Real approve/deny cycle, real tamper-evident audit
//! log, real Tier2ApprovalFlow state machine - the only thing "mock" is the
//! backend action itself (a flag flip, no real infrastructure touched),
//! and the approval channel is the terminal instead of Telegram.
//!
//! Run: cargo run --example demo_approve_deny --features test-utils

use axiom_gateway::approval::{CliApprovalChannel, MockDestructiveCapability, Tier2ApprovalFlow};
use axiom_gateway::audit::AuditLog;
use axiom_gateway::policy::CapabilityPolicy;
use axiom_crypto::identity::Keypair;
use axiom_types::intent::Constraint as C;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

fn pause(ms: u64) {
    sleep(Duration::from_millis(ms));
}

fn main() {
    let audit_path = std::env::temp_dir().join("axiom-readme-demo-audit.jsonl");
    let _ = std::fs::remove_file(&audit_path);
    let log = AuditLog::open(&audit_path).expect("open fresh audit log");
    let policy = Arc::new(CapabilityPolicy::for_test_with_protected_resources(Some(Vec::new())));
    let proposer = Keypair::generate().node_id();

    println!("AXIOM Tier 2 approval - real flow, terminal channel\n");
    pause(1300);

    // --- Round 1: approve ---
    println!(">> Agent proposes a Tier 2 (destructive) action...\n");
    pause(1000);
    let cap1 = MockDestructiveCapability::new();
    let flow1 = Tier2ApprovalFlow::new(CliApprovalChannel::stdio(), Arc::clone(&policy));
    let params1 = vec![C::string("target", "mock-service"), C::bool("enable", true)];
    let id1 = flow1.propose(proposer, &cap1, params1).expect("propose");
    let status1 = flow1.decide_and_execute(id1, &cap1).expect("decide_and_execute");
    let record1 = flow1.record(id1).expect("record exists");
    log.log_tier2_linked_record(&record1).expect("log");
    println!("\n   Intent status: {status1:?}");
    println!("   Mock backend flag: {}", cap1.flag());
    pause(4000);

    println!("\n----------------------------------------\n");
    pause(1300);

    // --- Round 2: deny ---
    println!(">> Agent proposes another Tier 2 (destructive) action...\n");
    pause(1000);
    let cap2 = MockDestructiveCapability::new();
    let flow2 = Tier2ApprovalFlow::new(CliApprovalChannel::stdio(), Arc::clone(&policy));
    let params2 = vec![C::string("target", "mock-service"), C::bool("enable", true)];
    let id2 = flow2.propose(proposer, &cap2, params2).expect("propose");
    let status2 = flow2.decide_and_execute(id2, &cap2).expect("decide_and_execute");
    let record2 = flow2.record(id2).expect("record exists");
    log.log_tier2_linked_record(&record2).expect("log");
    println!("\n   Intent status: {status2:?}");
    println!("   Mock backend flag: {}  <- unchanged, action did NOT execute", cap2.flag());
    println!("   Audit log entry: decision={{allowed: false}}, tamper-evident, hash-chained.");
    pause(4500);
}
