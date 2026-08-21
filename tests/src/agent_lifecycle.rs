//! Agent Lifecycle Integration Tests
//!
//! Tests the full lifecycle of an agent:
//! - Creation with identity
//! - Resource claiming from HAL
//! - Task execution
//! - Graceful shutdown

use axiom_hal::{
    Capability, CapabilityClass, CapabilityMetrics,
    Resource, AccessMethod,
    ComputeCapability, ComputeType, TensorOp, ComputeDataType,
    MemoryCapability, MemoryType,
};
use axiom_runtime::{
    Agent, AgentConfig, AgentState,
    AgentContext, ResourceClaim,
    Task, TaskPriority, Executor,
};
use axiom_types::trust::TrustLevel;
use std::sync::atomic::{AtomicU32, Ordering};

/// Create a realistic GPU resource
fn create_gpu(name: &str, tflops: f64, memory_gb: u32) -> Resource {
    let compute_cap = ComputeCapability::new(ComputeType::Gpu)
        .with_dtype(ComputeDataType::Fp16)
        .with_dtype(ComputeDataType::Bf16)
        .with_op(TensorOp::MatMul, ComputeDataType::Fp16, tflops as f32)
        .with_op(TensorOp::Attention, ComputeDataType::Fp16, (tflops * 0.8) as f32)
        .with_memory(
            (memory_gb as u64) * 1_000_000_000,
            900_000_000_000, // 900 GB/s HBM
        )
        .with_compute_units(132);

    Resource::new(name)
        .with_capability(
            Capability::new(CapabilityClass::Compute, "compute:tensor:fp16")
                .with_tag("gpu")
                .with_tag("cuda")
                .with_metrics(CapabilityMetrics::compute(tflops, 100))
                .with_specific(axiom_hal::capability::SpecificCapability::Compute(compute_cap))
        )
        .with_access(AccessMethod::CommandQueue {
            queue_base: 0xFE00_0000,
            queue_size: 1024,
            doorbell: 0xFE00_1000,
        })
}

/// Create a memory resource
fn create_hbm(name: &str, capacity_gb: u32) -> Resource {
    let mem_cap = MemoryCapability::new(MemoryType::Hbm, (capacity_gb as u64) * 1_000_000_000);

    Resource::new(name)
        .with_capability(
            Capability::new(CapabilityClass::Memory, "memory:hbm")
                .with_tag("high-bandwidth")
                .with_metrics(CapabilityMetrics::memory(capacity_gb, 900))
                .with_specific(axiom_hal::capability::SpecificCapability::Memory(mem_cap))
        )
        .with_access(AccessMethod::Mmio {
            base: 0x1_0000_0000,
            size: (capacity_gb as u64) * 1_000_000_000,
            cached: false,
        })
}

#[test]
fn test_agent_full_lifecycle() {
    // Create agent with requirements
    let config = AgentConfig::new("inference-agent")
        .require("compute:tensor")
        .prefer("memory:hbm")
        .with_trust(TrustLevel::Sig)
        .with_max_memory(80_000_000_000);

    let agent = Agent::new(config);
    let agent_id = agent.id().clone();
    let mut ctx = AgentContext::new(agent);

    // Register resources
    ctx.register_resource(create_gpu("GPU0", 100.0, 80));
    ctx.register_resource(create_hbm("HBM0", 80));

    // Verify initial state
    assert_eq!(ctx.agent().state(), AgentState::Created);

    // Initialize - should claim compute:tensor (required) and memory:hbm (preferred)
    ctx.initialize().expect("Failed to initialize");

    // Verify ready state
    assert_eq!(ctx.agent().state(), AgentState::Ready);
    assert!(ctx.has_resource("compute:tensor"));
    assert!(ctx.has_resource("memory:hbm")); // Preferred was available

    // Verify claims
    assert_eq!(ctx.claims().len(), 2);

    // Shutdown
    ctx.shutdown().expect("Failed to shutdown");

    // Verify terminated state
    assert_eq!(ctx.agent().state(), AgentState::Terminated);
    assert!(ctx.claims().is_empty());
}

#[test]
fn test_agent_missing_required_resource() {
    let config = AgentConfig::new("needy-agent")
        .require("compute:quantum"); // Not available!

    let agent = Agent::new(config);
    let mut ctx = AgentContext::new(agent);

    // Only register a GPU (no quantum computer)
    ctx.register_resource(create_gpu("GPU0", 100.0, 80));

    // Initialize should fail
    let result = ctx.initialize();
    assert!(result.is_err());

    // Should be terminated
    assert_eq!(ctx.agent().state(), AgentState::Terminated);
}

#[test]
fn test_agent_task_execution() {
    // Track execution
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let config = AgentConfig::new("worker-agent")
        .require("compute:tensor");

    let agent = Agent::new(config);
    let mut ctx = AgentContext::new(agent);

    ctx.register_resource(create_gpu("GPU0", 100.0, 80));
    ctx.initialize().expect("Failed to initialize");

    // Create executor
    let mut executor = Executor::new();

    // Submit tasks with different priorities
    executor.submit(
        Task::new("low-task", |_| {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }).with_priority(TaskPriority::Low)
    );

    executor.submit(
        Task::new("critical-task", |_| {
            COUNTER.fetch_add(10, Ordering::SeqCst);
            Ok(())
        }).with_priority(TaskPriority::Critical)
    );

    executor.submit(
        Task::new("normal-task", |_| {
            COUNTER.fetch_add(100, Ordering::SeqCst);
            Ok(())
        }).with_priority(TaskPriority::Normal)
    );

    // Run all tasks
    let count = executor.run_all(&mut ctx).expect("Failed to run tasks");

    assert_eq!(count, 3);
    assert_eq!(executor.stats().tasks_completed, 3);

    // Critical should run first (10), then normal (100), then low (1)
    // Total: 111
    assert_eq!(COUNTER.load(Ordering::SeqCst), 111);

    ctx.shutdown().unwrap();
}

#[test]
fn test_agent_provides_capability() {
    let config = AgentConfig::new("llm-provider");

    let mut agent = Agent::new(config);

    // Agent provides LLM capabilities
    agent.provide_capability("llm:completion");
    agent.provide_capability("llm:embedding");

    let caps = agent.provided_capabilities();
    assert_eq!(caps.len(), 2);
    assert!(caps.contains(&String::from("llm:completion")));
    assert!(caps.contains(&String::from("llm:embedding")));
}

#[test]
fn test_resource_access_method() {
    let config = AgentConfig::new("gpu-user")
        .require("compute:tensor");

    let agent = Agent::new(config);
    let mut ctx = AgentContext::new(agent);

    let gpu = create_gpu("GPU0", 100.0, 80);
    ctx.register_resource(gpu);
    ctx.initialize().unwrap();

    // Get the claim
    let claims: Vec<_> = ctx.claims().values().collect();
    let gpu_claim = claims.iter()
        .find(|c| c.capability == "compute:tensor")
        .expect("Should have GPU claim");

    // Verify access method
    match &gpu_claim.handle.access {
        AccessMethod::CommandQueue { queue_base, queue_size, doorbell } => {
            assert_eq!(*queue_base, 0xFE00_0000);
            assert_eq!(*queue_size, 1024);
            assert_eq!(*doorbell, 0xFE00_1000);
        }
        _ => panic!("Expected CommandQueue access method"),
    }

    ctx.shutdown().unwrap();
}

#[test]
fn test_multiple_resources_same_type() {
    let config = AgentConfig::new("multi-gpu")
        .require("compute:tensor");

    let agent = Agent::new(config);
    let mut ctx = AgentContext::new(agent);

    // Register multiple GPUs
    ctx.register_resource(create_gpu("GPU0", 100.0, 80));
    ctx.register_resource(create_gpu("GPU1", 150.0, 80)); // Faster

    // Initialize claims the best available
    ctx.initialize().unwrap();

    // Should have claimed one GPU
    assert_eq!(ctx.claims().len(), 1);

    // Can discover both GPUs
    let gpus = ctx.discover_resources("compute:tensor");
    // One is claimed, one is still available
    assert_eq!(gpus.len(), 1); // Only available ones returned

    ctx.shutdown().unwrap();
}
