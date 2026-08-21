//! AXIOM Integration Tests
//!
//! Tests that exercise the full stack:
//! - Agent lifecycle with resource claiming
//! - Semantic capability discovery
//! - Multi-agent communication
//! - End-to-end request/response

#[cfg(test)]
mod agent_lifecycle;

#[cfg(test)]
mod discovery;

#[cfg(test)]
mod multi_agent;
