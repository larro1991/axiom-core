//! Tiered Intelligence Architecture
//!
//! Three tiers of intelligence for AI-native networking:
//! - Tier 1: Translators (microseconds) - Pure lookup, no thinking
//! - Tier 2: Smart Agents (milliseconds) - Domain-specific small models
//! - Tier 3: Full AI (seconds) - General reasoning, LLM

pub mod tier1;
pub mod tier2;

pub use tier1::{Translator, TranslatorConfig, TranslateResult};
pub use tier2::{SmartAgent, AgentType, AgentConfig, Decision};
