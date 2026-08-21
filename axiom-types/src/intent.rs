//! Intent descriptor types for capability-based addressing

use alloc::string::String;
use alloc::vec::Vec;
use crate::crypto::IntentHash;

/// Constraint value types
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConstraintValue {
    /// UTF-8 string value
    String(String),
    /// 64-bit signed integer
    Int(i64),
    /// 64-bit float
    Float(f64),
    /// Boolean
    Bool(bool),
    /// Numeric range (min, max)
    Range { min: f64, max: f64 },
    /// One of several allowed values
    OneOf(Vec<String>),
}

impl ConstraintValue {
    /// Get the type code for wire format
    pub fn type_code(&self) -> u8 {
        match self {
            Self::String(_) => 0x00,
            Self::Int(_) => 0x01,
            Self::Float(_) => 0x02,
            Self::Bool(_) => 0x03,
            Self::Range { .. } => 0x04,
            Self::OneOf(_) => 0x05,
        }
    }
}

/// A single constraint (key-value pair)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Constraint {
    /// Constraint key
    pub key: String,
    /// Constraint value
    pub value: ConstraintValue,
}

impl Constraint {
    /// Create a new string constraint
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::String(value.into()),
        }
    }

    /// Create a new integer constraint
    pub fn int(key: impl Into<String>, value: i64) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::Int(value),
        }
    }

    /// Create a new float constraint
    pub fn float(key: impl Into<String>, value: f64) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::Float(value),
        }
    }

    /// Create a new boolean constraint
    pub fn bool(key: impl Into<String>, value: bool) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::Bool(value),
        }
    }

    /// Create a new range constraint
    pub fn range(key: impl Into<String>, min: f64, max: f64) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::Range { min, max },
        }
    }

    /// Create a new one-of constraint
    pub fn one_of(key: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            key: key.into(),
            value: ConstraintValue::OneOf(values),
        }
    }
}

/// Intent descriptor for capability-based addressing
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentDescriptor {
    /// Hierarchical capability path (e.g., "inference.llm.chat")
    pub capability: String,
    /// Key-value constraints
    pub constraints: Vec<Constraint>,
    /// Priority level (0-255, higher = more urgent)
    pub priority: u8,
    /// Time-to-live in milliseconds (0 = infinite)
    pub ttl_ms: u32,
    /// Fallback intent hashes if primary unavailable
    pub fallbacks: Vec<IntentHash>,
}

impl IntentDescriptor {
    /// Create a new intent descriptor with default settings
    pub fn new(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            constraints: Vec::new(),
            priority: 128, // Default: mid-priority
            ttl_ms: 30_000, // Default: 30 seconds
            fallbacks: Vec::new(),
        }
    }

    /// Add a constraint
    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set TTL
    pub fn with_ttl_ms(mut self, ttl_ms: u32) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Add a fallback
    pub fn with_fallback(mut self, fallback: IntentHash) -> Self {
        self.fallbacks.push(fallback);
        self
    }

    /// Sort constraints by key for canonical representation
    pub fn canonicalize(&mut self) {
        self.constraints.sort_by(|a, b| a.key.cmp(&b.key));
    }

    /// Check if a given capability matches this intent
    ///
    /// Returns true if `other` is equal to or more specific than this capability.
    /// E.g., "inference.llm.chat" matches "inference.llm"
    pub fn capability_matches(&self, other: &str) -> bool {
        other == self.capability || other.starts_with(&format!("{}.", self.capability))
    }
}

impl Default for IntentDescriptor {
    fn default() -> Self {
        Self::new("")
    }
}

/// Builder for IntentDescriptor with fluent API
pub struct IntentBuilder {
    desc: IntentDescriptor,
}

impl IntentBuilder {
    pub fn new(capability: impl Into<String>) -> Self {
        Self {
            desc: IntentDescriptor::new(capability),
        }
    }

    pub fn constraint(mut self, key: impl Into<String>, value: impl Into<ConstraintValue>) -> Self {
        self.desc.constraints.push(Constraint {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    pub fn string_constraint(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.constraint(key, ConstraintValue::String(value.into()))
    }

    pub fn int_constraint(self, key: impl Into<String>, value: i64) -> Self {
        self.constraint(key, ConstraintValue::Int(value))
    }

    pub fn priority(mut self, priority: u8) -> Self {
        self.desc.priority = priority;
        self
    }

    pub fn ttl_ms(mut self, ttl_ms: u32) -> Self {
        self.desc.ttl_ms = ttl_ms;
        self
    }

    pub fn fallback(mut self, fallback: IntentHash) -> Self {
        self.desc.fallbacks.push(fallback);
        self
    }

    pub fn build(mut self) -> IntentDescriptor {
        self.desc.canonicalize();
        self.desc
    }
}

// Conversion implementations for ConstraintValue
impl From<String> for ConstraintValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for ConstraintValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<i64> for ConstraintValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<f64> for ConstraintValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

impl From<bool> for ConstraintValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_builder() {
        let intent = IntentBuilder::new("inference.llm")
            .string_constraint("model", "llama-3-70b")
            .int_constraint("max_tokens", 512)
            .priority(200)
            .ttl_ms(5000)
            .build();

        assert_eq!(intent.capability, "inference.llm");
        assert_eq!(intent.constraints.len(), 2);
        assert_eq!(intent.priority, 200);
        assert_eq!(intent.ttl_ms, 5000);

        // Constraints should be sorted by key
        assert_eq!(intent.constraints[0].key, "max_tokens");
        assert_eq!(intent.constraints[1].key, "model");
    }

    #[test]
    fn test_capability_matches() {
        let intent = IntentDescriptor::new("inference.llm");

        assert!(intent.capability_matches("inference.llm"));
        assert!(intent.capability_matches("inference.llm.chat"));
        assert!(!intent.capability_matches("inference"));
        assert!(!intent.capability_matches("inference.embedding"));
    }

    #[test]
    fn test_constraint_value_types() {
        assert_eq!(ConstraintValue::String("test".into()).type_code(), 0x00);
        assert_eq!(ConstraintValue::Int(42).type_code(), 0x01);
        assert_eq!(ConstraintValue::Float(3.14).type_code(), 0x02);
        assert_eq!(ConstraintValue::Bool(true).type_code(), 0x03);
        assert_eq!(
            ConstraintValue::Range { min: 0.0, max: 1.0 }.type_code(),
            0x04
        );
        assert_eq!(ConstraintValue::OneOf(vec![]).type_code(), 0x05);
    }
}
