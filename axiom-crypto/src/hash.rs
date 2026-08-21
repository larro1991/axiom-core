//! BLAKE3 hashing for intent hashes

use axiom_types::crypto::IntentHash;
use axiom_types::intent::IntentDescriptor;

/// Intent hasher using BLAKE3
pub struct IntentHasher {
    hasher: blake3::Hasher,
}

impl IntentHasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Hash an intent descriptor to produce an IntentHash
    pub fn hash_intent(intent: &IntentDescriptor) -> IntentHash {
        let mut hasher = blake3::Hasher::new();

        // Hash capability
        hasher.update(intent.capability.as_bytes());

        // Hash constraints (sorted by key for canonical form)
        let mut sorted_constraints = intent.constraints.clone();
        sorted_constraints.sort_by(|a, b| a.key.cmp(&b.key));

        for constraint in &sorted_constraints {
            hasher.update(constraint.key.as_bytes());
            // Hash the value based on type
            match &constraint.value {
                axiom_types::intent::ConstraintValue::String(s) => {
                    hasher.update(&[0x00]);
                    hasher.update(s.as_bytes());
                }
                axiom_types::intent::ConstraintValue::Int(i) => {
                    hasher.update(&[0x01]);
                    hasher.update(&i.to_be_bytes());
                }
                axiom_types::intent::ConstraintValue::Float(f) => {
                    hasher.update(&[0x02]);
                    hasher.update(&f.to_be_bytes());
                }
                axiom_types::intent::ConstraintValue::Bool(b) => {
                    hasher.update(&[0x03]);
                    hasher.update(&[*b as u8]);
                }
                axiom_types::intent::ConstraintValue::Range { min, max } => {
                    hasher.update(&[0x04]);
                    hasher.update(&min.to_be_bytes());
                    hasher.update(&max.to_be_bytes());
                }
                axiom_types::intent::ConstraintValue::OneOf(values) => {
                    hasher.update(&[0x05]);
                    for v in values {
                        hasher.update(v.as_bytes());
                    }
                }
            }
        }

        // Hash priority and TTL
        hasher.update(&[intent.priority]);
        hasher.update(&intent.ttl_ms.to_be_bytes());

        // Finalize and truncate to 128 bits
        let hash = hasher.finalize();
        let mut result = [0u8; 16];
        result.copy_from_slice(&hash.as_bytes()[..16]);

        IntentHash::from_bytes(result)
    }

    /// Hash arbitrary bytes
    pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

impl Default for IntentHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_types::intent::IntentBuilder;

    #[test]
    fn test_intent_hash_deterministic() {
        let intent = IntentBuilder::new("inference.llm")
            .string_constraint("model", "llama-3")
            .int_constraint("max_tokens", 512)
            .build();

        let hash1 = IntentHasher::hash_intent(&intent);
        let hash2 = IntentHasher::hash_intent(&intent);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_intent_hash_different_for_different_intents() {
        let intent1 = IntentBuilder::new("inference.llm")
            .string_constraint("model", "llama-3")
            .build();

        let intent2 = IntentBuilder::new("inference.llm")
            .string_constraint("model", "gpt-4")
            .build();

        let hash1 = IntentHasher::hash_intent(&intent1);
        let hash2 = IntentHasher::hash_intent(&intent2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_constraint_order_independent() {
        // Due to canonicalization, order shouldn't matter
        let intent1 = IntentBuilder::new("inference.llm")
            .string_constraint("model", "llama-3")
            .int_constraint("max_tokens", 512)
            .build();

        // Build with constraints in different order
        let mut intent2 = IntentDescriptor::new("inference.llm");
        intent2.constraints.push(axiom_types::intent::Constraint::int("max_tokens", 512));
        intent2.constraints.push(axiom_types::intent::Constraint::string("model", "llama-3"));
        intent2.canonicalize();

        let hash1 = IntentHasher::hash_intent(&intent1);
        let hash2 = IntentHasher::hash_intent(&intent2);

        assert_eq!(hash1, hash2);
    }
}
