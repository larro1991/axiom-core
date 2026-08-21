//! Agent Card - A2A-compatible capability advertisement
//!
//! Agent Cards are JSON documents that describe an agent's identity,
//! capabilities, and how to interact with it. Compatible with the
//! A2A protocol's agent discovery mechanism.

use alloc::string::String;
use alloc::vec::Vec;
use axiom_types::crypto::NodeId;

/// Agent Card - describes an agent's identity and capabilities
#[derive(Debug, Clone)]
pub struct AgentCard {
    /// Agent's unique identifier
    pub id: NodeId,
    /// Human-readable name
    pub name: String,
    /// Description of what this agent does
    pub description: String,
    /// Version of the agent
    pub version: String,
    /// Provider/organization info
    pub provider: Option<ProviderInfo>,
    /// Service endpoint URL
    pub endpoint: String,
    /// Supported protocol versions
    pub protocol_versions: Vec<String>,
    /// Agent's skills/capabilities
    pub skills: Vec<AgentSkill>,
    /// Supported input modes
    pub input_modes: Vec<DataMode>,
    /// Supported output modes
    pub output_modes: Vec<DataMode>,
    /// Authentication requirements
    pub auth: AuthRequirements,
    /// A2A capabilities
    pub capabilities: CardCapabilities,
}

impl AgentCard {
    /// Create a new agent card builder
    pub fn builder(id: NodeId, name: impl Into<String>) -> AgentCardBuilder {
        AgentCardBuilder::new(id, name)
    }

    /// Get the well-known URI path for this card
    pub fn well_known_path() -> &'static str {
        "/.well-known/agent-card.json"
    }

    /// Serialize to JSON (simplified - would use serde in production)
    pub fn to_json(&self) -> String {
        let skills_json: Vec<String> = self.skills.iter()
            .map(|s| format!(
                r#"{{"id":"{}","name":"{}","description":"{}"}}"#,
                s.id, s.name, s.description
            ))
            .collect();

        format!(
            r#"{{"name":"{}","description":"{}","version":"{}","endpoint":"{}","skills":[{}]}}"#,
            self.name,
            self.description,
            self.version,
            self.endpoint,
            skills_json.join(",")
        )
    }
}

/// Provider/organization information
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Organization name
    pub name: String,
    /// Organization URL
    pub url: Option<String>,
    /// Contact email
    pub contact: Option<String>,
}

/// A skill/capability the agent provides
#[derive(Debug, Clone)]
pub struct AgentSkill {
    /// Unique skill identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this skill does
    pub description: String,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Input schema (JSON Schema format)
    pub input_schema: Option<String>,
    /// Output schema (JSON Schema format)
    pub output_schema: Option<String>,
    /// Example invocations
    pub examples: Vec<SkillExample>,
}

impl AgentSkill {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            tags: Vec::new(),
            input_schema: None,
            output_schema: None,
            examples: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_input_schema(mut self, schema: impl Into<String>) -> Self {
        self.input_schema = Some(schema.into());
        self
    }

    pub fn with_output_schema(mut self, schema: impl Into<String>) -> Self {
        self.output_schema = Some(schema.into());
        self
    }
}

/// Example invocation of a skill
#[derive(Debug, Clone)]
pub struct SkillExample {
    /// Example name
    pub name: String,
    /// Example input
    pub input: String,
    /// Expected output
    pub output: String,
}

/// Data format mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMode {
    /// Plain text
    Text,
    /// JSON data
    Json,
    /// Binary data
    Binary,
    /// Image data
    Image,
    /// Audio data
    Audio,
    /// Video data
    Video,
    /// Tensor/array data
    Tensor,
    /// Custom format
    Custom(String),
}

impl DataMode {
    pub fn mime_type(&self) -> &str {
        match self {
            DataMode::Text => "text/plain",
            DataMode::Json => "application/json",
            DataMode::Binary => "application/octet-stream",
            DataMode::Image => "image/*",
            DataMode::Audio => "audio/*",
            DataMode::Video => "video/*",
            DataMode::Tensor => "application/x-tensor",
            DataMode::Custom(s) => s,
        }
    }
}

/// Authentication requirements
#[derive(Debug, Clone)]
pub struct AuthRequirements {
    /// Supported auth schemes
    pub schemes: Vec<AuthScheme>,
    /// Whether auth is required
    pub required: bool,
}

impl Default for AuthRequirements {
    fn default() -> Self {
        Self {
            schemes: vec![AuthScheme::AxiomTrust],
            required: true,
        }
    }
}

/// Authentication scheme
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    /// AXIOM trust negotiation
    AxiomTrust,
    /// Bearer token
    Bearer,
    /// OAuth2
    OAuth2 { auth_url: String, token_url: String },
    /// API key
    ApiKey { header: String },
    /// Mutual TLS
    MutualTls,
    /// No authentication
    None,
}

/// A2A-compatible capabilities
#[derive(Debug, Clone, Default)]
pub struct CardCapabilities {
    /// Supports streaming responses
    pub streaming: bool,
    /// Supports push notifications
    pub push_notifications: bool,
    /// Supports state transfer (agent migration)
    pub state_transfer: bool,
    /// Supports multi-turn conversations
    pub multi_turn: bool,
    /// Supports batch requests
    pub batch: bool,
}

/// Builder for AgentCard
pub struct AgentCardBuilder {
    card: AgentCard,
}

impl AgentCardBuilder {
    pub fn new(id: NodeId, name: impl Into<String>) -> Self {
        Self {
            card: AgentCard {
                id,
                name: name.into(),
                description: String::new(),
                version: String::from("1.0.0"),
                provider: None,
                endpoint: String::new(),
                protocol_versions: vec![String::from("axiom/1.0"), String::from("a2a/1.0")],
                skills: Vec::new(),
                input_modes: vec![DataMode::Text, DataMode::Json],
                output_modes: vec![DataMode::Text, DataMode::Json],
                auth: AuthRequirements::default(),
                capabilities: CardCapabilities::default(),
            },
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.card.description = desc.into();
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.card.version = version.into();
        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.card.endpoint = endpoint.into();
        self
    }

    pub fn provider(mut self, info: ProviderInfo) -> Self {
        self.card.provider = Some(info);
        self
    }

    pub fn skill(mut self, skill: AgentSkill) -> Self {
        self.card.skills.push(skill);
        self
    }

    pub fn input_mode(mut self, mode: DataMode) -> Self {
        if !self.card.input_modes.contains(&mode) {
            self.card.input_modes.push(mode);
        }
        self
    }

    pub fn output_mode(mut self, mode: DataMode) -> Self {
        if !self.card.output_modes.contains(&mode) {
            self.card.output_modes.push(mode);
        }
        self
    }

    pub fn auth_scheme(mut self, scheme: AuthScheme) -> Self {
        self.card.auth.schemes.push(scheme);
        self
    }

    pub fn streaming(mut self, enabled: bool) -> Self {
        self.card.capabilities.streaming = enabled;
        self
    }

    pub fn push_notifications(mut self, enabled: bool) -> Self {
        self.card.capabilities.push_notifications = enabled;
        self
    }

    pub fn state_transfer(mut self, enabled: bool) -> Self {
        self.card.capabilities.state_transfer = enabled;
        self
    }

    pub fn multi_turn(mut self, enabled: bool) -> Self {
        self.card.capabilities.multi_turn = enabled;
        self
    }

    pub fn build(self) -> AgentCard {
        self.card
    }
}

/// Registry of known agent cards
pub struct AgentCardRegistry {
    cards: hashbrown::HashMap<NodeId, AgentCard>,
}

impl AgentCardRegistry {
    pub fn new() -> Self {
        Self {
            cards: hashbrown::HashMap::new(),
        }
    }

    /// Register an agent card
    pub fn register(&mut self, card: AgentCard) {
        self.cards.insert(card.id.clone(), card);
    }

    /// Get an agent card by ID
    pub fn get(&self, id: &NodeId) -> Option<&AgentCard> {
        self.cards.get(id)
    }

    /// Find agents with a specific skill
    pub fn find_by_skill(&self, skill_id: &str) -> Vec<&AgentCard> {
        self.cards.values()
            .filter(|card| card.skills.iter().any(|s| s.id == skill_id))
            .collect()
    }

    /// Find agents with a specific tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<&AgentCard> {
        self.cards.values()
            .filter(|card| {
                card.skills.iter().any(|s| s.tags.iter().any(|t| t == tag))
            })
            .collect()
    }

    /// Find agents supporting a data mode
    pub fn find_by_input_mode(&self, mode: &DataMode) -> Vec<&AgentCard> {
        self.cards.values()
            .filter(|card| card.input_modes.contains(mode))
            .collect()
    }

    /// List all registered cards
    pub fn list(&self) -> Vec<&AgentCard> {
        self.cards.values().collect()
    }

    /// Remove an agent card
    pub fn remove(&mut self, id: &NodeId) -> Option<AgentCard> {
        self.cards.remove(id)
    }
}

impl Default for AgentCardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn test_agent_card_builder() {
        let card = AgentCard::builder(test_node_id(1), "TestAgent")
            .description("A test agent")
            .version("2.0.0")
            .endpoint("https://agent.example.com")
            .skill(AgentSkill::new("summarize", "Summarize")
                .with_description("Summarizes text")
                .with_tag("nlp"))
            .streaming(true)
            .build();

        assert_eq!(card.name, "TestAgent");
        assert_eq!(card.version, "2.0.0");
        assert_eq!(card.skills.len(), 1);
        assert!(card.capabilities.streaming);
    }

    #[test]
    fn test_agent_skill() {
        let skill = AgentSkill::new("translate", "Translate")
            .with_description("Translates between languages")
            .with_tag("nlp")
            .with_tag("language")
            .with_input_schema(r#"{"type":"object","properties":{"text":{"type":"string"}}}"#);

        assert_eq!(skill.id, "translate");
        assert_eq!(skill.tags.len(), 2);
        assert!(skill.input_schema.is_some());
    }

    #[test]
    fn test_data_mode_mime() {
        assert_eq!(DataMode::Json.mime_type(), "application/json");
        assert_eq!(DataMode::Tensor.mime_type(), "application/x-tensor");
    }

    #[test]
    fn test_registry() {
        let mut registry = AgentCardRegistry::new();

        let card1 = AgentCard::builder(test_node_id(1), "Agent1")
            .skill(AgentSkill::new("summarize", "Summarize").with_tag("nlp"))
            .build();

        let card2 = AgentCard::builder(test_node_id(2), "Agent2")
            .skill(AgentSkill::new("translate", "Translate").with_tag("nlp"))
            .build();

        registry.register(card1);
        registry.register(card2);

        assert_eq!(registry.list().len(), 2);

        let nlp_agents = registry.find_by_tag("nlp");
        assert_eq!(nlp_agents.len(), 2);

        let summarizers = registry.find_by_skill("summarize");
        assert_eq!(summarizers.len(), 1);
    }

    #[test]
    fn test_to_json() {
        let card = AgentCard::builder(test_node_id(1), "TestAgent")
            .description("Test")
            .endpoint("https://example.com")
            .build();

        let json = card.to_json();
        assert!(json.contains("TestAgent"));
        assert!(json.contains("https://example.com"));
    }

    #[test]
    fn test_well_known_path() {
        assert_eq!(AgentCard::well_known_path(), "/.well-known/agent-card.json");
    }
}
