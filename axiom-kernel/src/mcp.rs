//! MCP Bridge - Model Context Protocol integration
//!
//! Bridges AXIOM agents to the MCP ecosystem, allowing them to:
//! - Act as MCP clients to use external tools
//! - Act as MCP servers to expose capabilities
//! - Translate between AXIOM intents and MCP primitives

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

/// MCP primitive types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpPrimitive {
    /// Resource: Read-only data access
    Resource,
    /// Tool: Action with side effects
    Tool,
    /// Prompt: Template for generation
    Prompt,
}

/// MCP Resource - read-only data source
#[derive(Debug, Clone)]
pub struct McpResource {
    /// Resource URI
    pub uri: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// MIME type
    pub mime_type: String,
}

/// MCP Tool - callable function with side effects
#[derive(Debug, Clone)]
pub struct McpTool {
    /// Tool name
    pub name: String,
    /// Description
    pub description: String,
    /// Input schema (JSON Schema)
    pub input_schema: String,
    /// Whether tool is dangerous/requires confirmation
    pub requires_confirmation: bool,
}

/// MCP Prompt - template for generation
#[derive(Debug, Clone)]
pub struct McpPrompt {
    /// Prompt name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Arguments
    pub arguments: Vec<PromptArgument>,
}

/// Prompt argument
#[derive(Debug, Clone)]
pub struct PromptArgument {
    /// Argument name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Whether required
    pub required: bool,
}

/// MCP message types (JSON-RPC based)
#[derive(Debug, Clone)]
pub enum McpMessage {
    /// Request message
    Request {
        id: u64,
        method: String,
        params: Option<String>,
    },
    /// Response message
    Response {
        id: u64,
        result: Option<String>,
        error: Option<McpError>,
    },
    /// Notification (no response expected)
    Notification {
        method: String,
        params: Option<String>,
    },
}

/// MCP error
#[derive(Debug, Clone)]
pub struct McpError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional data
    pub data: Option<String>,
}

impl McpError {
    pub fn parse_error() -> Self {
        Self { code: -32700, message: String::from("Parse error"), data: None }
    }

    pub fn invalid_request() -> Self {
        Self { code: -32600, message: String::from("Invalid Request"), data: None }
    }

    pub fn method_not_found() -> Self {
        Self { code: -32601, message: String::from("Method not found"), data: None }
    }

    pub fn invalid_params() -> Self {
        Self { code: -32602, message: String::from("Invalid params"), data: None }
    }

    pub fn internal_error() -> Self {
        Self { code: -32603, message: String::from("Internal error"), data: None }
    }
}

/// MCP Server capability
#[derive(Debug, Clone)]
pub struct ServerCapabilities {
    /// Supported resources
    pub resources: bool,
    /// Supported tools
    pub tools: bool,
    /// Supported prompts
    pub prompts: bool,
    /// Supports resource subscriptions
    pub resource_subscriptions: bool,
    /// Supports logging
    pub logging: bool,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            resources: true,
            tools: true,
            prompts: true,
            resource_subscriptions: false,
            logging: true,
        }
    }
}

/// MCP Client capability
#[derive(Debug, Clone)]
pub struct ClientCapabilities {
    /// Supports roots (filesystem access)
    pub roots: bool,
    /// Supports sampling (LLM calls)
    pub sampling: bool,
}

impl Default for ClientCapabilities {
    fn default() -> Self {
        Self {
            roots: false,
            sampling: false,
        }
    }
}

/// MCP Bridge - translates between AXIOM and MCP
pub struct McpBridge {
    /// Server info
    server_name: String,
    server_version: String,
    /// Server capabilities
    server_caps: ServerCapabilities,
    /// Registered resources
    resources: HashMap<String, McpResource>,
    /// Registered tools
    tools: HashMap<String, McpTool>,
    /// Registered prompts
    prompts: HashMap<String, McpPrompt>,
    /// Connected clients
    clients: Vec<McpClientInfo>,
    /// Request ID counter
    next_request_id: u64,
}

/// Connected client info
#[derive(Debug, Clone)]
pub struct McpClientInfo {
    /// Client name
    pub name: String,
    /// Client version
    pub version: String,
    /// Client capabilities
    pub capabilities: ClientCapabilities,
}

impl McpBridge {
    /// Create a new MCP bridge
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            server_name: name.into(),
            server_version: version.into(),
            server_caps: ServerCapabilities::default(),
            resources: HashMap::new(),
            tools: HashMap::new(),
            prompts: HashMap::new(),
            clients: Vec::new(),
            next_request_id: 1,
        }
    }

    /// Register a resource
    pub fn register_resource(&mut self, resource: McpResource) {
        self.resources.insert(resource.uri.clone(), resource);
    }

    /// Register a tool
    pub fn register_tool(&mut self, tool: McpTool) {
        self.tools.insert(tool.name.clone(), tool);
    }

    /// Register a prompt
    pub fn register_prompt(&mut self, prompt: McpPrompt) {
        self.prompts.insert(prompt.name.clone(), prompt);
    }

    /// Handle incoming MCP message
    pub fn handle_message(&mut self, message: McpMessage) -> Option<McpMessage> {
        match message {
            McpMessage::Request { id, method, params } => {
                let result = self.handle_request(&method, params.as_deref());
                let (result_val, error_val) = match result {
                    Ok(s) => (Some(s), None),
                    Err(e) => (None, Some(e)),
                };
                Some(McpMessage::Response {
                    id,
                    result: result_val,
                    error: error_val,
                })
            }
            McpMessage::Notification { method, params } => {
                self.handle_notification(&method, params.as_deref());
                None
            }
            McpMessage::Response { .. } => None,
        }
    }

    /// Handle a request
    fn handle_request(&mut self, method: &str, _params: Option<&str>) -> Result<String, McpError> {
        match method {
            "initialize" => self.handle_initialize(),
            "resources/list" => self.handle_list_resources(),
            "resources/read" => self.handle_read_resource(),
            "tools/list" => self.handle_list_tools(),
            "tools/call" => self.handle_call_tool(),
            "prompts/list" => self.handle_list_prompts(),
            "prompts/get" => self.handle_get_prompt(),
            _ => Err(McpError::method_not_found()),
        }
    }

    /// Handle notification
    fn handle_notification(&mut self, method: &str, _params: Option<&str>) {
        match method {
            "initialized" => {
                // Client has completed initialization
            }
            "cancelled" => {
                // Request was cancelled
            }
            _ => {}
        }
    }

    fn handle_initialize(&self) -> Result<String, McpError> {
        Ok(format!(
            r#"{{"protocolVersion":"1.0","serverInfo":{{"name":"{}","version":"{}"}},"capabilities":{{"resources":{},"tools":{},"prompts":{}}}}}"#,
            self.server_name,
            self.server_version,
            self.server_caps.resources,
            self.server_caps.tools,
            self.server_caps.prompts,
        ))
    }

    fn handle_list_resources(&self) -> Result<String, McpError> {
        let resources: Vec<String> = self.resources.values()
            .map(|r| format!(
                r#"{{"uri":"{}","name":"{}","mimeType":"{}"}}"#,
                r.uri, r.name, r.mime_type
            ))
            .collect();
        Ok(format!(r#"{{"resources":[{}]}}"#, resources.join(",")))
    }

    fn handle_read_resource(&self) -> Result<String, McpError> {
        // Would parse params and return resource content
        Err(McpError::invalid_params())
    }

    fn handle_list_tools(&self) -> Result<String, McpError> {
        let tools: Vec<String> = self.tools.values()
            .map(|t| format!(
                r#"{{"name":"{}","description":"{}","inputSchema":{}}}"#,
                t.name, t.description, t.input_schema
            ))
            .collect();
        Ok(format!(r#"{{"tools":[{}]}}"#, tools.join(",")))
    }

    fn handle_call_tool(&mut self) -> Result<String, McpError> {
        // Would parse params, execute tool, return result
        Err(McpError::invalid_params())
    }

    fn handle_list_prompts(&self) -> Result<String, McpError> {
        let prompts: Vec<String> = self.prompts.values()
            .map(|p| format!(
                r#"{{"name":"{}","description":"{}"}}"#,
                p.name,
                p.description.as_deref().unwrap_or("")
            ))
            .collect();
        Ok(format!(r#"{{"prompts":[{}]}}"#, prompts.join(",")))
    }

    fn handle_get_prompt(&self) -> Result<String, McpError> {
        // Would parse params and return prompt with arguments
        Err(McpError::invalid_params())
    }

    /// Create a client request
    pub fn create_request(&mut self, method: &str, params: Option<String>) -> McpMessage {
        let id = self.next_request_id;
        self.next_request_id += 1;
        McpMessage::Request {
            id,
            method: String::from(method),
            params,
        }
    }

    /// List resources
    pub fn list_resources(&self) -> Vec<&McpResource> {
        self.resources.values().collect()
    }

    /// List tools
    pub fn list_tools(&self) -> Vec<&McpTool> {
        self.tools.values().collect()
    }

    /// List prompts
    pub fn list_prompts(&self) -> Vec<&McpPrompt> {
        self.prompts.values().collect()
    }

    /// Get resource by URI
    pub fn get_resource(&self, uri: &str) -> Option<&McpResource> {
        self.resources.get(uri)
    }

    /// Get tool by name
    pub fn get_tool(&self, name: &str) -> Option<&McpTool> {
        self.tools.get(name)
    }
}

impl Default for McpBridge {
    fn default() -> Self {
        Self::new("axiom-mcp", "1.0.0")
    }
}

/// MCP to AXIOM intent translator
pub struct IntentTranslator;

impl IntentTranslator {
    /// Convert MCP tool call to AXIOM intent
    pub fn tool_to_intent(tool_name: &str) -> String {
        format!("mcp:tool:{}", tool_name)
    }

    /// Convert MCP resource read to AXIOM intent
    pub fn resource_to_intent(resource_uri: &str) -> String {
        format!("mcp:resource:{}", resource_uri)
    }

    /// Convert MCP prompt to AXIOM intent
    pub fn prompt_to_intent(prompt_name: &str) -> String {
        format!("mcp:prompt:{}", prompt_name)
    }

    /// Parse AXIOM intent to MCP primitive
    pub fn intent_to_mcp(intent: &str) -> Option<(McpPrimitive, String)> {
        if let Some(rest) = intent.strip_prefix("mcp:") {
            if let Some(name) = rest.strip_prefix("tool:") {
                return Some((McpPrimitive::Tool, String::from(name)));
            }
            if let Some(uri) = rest.strip_prefix("resource:") {
                return Some((McpPrimitive::Resource, String::from(uri)));
            }
            if let Some(name) = rest.strip_prefix("prompt:") {
                return Some((McpPrimitive::Prompt, String::from(name)));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_bridge_creation() {
        let bridge = McpBridge::new("test-server", "1.0.0");
        assert!(bridge.list_resources().is_empty());
        assert!(bridge.list_tools().is_empty());
    }

    #[test]
    fn test_register_resource() {
        let mut bridge = McpBridge::default();

        bridge.register_resource(McpResource {
            uri: String::from("file:///data.json"),
            name: String::from("Data File"),
            description: Some(String::from("Test data")),
            mime_type: String::from("application/json"),
        });

        assert_eq!(bridge.list_resources().len(), 1);
        assert!(bridge.get_resource("file:///data.json").is_some());
    }

    #[test]
    fn test_register_tool() {
        let mut bridge = McpBridge::default();

        bridge.register_tool(McpTool {
            name: String::from("search"),
            description: String::from("Search the web"),
            input_schema: String::from(r#"{"type":"object","properties":{"query":{"type":"string"}}}"#),
            requires_confirmation: false,
        });

        assert_eq!(bridge.list_tools().len(), 1);
        assert!(bridge.get_tool("search").is_some());
    }

    #[test]
    fn test_register_prompt() {
        let mut bridge = McpBridge::default();

        bridge.register_prompt(McpPrompt {
            name: String::from("summarize"),
            description: Some(String::from("Summarize text")),
            arguments: vec![PromptArgument {
                name: String::from("text"),
                description: Some(String::from("Text to summarize")),
                required: true,
            }],
        });

        assert_eq!(bridge.list_prompts().len(), 1);
    }

    #[test]
    fn test_handle_initialize() {
        let mut bridge = McpBridge::new("test", "1.0.0");

        let request = McpMessage::Request {
            id: 1,
            method: String::from("initialize"),
            params: None,
        };

        let response = bridge.handle_message(request).unwrap();
        if let McpMessage::Response { result, error, .. } = response {
            assert!(error.is_none());
            assert!(result.is_some());
            let r = result.unwrap();
            assert!(r.contains("test"));
            assert!(r.contains("1.0.0"));
        }
    }

    #[test]
    fn test_handle_list_tools() {
        let mut bridge = McpBridge::default();
        bridge.register_tool(McpTool {
            name: String::from("test_tool"),
            description: String::from("A test tool"),
            input_schema: String::from("{}"),
            requires_confirmation: false,
        });

        let request = McpMessage::Request {
            id: 1,
            method: String::from("tools/list"),
            params: None,
        };

        let response = bridge.handle_message(request).unwrap();
        if let McpMessage::Response { result, .. } = response {
            let r = result.unwrap();
            assert!(r.contains("test_tool"));
        }
    }

    #[test]
    fn test_unknown_method() {
        let mut bridge = McpBridge::default();

        let request = McpMessage::Request {
            id: 1,
            method: String::from("unknown/method"),
            params: None,
        };

        let response = bridge.handle_message(request).unwrap();
        if let McpMessage::Response { error, .. } = response {
            assert!(error.is_some());
            assert_eq!(error.unwrap().code, -32601);
        }
    }

    #[test]
    fn test_intent_translation() {
        assert_eq!(
            IntentTranslator::tool_to_intent("search"),
            "mcp:tool:search"
        );
        assert_eq!(
            IntentTranslator::resource_to_intent("file:///data.json"),
            "mcp:resource:file:///data.json"
        );

        let (prim, name) = IntentTranslator::intent_to_mcp("mcp:tool:search").unwrap();
        assert_eq!(prim, McpPrimitive::Tool);
        assert_eq!(name, "search");

        assert!(IntentTranslator::intent_to_mcp("not:mcp").is_none());
    }

    #[test]
    fn test_create_request() {
        let mut bridge = McpBridge::default();

        let req1 = bridge.create_request("tools/list", None);
        let req2 = bridge.create_request("resources/list", None);

        if let (McpMessage::Request { id: id1, .. }, McpMessage::Request { id: id2, .. }) = (req1, req2) {
            assert_eq!(id2, id1 + 1);
        }
    }
}
