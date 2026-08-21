//! Task State Machine - A2A compatible task lifecycle
//!
//! Implements explicit task states including InputRequired for
//! human-in-the-loop scenarios. Compatible with A2A protocol.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

/// Unique task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn generate() -> Self {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

/// Task state - A2A compatible lifecycle
#[derive(Debug, Clone, PartialEq)]
pub enum TaskState {
    /// Task has been submitted but not yet started
    Submitted,

    /// Task is actively being worked on
    Working {
        /// Progress percentage (0.0 - 1.0)
        progress: f32,
        /// Current status message
        message: Option<String>,
    },

    /// Task requires additional input from the user/caller
    InputRequired {
        /// Schema describing required input (JSON Schema)
        schema: InputSchema,
        /// Prompt/question for the user
        prompt: String,
        /// Timeout for response
        timeout: Option<Duration>,
    },

    /// Task is streaming partial results
    Streaming {
        /// Artifact ID for the stream
        artifact_id: u64,
        /// Total expected artifacts (if known)
        total: Option<usize>,
        /// Current artifact index
        current: usize,
    },

    /// Task completed successfully
    Completed {
        /// Result artifacts
        artifacts: Vec<Artifact>,
    },

    /// Task failed
    Failed {
        /// Error information
        error: TaskError,
        /// Whether the task can be retried
        recoverable: bool,
    },

    /// Task was cancelled
    Cancelled {
        /// Reason for cancellation
        reason: String,
    },

    /// Task is paused
    Paused {
        /// Reason for pause
        reason: Option<String>,
        /// Checkpoint ID if state was saved
        checkpoint_id: Option<u64>,
    },
}

impl TaskState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self,
            TaskState::Completed { .. } |
            TaskState::Failed { .. } |
            TaskState::Cancelled { .. }
        )
    }

    /// Check if task is waiting for input
    pub fn needs_input(&self) -> bool {
        matches!(self, TaskState::InputRequired { .. })
    }

    /// Check if task is actively running
    pub fn is_running(&self) -> bool {
        matches!(self,
            TaskState::Working { .. } |
            TaskState::Streaming { .. }
        )
    }

    /// Get progress if available
    pub fn progress(&self) -> Option<f32> {
        match self {
            TaskState::Working { progress, .. } => Some(*progress),
            TaskState::Streaming { total: Some(t), current, .. } => {
                Some(*current as f32 / *t as f32)
            }
            TaskState::Completed { .. } => Some(1.0),
            _ => None,
        }
    }
}

/// Input schema for InputRequired state
#[derive(Debug, Clone, PartialEq)]
pub struct InputSchema {
    /// Schema type
    pub schema_type: SchemaType,
    /// Field definitions
    pub fields: Vec<InputField>,
    /// Whether multiple values allowed
    pub multi_select: bool,
}

impl InputSchema {
    /// Create a simple text input schema
    pub fn text(prompt: &str) -> Self {
        Self {
            schema_type: SchemaType::Object,
            fields: vec![InputField {
                name: String::from("input"),
                field_type: FieldType::String,
                description: String::from(prompt),
                required: true,
                default: None,
                options: None,
            }],
            multi_select: false,
        }
    }

    /// Create a choice input schema
    pub fn choice(options: Vec<String>) -> Self {
        Self {
            schema_type: SchemaType::Enum,
            fields: vec![InputField {
                name: String::from("choice"),
                field_type: FieldType::String,
                description: String::from("Select an option"),
                required: true,
                default: None,
                options: Some(options),
            }],
            multi_select: false,
        }
    }

    /// Create a confirmation (yes/no) schema
    pub fn confirm(prompt: &str) -> Self {
        Self {
            schema_type: SchemaType::Boolean,
            fields: vec![InputField {
                name: String::from("confirm"),
                field_type: FieldType::Boolean,
                description: String::from(prompt),
                required: true,
                default: None,
                options: None,
            }],
            multi_select: false,
        }
    }
}

/// Schema type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaType {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Enum,
}

/// Input field definition
#[derive(Debug, Clone, PartialEq)]
pub struct InputField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Description/prompt
    pub description: String,
    /// Whether field is required
    pub required: bool,
    /// Default value
    pub default: Option<String>,
    /// Allowed options (for enum/choice)
    pub options: Option<Vec<String>>,
}

/// Field data type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    String,
    Number,
    Integer,
    Boolean,
    File,
    Date,
    DateTime,
}

/// Task output artifact
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    /// Artifact ID
    pub id: u64,
    /// Artifact name
    pub name: String,
    /// MIME type
    pub mime_type: String,
    /// Content (inline or reference)
    pub content: ArtifactContent,
    /// Size in bytes
    pub size: usize,
    /// Metadata
    pub metadata: Vec<(String, String)>,
}

/// Artifact content
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactContent {
    /// Inline text content
    Text(String),
    /// Inline binary content
    Binary(Vec<u8>),
    /// Reference to stored content
    Reference { uri: String },
    /// Streaming content (still being written)
    Stream { stream_id: u64 },
}

/// Task error information
#[derive(Debug, Clone, PartialEq)]
pub struct TaskError {
    /// Error code
    pub code: TaskErrorCode,
    /// Human-readable message
    pub message: String,
    /// Additional details
    pub details: Option<String>,
    /// Retry after duration (if applicable)
    pub retry_after: Option<Duration>,
}

/// Task error codes (A2A compatible range: -32000 to -32099)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskErrorCode {
    /// Internal error
    Internal = -32000,
    /// Invalid input
    InvalidInput = -32001,
    /// Resource not found
    NotFound = -32002,
    /// Permission denied
    PermissionDenied = -32003,
    /// Rate limited
    RateLimited = -32004,
    /// Timeout
    Timeout = -32005,
    /// Cancelled by user
    Cancelled = -32006,
    /// Dependency failed
    DependencyFailed = -32007,
    /// Resource exhausted
    ResourceExhausted = -32008,
    /// Not implemented
    NotImplemented = -32009,
    /// Validation error
    ValidationError = -32010,
    /// Conflict
    Conflict = -32011,
}

impl TaskErrorCode {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

/// A task with its state machine
#[derive(Debug)]
pub struct Task {
    /// Task ID
    pub id: TaskId,
    /// Current state
    state: TaskState,
    /// State history
    history: Vec<StateTransition>,
    /// Creation timestamp
    created_at: u64,
    /// Last update timestamp
    updated_at: u64,
    /// Task metadata
    metadata: Vec<(String, String)>,
}

impl Task {
    /// Create a new task
    pub fn new() -> Self {
        let now = 0; // Would use real clock
        Self {
            id: TaskId::generate(),
            state: TaskState::Submitted,
            history: vec![StateTransition {
                from: None,
                to: TaskState::Submitted,
                timestamp: now,
                reason: None,
            }],
            created_at: now,
            updated_at: now,
            metadata: Vec::new(),
        }
    }

    /// Get current state
    pub fn state(&self) -> &TaskState {
        &self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: TaskState) -> Result<(), TransitionError> {
        self.validate_transition(&new_state)?;

        let transition = StateTransition {
            from: Some(self.state.clone()),
            to: new_state.clone(),
            timestamp: 0, // Would use real clock
            reason: None,
        };

        self.history.push(transition);
        self.state = new_state;
        self.updated_at = 0;

        Ok(())
    }

    /// Start working on the task
    pub fn start(&mut self) -> Result<(), TransitionError> {
        self.transition(TaskState::Working {
            progress: 0.0,
            message: None,
        })
    }

    /// Update progress
    pub fn update_progress(&mut self, progress: f32, message: Option<String>) -> Result<(), TransitionError> {
        if !self.state.is_running() {
            return Err(TransitionError::InvalidState);
        }
        self.state = TaskState::Working {
            progress: progress.clamp(0.0, 1.0),
            message,
        };
        Ok(())
    }

    /// Request input from user
    pub fn request_input(&mut self, schema: InputSchema, prompt: String) -> Result<(), TransitionError> {
        self.transition(TaskState::InputRequired {
            schema,
            prompt,
            timeout: None,
        })
    }

    /// Provide requested input
    pub fn provide_input(&mut self, _input: String) -> Result<(), TransitionError> {
        if !matches!(self.state, TaskState::InputRequired { .. }) {
            return Err(TransitionError::InvalidState);
        }
        // Resume working
        self.transition(TaskState::Working {
            progress: 0.0,
            message: Some(String::from("Input received, resuming")),
        })
    }

    /// Complete the task
    pub fn complete(&mut self, artifacts: Vec<Artifact>) -> Result<(), TransitionError> {
        self.transition(TaskState::Completed { artifacts })
    }

    /// Fail the task
    pub fn fail(&mut self, error: TaskError, recoverable: bool) -> Result<(), TransitionError> {
        self.transition(TaskState::Failed { error, recoverable })
    }

    /// Cancel the task
    pub fn cancel(&mut self, reason: String) -> Result<(), TransitionError> {
        self.transition(TaskState::Cancelled { reason })
    }

    /// Pause the task
    pub fn pause(&mut self, reason: Option<String>) -> Result<(), TransitionError> {
        self.transition(TaskState::Paused {
            reason,
            checkpoint_id: None,
        })
    }

    /// Resume from pause
    pub fn resume(&mut self) -> Result<(), TransitionError> {
        if !matches!(self.state, TaskState::Paused { .. }) {
            return Err(TransitionError::InvalidState);
        }
        self.transition(TaskState::Working {
            progress: 0.0,
            message: Some(String::from("Resumed")),
        })
    }

    /// Validate state transition
    fn validate_transition(&self, new_state: &TaskState) -> Result<(), TransitionError> {
        // Can't transition from terminal states
        if self.state.is_terminal() {
            return Err(TransitionError::AlreadyTerminal);
        }

        // Validate specific transitions
        match (&self.state, new_state) {
            // Can always cancel or fail
            (_, TaskState::Cancelled { .. }) => Ok(()),
            (_, TaskState::Failed { .. }) => Ok(()),

            // Submitted can go to Working
            (TaskState::Submitted, TaskState::Working { .. }) => Ok(()),

            // Working can go to many states
            (TaskState::Working { .. }, TaskState::Completed { .. }) => Ok(()),
            (TaskState::Working { .. }, TaskState::InputRequired { .. }) => Ok(()),
            (TaskState::Working { .. }, TaskState::Streaming { .. }) => Ok(()),
            (TaskState::Working { .. }, TaskState::Paused { .. }) => Ok(()),

            // InputRequired can resume or complete
            (TaskState::InputRequired { .. }, TaskState::Working { .. }) => Ok(()),
            (TaskState::InputRequired { .. }, TaskState::Completed { .. }) => Ok(()),

            // Streaming can complete or go back to working
            (TaskState::Streaming { .. }, TaskState::Completed { .. }) => Ok(()),
            (TaskState::Streaming { .. }, TaskState::Working { .. }) => Ok(()),

            // Paused can resume
            (TaskState::Paused { .. }, TaskState::Working { .. }) => Ok(()),

            _ => Err(TransitionError::InvalidTransition),
        }
    }

    /// Add metadata
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        if let Some(entry) = self.metadata.iter_mut().find(|(k, _)| k == &key) {
            entry.1 = value.into();
        } else {
            self.metadata.push((key, value.into()));
        }
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Get state history
    pub fn history(&self) -> &[StateTransition] {
        &self.history
    }
}

impl Default for Task {
    fn default() -> Self {
        Self::new()
    }
}

/// State transition record
#[derive(Debug, Clone)]
pub struct StateTransition {
    /// Previous state (None if initial)
    pub from: Option<TaskState>,
    /// New state
    pub to: TaskState,
    /// Timestamp
    pub timestamp: u64,
    /// Reason for transition
    pub reason: Option<String>,
}

/// Transition error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    /// Invalid state for this transition
    InvalidState,
    /// Can't transition from terminal state
    AlreadyTerminal,
    /// Invalid transition
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_lifecycle() {
        let mut task = Task::new();
        assert!(matches!(task.state(), TaskState::Submitted));

        task.start().unwrap();
        assert!(task.state().is_running());

        task.update_progress(0.5, Some(String::from("Halfway"))).unwrap();

        task.complete(vec![]).unwrap();
        assert!(task.state().is_terminal());
    }

    #[test]
    fn test_input_required() {
        let mut task = Task::new();
        task.start().unwrap();

        task.request_input(
            InputSchema::confirm("Continue?"),
            String::from("Do you want to continue?"),
        ).unwrap();

        assert!(task.state().needs_input());

        task.provide_input(String::from("yes")).unwrap();
        assert!(task.state().is_running());
    }

    #[test]
    fn test_cancel() {
        let mut task = Task::new();
        task.start().unwrap();
        task.cancel(String::from("User requested")).unwrap();

        assert!(task.state().is_terminal());
        assert!(matches!(task.state(), TaskState::Cancelled { .. }));
    }

    #[test]
    fn test_fail() {
        let mut task = Task::new();
        task.start().unwrap();

        task.fail(TaskError {
            code: TaskErrorCode::Internal,
            message: String::from("Something went wrong"),
            details: None,
            retry_after: None,
        }, true).unwrap();

        assert!(task.state().is_terminal());
        if let TaskState::Failed { recoverable, .. } = task.state() {
            assert!(*recoverable);
        }
    }

    #[test]
    fn test_pause_resume() {
        let mut task = Task::new();
        task.start().unwrap();
        task.pause(Some(String::from("User paused"))).unwrap();

        assert!(matches!(task.state(), TaskState::Paused { .. }));

        task.resume().unwrap();
        assert!(task.state().is_running());
    }

    #[test]
    fn test_cannot_transition_from_terminal() {
        let mut task = Task::new();
        task.start().unwrap();
        task.complete(vec![]).unwrap();

        assert!(task.start().is_err());
    }

    #[test]
    fn test_input_schema() {
        let text = InputSchema::text("Enter name");
        assert_eq!(text.fields.len(), 1);
        assert!(text.fields[0].required);

        let choice = InputSchema::choice(vec![
            String::from("A"),
            String::from("B"),
        ]);
        assert!(choice.fields[0].options.is_some());

        let confirm = InputSchema::confirm("Are you sure?");
        assert_eq!(confirm.fields[0].field_type, FieldType::Boolean);
    }

    #[test]
    fn test_task_metadata() {
        let mut task = Task::new();
        task.set_metadata("user_id", "123");
        task.set_metadata("priority", "high");

        assert_eq!(task.get_metadata("user_id"), Some("123"));
        assert_eq!(task.get_metadata("priority"), Some("high"));
        assert_eq!(task.get_metadata("missing"), None);
    }

    #[test]
    fn test_progress() {
        let mut task = Task::new();
        assert_eq!(task.state().progress(), None);

        task.start().unwrap();
        task.update_progress(0.5, None).unwrap();
        assert_eq!(task.state().progress(), Some(0.5));

        task.complete(vec![]).unwrap();
        assert_eq!(task.state().progress(), Some(1.0));
    }

    #[test]
    fn test_history() {
        let mut task = Task::new();
        task.start().unwrap();
        task.update_progress(0.5, None).unwrap();
        task.complete(vec![]).unwrap();

        // Initial + start + complete = 3 transitions
        // (update_progress doesn't add to history)
        assert!(task.history().len() >= 2);
    }
}
