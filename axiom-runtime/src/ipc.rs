//! Inter-Process Communication for local agents
//!
//! When agents are on the same node, there's no need for network overhead.
//! This module provides zero-copy message passing between local agents.
//!
//! # Design
//!
//! Traditional IPC: pipes, shared memory, sockets - all require syscalls
//! AI-Native IPC: Direct memory sharing with ownership transfer
//!
//! An agent can:
//! - Send a message (transfers ownership)
//! - Receive messages (takes ownership)
//! - Share read-only data (reference counted)

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use hashbrown::HashMap;

use axiom_types::NodeId;

/// Unique channel identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(u64);

impl ChannelId {
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

/// Message priority for scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    /// Background tasks, can be delayed
    Low = 0,
    /// Normal operation
    Normal = 1,
    /// Time-sensitive
    High = 2,
    /// System critical, never delay
    Critical = 3,
}

/// A message between agents
#[derive(Debug)]
pub struct Message {
    /// Unique message ID
    pub id: u64,
    /// Sender agent
    pub sender: NodeId,
    /// Message priority
    pub priority: MessagePriority,
    /// Intent hash for routing
    pub intent: [u8; 16],
    /// Payload - owned by receiver after delivery
    pub payload: Box<[u8]>,
    /// Timestamp (hybrid clock)
    pub timestamp: u64,
}

impl Message {
    pub fn new(sender: NodeId, intent: [u8; 16], payload: Vec<u8>) -> Self {
        static MSG_COUNTER: AtomicU64 = AtomicU64::new(1);
        Self {
            id: MSG_COUNTER.fetch_add(1, Ordering::Relaxed),
            sender,
            priority: MessagePriority::Normal,
            intent,
            payload: payload.into_boxed_slice(),
            timestamp: 0,
        }
    }

    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Shared read-only data between agents
///
/// When multiple agents need the same data (e.g., model weights),
/// we share it via reference counting instead of copying.
#[derive(Clone)]
pub struct SharedData {
    data: Arc<[u8]>,
    /// Who created this shared data
    owner: NodeId,
    /// What capability this data relates to
    intent: [u8; 16],
}

impl SharedData {
    pub fn new(owner: NodeId, intent: [u8; 16], data: Vec<u8>) -> Self {
        Self {
            data: data.into(),
            owner,
            intent,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn owner(&self) -> &NodeId {
        &self.owner
    }

    pub fn intent(&self) -> &[u8; 16] {
        &self.intent
    }

    /// Number of references to this data
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }
}

/// A mailbox for receiving messages
pub struct Mailbox {
    /// Channel this mailbox belongs to
    channel_id: ChannelId,
    /// Owner agent
    owner: NodeId,
    /// Pending messages by priority
    queues: [VecDeque<Message>; 4],
    /// Total messages waiting
    pending_count: usize,
    /// Maximum queue depth (backpressure)
    max_depth: usize,
}

impl Mailbox {
    pub fn new(owner: NodeId, max_depth: usize) -> Self {
        Self {
            channel_id: ChannelId::generate(),
            owner,
            queues: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            pending_count: 0,
            max_depth,
        }
    }

    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    pub fn owner(&self) -> &NodeId {
        &self.owner
    }

    /// Receive next message (highest priority first)
    pub fn recv(&mut self) -> Option<Message> {
        // Check from highest to lowest priority
        for priority in (0..4).rev() {
            if let Some(msg) = self.queues[priority].pop_front() {
                self.pending_count -= 1;
                return Some(msg);
            }
        }
        None
    }

    /// Receive message with specific priority
    pub fn recv_priority(&mut self, priority: MessagePriority) -> Option<Message> {
        let idx = priority as usize;
        if let Some(msg) = self.queues[idx].pop_front() {
            self.pending_count -= 1;
            Some(msg)
        } else {
            None
        }
    }

    /// Check if there are pending messages
    pub fn has_messages(&self) -> bool {
        self.pending_count > 0
    }

    /// Number of pending messages
    pub fn pending(&self) -> usize {
        self.pending_count
    }

    /// Internal: deliver a message to this mailbox
    fn deliver(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.pending_count >= self.max_depth {
            return Err(IpcError::MailboxFull);
        }

        let idx = msg.priority as usize;
        self.queues[idx].push_back(msg);
        self.pending_count += 1;
        Ok(())
    }
}

/// IPC errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// Target mailbox doesn't exist
    ChannelNotFound,
    /// Mailbox is full (backpressure)
    MailboxFull,
    /// Agent not registered
    AgentNotFound,
    /// Message too large
    MessageTooLarge,
}

/// The local IPC router
///
/// Routes messages between agents on the same node.
/// Zero syscalls, zero network overhead.
pub struct LocalRouter {
    /// Registered mailboxes by channel ID
    mailboxes: HashMap<ChannelId, Mailbox>,
    /// Agent to channel mapping
    agent_channels: HashMap<NodeId, ChannelId>,
    /// Shared data registry
    shared_data: HashMap<[u8; 16], SharedData>,
    /// Stats
    messages_routed: u64,
    bytes_transferred: u64,
}

impl LocalRouter {
    pub fn new() -> Self {
        Self {
            mailboxes: HashMap::new(),
            agent_channels: HashMap::new(),
            shared_data: HashMap::new(),
            messages_routed: 0,
            bytes_transferred: 0,
        }
    }

    /// Register an agent's mailbox
    pub fn register(&mut self, agent_id: NodeId, max_depth: usize) -> ChannelId {
        let mailbox = Mailbox::new(agent_id.clone(), max_depth);
        let channel_id = mailbox.channel_id();

        self.mailboxes.insert(channel_id, mailbox);
        self.agent_channels.insert(agent_id, channel_id);

        channel_id
    }

    /// Unregister an agent
    pub fn unregister(&mut self, agent_id: &NodeId) {
        if let Some(channel_id) = self.agent_channels.remove(agent_id) {
            self.mailboxes.remove(&channel_id);
        }
    }

    /// Send a message to an agent
    pub fn send(&mut self, target: &NodeId, msg: Message) -> Result<(), IpcError> {
        let channel_id = self.agent_channels
            .get(target)
            .ok_or(IpcError::AgentNotFound)?;

        let mailbox = self.mailboxes
            .get_mut(channel_id)
            .ok_or(IpcError::ChannelNotFound)?;

        let payload_len = msg.payload.len() as u64;
        mailbox.deliver(msg)?;

        self.messages_routed += 1;
        self.bytes_transferred += payload_len;

        Ok(())
    }

    /// Send to channel directly (if you have the ID)
    pub fn send_to_channel(&mut self, channel: ChannelId, msg: Message) -> Result<(), IpcError> {
        let mailbox = self.mailboxes
            .get_mut(&channel)
            .ok_or(IpcError::ChannelNotFound)?;

        let payload_len = msg.payload.len() as u64;
        mailbox.deliver(msg)?;

        self.messages_routed += 1;
        self.bytes_transferred += payload_len;

        Ok(())
    }

    /// Get mailbox for receiving (agent must own it)
    pub fn mailbox(&mut self, agent_id: &NodeId) -> Option<&mut Mailbox> {
        let channel_id = self.agent_channels.get(agent_id)?;
        self.mailboxes.get_mut(channel_id)
    }

    /// Share data that multiple agents can read
    pub fn share_data(&mut self, data: SharedData) {
        self.shared_data.insert(*data.intent(), data);
    }

    /// Get shared data by intent
    pub fn get_shared(&self, intent: &[u8; 16]) -> Option<SharedData> {
        self.shared_data.get(intent).cloned()
    }

    /// Remove shared data
    pub fn unshare(&mut self, intent: &[u8; 16]) -> Option<SharedData> {
        self.shared_data.remove(intent)
    }

    /// Stats: total messages routed
    pub fn messages_routed(&self) -> u64 {
        self.messages_routed
    }

    /// Stats: total bytes transferred
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }

    /// Number of registered agents
    pub fn agent_count(&self) -> usize {
        self.agent_channels.len()
    }
}

impl Default for LocalRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent(id: u8) -> NodeId {
        NodeId::from_bytes([id; 32])
    }

    #[test]
    fn test_message_creation() {
        let sender = test_agent(1);
        let intent = [0xAB; 16];
        let payload = vec![1, 2, 3, 4];

        let msg = Message::new(sender.clone(), intent, payload)
            .with_priority(MessagePriority::High)
            .with_timestamp(12345);

        assert_eq!(msg.sender, sender);
        assert_eq!(msg.intent, intent);
        assert_eq!(&*msg.payload, &[1, 2, 3, 4]);
        assert_eq!(msg.priority, MessagePriority::High);
        assert_eq!(msg.timestamp, 12345);
    }

    #[test]
    fn test_shared_data() {
        let owner = test_agent(1);
        let intent = [0xCD; 16];
        let data = vec![0u8; 1024];

        let shared = SharedData::new(owner.clone(), intent, data);

        assert_eq!(shared.len(), 1024);
        assert_eq!(shared.owner(), &owner);
        assert_eq!(shared.ref_count(), 1);

        // Clone increases ref count
        let shared2 = shared.clone();
        assert_eq!(shared.ref_count(), 2);
        assert_eq!(shared2.ref_count(), 2);
    }

    #[test]
    fn test_mailbox_priority() {
        let owner = test_agent(1);
        let mut mailbox = Mailbox::new(owner.clone(), 100);

        // Send messages with different priorities
        let low = Message::new(owner.clone(), [1; 16], vec![1])
            .with_priority(MessagePriority::Low);
        let normal = Message::new(owner.clone(), [2; 16], vec![2])
            .with_priority(MessagePriority::Normal);
        let high = Message::new(owner.clone(), [3; 16], vec![3])
            .with_priority(MessagePriority::High);
        let critical = Message::new(owner.clone(), [4; 16], vec![4])
            .with_priority(MessagePriority::Critical);

        // Deliver in random order
        mailbox.deliver(normal).unwrap();
        mailbox.deliver(low).unwrap();
        mailbox.deliver(critical).unwrap();
        mailbox.deliver(high).unwrap();

        assert_eq!(mailbox.pending(), 4);

        // Should receive highest priority first
        assert_eq!(mailbox.recv().unwrap().payload[0], 4); // Critical
        assert_eq!(mailbox.recv().unwrap().payload[0], 3); // High
        assert_eq!(mailbox.recv().unwrap().payload[0], 2); // Normal
        assert_eq!(mailbox.recv().unwrap().payload[0], 1); // Low
        assert!(mailbox.recv().is_none());
    }

    #[test]
    fn test_mailbox_backpressure() {
        let owner = test_agent(1);
        let mut mailbox = Mailbox::new(owner.clone(), 2);

        let msg1 = Message::new(owner.clone(), [1; 16], vec![1]);
        let msg2 = Message::new(owner.clone(), [2; 16], vec![2]);
        let msg3 = Message::new(owner.clone(), [3; 16], vec![3]);

        assert!(mailbox.deliver(msg1).is_ok());
        assert!(mailbox.deliver(msg2).is_ok());
        assert_eq!(mailbox.deliver(msg3), Err(IpcError::MailboxFull));
    }

    #[test]
    fn test_local_router_basic() {
        let mut router = LocalRouter::new();

        let agent1 = test_agent(1);
        let agent2 = test_agent(2);

        // Register agents
        router.register(agent1.clone(), 100);
        router.register(agent2.clone(), 100);

        assert_eq!(router.agent_count(), 2);

        // Send message from agent1 to agent2
        let msg = Message::new(agent1.clone(), [0xAB; 16], vec![42, 43, 44]);
        router.send(&agent2, msg).unwrap();

        // Agent2 receives it
        let mailbox = router.mailbox(&agent2).unwrap();
        let received = mailbox.recv().unwrap();

        assert_eq!(received.sender, agent1);
        assert_eq!(&*received.payload, &[42, 43, 44]);

        assert_eq!(router.messages_routed(), 1);
        assert_eq!(router.bytes_transferred(), 3);
    }

    #[test]
    fn test_local_router_shared_data() {
        let mut router = LocalRouter::new();

        let owner = test_agent(1);
        let intent = [0xEF; 16];
        let data = vec![1, 2, 3, 4, 5];

        let shared = SharedData::new(owner, intent, data);
        router.share_data(shared);

        // Multiple agents can access
        let data1 = router.get_shared(&intent).unwrap();
        let data2 = router.get_shared(&intent).unwrap();

        assert_eq!(data1.data(), data2.data());
        assert_eq!(data1.ref_count(), 3); // Original + 2 clones

        // Unshare
        router.unshare(&intent);
        assert!(router.get_shared(&intent).is_none());
    }

    #[test]
    fn test_router_send_to_nonexistent() {
        let mut router = LocalRouter::new();
        let sender = test_agent(1);
        let target = test_agent(99);

        let msg = Message::new(sender, [0; 16], vec![]);
        assert_eq!(router.send(&target, msg), Err(IpcError::AgentNotFound));
    }

    #[test]
    fn test_router_unregister() {
        let mut router = LocalRouter::new();
        let agent = test_agent(1);

        router.register(agent.clone(), 100);
        assert_eq!(router.agent_count(), 1);

        router.unregister(&agent);
        assert_eq!(router.agent_count(), 0);

        // Can't send to unregistered agent
        let msg = Message::new(test_agent(2), [0; 16], vec![]);
        assert_eq!(router.send(&agent, msg), Err(IpcError::AgentNotFound));
    }

    #[test]
    fn test_many_messages() {
        let mut router = LocalRouter::new();
        let sender = test_agent(1);
        let receiver = test_agent(2);

        router.register(sender.clone(), 1000);
        router.register(receiver.clone(), 1000);

        // Send 100 messages
        for i in 0..100u8 {
            let msg = Message::new(sender.clone(), [i; 16], vec![i]);
            router.send(&receiver, msg).unwrap();
        }

        assert_eq!(router.messages_routed(), 100);

        // Receive all
        let mailbox = router.mailbox(&receiver).unwrap();
        for _ in 0..100 {
            assert!(mailbox.recv().is_some());
        }
        assert!(mailbox.recv().is_none());
    }
}
