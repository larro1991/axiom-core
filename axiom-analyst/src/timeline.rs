//! Event timeline management
//!
//! Maintains a time-ordered collection of security events.

use alloc::string::String;
use alloc::vec::Vec;

use crate::SecurityEvent;

/// A timeline event with metadata
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    /// The security event
    pub event: SecurityEvent,
    /// Correlation group ID (if correlated)
    pub correlation_group: Option<u64>,
    /// Whether this is part of an attack chain
    pub in_attack_chain: bool,
}

impl TimelineEvent {
    /// Create new timeline event
    pub fn new(event: SecurityEvent) -> Self {
        Self {
            event,
            correlation_group: None,
            in_attack_chain: false,
        }
    }
}

/// Event timeline
#[cfg(feature = "std")]
pub struct Timeline {
    /// Events in chronological order
    events: Vec<TimelineEvent>,
    /// Maximum age (seconds)
    max_age: u64,
    /// Event index by ID
    index: hashbrown::HashMap<u64, usize>,
}

#[cfg(feature = "std")]
impl Timeline {
    /// Create new timeline
    pub fn new(max_age: u64) -> Self {
        Self {
            events: Vec::new(),
            max_age,
            index: hashbrown::HashMap::new(),
        }
    }

    /// Add event
    pub fn add_event(&mut self, event: SecurityEvent) {
        let id = event.id;
        let idx = self.events.len();
        self.events.push(TimelineEvent::new(event));
        self.index.insert(id, idx);
    }

    /// Get event by ID
    pub fn get_event(&self, id: u64) -> Option<&TimelineEvent> {
        self.index.get(&id).and_then(|&idx| self.events.get(idx))
    }

    /// Get mutable event by ID
    pub fn get_event_mut(&mut self, id: u64) -> Option<&mut TimelineEvent> {
        self.index.get(&id).copied().and_then(move |idx| self.events.get_mut(idx))
    }

    /// Get events in time range
    pub fn events_in_range(&self, start: u64, end: u64) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.event.timestamp >= start && e.event.timestamp <= end)
            .collect()
    }

    /// Get events for entity
    pub fn events_for_entity(&self, entity_id: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.event.source.as_ref().map_or(false, |s| s.identifier == entity_id) ||
                e.event.target.as_ref().map_or(false, |t| t.identifier == entity_id)
            })
            .collect()
    }

    /// Get recent events
    pub fn recent_events(&self, count: usize) -> Vec<&TimelineEvent> {
        self.events.iter().rev().take(count).collect()
    }

    /// Get events by type
    pub fn events_by_type(&self, event_type: crate::EventType) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.event.event_type == event_type)
            .collect()
    }

    /// Mark events as correlated
    pub fn mark_correlated(&mut self, event_ids: &[u64], group_id: u64) {
        for &id in event_ids {
            if let Some(event) = self.get_event_mut(id) {
                event.correlation_group = Some(group_id);
            }
        }
    }

    /// Mark events as part of attack chain
    pub fn mark_attack_chain(&mut self, event_ids: &[u64]) {
        for &id in event_ids {
            if let Some(event) = self.get_event_mut(id) {
                event.in_attack_chain = true;
            }
        }
    }

    /// Get event count
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Cleanup old events
    pub fn cleanup(&mut self, current_time: u64) {
        let cutoff = current_time.saturating_sub(self.max_age);

        // Find first event to keep
        let keep_from = self.events
            .iter()
            .position(|e| e.event.timestamp >= cutoff)
            .unwrap_or(self.events.len());

        if keep_from > 0 {
            // Remove old events
            let removed: Vec<_> = self.events.drain(..keep_from).collect();

            // Update index
            for removed_event in removed {
                self.index.remove(&removed_event.event.id);
            }

            // Rebuild remaining indices
            self.index.clear();
            for (idx, event) in self.events.iter().enumerate() {
                self.index.insert(event.event.id, idx);
            }
        }
    }

    /// Get all events
    pub fn all_events(&self) -> &[TimelineEvent] {
        &self.events
    }

    /// Get events in correlation group
    pub fn events_in_group(&self, group_id: u64) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.correlation_group == Some(group_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventType, Entity};

    fn make_event(id: u64, timestamp: u64) -> SecurityEvent {
        SecurityEvent {
            id,
            timestamp,
            event_type: EventType::NetworkAnomaly,
            severity: 50,
            description: "Test event".into(),
            source: Some(Entity::from_ip([192, 168, 1, 10])),
            target: None,
            kill_chain_phase: None,
            evidence: Vec::new(),
            related_events: Vec::new(),
        }
    }

    #[test]
    fn test_timeline_add_get() {
        let mut timeline = Timeline::new(3600);

        timeline.add_event(make_event(1, 1000));
        timeline.add_event(make_event(2, 2000));

        assert_eq!(timeline.len(), 2);
        assert!(timeline.get_event(1).is_some());
        assert!(timeline.get_event(3).is_none());
    }

    #[test]
    fn test_time_range_query() {
        let mut timeline = Timeline::new(3600);

        timeline.add_event(make_event(1, 1000));
        timeline.add_event(make_event(2, 2000));
        timeline.add_event(make_event(3, 3000));

        let range = timeline.events_in_range(1500, 2500);
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].event.id, 2);
    }

    #[test]
    fn test_cleanup() {
        let mut timeline = Timeline::new(1000); // 1000 second window

        timeline.add_event(make_event(1, 1000));
        timeline.add_event(make_event(2, 2000));
        timeline.add_event(make_event(3, 3000));

        // Cleanup events older than 2500
        timeline.cleanup(3500);

        assert_eq!(timeline.len(), 1);
        assert!(timeline.get_event(3).is_some());
        assert!(timeline.get_event(1).is_none());
    }

    #[test]
    fn test_correlation_marking() {
        let mut timeline = Timeline::new(3600);

        timeline.add_event(make_event(1, 1000));
        timeline.add_event(make_event(2, 2000));

        timeline.mark_correlated(&[1, 2], 100);

        let event1 = timeline.get_event(1).unwrap();
        assert_eq!(event1.correlation_group, Some(100));
    }
}
