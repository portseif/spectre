//! Per-investigation event queues.
//!
//! Producers (provider tasks) push without blocking. Consumers either block on
//! a condition variable with a timeout (the FFI, called from a background
//! thread in the host app) or await via `spawn_blocking` (the CLI).

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use spectre_core::model::{InvestigationEvent, InvestigationEventKind};
use uuid::Uuid;

/// Events beyond this are dropped oldest-first (terminal events are kept).
const MAX_QUEUED_EVENTS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<InvestigationEvent>,
    /// The investigation has finished and every event has been delivered.
    pub finished: bool,
    /// No queue exists (never started in this process or already drained).
    pub unknown: bool,
}

#[derive(Default)]
struct Queue {
    events: VecDeque<InvestigationEvent>,
    next_sequence: u64,
    finished: bool,
}

#[derive(Default)]
pub struct EventHub {
    queues: Mutex<HashMap<Uuid, Queue>>,
    signal: Condvar,
}

impl EventHub {
    pub fn open(&self, investigation_id: Uuid) {
        self.queues.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(investigation_id).or_default();
    }

    pub fn push(&self, investigation_id: Uuid, kind: InvestigationEventKind) {
        let mut queues = self.queues.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let queue = queues.entry(investigation_id).or_default();
        queue.next_sequence += 1;
        queue.finished |= kind.is_terminal();
        queue.events.push_back(InvestigationEvent { investigation_id, sequence: queue.next_sequence, emitted_at: Utc::now(), event: kind });
        while queue.events.len() > MAX_QUEUED_EVENTS {
            if let Some(index) = queue.events.iter().position(|event| !event.event.is_terminal()) {
                queue.events.remove(index);
            } else {
                break;
            }
        }
        drop(queues);
        self.signal.notify_all();
    }

    /// Wait up to `timeout` for events, then drain up to `max_events`.
    pub fn wait(&self, investigation_id: Uuid, max_events: usize, timeout: Duration) -> EventBatch {
        let deadline = Instant::now() + timeout;
        let mut queues = self.queues.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match queues.get(&investigation_id) {
                None => return EventBatch { events: Vec::new(), finished: true, unknown: true },
                Some(queue) if !queue.events.is_empty() || queue.finished => break,
                Some(_) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return EventBatch { events: Vec::new(), finished: false, unknown: false };
            }
            queues = self.signal.wait_timeout(queues, deadline - now).unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
        let queue = queues.get_mut(&investigation_id).expect("queue checked above");
        let take = max_events.max(1).min(queue.events.len());
        let events: Vec<InvestigationEvent> = queue.events.drain(..take).collect();
        let finished = queue.finished && queue.events.is_empty();
        if finished {
            queues.remove(&investigation_id);
        }
        EventBatch { events, finished, unknown: false }
    }

    pub fn discard(&self, investigation_id: Uuid) {
        self.queues.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&investigation_id);
        self.signal.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use spectre_core::model::{InvestigationMetrics, InvestigationStatus};

    use super::*;

    #[test]
    fn wait_times_out_then_delivers_in_order() {
        let hub = Arc::new(EventHub::default());
        let investigation = Uuid::new_v4();
        hub.open(investigation);
        let empty = hub.wait(investigation, 10, Duration::from_millis(20));
        assert!(empty.events.is_empty() && !empty.finished && !empty.unknown);

        let producer = Arc::clone(&hub);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            producer.push(investigation, InvestigationEventKind::Progress { progress: 0.5 });
            producer.push(
                investigation,
                InvestigationEventKind::Finished { status: InvestigationStatus::Completed, metrics: InvestigationMetrics::default() },
            );
        });
        let first = hub.wait(investigation, 1, Duration::from_secs(2));
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].sequence, 1);
        handle.join().unwrap();
        let rest = hub.wait(investigation, 10, Duration::from_secs(1));
        assert_eq!(rest.events[0].sequence, 2);
        assert!(rest.finished);
        assert!(hub.wait(investigation, 10, Duration::from_millis(1)).unknown, "drained queues are removed");
    }
}
