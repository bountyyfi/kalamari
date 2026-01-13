// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Timer queue for setTimeout/setInterval management
//!
//! Provides Lonkero-compatible JS timing control:
//! - `flush_timers()` - Execute all pending timers immediately
//! - `wait_for_js_idle()` - Wait until no pending timers

use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Timer callback type
pub type TimerCallback = Box<dyn FnOnce() + Send + Sync>;

/// Timer entry in the queue
pub struct TimerEntry {
    /// Unique timer ID
    pub id: u32,
    /// When the timer should fire
    pub fire_at: Instant,
    /// The callback code to execute
    pub code: String,
    /// Whether this is an interval (repeating)
    pub is_interval: bool,
    /// Interval duration (for repeating timers)
    pub interval_ms: u64,
}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for TimerEntry {}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse order for min-heap (earliest fires first)
        other.fire_at.cmp(&self.fire_at)
    }
}

/// Timer queue for managing setTimeout/setInterval
pub struct TimerQueue {
    /// Pending timers (min-heap by fire_at)
    timers: Arc<RwLock<BinaryHeap<TimerEntry>>>,
    /// Next timer ID
    next_id: AtomicU32,
    /// Cancelled timer IDs
    cancelled: Arc<RwLock<Vec<u32>>>,
    /// Maximum timers to prevent infinite loops
    max_timers: usize,
}

impl Default for TimerQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerQueue {
    /// Create a new timer queue
    pub fn new() -> Self {
        Self {
            timers: Arc::new(RwLock::new(BinaryHeap::new())),
            next_id: AtomicU32::new(1),
            cancelled: Arc::new(RwLock::new(Vec::new())),
            max_timers: 1000, // Prevent runaway timers
        }
    }

    /// Create with custom max timers limit
    pub fn with_max_timers(max: usize) -> Self {
        Self {
            max_timers: max,
            ..Self::new()
        }
    }

    /// Schedule a setTimeout
    pub fn set_timeout(&self, code: String, delay_ms: u64) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let fire_at = Instant::now() + Duration::from_millis(delay_ms);

        let entry = TimerEntry {
            id,
            fire_at,
            code,
            is_interval: false,
            interval_ms: 0,
        };

        let mut timers = self.timers.write();
        if timers.len() < self.max_timers {
            timers.push(entry);
        }

        id
    }

    /// Schedule a setInterval
    pub fn set_interval(&self, code: String, interval_ms: u64) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let fire_at = Instant::now() + Duration::from_millis(interval_ms);

        let entry = TimerEntry {
            id,
            fire_at,
            code,
            is_interval: true,
            interval_ms,
        };

        let mut timers = self.timers.write();
        if timers.len() < self.max_timers {
            timers.push(entry);
        }

        id
    }

    /// Cancel a timer (setTimeout or setInterval)
    pub fn clear_timer(&self, id: u32) {
        self.cancelled.write().push(id);
    }

    /// Check if there are pending timers
    pub fn has_pending(&self) -> bool {
        let timers = self.timers.read();
        let cancelled = self.cancelled.read();

        timers.iter().any(|t| !cancelled.contains(&t.id))
    }

    /// Get number of pending timers
    pub fn pending_count(&self) -> usize {
        let timers = self.timers.read();
        let cancelled = self.cancelled.read();

        timers.iter().filter(|t| !cancelled.contains(&t.id)).count()
    }

    /// Get timers that are ready to fire
    pub fn get_ready_timers(&self) -> Vec<TimerEntry> {
        let now = Instant::now();
        let mut timers = self.timers.write();
        let cancelled = self.cancelled.read();

        let mut ready = Vec::new();
        let mut remaining = BinaryHeap::new();

        while let Some(entry) = timers.pop() {
            if cancelled.contains(&entry.id) {
                continue;
            }

            if entry.fire_at <= now {
                // Timer is ready
                if entry.is_interval {
                    // Re-schedule interval timer
                    let next_entry = TimerEntry {
                        id: entry.id,
                        fire_at: now + Duration::from_millis(entry.interval_ms),
                        code: entry.code.clone(),
                        is_interval: true,
                        interval_ms: entry.interval_ms,
                    };
                    remaining.push(next_entry);
                }
                ready.push(entry);
            } else {
                remaining.push(entry);
            }
        }

        *timers = remaining;
        ready
    }

    /// Flush all pending timers immediately (execute all)
    /// Returns the code strings to execute
    pub fn flush_all(&self) -> Vec<String> {
        let mut timers = self.timers.write();
        let cancelled = self.cancelled.read();

        let mut code_to_execute = Vec::new();
        let mut seen_intervals = std::collections::HashSet::new();

        // Execute all timers, intervals only once
        while let Some(entry) = timers.pop() {
            if cancelled.contains(&entry.id) {
                continue;
            }

            if entry.is_interval {
                if seen_intervals.contains(&entry.id) {
                    continue;
                }
                seen_intervals.insert(entry.id);
            }

            code_to_execute.push(entry.code);
        }

        // Clear cancelled list
        drop(cancelled);
        self.cancelled.write().clear();

        code_to_execute
    }

    /// Flush timers up to a maximum count (for safety)
    pub fn flush_limited(&self, max_executions: usize) -> Vec<String> {
        let mut code_to_execute = Vec::new();

        for _ in 0..max_executions {
            let ready = self.get_ready_timers();
            if ready.is_empty() {
                break;
            }
            for entry in ready {
                code_to_execute.push(entry.code);
            }
        }

        code_to_execute
    }

    /// Clear all timers
    pub fn clear_all(&self) {
        self.timers.write().clear();
        self.cancelled.write().clear();
    }

    /// Wait duration until next timer fires (for scheduling)
    pub fn time_until_next(&self) -> Option<Duration> {
        let timers = self.timers.read();
        let cancelled = self.cancelled.read();
        let now = Instant::now();

        timers
            .iter()
            .filter(|t| !cancelled.contains(&t.id))
            .map(|t| {
                if t.fire_at > now {
                    t.fire_at - now
                } else {
                    Duration::ZERO
                }
            })
            .min()
    }
}

/// Result of waiting for JS idle
#[derive(Debug, Clone)]
pub struct JsIdleResult {
    /// Whether we reached idle state
    pub is_idle: bool,
    /// Number of timers executed
    pub timers_executed: usize,
    /// Total wait time
    pub wait_time: Duration,
    /// Whether we hit the timeout
    pub timed_out: bool,
}

/// Configuration for wait_for_js_idle
#[derive(Debug, Clone)]
pub struct JsIdleConfig {
    /// Maximum time to wait for idle
    pub timeout: Duration,
    /// Maximum timers to execute
    pub max_timer_executions: usize,
    /// Minimum idle time before considering idle
    pub idle_threshold: Duration,
}

impl Default for JsIdleConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_timer_executions: 100,
            idle_threshold: Duration::from_millis(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_timeout() {
        let queue = TimerQueue::new();
        let id = queue.set_timeout("console.log('test')".to_string(), 100);
        assert!(id > 0);
        assert!(queue.has_pending());
    }

    #[test]
    fn test_clear_timeout() {
        let queue = TimerQueue::new();
        let id = queue.set_timeout("console.log('test')".to_string(), 100);
        queue.clear_timer(id);

        // Timer still in queue but marked cancelled
        let timers = queue.timers.read();
        assert!(!timers.is_empty());
    }

    #[test]
    fn test_flush_all() {
        let queue = TimerQueue::new();
        queue.set_timeout("code1".to_string(), 100);
        queue.set_timeout("code2".to_string(), 200);

        let code = queue.flush_all();
        assert_eq!(code.len(), 2);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_set_interval() {
        let queue = TimerQueue::new();
        let id = queue.set_interval("tick".to_string(), 100);
        assert!(id > 0);

        // Flush limited should only execute once per interval
        let code = queue.flush_all();
        assert_eq!(code.len(), 1);
    }
}
