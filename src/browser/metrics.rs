// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Browser metrics and telemetry
//!
//! Collects performance and usage statistics for monitoring and optimization.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Browser metrics collector
#[derive(Debug, Default)]
pub struct BrowserMetrics {
    /// Number of pages created
    pages_created: AtomicU64,
    /// Number of pages closed
    pages_closed: AtomicU64,
    /// Number of HTTP requests made
    requests_made: AtomicU64,
    /// Number of JavaScript executions
    js_executions: AtomicU64,
    /// Number of XSS triggers detected
    xss_triggers_detected: AtomicU64,
    /// Number of forms extracted
    forms_extracted: AtomicU64,
    /// Number of navigation errors
    navigation_errors: AtomicU64,
    /// Total navigation time (milliseconds)
    total_navigation_ms: AtomicU64,
    /// Total JS execution time (milliseconds)
    total_js_execution_ms: AtomicU64,
    /// Start time for uptime calculation
    start_time: RwLock<Option<Instant>>,
    /// Request latencies for percentile calculation
    request_latencies: RwLock<Vec<u64>>,
    /// Memory usage snapshots
    memory_snapshots: RwLock<Vec<MemorySnapshot>>,
}

/// Memory snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Timestamp
    pub timestamp_ms: u64,
    /// Heap size in bytes (estimated)
    pub heap_size: usize,
    /// Active pages at snapshot time
    pub active_pages: u64,
}

/// Metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total pages created
    pub pages_created: u64,
    /// Total pages closed
    pub pages_closed: u64,
    /// Currently active pages
    pub active_pages: u64,
    /// Total HTTP requests
    pub requests_made: u64,
    /// Total JS executions
    pub js_executions: u64,
    /// Total XSS triggers
    pub xss_triggers_detected: u64,
    /// Total forms extracted
    pub forms_extracted: u64,
    /// Navigation errors
    pub navigation_errors: u64,
    /// Average navigation time (ms)
    pub avg_navigation_ms: f64,
    /// Average JS execution time (ms)
    pub avg_js_execution_ms: f64,
    /// Request latency percentiles
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_p99_ms: u64,
    /// Pages per second
    pub pages_per_second: f64,
    /// Requests per second
    pub requests_per_second: f64,
}

impl BrowserMetrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        let metrics = Self::default();
        *metrics.start_time.write() = Some(Instant::now());
        metrics
    }

    /// Record page creation
    pub fn record_page_created(&self) {
        self.pages_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Record page closed
    pub fn record_page_closed(&self) {
        self.pages_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record HTTP request
    pub fn record_request(&self, latency_ms: u64) {
        self.requests_made.fetch_add(1, Ordering::Relaxed);

        let mut latencies = self.request_latencies.write();
        latencies.push(latency_ms);

        // Keep only last 10000 latencies
        if latencies.len() > 10000 {
            latencies.drain(0..5000);
        }
    }

    /// Record JS execution
    pub fn record_js_execution(&self, duration_ms: u64) {
        self.js_executions.fetch_add(1, Ordering::Relaxed);
        self.total_js_execution_ms.fetch_add(duration_ms, Ordering::Relaxed);
    }

    /// Record XSS trigger detection
    pub fn record_xss_trigger(&self) {
        self.xss_triggers_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record form extraction
    pub fn record_form_extracted(&self) {
        self.forms_extracted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record navigation
    pub fn record_navigation(&self, duration_ms: u64, success: bool) {
        self.total_navigation_ms.fetch_add(duration_ms, Ordering::Relaxed);
        if !success {
            self.navigation_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record memory snapshot
    pub fn record_memory_snapshot(&self, heap_size: usize) {
        let active = self.pages_created.load(Ordering::Relaxed)
            - self.pages_closed.load(Ordering::Relaxed);

        let timestamp_ms = self.start_time.read()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        let mut snapshots = self.memory_snapshots.write();
        snapshots.push(MemorySnapshot {
            timestamp_ms,
            heap_size,
            active_pages: active,
        });

        // Keep only last 100 snapshots
        if snapshots.len() > 100 {
            snapshots.drain(0..50);
        }
    }

    /// Get current report
    pub fn report(&self) -> MetricsReport {
        let pages_created = self.pages_created.load(Ordering::Relaxed);
        let pages_closed = self.pages_closed.load(Ordering::Relaxed);
        let requests_made = self.requests_made.load(Ordering::Relaxed);
        let js_executions = self.js_executions.load(Ordering::Relaxed);

        let uptime_secs = self.start_time.read()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);

        let total_nav_ms = self.total_navigation_ms.load(Ordering::Relaxed);
        let total_js_ms = self.total_js_execution_ms.load(Ordering::Relaxed);

        // Calculate percentiles
        let latencies = self.request_latencies.read();
        let (p50, p95, p99) = calculate_percentiles(&latencies);

        // Calculate rates
        let uptime_f = uptime_secs.max(1) as f64;
        let pages_per_second = pages_created as f64 / uptime_f;
        let requests_per_second = requests_made as f64 / uptime_f;

        // Calculate averages
        let avg_navigation_ms = if pages_created > 0 {
            total_nav_ms as f64 / pages_created as f64
        } else {
            0.0
        };

        let avg_js_execution_ms = if js_executions > 0 {
            total_js_ms as f64 / js_executions as f64
        } else {
            0.0
        };

        MetricsReport {
            uptime_secs,
            pages_created,
            pages_closed,
            active_pages: pages_created.saturating_sub(pages_closed),
            requests_made,
            js_executions,
            xss_triggers_detected: self.xss_triggers_detected.load(Ordering::Relaxed),
            forms_extracted: self.forms_extracted.load(Ordering::Relaxed),
            navigation_errors: self.navigation_errors.load(Ordering::Relaxed),
            avg_navigation_ms,
            avg_js_execution_ms,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            pages_per_second,
            requests_per_second,
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.pages_created.store(0, Ordering::Relaxed);
        self.pages_closed.store(0, Ordering::Relaxed);
        self.requests_made.store(0, Ordering::Relaxed);
        self.js_executions.store(0, Ordering::Relaxed);
        self.xss_triggers_detected.store(0, Ordering::Relaxed);
        self.forms_extracted.store(0, Ordering::Relaxed);
        self.navigation_errors.store(0, Ordering::Relaxed);
        self.total_navigation_ms.store(0, Ordering::Relaxed);
        self.total_js_execution_ms.store(0, Ordering::Relaxed);
        *self.start_time.write() = Some(Instant::now());
        self.request_latencies.write().clear();
        self.memory_snapshots.write().clear();
    }

    /// Get memory snapshots
    pub fn memory_history(&self) -> Vec<MemorySnapshot> {
        self.memory_snapshots.read().clone()
    }
}

/// Calculate percentiles from latencies
fn calculate_percentiles(latencies: &[u64]) -> (u64, u64, u64) {
    if latencies.is_empty() {
        return (0, 0, 0);
    }

    let mut sorted: Vec<u64> = latencies.to_vec();
    sorted.sort_unstable();

    let len = sorted.len();
    let p50 = sorted[len / 2];
    let p95 = sorted[(len as f64 * 0.95) as usize];
    let p99 = sorted[(len as f64 * 0.99).min((len - 1) as f64) as usize];

    (p50, p95, p99)
}

/// Timer for measuring operations
pub struct MetricsTimer {
    start: Instant,
    metrics: Arc<BrowserMetrics>,
    operation: MetricsOperation,
}

/// Operation type for timer
#[derive(Debug, Clone, Copy)]
pub enum MetricsOperation {
    Navigation,
    JsExecution,
    Request,
}

impl MetricsTimer {
    /// Start a new timer
    pub fn start(metrics: Arc<BrowserMetrics>, operation: MetricsOperation) -> Self {
        Self {
            start: Instant::now(),
            metrics,
            operation,
        }
    }

    /// Stop timer and record
    pub fn stop(self) {
        self.stop_with_result(true);
    }

    /// Stop timer with success/failure
    pub fn stop_with_result(self, success: bool) {
        let duration_ms = self.start.elapsed().as_millis() as u64;

        match self.operation {
            MetricsOperation::Navigation => {
                self.metrics.record_navigation(duration_ms, success);
            }
            MetricsOperation::JsExecution => {
                self.metrics.record_js_execution(duration_ms);
            }
            MetricsOperation::Request => {
                self.metrics.record_request(duration_ms);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_basic() {
        let metrics = BrowserMetrics::new();

        metrics.record_page_created();
        metrics.record_page_created();
        metrics.record_request(100);
        metrics.record_request(200);
        metrics.record_xss_trigger();

        let report = metrics.report();
        assert_eq!(report.pages_created, 2);
        assert_eq!(report.requests_made, 2);
        assert_eq!(report.xss_triggers_detected, 1);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = BrowserMetrics::new();

        metrics.record_page_created();
        metrics.record_request(100);

        metrics.reset();

        let report = metrics.report();
        assert_eq!(report.pages_created, 0);
        assert_eq!(report.requests_made, 0);
    }

    #[test]
    fn test_percentiles() {
        let latencies: Vec<u64> = (1..=100).collect();
        let (p50, p95, p99) = calculate_percentiles(&latencies);

        assert_eq!(p50, 50);
        assert_eq!(p95, 95);
        assert_eq!(p99, 99);
    }
}
