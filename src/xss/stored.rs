// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Stored XSS detection flow
//!
//! Detects stored/persistent XSS by:
//! 1. Submitting payload via form
//! 2. Checking multiple reflection points
//! 3. Verifying payload execution

use serde::{Deserialize, Serialize};

use crate::browser::Form;
use crate::error::Result;
use crate::xss::XssTrigger;

/// Stored XSS test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredXssTest {
    /// URL where payload is submitted (form page)
    pub inject_url: String,
    /// URLs where payload might be reflected
    pub reflect_urls: Vec<String>,
    /// XSS payload to inject
    pub payload: String,
    /// Form field name to inject into
    pub form_field: String,
    /// Optional: specific form selector
    pub form_selector: Option<String>,
    /// Optional: additional form data
    pub extra_fields: Vec<(String, String)>,
    /// Unique marker to identify our payload
    pub marker: String,
}

impl StoredXssTest {
    /// Create a new stored XSS test
    pub fn new(inject_url: impl Into<String>, payload: impl Into<String>) -> Self {
        let marker = format!("KALAMARI_{}", uuid_simple());
        Self {
            inject_url: inject_url.into(),
            reflect_urls: Vec::new(),
            payload: payload.into(),
            form_field: String::new(),
            form_selector: None,
            extra_fields: Vec::new(),
            marker,
        }
    }

    /// Set the form field to inject into
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.form_field = field.into();
        self
    }

    /// Add a reflection URL to check
    pub fn reflect_at(mut self, url: impl Into<String>) -> Self {
        self.reflect_urls.push(url.into());
        self
    }

    /// Add multiple reflection URLs
    pub fn reflect_at_all(mut self, urls: Vec<String>) -> Self {
        self.reflect_urls.extend(urls);
        self
    }

    /// Set form selector
    pub fn form(mut self, selector: impl Into<String>) -> Self {
        self.form_selector = Some(selector.into());
        self
    }

    /// Add extra form field
    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_fields.push((name.into(), value.into()));
        self
    }

    /// Get payload with marker
    pub fn marked_payload(&self) -> String {
        self.payload.replace("MARKER", &self.marker)
    }
}

/// Result of stored XSS test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoredXssResult {
    /// XSS vulnerability confirmed
    Vulnerable {
        /// Where payload was injected
        inject_point: String,
        /// Where payload was reflected/executed
        reflect_point: String,
        /// XSS triggers detected
        triggers: Vec<XssTrigger>,
        /// The payload that worked
        payload: String,
    },
    /// Payload was stored but not executed (potential)
    PayloadStored {
        /// Where payload was found
        reflect_point: String,
        /// Raw payload in page
        payload_in_page: String,
    },
    /// No vulnerability found
    NotVulnerable {
        /// Reflection points checked
        checked_urls: Vec<String>,
    },
    /// Test failed (couldn't submit form, etc.)
    TestFailed {
        /// Error message
        reason: String,
    },
}

impl StoredXssResult {
    /// Check if vulnerable
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, StoredXssResult::Vulnerable { .. })
    }

    /// Check if potentially vulnerable (payload stored but not executed)
    pub fn is_potential(&self) -> bool {
        matches!(self, StoredXssResult::PayloadStored { .. })
    }
}

/// Stored XSS test runner
pub struct StoredXssTester {
    /// Maximum reflection URLs to check
    pub max_reflect_checks: usize,
    /// Wait time between inject and reflect check (ms)
    pub wait_after_inject_ms: u64,
    /// Whether to check for payload in page source (not just execution)
    pub check_source: bool,
}

impl Default for StoredXssTester {
    fn default() -> Self {
        Self {
            max_reflect_checks: 10,
            wait_after_inject_ms: 500,
            check_source: true,
        }
    }
}

impl StoredXssTester {
    /// Create new tester
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max reflection checks
    pub fn max_checks(mut self, max: usize) -> Self {
        self.max_reflect_checks = max;
        self
    }

    /// Set wait time after injection
    pub fn wait_ms(mut self, ms: u64) -> Self {
        self.wait_after_inject_ms = ms;
        self
    }

    /// Enable/disable source checking
    pub fn check_source(mut self, check: bool) -> Self {
        self.check_source = check;
        self
    }
}

/// Form fill result
#[derive(Debug, Clone)]
pub struct FormFillResult {
    /// Whether form was found
    pub form_found: bool,
    /// Whether submission succeeded
    pub submitted: bool,
    /// Response status
    pub status: Option<u16>,
    /// Redirect URL if any
    pub redirect_url: Option<String>,
}

/// Common stored XSS payloads
pub fn stored_xss_payloads(marker: &str) -> Vec<String> {
    vec![
        format!("<script>alert('{}')</script>", marker),
        format!("<img src=x onerror=alert('{}')>", marker),
        format!("<svg onload=alert('{}')>", marker),
        format!("javascript:alert('{}')", marker),
        format!("<body onload=alert('{}')>", marker),
        format!("'\"><script>alert('{}')</script>", marker),
        format!("<iframe src=\"javascript:alert('{}')\">", marker),
        format!("<input onfocus=alert('{}') autofocus>", marker),
        format!("<marquee onstart=alert('{}')>", marker),
        format!("<details open ontoggle=alert('{}')>", marker),
    ]
}

/// Generate simple UUID-like string
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_xss_test_builder() {
        let test = StoredXssTest::new("https://example.com/post", "<script>alert(1)</script>")
            .field("comment")
            .reflect_at("https://example.com/posts")
            .reflect_at("https://example.com/profile")
            .with_field("title", "Test Post");

        assert_eq!(test.inject_url, "https://example.com/post");
        assert_eq!(test.reflect_urls.len(), 2);
        assert_eq!(test.form_field, "comment");
    }

    #[test]
    fn test_stored_xss_payloads() {
        let payloads = stored_xss_payloads("TEST123");
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("TEST123"));
    }
}
