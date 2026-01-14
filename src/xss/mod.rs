// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! XSS Detection module
//!
//! Provides comprehensive XSS detection including:
//! - alert/confirm/prompt interception
//! - DOM sink detection
//! - Event handler analysis
//! - Payload generation and testing
//! - Stored XSS detection flow

mod detector;
mod payloads;
mod sinks;
mod stored;

pub use detector::{XssDetector, XssDetectorConfig};
pub use payloads::{XssPayload, PayloadGenerator, PayloadContext};
pub use sinks::{DomSink, SinkType, SinkAnalyzer};
pub use stored::{StoredXssTest, StoredXssResult, StoredXssTester, stored_xss_payloads};

use serde::{Deserialize, Serialize};

/// XSS trigger information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssTrigger {
    /// Type of XSS trigger
    pub trigger_type: XssTriggerType,
    /// The payload that triggered XSS
    pub payload: String,
    /// Context where XSS was detected
    pub context: String,
    /// URL where XSS was found
    pub url: Option<String>,
}

/// Types of XSS triggers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XssTriggerType {
    /// alert() was called
    Alert,
    /// confirm() was called
    Confirm,
    /// prompt() was called
    Prompt,
    /// eval() with suspicious content
    Eval,
    /// document.write() usage
    DocumentWrite,
    /// innerHTML assignment
    InnerHtml,
    /// Event handler execution
    EventHandler,
    /// DOM manipulation
    DomManipulation,
    /// Script injection
    ScriptInjection,
    /// Error-based detection
    ErrorBased,
    /// Custom marker detection
    CustomMarker,
}

impl XssTrigger {
    /// Create a new XSS trigger
    pub fn new(trigger_type: XssTriggerType, payload: impl Into<String>) -> Self {
        Self {
            trigger_type,
            payload: payload.into(),
            context: String::new(),
            url: None,
        }
    }

    /// Add context
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    /// Add URL
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Get severity score (0-10)
    pub fn severity(&self) -> u8 {
        match self.trigger_type {
            XssTriggerType::Alert
            | XssTriggerType::Confirm
            | XssTriggerType::Prompt => 10, // Confirmed XSS
            XssTriggerType::ScriptInjection => 10,
            XssTriggerType::Eval => 9,
            XssTriggerType::DocumentWrite => 8,
            XssTriggerType::InnerHtml => 7,
            XssTriggerType::EventHandler => 7,
            XssTriggerType::DomManipulation => 6,
            XssTriggerType::ErrorBased => 5,
            XssTriggerType::CustomMarker => 8,
        }
    }

    /// Check if this is a confirmed XSS (JavaScript executed)
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self.trigger_type,
            XssTriggerType::Alert
                | XssTriggerType::Confirm
                | XssTriggerType::Prompt
                | XssTriggerType::ScriptInjection
        )
    }
}

impl std::fmt::Display for XssTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {} (severity: {})",
            self.trigger_type,
            self.payload,
            self.severity()
        )
    }
}

/// XSS detection result
#[derive(Debug, Clone, Default)]
pub struct XssResult {
    /// All detected triggers
    pub triggers: Vec<XssTrigger>,
    /// URL tested
    pub url: Option<String>,
    /// Parameter tested
    pub parameter: Option<String>,
    /// Original value
    pub original_value: Option<String>,
    /// Payload used
    pub payload_used: Option<String>,
    /// Response contains reflection
    pub has_reflection: bool,
    /// Response size
    pub response_size: usize,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

impl XssResult {
    /// Check if XSS was found
    pub fn is_vulnerable(&self) -> bool {
        self.triggers.iter().any(|t| t.is_confirmed())
    }

    /// Get the highest severity trigger
    pub fn highest_severity(&self) -> Option<&XssTrigger> {
        self.triggers.iter().max_by_key(|t| t.severity())
    }

    /// Get confirmed triggers only
    pub fn confirmed_triggers(&self) -> Vec<&XssTrigger> {
        self.triggers.iter().filter(|t| t.is_confirmed()).collect()
    }
}
