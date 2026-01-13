// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Error types for Kalamari browser
//!
//! Provides detailed error context for debugging security scanners.
//! Each error type includes relevant context (URL, status, network log).

use std::collections::VecDeque;
use std::fmt;

use thiserror::Error;

/// Result type alias for Kalamari operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Kalamari browser
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// URL parsing failed
    #[error("Invalid URL: {0}")]
    Url(#[from] url::ParseError),

    /// HTML parsing failed
    #[error("HTML parsing error: {0}")]
    HtmlParse(String),

    /// JavaScript execution failed
    #[error("JavaScript error: {message}")]
    JavaScript {
        message: String,
        script: Option<String>,
        line: Option<u32>,
        column: Option<u32>,
    },

    /// DOM operation failed
    #[error("DOM error: {0}")]
    Dom(String),

    /// Network interception error
    #[error("Network error: {0}")]
    Network(String),

    /// Cookie handling error
    #[error("Cookie error: {0}")]
    Cookie(String),

    /// Timeout error
    #[error("Operation timed out after {duration_ms}ms: {operation}")]
    Timeout {
        operation: String,
        duration_ms: u64,
        url: Option<String>,
    },

    /// Navigation error with full context
    #[error("Navigation failed to {url}: {reason}")]
    NavigationFailed {
        url: String,
        status: Option<u16>,
        reason: String,
        redirect_chain: Vec<String>,
        network_log: VecDeque<NetworkLogEntry>,
    },

    /// XSS detection error
    #[error("XSS detection error: {0}")]
    XssDetection(String),

    /// Selector parsing error
    #[error("Invalid selector '{selector}': {reason}")]
    Selector { selector: String, reason: String },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Page not found or closed
    #[error("Page not found: {0}")]
    PageNotFound(String),

    /// Browser closed
    #[error("Browser has been closed")]
    BrowserClosed,

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Form submission error
    #[error("Form submission failed: {reason}")]
    FormSubmission {
        reason: String,
        form_action: Option<String>,
        status: Option<u16>,
    },

    /// Frame/iframe error
    #[error("Frame error: {reason}")]
    Frame {
        reason: String,
        frame_url: Option<String>,
        parent_url: Option<String>,
    },

    /// WebSocket error
    #[error("WebSocket error: {reason}")]
    WebSocket {
        reason: String,
        url: Option<String>,
        close_code: Option<u16>,
    },

    /// PDF generation error
    #[error("PDF generation failed: {0}")]
    PdfGeneration(String),

    /// Authentication error
    #[error("Authentication failed: {reason}")]
    Authentication {
        reason: String,
        url: Option<String>,
        status: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited by {url}: retry after {retry_after_secs:?}s")]
    RateLimited {
        url: String,
        retry_after_secs: Option<u64>,
    },

    /// SSL/TLS error
    #[error("SSL/TLS error for {url}: {reason}")]
    Ssl { url: String, reason: String },

    /// CORS blocked
    #[error("CORS blocked: {url} from {origin}")]
    CorsBlocked {
        url: String,
        origin: String,
        allowed_origins: Vec<String>,
    },

    /// Resource blocked (CSP, etc.)
    #[error("Resource blocked: {url} - {policy}")]
    ResourceBlocked { url: String, policy: String },

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Network log entry for debugging
#[derive(Debug, Clone)]
pub struct NetworkLogEntry {
    pub timestamp: std::time::SystemTime,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub error: Option<String>,
}

impl fmt::Display for NetworkLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.status, &self.error) {
            (Some(status), _) => write!(f, "{} {} -> {}", self.method, self.url, status),
            (None, Some(err)) => write!(f, "{} {} -> ERROR: {}", self.method, self.url, err),
            _ => write!(f, "{} {} -> pending", self.method, self.url),
        }
    }
}

impl Error {
    /// Create a new JavaScript error
    pub fn js<S: Into<String>>(msg: S) -> Self {
        Error::JavaScript {
            message: msg.into(),
            script: None,
            line: None,
            column: None,
        }
    }

    /// Create a JavaScript error with location
    pub fn js_with_location<S: Into<String>>(
        msg: S,
        script: Option<String>,
        line: u32,
        column: u32,
    ) -> Self {
        Error::JavaScript {
            message: msg.into(),
            script,
            line: Some(line),
            column: Some(column),
        }
    }

    /// Create a new DOM error
    pub fn dom<S: Into<String>>(msg: S) -> Self {
        Error::Dom(msg.into())
    }

    /// Create a new navigation error (simple)
    pub fn navigation<S: Into<String>>(msg: S) -> Self {
        Error::NavigationFailed {
            url: String::new(),
            status: None,
            reason: msg.into(),
            redirect_chain: Vec::new(),
            network_log: VecDeque::new(),
        }
    }

    /// Create a navigation error with full context
    pub fn navigation_failed(
        url: impl Into<String>,
        status: Option<u16>,
        reason: impl Into<String>,
    ) -> Self {
        Error::NavigationFailed {
            url: url.into(),
            status,
            reason: reason.into(),
            redirect_chain: Vec::new(),
            network_log: VecDeque::new(),
        }
    }

    /// Create a navigation error with network log
    pub fn navigation_with_log(
        url: impl Into<String>,
        status: Option<u16>,
        reason: impl Into<String>,
        network_log: VecDeque<NetworkLogEntry>,
    ) -> Self {
        Error::NavigationFailed {
            url: url.into(),
            status,
            reason: reason.into(),
            redirect_chain: Vec::new(),
            network_log,
        }
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        Error::Network(msg.into())
    }

    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, duration_ms: u64) -> Self {
        Error::Timeout {
            operation: operation.into(),
            duration_ms,
            url: None,
        }
    }

    /// Create a timeout error with URL
    pub fn timeout_with_url(
        operation: impl Into<String>,
        duration_ms: u64,
        url: impl Into<String>,
    ) -> Self {
        Error::Timeout {
            operation: operation.into(),
            duration_ms,
            url: Some(url.into()),
        }
    }

    /// Create a selector error
    pub fn selector(selector: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::Selector {
            selector: selector.into(),
            reason: reason.into(),
        }
    }

    /// Create a form submission error
    pub fn form_submission(reason: impl Into<String>) -> Self {
        Error::FormSubmission {
            reason: reason.into(),
            form_action: None,
            status: None,
        }
    }

    /// Create a frame error
    pub fn frame(reason: impl Into<String>) -> Self {
        Error::Frame {
            reason: reason.into(),
            frame_url: None,
            parent_url: None,
        }
    }

    /// Create a WebSocket error
    pub fn websocket(reason: impl Into<String>) -> Self {
        Error::WebSocket {
            reason: reason.into(),
            url: None,
            close_code: None,
        }
    }

    /// Create an authentication error
    pub fn auth(reason: impl Into<String>) -> Self {
        Error::Authentication {
            reason: reason.into(),
            url: None,
            status: None,
        }
    }

    /// Create a generic error
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }

    /// Check if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }

    /// Check if this is a network error
    pub fn is_network(&self) -> bool {
        matches!(self, Error::Network(_) | Error::Http(_))
    }

    /// Check if this is recoverable (can retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Timeout { .. }
                | Error::RateLimited { .. }
                | Error::Network(_)
                | Error::Http(_)
        )
    }

    /// Check if this is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        match self {
            Error::NavigationFailed { status: Some(s), .. } => (400..500).contains(s),
            Error::FormSubmission { status: Some(s), .. } => (400..500).contains(s),
            Error::Authentication { status: Some(s), .. } => (400..500).contains(s),
            _ => false,
        }
    }

    /// Check if this is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        match self {
            Error::NavigationFailed { status: Some(s), .. } => (500..600).contains(s),
            Error::FormSubmission { status: Some(s), .. } => (500..600).contains(s),
            _ => false,
        }
    }

    /// Get HTTP status code if available
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Error::NavigationFailed { status, .. } => *status,
            Error::FormSubmission { status, .. } => *status,
            Error::Authentication { status, .. } => *status,
            _ => None,
        }
    }

    /// Get URL if available
    pub fn url(&self) -> Option<&str> {
        match self {
            Error::NavigationFailed { url, .. } => Some(url),
            Error::Timeout { url: Some(u), .. } => Some(u),
            Error::WebSocket { url: Some(u), .. } => Some(u),
            Error::Ssl { url, .. } => Some(url),
            Error::CorsBlocked { url, .. } => Some(url),
            Error::ResourceBlocked { url, .. } => Some(url),
            Error::RateLimited { url, .. } => Some(url),
            _ => None,
        }
    }

    /// Add network log to navigation error
    pub fn with_network_log(mut self, log: VecDeque<NetworkLogEntry>) -> Self {
        if let Error::NavigationFailed {
            ref mut network_log,
            ..
        } = self
        {
            *network_log = log;
        }
        self
    }

    /// Add redirect chain to navigation error
    pub fn with_redirect_chain(mut self, chain: Vec<String>) -> Self {
        if let Error::NavigationFailed {
            ref mut redirect_chain,
            ..
        } = self
        {
            *redirect_chain = chain;
        }
        self
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

/// Helper trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add URL context to error
    fn with_url(self, url: &str) -> Result<T>;

    /// Add operation context to error
    fn context(self, msg: &str) -> Result<T>;
}

impl<T, E: Into<Error>> ErrorContext<T> for std::result::Result<T, E> {
    fn with_url(self, url: &str) -> Result<T> {
        self.map_err(|e| {
            let err = e.into();
            match err {
                Error::Timeout {
                    operation,
                    duration_ms,
                    ..
                } => Error::Timeout {
                    operation,
                    duration_ms,
                    url: Some(url.to_string()),
                },
                other => other,
            }
        })
    }

    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| {
            let err = e.into();
            Error::Other(format!("{}: {}", msg, err))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_error() {
        let err = Error::navigation_failed("https://example.com", Some(403), "Forbidden");

        assert!(err.is_client_error());
        assert_eq!(err.status_code(), Some(403));
        assert_eq!(err.url(), Some("https://example.com"));
    }

    #[test]
    fn test_timeout_error() {
        let err = Error::timeout_with_url("navigation", 5000, "https://example.com");

        assert!(err.is_timeout());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_network_log() {
        let mut log = VecDeque::new();
        log.push_back(NetworkLogEntry {
            timestamp: std::time::SystemTime::now(),
            method: "GET".to_string(),
            url: "https://example.com".to_string(),
            status: Some(301),
            error: None,
        });

        let err =
            Error::navigation_failed("https://example.com/final", Some(403), "Forbidden")
                .with_network_log(log);

        if let Error::NavigationFailed { network_log, .. } = err {
            assert_eq!(network_log.len(), 1);
        } else {
            panic!("Expected NavigationFailed");
        }
    }
}
