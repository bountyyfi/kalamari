// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Error types for Kalamari browser

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
    #[error("JavaScript error: {0}")]
    JavaScript(String),

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
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Navigation error
    #[error("Navigation failed: {0}")]
    Navigation(String),

    /// XSS detection error
    #[error("XSS detection error: {0}")]
    XssDetection(String),

    /// Selector parsing error
    #[error("Invalid selector: {0}")]
    Selector(String),

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

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a new JavaScript error
    pub fn js<S: Into<String>>(msg: S) -> Self {
        Error::JavaScript(msg.into())
    }

    /// Create a new DOM error
    pub fn dom<S: Into<String>>(msg: S) -> Self {
        Error::Dom(msg.into())
    }

    /// Create a new navigation error
    pub fn navigation<S: Into<String>>(msg: S) -> Self {
        Error::Navigation(msg.into())
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        Error::Network(msg.into())
    }

    /// Create a generic error
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }

    /// Check if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout(_))
    }

    /// Check if this is a network error
    pub fn is_network(&self) -> bool {
        matches!(self, Error::Network(_) | Error::Http(_))
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
