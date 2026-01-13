// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Network event types

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Network event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: EventType,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Request information
    pub request: RequestInfo,
    /// Response information (if available)
    pub response: Option<ResponseInfo>,
    /// Duration
    pub duration: Option<Duration>,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether this was initiated by JavaScript
    pub js_initiated: bool,
    /// Initiator URL
    pub initiator: Option<String>,
}

/// Event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Document navigation
    Navigation,
    /// XHR request
    Xhr,
    /// Fetch request
    Fetch,
    /// Script load
    Script,
    /// Stylesheet load
    Stylesheet,
    /// Image load
    Image,
    /// Font load
    Font,
    /// WebSocket connection
    WebSocket,
    /// Form submission
    FormSubmission,
    /// Iframe load
    Iframe,
    /// Other resource
    Other,
}

/// Request information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInfo {
    /// Request URL
    pub url: String,
    /// HTTP method
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body
    pub body: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Cookies sent
    pub cookies: Option<String>,
    /// Whether credentials were included
    pub with_credentials: bool,
}

/// Response information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// Status code
    pub status: u16,
    /// Status text
    pub status_text: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (may be truncated)
    pub body: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Content length
    pub content_length: Option<usize>,
    /// Set-Cookie headers
    pub set_cookies: Vec<String>,
    /// Whether response was from cache
    pub from_cache: bool,
}

impl NetworkEvent {
    /// Create a new network event
    pub fn new(id: impl Into<String>, event_type: EventType, request: RequestInfo) -> Self {
        Self {
            id: id.into(),
            event_type,
            timestamp: SystemTime::now(),
            request,
            response: None,
            duration: None,
            error: None,
            js_initiated: false,
            initiator: None,
        }
    }

    /// Set response
    pub fn with_response(mut self, response: ResponseInfo) -> Self {
        self.response = Some(response);
        self
    }

    /// Set duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set error
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Mark as JS initiated
    pub fn js_initiated(mut self) -> Self {
        self.js_initiated = true;
        self
    }

    /// Set initiator
    pub fn with_initiator(mut self, initiator: impl Into<String>) -> Self {
        self.initiator = Some(initiator.into());
        self
    }

    /// Check if this is an API request
    pub fn is_api_request(&self) -> bool {
        let url_lower = self.request.url.to_lowercase();

        // Check URL patterns
        if url_lower.contains("/api/")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/graphql")
            || url_lower.contains("/rest/")
        {
            return true;
        }

        // Check content type
        if let Some(ref ct) = self.request.content_type {
            if ct.contains("application/json") || ct.contains("application/xml") {
                return true;
            }
        }

        // Check event type
        matches!(self.event_type, EventType::Xhr | EventType::Fetch)
    }

    /// Check if this is a form submission
    pub fn is_form_submission(&self) -> bool {
        if self.event_type == EventType::FormSubmission {
            return true;
        }

        if let Some(ref ct) = self.request.content_type {
            if ct.contains("application/x-www-form-urlencoded")
                || ct.contains("multipart/form-data")
            {
                return true;
            }
        }

        false
    }

    /// Check if response was successful
    pub fn is_success(&self) -> bool {
        self.response
            .as_ref()
            .map(|r| r.status >= 200 && r.status < 300)
            .unwrap_or(false)
    }

    /// Check if response is HTML
    pub fn is_html(&self) -> bool {
        self.response
            .as_ref()
            .and_then(|r| r.content_type.as_ref())
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false)
    }

    /// Check if response is JSON
    pub fn is_json(&self) -> bool {
        self.response
            .as_ref()
            .and_then(|r| r.content_type.as_ref())
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }

    /// Get response body if JSON
    pub fn json_body<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        self.response
            .as_ref()
            .and_then(|r| r.body.as_ref())
            .and_then(|body| serde_json::from_str(body).ok())
    }
}

impl RequestInfo {
    /// Create a new request info
    pub fn new(url: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: method.into(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
            cookies: None,
            with_credentials: false,
        }
    }

    /// Add header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Add body
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Get URL parameters
    pub fn url_params(&self) -> HashMap<String, String> {
        if let Ok(url) = url::Url::parse(&self.url) {
            url.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Get body parameters (for form data)
    pub fn body_params(&self) -> HashMap<String, String> {
        self.body
            .as_ref()
            .map(|body| {
                body.split('&')
                    .filter_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        Some((
                            urlencoding_decode(parts.next()?),
                            urlencoding_decode(parts.next().unwrap_or("")),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl ResponseInfo {
    /// Create a new response info
    pub fn new(status: u16, status_text: impl Into<String>) -> Self {
        Self {
            status,
            status_text: status_text.into(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
            content_length: None,
            set_cookies: Vec::new(),
            from_cache: false,
        }
    }

    /// Check if redirect
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Get redirect location
    pub fn redirect_location(&self) -> Option<&str> {
        self.headers.get("location").map(|s| s.as_str())
    }
}

/// Simple URL decoding
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push_str(&hex);
                    }
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_event() {
        let request = RequestInfo::new("https://api.example.com/users", "GET");
        let event = NetworkEvent::new("1", EventType::Xhr, request);

        assert!(event.is_api_request());
    }

    #[test]
    fn test_url_params() {
        let request = RequestInfo::new("https://example.com?foo=bar&baz=qux", "GET");
        let params = request.url_params();

        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_body_params() {
        let request =
            RequestInfo::new("https://example.com", "POST").with_body("username=test&password=pass");
        let params = request.body_params();

        assert_eq!(params.get("username"), Some(&"test".to_string()));
        assert_eq!(params.get("password"), Some(&"pass".to_string()));
    }
}
