// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Network event types

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Network event with full metadata for security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: EventType,
    /// Request type (more specific than event_type)
    pub request_type: RequestType,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Request information
    pub request: RequestInfo,
    /// Response information (if available)
    pub response: Option<ResponseInfo>,
    /// Duration
    pub duration: Option<Duration>,
    /// Request timing breakdown (for timing attack detection)
    pub timing: Option<RequestTiming>,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether this was initiated by JavaScript
    pub js_initiated: bool,
    /// Initiator URL or script that triggered this request
    pub initiator: Option<String>,
    /// Stack trace of initiator (if available)
    pub initiator_stack: Option<String>,
    /// Frame ID (for iframe requests)
    pub frame_id: Option<String>,
    /// Security info
    pub security: Option<SecurityInfo>,
}

/// More specific request type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestType {
    /// Direct navigation
    Document,
    /// XMLHttpRequest
    XHR,
    /// Fetch API
    Fetch,
    /// WebSocket handshake
    WebSocket,
    /// WebSocket message
    WebSocketMessage,
    /// EventSource/SSE
    EventSource,
    /// Beacon API
    Beacon,
    /// Script tag
    Script,
    /// Link stylesheet
    Stylesheet,
    /// Image
    Image,
    /// Font
    Font,
    /// Media (audio/video)
    Media,
    /// Prefetch/preload
    Prefetch,
    /// Service worker
    ServiceWorker,
    /// Form submission
    Form,
    /// Iframe navigation
    IFrame,
    /// Unknown
    Other,
}

/// Request timing breakdown (similar to PerformanceResourceTiming)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTiming {
    /// Time when request started
    pub start_time: f64,
    /// DNS lookup time
    pub dns_time: Option<f64>,
    /// TCP connection time
    pub connect_time: Option<f64>,
    /// TLS handshake time
    pub tls_time: Option<f64>,
    /// Time to first byte (TTFB)
    pub ttfb: Option<f64>,
    /// Content download time
    pub download_time: Option<f64>,
    /// Total time
    pub total_time: f64,
    /// Whether connection was reused
    pub connection_reused: bool,
}

/// Security information for the request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    /// Protocol (TLS version)
    pub protocol: Option<String>,
    /// Cipher suite
    pub cipher: Option<String>,
    /// Certificate issuer
    pub cert_issuer: Option<String>,
    /// Certificate subject
    pub cert_subject: Option<String>,
    /// Certificate valid from
    pub cert_valid_from: Option<String>,
    /// Certificate valid to
    pub cert_valid_to: Option<String>,
    /// HSTS enabled
    pub hsts: bool,
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
        let request_type = match event_type {
            EventType::Navigation => RequestType::Document,
            EventType::Xhr => RequestType::XHR,
            EventType::Fetch => RequestType::Fetch,
            EventType::Script => RequestType::Script,
            EventType::Stylesheet => RequestType::Stylesheet,
            EventType::Image => RequestType::Image,
            EventType::Font => RequestType::Font,
            EventType::WebSocket => RequestType::WebSocket,
            EventType::FormSubmission => RequestType::Form,
            EventType::Iframe => RequestType::IFrame,
            EventType::Other => RequestType::Other,
        };

        Self {
            id: id.into(),
            event_type,
            request_type,
            timestamp: SystemTime::now(),
            request,
            response: None,
            duration: None,
            timing: None,
            error: None,
            js_initiated: false,
            initiator: None,
            initiator_stack: None,
            frame_id: None,
            security: None,
        }
    }

    /// Create with specific request type
    pub fn with_request_type(id: impl Into<String>, request_type: RequestType, request: RequestInfo) -> Self {
        let event_type = match request_type {
            RequestType::Document => EventType::Navigation,
            RequestType::XHR => EventType::Xhr,
            RequestType::Fetch => EventType::Fetch,
            RequestType::WebSocket | RequestType::WebSocketMessage => EventType::WebSocket,
            RequestType::Script => EventType::Script,
            RequestType::Stylesheet => EventType::Stylesheet,
            RequestType::Image => EventType::Image,
            RequestType::Font => EventType::Font,
            RequestType::Form => EventType::FormSubmission,
            RequestType::IFrame => EventType::Iframe,
            _ => EventType::Other,
        };

        Self {
            id: id.into(),
            event_type,
            request_type,
            timestamp: SystemTime::now(),
            request,
            response: None,
            duration: None,
            timing: None,
            error: None,
            js_initiated: false,
            initiator: None,
            initiator_stack: None,
            frame_id: None,
            security: None,
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

    /// Set initiator stack trace
    pub fn with_initiator_stack(mut self, stack: impl Into<String>) -> Self {
        self.initiator_stack = Some(stack.into());
        self
    }

    /// Set timing information
    pub fn with_timing(mut self, timing: RequestTiming) -> Self {
        self.timing = Some(timing);
        self
    }

    /// Set frame ID
    pub fn with_frame_id(mut self, frame_id: impl Into<String>) -> Self {
        self.frame_id = Some(frame_id.into());
        self
    }

    /// Set security info
    pub fn with_security(mut self, security: SecurityInfo) -> Self {
        self.security = Some(security);
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

impl RequestTiming {
    /// Create new timing starting now
    pub fn start() -> Self {
        Self {
            start_time: 0.0,
            dns_time: None,
            connect_time: None,
            tls_time: None,
            ttfb: None,
            download_time: None,
            total_time: 0.0,
            connection_reused: false,
        }
    }

    /// Create from duration measurements
    pub fn from_duration(total: Duration) -> Self {
        Self {
            start_time: 0.0,
            dns_time: None,
            connect_time: None,
            tls_time: None,
            ttfb: None,
            download_time: None,
            total_time: total.as_secs_f64() * 1000.0, // Convert to ms
            connection_reused: false,
        }
    }

    /// Check if request was slow (potential timing attack indicator)
    pub fn is_slow(&self, threshold_ms: f64) -> bool {
        self.total_time > threshold_ms
    }

    /// Get TTFB if available
    pub fn time_to_first_byte(&self) -> Option<f64> {
        self.ttfb
    }
}

impl SecurityInfo {
    /// Create empty security info
    pub fn empty() -> Self {
        Self {
            protocol: None,
            cipher: None,
            cert_issuer: None,
            cert_subject: None,
            cert_valid_from: None,
            cert_valid_to: None,
            hsts: false,
        }
    }

    /// Create for TLS connection
    pub fn tls(protocol: impl Into<String>, cipher: impl Into<String>) -> Self {
        Self {
            protocol: Some(protocol.into()),
            cipher: Some(cipher.into()),
            cert_issuer: None,
            cert_subject: None,
            cert_valid_from: None,
            cert_valid_to: None,
            hsts: false,
        }
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
