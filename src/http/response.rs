// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! HTTP response types

use bytes::Bytes;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use url::Url;

use crate::error::{Error, Result};

/// HTTP response representation
#[derive(Debug, Clone)]
pub struct Response {
    /// Response status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body
    pub body: Bytes,
    /// Final URL (after redirects)
    pub url: Url,
    /// Whether this was a redirect
    pub redirected: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

impl Response {
    /// Create a new response
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        url: Url,
        redirected: bool,
        response_time_ms: u64,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            url,
            redirected,
            response_time_ms,
        }
    }

    /// Check if status is success (2xx)
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Check if status is redirect (3xx)
    pub fn is_redirect(&self) -> bool {
        self.status.is_redirection()
    }

    /// Check if status is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }

    /// Check if status is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// Get status code as u16
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    /// Get body as text
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.to_vec()).map_err(|e| Error::Other(e.to_string()))
    }

    /// Get body as text, lossy conversion
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Parse body as JSON
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::from)
    }

    /// Get a header value
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get all values for a header
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect()
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Check if content type is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/html") || ct.contains("application/xhtml"))
            .unwrap_or(false)
    }

    /// Check if content type is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }

    /// Check if content type is JavaScript
    pub fn is_javascript(&self) -> bool {
        self.content_type()
            .map(|ct| {
                ct.contains("application/javascript")
                    || ct.contains("text/javascript")
                    || ct.contains("application/x-javascript")
            })
            .unwrap_or(false)
    }

    /// Get content length
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.parse().ok())
    }

    /// Get Set-Cookie headers
    pub fn set_cookies(&self) -> Vec<&str> {
        self.header_all("set-cookie")
    }

    /// Get the final URL as string
    pub fn url_str(&self) -> &str {
        self.url.as_str()
    }

    /// Get body length
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Get raw body bytes
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_status() {
        let resp = Response::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::new(),
            Url::parse("https://example.com").unwrap(),
            false,
            100,
        );
        assert!(resp.is_success());
        assert_eq!(resp.status_code(), 200);
    }

    #[test]
    fn test_response_text() {
        let resp = Response::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("Hello, World!"),
            Url::parse("https://example.com").unwrap(),
            false,
            100,
        );
        assert_eq!(resp.text().unwrap(), "Hello, World!");
    }
}
