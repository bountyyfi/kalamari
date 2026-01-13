// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! HTTP request types and builder

use crate::error::Result;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// HTTP request representation
#[derive(Debug, Clone)]
pub struct Request {
    /// Request method
    pub method: Method,
    /// Request URL
    pub url: Url,
    /// Request headers
    pub headers: HeaderMap,
    /// Request body
    pub body: Option<Bytes>,
    /// Request timeout
    pub timeout: Option<Duration>,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirects to follow
    pub max_redirects: u32,
    /// Credentials mode
    pub credentials: CredentialsMode,
}

/// Credentials mode for requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialsMode {
    /// Send credentials only to same-origin requests
    #[default]
    SameOrigin,
    /// Always send credentials
    Include,
    /// Never send credentials
    Omit,
}

impl Request {
    /// Create a new GET request
    pub fn get(url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            method: Method::GET,
            url: Url::parse(url.as_ref())?,
            headers: HeaderMap::new(),
            body: None,
            timeout: Some(Duration::from_secs(30)),
            follow_redirects: true,
            max_redirects: 10,
            credentials: CredentialsMode::default(),
        })
    }

    /// Create a new POST request
    pub fn post(url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            method: Method::POST,
            url: Url::parse(url.as_ref())?,
            headers: HeaderMap::new(),
            body: None,
            timeout: Some(Duration::from_secs(30)),
            follow_redirects: true,
            max_redirects: 10,
            credentials: CredentialsMode::default(),
        })
    }

    /// Create a new request with arbitrary method
    pub fn new(method: Method, url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            method,
            url: Url::parse(url.as_ref())?,
            headers: HeaderMap::new(),
            body: None,
            timeout: Some(Duration::from_secs(30)),
            follow_redirects: true,
            max_redirects: 10,
            credentials: CredentialsMode::default(),
        })
    }

    /// Set a header
    pub fn header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_ref()),
            HeaderValue::try_from(value.as_ref()),
        ) {
            self.headers.insert(name, value);
        }
        self
    }

    /// Set multiple headers
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        for (name, value) in headers {
            if let (Ok(name), Ok(value)) =
                (HeaderName::try_from(name.as_str()), HeaderValue::try_from(value.as_str()))
            {
                self.headers.insert(name, value);
            }
        }
        self
    }

    /// Set the request body
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set JSON body
    pub fn json<T: Serialize>(mut self, data: &T) -> Result<Self> {
        let json = serde_json::to_vec(data)?;
        self.body = Some(Bytes::from(json));
        self = self.header("content-type", "application/json");
        Ok(self)
    }

    /// Set form body
    pub fn form(mut self, data: &HashMap<String, String>) -> Self {
        let body = data
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding_encode(k), urlencoding_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.body = Some(Bytes::from(body));
        self = self.header("content-type", "application/x-www-form-urlencoded");
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable timeout
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Set follow redirects
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Set max redirects
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = max;
        self
    }

    /// Set credentials mode
    pub fn credentials(mut self, mode: CredentialsMode) -> Self {
        self.credentials = mode;
        self
    }

    /// Get the URL as string
    pub fn url_str(&self) -> &str {
        self.url.as_str()
    }

    /// Get the host
    pub fn host(&self) -> Option<&str> {
        self.url.host_str()
    }

    /// Get the origin
    pub fn origin(&self) -> String {
        format!(
            "{}://{}{}",
            self.url.scheme(),
            self.url.host_str().unwrap_or(""),
            self.url
                .port()
                .map(|p| format!(":{}", p))
                .unwrap_or_default()
        )
    }
}

/// Request builder for more complex requests
#[derive(Debug)]
pub struct RequestBuilder {
    request: Request,
}

impl RequestBuilder {
    /// Create a new request builder
    pub fn new(method: Method, url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            request: Request::new(method, url)?,
        })
    }

    /// Set a header
    pub fn header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    /// Set the body
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.request = self.request.body(body);
        self
    }

    /// Set JSON body
    pub fn json<T: Serialize>(mut self, data: &T) -> Result<Self> {
        self.request = self.request.json(data)?;
        Ok(self)
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.request = self.request.timeout(timeout);
        self
    }

    /// Build the request
    pub fn build(self) -> Request {
        self.request
    }
}

/// URL encode a string
fn urlencoding_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let req = Request::get("https://example.com/path").unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.url.host_str(), Some("example.com"));
    }

    #[test]
    fn test_request_headers() {
        let req = Request::get("https://example.com")
            .unwrap()
            .header("x-custom", "value");
        assert_eq!(
            req.headers.get("x-custom").map(|v| v.to_str().unwrap()),
            Some("value")
        );
    }

    #[test]
    fn test_request_origin() {
        let req = Request::get("https://example.com:8080/path").unwrap();
        assert_eq!(req.origin(), "https://example.com:8080");
    }
}
