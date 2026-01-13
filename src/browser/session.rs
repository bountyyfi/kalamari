// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Authentication session extraction for Lonkero integration
//!
//! Extracts session data after login flows:
//! - Cookies (session tokens)
//! - localStorage/sessionStorage (JWT, auth tokens)
//! - Authorization headers from intercepted requests

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::http::Cookie;

/// Extracted authentication session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthSession {
    /// Session cookies
    pub cookies: Vec<Cookie>,
    /// localStorage items
    pub local_storage: HashMap<String, String>,
    /// sessionStorage items
    pub session_storage: HashMap<String, String>,
    /// Authorization headers captured from requests
    pub auth_headers: HashMap<String, String>,
    /// Bearer token (extracted from cookies or storage)
    pub bearer_token: Option<String>,
    /// CSRF token (extracted from cookies or meta tags)
    pub csrf_token: Option<String>,
    /// Session ID (common session cookie)
    pub session_id: Option<String>,
    /// User ID if detected
    pub user_id: Option<String>,
    /// Whether session appears authenticated
    pub is_authenticated: bool,
}

impl AuthSession {
    /// Create a new empty session
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cookie
    pub fn add_cookie(&mut self, cookie: Cookie) {
        // Check for session-like cookies
        let name_lower = cookie.name.to_lowercase();
        if name_lower.contains("session")
            || name_lower.contains("sid")
            || name_lower == "phpsessid"
            || name_lower == "jsessionid"
            || name_lower == "asp.net_sessionid"
        {
            self.session_id = Some(cookie.value.clone());
            self.is_authenticated = true;
        }

        // Check for CSRF tokens
        if name_lower.contains("csrf") || name_lower.contains("xsrf") {
            self.csrf_token = Some(cookie.value.clone());
        }

        // Check for auth tokens
        if name_lower.contains("token")
            || name_lower.contains("auth")
            || name_lower.contains("jwt")
        {
            self.bearer_token = Some(cookie.value.clone());
            self.is_authenticated = true;
        }

        self.cookies.push(cookie);
    }

    /// Add localStorage item
    pub fn add_local_storage(&mut self, key: String, value: String) {
        let key_lower = key.to_lowercase();

        // Check for auth tokens
        if key_lower.contains("token")
            || key_lower.contains("auth")
            || key_lower.contains("jwt")
            || key_lower.contains("access")
        {
            self.bearer_token = Some(value.clone());
            self.is_authenticated = true;
        }

        // Check for user ID
        if key_lower.contains("user") && (key_lower.contains("id") || key_lower.contains("_id")) {
            self.user_id = Some(value.clone());
        }

        self.local_storage.insert(key, value);
    }

    /// Add sessionStorage item
    pub fn add_session_storage(&mut self, key: String, value: String) {
        let key_lower = key.to_lowercase();

        // Check for auth tokens
        if key_lower.contains("token") || key_lower.contains("auth") {
            self.bearer_token = Some(value.clone());
            self.is_authenticated = true;
        }

        self.session_storage.insert(key, value);
    }

    /// Add authorization header
    pub fn add_auth_header(&mut self, name: String, value: String) {
        let name_lower = name.to_lowercase();

        if name_lower == "authorization" {
            // Extract bearer token
            if let Some(token) = value.strip_prefix("Bearer ") {
                self.bearer_token = Some(token.to_string());
                self.is_authenticated = true;
            } else if let Some(token) = value.strip_prefix("bearer ") {
                self.bearer_token = Some(token.to_string());
                self.is_authenticated = true;
            }
        }

        // Check for CSRF headers
        if name_lower.contains("csrf") || name_lower.contains("xsrf") {
            self.csrf_token = Some(value.clone());
        }

        self.auth_headers.insert(name, value);
    }

    /// Get cookie by name
    pub fn get_cookie(&self, name: &str) -> Option<&Cookie> {
        self.cookies.iter().find(|c| c.name == name)
    }

    /// Get cookie value by name
    pub fn get_cookie_value(&self, name: &str) -> Option<&str> {
        self.get_cookie(name).map(|c| c.value.as_str())
    }

    /// Get all cookies as a cookie header string
    pub fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Get Authorization header value
    pub fn authorization_header(&self) -> Option<String> {
        self.bearer_token
            .as_ref()
            .map(|t| format!("Bearer {}", t))
    }

    /// Check if session has valid auth
    pub fn has_auth(&self) -> bool {
        self.is_authenticated
            || self.bearer_token.is_some()
            || self.session_id.is_some()
            || !self.auth_headers.is_empty()
    }

    /// Merge another session into this one
    pub fn merge(&mut self, other: AuthSession) {
        for cookie in other.cookies {
            if !self.cookies.iter().any(|c| c.name == cookie.name) {
                self.add_cookie(cookie);
            }
        }

        for (k, v) in other.local_storage {
            self.add_local_storage(k, v);
        }

        for (k, v) in other.session_storage {
            self.add_session_storage(k, v);
        }

        for (k, v) in other.auth_headers {
            self.add_auth_header(k, v);
        }

        if other.bearer_token.is_some() && self.bearer_token.is_none() {
            self.bearer_token = other.bearer_token;
        }

        if other.csrf_token.is_some() && self.csrf_token.is_none() {
            self.csrf_token = other.csrf_token;
        }

        if other.session_id.is_some() && self.session_id.is_none() {
            self.session_id = other.session_id;
        }

        if other.user_id.is_some() && self.user_id.is_none() {
            self.user_id = other.user_id;
        }

        self.is_authenticated = self.is_authenticated || other.is_authenticated;
    }

    /// Export to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Create from JSON
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

/// Builder for extracting auth session from page context
pub struct AuthSessionExtractor {
    /// Common auth cookie names to look for
    cookie_patterns: Vec<String>,
    /// Common storage key patterns
    storage_patterns: Vec<String>,
    /// Header patterns to capture
    header_patterns: Vec<String>,
}

impl Default for AuthSessionExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthSessionExtractor {
    /// Create new extractor with default patterns
    pub fn new() -> Self {
        Self {
            cookie_patterns: vec![
                "session".to_string(),
                "token".to_string(),
                "auth".to_string(),
                "jwt".to_string(),
                "sid".to_string(),
                "csrf".to_string(),
                "xsrf".to_string(),
            ],
            storage_patterns: vec![
                "token".to_string(),
                "auth".to_string(),
                "jwt".to_string(),
                "user".to_string(),
                "session".to_string(),
            ],
            header_patterns: vec![
                "authorization".to_string(),
                "x-auth".to_string(),
                "x-token".to_string(),
                "x-csrf".to_string(),
                "x-xsrf".to_string(),
            ],
        }
    }

    /// Add cookie pattern
    pub fn cookie_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.cookie_patterns.push(pattern.into());
        self
    }

    /// Add storage pattern
    pub fn storage_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.storage_patterns.push(pattern.into());
        self
    }

    /// Add header pattern
    pub fn header_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.header_patterns.push(pattern.into());
        self
    }

    /// Check if cookie name matches patterns
    pub fn matches_cookie(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.cookie_patterns
            .iter()
            .any(|p| name_lower.contains(p))
    }

    /// Check if storage key matches patterns
    pub fn matches_storage(&self, key: &str) -> bool {
        let key_lower = key.to_lowercase();
        self.storage_patterns.iter().any(|p| key_lower.contains(p))
    }

    /// Check if header matches patterns
    pub fn matches_header(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.header_patterns.iter().any(|p| name_lower.contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::SameSite;

    #[test]
    fn test_auth_session_cookies() {
        let mut session = AuthSession::new();
        session.add_cookie(Cookie::new("PHPSESSID", "abc123"));

        assert!(session.is_authenticated);
        assert_eq!(session.session_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_auth_session_jwt() {
        let mut session = AuthSession::new();
        session.add_local_storage(
            "access_token".to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string(),
        );

        assert!(session.is_authenticated);
        assert!(session.bearer_token.is_some());
    }

    #[test]
    fn test_auth_header_extraction() {
        let mut session = AuthSession::new();
        session.add_auth_header(
            "Authorization".to_string(),
            "Bearer my-secret-token".to_string(),
        );

        assert!(session.is_authenticated);
        assert_eq!(session.bearer_token, Some("my-secret-token".to_string()));
    }

    #[test]
    fn test_cookie_header() {
        let mut session = AuthSession::new();
        session.cookies.push(Cookie::new("foo", "bar"));
        session.cookies.push(Cookie::new("baz", "qux"));

        assert_eq!(session.cookie_header(), "foo=bar; baz=qux");
    }
}
