// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Cookie jar implementation for persistent cookie storage

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

/// A single HTTP cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name
    pub name: String,
    /// Cookie value
    pub value: String,
    /// Domain the cookie belongs to
    pub domain: String,
    /// Path the cookie is valid for
    pub path: String,
    /// Expiration time (None = session cookie)
    pub expires: Option<DateTime<Utc>>,
    /// Secure flag (HTTPS only)
    pub secure: bool,
    /// HttpOnly flag (not accessible via JavaScript)
    pub http_only: bool,
    /// SameSite attribute
    pub same_site: SameSite,
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SameSite {
    /// Cookie sent with all requests
    #[default]
    None,
    /// Cookie sent with same-site and top-level navigations
    Lax,
    /// Cookie only sent with same-site requests
    Strict,
}

impl Cookie {
    /// Create a new cookie
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: String::new(),
            path: "/".to_string(),
            expires: None,
            secure: false,
            http_only: false,
            same_site: SameSite::default(),
        }
    }

    /// Set the domain
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Set the path
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set secure flag
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set http_only flag
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Set same_site attribute
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Set expiration time
    pub fn expires(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Check if the cookie is expired
    pub fn is_expired(&self) -> bool {
        self.expires.map_or(false, |exp| exp < Utc::now())
    }

    /// Check if the cookie matches the given URL
    pub fn matches(&self, url: &Url) -> bool {
        // Check domain
        let host = url.host_str().unwrap_or("");
        if !self.domain_matches(host) {
            return false;
        }

        // Check path
        let path = url.path();
        if !path.starts_with(&self.path) {
            return false;
        }

        // Check secure flag
        if self.secure && url.scheme() != "https" {
            return false;
        }

        // Check expiration
        if self.is_expired() {
            return false;
        }

        true
    }

    /// Check if domain matches
    fn domain_matches(&self, host: &str) -> bool {
        if self.domain.is_empty() {
            return true;
        }

        let domain = self.domain.trim_start_matches('.');
        host == domain || host.ends_with(&format!(".{}", domain))
    }

    /// Parse a Set-Cookie header value
    pub fn parse(header: &str, url: &Url) -> Option<Self> {
        let mut parts = header.split(';');
        let first = parts.next()?.trim();

        let (name, value) = first.split_once('=')?;
        let mut cookie = Cookie::new(name.trim(), value.trim());

        // Default domain to request host
        cookie.domain = url.host_str().unwrap_or("").to_string();

        // Parse attributes
        for part in parts {
            let part = part.trim();
            if let Some((attr, val)) = part.split_once('=') {
                let attr = attr.trim().to_lowercase();
                let val = val.trim();
                match attr.as_str() {
                    "domain" => cookie.domain = val.trim_start_matches('.').to_string(),
                    "path" => cookie.path = val.to_string(),
                    "expires" => {
                        if let Ok(dt) = DateTime::parse_from_rfc2822(val) {
                            cookie.expires = Some(dt.with_timezone(&Utc));
                        }
                    }
                    "max-age" => {
                        if let Ok(secs) = val.parse::<i64>() {
                            cookie.expires =
                                Some(Utc::now() + chrono::Duration::seconds(secs));
                        }
                    }
                    "samesite" => {
                        cookie.same_site = match val.to_lowercase().as_str() {
                            "strict" => SameSite::Strict,
                            "lax" => SameSite::Lax,
                            _ => SameSite::None,
                        };
                    }
                    _ => {}
                }
            } else {
                match part.to_lowercase().as_str() {
                    "secure" => cookie.secure = true,
                    "httponly" => cookie.http_only = true,
                    _ => {}
                }
            }
        }

        Some(cookie)
    }

    /// Convert to cookie header format
    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// Thread-safe cookie storage
#[derive(Debug, Clone)]
pub struct CookieJar {
    /// Cookies stored by domain
    cookies: Arc<DashMap<String, Vec<Cookie>>>,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    /// Create a new empty cookie jar
    pub fn new() -> Self {
        Self {
            cookies: Arc::new(DashMap::new()),
        }
    }

    /// Add a cookie to the jar
    pub fn add(&self, cookie: Cookie) {
        let domain = cookie.domain.clone();
        self.cookies
            .entry(domain)
            .or_default()
            .retain(|c| c.name != cookie.name || c.path != cookie.path);
        self.cookies.entry(cookie.domain.clone()).or_default().push(cookie);
    }

    /// Add a cookie from a Set-Cookie header
    pub fn add_from_header(&self, header: &str, url: &Url) {
        if let Some(cookie) = Cookie::parse(header, url) {
            self.add(cookie);
        }
    }

    /// Get all cookies for a URL
    pub fn get_cookies(&self, url: &Url) -> Vec<Cookie> {
        let host = url.host_str().unwrap_or("");
        let mut result = Vec::new();

        // Collect matching cookies from all domains
        for entry in self.cookies.iter() {
            for cookie in entry.value().iter() {
                if cookie.matches(url) {
                    result.push(cookie.clone());
                }
            }
        }

        // Remove expired cookies
        self.remove_expired();

        result
    }

    /// Get Cookie header value for a URL
    pub fn get_cookie_header(&self, url: &Url) -> Option<String> {
        let cookies = self.get_cookies(url);
        if cookies.is_empty() {
            return None;
        }

        Some(
            cookies
                .iter()
                .map(|c| c.to_header_value())
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Get all non-HttpOnly cookies for JavaScript access
    pub fn get_js_accessible_cookies(&self, url: &Url) -> Vec<Cookie> {
        self.get_cookies(url)
            .into_iter()
            .filter(|c| !c.http_only)
            .collect()
    }

    /// Remove a specific cookie
    pub fn remove(&self, name: &str, domain: &str, path: &str) {
        if let Some(mut cookies) = self.cookies.get_mut(domain) {
            cookies.retain(|c| c.name != name || c.path != path);
        }
    }

    /// Clear all cookies
    pub fn clear(&self) {
        self.cookies.clear();
    }

    /// Clear cookies for a specific domain
    pub fn clear_domain(&self, domain: &str) {
        self.cookies.remove(domain);
    }

    /// Remove expired cookies
    fn remove_expired(&self) {
        for mut entry in self.cookies.iter_mut() {
            entry.value_mut().retain(|c| !c.is_expired());
        }
    }

    /// Get total cookie count
    pub fn len(&self) -> usize {
        self.cookies.iter().map(|e| e.value().len()).sum()
    }

    /// Check if jar is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export all cookies as JSON
    pub fn to_json(&self) -> serde_json::Result<String> {
        let all_cookies: Vec<Cookie> = self
            .cookies
            .iter()
            .flat_map(|e| e.value().clone())
            .collect();
        serde_json::to_string(&all_cookies)
    }

    /// Import cookies from JSON
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        let cookies: Vec<Cookie> = serde_json::from_str(json)?;
        let jar = CookieJar::new();
        for cookie in cookies {
            jar.add(cookie);
        }
        Ok(jar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_parsing() {
        let url = Url::parse("https://example.com/path").unwrap();
        let header = "session=abc123; Domain=example.com; Path=/; Secure; HttpOnly";
        let cookie = Cookie::parse(header, &url).unwrap();

        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.secure);
        assert!(cookie.http_only);
    }

    #[test]
    fn test_cookie_jar() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/path").unwrap();

        jar.add(Cookie::new("test", "value").domain("example.com"));
        assert_eq!(jar.len(), 1);

        let cookies = jar.get_cookies(&url);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "test");
    }
}
