// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Request/Response interceptor trait for CDP-like interception
//!
//! Provides middleware pattern similar to Chrome DevTools Protocol Fetch domain.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::http::{Request, Response};

/// Request interceptor trait - similar to CDP Fetch protocol
///
/// Allows injecting auth headers, modifying requests, capturing responses.
///
/// # Example
///
/// ```rust,no_run
/// use kalamari::network::{RequestInterceptor, InterceptAction};
/// use kalamari::http::{Request, Response};
/// use async_trait::async_trait;
///
/// struct AuthInjector {
///     token: String,
/// }
///
/// #[async_trait]
/// impl RequestInterceptor for AuthInjector {
///     async fn before_request(&self, req: &mut Request) -> InterceptAction {
///         req.headers.insert(
///             "authorization".parse().unwrap(),
///             format!("Bearer {}", self.token).parse().unwrap()
///         );
///         InterceptAction::Continue
///     }
/// }
/// ```
#[async_trait]
pub trait RequestInterceptor: Send + Sync {
    /// Called before a request is sent
    ///
    /// Can modify the request or abort it entirely.
    async fn before_request(&self, request: &mut Request) -> InterceptAction {
        InterceptAction::Continue
    }

    /// Called after a response is received
    ///
    /// Can inspect/modify response or trigger additional actions.
    async fn after_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        Ok(())
    }

    /// Called when request fails
    async fn on_error(&self, request: &Request, error: &crate::error::Error) {
        // Default: do nothing
    }

    /// Called for WebSocket upgrade requests
    async fn on_websocket_upgrade(&self, request: &Request) -> InterceptAction {
        InterceptAction::Continue
    }

    /// Filter - return true if this interceptor should handle the request
    fn should_intercept(&self, request: &Request) -> bool {
        true
    }

    /// Priority - higher priority interceptors run first
    fn priority(&self) -> i32 {
        0
    }
}

/// Action to take after interception
#[derive(Debug, Clone)]
pub enum InterceptAction {
    /// Continue with the (possibly modified) request
    Continue,
    /// Abort the request with an error
    Abort(String),
    /// Return a mock response instead of making the actual request
    MockResponse(Response),
    /// Pause/delay the request (for rate limiting)
    Delay(std::time::Duration),
}

/// Header entry for request modification (CDP-compatible)
#[derive(Debug, Clone)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

impl HeaderEntry {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Auth header injector - common interceptor
pub struct AuthHeaderInjector {
    /// Headers to inject into every request
    headers: Vec<HeaderEntry>,
    /// Domains to inject into (empty = all)
    domains: Vec<String>,
}

impl AuthHeaderInjector {
    /// Create a new auth header injector
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            domains: Vec::new(),
        }
    }

    /// Add a bearer token
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.headers.push(HeaderEntry::new(
            "authorization",
            format!("Bearer {}", token.into()),
        ));
        self
    }

    /// Add basic auth
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", username, password),
        );
        self.headers
            .push(HeaderEntry::new("authorization", format!("Basic {}", encoded)));
        self
    }

    /// Add custom header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderEntry::new(name, value));
        self
    }

    /// Restrict to specific domains
    pub fn for_domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }
}

impl Default for AuthHeaderInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RequestInterceptor for AuthHeaderInjector {
    fn should_intercept(&self, request: &Request) -> bool {
        if self.domains.is_empty() {
            return true;
        }

        request
            .url
            .host_str()
            .map(|host| self.domains.iter().any(|d| host.contains(d)))
            .unwrap_or(false)
    }

    async fn before_request(&self, request: &mut Request) -> InterceptAction {
        for header in &self.headers {
            if let (Ok(name), Ok(value)) = (
                header.name.parse::<reqwest::header::HeaderName>(),
                header.value.parse::<reqwest::header::HeaderValue>(),
            ) {
                request.headers.insert(name, value);
            }
        }
        InterceptAction::Continue
    }

    fn priority(&self) -> i32 {
        100 // High priority - run auth injection early
    }
}

/// Request logger interceptor
pub struct RequestLogger {
    /// Log request bodies
    pub log_bodies: bool,
    /// Log response bodies
    pub log_responses: bool,
    /// Filter by URL pattern
    pub url_filter: Option<String>,
}

impl Default for RequestLogger {
    fn default() -> Self {
        Self {
            log_bodies: false,
            log_responses: false,
            url_filter: None,
        }
    }
}

#[async_trait]
impl RequestInterceptor for RequestLogger {
    fn should_intercept(&self, request: &Request) -> bool {
        if let Some(ref filter) = self.url_filter {
            request.url.as_str().contains(filter)
        } else {
            true
        }
    }

    async fn before_request(&self, request: &mut Request) -> InterceptAction {
        tracing::info!(
            method = %request.method,
            url = %request.url,
            "Request"
        );

        if self.log_bodies {
            if let Some(ref body) = request.body {
                tracing::debug!(body = ?String::from_utf8_lossy(body), "Request body");
            }
        }

        InterceptAction::Continue
    }

    async fn after_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        tracing::info!(
            url = %request.url,
            status = %response.status,
            time_ms = response.response_time_ms,
            "Response"
        );

        if self.log_responses {
            tracing::debug!(body = %response.text_lossy(), "Response body");
        }

        Ok(())
    }

    fn priority(&self) -> i32 {
        -100 // Low priority - run logging last
    }
}

/// Cookie capture interceptor - captures Set-Cookie from responses
pub struct CookieCaptureInterceptor {
    /// Captured cookies (domain -> cookies)
    pub cookies: Arc<parking_lot::RwLock<Vec<CapturedCookie>>>,
}

/// Captured cookie information
#[derive(Debug, Clone)]
pub struct CapturedCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub url: String,
    pub http_only: bool,
    pub secure: bool,
}

impl Default for CookieCaptureInterceptor {
    fn default() -> Self {
        Self {
            cookies: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl RequestInterceptor for CookieCaptureInterceptor {
    async fn after_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        for cookie_str in response.set_cookies() {
            if let Some(cookie) = parse_set_cookie(cookie_str, &request.url) {
                self.cookies.write().push(cookie);
            }
        }
        Ok(())
    }
}

/// Parse Set-Cookie header into CapturedCookie
fn parse_set_cookie(header: &str, url: &url::Url) -> Option<CapturedCookie> {
    let mut parts = header.split(';');
    let first = parts.next()?.trim();
    let (name, value) = first.split_once('=')?;

    let mut cookie = CapturedCookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        domain: url.host_str().unwrap_or("").to_string(),
        path: "/".to_string(),
        url: url.to_string(),
        http_only: false,
        secure: false,
    };

    for part in parts {
        let part = part.trim().to_lowercase();
        if part == "httponly" {
            cookie.http_only = true;
        } else if part == "secure" {
            cookie.secure = true;
        } else if let Some(domain) = part.strip_prefix("domain=") {
            cookie.domain = domain.trim_start_matches('.').to_string();
        } else if let Some(path) = part.strip_prefix("path=") {
            cookie.path = path.to_string();
        }
    }

    Some(cookie)
}

/// Interceptor chain - manages multiple interceptors
pub struct InterceptorChain {
    interceptors: Vec<Arc<dyn RequestInterceptor>>,
}

impl Default for InterceptorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl InterceptorChain {
    /// Create a new empty chain
    pub fn new() -> Self {
        Self {
            interceptors: Vec::new(),
        }
    }

    /// Add an interceptor
    pub fn add<I: RequestInterceptor + 'static>(&mut self, interceptor: I) {
        self.interceptors.push(Arc::new(interceptor));
        // Sort by priority (highest first)
        self.interceptors.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    /// Process request through all interceptors
    pub async fn process_request(&self, request: &mut Request) -> InterceptAction {
        for interceptor in &self.interceptors {
            if !interceptor.should_intercept(request) {
                continue;
            }

            match interceptor.before_request(request).await {
                InterceptAction::Continue => continue,
                action => return action,
            }
        }
        InterceptAction::Continue
    }

    /// Process response through all interceptors
    pub async fn process_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        for interceptor in &self.interceptors {
            if !interceptor.should_intercept(request) {
                continue;
            }
            interceptor.after_response(request, response).await?;
        }
        Ok(())
    }

    /// Notify interceptors of an error
    pub async fn notify_error(&self, request: &Request, error: &crate::error::Error) {
        for interceptor in &self.interceptors {
            if interceptor.should_intercept(request) {
                interceptor.on_error(request, error).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_injector() {
        let injector = AuthHeaderInjector::new()
            .bearer_token("test_token")
            .header("x-custom", "value");

        assert_eq!(injector.headers.len(), 2);
    }

    #[test]
    fn test_interceptor_chain() {
        let mut chain = InterceptorChain::new();
        chain.add(AuthHeaderInjector::new().bearer_token("token"));
        chain.add(RequestLogger::default());

        assert_eq!(chain.interceptors.len(), 2);
    }
}
