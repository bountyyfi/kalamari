// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! HTTP client implementation

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::RwLock;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Method, StatusCode};
use url::Url;

use super::cookie::CookieJar;
use super::request::{CredentialsMode, Request};
use super::response::Response;
use super::DEFAULT_USER_AGENT;
use crate::error::{Error, Result};

/// HTTP client configuration
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// User agent string
    pub user_agent: String,
    /// Default timeout
    pub timeout: Duration,
    /// Maximum redirects to follow
    pub max_redirects: usize,
    /// Accept invalid certificates (dangerous!)
    pub accept_invalid_certs: bool,
    /// Default headers
    pub default_headers: HeaderMap,
    /// Enable cookie handling
    pub handle_cookies: bool,
    /// Proxy URL
    pub proxy: Option<String>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "accept",
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            ),
        );
        default_headers.insert(
            "accept-language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
        default_headers.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );

        Self {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            timeout: Duration::from_secs(30),
            max_redirects: 10,
            accept_invalid_certs: false,
            default_headers,
            handle_cookies: true,
            proxy: None,
        }
    }
}

/// HTTP client with cookie management
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    config: HttpClientConfig,
    cookie_jar: CookieJar,
    /// Auth tokens (Bearer, Basic, etc.)
    auth_tokens: Arc<RwLock<AuthTokens>>,
}

/// Authentication tokens storage
#[derive(Debug, Default)]
pub struct AuthTokens {
    /// Bearer token
    pub bearer: Option<String>,
    /// Basic auth (username, password)
    pub basic: Option<(String, String)>,
    /// Custom auth header
    pub custom: Option<(String, String)>,
}

impl HttpClient {
    /// Create a new HTTP client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(HttpClientConfig::default())
    }

    /// Create a new HTTP client with custom configuration
    pub fn with_config(config: HttpClientConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .user_agent(&config.user_agent)
            .timeout(config.timeout)
            .redirect(Policy::limited(config.max_redirects))
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .default_headers(config.default_headers.clone())
            .cookie_store(false); // We handle cookies ourselves

        if let Some(ref proxy_url) = config.proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy_url)
                    .map_err(|e| Error::Config(format!("Invalid proxy URL: {}", e)))?,
            );
        }

        let client = builder.build()?;

        Ok(Self {
            client,
            config,
            cookie_jar: CookieJar::new(),
            auth_tokens: Arc::new(RwLock::new(AuthTokens::default())),
        })
    }

    /// Get the cookie jar
    pub fn cookie_jar(&self) -> &CookieJar {
        &self.cookie_jar
    }

    /// Set bearer token
    pub fn set_bearer_token(&self, token: impl Into<String>) {
        self.auth_tokens.write().bearer = Some(token.into());
    }

    /// Set basic auth
    pub fn set_basic_auth(&self, username: impl Into<String>, password: impl Into<String>) {
        self.auth_tokens.write().basic = Some((username.into(), password.into()));
    }

    /// Set custom auth header
    pub fn set_custom_auth(&self, header: impl Into<String>, value: impl Into<String>) {
        self.auth_tokens.write().custom = Some((header.into(), value.into()));
    }

    /// Clear all auth tokens
    pub fn clear_auth(&self) {
        let mut tokens = self.auth_tokens.write();
        tokens.bearer = None;
        tokens.basic = None;
        tokens.custom = None;
    }

    /// Execute a GET request
    pub async fn get(&self, url: impl AsRef<str>) -> Result<Response> {
        self.execute(Request::get(url)?).await
    }

    /// Execute a POST request
    pub async fn post(&self, url: impl AsRef<str>, body: impl Into<Bytes>) -> Result<Response> {
        self.execute(Request::post(url)?.body(body)).await
    }

    /// Execute a request
    pub async fn execute(&self, request: Request) -> Result<Response> {
        let start = Instant::now();

        // Build the reqwest request
        let mut builder = self
            .client
            .request(request.method.clone(), request.url.clone());

        // Add headers
        for (name, value) in request.headers.iter() {
            builder = builder.header(name, value);
        }

        // Add cookies if handling is enabled
        if self.config.handle_cookies {
            if let Some(cookie_header) = self.cookie_jar.get_cookie_header(&request.url) {
                builder = builder.header("cookie", cookie_header);
            }
        }

        // Add auth tokens based on credentials mode
        if request.credentials != CredentialsMode::Omit {
            let should_send = match request.credentials {
                CredentialsMode::Include => true,
                CredentialsMode::SameOrigin => {
                    // For same-origin, we'd need to compare with the original page URL
                    // For now, always send in SameOrigin mode
                    true
                }
                CredentialsMode::Omit => false,
            };

            if should_send {
                let tokens = self.auth_tokens.read();
                if let Some(ref bearer) = tokens.bearer {
                    builder = builder.header("authorization", format!("Bearer {}", bearer));
                } else if let Some((ref user, ref pass)) = tokens.basic {
                    let encoded = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{}:{}", user, pass),
                    );
                    builder = builder.header("authorization", format!("Basic {}", encoded));
                }
                if let Some((ref header, ref value)) = tokens.custom {
                    builder = builder.header(header.as_str(), value.as_str());
                }
            }
        }

        // Set body if present
        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        // Set timeout
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }

        // Execute the request
        let response = builder.send().await?;
        let response_time = start.elapsed().as_millis() as u64;

        // Check if redirected
        let redirected = response.url() != &request.url;
        let final_url = response.url().clone();
        let status = response.status();
        let headers = response.headers().clone();

        // Process Set-Cookie headers
        if self.config.handle_cookies {
            for cookie in headers.get_all("set-cookie") {
                if let Ok(cookie_str) = cookie.to_str() {
                    self.cookie_jar.add_from_header(cookie_str, &final_url);
                }
            }
        }

        // Get body
        let body = response.bytes().await?;

        Ok(Response::new(
            status,
            headers,
            body,
            final_url,
            redirected,
            response_time,
        ))
    }

    /// Execute multiple requests concurrently
    pub async fn execute_all(&self, requests: Vec<Request>) -> Vec<Result<Response>> {
        let futures: Vec<_> = requests.into_iter().map(|r| self.execute(r)).collect();
        futures::future::join_all(futures).await
    }

    /// Create a request builder
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> Result<RequestBuilder> {
        Ok(RequestBuilder {
            client: self.clone(),
            request: Request::new(method, url)?,
        })
    }

    /// Get client configuration
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default HTTP client")
    }
}

/// Builder for executing requests with the client
pub struct RequestBuilder {
    client: HttpClient,
    request: Request,
}

impl RequestBuilder {
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
    pub fn json<T: serde::Serialize>(mut self, data: &T) -> Result<Self> {
        self.request = self.request.json(data)?;
        Ok(self)
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.request = self.request.timeout(timeout);
        self
    }

    /// Execute the request
    pub async fn send(self) -> Result<Response> {
        self.client.execute(self.request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = HttpClient::new().unwrap();
        assert_eq!(client.config().user_agent, DEFAULT_USER_AGENT);
    }

    #[test]
    fn test_auth_tokens() {
        let client = HttpClient::new().unwrap();
        client.set_bearer_token("test_token");
        assert!(client.auth_tokens.read().bearer.is_some());
        client.clear_auth();
        assert!(client.auth_tokens.read().bearer.is_none());
    }
}
