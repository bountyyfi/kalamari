// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Browser implementation

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use super::config::{BrowserConfig, PageConfig};
use super::page::Page;
use crate::error::{Error, Result};
use crate::http::{CookieJar, HttpClient, HttpClientConfig};
use crate::network::NetworkInterceptor;

/// Lightweight headless browser
pub struct Browser {
    /// Browser configuration
    config: BrowserConfig,
    /// HTTP client (shared across pages)
    client: HttpClient,
    /// Cookie jar (shared across pages)
    cookie_jar: CookieJar,
    /// Network interceptor
    network: NetworkInterceptor,
    /// Active pages
    pages: Arc<RwLock<Vec<Arc<Page>>>>,
    /// Page counter
    page_counter: AtomicU64,
    /// Browser ID
    id: String,
    /// Whether browser is closed
    closed: Arc<RwLock<bool>>,
}

impl Browser {
    /// Create a new browser instance
    pub async fn new(config: BrowserConfig) -> Result<Self> {
        let http_config = HttpClientConfig {
            user_agent: config.user_agent.clone(),
            timeout: config.timeout,
            accept_invalid_certs: config.ignore_https_errors,
            proxy: config.proxy.clone(),
            ..Default::default()
        };

        let client = HttpClient::with_config(http_config)?;
        let cookie_jar = client.cookie_jar().clone();
        let network = NetworkInterceptor::new(client.clone());

        Ok(Self {
            config,
            client,
            cookie_jar,
            network,
            pages: Arc::new(RwLock::new(Vec::new())),
            page_counter: AtomicU64::new(0),
            id: format!("browser_{}", uuid_simple()),
            closed: Arc::new(RwLock::new(false)),
        })
    }

    /// Create browser with default config
    pub async fn launch() -> Result<Self> {
        Self::new(BrowserConfig::default()).await
    }

    /// Create browser optimized for security scanning
    pub async fn for_security_scanning() -> Result<Self> {
        Self::new(BrowserConfig::for_security_scanning()).await
    }

    /// Get browser ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Create a new page
    pub async fn new_page(&self) -> Result<Arc<Page>> {
        self.new_page_with_config(PageConfig::default()).await
    }

    /// Create a new page with custom config
    pub async fn new_page_with_config(&self, config: PageConfig) -> Result<Arc<Page>> {
        if *self.closed.read() {
            return Err(Error::BrowserClosed);
        }

        let pages = self.pages.read();
        if pages.len() >= self.config.max_pages {
            return Err(Error::Config(format!(
                "Maximum pages ({}) reached",
                self.config.max_pages
            )));
        }
        drop(pages);

        let page_id = self.page_counter.fetch_add(1, Ordering::Relaxed);
        let page = Page::new(
            format!("page_{}", page_id),
            config,
            self.client.clone(),
            self.network.clone(),
            self.config.javascript_enabled,
        );

        let page = Arc::new(page);
        self.pages.write().push(page.clone());

        Ok(page)
    }

    /// Get all pages
    pub fn pages(&self) -> Vec<Arc<Page>> {
        self.pages.read().clone()
    }

    /// Close a specific page
    pub fn close_page(&self, page_id: &str) {
        self.pages.write().retain(|p| p.id() != page_id);
    }

    /// Close all pages
    pub fn close_all_pages(&self) {
        self.pages.write().clear();
    }

    /// Get the cookie jar
    pub fn cookies(&self) -> &CookieJar {
        &self.cookie_jar
    }

    /// Get network interceptor
    pub fn network(&self) -> &NetworkInterceptor {
        &self.network
    }

    /// Get HTTP client
    pub fn client(&self) -> &HttpClient {
        &self.client
    }

    /// Set authentication token
    pub fn set_auth_token(&self, token: impl Into<String>) {
        self.client.set_bearer_token(token);
    }

    /// Set basic auth
    pub fn set_basic_auth(&self, username: impl Into<String>, password: impl Into<String>) {
        self.client.set_basic_auth(username, password);
    }

    /// Set custom auth header
    pub fn set_custom_auth(&self, header: impl Into<String>, value: impl Into<String>) {
        self.client.set_custom_auth(header, value);
    }

    /// Clear authentication
    pub fn clear_auth(&self) {
        self.client.clear_auth();
    }

    /// Clear all cookies
    pub fn clear_cookies(&self) {
        self.cookie_jar.clear();
    }

    /// Get browser config
    pub fn config(&self) -> &BrowserConfig {
        &self.config
    }

    /// Check if browser is closed
    pub fn is_closed(&self) -> bool {
        *self.closed.read()
    }

    /// Close the browser
    pub fn close(&self) {
        *self.closed.write() = true;
        self.close_all_pages();
    }

    /// Get all captured network events
    pub fn network_events(&self) -> Vec<crate::network::NetworkEvent> {
        self.network.events()
    }

    /// Get all unique URLs visited
    pub fn visited_urls(&self) -> Vec<String> {
        self.network.unique_urls()
    }

    /// Export network events as JSON
    pub fn export_network_json(&self) -> serde_json::Result<String> {
        self.network.to_json()
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.close();
    }
}

/// Generate a simple unique ID
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{:x}{:x}",
        duration.as_secs(),
        duration.subsec_nanos()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_browser_creation() {
        let browser = Browser::launch().await.unwrap();
        assert!(!browser.is_closed());
    }

    #[tokio::test]
    async fn test_page_creation() {
        let browser = Browser::launch().await.unwrap();
        let page = browser.new_page().await.unwrap();
        assert!(browser.pages().len() == 1);
    }

    #[tokio::test]
    async fn test_browser_close() {
        let browser = Browser::launch().await.unwrap();
        let _ = browser.new_page().await.unwrap();
        browser.close();
        assert!(browser.is_closed());
        assert!(browser.pages().is_empty());
    }
}
