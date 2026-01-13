// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Browser and Page configuration

use std::time::Duration;

use crate::http::DEFAULT_USER_AGENT;

/// Browser configuration
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// User agent string
    pub user_agent: String,
    /// Default timeout for requests
    pub timeout: Duration,
    /// Accept invalid TLS certificates
    pub ignore_https_errors: bool,
    /// Enable JavaScript execution
    pub javascript_enabled: bool,
    /// Proxy URL
    pub proxy: Option<String>,
    /// Maximum concurrent pages
    pub max_pages: usize,
    /// Cookie persistence
    pub persist_cookies: bool,
    /// Default headers
    pub default_headers: Vec<(String, String)>,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            timeout: Duration::from_secs(30),
            ignore_https_errors: false,
            javascript_enabled: true,
            proxy: None,
            max_pages: 10,
            persist_cookies: true,
            default_headers: vec![],
        }
    }
}

impl BrowserConfig {
    /// Create a new browser config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set user agent
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Ignore HTTPS errors
    pub fn ignore_https_errors(mut self, ignore: bool) -> Self {
        self.ignore_https_errors = ignore;
        self
    }

    /// Enable/disable JavaScript
    pub fn javascript_enabled(mut self, enabled: bool) -> Self {
        self.javascript_enabled = enabled;
        self
    }

    /// Set proxy
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Add default header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.push((name.into(), value.into()));
        self
    }

    /// Create config optimized for security scanning
    pub fn for_security_scanning() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            ignore_https_errors: true,
            javascript_enabled: true,
            persist_cookies: true,
            ..Default::default()
        }
    }

    /// Create config optimized for fast crawling
    pub fn for_crawling() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            javascript_enabled: false, // Faster without JS
            persist_cookies: true,
            ..Default::default()
        }
    }
}

/// Page configuration
#[derive(Debug, Clone)]
pub struct PageConfig {
    /// Page timeout
    pub timeout: Duration,
    /// Execute JavaScript
    pub execute_js: bool,
    /// Enable XSS detection
    pub xss_detection: bool,
    /// Capture network events
    pub capture_network: bool,
    /// Wait for network idle
    pub wait_for_network_idle: bool,
    /// Network idle timeout
    pub network_idle_timeout: Duration,
    /// Viewport width
    pub viewport_width: u32,
    /// Viewport height
    pub viewport_height: u32,
    /// Block resource types
    pub blocked_resources: Vec<ResourceType>,
    /// Extra HTTP headers for this page
    pub extra_headers: Vec<(String, String)>,
}

impl Default for PageConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            execute_js: true,
            xss_detection: true,
            capture_network: true,
            wait_for_network_idle: false,
            network_idle_timeout: Duration::from_millis(500),
            viewport_width: 1920,
            viewport_height: 1080,
            blocked_resources: vec![],
            extra_headers: vec![],
        }
    }
}

impl PageConfig {
    /// Create a new page config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable/disable JS execution
    pub fn execute_js(mut self, execute: bool) -> Self {
        self.execute_js = execute;
        self
    }

    /// Enable/disable XSS detection
    pub fn xss_detection(mut self, enabled: bool) -> Self {
        self.xss_detection = enabled;
        self
    }

    /// Block resource types
    pub fn block_resources(mut self, types: Vec<ResourceType>) -> Self {
        self.blocked_resources = types;
        self
    }

    /// Add extra header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Config for XSS scanning
    pub fn for_xss_scanning() -> Self {
        Self {
            execute_js: true,
            xss_detection: true,
            capture_network: true,
            blocked_resources: vec![
                ResourceType::Image,
                ResourceType::Font,
                ResourceType::Stylesheet,
            ],
            ..Default::default()
        }
    }

    /// Config for form testing
    pub fn for_form_testing() -> Self {
        Self {
            execute_js: true,
            capture_network: true,
            ..Default::default()
        }
    }
}

/// Resource types that can be blocked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// Images
    Image,
    /// Stylesheets
    Stylesheet,
    /// Fonts
    Font,
    /// Media (video/audio)
    Media,
    /// WebSocket connections
    WebSocket,
    /// Other resources
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_config() {
        let config = BrowserConfig::new()
            .user_agent("Custom Agent")
            .timeout(Duration::from_secs(60));

        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_page_config() {
        let config = PageConfig::for_xss_scanning();
        assert!(config.xss_detection);
        assert!(config.execute_js);
    }
}
