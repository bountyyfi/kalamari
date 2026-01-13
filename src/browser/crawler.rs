// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Web crawler for discovering pages and endpoints

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use url::Url;

use super::Browser;
use crate::error::{Error, Result};
use crate::http::Response;

/// Crawler configuration
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// Maximum depth to crawl
    pub max_depth: u32,
    /// Maximum pages to visit
    pub max_pages: usize,
    /// Delay between requests
    pub delay: Duration,
    /// Stay within same domain
    pub same_domain_only: bool,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Crawl forms
    pub crawl_forms: bool,
    /// Crawl JavaScript links
    pub crawl_js_links: bool,
    /// URL patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// URL patterns to include (empty = all)
    pub include_patterns: Vec<String>,
    /// File extensions to skip
    pub skip_extensions: Vec<String>,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum concurrent requests
    pub concurrency: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_pages: 1000,
            delay: Duration::from_millis(100),
            same_domain_only: true,
            follow_redirects: true,
            crawl_forms: true,
            crawl_js_links: false,
            exclude_patterns: vec![
                "logout".to_string(),
                "signout".to_string(),
                "delete".to_string(),
            ],
            include_patterns: vec![],
            skip_extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "svg".to_string(),
                "ico".to_string(),
                "css".to_string(),
                "js".to_string(),
                "woff".to_string(),
                "woff2".to_string(),
                "ttf".to_string(),
                "eot".to_string(),
                "pdf".to_string(),
                "zip".to_string(),
                "tar".to_string(),
                "gz".to_string(),
            ],
            timeout: Duration::from_secs(30),
            concurrency: 5,
        }
    }
}

impl CrawlConfig {
    /// Create a new crawler config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max depth
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set max pages
    pub fn max_pages(mut self, pages: usize) -> Self {
        self.max_pages = pages;
        self
    }

    /// Set delay between requests
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Set same domain only
    pub fn same_domain_only(mut self, same_domain: bool) -> Self {
        self.same_domain_only = same_domain;
        self
    }

    /// Add exclude pattern
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Add include pattern
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.include_patterns.push(pattern.into());
        self
    }
}

/// Crawl result for a single page
#[derive(Debug, Clone)]
pub struct CrawlResult {
    /// URL visited
    pub url: String,
    /// HTTP status code
    pub status: u16,
    /// Page title
    pub title: Option<String>,
    /// Depth at which page was found
    pub depth: u32,
    /// Links found on page
    pub links: Vec<String>,
    /// Forms found on page
    pub forms: Vec<FormInfo>,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Content type
    pub content_type: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Form information for crawl results
#[derive(Debug, Clone)]
pub struct FormInfo {
    pub action: Option<String>,
    pub method: String,
    pub fields: Vec<String>,
}

/// Web crawler
pub struct Crawler {
    /// Crawler configuration
    config: CrawlConfig,
    /// Browser instance
    browser: Arc<Browser>,
    /// Visited URLs
    visited: Arc<RwLock<HashSet<String>>>,
    /// URL queue
    queue: Arc<RwLock<VecDeque<(String, u32)>>>,
    /// Results
    results: Arc<RwLock<Vec<CrawlResult>>>,
    /// Base domain (for same-domain filtering)
    base_domain: Arc<RwLock<Option<String>>>,
}

impl Crawler {
    /// Create a new crawler
    pub fn new(browser: Arc<Browser>, config: CrawlConfig) -> Self {
        Self {
            config,
            browser,
            visited: Arc::new(RwLock::new(HashSet::new())),
            queue: Arc::new(RwLock::new(VecDeque::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            base_domain: Arc::new(RwLock::new(None)),
        }
    }

    /// Create crawler with default config
    pub fn with_defaults(browser: Arc<Browser>) -> Self {
        Self::new(browser, CrawlConfig::default())
    }

    /// Start crawling from a URL
    pub async fn crawl(&self, start_url: &str) -> Result<Vec<CrawlResult>> {
        let start_parsed = Url::parse(start_url)?;

        // Set base domain
        if self.config.same_domain_only {
            *self.base_domain.write() = start_parsed.host_str().map(String::from);
        }

        // Add start URL to queue
        self.queue.write().push_back((start_url.to_string(), 0));

        // Process queue
        while let Some((url, depth)) = self.next_url() {
            if self.visited.read().len() >= self.config.max_pages {
                break;
            }

            if depth > self.config.max_depth {
                continue;
            }

            if !self.should_visit(&url) {
                continue;
            }

            // Mark as visited
            self.visited.write().insert(self.normalize_url(&url));

            // Visit the page
            let result = self.visit_page(&url, depth).await;
            self.results.write().push(result.clone());

            // Add discovered links to queue
            if depth < self.config.max_depth {
                for link in &result.links {
                    if !self.visited.read().contains(&self.normalize_url(link)) {
                        self.queue.write().push_back((link.clone(), depth + 1));
                    }
                }
            }

            // Delay between requests
            if !self.config.delay.is_zero() {
                tokio::time::sleep(self.config.delay).await;
            }
        }

        Ok(self.results.read().clone())
    }

    /// Visit a single page
    async fn visit_page(&self, url: &str, depth: u32) -> CrawlResult {
        let page = match self.browser.new_page().await {
            Ok(p) => p,
            Err(e) => {
                return CrawlResult {
                    url: url.to_string(),
                    status: 0,
                    title: None,
                    depth,
                    links: vec![],
                    forms: vec![],
                    response_time_ms: 0,
                    content_type: None,
                    error: Some(e.to_string()),
                };
            }
        };

        let start = std::time::Instant::now();

        match page.navigate(url).await {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis() as u64;

                // Extract links
                let links = self.extract_links(&page, url);

                // Extract forms
                let forms = if self.config.crawl_forms {
                    page.forms()
                        .into_iter()
                        .map(|f| FormInfo {
                            action: f.action,
                            method: f.method,
                            fields: f
                                .fields
                                .iter()
                                .filter_map(|field| field.name.clone())
                                .collect(),
                        })
                        .collect()
                } else {
                    vec![]
                };

                CrawlResult {
                    url: url.to_string(),
                    status: response.status.as_u16(),
                    title: page.title(),
                    depth,
                    links,
                    forms,
                    response_time_ms: elapsed,
                    content_type: response.content_type().map(String::from),
                    error: None,
                }
            }
            Err(e) => CrawlResult {
                url: url.to_string(),
                status: 0,
                title: None,
                depth,
                links: vec![],
                forms: vec![],
                response_time_ms: start.elapsed().as_millis() as u64,
                content_type: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Extract links from page
    fn extract_links(&self, page: &super::Page, base_url: &str) -> Vec<String> {
        let mut links = Vec::new();
        let base = Url::parse(base_url).ok();

        for link in page.links() {
            if let Some(resolved) = self.resolve_url(&link, base.as_ref()) {
                links.push(resolved);
            }
        }

        // Deduplicate
        links.sort();
        links.dedup();

        links
    }

    /// Resolve a relative URL
    fn resolve_url(&self, url: &str, base: Option<&Url>) -> Option<String> {
        if url.starts_with("http://") || url.starts_with("https://") {
            return Some(url.to_string());
        }

        // Skip non-HTTP URLs
        if url.starts_with("javascript:")
            || url.starts_with("mailto:")
            || url.starts_with("tel:")
            || url.starts_with("data:")
            || url.starts_with("#")
        {
            return None;
        }

        base.and_then(|b| b.join(url).ok()).map(|u| u.to_string())
    }

    /// Check if URL should be visited
    fn should_visit(&self, url: &str) -> bool {
        let normalized = self.normalize_url(url);

        // Already visited
        if self.visited.read().contains(&normalized) {
            return false;
        }

        // Parse URL
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // Same domain check
        if self.config.same_domain_only {
            if let Some(ref base) = *self.base_domain.read() {
                if parsed.host_str() != Some(base) {
                    return false;
                }
            }
        }

        // Check file extension
        let path = parsed.path().to_lowercase();
        for ext in &self.config.skip_extensions {
            if path.ends_with(&format!(".{}", ext)) {
                return false;
            }
        }

        // Check exclude patterns
        let url_lower = url.to_lowercase();
        for pattern in &self.config.exclude_patterns {
            if url_lower.contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        // Check include patterns (if any)
        if !self.config.include_patterns.is_empty() {
            let matches_include = self
                .config
                .include_patterns
                .iter()
                .any(|p| url_lower.contains(&p.to_lowercase()));
            if !matches_include {
                return false;
            }
        }

        true
    }

    /// Normalize URL for deduplication
    fn normalize_url(&self, url: &str) -> String {
        if let Ok(mut parsed) = Url::parse(url) {
            parsed.set_fragment(None);
            // Remove trailing slash for consistency
            let path = parsed.path().to_string();
            if path.len() > 1 && path.ends_with('/') {
                parsed.set_path(&path[..path.len() - 1]);
            }
            parsed.to_string()
        } else {
            url.to_string()
        }
    }

    /// Get next URL from queue
    fn next_url(&self) -> Option<(String, u32)> {
        self.queue.write().pop_front()
    }

    /// Get current results
    pub fn results(&self) -> Vec<CrawlResult> {
        self.results.read().clone()
    }

    /// Get visited URLs
    pub fn visited_urls(&self) -> HashSet<String> {
        self.visited.read().clone()
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.queue.read().len()
    }

    /// Clear state
    pub fn clear(&self) {
        self.visited.write().clear();
        self.queue.write().clear();
        self.results.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawl_config() {
        let config = CrawlConfig::new()
            .max_depth(3)
            .max_pages(100)
            .same_domain_only(true);

        assert_eq!(config.max_depth, 3);
        assert_eq!(config.max_pages, 100);
        assert!(config.same_domain_only);
    }
}
