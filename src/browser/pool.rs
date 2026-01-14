// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Browser pool for parallel page execution
//!
//! Provides efficient parallel scanning by managing a pool of pages.
//! Integrates with Lonkero's `par_iter()` pattern.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tokio::sync::Semaphore;

use crate::browser::{Browser, BrowserConfig, Page, PageConfig};
use crate::error::{Error, Result};

/// Browser pool for parallel operations
pub struct BrowserPool {
    /// Underlying browsers
    browsers: Vec<Arc<Browser>>,
    /// Maximum concurrent pages
    max_concurrent: usize,
    /// Semaphore for limiting concurrency
    semaphore: Arc<Semaphore>,
    /// Round-robin counter
    next_browser: AtomicUsize,
    /// Pool statistics
    stats: Arc<RwLock<PoolStats>>,
}

/// Pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total pages created
    pub pages_created: u64,
    /// Total pages released
    pub pages_released: u64,
    /// Current active pages
    pub active_pages: u64,
    /// Peak concurrent pages
    pub peak_concurrent: u64,
    /// Total wait time for acquiring pages (ms)
    pub total_wait_ms: u64,
}

/// A page acquired from the pool
pub struct PooledPage {
    /// The underlying page
    page: Page,
    /// Pool reference for release
    pool: Arc<BrowserPool>,
    /// Semaphore permit
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PooledPage {
    /// Get reference to the page
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Get mutable reference to the page
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }
}

impl std::ops::Deref for PooledPage {
    type Target = Page;

    fn deref(&self) -> &Self::Target {
        &self.page
    }
}

impl std::ops::DerefMut for PooledPage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.page
    }
}

impl Drop for PooledPage {
    fn drop(&mut self) {
        let mut stats = self.pool.stats.write();
        stats.pages_released += 1;
        stats.active_pages = stats.active_pages.saturating_sub(1);
    }
}

impl BrowserPool {
    /// Create a new browser pool with specified size
    pub async fn new(pool_size: usize) -> Result<Arc<Self>> {
        Self::with_config(pool_size, BrowserConfig::default()).await
    }

    /// Create pool with custom browser config
    pub async fn with_config(pool_size: usize, config: BrowserConfig) -> Result<Arc<Self>> {
        let mut browsers = Vec::with_capacity(pool_size);

        for _ in 0..pool_size {
            let browser = Browser::new(config.clone()).await?;
            browsers.push(Arc::new(browser));
        }

        let max_concurrent = pool_size * 4; // 4 pages per browser

        Ok(Arc::new(Self {
            browsers,
            max_concurrent,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            next_browser: AtomicUsize::new(0),
            stats: Arc::new(RwLock::new(PoolStats::default())),
        }))
    }

    /// Create pool for security scanning
    pub async fn for_security_scanning(pool_size: usize) -> Result<Arc<Self>> {
        let config = BrowserConfig::for_security_scanning();
        Self::with_config(pool_size, config).await
    }

    /// Acquire a page from the pool
    pub async fn acquire(self: &Arc<Self>) -> Result<PooledPage> {
        let start = std::time::Instant::now();

        // Wait for available slot
        let permit = self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::other("Pool semaphore closed"))?;

        // Update wait stats
        {
            let mut stats = self.stats.write();
            stats.total_wait_ms += start.elapsed().as_millis() as u64;
        }

        // Get browser round-robin
        let browser_idx = self.next_browser.fetch_add(1, Ordering::Relaxed) % self.browsers.len();
        let browser = &self.browsers[browser_idx];

        // Create new page
        let page = browser.new_page().await?;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.pages_created += 1;
            stats.active_pages += 1;
            if stats.active_pages > stats.peak_concurrent {
                stats.peak_concurrent = stats.active_pages;
            }
        }

        Ok(PooledPage {
            page,
            pool: Arc::clone(self),
            _permit: permit,
        })
    }

    /// Acquire a page with custom config
    pub async fn acquire_with_config(self: &Arc<Self>, config: PageConfig) -> Result<PooledPage> {
        let start = std::time::Instant::now();

        let permit = self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::other("Pool semaphore closed"))?;

        {
            let mut stats = self.stats.write();
            stats.total_wait_ms += start.elapsed().as_millis() as u64;
        }

        let browser_idx = self.next_browser.fetch_add(1, Ordering::Relaxed) % self.browsers.len();
        let browser = &self.browsers[browser_idx];

        let page = browser.new_page_with_config(config).await?;

        {
            let mut stats = self.stats.write();
            stats.pages_created += 1;
            stats.active_pages += 1;
            if stats.active_pages > stats.peak_concurrent {
                stats.peak_concurrent = stats.active_pages;
            }
        }

        Ok(PooledPage {
            page,
            pool: Arc::clone(self),
            _permit: permit,
        })
    }

    /// Execute function on multiple URLs in parallel
    pub async fn map<F, T, Fut>(
        self: &Arc<Self>,
        urls: &[String],
        f: F,
    ) -> Vec<Result<T>>
    where
        F: Fn(PooledPage, String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send + 'static,
    {
        use futures::future::join_all;

        let tasks: Vec<_> = urls
            .iter()
            .map(|url| {
                let pool = Arc::clone(self);
                let url = url.clone();
                let f = f.clone();

                async move {
                    let page = pool.acquire().await?;
                    f(page, url).await
                }
            })
            .collect();

        join_all(tasks).await
    }

    /// Execute with concurrency limit
    pub async fn map_limited<F, T, Fut>(
        self: &Arc<Self>,
        urls: &[String],
        concurrency: usize,
        f: F,
    ) -> Vec<Result<T>>
    where
        F: Fn(PooledPage, String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send + 'static,
    {
        use futures::stream::{self, StreamExt};

        let pool = Arc::clone(self);

        stream::iter(urls.iter().cloned())
            .map(|url| {
                let pool = Arc::clone(&pool);
                let f = f.clone();

                async move {
                    let page = pool.acquire().await?;
                    f(page, url).await
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write();
        *stats = PoolStats::default();
    }

    /// Get number of browsers in pool
    pub fn browser_count(&self) -> usize {
        self.browsers.len()
    }

    /// Get maximum concurrent pages
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Get current active page count
    pub fn active_pages(&self) -> u64 {
        self.stats.read().active_pages
    }

    /// Get available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require async runtime and actual Browser implementation
    // They serve as documentation of expected behavior

    #[test]
    fn test_pool_stats_default() {
        let stats = PoolStats::default();
        assert_eq!(stats.pages_created, 0);
        assert_eq!(stats.active_pages, 0);
    }
}
