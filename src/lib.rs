// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! # Kalamari - Lightweight Headless Browser
//!
//! A pure Rust headless browser designed for XSS scanning and web crawling.
//! No Chrome/Chromium dependency - uses boa_engine for JavaScript execution.
//!
//! ## Features
//!
//! - **Lightweight**: ~10MB vs Chrome's 200MB+
//! - **Fast startup**: No browser process to spawn
//! - **XSS Detection**: Built-in alert/confirm/prompt interception
//! - **DOM API**: JavaScript can interact with parsed HTML
//! - **Cookie management**: Full cookie jar support with auth tokens
//! - **Network interception**: Capture all requests/responses
//! - **Form extraction**: Automatically detect and extract forms
//!
//! ## Example
//!
//! ```rust,no_run
//! use kalamari::{Browser, BrowserConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let browser = Browser::new(BrowserConfig::default()).await?;
//!     let page = browser.new_page().await?;
//!
//!     page.navigate("https://example.com").await?;
//!
//!     // Check for XSS triggers
//!     let xss_results = page.get_xss_triggers();
//!     for trigger in xss_results {
//!         println!("XSS detected: {:?}", trigger);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod browser;
pub mod dom;
pub mod error;
pub mod http;
pub mod js;
pub mod network;
pub mod xss;

// Re-exports for convenience
pub use browser::{Browser, BrowserConfig, Page, PageConfig};
pub use dom::{Document, Element, Node};
pub use error::{Error, Result};
pub use http::{CookieJar, HttpClient, Request, Response};
pub use js::{JsRuntime, JsValue};
pub use network::{NetworkEvent, NetworkInterceptor};
pub use xss::{XssDetector, XssTrigger, XssTriggerType};
