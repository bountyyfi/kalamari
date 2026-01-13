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
//! - **Full DOM API**: createElement, MutationObserver, localStorage
//! - **Cookie management**: Full cookie jar support with auth tokens
//! - **Network interception**: CDP-like request/response capture
//! - **Form extraction**: Automatically detect forms with CSRF tokens
//! - **Iframe handling**: Recursive frame processing with XSS hooks
//! - **SPA route detection**: Vue/React/Angular route extraction
//! - **WebSocket discovery**: Find WebSocket endpoints in JS
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
//!
//! ## Lonkero Integration
//!
//! Kalamari is designed as a drop-in replacement for Chrome headless in Lonkero:
//!
//! ```rust,no_run
//! use kalamari::{Browser, RequestInterceptor, InterceptAction, AuthSession};
//!
//! // Request interception (replaces CDP Fetch protocol)
//! // AuthSession extraction (cookies, localStorage, headers)
//! // SPA route detection from JS bundles
//! // WebSocket endpoint discovery
//! ```

pub mod browser;
pub mod dom;
pub mod error;
pub mod http;
pub mod js;
pub mod network;
pub mod xss;

// Re-exports for convenience

// Browser and Page
pub use browser::{Browser, BrowserConfig, Page, PageConfig, ResourceType};

// Crawler
pub use browser::{Crawler, CrawlConfig, CrawlResult};

// Forms
pub use browser::{Form, FormField, FormSubmitter};

// Iframes
pub use browser::{Frame, FrameTree, FrameHandler, XSS_HOOK_SCRIPT};

// PDF
pub use browser::{PrintToPdfOptions, ReportFormat};

// Auth session extraction
pub use browser::{AuthSession, AuthSessionExtractor};

// Script analysis (SPA routes, WebSocket endpoints)
pub use browser::{
    ScriptSource, ScriptAnalyzer, ScriptAnalysisResult,
    SpaRoute, SpaFramework,
    WebSocketEndpoint, WebSocketDiscoveryMethod,
};

// DOM
pub use dom::{Document, Element, Node};

// Errors
pub use error::{Error, Result, NetworkLogEntry, ErrorContext};

// HTTP
pub use http::{CookieJar, HttpClient, Request, Response, Cookie};

// JavaScript
pub use js::{JsRuntime, JsRuntimeConfig, JsValue, ConsoleMessage, ConsoleLevel};
pub use js::{TimerQueue, JsIdleConfig, JsIdleResult};
pub use js::{DomApiInstaller, DomBindings};

// Network
pub use network::{NetworkEvent, NetworkInterceptor, EventType};
pub use network::{RequestType, RequestTiming, SecurityInfo, RequestInfo, ResponseInfo};
pub use network::{
    RequestInterceptor, InterceptAction, InterceptorChain,
    AuthHeaderInjector, RequestLogger, CookieCaptureInterceptor,
};

// XSS
pub use xss::{XssDetector, XssTrigger, XssTriggerType};
pub use xss::{PayloadGenerator, XssPayload, PayloadContext};

/// Kalamari version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
