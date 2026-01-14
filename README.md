# Kalamari

[![CI](https://github.com/bountyyfi/kalamari/actions/workflows/ci.yml/badge.svg)](https://github.com/bountyyfi/kalamari/actions/workflows/ci.yml)
[![Release](https://github.com/bountyyfi/kalamari/actions/workflows/release.yml/badge.svg)](https://github.com/bountyyfi/kalamari/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/kalamari.svg)](https://crates.io/crates/kalamari)
[![docs.rs](https://docs.rs/kalamari/badge.svg)](https://docs.rs/kalamari)
[![license](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)

**Lightweight Headless Browser for Security Testing**

[Features](#features) | [Installation](#installation) | [Quick Start](#quick-start) | [API Reference](#api-reference) | [Lonkero Integration](#lonkero-integration)

---

## What is Kalamari?

Kalamari is a pure Rust headless browser designed specifically for XSS scanning, web crawling, and security testing. Unlike traditional headless browsers that require Chrome/Chromium binaries (~200MB+), Kalamari is entirely self-contained with minimal dependencies.

Built as a drop-in replacement for Chrome headless in security scanners like [Lonkero](https://github.com/bountyyfi/lonkero).

## Features

### Core Browser

- **Lightweight** - ~10MB binary vs Chrome's 200MB+ footprint
- **Fast Startup** - No browser process to spawn, instant initialization
- **Full DOM API** - createElement, MutationObserver, localStorage, sessionStorage
- **Cookie Management** - Complete cookie jar with domain scoping and auth tokens
- **Network Interception** - CDP-like request/response capture with middleware chain

### Security Testing

- **XSS Detection** - Built-in alert/confirm/prompt/eval interception
- **Stored XSS Flow** - Complete stored XSS detection with form submission
- **CSP Analysis** - Parse Content-Security-Policy, identify bypasses
- **DOM Clobbering** - Detect clobbering vectors and form hijacking
- **SRI Checking** - Identify missing/weak subresource integrity

### Framework Support

- **SPA Route Detection** - Extract routes from Vue, React, Angular bundles
- **WebSocket Discovery** - Find WebSocket endpoints in JavaScript
- **Framework Detectors** - Identify v-html, dangerouslySetInnerHTML, ng-bind-html sinks

### Performance

- **Browser Pool** - Parallel scanning with page pooling
- **Metrics Collection** - Request latencies, page counts, XSS triggers
- **Real Timer Queue** - Production-grade setTimeout/setInterval with unique IDs, clearTimeout/clearInterval, and flush_timers() for async JS control
- **Console Capture** - Real console.log/error/warn/info/debug capture for debugging

## Lonkero Integration

Kalamari addresses all key integration requirements for Lonkero:

| Feature | Chrome-based | Kalamari |
|---------|-------------|----------|
| Binary size | ~200MB | ~10MB |
| Memory/page | ~100-300MB | ~10-20MB |
| Startup time | 1-3s | Instant |
| XSS detection | External | Built-in |
| Request interception | CDP Fetch | `RequestInterceptor` trait |
| Iframe support | Native | Recursive processing |
| MutationObserver | Native | JS stub |
| PDF generation | Native | Feature-gated |
| Auth session | Manual | `AuthSession` extractor |
| SPA routes | Manual | `ScriptAnalyzer` |
| WebSocket discovery | Manual | `ScriptAnalyzer` |
| Timer control | Native | `TimerQueue` |
| CSP analysis | Manual | `CspAnalyzer` |
| Parallel scanning | Thread pool | `BrowserPool` |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kalamari = "0.1"

# With optional features
kalamari = { version = "0.1", features = ["pdf", "websocket"] }
```

Or install the CLI:

```bash
cargo install kalamari
```

## Quick Start

### Basic Usage

```rust
use kalamari::{Browser, BrowserConfig, PageConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com").await?;
    println!("Title: {:?}", page.title());

    for link in page.links() {
        println!("Link: {}", link);
    }

    Ok(())
}
```

### XSS Scanning

```rust
use kalamari::{Browser, PageConfig, XssTriggerType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::for_security_scanning().await?;
    let page = browser.new_page_with_config(PageConfig::for_xss_scanning()).await?;

    page.navigate("https://target.com/search?q=<script>alert(1)</script>").await?;

    let result = page.analyze_xss();
    for trigger in result.triggers {
        if trigger.is_confirmed() {
            println!("CONFIRMED XSS: {:?} - {}", trigger.trigger_type, trigger.payload);
        }
    }

    Ok(())
}
```

### Stored XSS Detection

```rust
use kalamari::{StoredXssTest, StoredXssTester};

let test = StoredXssTest::new("https://example.com/post", "<script>alert(1)</script>")
    .field("comment")
    .reflect_at("https://example.com/posts")
    .reflect_at("https://example.com/profile");

let tester = StoredXssTester::new();
// Execute test via page methods
```

### CSP Analysis

```rust
use kalamari::{CspAnalyzer, CspBypass};

let analyzer = CspAnalyzer::new();
let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'";
let analysis = analyzer.parse(csp);

println!("Security Score: {}/100", analysis.security_score);
println!("Blocks inline: {}", analysis.blocks_inline);

for bypass in &analysis.bypasses {
    println!("Bypass: {:?} - {}", bypass, bypass.description());
}
```

### Parallel Scanning with Browser Pool

```rust
use kalamari::BrowserPool;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = BrowserPool::new(8).await?;  // 8 browsers

    let urls = vec![
        "https://example.com/page1".to_string(),
        "https://example.com/page2".to_string(),
        "https://example.com/page3".to_string(),
    ];

    let results = pool.map(&urls, |page, url| async move {
        page.navigate(&url).await?;
        Ok(page.analyze_xss())
    }).await;

    for result in results {
        if let Ok(xss) = result {
            if xss.is_vulnerable() {
                println!("XSS found!");
            }
        }
    }

    Ok(())
}
```

### Request Interception

```rust
use kalamari::{Browser, RequestInterceptor, InterceptAction, AuthHeaderInjector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;

    // Use built-in auth injector
    let auth = AuthHeaderInjector::new()
        .bearer_token("your-jwt-token")
        .header("x-api-key", "secret");

    // Or set directly on browser
    browser.set_auth_token("your-jwt-token");

    Ok(())
}
```

### Auth Session Extraction

```rust
use kalamari::{Browser, AuthSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com/login").await?;
    // ... perform login ...

    let session = page.extract_auth_session();

    println!("Session ID: {:?}", session.session_id);
    println!("Bearer Token: {:?}", session.bearer_token);
    println!("CSRF Token: {:?}", session.csrf_token);
    println!("Authenticated: {}", session.is_authenticated);

    Ok(())
}
```

### SPA Route Detection

```rust
use kalamari::{ScriptAnalyzer, ScriptSource};

let analyzer = ScriptAnalyzer::new();
let scripts = page.get_script_sources();

for script in &scripts {
    // Find routes
    let routes = analyzer.find_routes(script);
    for route in routes {
        println!("Route: {} (auth: {})", route.path, route.requires_auth);
    }

    // Find WebSocket endpoints
    let ws_endpoints = analyzer.find_websocket_endpoints(script);
    for endpoint in ws_endpoints {
        println!("WebSocket: {}", endpoint.url);
    }
}
```

### Framework Detection

```rust
use kalamari::FrameworkDetector;

let detector = FrameworkDetector::new();
let html = page.content()?;
let scripts = page.get_script_sources();
let script_contents: Vec<String> = scripts.iter().map(|s| s.content.clone()).collect();

let frameworks = detector.detect_all(&html, &script_contents);
for fw in frameworks {
    println!("Framework: {:?} {:?}", fw.framework, fw.version);
    for sink in fw.sinks {
        println!("  Sink: {} (risk: {})", sink.name, sink.risk);
    }
}
```

## CLI Usage

```bash
# Fetch a URL and display info
kalamari fetch https://example.com

# Check for XSS vulnerabilities
kalamari xss "https://example.com/search?q=<script>alert(1)</script>"

# Crawl a website
kalamari crawl https://example.com

# Extract forms
kalamari forms https://example.com/login
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    KALAMARI BROWSER                          │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  HTTP Layer  │  │  DOM Engine  │  │   JS Runtime     │   │
│  │   (reqwest)  │──│  (html5ever) │──│   (boa_engine)   │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         │                  │                   │             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Interceptor  │  │   Iframe     │  │  XSS Detection   │   │
│  │    Chain     │  │   Handler    │  │  (alert hooks)   │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         │                  │                   │             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   Cookie     │  │    Form      │  │    Security      │   │
│  │     Jar      │  │  Extractor   │  │   (CSP, SRI)     │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## API Reference

### Browser Module

| Type | Description |
|------|-------------|
| `Browser` | Main browser instance |
| `Page` | Individual page/tab |
| `BrowserPool` | Pool for parallel scanning |
| `BrowserMetrics` | Performance metrics |

### Security Module

| Type | Description |
|------|-------------|
| `CspAnalyzer` | CSP parsing and bypass detection |
| `SriChecker` | Subresource integrity validation |
| `DomClobberDetector` | DOM clobbering detection |

### XSS Module

| Type | Description |
|------|-------------|
| `XssDetector` | XSS trigger detection |
| `StoredXssTest` | Stored XSS test configuration |
| `PayloadGenerator` | XSS payload generation |

### Network Module

| Type | Description |
|------|-------------|
| `RequestInterceptor` | Request/response middleware |
| `NetworkEvent` | Captured network events |
| `AuthHeaderInjector` | Auth header injection |

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `default` | Core functionality | None |
| `websocket` | WebSocket support | tokio-tungstenite |
| `pdf` | Simple PDF generation | printpdf |
| `chrome-pdf` | Full Chrome PDF (fallback) | headless_chrome |
| `full` | All features | All above |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `boa_engine` | JavaScript execution (pure Rust) |
| `html5ever` | HTML parsing (spec-compliant) |
| `reqwest` | HTTP client (rustls TLS) |
| `tokio` | Async runtime |

## Limitations

Kalamari is optimized for security testing, not full browser emulation:

- **No visual rendering** - CSS layout/painting not implemented
- **No WebGL/Canvas** - Graphics APIs not supported
- **Timer execution** - setTimeout/setInterval use real TimerQueue with unique IDs; use `flush_timers()` or `execute_ready_timers()` to execute
- **No plugins** - Flash, PDF viewer, etc. not supported

For features requiring full browser rendering, use the `chrome-pdf` feature.

## License

Copyright (c) 2026 Bountyy Oy. All rights reserved.

This software is licensed under the Bountyy Oy Source-Available License. You may view, study, and use the software for personal, non-commercial purposes. Commercial use requires a separate license agreement.

See [LICENSE](LICENSE) for full terms. For licensing inquiries: info@bountyy.fi

## Links

- [Lonkero Security Scanner](https://github.com/bountyyfi/lonkero)
- [Bountyy](https://bountyy.fi)
