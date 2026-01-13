# Kalamari 🦑

**Lightweight Headless Browser for Security Testing**

Kalamari is a pure Rust headless browser designed specifically for XSS scanning, web crawling, and security testing. Unlike traditional headless browsers that require Chrome/Chromium binaries (~200MB+), Kalamari is entirely self-contained with minimal dependencies.

## Features

- **🪶 Lightweight**: ~10MB vs Chrome's 200MB+ footprint
- **🚀 Fast Startup**: No browser process to spawn
- **🔒 XSS Detection**: Built-in alert/confirm/prompt interception
- **🌐 Full DOM API**: createElement, MutationObserver, localStorage, etc.
- **🍪 Cookie Management**: Full cookie jar support with auth tokens
- **📡 Network Interception**: CDP-like request/response capture with middleware
- **📝 Form Extraction**: Automatically detect forms with CSRF tokens
- **🖼️ Iframe Handling**: Recursive frame processing with XSS hook injection
- **🕷️ Crawler**: Built-in web crawler with configurable depth
- **📄 PDF Generation**: Optional PDF reports (feature-gated)
- **🔐 Auth Session**: Extract cookies, localStorage, JWT tokens after login
- **🗺️ SPA Routes**: Detect Vue/React/Angular routes from JS bundles
- **🔌 WebSocket Discovery**: Find WebSocket endpoints in JavaScript
- **⏱️ Timer Control**: flush_timers() and wait_for_js_idle() for async JS

## Lonkero Integration

Kalamari is designed as a drop-in replacement for Chrome headless in [Lonkero](https://github.com/bountyyfi/lonkero) security scanner. It addresses all key integration requirements:

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

### XSS Scanning (Lonkero-compatible)

```rust
use kalamari::{Browser, PageConfig, XssTriggerType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::for_security_scanning().await?;
    let page = browser.new_page_with_config(PageConfig::for_xss_scanning()).await?;

    // Navigate with XSS payload
    page.navigate("https://target.com/search?q=<script>alert(1)</script>").await?;

    // Check for XSS triggers
    let result = page.analyze_xss();
    for trigger in result.triggers {
        if trigger.is_confirmed() {
            println!("CONFIRMED XSS: {:?} - {}", trigger.trigger_type, trigger.payload);
        }
    }

    // Test custom payload
    let triggers = page.test_xss_payload("alert('XSS')");
    if !triggers.is_empty() {
        println!("Payload executed!");
    }

    Ok(())
}
```

### Request Interception (CDP Fetch Replacement)

```rust
use kalamari::{Browser, RequestInterceptor, InterceptAction, AuthHeaderInjector};
use kalamari::http::Request;
use async_trait::async_trait;

// Custom interceptor - like CDP Fetch protocol
struct TokenInjector {
    token: String,
}

#[async_trait]
impl RequestInterceptor for TokenInjector {
    async fn before_request(&self, req: &mut Request) -> InterceptAction {
        // Inject auth header into ALL requests (like CDP Fetch.continueRequest)
        req.headers.insert(
            "authorization".parse().unwrap(),
            format!("Bearer {}", self.token).parse().unwrap()
        );
        InterceptAction::Continue
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;

    // Use built-in auth injector
    let _auth = AuthHeaderInjector::new()
        .bearer_token("your-jwt-token")
        .header("x-api-key", "secret");

    // Or set directly on browser
    browser.set_auth_token("your-jwt-token");

    Ok(())
}
```

### Iframe Handling with XSS Hook Injection

```rust
use kalamari::{Browser, FrameHandler, FrameTree};
use kalamari::browser::XSS_HOOK_SCRIPT;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com").await?;

    // Process all iframes recursively (up to depth 3)
    let handler = FrameHandler::new(browser.client().clone())
        .max_depth(3)
        .execute_js(true);

    // XSS hooks are injected into each frame context
    // including: alert, confirm, prompt, eval, innerHTML

    // Get XSS triggers from all frames
    let all_triggers = handler.get_xss_triggers();
    for trigger in all_triggers {
        println!("Frame XSS: {:?}", trigger);
    }

    Ok(())
}
```

### Form Extraction with CSRF Detection

```rust
use kalamari::Browser;
use kalamari::browser::FormSubmitter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com/login").await?;

    for mut form in page.forms() {
        println!("Form: {} {}", form.method, form.action.as_deref().unwrap_or("/"));

        // Detect CSRF token
        if let Some(token) = form.csrf_token() {
            println!("  CSRF Token: {}", token);
        }

        // Auto-fill with test data
        let submitter = FormSubmitter::new();
        submitter.fill_defaults(&mut form);
    }

    Ok(())
}
```

### Web Crawling

```rust
use kalamari::{Browser, Crawler, CrawlConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Arc::new(Browser::launch().await?);

    let config = CrawlConfig::new()
        .max_depth(3)
        .max_pages(100)
        .same_domain_only(true)
        .exclude("logout");

    let crawler = Crawler::new(browser, config);
    let results = crawler.crawl("https://example.com").await?;

    println!("Crawled {} pages", results.len());
    for result in results {
        println!("{} [{}] - {} forms", result.url, result.status, result.forms.len());
    }

    Ok(())
}
```

### PDF Generation (Feature-gated)

```rust
use kalamari::browser::{PrintToPdfOptions, create_pdf_generator};

// Enable with: kalamari = { features = ["pdf"] }

let generator = create_pdf_generator();
let options = PrintToPdfOptions::a4()
    .margins(0.5)
    .header("<div>Report Header</div>")
    .footer("<div>Page <span class='pageNumber'></span></div>");

let pdf_bytes = generator.generate_pdf(&html, &options)?;
std::fs::write("report.pdf", pdf_bytes)?;
```

### Auth Session Extraction

```rust
use kalamari::{Browser, AuthSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    // Navigate to login and authenticate
    page.navigate("https://example.com/login").await?;
    // ... perform login ...

    // Extract auth session (cookies, localStorage, headers)
    let session = page.extract_auth_session();

    println!("Session ID: {:?}", session.session_id);
    println!("Bearer Token: {:?}", session.bearer_token);
    println!("CSRF Token: {:?}", session.csrf_token);
    println!("Authenticated: {}", session.is_authenticated);

    // Use session for subsequent requests
    if let Some(auth_header) = session.authorization_header() {
        println!("Auth Header: {}", auth_header);
    }

    Ok(())
}
```

### SPA Route Detection

```rust
use kalamari::{ScriptAnalyzer, ScriptSource};

// Extract SPA routes from JavaScript bundles (Vue/React/Angular)
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
        println!("WebSocket: {} ({:?})", endpoint.url, endpoint.discovery_method);
    }

    // Find API endpoints
    let api_endpoints = analyzer.find_api_endpoints(script);
    for endpoint in api_endpoints {
        println!("API: {}", endpoint);
    }
}
```

### JavaScript Timer Control

```rust
use kalamari::{TimerQueue, JsIdleConfig};

// Lonkero pattern for waiting on async JS:
// std::thread::sleep(Duration::from_millis(500));
// let result = tab.evaluate(&js_code, true).await?;

// Kalamari equivalent:
let timer_queue = TimerQueue::new();

// Execute all pending setTimeout/setInterval immediately
let code_to_execute = timer_queue.flush_all();
for code in code_to_execute {
    runtime.execute(&code)?;
}

// Or flush with a limit (prevent infinite loops)
let code = timer_queue.flush_limited(100);

// Check if there are pending timers
if timer_queue.has_pending() {
    println!("Still {} pending timers", timer_queue.pending_count());
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

## JavaScript API Coverage

Kalamari implements browser-compatible JavaScript APIs that Lonkero's XSS scanner expects:

### DOM API
- `document.createElement()`, `document.createTextNode()`
- `document.getElementById()`, `document.querySelector()`, `document.querySelectorAll()`
- `document.write()`, `document.writeln()` (XSS sinks - monitored)
- `element.innerHTML`, `element.outerHTML`, `element.textContent`
- `element.getAttribute()`, `element.setAttribute()`, `element.removeAttribute()`
- `element.appendChild()`, `element.removeChild()`, `element.insertBefore()`
- `element.addEventListener()`, `element.removeEventListener()`
- `element.classList.add()`, `element.classList.remove()`, `element.classList.contains()`

### Browser APIs
- `MutationObserver` - Stub for DOM change detection
- `localStorage`, `sessionStorage` - Full implementation
- `XMLHttpRequest` - Stub with readyState tracking
- `fetch()` - Stub with Promise-like interface
- `Event`, `CustomEvent` - Event construction
- `DOMParser` - HTML parsing

### XSS Hooks (Auto-injected)
- `alert()`, `confirm()`, `prompt()` - Intercepted and logged as XSS triggers
- `eval()`, `Function()` - Monitored for suspicious content
- `innerHTML` setter - Monitored for script injection
- `document.write()` - Monitored as XSS sink

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
│  │   Cookie     │  │    Form      │  │    Crawler       │   │
│  │     Jar      │  │  Extractor   │  │                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `default` | Core functionality | None |
| `websocket` | WebSocket support | tokio-tungstenite |
| `pdf` | Simple PDF generation | printpdf |
| `chrome-pdf` | Full Chrome PDF (fallback) | headless_chrome |
| `full` | All features | All above |

## Dependencies

| Crate | Purpose | Notes |
|-------|---------|-------|
| `boa_engine` | JavaScript execution | Pure Rust, no external binaries |
| `html5ever` | HTML parsing | Spec-compliant HTML5 parser |
| `reqwest` | HTTP client | rustls for TLS (no OpenSSL) |
| `tokio` | Async runtime | Industry standard |

## Limitations

Kalamari is optimized for security testing, not full browser emulation:

- **No visual rendering**: CSS layout/painting not implemented
- **No WebGL/Canvas**: Graphics APIs not supported
- **Timer execution**: setTimeout/setInterval queued, use `flush_timers()` to execute
- **No plugins**: Flash, PDF viewer, etc. not supported

For features requiring full browser rendering (screenshots, visual testing), use the `chrome-pdf` feature which falls back to headless_chrome.

## License

Copyright (c) 2026 Bountyy Oy. All rights reserved.

This software is proprietary and confidential.

## Links

- [Lonkero Security Scanner](https://github.com/bountyyfi/lonkero)
- [Bountyy](https://bountyy.fi)
