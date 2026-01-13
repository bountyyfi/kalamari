# Kalamari 🦑

**Lightweight Headless Browser for Security Testing**

Kalamari is a pure Rust headless browser designed specifically for XSS scanning, web crawling, and security testing. Unlike traditional headless browsers that require Chrome/Chromium binaries (~200MB+), Kalamari is entirely self-contained with minimal dependencies.

## Features

- **🪶 Lightweight**: ~10MB vs Chrome's 200MB+ footprint
- **🚀 Fast Startup**: No browser process to spawn
- **🔒 XSS Detection**: Built-in alert/confirm/prompt interception
- **🌐 DOM API**: JavaScript can interact with parsed HTML via boa_engine
- **🍪 Cookie Management**: Full cookie jar support with auth tokens
- **📡 Network Interception**: Capture all requests/responses
- **📝 Form Extraction**: Automatically detect and extract forms with CSRF tokens
- **🕷️ Crawler**: Built-in web crawler with configurable depth and patterns

## Why Kalamari?

Traditional headless browsers like Puppeteer, Playwright, or headless_chrome require:
- Chrome/Chromium binary (~200MB)
- High memory usage (~100-300MB per instance)
- Slow startup (1-3 seconds)
- Complex process management

Kalamari provides:
- Pure Rust implementation
- Zero external browser dependencies
- Instant startup
- ~10-20MB memory per page
- Perfect for security scanning at scale

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kalamari = "0.1"
```

Or install the CLI:

```bash
cargo install kalamari
```

## Quick Start

### As a Library

```rust
use kalamari::{Browser, BrowserConfig, PageConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a browser instance
    let browser = Browser::launch().await?;

    // Create a new page
    let page = browser.new_page().await?;

    // Navigate to a URL
    page.navigate("https://example.com").await?;

    // Get page title
    println!("Title: {:?}", page.title());

    // Extract all links
    for link in page.links() {
        println!("Link: {}", link);
    }

    // Check for XSS triggers
    let xss_result = page.analyze_xss();
    if xss_result.is_vulnerable() {
        println!("XSS vulnerability detected!");
        for trigger in xss_result.triggers {
            println!("  - {:?}: {}", trigger.trigger_type, trigger.payload);
        }
    }

    Ok(())
}
```

### XSS Scanning

```rust
use kalamari::{Browser, PageConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::for_security_scanning().await?;
    let page = browser.new_page_with_config(PageConfig::for_xss_scanning()).await?;

    // Test a URL with payload
    page.navigate("https://target.com/search?q=<script>alert(1)</script>").await?;

    // Check for XSS
    let result = page.analyze_xss();

    for trigger in result.triggers {
        if trigger.is_confirmed() {
            println!("CONFIRMED XSS: {:?}", trigger);
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

### Form Extraction and Testing

```rust
use kalamari::Browser;
use kalamari::browser::FormSubmitter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com/login").await?;

    // Extract forms
    let mut forms = page.forms();

    for form in &mut forms {
        println!("Form: {} {}", form.method, form.action.as_deref().unwrap_or("/"));

        // Check for CSRF token
        if let Some(token) = form.csrf_token() {
            println!("  CSRF Token: {}", token);
        }

        // Fill with test data
        let submitter = FormSubmitter::new();
        submitter.fill_defaults(form);

        // Get form data
        for (name, value) in form.get_data() {
            println!("  {} = {}", name, value);
        }
    }

    Ok(())
}
```

### Web Crawling

```rust
use kalamari::Browser;
use kalamari::browser::{Crawler, CrawlConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Arc::new(Browser::launch().await?);

    let config = CrawlConfig::new()
        .max_depth(3)
        .max_pages(100)
        .same_domain_only(true)
        .exclude("logout".to_string());

    let crawler = Crawler::new(browser, config);
    let results = crawler.crawl("https://example.com").await?;

    println!("Crawled {} pages", results.len());

    for result in results {
        println!("{} [{}] - {} forms",
            result.url,
            result.status,
            result.forms.len()
        );
    }

    Ok(())
}
```

### Network Interception

```rust
use kalamari::Browser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::launch().await?;
    let page = browser.new_page().await?;

    page.navigate("https://example.com").await?;

    // Get all network events
    for event in browser.network_events() {
        println!("{} {} -> {}",
            event.request.method,
            event.request.url,
            event.response.map(|r| r.status.to_string()).unwrap_or("Error".to_string())
        );
    }

    // Get API requests specifically
    for api in browser.network().api_requests() {
        println!("API: {} {}", api.request.method, api.request.url);
    }

    Ok(())
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

## Integration with Lonkero

Kalamari is designed to integrate seamlessly with [Lonkero](https://github.com/bountyyfi/lonkero), Bountyy's web security scanner:

```rust
use kalamari::{Browser, PageConfig};
use kalamari::xss::PayloadGenerator;

// Generate payloads
let generator = PayloadGenerator::with_marker("LONKERO_XSS");
let payloads = generator.all_payloads();

// Test each payload
let browser = Browser::for_security_scanning().await?;
let page = browser.new_page_with_config(PageConfig::for_xss_scanning()).await?;

for payload in payloads {
    let url = format!("https://target.com/search?q={}", payload.payload);
    page.navigate(&url).await?;

    let triggers = page.get_xss_triggers();
    if !triggers.is_empty() {
        // Report vulnerability to Lonkero
    }
}
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
│  │ Cookie Jar   │  │  CSS Select  │  │  XSS Detection   │   │
│  │ Auth Tokens  │  │  (selectors) │  │  (alert hooks)   │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         │                  │                   │             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   Network    │  │    Form      │  │    Crawler       │   │
│  │ Interceptor  │  │  Extractor   │  │                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

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
- **Limited JavaScript**: Some browser APIs are stubbed
- **No plugins**: Flash, PDF viewer, etc. not supported

For full browser compatibility, consider Puppeteer/Playwright. For security testing, Kalamari offers a lighter, faster alternative.

## License

Copyright (c) 2026 Bountyy Oy. All rights reserved.

This software is proprietary and confidential.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Links

- [Lonkero Security Scanner](https://github.com/bountyyfi/lonkero)
- [Bountyy](https://bountyy.fi)
- [Documentation](https://docs.rs/kalamari)
