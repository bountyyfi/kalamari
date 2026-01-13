// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Kalamari CLI - Lightweight Headless Browser
//!
//! Example usage and demonstration of the kalamari library.

use std::env;
use std::process::ExitCode;

use kalamari::{Browser, BrowserConfig, PageConfig};

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("kalamari=info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }

    match args[1].as_str() {
        "fetch" => {
            if args.len() < 3 {
                eprintln!("Usage: kalamari fetch <url>");
                return ExitCode::from(1);
            }
            fetch_url(&args[2]).await
        }
        "xss" => {
            if args.len() < 3 {
                eprintln!("Usage: kalamari xss <url>");
                return ExitCode::from(1);
            }
            check_xss(&args[2]).await
        }
        "crawl" => {
            if args.len() < 3 {
                eprintln!("Usage: kalamari crawl <url>");
                return ExitCode::from(1);
            }
            crawl_site(&args[2]).await
        }
        "forms" => {
            if args.len() < 3 {
                eprintln!("Usage: kalamari forms <url>");
                return ExitCode::from(1);
            }
            extract_forms(&args[2]).await
        }
        "--help" | "-h" | "help" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "--version" | "-v" | "version" => {
            println!("kalamari {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    println!(
        r#"Kalamari - Lightweight Headless Browser for Security Testing

USAGE:
    kalamari <COMMAND> [OPTIONS]

COMMANDS:
    fetch <url>     Fetch a URL and display page information
    xss <url>       Check a URL for XSS vulnerabilities
    crawl <url>     Crawl a website and discover pages
    forms <url>     Extract forms from a page
    help            Show this help message
    version         Show version information

EXAMPLES:
    kalamari fetch https://example.com
    kalamari xss "https://example.com/search?q=<script>alert(1)</script>"
    kalamari crawl https://example.com --depth 3
    kalamari forms https://example.com/login

For more information, see: https://github.com/bountyyfi/kalamari
"#
    );
}

async fn fetch_url(url: &str) -> ExitCode {
    println!("Fetching: {}", url);

    let browser = match Browser::launch().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create browser: {}", e);
            return ExitCode::from(1);
        }
    };

    let page = match browser.new_page().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to create page: {}", e);
            return ExitCode::from(1);
        }
    };

    match page.navigate(url).await {
        Ok(response) => {
            println!("\n=== Response ===");
            println!("Status: {}", response.status);
            println!("URL: {}", response.url);
            println!("Content-Type: {:?}", response.content_type());
            println!("Size: {} bytes", response.body_len());
            println!("Time: {}ms", response.response_time_ms);

            if let Some(title) = page.title() {
                println!("\n=== Page ===");
                println!("Title: {}", title);
            }

            let links = page.links();
            if !links.is_empty() {
                println!("\n=== Links ({}) ===", links.len());
                for link in links.iter().take(10) {
                    println!("  - {}", link);
                }
                if links.len() > 10 {
                    println!("  ... and {} more", links.len() - 10);
                }
            }

            let forms = page.forms();
            if !forms.is_empty() {
                println!("\n=== Forms ({}) ===", forms.len());
                for form in &forms {
                    println!(
                        "  - {} {} ({} fields)",
                        form.method,
                        form.action.as_deref().unwrap_or("(current)"),
                        form.fields.len()
                    );
                }
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to fetch URL: {}", e);
            ExitCode::from(1)
        }
    }
}

async fn check_xss(url: &str) -> ExitCode {
    println!("Checking for XSS: {}", url);

    let browser = match Browser::for_security_scanning().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create browser: {}", e);
            return ExitCode::from(1);
        }
    };

    let page = match browser
        .new_page_with_config(PageConfig::for_xss_scanning())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to create page: {}", e);
            return ExitCode::from(1);
        }
    };

    match page.navigate(url).await {
        Ok(_) => {
            let result = page.analyze_xss();

            if result.triggers.is_empty() {
                println!("\n[OK] No XSS triggers detected");
                ExitCode::SUCCESS
            } else {
                println!("\n[!] XSS Triggers Detected:");
                for trigger in &result.triggers {
                    println!(
                        "  [{:?}] {} (severity: {})",
                        trigger.trigger_type,
                        trigger.payload.chars().take(50).collect::<String>(),
                        trigger.severity()
                    );
                    if !trigger.context.is_empty() {
                        println!("    Context: {}", trigger.context);
                    }
                }

                if result.is_vulnerable() {
                    println!("\n[VULNERABLE] Confirmed XSS vulnerability!");
                    ExitCode::from(2)
                } else {
                    println!("\n[POTENTIAL] Potential XSS issues found");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to fetch URL: {}", e);
            ExitCode::from(1)
        }
    }
}

async fn crawl_site(url: &str) -> ExitCode {
    use kalamari::browser::{CrawlConfig, Crawler};
    use std::sync::Arc;

    println!("Crawling: {}", url);

    let browser = match Browser::launch().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("Failed to create browser: {}", e);
            return ExitCode::from(1);
        }
    };

    let config = CrawlConfig::new()
        .max_depth(2)
        .max_pages(50)
        .same_domain_only(true);

    let crawler = Crawler::new(browser, config);

    match crawler.crawl(url).await {
        Ok(results) => {
            println!("\n=== Crawl Results ({} pages) ===", results.len());

            for result in &results {
                let status_emoji = if result.status >= 200 && result.status < 300 {
                    "✓"
                } else if result.error.is_some() {
                    "✗"
                } else {
                    "?"
                };

                println!(
                    "{} [{}] {} ({}ms)",
                    status_emoji, result.status, result.url, result.response_time_ms
                );

                if !result.forms.is_empty() {
                    println!("   Forms: {}", result.forms.len());
                }
            }

            let total_forms: usize = results.iter().map(|r| r.forms.len()).sum();
            println!(
                "\nSummary: {} pages, {} forms found",
                results.len(),
                total_forms
            );

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Crawl failed: {}", e);
            ExitCode::from(1)
        }
    }
}

async fn extract_forms(url: &str) -> ExitCode {
    println!("Extracting forms from: {}", url);

    let browser = match Browser::launch().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create browser: {}", e);
            return ExitCode::from(1);
        }
    };

    let page = match browser.new_page().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to create page: {}", e);
            return ExitCode::from(1);
        }
    };

    match page.navigate(url).await {
        Ok(_) => {
            let forms = page.forms();

            if forms.is_empty() {
                println!("\nNo forms found on page");
            } else {
                println!("\n=== Forms ({}) ===", forms.len());

                for (i, form) in forms.iter().enumerate() {
                    println!("\nForm #{}", i + 1);
                    println!("  ID: {:?}", form.id);
                    println!("  Action: {:?}", form.action);
                    println!("  Method: {}", form.method);
                    println!("  Enctype: {}", form.enctype);

                    if let Some(ref csrf) = form.csrf_field {
                        println!("  CSRF Field: {}", csrf);
                    }

                    println!("  Fields:");
                    for field in &form.fields {
                        println!(
                            "    - {} (type: {}, required: {})",
                            field.name.as_deref().unwrap_or("<unnamed>"),
                            field.field_type,
                            field.required
                        );
                    }
                }
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to fetch URL: {}", e);
            ExitCode::from(1)
        }
    }
}
