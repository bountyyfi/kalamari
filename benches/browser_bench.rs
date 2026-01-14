// Copyright (c) 2026 Bountyy Oy. All rights reserved.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn html_parsing_benchmark(c: &mut Criterion) {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Test</title></head>
        <body>
            <div id="content">
                <a href="/page1">Link 1</a>
                <a href="/page2">Link 2</a>
                <form action="/submit" method="post">
                    <input type="text" name="query">
                    <input type="submit">
                </form>
            </div>
        </body>
        </html>
    "#;

    c.bench_function("parse_html", |b| {
        b.iter(|| {
            black_box(html.len())
        })
    });
}

fn xss_detection_benchmark(c: &mut Criterion) {
    let payloads = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ];

    c.bench_function("xss_payload_check", |b| {
        b.iter(|| {
            for payload in &payloads {
                black_box(payload.contains("alert"));
            }
        })
    });
}

criterion_group!(benches, html_parsing_benchmark, xss_detection_benchmark);
criterion_main!(benches);
