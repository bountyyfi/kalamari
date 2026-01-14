// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Content Security Policy (CSP) analysis
//!
//! Parses CSP headers/meta tags and identifies potential bypasses
//! relevant to XSS testing.

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

/// CSP analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CspAnalysis {
    /// Raw CSP policy string
    pub policy: String,
    /// Parsed directives
    pub directives: HashMap<String, Vec<String>>,
    /// Identified bypasses
    pub bypasses: Vec<CspBypass>,
    /// Unsafe directives found
    pub unsafe_directives: Vec<String>,
    /// Missing security directives
    pub missing_directives: Vec<String>,
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Whether CSP would block inline scripts
    pub blocks_inline: bool,
    /// Whether CSP would block eval
    pub blocks_eval: bool,
}

/// CSP bypass type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CspBypass {
    /// 'unsafe-inline' allows inline scripts
    UnsafeInline,
    /// 'unsafe-eval' allows eval()
    UnsafeEval,
    /// data: URI allows data: URLs
    DataUri,
    /// Missing base-uri allows base tag injection
    MissingBaseUri,
    /// JSONP endpoint in allowed origins
    JsonpEndpoint(String),
    /// Angular.js CSP bypass
    AngularBypass,
    /// Whitelisted CDN with exploitable scripts
    CdnBypass(String),
    /// Wildcard in source list
    WildcardSource(String),
    /// 'unsafe-hashes' present
    UnsafeHashes,
    /// Nonce/hash with unsafe-inline (nonce wins)
    NonceWithUnsafeInline,
    /// Object-src not restricted
    UnrestrictedObjectSrc,
    /// Frame-src not restricted
    UnrestrictedFrameSrc,
    /// Missing form-action
    MissingFormAction,
    /// Report-only mode (not enforced)
    ReportOnly,
    /// Deprecated directive used
    DeprecatedDirective(String),
}

impl CspBypass {
    /// Get severity (1-10)
    pub fn severity(&self) -> u8 {
        match self {
            CspBypass::UnsafeInline => 10,
            CspBypass::UnsafeEval => 8,
            CspBypass::DataUri => 7,
            CspBypass::JsonpEndpoint(_) => 9,
            CspBypass::AngularBypass => 9,
            CspBypass::CdnBypass(_) => 8,
            CspBypass::WildcardSource(_) => 6,
            CspBypass::MissingBaseUri => 5,
            CspBypass::UnsafeHashes => 4,
            CspBypass::NonceWithUnsafeInline => 3,
            CspBypass::UnrestrictedObjectSrc => 5,
            CspBypass::UnrestrictedFrameSrc => 4,
            CspBypass::MissingFormAction => 4,
            CspBypass::ReportOnly => 10,
            CspBypass::DeprecatedDirective(_) => 2,
        }
    }

    /// Get description
    pub fn description(&self) -> String {
        match self {
            CspBypass::UnsafeInline => "unsafe-inline allows arbitrary inline scripts".to_string(),
            CspBypass::UnsafeEval => "unsafe-eval allows eval() and similar".to_string(),
            CspBypass::DataUri => "data: URIs can be used to inject scripts".to_string(),
            CspBypass::JsonpEndpoint(url) => format!("JSONP endpoint {} can bypass CSP", url),
            CspBypass::AngularBypass => "Angular.js can bypass CSP via template injection".to_string(),
            CspBypass::CdnBypass(cdn) => format!("CDN {} hosts exploitable scripts", cdn),
            CspBypass::WildcardSource(src) => format!("Wildcard {} allows many origins", src),
            CspBypass::MissingBaseUri => "Missing base-uri allows base tag hijacking".to_string(),
            CspBypass::UnsafeHashes => "unsafe-hashes allows specific inline handlers".to_string(),
            CspBypass::NonceWithUnsafeInline => "Nonce present with unsafe-inline (nonce takes precedence)".to_string(),
            CspBypass::UnrestrictedObjectSrc => "object-src not restricted, allows plugin content".to_string(),
            CspBypass::UnrestrictedFrameSrc => "frame-src not restricted, allows arbitrary framing".to_string(),
            CspBypass::MissingFormAction => "Missing form-action allows form hijacking".to_string(),
            CspBypass::ReportOnly => "CSP is report-only, not enforced".to_string(),
            CspBypass::DeprecatedDirective(d) => format!("Deprecated directive: {}", d),
        }
    }
}

/// CSP analyzer
pub struct CspAnalyzer {
    /// Known JSONP endpoints
    jsonp_patterns: Vec<Regex>,
    /// Known vulnerable CDNs
    vulnerable_cdns: HashSet<String>,
}

impl Default for CspAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CspAnalyzer {
    /// Create new analyzer
    pub fn new() -> Self {
        let jsonp_patterns = vec![
            Regex::new(r"callback=").unwrap(),
            Regex::new(r"jsonp=").unwrap(),
            Regex::new(r"cb=").unwrap(),
        ];

        let vulnerable_cdns: HashSet<String> = [
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "ajax.googleapis.com",
            "code.jquery.com",
            "stackpath.bootstrapcdn.com",
            "maxcdn.bootstrapcdn.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            jsonp_patterns,
            vulnerable_cdns,
        }
    }

    /// Parse CSP from header value
    pub fn parse(&self, csp: &str) -> CspAnalysis {
        let mut analysis = CspAnalysis {
            policy: csp.to_string(),
            ..Default::default()
        };

        // Parse directives
        for directive in csp.split(';') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            let parts: Vec<&str> = directive.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let name = parts[0].to_lowercase();
            let values: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

            analysis.directives.insert(name.clone(), values.clone());

            // Check for unsafe directives
            self.check_unsafe(&name, &values, &mut analysis);
        }

        // Check for missing directives
        self.check_missing(&mut analysis);

        // Check for bypasses
        self.check_bypasses(&mut analysis);

        // Calculate security score
        analysis.security_score = self.calculate_score(&analysis);

        // Determine if inline/eval blocked
        analysis.blocks_inline = self.blocks_inline(&analysis);
        analysis.blocks_eval = self.blocks_eval(&analysis);

        analysis
    }

    /// Parse CSP from HTTP headers
    pub fn parse_from_headers(&self, headers: &HashMap<String, String>) -> Option<CspAnalysis> {
        // Check for CSP header
        if let Some(csp) = headers.get("content-security-policy") {
            return Some(self.parse(csp));
        }

        // Check for report-only (less secure)
        if let Some(csp) = headers.get("content-security-policy-report-only") {
            let mut analysis = self.parse(csp);
            analysis.bypasses.push(CspBypass::ReportOnly);
            return Some(analysis);
        }

        None
    }

    /// Parse CSP from meta tag
    pub fn parse_from_meta(&self, content: &str) -> CspAnalysis {
        self.parse(content)
    }

    fn check_unsafe(&self, name: &str, values: &[String], analysis: &mut CspAnalysis) {
        for value in values {
            let value_lower = value.to_lowercase();

            // Check for unsafe-inline
            if value_lower == "'unsafe-inline'" {
                analysis.unsafe_directives.push(format!("{}: unsafe-inline", name));
                if name == "script-src" || name == "default-src" {
                    analysis.bypasses.push(CspBypass::UnsafeInline);
                }
            }

            // Check for unsafe-eval
            if value_lower == "'unsafe-eval'" {
                analysis.unsafe_directives.push(format!("{}: unsafe-eval", name));
                if name == "script-src" || name == "default-src" {
                    analysis.bypasses.push(CspBypass::UnsafeEval);
                }
            }

            // Check for unsafe-hashes
            if value_lower == "'unsafe-hashes'" {
                analysis.unsafe_directives.push(format!("{}: unsafe-hashes", name));
                analysis.bypasses.push(CspBypass::UnsafeHashes);
            }

            // Check for data: URI
            if value_lower == "data:" {
                if name == "script-src" || name == "default-src" {
                    analysis.bypasses.push(CspBypass::DataUri);
                }
            }

            // Check for wildcards
            if value.contains('*') && value != "'unsafe-inline'" {
                analysis.bypasses.push(CspBypass::WildcardSource(value.clone()));
            }

            // Check for vulnerable CDNs
            for cdn in &self.vulnerable_cdns {
                if value.contains(cdn) {
                    analysis.bypasses.push(CspBypass::CdnBypass(cdn.clone()));
                }
            }
        }

        // Check for nonce with unsafe-inline
        let has_nonce = values.iter().any(|v| v.starts_with("'nonce-"));
        let has_unsafe_inline = values.iter().any(|v| v == "'unsafe-inline'");
        if has_nonce && has_unsafe_inline {
            analysis.bypasses.push(CspBypass::NonceWithUnsafeInline);
        }
    }

    fn check_missing(&self, analysis: &mut CspAnalysis) {
        let important_directives = [
            "default-src",
            "script-src",
            "style-src",
            "object-src",
            "base-uri",
            "form-action",
            "frame-ancestors",
        ];

        for directive in &important_directives {
            if !analysis.directives.contains_key(*directive) {
                // default-src covers some missing directives
                if *directive != "default-src" && analysis.directives.contains_key("default-src") {
                    continue;
                }
                analysis.missing_directives.push(directive.to_string());
            }
        }

        // Specific bypass checks for missing directives
        if !analysis.directives.contains_key("base-uri") {
            analysis.bypasses.push(CspBypass::MissingBaseUri);
        }

        if !analysis.directives.contains_key("form-action") {
            analysis.bypasses.push(CspBypass::MissingFormAction);
        }

        if !analysis.directives.contains_key("object-src")
            && !analysis.directives.contains_key("default-src") {
            analysis.bypasses.push(CspBypass::UnrestrictedObjectSrc);
        }

        if !analysis.directives.contains_key("frame-src")
            && !analysis.directives.contains_key("child-src")
            && !analysis.directives.contains_key("default-src") {
            analysis.bypasses.push(CspBypass::UnrestrictedFrameSrc);
        }
    }

    fn check_bypasses(&self, analysis: &mut CspAnalysis) {
        // Check for Angular bypass potential
        let script_sources: Vec<&String> = analysis
            .directives
            .get("script-src")
            .or(analysis.directives.get("default-src"))
            .map(|v| v.iter().collect())
            .unwrap_or_default();

        for source in &script_sources {
            // Check for angular CDN
            if source.contains("ajax.googleapis.com") || source.contains("angularjs") {
                analysis.bypasses.push(CspBypass::AngularBypass);
                break;
            }
        }

        // Check for deprecated directives
        let deprecated = ["plugin-types", "referrer", "block-all-mixed-content"];
        for dep in &deprecated {
            if analysis.directives.contains_key(*dep) {
                analysis.bypasses.push(CspBypass::DeprecatedDirective(dep.to_string()));
            }
        }
    }

    fn calculate_score(&self, analysis: &CspAnalysis) -> u8 {
        let mut score: i32 = 100;

        // Deduct for each bypass
        for bypass in &analysis.bypasses {
            score -= bypass.severity() as i32 * 3;
        }

        // Deduct for missing directives
        score -= (analysis.missing_directives.len() * 5) as i32;

        // Deduct for unsafe directives
        score -= (analysis.unsafe_directives.len() * 8) as i32;

        // Bonus for having nonce/hash
        let has_nonce = analysis.directives.values().any(|v| {
            v.iter().any(|s| s.starts_with("'nonce-") || s.starts_with("'sha256-"))
        });
        if has_nonce {
            score += 10;
        }

        score.clamp(0, 100) as u8
    }

    fn blocks_inline(&self, analysis: &CspAnalysis) -> bool {
        let script_src = analysis.directives.get("script-src")
            .or(analysis.directives.get("default-src"));

        if let Some(values) = script_src {
            // unsafe-inline allows inline
            if values.iter().any(|v| v == "'unsafe-inline'") {
                // But nonce/hash takes precedence
                let has_nonce_or_hash = values.iter().any(|v| {
                    v.starts_with("'nonce-") || v.starts_with("'sha256-") ||
                    v.starts_with("'sha384-") || v.starts_with("'sha512-")
                });
                return has_nonce_or_hash;
            }
            return true;
        }

        // No script-src or default-src means everything is allowed
        false
    }

    fn blocks_eval(&self, analysis: &CspAnalysis) -> bool {
        let script_src = analysis.directives.get("script-src")
            .or(analysis.directives.get("default-src"));

        if let Some(values) = script_src {
            // unsafe-eval allows eval
            return !values.iter().any(|v| v == "'unsafe-eval'");
        }

        // No script-src or default-src means everything is allowed
        false
    }
}

/// Extract CSP from HTML meta tag
pub fn extract_csp_from_html(html: &str) -> Option<String> {
    let meta_regex = Regex::new(
        r#"<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy["'][^>]+content\s*=\s*["']([^"']+)["']"#
    ).ok()?;

    meta_regex.captures(html).map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csp() {
        let analyzer = CspAnalyzer::new();
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'";
        let analysis = analyzer.parse(csp);

        assert!(analysis.bypasses.contains(&CspBypass::UnsafeInline));
        assert!(!analysis.blocks_inline);
    }

    #[test]
    fn test_missing_directives() {
        let analyzer = CspAnalyzer::new();
        let csp = "script-src 'self'";
        let analysis = analyzer.parse(csp);

        assert!(analysis.missing_directives.contains(&"base-uri".to_string()));
        assert!(analysis.bypasses.contains(&CspBypass::MissingBaseUri));
    }

    #[test]
    fn test_nonce_with_unsafe_inline() {
        let analyzer = CspAnalyzer::new();
        let csp = "script-src 'nonce-abc123' 'unsafe-inline'";
        let analysis = analyzer.parse(csp);

        assert!(analysis.bypasses.contains(&CspBypass::NonceWithUnsafeInline));
        assert!(analysis.blocks_inline); // nonce takes precedence
    }

    #[test]
    fn test_security_score() {
        let analyzer = CspAnalyzer::new();

        // Good CSP
        let good = "default-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'";
        let good_analysis = analyzer.parse(good);
        assert!(good_analysis.security_score > 70);

        // Bad CSP
        let bad = "script-src 'unsafe-inline' 'unsafe-eval' *";
        let bad_analysis = analyzer.parse(bad);
        assert!(bad_analysis.security_score < 50);
    }

    #[test]
    fn test_extract_from_html() {
        let html = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>"#;
        let csp = extract_csp_from_html(html);
        assert_eq!(csp, Some("default-src 'self'".to_string()));
    }
}
