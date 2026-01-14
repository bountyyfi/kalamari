// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Subresource Integrity (SRI) checking
//!
//! Detects missing or invalid integrity attributes on scripts/stylesheets.

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// SRI violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SriViolation {
    /// Resource URL
    pub resource_url: String,
    /// Resource type
    pub resource_type: ResourceType,
    /// Expected hash (from integrity attribute)
    pub expected_hash: Option<String>,
    /// Actual hash of content
    pub actual_hash: Option<String>,
    /// Type of violation
    pub violation_type: SriViolationType,
    /// Element HTML (truncated)
    pub element_html: String,
}

/// Type of SRI violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SriViolationType {
    /// No integrity attribute present
    MissingIntegrity,
    /// Hash doesn't match content
    HashMismatch,
    /// Weak algorithm (sha256 instead of sha384/512)
    WeakAlgorithm,
    /// Invalid hash format
    InvalidFormat,
    /// crossorigin attribute missing with integrity
    MissingCrossorigin,
}

impl SriViolationType {
    /// Get severity (1-10)
    pub fn severity(&self) -> u8 {
        match self {
            SriViolationType::MissingIntegrity => 6,
            SriViolationType::HashMismatch => 10,
            SriViolationType::WeakAlgorithm => 3,
            SriViolationType::InvalidFormat => 5,
            SriViolationType::MissingCrossorigin => 4,
        }
    }
}

/// Resource type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceType {
    Script,
    Stylesheet,
    Other,
}

/// SRI checker
pub struct SriChecker {
    /// Require SRI for all external scripts
    pub require_scripts: bool,
    /// Require SRI for all external stylesheets
    pub require_stylesheets: bool,
    /// Minimum acceptable algorithm
    pub min_algorithm: SriAlgorithm,
    /// CDN hosts that should have SRI
    pub cdn_hosts: Vec<String>,
}

/// SRI hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SriAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Default for SriChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SriChecker {
    /// Create new SRI checker
    pub fn new() -> Self {
        Self {
            require_scripts: true,
            require_stylesheets: false,
            min_algorithm: SriAlgorithm::Sha384,
            cdn_hosts: vec![
                "cdnjs.cloudflare.com".to_string(),
                "cdn.jsdelivr.net".to_string(),
                "unpkg.com".to_string(),
                "ajax.googleapis.com".to_string(),
                "code.jquery.com".to_string(),
            ],
        }
    }

    /// Check HTML for SRI violations
    pub fn check_html(&self, html: &str, page_url: &str) -> Vec<SriViolation> {
        let mut violations = Vec::new();

        // Check scripts
        violations.extend(self.check_scripts(html, page_url));

        // Check stylesheets
        violations.extend(self.check_stylesheets(html, page_url));

        violations
    }

    /// Check script tags
    fn check_scripts(&self, html: &str, page_url: &str) -> Vec<SriViolation> {
        let mut violations = Vec::new();

        let script_regex = Regex::new(r#"<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();

        for cap in script_regex.captures_iter(html) {
            let src = &cap[1];
            let full_tag = &cap[0];

            // Skip inline scripts and same-origin
            if self.is_same_origin(src, page_url) {
                continue;
            }

            // Check for integrity attribute
            let integrity = self.extract_integrity(full_tag);
            let has_crossorigin = full_tag.contains("crossorigin");

            if let Some(ref hash) = integrity {
                // Has integrity, check validity
                if let Some(violation) = self.validate_integrity(hash, src, full_tag) {
                    violations.push(violation);
                }

                // Check for crossorigin
                if !has_crossorigin {
                    violations.push(SriViolation {
                        resource_url: src.to_string(),
                        resource_type: ResourceType::Script,
                        expected_hash: Some(hash.clone()),
                        actual_hash: None,
                        violation_type: SriViolationType::MissingCrossorigin,
                        element_html: truncate(full_tag, 200),
                    });
                }
            } else if self.should_require_sri(src) {
                // Missing integrity on external script
                violations.push(SriViolation {
                    resource_url: src.to_string(),
                    resource_type: ResourceType::Script,
                    expected_hash: None,
                    actual_hash: None,
                    violation_type: SriViolationType::MissingIntegrity,
                    element_html: truncate(full_tag, 200),
                });
            }
        }

        violations
    }

    /// Check link stylesheets
    fn check_stylesheets(&self, html: &str, page_url: &str) -> Vec<SriViolation> {
        let mut violations = Vec::new();

        if !self.require_stylesheets {
            return violations;
        }

        let link_regex = Regex::new(
            r#"<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>"#
        ).unwrap();

        for cap in link_regex.captures_iter(html) {
            let href = &cap[1];
            let full_tag = &cap[0];

            if self.is_same_origin(href, page_url) {
                continue;
            }

            let integrity = self.extract_integrity(full_tag);

            if integrity.is_none() && self.should_require_sri(href) {
                violations.push(SriViolation {
                    resource_url: href.to_string(),
                    resource_type: ResourceType::Stylesheet,
                    expected_hash: None,
                    actual_hash: None,
                    violation_type: SriViolationType::MissingIntegrity,
                    element_html: truncate(full_tag, 200),
                });
            }
        }

        violations
    }

    /// Extract integrity attribute value
    fn extract_integrity(&self, tag: &str) -> Option<String> {
        let integrity_regex = Regex::new(r#"integrity\s*=\s*["']([^"']+)["']"#).ok()?;
        integrity_regex.captures(tag).map(|c| c[1].to_string())
    }

    /// Validate integrity hash format
    fn validate_integrity(&self, hash: &str, url: &str, tag: &str) -> Option<SriViolation> {
        // Check format: sha256-xxx, sha384-xxx, sha512-xxx
        let parts: Vec<&str> = hash.split('-').collect();
        if parts.len() < 2 {
            return Some(SriViolation {
                resource_url: url.to_string(),
                resource_type: ResourceType::Script,
                expected_hash: Some(hash.to_string()),
                actual_hash: None,
                violation_type: SriViolationType::InvalidFormat,
                element_html: truncate(tag, 200),
            });
        }

        let algorithm = parts[0].to_lowercase();
        let min_algo = match self.min_algorithm {
            SriAlgorithm::Sha256 => "sha256",
            SriAlgorithm::Sha384 => "sha384",
            SriAlgorithm::Sha512 => "sha512",
        };

        // Check for weak algorithm
        if algorithm == "sha256" && self.min_algorithm > SriAlgorithm::Sha256 {
            return Some(SriViolation {
                resource_url: url.to_string(),
                resource_type: ResourceType::Script,
                expected_hash: Some(hash.to_string()),
                actual_hash: None,
                violation_type: SriViolationType::WeakAlgorithm,
                element_html: truncate(tag, 200),
            });
        }

        None
    }

    /// Check if URL is same origin
    fn is_same_origin(&self, url: &str, page_url: &str) -> bool {
        // Relative URLs are same-origin
        if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("//") {
            return true;
        }

        // Compare hosts
        let url_host = extract_host(url);
        let page_host = extract_host(page_url);

        url_host == page_host
    }

    /// Check if URL should require SRI
    fn should_require_sri(&self, url: &str) -> bool {
        if !self.require_scripts {
            return false;
        }

        let host = extract_host(url);
        self.cdn_hosts.iter().any(|cdn| host.contains(cdn))
    }
}

/// Extract host from URL
fn extract_host(url: &str) -> String {
    let url = url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("//");

    url.split('/').next().unwrap_or("").to_string()
}

/// Truncate string
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_integrity() {
        let checker = SriChecker::new();
        let html = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>"#;
        let violations = checker.check_html(html, "https://example.com");

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, SriViolationType::MissingIntegrity);
    }

    #[test]
    fn test_with_integrity() {
        let checker = SriChecker::new();
        let html = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js" integrity="sha384-xxx" crossorigin="anonymous"></script>"#;
        let violations = checker.check_html(html, "https://example.com");

        assert!(violations.is_empty());
    }

    #[test]
    fn test_same_origin_ignored() {
        let checker = SriChecker::new();
        let html = r#"<script src="/js/app.js"></script>"#;
        let violations = checker.check_html(html, "https://example.com");

        assert!(violations.is_empty());
    }
}
