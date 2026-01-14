// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! DOM Clobbering detection
//!
//! Detects potential DOM clobbering vulnerabilities where HTML elements
//! with id/name attributes can override window/document properties.

use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// DOM clobbering detection result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomClobberResult {
    /// Elements that could clobber window globals
    pub clobbered_globals: Vec<ClobberedElement>,
    /// Form elements that could hijack form.action
    pub form_hijacks: Vec<ClobberedElement>,
    /// Potential prototype pollution vectors
    pub prototype_pollution: Vec<String>,
    /// Total risk score
    pub risk_score: u8,
}

/// Element that causes clobbering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClobberedElement {
    /// HTML tag name
    pub tag: String,
    /// The id or name attribute
    pub identifier: String,
    /// What it clobbers
    pub clobbers: String,
    /// Impact description
    pub impact: String,
    /// Element HTML (truncated)
    pub html: String,
}

/// DOM clobber detector
pub struct DomClobberDetector {
    /// Window properties to check for clobbering
    window_properties: HashSet<String>,
    /// Document properties to check
    document_properties: HashSet<String>,
    /// Dangerous property names
    dangerous_names: HashSet<String>,
}

impl Default for DomClobberDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DomClobberDetector {
    /// Create new detector
    pub fn new() -> Self {
        let window_properties: HashSet<String> = [
            "location", "document", "alert", "confirm", "prompt",
            "open", "close", "print", "fetch", "XMLHttpRequest",
            "eval", "Function", "setTimeout", "setInterval",
            "localStorage", "sessionStorage", "indexedDB",
            "navigator", "history", "screen", "frames",
            "parent", "top", "self", "opener", "name",
        ].iter().map(|s| s.to_string()).collect();

        let document_properties: HashSet<String> = [
            "body", "head", "forms", "links", "images", "scripts",
            "cookie", "domain", "referrer", "URL", "location",
            "createElement", "getElementById", "querySelector",
            "write", "writeln", "open", "close",
        ].iter().map(|s| s.to_string()).collect();

        let dangerous_names: HashSet<String> = [
            // Security-sensitive
            "location", "url", "href", "src", "action", "data",
            "innerHTML", "outerHTML", "textContent",
            // Common sinks
            "callback", "redirect", "return", "next", "goto",
            // Config
            "config", "settings", "options", "params",
            // Auth
            "token", "auth", "session", "user", "admin",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            window_properties,
            document_properties,
            dangerous_names,
        }
    }

    /// Analyze HTML for DOM clobbering vectors
    pub fn analyze(&self, html: &str) -> DomClobberResult {
        let mut result = DomClobberResult::default();

        // Find elements with id attribute
        self.find_id_clobbering(html, &mut result);

        // Find elements with name attribute
        self.find_name_clobbering(html, &mut result);

        // Find form clobbering (form.elements)
        self.find_form_clobbering(html, &mut result);

        // Find prototype pollution vectors
        self.find_prototype_pollution(html, &mut result);

        // Calculate risk score
        result.risk_score = self.calculate_risk(&result);

        result
    }

    fn find_id_clobbering(&self, html: &str, result: &mut DomClobberResult) {
        let id_regex = Regex::new(r#"<(\w+)[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();

        for cap in id_regex.captures_iter(html) {
            let tag = &cap[1];
            let id = &cap[2];
            let full_match = &cap[0];

            // Check if id clobbers window property
            if self.window_properties.contains(id) {
                result.clobbered_globals.push(ClobberedElement {
                    tag: tag.to_string(),
                    identifier: id.to_string(),
                    clobbers: format!("window.{}", id),
                    impact: format!("Element with id='{}' will override window.{}", id, id),
                    html: truncate(full_match, 150),
                });
            }

            // Check if id is dangerous
            if self.dangerous_names.contains(&id.to_lowercase()) {
                result.clobbered_globals.push(ClobberedElement {
                    tag: tag.to_string(),
                    identifier: id.to_string(),
                    clobbers: format!("window.{}", id),
                    impact: format!("Potentially dangerous id='{}' could be used in attack", id),
                    html: truncate(full_match, 150),
                });
            }
        }
    }

    fn find_name_clobbering(&self, html: &str, result: &mut DomClobberResult) {
        // Elements with name attribute that get added to window/document
        let name_regex = Regex::new(r#"<(form|iframe|embed|object|img)[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();

        for cap in name_regex.captures_iter(html) {
            let tag = &cap[1];
            let name = &cap[2];
            let full_match = &cap[0];

            if self.window_properties.contains(name) || self.dangerous_names.contains(&name.to_lowercase()) {
                result.clobbered_globals.push(ClobberedElement {
                    tag: tag.to_string(),
                    identifier: name.to_string(),
                    clobbers: format!("window.{} / document.{}", name, name),
                    impact: format!("<{}> with name='{}' clobbers global", tag, name),
                    html: truncate(full_match, 150),
                });
            }
        }
    }

    fn find_form_clobbering(&self, html: &str, result: &mut DomClobberResult) {
        // Find forms and check for element name collision with form properties
        let form_regex = Regex::new(r#"<form[^>]*>([\s\S]*?)</form>"#).unwrap();
        let input_regex = Regex::new(r#"<(input|button|select|textarea)[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();

        let form_properties: HashSet<&str> = [
            "action", "method", "target", "submit", "reset",
            "elements", "length", "encoding", "enctype",
        ].iter().cloned().collect();

        for form_cap in form_regex.captures_iter(html) {
            let form_content = &form_cap[1];

            for input_cap in input_regex.captures_iter(form_content) {
                let tag = &input_cap[1];
                let name = &input_cap[2];
                let full_match = &input_cap[0];

                if form_properties.contains(name) {
                    result.form_hijacks.push(ClobberedElement {
                        tag: tag.to_string(),
                        identifier: name.to_string(),
                        clobbers: format!("form.{}", name),
                        impact: format!("Input name='{}' clobbers form.{}", name, name),
                        html: truncate(full_match, 150),
                    });
                }
            }
        }
    }

    fn find_prototype_pollution(&self, html: &str, result: &mut DomClobberResult) {
        // Look for __proto__, constructor, prototype in ids/names
        let proto_regex = Regex::new(r#"(?:id|name)\s*=\s*["'](__proto__|constructor|prototype)[^"']*["']"#).unwrap();

        for cap in proto_regex.captures_iter(html) {
            result.prototype_pollution.push(cap[0].to_string());
        }
    }

    fn calculate_risk(&self, result: &DomClobberResult) -> u8 {
        let mut score = 0u32;

        // Each clobbered global adds risk
        for clobbered in &result.clobbered_globals {
            if self.window_properties.contains(&clobbered.identifier) {
                score += 15;
            } else if self.dangerous_names.contains(&clobbered.identifier.to_lowercase()) {
                score += 10;
            }
        }

        // Form hijacks are high risk
        score += (result.form_hijacks.len() * 20) as u32;

        // Prototype pollution is critical
        score += (result.prototype_pollution.len() * 30) as u32;

        score.min(100) as u8
    }
}

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
    fn test_id_clobbering() {
        let detector = DomClobberDetector::new();
        let html = r#"<div id="location">test</div>"#;
        let result = detector.analyze(html);

        assert!(!result.clobbered_globals.is_empty());
        assert!(result.clobbered_globals[0].identifier == "location");
    }

    #[test]
    fn test_form_clobbering() {
        let detector = DomClobberDetector::new();
        let html = r#"<form><input name="action" value="test"></form>"#;
        let result = detector.analyze(html);

        assert!(!result.form_hijacks.is_empty());
        assert!(result.form_hijacks[0].identifier == "action");
    }

    #[test]
    fn test_prototype_pollution() {
        let detector = DomClobberDetector::new();
        let html = r#"<div id="__proto__">test</div>"#;
        let result = detector.analyze(html);

        assert!(!result.prototype_pollution.is_empty());
    }
}
