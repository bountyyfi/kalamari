// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! XSS Detector implementation

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use regex::Regex;

use super::{XssResult, XssTrigger, XssTriggerType};
use crate::dom::{Document, Element};
use crate::error::Result;
use crate::js::JsRuntime;

/// XSS Detector configuration
#[derive(Debug, Clone)]
pub struct XssDetectorConfig {
    /// Enable JavaScript execution for detection
    pub execute_js: bool,
    /// Check event handlers
    pub check_event_handlers: bool,
    /// Check DOM sinks
    pub check_dom_sinks: bool,
    /// Custom marker to detect in responses
    pub custom_marker: Option<String>,
    /// Maximum scripts to execute
    pub max_scripts: usize,
    /// Timeout for JS execution (ms)
    pub js_timeout_ms: u64,
}

impl Default for XssDetectorConfig {
    fn default() -> Self {
        Self {
            execute_js: true,
            check_event_handlers: true,
            check_dom_sinks: true,
            custom_marker: None,
            max_scripts: 50,
            js_timeout_ms: 5000,
        }
    }
}

/// XSS Detector for analyzing pages
pub struct XssDetector {
    config: XssDetectorConfig,
    js_runtime: JsRuntime,
    triggers: Arc<RwLock<Vec<XssTrigger>>>,
}

impl XssDetector {
    /// Create a new XSS detector
    pub fn new(config: XssDetectorConfig) -> Self {
        let js_config = crate::js::runtime::JsRuntimeConfig {
            timeout_ms: config.js_timeout_ms,
            xss_detection: true,
            ..Default::default()
        };

        Self {
            config,
            js_runtime: JsRuntime::new(js_config),
            triggers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with default config
    pub fn default_detector() -> Self {
        Self::new(XssDetectorConfig::default())
    }

    /// Analyze a document for XSS
    pub fn analyze(&self, document: &Document, url: Option<&str>) -> XssResult {
        self.triggers.write().clear();

        if let Some(u) = url {
            self.js_runtime.set_url(u);
        }

        let mut result = XssResult {
            url: url.map(String::from),
            ..Default::default()
        };

        // Check for custom marker
        if let Some(ref marker) = self.config.custom_marker {
            self.check_marker(document, marker);
        }

        // Check event handlers
        if self.config.check_event_handlers {
            self.check_event_handlers(document);
        }

        // Check DOM sinks in HTML
        if self.config.check_dom_sinks {
            self.check_dom_sinks(document);
        }

        // Execute inline scripts
        if self.config.execute_js {
            self.execute_scripts(document);
        }

        // Collect triggers
        result.triggers = self.triggers.read().clone();
        result.triggers.extend(self.js_runtime.get_xss_triggers());

        result
    }

    /// Check for reflection of a payload in the response
    pub fn check_reflection(&self, html: &str, payload: &str) -> bool {
        html.contains(payload)
    }

    /// Check for custom marker in document
    fn check_marker(&self, document: &Document, marker: &str) {
        let html = document.outer_html();

        if html.contains(marker) {
            self.triggers.write().push(XssTrigger {
                trigger_type: XssTriggerType::CustomMarker,
                payload: marker.to_string(),
                context: "Marker found in response".to_string(),
                url: None,
            });
        }
    }

    /// Check event handlers for XSS
    fn check_event_handlers(&self, document: &Document) {
        let event_attrs = [
            "onclick",
            "onmouseover",
            "onmouseout",
            "onmouseenter",
            "onmouseleave",
            "onfocus",
            "onblur",
            "onload",
            "onerror",
            "onsubmit",
            "onchange",
            "oninput",
            "onkeydown",
            "onkeyup",
            "onkeypress",
            "ondblclick",
            "oncontextmenu",
            "onscroll",
            "onresize",
            "oncopy",
            "onpaste",
            "ondrag",
            "ondrop",
            "onanimationend",
            "ontouchstart",
            "ontouchmove",
            "ontouchend",
        ];

        // Find all elements with event handlers
        for attr in event_attrs {
            let selector = format!("[{}]", attr);
            for element in document.query_selector_all(&selector) {
                if let Some(handler) = element.get_attribute(attr) {
                    // Check for suspicious patterns
                    if self.is_suspicious_handler(&handler) {
                        self.triggers.write().push(XssTrigger {
                            trigger_type: XssTriggerType::EventHandler,
                            payload: handler.clone(),
                            context: format!("{} attribute on <{}>", attr, element.local_name()),
                            url: None,
                        });
                    }

                    // Execute the handler to detect XSS
                    if self.config.execute_js {
                        let _ = self.js_runtime.execute(&handler);
                    }
                }
            }
        }
    }

    /// Check for suspicious handler content
    fn is_suspicious_handler(&self, handler: &str) -> bool {
        let suspicious_patterns = [
            "alert",
            "confirm",
            "prompt",
            "document.cookie",
            "document.domain",
            "eval(",
            "Function(",
            "setTimeout(",
            "setInterval(",
            "javascript:",
            "data:text/html",
            "onerror",
            "expression(",
            "fromCharCode",
            "atob(",
            "btoa(",
            "String.fromCharCode",
            "\\x",
            "\\u",
            "&#",
        ];

        let handler_lower = handler.to_lowercase();
        suspicious_patterns
            .iter()
            .any(|p| handler_lower.contains(&p.to_lowercase()))
    }

    /// Check DOM sinks in the HTML
    fn check_dom_sinks(&self, document: &Document) {
        let html = document.outer_html();

        // Check for dangerous patterns
        let dangerous_patterns = [
            (r"document\.write\s*\(", "document.write"),
            (r"document\.writeln\s*\(", "document.writeln"),
            (r"\.innerHTML\s*=", "innerHTML assignment"),
            (r"\.outerHTML\s*=", "outerHTML assignment"),
            (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
            (r"eval\s*\(", "eval"),
            (r"new\s+Function\s*\(", "Function constructor"),
            (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
            (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
            (r"location\s*=", "location assignment"),
            (r"location\.href\s*=", "location.href assignment"),
            (r"location\.replace\s*\(", "location.replace"),
            (r"location\.assign\s*\(", "location.assign"),
            (r"window\.open\s*\(", "window.open"),
        ];

        for (pattern, name) in dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(&html) {
                    self.triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::DomManipulation,
                        payload: m.as_str().to_string(),
                        context: format!("Potential {} sink found", name),
                        url: None,
                    });
                }
            }
        }

        // Check script tags for suspicious content
        for script in document.scripts() {
            let content = script.text_content();
            if self.is_suspicious_script(&content) {
                self.triggers.write().push(XssTrigger {
                    trigger_type: XssTriggerType::ScriptInjection,
                    payload: content.chars().take(200).collect(),
                    context: "Suspicious inline script".to_string(),
                    url: None,
                });
            }
        }
    }

    /// Check if script content is suspicious
    fn is_suspicious_script(&self, content: &str) -> bool {
        // Check for unencoded user input indicators
        let suspicious = [
            "{{",          // Template injection
            "${",          // Template literal injection
            "<%",          // Server-side template
            "?>",          // PHP
            "document.URL",
            "document.documentURI",
            "document.location",
            "document.referrer",
            "window.name",
            "location.hash",
            "location.search",
            "location.href",
        ];

        suspicious.iter().any(|s| content.contains(s))
    }

    /// Execute inline scripts from document
    fn execute_scripts(&self, document: &Document) {
        let scripts: Vec<_> = document
            .scripts()
            .into_iter()
            .filter(|s| s.src().is_none()) // Only inline scripts
            .take(self.config.max_scripts)
            .collect();

        for script in scripts {
            let content = script.text_content();
            if !content.trim().is_empty() {
                // Execute and capture any XSS triggers
                let _ = self.js_runtime.execute(&content);
            }
        }
    }

    /// Get all detected triggers
    pub fn get_triggers(&self) -> Vec<XssTrigger> {
        let mut triggers = self.triggers.read().clone();
        triggers.extend(self.js_runtime.get_xss_triggers());
        triggers
    }

    /// Clear all triggers
    pub fn clear_triggers(&self) {
        self.triggers.write().clear();
        self.js_runtime.clear_xss_triggers();
    }

    /// Test a specific payload
    pub fn test_payload(&self, payload: &str) -> Vec<XssTrigger> {
        self.js_runtime.clear_xss_triggers();
        let _ = self.js_runtime.execute(payload);
        self.js_runtime.get_xss_triggers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::parse_html;

    #[test]
    fn test_event_handler_detection() {
        let html = r#"<div onclick="alert('xss')">Click me</div>"#;
        let doc = parse_html(html).unwrap();
        let detector = XssDetector::default_detector();

        let result = detector.analyze(&doc, None);
        assert!(!result.triggers.is_empty());
    }

    #[test]
    fn test_script_execution() {
        let html = r#"<script>alert('xss')</script>"#;
        let doc = parse_html(html).unwrap();
        let detector = XssDetector::default_detector();

        let result = detector.analyze(&doc, None);
        assert!(result.is_vulnerable());
    }

    #[test]
    fn test_reflection_check() {
        let detector = XssDetector::default_detector();
        let html = r#"<div>User input: <script>alert(1)</script></div>"#;
        let payload = "<script>alert(1)</script>";

        assert!(detector.check_reflection(html, payload));
    }
}
