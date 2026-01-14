// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Framework-specific detection helpers
//!
//! Detects and analyzes Vue, React, Angular, and other frameworks
//! for security-relevant patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Framework detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkInfo {
    /// Detected framework
    pub framework: Framework,
    /// Version if detected
    pub version: Option<String>,
    /// XSS sinks specific to this framework
    pub sinks: Vec<FrameworkSink>,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

/// Detected framework
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Framework {
    Vue,
    React,
    Angular,
    AngularJs,
    Svelte,
    jQuery,
    Ember,
    Backbone,
    Knockout,
    Unknown,
}

/// Framework-specific XSS sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSink {
    /// Sink name
    pub name: String,
    /// Element selector or pattern
    pub pattern: String,
    /// Risk level (1-10)
    pub risk: u8,
    /// Description
    pub description: String,
}

/// Vue.js detector
pub struct VueDetector {
    version_regex: Regex,
    v_html_regex: Regex,
    template_regex: Regex,
}

impl Default for VueDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VueDetector {
    pub fn new() -> Self {
        Self {
            version_regex: Regex::new(r#"Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)["']"#).unwrap(),
            v_html_regex: Regex::new(r#"v-html\s*=\s*["']([^"']+)["']"#).unwrap(),
            template_regex: Regex::new(r#"\{\{\s*([^}]+)\s*\}\}"#).unwrap(),
        }
    }

    /// Detect Vue.js in HTML/JS
    pub fn detect(&self, html: &str, scripts: &[String]) -> Option<FrameworkInfo> {
        // Check for Vue presence
        let is_vue = html.contains("v-")
            || html.contains("Vue")
            || scripts.iter().any(|s| s.contains("Vue") || s.contains("createApp"));

        if !is_vue {
            return None;
        }

        let mut info = FrameworkInfo {
            framework: Framework::Vue,
            version: None,
            sinks: Vec::new(),
            recommendations: Vec::new(),
        };

        // Detect version
        for script in scripts {
            if let Some(cap) = self.version_regex.captures(script) {
                info.version = Some(cap[1].to_string());
                break;
            }
        }

        // Find v-html sinks
        for cap in self.v_html_regex.captures_iter(html) {
            info.sinks.push(FrameworkSink {
                name: "v-html".to_string(),
                pattern: cap[0].to_string(),
                risk: 9,
                description: format!("v-html with dynamic content: {}", &cap[1]),
            });
        }

        // Find template interpolations with dangerous patterns
        for cap in self.template_regex.captures_iter(html) {
            let content = &cap[1];
            if content.contains("html") || content.contains("raw") || content.contains("$") {
                info.sinks.push(FrameworkSink {
                    name: "template".to_string(),
                    pattern: cap[0].to_string(),
                    risk: 5,
                    description: format!("Template with potentially unsafe content: {}", content),
                });
            }
        }

        if !info.sinks.is_empty() {
            info.recommendations.push("Review v-html usage - consider v-text instead".to_string());
            info.recommendations.push("Sanitize all dynamic HTML content".to_string());
        }

        Some(info)
    }
}

/// React detector
pub struct ReactDetector {
    version_regex: Regex,
    dangerous_html_regex: Regex,
}

impl Default for ReactDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ReactDetector {
    pub fn new() -> Self {
        Self {
            version_regex: Regex::new(r#"React\.version\s*=\s*["'](\d+\.\d+\.\d+)["']"#).unwrap(),
            dangerous_html_regex: Regex::new(r#"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\s*\}"#).unwrap(),
        }
    }

    /// Detect React in HTML/JS
    pub fn detect(&self, html: &str, scripts: &[String]) -> Option<FrameworkInfo> {
        let is_react = html.contains("data-reactroot")
            || html.contains("_reactRootContainer")
            || scripts.iter().any(|s| s.contains("React") || s.contains("ReactDOM"));

        if !is_react {
            return None;
        }

        let mut info = FrameworkInfo {
            framework: Framework::React,
            version: None,
            sinks: Vec::new(),
            recommendations: Vec::new(),
        };

        // Detect version
        for script in scripts {
            if let Some(cap) = self.version_regex.captures(script) {
                info.version = Some(cap[1].to_string());
                break;
            }
        }

        // Find dangerouslySetInnerHTML
        for script in scripts {
            for cap in self.dangerous_html_regex.captures_iter(script) {
                info.sinks.push(FrameworkSink {
                    name: "dangerouslySetInnerHTML".to_string(),
                    pattern: cap[0].to_string(),
                    risk: 9,
                    description: format!("dangerouslySetInnerHTML with: {}", &cap[1]),
                });
            }
        }

        if !info.sinks.is_empty() {
            info.recommendations.push("Avoid dangerouslySetInnerHTML - sanitize with DOMPurify".to_string());
        }

        Some(info)
    }
}

/// Angular detector
pub struct AngularDetector {
    ng_bind_html_regex: Regex,
    ng_template_regex: Regex,
    version_regex: Regex,
}

impl Default for AngularDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AngularDetector {
    pub fn new() -> Self {
        Self {
            ng_bind_html_regex: Regex::new(r#"\[innerHTML\]\s*=\s*["']([^"']+)["']"#).unwrap(),
            ng_template_regex: Regex::new(r#"\{\{\s*([^}]+)\s*\}\}"#).unwrap(),
            version_regex: Regex::new(r#"@angular/core.*?(\d+\.\d+\.\d+)"#).unwrap(),
        }
    }

    /// Detect Angular in HTML/JS
    pub fn detect(&self, html: &str, scripts: &[String]) -> Option<FrameworkInfo> {
        let is_angular = html.contains("ng-")
            || html.contains("_nghost")
            || html.contains("_ngcontent")
            || scripts.iter().any(|s| s.contains("@angular") || s.contains("platformBrowserDynamic"));

        let is_angularjs = html.contains("ng-app") || scripts.iter().any(|s| s.contains("angular.module"));

        if !is_angular && !is_angularjs {
            return None;
        }

        let framework = if is_angularjs { Framework::AngularJs } else { Framework::Angular };

        let mut info = FrameworkInfo {
            framework,
            version: None,
            sinks: Vec::new(),
            recommendations: Vec::new(),
        };

        // Find innerHTML bindings
        for cap in self.ng_bind_html_regex.captures_iter(html) {
            info.sinks.push(FrameworkSink {
                name: "[innerHTML]".to_string(),
                pattern: cap[0].to_string(),
                risk: 9,
                description: format!("innerHTML binding with: {}", &cap[1]),
            });
        }

        // AngularJS specific - ng-bind-html
        if is_angularjs {
            let ng_bind_html = Regex::new(r#"ng-bind-html\s*=\s*["']([^"']+)["']"#).unwrap();
            for cap in ng_bind_html.captures_iter(html) {
                info.sinks.push(FrameworkSink {
                    name: "ng-bind-html".to_string(),
                    pattern: cap[0].to_string(),
                    risk: 9,
                    description: format!("ng-bind-html with: {}", &cap[1]),
                });
            }

            info.recommendations.push("AngularJS is deprecated - consider migrating to Angular".to_string());
            info.recommendations.push("Use $sce.trustAsHtml carefully".to_string());
        }

        if !info.sinks.is_empty() {
            info.recommendations.push("Use Angular's built-in sanitizer for HTML content".to_string());
        }

        Some(info)
    }

    /// Find potential template injection (AngularJS)
    pub fn find_template_injection(&self, html: &str) -> Vec<String> {
        let mut injections = Vec::new();

        // Look for user input in templates
        let injection_patterns = [
            r#"\{\{\s*\$\w+\s*\}\}"#,  // {{$scope.var}}
            r#"\{\{.*constructor.*\}\}"#,  // constructor access
            r#"\{\{.*\[.*\].*\}\}"#,  // bracket notation
        ];

        for pattern in &injection_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(html) {
                injections.push(mat.as_str().to_string());
            }
        }

        injections
    }
}

/// Combined framework detector
pub struct FrameworkDetector {
    vue: VueDetector,
    react: ReactDetector,
    angular: AngularDetector,
}

impl Default for FrameworkDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkDetector {
    pub fn new() -> Self {
        Self {
            vue: VueDetector::new(),
            react: ReactDetector::new(),
            angular: AngularDetector::new(),
        }
    }

    /// Detect all frameworks
    pub fn detect_all(&self, html: &str, scripts: &[String]) -> Vec<FrameworkInfo> {
        let mut results = Vec::new();

        if let Some(vue) = self.vue.detect(html, scripts) {
            results.push(vue);
        }

        if let Some(react) = self.react.detect(html, scripts) {
            results.push(react);
        }

        if let Some(angular) = self.angular.detect(html, scripts) {
            results.push(angular);
        }

        // Check for jQuery
        if scripts.iter().any(|s| s.contains("jQuery") || s.contains("$.")) {
            results.push(FrameworkInfo {
                framework: Framework::jQuery,
                version: None,
                sinks: Vec::new(),
                recommendations: vec!["Check for .html() calls with user input".to_string()],
            });
        }

        results
    }

    /// Get all XSS sinks from detected frameworks
    pub fn all_sinks(&self, html: &str, scripts: &[String]) -> Vec<FrameworkSink> {
        self.detect_all(html, scripts)
            .into_iter()
            .flat_map(|f| f.sinks)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vue_detection() {
        let detector = VueDetector::new();
        let html = r#"<div v-html="userInput"></div>"#;
        let result = detector.detect(html, &[]);

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.framework, Framework::Vue);
        assert!(!info.sinks.is_empty());
    }

    #[test]
    fn test_react_detection() {
        let detector = ReactDetector::new();
        let html = r#"<div data-reactroot></div>"#;
        let scripts = vec!["dangerouslySetInnerHTML={{ __html: userInput }}".to_string()];
        let result = detector.detect(html, &scripts);

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.framework, Framework::React);
    }

    #[test]
    fn test_angular_detection() {
        let detector = AngularDetector::new();
        let html = r#"<div [innerHTML]="userContent"></div>"#;
        let result = detector.detect(html, &[]);

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.framework, Framework::Angular);
    }
}
