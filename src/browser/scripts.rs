// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Script source extraction for SPA route detection
//!
//! Exposes raw JavaScript source for static analysis:
//! - Vue/React/Angular route detection
//! - GraphQL endpoint discovery
//! - API URL extraction
//! - WebSocket endpoint discovery

use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Script source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSource {
    /// Script URL (or "inline" for inline scripts)
    pub url: String,
    /// Script content
    pub content: String,
    /// Whether this is an inline script
    pub is_inline: bool,
    /// Script type attribute
    pub script_type: Option<String>,
    /// Whether script has async attribute
    pub is_async: bool,
    /// Whether script has defer attribute
    pub is_defer: bool,
    /// Nonce value (for CSP)
    pub nonce: Option<String>,
}

/// Discovered routes from SPA analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaRoute {
    /// Route path
    pub path: String,
    /// Whether route requires authentication
    pub requires_auth: bool,
    /// Route name (if available)
    pub name: Option<String>,
    /// Component name (if available)
    pub component: Option<String>,
    /// Source framework
    pub framework: SpaFramework,
}

/// SPA framework type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaFramework {
    Vue,
    React,
    Angular,
    Svelte,
    Unknown,
}

/// Discovered WebSocket endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketEndpoint {
    /// WebSocket URL
    pub url: String,
    /// How it was discovered
    pub discovery_method: WebSocketDiscoveryMethod,
    /// Protocol (if specified)
    pub protocols: Vec<String>,
}

/// How a WebSocket endpoint was discovered
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketDiscoveryMethod {
    /// new WebSocket() constructor in JS
    Constructor,
    /// URL in configuration object
    ConfigUrl,
    /// Socket.io initialization
    SocketIo,
    /// Observed network request
    NetworkObserved,
}

/// Script analyzer for SPA route and endpoint discovery
pub struct ScriptAnalyzer {
    /// Vue route patterns
    vue_route_regex: Regex,
    vue_auth_regex: Regex,
    /// React route patterns
    react_route_regex: Regex,
    /// Angular route patterns
    angular_route_regex: Regex,
    /// WebSocket patterns
    ws_constructor_regex: Regex,
    ws_url_regex: Regex,
    socket_io_regex: Regex,
    /// API endpoint patterns
    api_url_regex: Regex,
    graphql_regex: Regex,
}

impl Default for ScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptAnalyzer {
    /// Create a new script analyzer
    pub fn new() -> Self {
        Self {
            // Vue.js routes
            vue_route_regex: Regex::new(
                r#"path:\s*["']([^"']+)["']"#
            ).unwrap(),
            vue_auth_regex: Regex::new(
                r#"path:\s*["']([^"']+)["'][^}]*(?:requireAuth|meta:\s*\{[^}]*auth)"#
            ).unwrap(),
            // React routes
            react_route_regex: Regex::new(
                r#"<Route[^>]*path=["']([^"']+)["']"#
            ).unwrap(),
            // Angular routes
            angular_route_regex: Regex::new(
                r#"\{\s*path:\s*["']([^"']+)["']"#
            ).unwrap(),
            // WebSocket patterns
            ws_constructor_regex: Regex::new(
                r#"new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]"#
            ).unwrap(),
            ws_url_regex: Regex::new(
                r#"wss?://[^\s"'`<>]+"#
            ).unwrap(),
            socket_io_regex: Regex::new(
                r#"io\s*\(\s*["'`]([^"'`]+)["'`]"#
            ).unwrap(),
            // API patterns
            api_url_regex: Regex::new(
                r#"["'`](https?://[^"'`\s]+(?:/api/|/v\d+/|/graphql)[^"'`\s]*)["'`]"#
            ).unwrap(),
            graphql_regex: Regex::new(
                r#"["'`]([^"'`\s]*/graphql[^"'`\s]*)["'`]"#
            ).unwrap(),
        }
    }

    /// Analyze script for SPA routes
    pub fn find_routes(&self, script: &ScriptSource) -> Vec<SpaRoute> {
        let mut routes = Vec::new();
        let content = &script.content;

        // Detect framework
        let framework = self.detect_framework(content);

        // Extract routes based on framework
        match framework {
            SpaFramework::Vue => {
                // Extract auth routes first
                let auth_routes: HashSet<String> = self.vue_auth_regex
                    .captures_iter(content)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .collect();

                // Extract all routes
                for cap in self.vue_route_regex.captures_iter(content) {
                    if let Some(path) = cap.get(1) {
                        let path_str = path.as_str().to_string();
                        routes.push(SpaRoute {
                            path: path_str.clone(),
                            requires_auth: auth_routes.contains(&path_str),
                            name: None,
                            component: None,
                            framework: SpaFramework::Vue,
                        });
                    }
                }
            }
            SpaFramework::React => {
                for cap in self.react_route_regex.captures_iter(content) {
                    if let Some(path) = cap.get(1) {
                        routes.push(SpaRoute {
                            path: path.as_str().to_string(),
                            requires_auth: false, // Would need more context
                            name: None,
                            component: None,
                            framework: SpaFramework::React,
                        });
                    }
                }
            }
            SpaFramework::Angular => {
                for cap in self.angular_route_regex.captures_iter(content) {
                    if let Some(path) = cap.get(1) {
                        routes.push(SpaRoute {
                            path: path.as_str().to_string(),
                            requires_auth: content.contains("canActivate"),
                            name: None,
                            component: None,
                            framework: SpaFramework::Angular,
                        });
                    }
                }
            }
            _ => {
                // Try all patterns for unknown frameworks
                for cap in self.vue_route_regex.captures_iter(content) {
                    if let Some(path) = cap.get(1) {
                        routes.push(SpaRoute {
                            path: path.as_str().to_string(),
                            requires_auth: false,
                            name: None,
                            component: None,
                            framework: SpaFramework::Unknown,
                        });
                    }
                }
            }
        }

        routes
    }

    /// Find WebSocket endpoints in script
    pub fn find_websocket_endpoints(&self, script: &ScriptSource) -> Vec<WebSocketEndpoint> {
        let mut endpoints = Vec::new();
        let content = &script.content;

        // Find new WebSocket() constructors
        for cap in self.ws_constructor_regex.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                endpoints.push(WebSocketEndpoint {
                    url: url.as_str().to_string(),
                    discovery_method: WebSocketDiscoveryMethod::Constructor,
                    protocols: Vec::new(),
                });
            }
        }

        // Find socket.io connections
        for cap in self.socket_io_regex.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                endpoints.push(WebSocketEndpoint {
                    url: url.as_str().to_string(),
                    discovery_method: WebSocketDiscoveryMethod::SocketIo,
                    protocols: Vec::new(),
                });
            }
        }

        // Find ws:// or wss:// URLs
        for mat in self.ws_url_regex.find_iter(content) {
            let url = mat.as_str().to_string();
            // Avoid duplicates
            if !endpoints.iter().any(|e| e.url == url) {
                endpoints.push(WebSocketEndpoint {
                    url,
                    discovery_method: WebSocketDiscoveryMethod::ConfigUrl,
                    protocols: Vec::new(),
                });
            }
        }

        endpoints
    }

    /// Find API endpoints in script
    pub fn find_api_endpoints(&self, script: &ScriptSource) -> Vec<String> {
        let mut endpoints = HashSet::new();
        let content = &script.content;

        for cap in self.api_url_regex.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                endpoints.insert(url.as_str().to_string());
            }
        }

        for cap in self.graphql_regex.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                endpoints.insert(url.as_str().to_string());
            }
        }

        endpoints.into_iter().collect()
    }

    /// Detect SPA framework from script content
    pub fn detect_framework(&self, content: &str) -> SpaFramework {
        // Vue.js indicators
        if content.contains("Vue.")
            || content.contains("createApp")
            || content.contains("VueRouter")
            || content.contains("$route")
        {
            return SpaFramework::Vue;
        }

        // React indicators
        if content.contains("React.")
            || content.contains("ReactDOM")
            || content.contains("createElement")
            || content.contains("useEffect")
            || content.contains("useState")
        {
            return SpaFramework::React;
        }

        // Angular indicators
        if content.contains("@angular")
            || content.contains("NgModule")
            || content.contains("platformBrowserDynamic")
        {
            return SpaFramework::Angular;
        }

        // Svelte indicators
        if content.contains("svelte") || content.contains("SvelteComponent") {
            return SpaFramework::Svelte;
        }

        SpaFramework::Unknown
    }

    /// Analyze all scripts and return combined results
    pub fn analyze_all(&self, scripts: &[ScriptSource]) -> ScriptAnalysisResult {
        let mut result = ScriptAnalysisResult::default();

        for script in scripts {
            result.routes.extend(self.find_routes(script));
            result.websocket_endpoints.extend(self.find_websocket_endpoints(script));
            result.api_endpoints.extend(self.find_api_endpoints(script));
        }

        // Deduplicate
        result.routes.sort_by(|a, b| a.path.cmp(&b.path));
        result.routes.dedup_by(|a, b| a.path == b.path);

        result.websocket_endpoints.sort_by(|a, b| a.url.cmp(&b.url));
        result.websocket_endpoints.dedup_by(|a, b| a.url == b.url);

        result.api_endpoints.sort();
        result.api_endpoints.dedup();

        result
    }
}

/// Combined analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptAnalysisResult {
    /// Discovered SPA routes
    pub routes: Vec<SpaRoute>,
    /// Discovered WebSocket endpoints
    pub websocket_endpoints: Vec<WebSocketEndpoint>,
    /// Discovered API endpoints
    pub api_endpoints: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vue_route_detection() {
        let analyzer = ScriptAnalyzer::new();
        let script = ScriptSource {
            url: "app.js".to_string(),
            content: r#"
                const routes = [
                    { path: '/login', component: Login },
                    { path: '/dashboard', component: Dashboard, meta: { auth: true } },
                    { path: '/admin', component: Admin, requireAuth: true }
                ]
            "#.to_string(),
            is_inline: false,
            script_type: None,
            is_async: false,
            is_defer: false,
            nonce: None,
        };

        let routes = analyzer.find_routes(&script);
        assert!(routes.iter().any(|r| r.path == "/login"));
        assert!(routes.iter().any(|r| r.path == "/dashboard"));
    }

    #[test]
    fn test_websocket_detection() {
        let analyzer = ScriptAnalyzer::new();
        let script = ScriptSource {
            url: "app.js".to_string(),
            content: r#"
                const socket = new WebSocket("wss://api.example.com/ws");
                const io = io("wss://chat.example.com");
            "#.to_string(),
            is_inline: false,
            script_type: None,
            is_async: false,
            is_defer: false,
            nonce: None,
        };

        let endpoints = analyzer.find_websocket_endpoints(&script);
        assert!(endpoints.iter().any(|e| e.url.contains("api.example.com")));
    }

    #[test]
    fn test_api_endpoint_detection() {
        let analyzer = ScriptAnalyzer::new();
        let script = ScriptSource {
            url: "app.js".to_string(),
            content: r#"
                fetch("https://api.example.com/v1/users");
                const graphql = "https://example.com/graphql";
            "#.to_string(),
            is_inline: false,
            script_type: None,
            is_async: false,
            is_defer: false,
            nonce: None,
        };

        let endpoints = analyzer.find_api_endpoints(&script);
        assert!(!endpoints.is_empty());
    }
}
