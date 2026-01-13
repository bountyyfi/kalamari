// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Iframe handling and recursive frame processing
//!
//! Handles iframe content loading and XSS hook injection.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use url::Url;

use crate::dom::{Document, Element};
use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::js::JsRuntime;
use crate::xss::XssTrigger;

/// Frame information
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame ID
    pub id: String,
    /// Frame URL
    pub url: Option<Url>,
    /// Frame name
    pub name: Option<String>,
    /// Frame source attribute
    pub src: Option<String>,
    /// Whether this is the main frame
    pub is_main: bool,
    /// Parent frame ID
    pub parent_id: Option<String>,
    /// Child frame IDs
    pub child_ids: Vec<String>,
    /// Frame document (if loaded)
    pub document: Option<Document>,
}

impl Frame {
    /// Create a main frame
    pub fn main(url: Url) -> Self {
        Self {
            id: "main".to_string(),
            url: Some(url),
            name: None,
            src: None,
            is_main: true,
            parent_id: None,
            child_ids: Vec::new(),
            document: None,
        }
    }

    /// Create a child frame
    pub fn child(id: impl Into<String>, src: Option<String>, parent_id: &str) -> Self {
        Self {
            id: id.into(),
            url: None,
            name: None,
            src,
            is_main: false,
            parent_id: Some(parent_id.to_string()),
            child_ids: Vec::new(),
            document: None,
        }
    }
}

/// Frame tree - manages all frames in a page
pub struct FrameTree {
    /// All frames by ID
    frames: HashMap<String, Frame>,
    /// Main frame ID
    main_frame_id: String,
    /// Frame counter for ID generation
    frame_counter: u64,
}

impl Default for FrameTree {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameTree {
    /// Create a new frame tree
    pub fn new() -> Self {
        Self {
            frames: HashMap::new(),
            main_frame_id: "main".to_string(),
            frame_counter: 0,
        }
    }

    /// Set the main frame
    pub fn set_main_frame(&mut self, url: Url, document: Document) {
        let mut frame = Frame::main(url);
        frame.document = Some(document);
        self.frames.insert("main".to_string(), frame);
    }

    /// Get main frame
    pub fn main_frame(&self) -> Option<&Frame> {
        self.frames.get(&self.main_frame_id)
    }

    /// Get main frame mutable
    pub fn main_frame_mut(&mut self) -> Option<&mut Frame> {
        self.frames.get_mut(&self.main_frame_id)
    }

    /// Add a child frame
    pub fn add_frame(&mut self, parent_id: &str, src: Option<String>) -> String {
        self.frame_counter += 1;
        let frame_id = format!("frame_{}", self.frame_counter);

        let frame = Frame::child(&frame_id, src, parent_id);
        self.frames.insert(frame_id.clone(), frame);

        // Add to parent's child list
        if let Some(parent) = self.frames.get_mut(parent_id) {
            parent.child_ids.push(frame_id.clone());
        }

        frame_id
    }

    /// Get a frame by ID
    pub fn get_frame(&self, id: &str) -> Option<&Frame> {
        self.frames.get(id)
    }

    /// Get a frame by ID (mutable)
    pub fn get_frame_mut(&mut self, id: &str) -> Option<&mut Frame> {
        self.frames.get_mut(id)
    }

    /// Get all frames
    pub fn all_frames(&self) -> Vec<&Frame> {
        self.frames.values().collect()
    }

    /// Get frame count
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

/// Frame handler - loads and processes iframes
pub struct FrameHandler {
    /// HTTP client for loading frame content
    client: HttpClient,
    /// Maximum depth to recurse
    max_depth: u32,
    /// XSS triggers from all frames
    xss_triggers: Arc<RwLock<Vec<XssTrigger>>>,
    /// Whether to execute JS in frames
    execute_js: bool,
}

impl FrameHandler {
    /// Create a new frame handler
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            max_depth: 3,
            xss_triggers: Arc::new(RwLock::new(Vec::new())),
            execute_js: true,
        }
    }

    /// Set max depth
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set JS execution
    pub fn execute_js(mut self, execute: bool) -> Self {
        self.execute_js = execute;
        self
    }

    /// Process a document and all its iframes
    pub async fn process_frames(
        &self,
        frame_tree: &mut FrameTree,
        base_url: &Url,
    ) -> Result<()> {
        self.process_frame_recursive(frame_tree, "main", base_url, 0)
            .await
    }

    /// Recursively process frames
    async fn process_frame_recursive(
        &self,
        frame_tree: &mut FrameTree,
        frame_id: &str,
        base_url: &Url,
        depth: u32,
    ) -> Result<()> {
        if depth > self.max_depth {
            return Ok(());
        }

        // Get iframe elements from this frame's document
        let iframe_elements: Vec<(Option<String>, Option<String>)> = {
            let frame = frame_tree.get_frame(frame_id);
            if let Some(frame) = frame {
                if let Some(ref doc) = frame.document {
                    doc.query_selector_all("iframe, frame")
                        .iter()
                        .map(|e| (e.src(), e.get_attribute("name")))
                        .collect()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        // Process each iframe
        for (src, name) in iframe_elements {
            let child_id = frame_tree.add_frame(frame_id, src.clone());

            // Set name if present
            if let Some(name) = name {
                if let Some(child) = frame_tree.get_frame_mut(&child_id) {
                    child.name = Some(name);
                }
            }

            // Load iframe content if src is present
            if let Some(src) = src {
                if let Ok(iframe_url) = self.resolve_url(&src, base_url) {
                    if self.should_load_frame(&iframe_url) {
                        if let Ok(doc) = self.load_frame_content(&iframe_url).await {
                            if let Some(child) = frame_tree.get_frame_mut(&child_id) {
                                child.url = Some(iframe_url.clone());
                                child.document = Some(doc);
                            }

                            // Execute JS in frame if enabled
                            if self.execute_js {
                                self.inject_xss_hooks(&child_id, frame_tree);
                            }

                            // Recurse into this frame
                            Box::pin(self.process_frame_recursive(
                                frame_tree,
                                &child_id,
                                &iframe_url,
                                depth + 1,
                            ))
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load frame content
    async fn load_frame_content(&self, url: &Url) -> Result<Document> {
        let response = self.client.get(url.as_str()).await?;

        if !response.is_html() {
            return Err(Error::Navigation("Frame content is not HTML".into()));
        }

        let html = response.text_lossy();
        crate::dom::parse_html_with_url(&html, Some(url.clone()))
    }

    /// Resolve URL relative to base
    fn resolve_url(&self, src: &str, base: &Url) -> Result<Url> {
        // Skip data: and javascript: URLs
        if src.starts_with("data:") || src.starts_with("javascript:") {
            return Err(Error::Navigation("Skipping non-http URL".into()));
        }

        if src.starts_with("http://") || src.starts_with("https://") {
            Url::parse(src).map_err(|e| Error::Navigation(e.to_string()))
        } else {
            base.join(src).map_err(|e| Error::Navigation(e.to_string()))
        }
    }

    /// Check if frame should be loaded (same-origin, etc.)
    fn should_load_frame(&self, url: &Url) -> bool {
        // Load all HTTP/HTTPS frames
        url.scheme() == "http" || url.scheme() == "https"
    }

    /// Inject XSS detection hooks into a frame
    fn inject_xss_hooks(&self, frame_id: &str, frame_tree: &FrameTree) {
        let frame = match frame_tree.get_frame(frame_id) {
            Some(f) => f,
            None => return,
        };

        let doc = match &frame.document {
            Some(d) => d,
            None => return,
        };

        // Create JS runtime for this frame
        let runtime = JsRuntime::default_runtime();
        if let Some(ref url) = frame.url {
            runtime.set_url(url.to_string());
        }

        // Execute inline scripts
        for script in doc.scripts() {
            if script.src().is_none() {
                let content = script.text_content();
                if !content.trim().is_empty() {
                    let _ = runtime.execute(&content);
                }
            }
        }

        // Collect triggers
        self.xss_triggers.write().extend(runtime.get_xss_triggers());
    }

    /// Get all XSS triggers from all frames
    pub fn get_xss_triggers(&self) -> Vec<XssTrigger> {
        self.xss_triggers.read().clone()
    }

    /// Clear XSS triggers
    pub fn clear_xss_triggers(&self) {
        self.xss_triggers.write().clear();
    }
}

/// XSS hook injection script - to be executed in each frame context
pub const XSS_HOOK_SCRIPT: &str = r#"
(function() {
    // Store original functions
    var origAlert = window.alert;
    var origConfirm = window.confirm;
    var origPrompt = window.prompt;
    var origEval = window.eval;
    var origFunction = window.Function;
    var origSetTimeout = window.setTimeout;
    var origSetInterval = window.setInterval;

    // Hook alert
    window.alert = function(msg) {
        window.__xss_triggered__ = { type: 'alert', payload: msg };
        return origAlert ? origAlert.apply(this, arguments) : undefined;
    };

    // Hook confirm
    window.confirm = function(msg) {
        window.__xss_triggered__ = { type: 'confirm', payload: msg };
        return false;
    };

    // Hook prompt
    window.prompt = function(msg) {
        window.__xss_triggered__ = { type: 'prompt', payload: msg };
        return null;
    };

    // Hook eval
    window.eval = function(code) {
        if (typeof code === 'string' &&
            (code.indexOf('alert') !== -1 ||
             code.indexOf('document.cookie') !== -1)) {
            window.__xss_triggered__ = { type: 'eval', payload: code };
        }
        return origEval.apply(this, arguments);
    };

    // Hook Function constructor
    window.Function = function() {
        var code = Array.prototype.slice.call(arguments).join(' ');
        if (code.indexOf('alert') !== -1 ||
            code.indexOf('document.cookie') !== -1) {
            window.__xss_triggered__ = { type: 'function', payload: code };
        }
        return origFunction.apply(this, arguments);
    };

    // Hook innerHTML setter
    var originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (typeof value === 'string' &&
                    (value.indexOf('<script') !== -1 ||
                     value.indexOf('onerror') !== -1 ||
                     value.indexOf('onload') !== -1)) {
                    window.__xss_triggered__ = { type: 'innerHTML', payload: value };
                }
                return originalInnerHTMLDescriptor.set.call(this, value);
            },
            get: originalInnerHTMLDescriptor.get,
            configurable: true
        });
    }

    // Hook document.write
    var origWrite = document.write;
    document.write = function(html) {
        if (typeof html === 'string' &&
            (html.indexOf('<script') !== -1 ||
             html.indexOf('onerror') !== -1)) {
            window.__xss_triggered__ = { type: 'document.write', payload: html };
        }
        return origWrite.apply(this, arguments);
    };

    // Inject into iframes
    function injectIntoFrame(frame) {
        try {
            if (frame.contentWindow && frame.contentWindow.alert !== window.alert) {
                frame.contentWindow.alert = window.alert;
                frame.contentWindow.confirm = window.confirm;
                frame.contentWindow.prompt = window.prompt;
                frame.contentWindow.eval = window.eval;
            }
        } catch(e) {
            // Cross-origin frame - can't inject
        }
    }

    // Watch for new iframes
    var observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            mutation.addedNodes.forEach(function(node) {
                if (node.tagName === 'IFRAME') {
                    node.addEventListener('load', function() {
                        injectIntoFrame(node);
                    });
                }
            });
        });
    });

    if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
    }

    // Inject into existing iframes
    var frames = document.getElementsByTagName('iframe');
    for (var i = 0; i < frames.length; i++) {
        injectIntoFrame(frames[i]);
    }
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_tree() {
        let mut tree = FrameTree::new();
        let url = Url::parse("https://example.com").unwrap();
        tree.set_main_frame(url, crate::dom::Document::new());

        assert!(tree.main_frame().is_some());
        assert_eq!(tree.frame_count(), 1);

        let child_id = tree.add_frame("main", Some("/child.html".to_string()));
        assert_eq!(tree.frame_count(), 2);
        assert!(tree.get_frame(&child_id).is_some());
    }
}
