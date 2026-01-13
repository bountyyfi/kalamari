// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Document representation

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use url::Url;

use super::element::Element;
use super::node::{Node, NodeData, NodeId, NodeType};
use super::selector::Selector;

/// HTML Document representation
#[derive(Debug, Clone)]
pub struct Document {
    /// Document URL
    pub url: Option<Url>,
    /// Document title
    title: Arc<RwLock<String>>,
    /// Root node ID
    root_id: NodeId,
    /// Node storage
    pub(crate) nodes: Arc<RwLock<HashMap<NodeId, NodeData>>>,
    /// Document element (<html>) ID
    document_element_id: Option<NodeId>,
    /// Head element ID
    head_id: Option<NodeId>,
    /// Body element ID
    body_id: Option<NodeId>,
}

impl Document {
    /// Create a new empty document
    pub fn new() -> Self {
        let root_id = NodeId::new();
        let mut nodes = HashMap::new();
        nodes.insert(root_id, NodeData::document());

        Self {
            url: None,
            title: Arc::new(RwLock::new(String::new())),
            root_id,
            nodes: Arc::new(RwLock::new(nodes)),
            document_element_id: None,
            head_id: None,
            body_id: None,
        }
    }

    /// Create a document with URL
    pub fn with_url(url: Url) -> Self {
        let mut doc = Self::new();
        doc.url = Some(url);
        doc
    }

    /// Get document URL as string
    pub fn url_string(&self) -> Option<String> {
        self.url.as_ref().map(|u| u.to_string())
    }

    /// Get document title
    pub fn title(&self) -> String {
        self.title.read().clone()
    }

    /// Set document title
    pub fn set_title(&self, title: impl Into<String>) {
        *self.title.write() = title.into();
    }

    /// Get the document element (<html>)
    pub fn document_element(&self) -> Option<Element> {
        self.document_element_id
            .and_then(|id| Element::from_id(id, self.nodes.clone()))
    }

    /// Get the <head> element
    pub fn head(&self) -> Option<Element> {
        self.head_id
            .and_then(|id| Element::from_id(id, self.nodes.clone()))
    }

    /// Get the <body> element
    pub fn body(&self) -> Option<Element> {
        self.body_id
            .and_then(|id| Element::from_id(id, self.nodes.clone()))
    }

    /// Set document element IDs (called during parsing)
    pub(crate) fn set_elements(
        &mut self,
        document_element: Option<NodeId>,
        head: Option<NodeId>,
        body: Option<NodeId>,
    ) {
        self.document_element_id = document_element;
        self.head_id = head;
        self.body_id = body;
    }

    /// Get the root node
    pub fn root(&self) -> Node {
        Node::new(self.root_id, self.nodes.clone())
    }

    /// Query selector - find first matching element
    pub fn query_selector(&self, selector: &str) -> Option<Element> {
        let sel = Selector::parse(selector).ok()?;
        self.find_matching(&sel, false).into_iter().next()
    }

    /// Query selector all - find all matching elements
    pub fn query_selector_all(&self, selector: &str) -> Vec<Element> {
        Selector::parse(selector)
            .map(|sel| self.find_matching(&sel, true))
            .unwrap_or_default()
    }

    /// Find matching elements
    fn find_matching(&self, selector: &Selector, find_all: bool) -> Vec<Element> {
        let mut results = Vec::new();
        let nodes = self.nodes.read();

        // Start from document element children
        if let Some(root_data) = nodes.get(&self.root_id) {
            for &child_id in &root_data.children {
                self.find_in_subtree(&nodes, child_id, selector, &mut results, find_all);
                if !find_all && !results.is_empty() {
                    break;
                }
            }
        }

        results
    }

    /// Recursively find matching elements in subtree
    fn find_in_subtree(
        &self,
        nodes: &HashMap<NodeId, NodeData>,
        node_id: NodeId,
        selector: &Selector,
        results: &mut Vec<Element>,
        find_all: bool,
    ) {
        if let Some(node_data) = nodes.get(&node_id) {
            if node_data.node_type == NodeType::Element {
                let node = Node::new(node_id, self.nodes.clone());
                if selector.matches(&node) {
                    if let Some(elem) = Element::from_id(node_id, self.nodes.clone()) {
                        results.push(elem);
                        if !find_all {
                            return;
                        }
                    }
                }
            }

            // Search children
            for &child_id in &node_data.children {
                if !find_all && !results.is_empty() {
                    return;
                }
                self.find_in_subtree(nodes, child_id, selector, results, find_all);
            }
        }
    }

    /// Get element by ID
    pub fn get_element_by_id(&self, id: &str) -> Option<Element> {
        self.query_selector(&format!("#{}", id))
    }

    /// Get elements by tag name
    pub fn get_elements_by_tag_name(&self, tag: &str) -> Vec<Element> {
        self.query_selector_all(tag)
    }

    /// Get elements by class name
    pub fn get_elements_by_class_name(&self, class: &str) -> Vec<Element> {
        self.query_selector_all(&format!(".{}", class))
    }

    /// Create a new element
    pub fn create_element(&self, tag: &str) -> Element {
        let id = NodeId::new();
        let data = NodeData::element(tag);
        self.nodes.write().insert(id, data);
        Element::from_id(id, self.nodes.clone()).unwrap()
    }

    /// Create a text node
    pub fn create_text_node(&self, content: &str) -> Node {
        let id = NodeId::new();
        let data = NodeData::text(content);
        self.nodes.write().insert(id, data);
        Node::new(id, self.nodes.clone())
    }

    /// Get all links (<a> elements with href)
    pub fn links(&self) -> Vec<Element> {
        self.query_selector_all("a[href]")
    }

    /// Get all images
    pub fn images(&self) -> Vec<Element> {
        self.query_selector_all("img")
    }

    /// Get all forms
    pub fn forms(&self) -> Vec<Element> {
        self.query_selector_all("form")
    }

    /// Get all scripts
    pub fn scripts(&self) -> Vec<Element> {
        self.query_selector_all("script")
    }

    /// Get all stylesheets
    pub fn stylesheets(&self) -> Vec<Element> {
        self.query_selector_all("link[rel=stylesheet]")
    }

    /// Get all input elements
    pub fn inputs(&self) -> Vec<Element> {
        self.query_selector_all("input, textarea, select")
    }

    /// Get document cookies (from meta tag or cookie jar)
    pub fn cookie(&self) -> String {
        // This would be populated from the cookie jar
        String::new()
    }

    /// Get the document's HTML
    pub fn outer_html(&self) -> String {
        self.root().outer_html()
    }

    /// Get all text content
    pub fn text_content(&self) -> String {
        self.root().text_content()
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::parse_html;

    #[test]
    fn test_document_creation() {
        let doc = Document::new();
        assert!(doc.url.is_none());
        assert!(doc.title().is_empty());
    }

    #[test]
    fn test_create_element() {
        let doc = Document::new();
        let div = doc.create_element("div");
        assert_eq!(div.tag_name(), "DIV");
    }

    #[test]
    fn test_query_selector() {
        let doc = parse_html("<html><body><div id='test'>Hello</div></body></html>").unwrap();
        let elem = doc.get_element_by_id("test");
        assert!(elem.is_some());
        assert_eq!(elem.unwrap().text_content(), "Hello");
    }
}
