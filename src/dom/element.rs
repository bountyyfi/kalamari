// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Element-specific DOM operations

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use super::node::{Node, NodeData, NodeId, NodeType};
use super::selector::Selector;

/// Element node with extended operations
#[derive(Debug, Clone)]
pub struct Element {
    /// Inner node reference
    pub node: Node,
}

impl Element {
    /// Create a new element from a node
    pub fn new(node: Node) -> Option<Self> {
        if node.node_type() == NodeType::Element {
            Some(Self { node })
        } else {
            None
        }
    }

    /// Create element from node ID
    pub(crate) fn from_id(
        id: NodeId,
        nodes: Arc<RwLock<HashMap<NodeId, NodeData>>>,
    ) -> Option<Self> {
        let node = Node::new(id, nodes);
        Self::new(node)
    }

    /// Get the tag name (uppercase)
    pub fn tag_name(&self) -> String {
        self.node.tag_name().unwrap_or_default()
    }

    /// Get local name (lowercase)
    pub fn local_name(&self) -> String {
        self.node.local_name().unwrap_or_default()
    }

    /// Get element ID
    pub fn id(&self) -> Option<String> {
        self.node.get_attribute("id")
    }

    /// Get class list as vector
    pub fn class_list(&self) -> Vec<String> {
        self.node
            .get_attribute("class")
            .map(|c| c.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    }

    /// Check if element has a class
    pub fn has_class(&self, class: &str) -> bool {
        self.class_list().iter().any(|c| c == class)
    }

    /// Add a class
    pub fn add_class(&self, class: &str) {
        let mut classes = self.class_list();
        if !classes.contains(&class.to_string()) {
            classes.push(class.to_string());
            self.node.set_attribute("class", classes.join(" "));
        }
    }

    /// Remove a class
    pub fn remove_class(&self, class: &str) {
        let classes: Vec<_> = self
            .class_list()
            .into_iter()
            .filter(|c| c != class)
            .collect();
        self.node.set_attribute("class", classes.join(" "));
    }

    /// Get an attribute
    pub fn get_attribute(&self, name: &str) -> Option<String> {
        self.node.get_attribute(name)
    }

    /// Set an attribute
    pub fn set_attribute(&self, name: impl Into<String>, value: impl Into<String>) {
        self.node.set_attribute(name, value);
    }

    /// Remove an attribute
    pub fn remove_attribute(&self, name: &str) {
        self.node.remove_attribute(name);
    }

    /// Check if has attribute
    pub fn has_attribute(&self, name: &str) -> bool {
        self.node.has_attribute(name)
    }

    /// Get all attributes
    pub fn attributes(&self) -> HashMap<String, String> {
        self.node.attributes()
    }

    /// Get text content
    pub fn text_content(&self) -> String {
        self.node.text_content()
    }

    /// Set text content
    pub fn set_text_content(&self, content: impl Into<String>) {
        self.node.set_text_content(content);
    }

    /// Get inner HTML
    pub fn inner_html(&self) -> String {
        self.node.inner_html()
    }

    /// Get outer HTML
    pub fn outer_html(&self) -> String {
        self.node.outer_html()
    }

    /// Get parent element
    pub fn parent_element(&self) -> Option<Element> {
        self.node.parent().and_then(Element::new)
    }

    /// Get child elements (only element nodes)
    pub fn children(&self) -> Vec<Element> {
        self.node
            .children()
            .into_iter()
            .filter_map(Element::new)
            .collect()
    }

    /// Get first child element
    pub fn first_element_child(&self) -> Option<Element> {
        self.children().into_iter().next()
    }

    /// Get last child element
    pub fn last_element_child(&self) -> Option<Element> {
        self.children().into_iter().last()
    }

    /// Get next sibling element
    pub fn next_element_sibling(&self) -> Option<Element> {
        let mut sibling = self.node.next_sibling();
        while let Some(s) = sibling {
            if s.is_element() {
                return Element::new(s);
            }
            sibling = s.next_sibling();
        }
        None
    }

    /// Get previous sibling element
    pub fn previous_element_sibling(&self) -> Option<Element> {
        let mut sibling = self.node.prev_sibling();
        while let Some(s) = sibling {
            if s.is_element() {
                return Element::new(s);
            }
            sibling = s.prev_sibling();
        }
        None
    }

    /// Query selector - find first matching element
    pub fn query_selector(&self, selector: &str) -> Option<Element> {
        let sel = Selector::parse(selector).ok()?;
        self.query_selector_internal(&sel)
    }

    /// Query selector all - find all matching elements
    pub fn query_selector_all(&self, selector: &str) -> Vec<Element> {
        if let Ok(sel) = Selector::parse(selector) {
            self.query_selector_all_internal(&sel)
        } else {
            Vec::new()
        }
    }

    /// Internal query selector implementation
    fn query_selector_internal(&self, selector: &Selector) -> Option<Element> {
        // Check self
        if selector.matches(&self.node) {
            return Some(self.clone());
        }

        // Check children recursively
        for child in self.children() {
            if let Some(found) = child.query_selector_internal(selector) {
                return Some(found);
            }
        }

        None
    }

    /// Internal query selector all implementation
    fn query_selector_all_internal(&self, selector: &Selector) -> Vec<Element> {
        let mut results = Vec::new();

        // Check self
        if selector.matches(&self.node) {
            results.push(self.clone());
        }

        // Check children recursively
        for child in self.children() {
            results.extend(child.query_selector_all_internal(selector));
        }

        results
    }

    /// Get elements by tag name
    pub fn get_elements_by_tag_name(&self, tag: &str) -> Vec<Element> {
        let tag = tag.to_lowercase();
        self.query_selector_all(&tag)
    }

    /// Get elements by class name
    pub fn get_elements_by_class_name(&self, class: &str) -> Vec<Element> {
        self.query_selector_all(&format!(".{}", class))
    }

    /// Check if element matches a selector
    pub fn matches(&self, selector: &str) -> bool {
        Selector::parse(selector)
            .map(|sel| sel.matches(&self.node))
            .unwrap_or(false)
    }

    /// Get closest ancestor matching selector
    pub fn closest(&self, selector: &str) -> Option<Element> {
        let sel = Selector::parse(selector).ok()?;

        // Check self first
        if sel.matches(&self.node) {
            return Some(self.clone());
        }

        // Walk up the tree
        let mut current = self.parent_element();
        while let Some(parent) = current {
            if sel.matches(&parent.node) {
                return Some(parent);
            }
            current = parent.parent_element();
        }

        None
    }

    /// Check if this element contains another
    pub fn contains(&self, other: &Element) -> bool {
        let mut current = other.parent_element();
        while let Some(parent) = current {
            if parent.node.id == self.node.id {
                return true;
            }
            current = parent.parent_element();
        }
        false
    }

    /// Get bounding client rect (placeholder - returns empty rect)
    pub fn get_bounding_client_rect(&self) -> BoundingRect {
        // In a real browser this would calculate layout
        BoundingRect::default()
    }

    /// Focus the element (no-op in headless)
    pub fn focus(&self) {
        // No-op in headless mode
    }

    /// Blur the element (no-op in headless)
    pub fn blur(&self) {
        // No-op in headless mode
    }

    /// Click the element (fires events in JS context)
    pub fn click(&self) {
        // Event handling would be done by JS runtime
    }

    /// Get/set value for form elements
    pub fn value(&self) -> Option<String> {
        match self.local_name().as_str() {
            "input" | "textarea" | "select" => self.get_attribute("value"),
            _ => None,
        }
    }

    /// Set value for form elements
    pub fn set_value(&self, value: impl Into<String>) {
        match self.local_name().as_str() {
            "input" | "textarea" | "select" => {
                self.set_attribute("value", value);
            }
            _ => {}
        }
    }

    /// Check if checkbox/radio is checked
    pub fn checked(&self) -> bool {
        self.has_attribute("checked")
    }

    /// Set checked state
    pub fn set_checked(&self, checked: bool) {
        if checked {
            self.set_attribute("checked", "checked");
        } else {
            self.remove_attribute("checked");
        }
    }

    /// Check if element is disabled
    pub fn disabled(&self) -> bool {
        self.has_attribute("disabled")
    }

    /// Get href for links
    pub fn href(&self) -> Option<String> {
        self.get_attribute("href")
    }

    /// Get src for images, scripts, etc.
    pub fn src(&self) -> Option<String> {
        self.get_attribute("src")
    }

    /// Get the form this element belongs to
    pub fn form(&self) -> Option<Element> {
        self.closest("form")
    }
}

impl std::ops::Deref for Element {
    type Target = Node;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

/// Bounding rectangle (placeholder)
#[derive(Debug, Clone, Copy, Default)]
pub struct BoundingRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub top: f64,
    pub right: f64,
    pub bottom: f64,
    pub left: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::parse_html;

    #[test]
    fn test_element_class_list() {
        let doc = parse_html("<div class=\"foo bar baz\">test</div>").unwrap();
        let div = doc.query_selector("div").unwrap();
        let classes = div.class_list();
        assert!(classes.contains(&"foo".to_string()));
        assert!(classes.contains(&"bar".to_string()));
        assert!(classes.contains(&"baz".to_string()));
    }
}
