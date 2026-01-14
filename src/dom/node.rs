// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! DOM Node types

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

/// Unique node identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u64);

impl NodeId {
    /// Create a new unique node ID
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Get the raw ID value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Node type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Document node
    Document,
    /// Element node (like <div>, <p>, etc.)
    Element,
    /// Text node
    Text,
    /// Comment node
    Comment,
    /// Document type node (<!DOCTYPE>)
    DocumentType,
    /// Processing instruction
    ProcessingInstruction,
    /// Document fragment
    DocumentFragment,
}

impl NodeType {
    /// Get the numeric value (matches DOM spec)
    pub fn as_u8(&self) -> u8 {
        match self {
            NodeType::Element => 1,
            NodeType::Text => 3,
            NodeType::ProcessingInstruction => 7,
            NodeType::Comment => 8,
            NodeType::Document => 9,
            NodeType::DocumentType => 10,
            NodeType::DocumentFragment => 11,
        }
    }
}

/// Internal node data
#[derive(Debug)]
pub struct NodeData {
    /// Node type
    pub node_type: NodeType,
    /// Tag name (for elements)
    pub tag_name: Option<String>,
    /// Text content (for text/comment nodes)
    pub text_content: Option<String>,
    /// Attributes (for elements)
    pub attributes: HashMap<String, String>,
    /// Parent node ID
    pub parent: Option<NodeId>,
    /// Child node IDs
    pub children: Vec<NodeId>,
    /// Previous sibling ID
    pub prev_sibling: Option<NodeId>,
    /// Next sibling ID
    pub next_sibling: Option<NodeId>,
}

impl NodeData {
    /// Create a new element node data
    pub fn element(tag_name: impl Into<String>) -> Self {
        Self {
            node_type: NodeType::Element,
            tag_name: Some(tag_name.into().to_lowercase()),
            text_content: None,
            attributes: HashMap::new(),
            parent: None,
            children: Vec::new(),
            prev_sibling: None,
            next_sibling: None,
        }
    }

    /// Create a new text node data
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            node_type: NodeType::Text,
            tag_name: None,
            text_content: Some(content.into()),
            attributes: HashMap::new(),
            parent: None,
            children: Vec::new(),
            prev_sibling: None,
            next_sibling: None,
        }
    }

    /// Create a new comment node data
    pub fn comment(content: impl Into<String>) -> Self {
        Self {
            node_type: NodeType::Comment,
            tag_name: None,
            text_content: Some(content.into()),
            attributes: HashMap::new(),
            parent: None,
            children: Vec::new(),
            prev_sibling: None,
            next_sibling: None,
        }
    }

    /// Create a new document node data
    pub fn document() -> Self {
        Self {
            node_type: NodeType::Document,
            tag_name: None,
            text_content: None,
            attributes: HashMap::new(),
            parent: None,
            children: Vec::new(),
            prev_sibling: None,
            next_sibling: None,
        }
    }
}

/// A reference to a node in the DOM tree
#[derive(Debug, Clone)]
pub struct Node {
    /// Node ID
    pub id: NodeId,
    /// Reference to document's node storage
    nodes: Arc<RwLock<HashMap<NodeId, NodeData>>>,
}

impl Node {
    /// Create a new node reference
    pub(crate) fn new(id: NodeId, nodes: Arc<RwLock<HashMap<NodeId, NodeData>>>) -> Self {
        Self { id, nodes }
    }

    /// Get the node type
    pub fn node_type(&self) -> NodeType {
        self.nodes
            .read()
            .get(&self.id)
            .map(|n| n.node_type)
            .unwrap_or(NodeType::Element)
    }

    /// Get the tag name (uppercase, like browsers)
    pub fn tag_name(&self) -> Option<String> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.tag_name.clone())
            .map(|t| t.to_uppercase())
    }

    /// Get the tag name in lowercase
    pub fn local_name(&self) -> Option<String> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.tag_name.clone())
    }

    /// Get text content
    pub fn text_content(&self) -> String {
        let nodes = self.nodes.read();
        self.collect_text_content(&nodes, self.id)
    }

    /// Recursively collect text content
    fn collect_text_content(&self, nodes: &HashMap<NodeId, NodeData>, node_id: NodeId) -> String {
        if let Some(node) = nodes.get(&node_id) {
            match node.node_type {
                NodeType::Text => node.text_content.clone().unwrap_or_default(),
                NodeType::Element | NodeType::Document | NodeType::DocumentFragment => {
                    node.children
                        .iter()
                        .map(|&child_id| self.collect_text_content(nodes, child_id))
                        .collect()
                }
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }

    /// Set text content (replaces all children with a text node)
    pub fn set_text_content(&self, content: impl Into<String>) {
        let content = content.into();
        let mut nodes = self.nodes.write();

        if let Some(node) = nodes.get_mut(&self.id) {
            // Remove existing children
            node.children.clear();

            if node.node_type == NodeType::Text {
                node.text_content = Some(content);
            } else {
                // Create a text node child
                let text_id = NodeId::new();
                let mut text_data = NodeData::text(content);
                text_data.parent = Some(self.id);
                nodes.insert(text_id, text_data);

                if let Some(parent) = nodes.get_mut(&self.id) {
                    parent.children.push(text_id);
                }
            }
        }
    }

    /// Get an attribute value
    pub fn get_attribute(&self, name: &str) -> Option<String> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.attributes.get(&name.to_lowercase()).cloned())
    }

    /// Set an attribute value
    pub fn set_attribute(&self, name: impl Into<String>, value: impl Into<String>) {
        if let Some(node) = self.nodes.write().get_mut(&self.id) {
            node.attributes.insert(name.into().to_lowercase(), value.into());
        }
    }

    /// Remove an attribute
    pub fn remove_attribute(&self, name: &str) {
        if let Some(node) = self.nodes.write().get_mut(&self.id) {
            node.attributes.remove(&name.to_lowercase());
        }
    }

    /// Check if has an attribute
    pub fn has_attribute(&self, name: &str) -> bool {
        self.nodes
            .read()
            .get(&self.id)
            .map(|n| n.attributes.contains_key(&name.to_lowercase()))
            .unwrap_or(false)
    }

    /// Get all attributes
    pub fn attributes(&self) -> HashMap<String, String> {
        self.nodes
            .read()
            .get(&self.id)
            .map(|n| n.attributes.clone())
            .unwrap_or_default()
    }

    /// Get parent node
    pub fn parent(&self) -> Option<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.parent)
            .map(|id| Node::new(id, self.nodes.clone()))
    }

    /// Get child nodes
    pub fn children(&self) -> Vec<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .map(|n| {
                n.children
                    .iter()
                    .map(|&id| Node::new(id, self.nodes.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get first child
    pub fn first_child(&self) -> Option<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.children.first().copied())
            .map(|id| Node::new(id, self.nodes.clone()))
    }

    /// Get last child
    pub fn last_child(&self) -> Option<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.children.last().copied())
            .map(|id| Node::new(id, self.nodes.clone()))
    }

    /// Get next sibling
    pub fn next_sibling(&self) -> Option<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.next_sibling)
            .map(|id| Node::new(id, self.nodes.clone()))
    }

    /// Get previous sibling
    pub fn prev_sibling(&self) -> Option<Node> {
        self.nodes
            .read()
            .get(&self.id)
            .and_then(|n| n.prev_sibling)
            .map(|id| Node::new(id, self.nodes.clone()))
    }

    /// Check if this is an element node
    pub fn is_element(&self) -> bool {
        self.node_type() == NodeType::Element
    }

    /// Check if this is a text node
    pub fn is_text(&self) -> bool {
        self.node_type() == NodeType::Text
    }

    /// Append a child node
    pub fn append_child(&self, child: &Node) {
        let mut nodes = self.nodes.write();

        // Collect info needed for updates
        let old_parent_id = nodes.get(&child.id).and_then(|d| d.parent);
        let last_child_id = nodes.get(&self.id).and_then(|d| d.children.last().copied());

        // Remove from old parent if any
        if let Some(old_pid) = old_parent_id {
            if let Some(old_parent) = nodes.get_mut(&old_pid) {
                old_parent.children.retain(|&id| id != child.id);
            }
        }

        // Update child's parent and reset siblings
        if let Some(child_data) = nodes.get_mut(&child.id) {
            child_data.parent = Some(self.id);
            child_data.prev_sibling = last_child_id;
            child_data.next_sibling = None;
        }

        // Update last child's next_sibling
        if let Some(last_id) = last_child_id {
            if let Some(last_child) = nodes.get_mut(&last_id) {
                last_child.next_sibling = Some(child.id);
            }
        }

        // Add to parent's children
        if let Some(parent_data) = nodes.get_mut(&self.id) {
            parent_data.children.push(child.id);
        }
    }

    /// Remove a child node
    pub fn remove_child(&self, child: &Node) {
        let mut nodes = self.nodes.write();

        // Update sibling links
        if let Some(child_data) = nodes.get(&child.id) {
            let prev = child_data.prev_sibling;
            let next = child_data.next_sibling;

            if let Some(prev_id) = prev {
                if let Some(prev_node) = nodes.get_mut(&prev_id) {
                    prev_node.next_sibling = next;
                }
            }
            if let Some(next_id) = next {
                if let Some(next_node) = nodes.get_mut(&next_id) {
                    next_node.prev_sibling = prev;
                }
            }
        }

        // Remove from parent
        if let Some(parent_data) = nodes.get_mut(&self.id) {
            parent_data.children.retain(|&id| id != child.id);
        }

        // Clear child's parent
        if let Some(child_data) = nodes.get_mut(&child.id) {
            child_data.parent = None;
            child_data.prev_sibling = None;
            child_data.next_sibling = None;
        }
    }

    /// Get inner HTML
    pub fn inner_html(&self) -> String {
        let nodes = self.nodes.read();
        if let Some(node) = nodes.get(&self.id) {
            node.children
                .iter()
                .map(|&id| self.serialize_node(&nodes, id))
                .collect()
        } else {
            String::new()
        }
    }

    /// Get outer HTML
    pub fn outer_html(&self) -> String {
        let nodes = self.nodes.read();
        self.serialize_node(&nodes, self.id)
    }

    /// Serialize a node to HTML string
    fn serialize_node(&self, nodes: &HashMap<NodeId, NodeData>, node_id: NodeId) -> String {
        if let Some(node) = nodes.get(&node_id) {
            match node.node_type {
                NodeType::Text => node.text_content.clone().unwrap_or_default(),
                NodeType::Comment => {
                    format!("<!--{}-->", node.text_content.as_deref().unwrap_or(""))
                }
                NodeType::Element => {
                    let tag = node.tag_name.as_deref().unwrap_or("div");
                    let attrs: String = node
                        .attributes
                        .iter()
                        .map(|(k, v)| {
                            if v.is_empty() {
                                format!(" {}", k)
                            } else {
                                format!(" {}=\"{}\"", k, html_escape(v))
                            }
                        })
                        .collect();

                    // Void elements
                    let void_elements = [
                        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                        "meta", "param", "source", "track", "wbr",
                    ];

                    if void_elements.contains(&tag) {
                        format!("<{}{}>", tag, attrs)
                    } else {
                        let children: String = node
                            .children
                            .iter()
                            .map(|&id| self.serialize_node(nodes, id))
                            .collect();
                        format!("<{}{}>{}</{}>", tag, attrs, children, tag)
                    }
                }
                NodeType::Document | NodeType::DocumentFragment => node
                    .children
                    .iter()
                    .map(|&id| self.serialize_node(nodes, id))
                    .collect(),
                NodeType::DocumentType => "<!DOCTYPE html>".to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Node {}

impl std::hash::Hash for Node {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id() {
        let id1 = NodeId::new();
        let id2 = NodeId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_data() {
        let element = NodeData::element("div");
        assert_eq!(element.tag_name, Some("div".to_string()));
        assert_eq!(element.node_type, NodeType::Element);

        let text = NodeData::text("Hello");
        assert_eq!(text.text_content, Some("Hello".to_string()));
        assert_eq!(text.node_type, NodeType::Text);
    }
}
