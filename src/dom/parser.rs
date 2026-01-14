// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! HTML parser using html5ever

use std::collections::HashMap;

use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use html5ever::tree_builder::TreeBuilderOpts;
use html5ever::ParseOpts;
use markup5ever_rcdom::{Handle, NodeData as RcNodeData, RcDom};
use url::Url;

use super::document::Document;
use super::node::{NodeData, NodeId};
use crate::error::{Error, Result};

/// Parse HTML string into a Document
pub fn parse_html(html: &str) -> Result<Document> {
    parse_html_with_url(html, None)
}

/// Parse HTML string with a base URL
pub fn parse_html_with_url(html: &str, url: Option<Url>) -> Result<Document> {
    let opts = ParseOpts {
        tree_builder: TreeBuilderOpts {
            drop_doctype: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let dom = parse_document(RcDom::default(), opts)
        .from_utf8()
        .read_from(&mut html.as_bytes())
        .unwrap();

    let mut doc = match url {
        Some(u) => Document::with_url(u),
        None => Document::new(),
    };

    // Convert html5ever DOM to our DOM
    let converter = DomConverter::new(&mut doc);
    converter.convert(&dom.document);

    // Find title
    if let Some(title_elem) = doc.query_selector("title") {
        doc.set_title(title_elem.text_content());
    }

    Ok(doc)
}

/// Converts html5ever DOM to our DOM
struct DomConverter<'a> {
    doc: &'a mut Document,
}

impl<'a> DomConverter<'a> {
    fn new(doc: &'a mut Document) -> Self {
        Self { doc }
    }

    fn convert(mut self, handle: &Handle) {
        let root_id = self.doc.root().id;

        // Track special elements
        let mut html_id = None;
        let mut head_id = None;
        let mut body_id = None;

        // Convert children of the document node
        for child in handle.children.borrow().iter() {
            if let Some(id) = self.convert_node(child, root_id) {
                // Check if this is html, head, or body
                let nodes = self.doc.nodes.read();
                if let Some(node_data) = nodes.get(&id) {
                    if let Some(ref tag) = node_data.tag_name {
                        match tag.as_str() {
                            "html" => html_id = Some(id),
                            "head" => head_id = Some(id),
                            "body" => body_id = Some(id),
                            _ => {}
                        }
                    }
                }
                drop(nodes);
            }
        }

        // If we found html but not head/body, search inside html
        if let Some(html) = html_id {
            let nodes = self.doc.nodes.read();
            if let Some(html_data) = nodes.get(&html) {
                for &child_id in &html_data.children {
                    if let Some(child_data) = nodes.get(&child_id) {
                        if let Some(ref tag) = child_data.tag_name {
                            match tag.as_str() {
                                "head" => head_id = Some(child_id),
                                "body" => body_id = Some(child_id),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        self.doc.set_elements(html_id, head_id, body_id);
    }

    fn convert_node(&mut self, handle: &Handle, parent_id: NodeId) -> Option<NodeId> {
        let node_id = NodeId::new();

        let node_data = match handle.data {
            RcNodeData::Document => {
                // Skip document node, we already have one
                return None;
            }
            RcNodeData::Doctype { .. } => {
                // Create doctype node
                let mut data = NodeData::document();
                data.node_type = super::node::NodeType::DocumentType;
                data
            }
            RcNodeData::Text { ref contents } => {
                let text = contents.borrow().to_string();
                if text.trim().is_empty() && text.len() > 1 {
                    // Skip whitespace-only text nodes (but keep single spaces)
                    return None;
                }
                NodeData::text(text)
            }
            RcNodeData::Comment { ref contents } => NodeData::comment(contents.to_string()),
            RcNodeData::Element {
                ref name,
                ref attrs,
                ..
            } => {
                let tag_name = name.local.to_string();
                let mut data = NodeData::element(&tag_name);

                // Add attributes
                for attr in attrs.borrow().iter() {
                    let attr_name = attr.name.local.to_string();
                    let attr_value = attr.value.to_string();
                    data.attributes.insert(attr_name, attr_value);
                }

                data
            }
            RcNodeData::ProcessingInstruction { .. } => {
                // Skip processing instructions
                return None;
            }
        };

        // Set parent
        let mut data = node_data;
        data.parent = Some(parent_id);

        // Insert the node
        {
            let mut nodes = self.doc.nodes.write();
            nodes.insert(node_id, data);

            // Get last child before modification
            let last_child_id = nodes.get(&parent_id).and_then(|p| p.children.last().copied());

            // Update last child's next_sibling
            if let Some(last_id) = last_child_id {
                if let Some(last) = nodes.get_mut(&last_id) {
                    last.next_sibling = Some(node_id);
                }
            }

            // Update current node's prev_sibling
            if let Some(current) = nodes.get_mut(&node_id) {
                current.prev_sibling = last_child_id;
            }

            // Add to parent's children
            if let Some(parent) = nodes.get_mut(&parent_id) {
                parent.children.push(node_id);
            }
        }

        // Convert children
        for child in handle.children.borrow().iter() {
            self.convert_node(child, node_id);
        }

        Some(node_id)
    }
}

/// Parse HTML fragment (for innerHTML)
pub fn parse_fragment(html: &str) -> Result<Vec<super::node::Node>> {
    let doc = parse_html(&format!("<div>{}</div>", html))?;
    if let Some(wrapper) = doc.query_selector("div") {
        Ok(wrapper.node.children())
    } else {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_html() {
        let doc = parse_html("<html><body><p>Hello</p></body></html>").unwrap();
        assert!(doc.body().is_some());
    }

    #[test]
    fn test_parse_with_attributes() {
        let doc = parse_html("<div id=\"test\" class=\"foo bar\">content</div>").unwrap();
        let div = doc.query_selector("div").unwrap();
        assert_eq!(div.get_attribute("id"), Some("test".to_string()));
        assert!(div.has_class("foo"));
    }

    #[test]
    fn test_parse_complex_html() {
        let html = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Test Page</title>
            </head>
            <body>
                <div id="container">
                    <h1>Hello World</h1>
                    <p class="content">This is a test.</p>
                    <a href="https://example.com">Link</a>
                </div>
            </body>
            </html>
        "#;
        let doc = parse_html(html).unwrap();

        assert_eq!(doc.title(), "Test Page");
        assert!(doc.head().is_some());
        assert!(doc.body().is_some());

        let h1 = doc.query_selector("h1").unwrap();
        assert_eq!(h1.text_content(), "Hello World");

        let links = doc.links();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href(), Some("https://example.com".to_string()));
    }

    #[test]
    fn test_forms() {
        let html = r#"
            <form id="login" action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        "#;
        let doc = parse_html(html).unwrap();

        let forms = doc.forms();
        assert_eq!(forms.len(), 1);

        let inputs = doc.inputs();
        assert_eq!(inputs.len(), 2);
    }
}
