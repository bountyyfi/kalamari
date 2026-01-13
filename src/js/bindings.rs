// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! DOM bindings for JavaScript runtime
//!
//! Provides document, window, and element APIs for JavaScript execution.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::dom::Document;
use crate::error::Result;

/// DOM bindings for JavaScript context
pub struct DomBindings {
    document: Arc<RwLock<Document>>,
}

impl DomBindings {
    /// Create new DOM bindings
    pub fn new(document: Document) -> Self {
        Self {
            document: Arc::new(RwLock::new(document)),
        }
    }

    /// Get document reference
    pub fn document(&self) -> Arc<RwLock<Document>> {
        self.document.clone()
    }

    /// Get element by ID
    pub fn get_element_by_id(&self, id: &str) -> Option<String> {
        self.document
            .read()
            .get_element_by_id(id)
            .map(|e| e.outer_html())
    }

    /// Query selector
    pub fn query_selector(&self, selector: &str) -> Option<String> {
        self.document
            .read()
            .query_selector(selector)
            .map(|e| e.outer_html())
    }

    /// Query selector all
    pub fn query_selector_all(&self, selector: &str) -> Vec<String> {
        self.document
            .read()
            .query_selector_all(selector)
            .into_iter()
            .map(|e| e.outer_html())
            .collect()
    }

    /// Get document title
    pub fn get_title(&self) -> String {
        self.document.read().title()
    }

    /// Set document title
    pub fn set_title(&self, title: &str) {
        self.document.read().set_title(title);
    }

    /// Get document body HTML
    pub fn get_body_html(&self) -> Option<String> {
        self.document.read().body().map(|b| b.inner_html())
    }

    /// Get all links
    pub fn get_links(&self) -> Vec<String> {
        self.document
            .read()
            .links()
            .into_iter()
            .filter_map(|e| e.href())
            .collect()
    }

    /// Get all forms
    pub fn get_forms(&self) -> Vec<FormInfo> {
        self.document
            .read()
            .forms()
            .into_iter()
            .map(|form| FormInfo {
                id: form.id(),
                action: form.get_attribute("action"),
                method: form
                    .get_attribute("method")
                    .unwrap_or_else(|| "GET".to_string())
                    .to_uppercase(),
                inputs: form
                    .query_selector_all("input, textarea, select")
                    .into_iter()
                    .map(|input| InputInfo {
                        name: input.get_attribute("name"),
                        input_type: input.get_attribute("type").unwrap_or_else(|| "text".to_string()),
                        value: input.value(),
                        required: input.has_attribute("required"),
                    })
                    .collect(),
            })
            .collect()
    }

    /// Get document cookie string
    pub fn get_cookie(&self) -> String {
        self.document.read().cookie()
    }

    /// Get all script sources
    pub fn get_script_sources(&self) -> Vec<String> {
        self.document
            .read()
            .scripts()
            .into_iter()
            .filter_map(|s| s.src())
            .collect()
    }

    /// Get inline script contents
    pub fn get_inline_scripts(&self) -> Vec<String> {
        self.document
            .read()
            .scripts()
            .into_iter()
            .filter(|s| s.src().is_none())
            .map(|s| s.text_content())
            .collect()
    }
}

/// Form information
#[derive(Debug, Clone)]
pub struct FormInfo {
    pub id: Option<String>,
    pub action: Option<String>,
    pub method: String,
    pub inputs: Vec<InputInfo>,
}

/// Input field information
#[derive(Debug, Clone)]
pub struct InputInfo {
    pub name: Option<String>,
    pub input_type: String,
    pub value: Option<String>,
    pub required: bool,
}

impl FormInfo {
    /// Check if form has file upload
    pub fn has_file_upload(&self) -> bool {
        self.inputs.iter().any(|i| i.input_type == "file")
    }

    /// Check if form has password field
    pub fn has_password(&self) -> bool {
        self.inputs.iter().any(|i| i.input_type == "password")
    }

    /// Get form fields as key-value pairs
    pub fn get_fields(&self) -> Vec<(String, String)> {
        self.inputs
            .iter()
            .filter_map(|i| {
                i.name
                    .as_ref()
                    .map(|n| (n.clone(), i.value.clone().unwrap_or_default()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::parse_html;

    #[test]
    fn test_dom_bindings() {
        let doc = parse_html("<html><body><div id='test'>Hello</div></body></html>").unwrap();
        let bindings = DomBindings::new(doc);

        assert!(bindings.get_element_by_id("test").is_some());
    }

    #[test]
    fn test_form_extraction() {
        let html = r#"
            <form id="login" action="/login" method="post">
                <input type="text" name="username" required>
                <input type="password" name="password" required>
            </form>
        "#;
        let doc = parse_html(html).unwrap();
        let bindings = DomBindings::new(doc);

        let forms = bindings.get_forms();
        assert_eq!(forms.len(), 1);
        assert!(forms[0].has_password());
    }
}
