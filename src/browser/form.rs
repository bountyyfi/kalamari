// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Form extraction and submission

use std::collections::HashMap;

use url::Url;

use crate::dom::Element;
use crate::error::{Error, Result};
use crate::http::{Request, Response};
use crate::network::{EventType, NetworkInterceptor};

/// Extracted form data
#[derive(Debug, Clone)]
pub struct Form {
    /// Form ID
    pub id: Option<String>,
    /// Form name
    pub name: Option<String>,
    /// Form action URL
    pub action: Option<String>,
    /// HTTP method (GET/POST)
    pub method: String,
    /// Encoding type
    pub enctype: String,
    /// Form fields
    pub fields: Vec<FormField>,
    /// Whether form has file upload
    pub has_file_upload: bool,
    /// Whether form has password field
    pub has_password: bool,
    /// CSRF token field name (if detected)
    pub csrf_field: Option<String>,
}

/// Form field
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name
    pub name: Option<String>,
    /// Field type (text, password, hidden, etc.)
    pub field_type: String,
    /// Current value
    pub value: Option<String>,
    /// Placeholder
    pub placeholder: Option<String>,
    /// Whether field is required
    pub required: bool,
    /// Whether field is disabled
    pub disabled: bool,
    /// Field pattern (for validation)
    pub pattern: Option<String>,
    /// Max length
    pub maxlength: Option<u32>,
    /// Min length
    pub minlength: Option<u32>,
    /// Select options (for select elements)
    pub options: Vec<SelectOption>,
}

/// Select option
#[derive(Debug, Clone)]
pub struct SelectOption {
    pub value: String,
    pub text: String,
    pub selected: bool,
}

impl Form {
    /// Create a form from a DOM element
    pub fn from_element(element: Element) -> Self {
        let mut fields = Vec::new();
        let mut has_file_upload = false;
        let mut has_password = false;
        let mut csrf_field = None;

        // Find all input, textarea, and select elements
        for input in element.query_selector_all("input, textarea, select") {
            let field_type = input
                .get_attribute("type")
                .unwrap_or_else(|| {
                    if input.local_name() == "textarea" {
                        "textarea".to_string()
                    } else if input.local_name() == "select" {
                        "select".to_string()
                    } else {
                        "text".to_string()
                    }
                })
                .to_lowercase();

            let name = input.get_attribute("name");

            // Check for file upload
            if field_type == "file" {
                has_file_upload = true;
            }

            // Check for password
            if field_type == "password" {
                has_password = true;
            }

            // Detect CSRF token
            if let Some(ref n) = name {
                let n_lower = n.to_lowercase();
                if field_type == "hidden"
                    && (n_lower.contains("csrf")
                        || n_lower.contains("token")
                        || n_lower.contains("_token")
                        || n_lower == "authenticity_token"
                        || n_lower == "_csrf")
                {
                    csrf_field = Some(n.clone());
                }
            }

            // Get select options
            let options = if field_type == "select" {
                input
                    .query_selector_all("option")
                    .into_iter()
                    .map(|opt| SelectOption {
                        value: opt.get_attribute("value").unwrap_or_default(),
                        text: opt.text_content(),
                        selected: opt.has_attribute("selected"),
                    })
                    .collect()
            } else {
                Vec::new()
            };

            fields.push(FormField {
                name,
                field_type,
                value: input.value(),
                placeholder: input.get_attribute("placeholder"),
                required: input.has_attribute("required"),
                disabled: input.has_attribute("disabled"),
                pattern: input.get_attribute("pattern"),
                maxlength: input
                    .get_attribute("maxlength")
                    .and_then(|v| v.parse().ok()),
                minlength: input
                    .get_attribute("minlength")
                    .and_then(|v| v.parse().ok()),
                options,
            });
        }

        Self {
            id: element.id(),
            name: element.get_attribute("name"),
            action: element.get_attribute("action"),
            method: element
                .get_attribute("method")
                .unwrap_or_else(|| "GET".to_string())
                .to_uppercase(),
            enctype: element
                .get_attribute("enctype")
                .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string()),
            fields,
            has_file_upload,
            has_password,
            csrf_field,
        }
    }

    /// Get fields as name-value pairs
    pub fn get_data(&self) -> HashMap<String, String> {
        self.fields
            .iter()
            .filter(|f| !f.disabled && f.name.is_some())
            .map(|f| {
                (
                    f.name.clone().unwrap(),
                    f.value.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Set a field value
    pub fn set_field(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        for field in &mut self.fields {
            if field.name.as_deref() == Some(name) {
                field.value = Some(value.clone());
            }
        }
    }

    /// Get visible fields (non-hidden)
    pub fn visible_fields(&self) -> Vec<&FormField> {
        self.fields
            .iter()
            .filter(|f| f.field_type != "hidden")
            .collect()
    }

    /// Get hidden fields
    pub fn hidden_fields(&self) -> Vec<&FormField> {
        self.fields
            .iter()
            .filter(|f| f.field_type == "hidden")
            .collect()
    }

    /// Get input fields (text, email, etc.)
    pub fn input_fields(&self) -> Vec<&FormField> {
        self.fields
            .iter()
            .filter(|f| {
                matches!(
                    f.field_type.as_str(),
                    "text" | "email" | "url" | "tel" | "number" | "search" | "password"
                )
            })
            .collect()
    }

    /// Get CSRF token value
    pub fn csrf_token(&self) -> Option<String> {
        self.csrf_field.as_ref().and_then(|name| {
            self.fields
                .iter()
                .find(|f| f.name.as_deref() == Some(name))
                .and_then(|f| f.value.clone())
        })
    }

    /// Submit the form
    pub async fn submit(
        &self,
        network: &NetworkInterceptor,
        base_url: Option<&Url>,
    ) -> Result<Response> {
        let action_url = self.resolve_action(base_url)?;
        let data = self.get_data();

        let response = if self.method == "POST" {
            let body = self.encode_form_data(&data);
            let request = Request::post(&action_url)?
                .header("content-type", &self.enctype)
                .body(body);
            network.execute(request, EventType::FormSubmission).await?
        } else {
            // GET request with query params
            let mut url = Url::parse(&action_url)?;
            for (key, value) in &data {
                url.query_pairs_mut().append_pair(key, value);
            }
            let request = Request::get(url.as_str())?;
            network.execute(request, EventType::FormSubmission).await?
        };

        Ok(response)
    }

    /// Resolve action URL against base URL
    fn resolve_action(&self, base_url: Option<&Url>) -> Result<String> {
        let action = self.action.as_deref().unwrap_or("");

        if action.is_empty() {
            // Submit to current URL
            base_url
                .map(|u| u.to_string())
                .ok_or_else(|| Error::navigation("No base URL for form submission".into()))
        } else if action.starts_with("http://") || action.starts_with("https://") {
            Ok(action.to_string())
        } else if let Some(base) = base_url {
            base.join(action)
                .map(|u| u.to_string())
                .map_err(|e| Error::navigation(e.to_string()))
        } else {
            Err(Error::navigation("Cannot resolve relative action URL".into()))
        }
    }

    /// Encode form data
    fn encode_form_data(&self, data: &HashMap<String, String>) -> String {
        data.iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

impl FormField {
    /// Check if field is a text input
    pub fn is_text_input(&self) -> bool {
        matches!(
            self.field_type.as_str(),
            "text" | "email" | "url" | "tel" | "number" | "search"
        )
    }

    /// Check if field is interesting for security testing
    pub fn is_security_relevant(&self) -> bool {
        !self.disabled
            && self.name.is_some()
            && !matches!(
                self.field_type.as_str(),
                "submit" | "button" | "reset" | "image"
            )
    }
}

/// Form submitter for automated testing
pub struct FormSubmitter {
    /// Default values for common field names
    default_values: HashMap<String, String>,
}

impl Default for FormSubmitter {
    fn default() -> Self {
        let mut default_values = HashMap::new();
        default_values.insert("email".to_string(), "test@example.com".to_string());
        default_values.insert("username".to_string(), "testuser".to_string());
        default_values.insert("password".to_string(), "TestPass123!".to_string());
        default_values.insert("name".to_string(), "Test User".to_string());
        default_values.insert("phone".to_string(), "+1234567890".to_string());
        default_values.insert("url".to_string(), "https://example.com".to_string());
        default_values.insert("search".to_string(), "test".to_string());

        Self { default_values }
    }
}

impl FormSubmitter {
    /// Create a new form submitter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add default value for a field name
    pub fn with_default(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_values.insert(name.into(), value.into());
        self
    }

    /// Fill form with default values
    pub fn fill_defaults(&self, form: &mut Form) {
        for field in &mut form.fields {
            if field.disabled || field.value.is_some() {
                continue;
            }

            if let Some(ref name) = field.name {
                // Try exact match
                if let Some(value) = self.default_values.get(name) {
                    field.value = Some(value.clone());
                    continue;
                }

                // Try partial match
                let name_lower = name.to_lowercase();
                for (key, value) in &self.default_values {
                    if name_lower.contains(key) {
                        field.value = Some(value.clone());
                        break;
                    }
                }

                // Fallback based on type
                if field.value.is_none() {
                    field.value = match field.field_type.as_str() {
                        "email" => Some("test@example.com".to_string()),
                        "password" => Some("TestPass123!".to_string()),
                        "url" => Some("https://example.com".to_string()),
                        "tel" => Some("+1234567890".to_string()),
                        "number" => Some("42".to_string()),
                        "text" | "search" => Some("test".to_string()),
                        _ => None,
                    };
                }
            }
        }
    }
}

/// URL encode a string
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::parse_html;

    #[test]
    fn test_form_extraction() {
        let html = r#"
            <form id="login" action="/login" method="post">
                <input type="hidden" name="_csrf" value="token123">
                <input type="email" name="email" required>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
        "#;

        let doc = parse_html(html).unwrap();
        let form_elem = doc.query_selector("form").unwrap();
        let form = Form::from_element(form_elem);

        assert_eq!(form.id, Some("login".to_string()));
        assert_eq!(form.method, "POST");
        assert!(form.has_password);
        assert!(form.csrf_field.is_some());
    }

    #[test]
    fn test_form_filling() {
        let html = r#"
            <form>
                <input type="text" name="username">
                <input type="email" name="email">
            </form>
        "#;

        let doc = parse_html(html).unwrap();
        let form_elem = doc.query_selector("form").unwrap();
        let mut form = Form::from_element(form_elem);

        let submitter = FormSubmitter::new();
        submitter.fill_defaults(&mut form);

        let data = form.get_data();
        assert!(data.get("username").is_some());
        assert!(data.get("email").is_some());
    }
}
