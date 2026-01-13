// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Page implementation

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use url::Url;

use super::config::PageConfig;
use super::form::Form;
use crate::dom::{Document, Element};
use crate::error::{Error, Result};
use crate::http::{HttpClient, Request, Response};
use crate::js::JsRuntime;
use crate::network::{EventType, NetworkInterceptor};
use crate::xss::{XssDetector, XssDetectorConfig, XssResult, XssTrigger};

/// A browser page
pub struct Page {
    /// Page ID
    id: String,
    /// Page configuration
    config: PageConfig,
    /// HTTP client
    client: HttpClient,
    /// Network interceptor
    network: NetworkInterceptor,
    /// JavaScript runtime
    js_runtime: Option<JsRuntime>,
    /// XSS detector
    xss_detector: Option<XssDetector>,
    /// Current URL
    url: Arc<RwLock<Option<Url>>>,
    /// Current document
    document: Arc<RwLock<Option<Document>>>,
    /// Last response
    last_response: Arc<RwLock<Option<Response>>>,
    /// Navigation history
    history: Arc<RwLock<Vec<String>>>,
}

impl Page {
    /// Create a new page
    pub(crate) fn new(
        id: String,
        config: PageConfig,
        client: HttpClient,
        network: NetworkInterceptor,
        js_enabled: bool,
    ) -> Self {
        let js_runtime = if js_enabled && config.execute_js {
            Some(JsRuntime::default_runtime())
        } else {
            None
        };

        let xss_detector = if config.xss_detection {
            Some(XssDetector::new(XssDetectorConfig {
                execute_js: js_enabled && config.execute_js,
                ..Default::default()
            }))
        } else {
            None
        };

        Self {
            id,
            config,
            client,
            network,
            js_runtime,
            xss_detector,
            url: Arc::new(RwLock::new(None)),
            document: Arc::new(RwLock::new(None)),
            last_response: Arc::new(RwLock::new(None)),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get page ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Navigate to a URL
    pub async fn navigate(&self, url: &str) -> Result<Response> {
        let parsed_url = Url::parse(url).map_err(|e| Error::Navigation(e.to_string()))?;

        let request = Request::get(url)?
            .timeout(self.config.timeout);

        let response = self.network.execute(request, EventType::Navigation).await?;

        // Update URL
        *self.url.write() = Some(response.url.clone());

        // Add to history
        self.history.write().push(response.url.to_string());

        // Parse HTML if response is HTML
        if response.is_html() {
            let html = response.text_lossy();
            let doc = crate::dom::parse_html_with_url(&html, Some(response.url.clone()))?;

            // Execute inline scripts if JS is enabled
            if let Some(ref js) = self.js_runtime {
                js.set_url(response.url.to_string());
                for script in doc.scripts() {
                    if script.src().is_none() {
                        let content = script.text_content();
                        if !content.trim().is_empty() {
                            let _ = js.execute(&content);
                        }
                    }
                }
            }

            *self.document.write() = Some(doc);
        }

        *self.last_response.write() = Some(response.clone());

        Ok(response)
    }

    /// Get current URL
    pub fn url(&self) -> Option<String> {
        self.url.read().as_ref().map(|u| u.to_string())
    }

    /// Get current document
    pub fn document(&self) -> Option<Document> {
        self.document.read().clone()
    }

    /// Get last response
    pub fn response(&self) -> Option<Response> {
        self.last_response.read().clone()
    }

    /// Get page title
    pub fn title(&self) -> Option<String> {
        self.document.read().as_ref().map(|d| d.title())
    }

    /// Get page content (HTML)
    pub fn content(&self) -> Option<String> {
        self.document.read().as_ref().map(|d| d.outer_html())
    }

    /// Query selector on current document
    pub fn query_selector(&self, selector: &str) -> Option<Element> {
        self.document.read().as_ref()?.query_selector(selector)
    }

    /// Query selector all on current document
    pub fn query_selector_all(&self, selector: &str) -> Vec<Element> {
        self.document
            .read()
            .as_ref()
            .map(|d| d.query_selector_all(selector))
            .unwrap_or_default()
    }

    /// Get element by ID
    pub fn get_element_by_id(&self, id: &str) -> Option<Element> {
        self.document.read().as_ref()?.get_element_by_id(id)
    }

    /// Get all links on the page
    pub fn links(&self) -> Vec<String> {
        self.document
            .read()
            .as_ref()
            .map(|d| {
                d.links()
                    .into_iter()
                    .filter_map(|e| e.href())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all forms on the page
    pub fn forms(&self) -> Vec<Form> {
        self.document
            .read()
            .as_ref()
            .map(|d| {
                d.forms()
                    .into_iter()
                    .map(Form::from_element)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get form by ID
    pub fn form_by_id(&self, id: &str) -> Option<Form> {
        self.query_selector(&format!("form#{}", id))
            .map(Form::from_element)
    }

    /// Execute JavaScript
    pub fn evaluate(&self, script: &str) -> Result<crate::js::JsValue> {
        let js = self.js_runtime.as_ref().ok_or_else(|| {
            Error::JavaScript("JavaScript is disabled".to_string())
        })?;

        js.execute(script)
    }

    /// Check for XSS triggers
    pub fn get_xss_triggers(&self) -> Vec<XssTrigger> {
        let mut triggers = Vec::new();

        // Get triggers from JS runtime
        if let Some(ref js) = self.js_runtime {
            triggers.extend(js.get_xss_triggers());
        }

        // Get triggers from XSS detector
        if let Some(ref detector) = self.xss_detector {
            triggers.extend(detector.get_triggers());
        }

        triggers
    }

    /// Analyze page for XSS
    pub fn analyze_xss(&self) -> XssResult {
        if let (Some(ref detector), Some(doc)) = (&self.xss_detector, &*self.document.read()) {
            detector.analyze(doc, self.url().as_deref())
        } else {
            XssResult::default()
        }
    }

    /// Test XSS payload
    pub fn test_xss_payload(&self, payload: &str) -> Vec<XssTrigger> {
        if let Some(ref js) = self.js_runtime {
            let (_, triggers) = js.execute_with_xss_check(payload).unwrap_or_default();
            triggers
        } else {
            Vec::new()
        }
    }

    /// Click on an element
    pub async fn click(&self, selector: &str) -> Result<()> {
        let element = self.query_selector(selector).ok_or_else(|| {
            Error::Dom(format!("Element not found: {}", selector))
        })?;

        // If it's a link, navigate to it
        if let Some(href) = element.href() {
            if let Some(base_url) = self.url.read().as_ref() {
                let target_url = base_url.join(&href).map_err(|e| Error::Navigation(e.to_string()))?;
                self.navigate(target_url.as_str()).await?;
            }
        }

        // Execute onclick handler if present
        if let Some(onclick) = element.get_attribute("onclick") {
            let _ = self.evaluate(&onclick);
        }

        Ok(())
    }

    /// Fill a form field
    pub fn fill(&self, selector: &str, value: &str) -> Result<()> {
        let element = self.query_selector(selector).ok_or_else(|| {
            Error::Dom(format!("Element not found: {}", selector))
        })?;

        element.set_value(value);
        Ok(())
    }

    /// Submit a form
    pub async fn submit_form(&self, selector: &str) -> Result<Response> {
        let form_element = self.query_selector(selector).ok_or_else(|| {
            Error::Dom(format!("Form not found: {}", selector))
        })?;

        let form = Form::from_element(form_element);
        form.submit(&self.network, self.url.read().as_ref()).await
    }

    /// Go back in history
    pub async fn go_back(&self) -> Result<Option<Response>> {
        let mut history = self.history.write();
        if history.len() < 2 {
            return Ok(None);
        }

        history.pop(); // Remove current
        if let Some(prev) = history.pop() {
            drop(history);
            let response = self.navigate(&prev).await?;
            return Ok(Some(response));
        }

        Ok(None)
    }

    /// Get navigation history
    pub fn navigation_history(&self) -> Vec<String> {
        self.history.read().clone()
    }

    /// Wait for a specified duration
    pub async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    /// Wait for an element to appear
    pub async fn wait_for_selector(&self, selector: &str, timeout: Duration) -> Result<Element> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if let Some(element) = self.query_selector(selector) {
                return Ok(element);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(Error::Timeout(format!(
            "Timeout waiting for selector: {}",
            selector
        )))
    }

    /// Get page configuration
    pub fn config(&self) -> &PageConfig {
        &self.config
    }

    /// Reload the page
    pub async fn reload(&self) -> Result<Response> {
        let url = self.url().ok_or_else(|| {
            Error::Navigation("No URL to reload".to_string())
        })?;
        self.navigate(&url).await
    }

    /// Take a text snapshot of the page
    pub fn text_content(&self) -> Option<String> {
        self.document.read().as_ref().map(|d| d.text_content())
    }

    /// Get console output from JS runtime
    pub fn console_output(&self) -> Vec<String> {
        self.js_runtime
            .as_ref()
            .map(|js| {
                js.get_console_output()
                    .into_iter()
                    .map(|m| format!("[{:?}] {}", m.level, m.message))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_creation() {
        let client = HttpClient::new().unwrap();
        let network = NetworkInterceptor::new(client.clone());
        let page = Page::new(
            "test".to_string(),
            PageConfig::default(),
            client,
            network,
            true,
        );
        assert_eq!(page.id(), "test");
    }
}
