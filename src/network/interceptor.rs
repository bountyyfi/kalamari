// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Network interceptor for capturing and modifying requests/responses

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use super::event::{EventType, NetworkEvent, RequestInfo, ResponseInfo};
use crate::error::Result;
use crate::http::{HttpClient, Request, Response};

/// Network interceptor callback type
pub type InterceptCallback = Arc<dyn Fn(&NetworkEvent) + Send + Sync>;

/// Network interceptor for capturing all network activity
pub struct NetworkInterceptor {
    /// HTTP client
    client: HttpClient,
    /// Captured events
    events: Arc<RwLock<Vec<NetworkEvent>>>,
    /// Event counter for ID generation
    event_counter: Arc<RwLock<u64>>,
    /// Request interceptor callback
    on_request: Option<InterceptCallback>,
    /// Response interceptor callback
    on_response: Option<InterceptCallback>,
    /// Maximum events to store
    max_events: usize,
    /// Capture response bodies
    capture_bodies: bool,
    /// Maximum body size to capture
    max_body_size: usize,
}

impl NetworkInterceptor {
    /// Create a new network interceptor
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            events: Arc::new(RwLock::new(Vec::new())),
            event_counter: Arc::new(RwLock::new(0)),
            on_request: None,
            on_response: None,
            max_events: 1000,
            capture_bodies: true,
            max_body_size: 1024 * 1024, // 1MB
        }
    }

    /// Set request callback
    pub fn on_request(mut self, callback: InterceptCallback) -> Self {
        self.on_request = Some(callback);
        self
    }

    /// Set response callback
    pub fn on_response(mut self, callback: InterceptCallback) -> Self {
        self.on_response = Some(callback);
        self
    }

    /// Set max events
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Set body capture settings
    pub fn capture_bodies(mut self, capture: bool, max_size: usize) -> Self {
        self.capture_bodies = capture;
        self.max_body_size = max_size;
        self
    }

    /// Execute a request with interception
    pub async fn execute(&self, request: Request, event_type: EventType) -> Result<Response> {
        let start = Instant::now();
        let event_id = self.next_event_id();

        // Create request info
        let request_info = RequestInfo {
            url: request.url.to_string(),
            method: request.method.to_string(),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect(),
            body: request.body.as_ref().map(|b| {
                String::from_utf8_lossy(&b[..b.len().min(self.max_body_size)]).to_string()
            }),
            content_type: request
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cookies: self
                .client
                .cookie_jar()
                .get_cookie_header(&request.url),
            with_credentials: true,
        };

        // Create initial event
        let mut event = NetworkEvent::new(event_id.clone(), event_type, request_info);

        // Call request callback
        if let Some(ref callback) = self.on_request {
            callback(&event);
        }

        // Execute the request
        let result = self.client.execute(request).await;
        let duration = start.elapsed();

        // Update event with response
        match &result {
            Ok(response) => {
                let response_info = ResponseInfo {
                    status: response.status.as_u16(),
                    status_text: response.status.canonical_reason().unwrap_or("").to_string(),
                    headers: response
                        .headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect(),
                    body: if self.capture_bodies {
                        Some(response.text_lossy())
                    } else {
                        None
                    },
                    content_type: response.content_type().map(String::from),
                    content_length: response.content_length(),
                    set_cookies: response.set_cookies().iter().map(|s| s.to_string()).collect(),
                    from_cache: false,
                };

                event = event.with_response(response_info).with_duration(duration);
            }
            Err(e) => {
                event = event.with_error(e.to_string()).with_duration(duration);
            }
        }

        // Call response callback
        if let Some(ref callback) = self.on_response {
            callback(&event);
        }

        // Store event
        self.store_event(event);

        result
    }

    /// Execute a GET request
    pub async fn get(&self, url: &str) -> Result<Response> {
        let request = Request::get(url)?;
        self.execute(request, EventType::Navigation).await
    }

    /// Execute a POST request
    pub async fn post(&self, url: &str, body: impl Into<bytes::Bytes>) -> Result<Response> {
        let request = Request::post(url)?.body(body);
        self.execute(request, EventType::FormSubmission).await
    }

    /// Execute an XHR-like request
    pub async fn xhr(&self, request: Request) -> Result<Response> {
        self.execute(request, EventType::Xhr).await
    }

    /// Execute a fetch-like request
    pub async fn fetch(&self, request: Request) -> Result<Response> {
        self.execute(request, EventType::Fetch).await
    }

    /// Get all captured events
    pub fn events(&self) -> Vec<NetworkEvent> {
        self.events.read().clone()
    }

    /// Get events by type
    pub fn events_by_type(&self, event_type: EventType) -> Vec<NetworkEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get API requests
    pub fn api_requests(&self) -> Vec<NetworkEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.is_api_request())
            .cloned()
            .collect()
    }

    /// Get form submissions
    pub fn form_submissions(&self) -> Vec<NetworkEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.is_form_submission())
            .cloned()
            .collect()
    }

    /// Get failed requests
    pub fn failed_requests(&self) -> Vec<NetworkEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.error.is_some() || !e.is_success())
            .cloned()
            .collect()
    }

    /// Get requests to a specific domain
    pub fn requests_to_domain(&self, domain: &str) -> Vec<NetworkEvent> {
        let domain_lower = domain.to_lowercase();
        self.events
            .read()
            .iter()
            .filter(|e| {
                e.request
                    .url
                    .to_lowercase()
                    .contains(&domain_lower)
            })
            .cloned()
            .collect()
    }

    /// Get unique URLs
    pub fn unique_urls(&self) -> Vec<String> {
        let mut urls: Vec<String> = self
            .events
            .read()
            .iter()
            .map(|e| e.request.url.clone())
            .collect();
        urls.sort();
        urls.dedup();
        urls
    }

    /// Get unique domains
    pub fn unique_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .events
            .read()
            .iter()
            .filter_map(|e| {
                url::Url::parse(&e.request.url)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
            })
            .collect();
        domains.sort();
        domains.dedup();
        domains
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }

    /// Export events as JSON
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.events())
    }

    /// Get HTTP client reference
    pub fn client(&self) -> &HttpClient {
        &self.client
    }

    /// Generate next event ID
    fn next_event_id(&self) -> String {
        let mut counter = self.event_counter.write();
        *counter += 1;
        format!("evt_{}", *counter)
    }

    /// Store an event (with max limit)
    fn store_event(&self, event: NetworkEvent) {
        let mut events = self.events.write();
        if events.len() >= self.max_events {
            events.remove(0);
        }
        events.push(event);
    }
}

impl Clone for NetworkInterceptor {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            events: self.events.clone(),
            event_counter: self.event_counter.clone(),
            on_request: self.on_request.clone(),
            on_response: self.on_response.clone(),
            max_events: self.max_events,
            capture_bodies: self.capture_bodies,
            max_body_size: self.max_body_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interceptor_creation() {
        let client = HttpClient::new().unwrap();
        let interceptor = NetworkInterceptor::new(client);
        assert_eq!(interceptor.event_count(), 0);
    }
}
