// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! HTTP client layer for Kalamari browser
//!
//! Provides a lightweight HTTP client with cookie management,
//! authentication support, and request/response interception.

mod client;
mod cookie;
mod request;
mod response;

pub use client::HttpClient;
pub use cookie::CookieJar;
pub use request::{Request, RequestBuilder};
pub use response::Response;

/// Default user agent string
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// Common HTTP headers
pub mod headers {
    pub const ACCEPT: &str = "accept";
    pub const ACCEPT_LANGUAGE: &str = "accept-language";
    pub const ACCEPT_ENCODING: &str = "accept-encoding";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const COOKIE: &str = "cookie";
    pub const SET_COOKIE: &str = "set-cookie";
    pub const USER_AGENT: &str = "user-agent";
    pub const REFERER: &str = "referer";
    pub const ORIGIN: &str = "origin";
    pub const AUTHORIZATION: &str = "authorization";
    pub const X_REQUESTED_WITH: &str = "x-requested-with";
}
