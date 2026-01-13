// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Network interception and monitoring
//!
//! Captures all network requests and responses for analysis.

mod interceptor;
mod event;
mod interceptor_trait;

pub use interceptor::NetworkInterceptor;
pub use event::{NetworkEvent, EventType, RequestInfo, ResponseInfo};
pub use interceptor_trait::{
    RequestInterceptor, InterceptAction, InterceptorChain,
    HeaderEntry, AuthHeaderInjector, RequestLogger,
    CookieCaptureInterceptor, CapturedCookie,
};
