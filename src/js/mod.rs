// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript runtime using boa_engine
//!
//! Provides JavaScript execution with DOM bindings and XSS detection hooks.

mod runtime;
mod value;
mod bindings;
mod dom_api;
mod timers;

pub use runtime::{JsRuntime, JsRuntimeConfig, ConsoleMessage, ConsoleLevel};
pub use value::JsValue;
pub use bindings::DomBindings;
pub use dom_api::{DomApiInstaller, MutationObserverOptions};
pub use timers::{TimerQueue, TimerEntry, JsIdleConfig, JsIdleResult};
