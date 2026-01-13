// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript runtime using boa_engine
//!
//! Provides JavaScript execution with DOM bindings and XSS detection hooks.

mod runtime;
mod value;
mod bindings;

pub use runtime::JsRuntime;
pub use value::JsValue;
pub use bindings::DomBindings;
