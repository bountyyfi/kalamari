// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! DOM engine for HTML parsing and manipulation
//!
//! Provides a DOM-like interface built on top of html5ever.

mod document;
mod element;
mod node;
mod parser;
mod selector;

pub use document::Document;
pub use element::Element;
pub use node::{Node, NodeId, NodeType};
pub use parser::parse_html;
pub use selector::Selector;
