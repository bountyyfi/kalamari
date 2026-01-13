// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Browser and Page API
//!
//! High-level API for headless browser operations.

mod browser;
mod page;
mod config;
mod crawler;
mod form;
mod iframe;
mod pdf;

pub use browser::Browser;
pub use page::Page;
pub use config::{BrowserConfig, PageConfig, ResourceType};
pub use crawler::{Crawler, CrawlResult, CrawlConfig};
pub use form::{Form, FormField, FormSubmitter};
pub use iframe::{Frame, FrameTree, FrameHandler, XSS_HOOK_SCRIPT};
pub use pdf::{PrintToPdfOptions, PdfGenerator, ReportFormat, create_pdf_generator};
