// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Security analysis modules
//!
//! - CSP analysis and bypass detection
//! - SRI checking
//! - DOM clobbering detection

mod csp;
mod sri;
mod clobbering;

pub use csp::{CspAnalyzer, CspAnalysis, CspBypass, extract_csp_from_html};
pub use sri::{SriChecker, SriViolation, SriViolationType};
pub use clobbering::{DomClobberDetector, DomClobberResult, ClobberedElement};
