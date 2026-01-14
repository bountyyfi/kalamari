// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! DOM sink detection for XSS analysis

use regex::Regex;
use serde::{Deserialize, Serialize};

/// DOM sink information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomSink {
    /// Sink type
    pub sink_type: SinkType,
    /// Line number where found
    pub line: Option<usize>,
    /// Column number
    pub column: Option<usize>,
    /// Code snippet around the sink
    pub snippet: String,
    /// Source that flows into sink (if detectable)
    pub source: Option<String>,
    /// Risk level (1-10)
    pub risk_level: u8,
}

/// Types of DOM sinks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SinkType {
    // Execution sinks (highest risk)
    /// eval() function
    Eval,
    /// Function constructor
    FunctionConstructor,
    /// setTimeout with string
    SetTimeoutString,
    /// setInterval with string
    SetIntervalString,

    // HTML manipulation sinks
    /// document.write()
    DocumentWrite,
    /// document.writeln()
    DocumentWriteln,
    /// innerHTML assignment
    InnerHtml,
    /// outerHTML assignment
    OuterHtml,
    /// insertAdjacentHTML()
    InsertAdjacentHtml,

    // URL/Navigation sinks
    /// location assignment
    LocationAssign,
    /// location.href assignment
    LocationHref,
    /// location.replace()
    LocationReplace,
    /// window.open()
    WindowOpen,

    // Other sinks
    /// jQuery html()
    JQueryHtml,
    /// jQuery append()
    JQueryAppend,
    /// React dangerouslySetInnerHTML
    ReactDangerousHtml,
    /// Angular bypassSecurityTrust
    AngularBypassSecurity,
    /// Vue v-html
    VueHtml,
}

impl SinkType {
    /// Get risk level for this sink type
    pub fn risk_level(&self) -> u8 {
        match self {
            SinkType::Eval => 10,
            SinkType::FunctionConstructor => 10,
            SinkType::SetTimeoutString => 9,
            SinkType::SetIntervalString => 9,
            SinkType::DocumentWrite => 9,
            SinkType::DocumentWriteln => 9,
            SinkType::InnerHtml => 8,
            SinkType::OuterHtml => 8,
            SinkType::InsertAdjacentHtml => 8,
            SinkType::LocationAssign => 7,
            SinkType::LocationHref => 7,
            SinkType::LocationReplace => 7,
            SinkType::WindowOpen => 6,
            SinkType::JQueryHtml => 8,
            SinkType::JQueryAppend => 7,
            SinkType::ReactDangerousHtml => 8,
            SinkType::AngularBypassSecurity => 9,
            SinkType::VueHtml => 8,
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            SinkType::Eval => "Direct JavaScript code execution via eval()",
            SinkType::FunctionConstructor => "JavaScript code execution via Function constructor",
            SinkType::SetTimeoutString => "Delayed code execution via setTimeout with string",
            SinkType::SetIntervalString => "Repeated code execution via setInterval with string",
            SinkType::DocumentWrite => "HTML injection via document.write()",
            SinkType::DocumentWriteln => "HTML injection via document.writeln()",
            SinkType::InnerHtml => "HTML injection via innerHTML assignment",
            SinkType::OuterHtml => "HTML injection via outerHTML assignment",
            SinkType::InsertAdjacentHtml => "HTML injection via insertAdjacentHTML()",
            SinkType::LocationAssign => "URL manipulation via location assignment",
            SinkType::LocationHref => "URL manipulation via location.href",
            SinkType::LocationReplace => "URL manipulation via location.replace()",
            SinkType::WindowOpen => "New window/tab opening via window.open()",
            SinkType::JQueryHtml => "HTML injection via jQuery .html()",
            SinkType::JQueryAppend => "HTML injection via jQuery .append()",
            SinkType::ReactDangerousHtml => "HTML injection via React dangerouslySetInnerHTML",
            SinkType::AngularBypassSecurity => "Security bypass in Angular",
            SinkType::VueHtml => "HTML injection via Vue v-html directive",
        }
    }
}

/// DOM source types (where user input can come from)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    /// location.hash
    LocationHash,
    /// location.search
    LocationSearch,
    /// location.href
    LocationHref,
    /// location.pathname
    LocationPathname,
    /// document.referrer
    DocumentReferrer,
    /// document.URL
    DocumentUrl,
    /// document.documentURI
    DocumentUri,
    /// window.name
    WindowName,
    /// document.cookie
    DocumentCookie,
    /// localStorage
    LocalStorage,
    /// sessionStorage
    SessionStorage,
    /// postMessage data
    PostMessage,
    /// WebSocket message
    WebSocketMessage,
}

impl SourceType {
    /// Get the JavaScript access pattern for this source
    pub fn pattern(&self) -> &'static str {
        match self {
            SourceType::LocationHash => r"location\.hash",
            SourceType::LocationSearch => r"location\.search",
            SourceType::LocationHref => r"location\.href",
            SourceType::LocationPathname => r"location\.pathname",
            SourceType::DocumentReferrer => r"document\.referrer",
            SourceType::DocumentUrl => r"document\.URL",
            SourceType::DocumentUri => r"document\.documentURI",
            SourceType::WindowName => r"window\.name",
            SourceType::DocumentCookie => r"document\.cookie",
            SourceType::LocalStorage => r"localStorage\.",
            SourceType::SessionStorage => r"sessionStorage\.",
            SourceType::PostMessage => r"\.data\b",  // In message event handler
            SourceType::WebSocketMessage => r"\.data\b",  // In WebSocket message handler
        }
    }
}

/// Analyzer for finding DOM sinks in JavaScript code
pub struct SinkAnalyzer {
    /// Compiled regex patterns for each sink type
    patterns: Vec<(SinkType, Regex)>,
    /// Source patterns
    source_patterns: Vec<(SourceType, Regex)>,
}

impl Default for SinkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SinkAnalyzer {
    /// Create a new sink analyzer
    pub fn new() -> Self {
        let patterns = vec![
            (SinkType::Eval, r"\beval\s*\("),
            (SinkType::FunctionConstructor, r"\bnew\s+Function\s*\("),
            (SinkType::SetTimeoutString, r#"\bsetTimeout\s*\(\s*['"`]"#),
            (SinkType::SetIntervalString, r#"\bsetInterval\s*\(\s*['"`]"#),
            (SinkType::DocumentWrite, r"\bdocument\.write\s*\("),
            (SinkType::DocumentWriteln, r"\bdocument\.writeln\s*\("),
            (SinkType::InnerHtml, r"\.innerHTML\s*="),
            (SinkType::OuterHtml, r"\.outerHTML\s*="),
            (SinkType::InsertAdjacentHtml, r"\.insertAdjacentHTML\s*\("),
            (SinkType::LocationAssign, r"\blocation\s*="),
            (SinkType::LocationHref, r"\blocation\.href\s*="),
            (SinkType::LocationReplace, r"\blocation\.replace\s*\("),
            (SinkType::WindowOpen, r"\bwindow\.open\s*\("),
            (SinkType::JQueryHtml, r"\$\([^)]*\)\.html\s*\("),
            (SinkType::JQueryAppend, r"\$\([^)]*\)\.append\s*\("),
            (SinkType::ReactDangerousHtml, r"dangerouslySetInnerHTML"),
            (SinkType::AngularBypassSecurity, r"bypassSecurityTrust"),
            (SinkType::VueHtml, r"v-html\s*="),
        ];

        let compiled_patterns: Vec<_> = patterns
            .into_iter()
            .filter_map(|(sink_type, pattern)| {
                Regex::new(pattern).ok().map(|r| (sink_type, r))
            })
            .collect();

        let source_patterns: Vec<_> = [
            SourceType::LocationHash,
            SourceType::LocationSearch,
            SourceType::LocationHref,
            SourceType::LocationPathname,
            SourceType::DocumentReferrer,
            SourceType::DocumentUrl,
            SourceType::DocumentUri,
            SourceType::WindowName,
            SourceType::DocumentCookie,
            SourceType::LocalStorage,
            SourceType::SessionStorage,
        ]
        .iter()
        .filter_map(|source| {
            Regex::new(source.pattern()).ok().map(|r| (*source, r))
        })
        .collect();

        Self {
            patterns: compiled_patterns,
            source_patterns,
        }
    }

    /// Analyze JavaScript code for sinks
    pub fn analyze(&self, code: &str) -> Vec<DomSink> {
        let mut sinks = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for (sink_type, pattern) in &self.patterns {
            for m in pattern.find_iter(code) {
                // Find line number
                let line_num = code[..m.start()].matches('\n').count() + 1;

                // Get snippet (surrounding context)
                let snippet = if line_num > 0 && line_num <= lines.len() {
                    lines[line_num - 1].trim().to_string()
                } else {
                    m.as_str().to_string()
                };

                // Check if any source flows into this area
                let source = self.find_source_in_context(code, m.start(), m.end());

                sinks.push(DomSink {
                    sink_type: *sink_type,
                    line: Some(line_num),
                    column: Some(m.start() - code[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0)),
                    snippet,
                    source,
                    risk_level: sink_type.risk_level(),
                });
            }
        }

        // Sort by risk level (highest first)
        sinks.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

        sinks
    }

    /// Find if any source is used near a sink
    fn find_source_in_context(&self, code: &str, start: usize, end: usize) -> Option<String> {
        // Look at surrounding code (100 chars before and after)
        let context_start = start.saturating_sub(100);
        let context_end = (end + 100).min(code.len());
        let context = &code[context_start..context_end];

        for (source_type, pattern) in &self.source_patterns {
            if pattern.is_match(context) {
                return Some(format!("{:?}", source_type));
            }
        }

        None
    }

    /// Check if code has any high-risk sinks
    pub fn has_high_risk_sinks(&self, code: &str) -> bool {
        self.analyze(code).iter().any(|s| s.risk_level >= 8)
    }

    /// Get sinks above a certain risk level
    pub fn sinks_above_risk(&self, code: &str, min_risk: u8) -> Vec<DomSink> {
        self.analyze(code)
            .into_iter()
            .filter(|s| s.risk_level >= min_risk)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sink_detection() {
        let analyzer = SinkAnalyzer::new();

        let code = r#"
            var userInput = location.hash.slice(1);
            document.getElementById('output').innerHTML = userInput;
        "#;

        let sinks = analyzer.analyze(code);
        assert!(!sinks.is_empty());
        assert!(sinks.iter().any(|s| s.sink_type == SinkType::InnerHtml));
    }

    #[test]
    fn test_eval_detection() {
        let analyzer = SinkAnalyzer::new();
        let code = "eval(userInput)";

        let sinks = analyzer.analyze(code);
        assert!(!sinks.is_empty());
        assert_eq!(sinks[0].sink_type, SinkType::Eval);
        assert_eq!(sinks[0].risk_level, 10);
    }

    #[test]
    fn test_source_detection() {
        let analyzer = SinkAnalyzer::new();

        let code = r#"
            var data = location.search;
            element.innerHTML = data;
        "#;

        let sinks = analyzer.analyze(code);
        assert!(!sinks.is_empty());
        // Should detect that location.search flows into innerHTML
        assert!(sinks.iter().any(|s| s.source.is_some()));
    }
}
