// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! CSS Selector parsing and matching
//!
//! Simplified CSS selector implementation for DOM queries.

use crate::error::{Error, Result};

use super::node::Node;

/// A parsed CSS selector
#[derive(Debug, Clone)]
pub struct Selector {
    parts: Vec<SelectorPart>,
    combinator: Option<Combinator>,
    next: Option<Box<Selector>>,
}

/// Combinator between selector parts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combinator {
    /// Descendant (space)
    Descendant,
    /// Child (>)
    Child,
    /// Adjacent sibling (+)
    AdjacentSibling,
    /// General sibling (~)
    GeneralSibling,
}

/// A part of a selector
#[derive(Debug, Clone)]
pub enum SelectorPart {
    /// Universal selector (*)
    Universal,
    /// Tag name
    Tag(String),
    /// ID selector (#id)
    Id(String),
    /// Class selector (.class)
    Class(String),
    /// Attribute selector ([attr], [attr=value], etc.)
    Attribute(AttributeSelector),
    /// Pseudo-class (:first-child, etc.)
    PseudoClass(PseudoClass),
}

/// Attribute selector
#[derive(Debug, Clone)]
pub struct AttributeSelector {
    pub name: String,
    pub operator: Option<AttributeOperator>,
    pub value: Option<String>,
    pub case_insensitive: bool,
}

/// Attribute selector operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeOperator {
    /// [attr=value] - exact match
    Equals,
    /// [attr~=value] - word in space-separated list
    Includes,
    /// [attr|=value] - exact or prefix with hyphen
    DashMatch,
    /// [attr^=value] - starts with
    Prefix,
    /// [attr$=value] - ends with
    Suffix,
    /// [attr*=value] - contains substring
    Substring,
}

/// Pseudo-class selectors
#[derive(Debug, Clone)]
pub enum PseudoClass {
    FirstChild,
    LastChild,
    NthChild(NthExpr),
    NthLastChild(NthExpr),
    FirstOfType,
    LastOfType,
    NthOfType(NthExpr),
    OnlyChild,
    OnlyOfType,
    Empty,
    Not(Box<Selector>),
    Has(Box<Selector>),
    Is(Vec<Selector>),
    Where(Vec<Selector>),
    Checked,
    Disabled,
    Enabled,
    Required,
    Optional,
    Root,
}

/// An+B expression for :nth-* selectors
#[derive(Debug, Clone)]
pub struct NthExpr {
    pub a: i32,
    pub b: i32,
}

impl Selector {
    /// Parse a CSS selector string
    pub fn parse(selector: &str) -> Result<Self> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(Error::Selector("Empty selector".into()));
        }

        // Simple parser - handles basic selectors
        let mut parser = SelectorParser::new(selector);
        parser.parse()
    }

    /// Check if a node matches this selector
    pub fn matches(&self, node: &Node) -> bool {
        // Check all parts match
        for part in &self.parts {
            if !Self::part_matches(part, node) {
                return false;
            }
        }

        // TODO: Handle combinators for complex selectors
        true
    }

    /// Check if a selector part matches
    fn part_matches(part: &SelectorPart, node: &Node) -> bool {
        match part {
            SelectorPart::Universal => true,
            SelectorPart::Tag(tag) => node
                .local_name()
                .map(|n| n.eq_ignore_ascii_case(tag))
                .unwrap_or(false),
            SelectorPart::Id(id) => node
                .get_attribute("id")
                .map(|n| n == *id)
                .unwrap_or(false),
            SelectorPart::Class(class) => node
                .get_attribute("class")
                .map(|c| c.split_whitespace().any(|c| c == class))
                .unwrap_or(false),
            SelectorPart::Attribute(attr) => Self::attribute_matches(attr, node),
            SelectorPart::PseudoClass(pseudo) => Self::pseudo_matches(pseudo, node),
        }
    }

    /// Check if attribute selector matches
    fn attribute_matches(attr: &AttributeSelector, node: &Node) -> bool {
        let value = match node.get_attribute(&attr.name) {
            Some(v) => v,
            None => return attr.operator.is_none() && attr.value.is_none(),
        };

        let (Some(op), Some(target)) = (&attr.operator, &attr.value) else {
            return true; // Just checking existence
        };

        let (value, target) = if attr.case_insensitive {
            (value.to_lowercase(), target.to_lowercase())
        } else {
            (value, target.clone())
        };

        match op {
            AttributeOperator::Equals => value == target,
            AttributeOperator::Includes => value.split_whitespace().any(|w| w == target),
            AttributeOperator::DashMatch => value == target || value.starts_with(&format!("{}-", target)),
            AttributeOperator::Prefix => value.starts_with(&target),
            AttributeOperator::Suffix => value.ends_with(&target),
            AttributeOperator::Substring => value.contains(&target),
        }
    }

    /// Check if pseudo-class matches
    fn pseudo_matches(pseudo: &PseudoClass, node: &Node) -> bool {
        match pseudo {
            PseudoClass::FirstChild => node.prev_sibling().is_none(),
            PseudoClass::LastChild => node.next_sibling().is_none(),
            PseudoClass::OnlyChild => {
                node.prev_sibling().is_none() && node.next_sibling().is_none()
            }
            PseudoClass::Empty => node.children().is_empty(),
            PseudoClass::Checked => node.has_attribute("checked"),
            PseudoClass::Disabled => node.has_attribute("disabled"),
            PseudoClass::Enabled => !node.has_attribute("disabled"),
            PseudoClass::Required => node.has_attribute("required"),
            PseudoClass::Optional => !node.has_attribute("required"),
            PseudoClass::Not(sel) => !sel.matches(node),
            PseudoClass::Has(sel) => {
                // Check if any descendant matches
                node.children().iter().any(|child| {
                    sel.matches(child)
                        || child
                            .children()
                            .iter()
                            .any(|grandchild| sel.matches(grandchild))
                })
            }
            PseudoClass::Is(selectors) | PseudoClass::Where(selectors) => {
                selectors.iter().any(|sel| sel.matches(node))
            }
            PseudoClass::NthChild(expr) => {
                let mut index = 1;
                let mut sibling = node.prev_sibling();
                while sibling.is_some() {
                    index += 1;
                    sibling = sibling.unwrap().prev_sibling();
                }
                expr.matches(index)
            }
            _ => true, // Unimplemented pseudo-classes match by default
        }
    }
}

impl NthExpr {
    /// Check if an index matches this expression
    pub fn matches(&self, index: i32) -> bool {
        if self.a == 0 {
            return index == self.b;
        }

        let diff = index - self.b;
        if self.a > 0 {
            diff >= 0 && diff % self.a == 0
        } else {
            diff <= 0 && diff % self.a == 0
        }
    }

    /// Parse an An+B expression
    pub fn parse(expr: &str) -> Option<Self> {
        let expr = expr.trim().to_lowercase();
        match expr.as_str() {
            "odd" => return Some(Self { a: 2, b: 1 }),
            "even" => return Some(Self { a: 2, b: 0 }),
            _ => {}
        }

        // Try parsing as number
        if let Ok(n) = expr.parse::<i32>() {
            return Some(Self { a: 0, b: n });
        }

        // Parse An+B format
        if let Some((a_part, b_part)) = expr.split_once('n') {
            let a = match a_part.trim() {
                "" | "+" => 1,
                "-" => -1,
                s => s.parse().ok()?,
            };
            let b = if b_part.is_empty() {
                0
            } else {
                b_part.trim().parse().ok()?
            };
            return Some(Self { a, b });
        }

        None
    }
}

/// Simple selector parser
struct SelectorParser {
    input: Vec<char>,
    pos: usize,
}

impl SelectorParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    fn parse(&mut self) -> Result<Selector> {
        let mut parts = Vec::new();

        while self.pos < self.input.len() {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                break;
            }

            match self.peek() {
                Some('#') => {
                    self.advance();
                    let id = self.read_identifier()?;
                    parts.push(SelectorPart::Id(id));
                }
                Some('.') => {
                    self.advance();
                    let class = self.read_identifier()?;
                    parts.push(SelectorPart::Class(class));
                }
                Some('[') => {
                    parts.push(SelectorPart::Attribute(self.parse_attribute()?));
                }
                Some(':') => {
                    parts.push(SelectorPart::PseudoClass(self.parse_pseudo()?));
                }
                Some('*') => {
                    self.advance();
                    parts.push(SelectorPart::Universal);
                }
                Some(',') | Some('>') | Some('+') | Some('~') => {
                    break; // Combinator - stop here
                }
                Some(c) if c.is_alphabetic() || c == '_' || c == '-' => {
                    let tag = self.read_identifier()?;
                    parts.push(SelectorPart::Tag(tag.to_lowercase()));
                }
                _ => break,
            }
        }

        if parts.is_empty() {
            return Err(Error::Selector("Invalid selector".into()));
        }

        Ok(Selector {
            parts,
            combinator: None,
            next: None,
        })
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek();
        self.pos += 1;
        c
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if !c.is_whitespace() {
                break;
            }
            self.advance();
        }
    }

    fn read_identifier(&mut self) -> Result<String> {
        let mut result = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                result.push(c);
                self.advance();
            } else {
                break;
            }
        }
        if result.is_empty() {
            return Err(Error::Selector("Expected identifier".into()));
        }
        Ok(result)
    }

    fn parse_attribute(&mut self) -> Result<AttributeSelector> {
        self.advance(); // consume '['

        self.skip_whitespace();
        let name = self.read_identifier()?;
        self.skip_whitespace();

        let mut operator = None;
        let mut value = None;
        let mut case_insensitive = false;

        if let Some(c) = self.peek() {
            if c != ']' {
                // Parse operator
                let op = match c {
                    '=' => {
                        self.advance();
                        AttributeOperator::Equals
                    }
                    '~' => {
                        self.advance();
                        self.expect('=')?;
                        AttributeOperator::Includes
                    }
                    '|' => {
                        self.advance();
                        self.expect('=')?;
                        AttributeOperator::DashMatch
                    }
                    '^' => {
                        self.advance();
                        self.expect('=')?;
                        AttributeOperator::Prefix
                    }
                    '$' => {
                        self.advance();
                        self.expect('=')?;
                        AttributeOperator::Suffix
                    }
                    '*' => {
                        self.advance();
                        self.expect('=')?;
                        AttributeOperator::Substring
                    }
                    _ => return Err(Error::Selector(format!("Unknown operator: {}", c))),
                };
                operator = Some(op);

                self.skip_whitespace();
                value = Some(self.read_string_or_ident()?);
                self.skip_whitespace();

                // Check for case-insensitive flag
                if let Some('i') | Some('I') = self.peek() {
                    case_insensitive = true;
                    self.advance();
                    self.skip_whitespace();
                }
            }
        }

        self.expect(']')?;

        Ok(AttributeSelector {
            name,
            operator,
            value,
            case_insensitive,
        })
    }

    fn parse_pseudo(&mut self) -> Result<PseudoClass> {
        self.advance(); // consume ':'

        // Check for ::
        if let Some(':') = self.peek() {
            self.advance();
        }

        let name = self.read_identifier()?;

        let pseudo = match name.to_lowercase().as_str() {
            "first-child" => PseudoClass::FirstChild,
            "last-child" => PseudoClass::LastChild,
            "first-of-type" => PseudoClass::FirstOfType,
            "last-of-type" => PseudoClass::LastOfType,
            "only-child" => PseudoClass::OnlyChild,
            "only-of-type" => PseudoClass::OnlyOfType,
            "empty" => PseudoClass::Empty,
            "checked" => PseudoClass::Checked,
            "disabled" => PseudoClass::Disabled,
            "enabled" => PseudoClass::Enabled,
            "required" => PseudoClass::Required,
            "optional" => PseudoClass::Optional,
            "root" => PseudoClass::Root,
            "nth-child" => {
                let expr = self.parse_function_arg()?;
                PseudoClass::NthChild(NthExpr::parse(&expr).ok_or_else(|| {
                    Error::Selector("Invalid nth expression".into())
                })?)
            }
            "nth-last-child" => {
                let expr = self.parse_function_arg()?;
                PseudoClass::NthLastChild(NthExpr::parse(&expr).ok_or_else(|| {
                    Error::Selector("Invalid nth expression".into())
                })?)
            }
            "not" => {
                let inner = self.parse_function_arg()?;
                PseudoClass::Not(Box::new(Selector::parse(&inner)?))
            }
            _ => {
                // Unknown pseudo-class, skip any arguments
                if let Some('(') = self.peek() {
                    let _ = self.parse_function_arg();
                }
                PseudoClass::Empty // Default fallback
            }
        };

        Ok(pseudo)
    }

    fn parse_function_arg(&mut self) -> Result<String> {
        self.expect('(')?;
        let mut depth = 1;
        let mut result = String::new();

        while let Some(c) = self.advance() {
            match c {
                '(' => {
                    depth += 1;
                    result.push(c);
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    result.push(c);
                }
                _ => result.push(c),
            }
        }

        Ok(result.trim().to_string())
    }

    fn read_string_or_ident(&mut self) -> Result<String> {
        match self.peek() {
            Some('"') | Some('\'') => {
                let quote = self.advance().unwrap();
                let mut result = String::new();
                while let Some(c) = self.advance() {
                    if c == quote {
                        break;
                    }
                    if c == '\\' {
                        if let Some(escaped) = self.advance() {
                            result.push(escaped);
                        }
                    } else {
                        result.push(c);
                    }
                }
                Ok(result)
            }
            _ => self.read_identifier(),
        }
    }

    fn expect(&mut self, expected: char) -> Result<()> {
        match self.advance() {
            Some(c) if c == expected => Ok(()),
            Some(c) => Err(Error::Selector(format!(
                "Expected '{}', got '{}'",
                expected, c
            ))),
            None => Err(Error::Selector(format!("Expected '{}', got EOF", expected))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_parsing() {
        assert!(Selector::parse("div").is_ok());
        assert!(Selector::parse(".class").is_ok());
        assert!(Selector::parse("#id").is_ok());
        assert!(Selector::parse("[attr]").is_ok());
        assert!(Selector::parse("[attr=value]").is_ok());
        assert!(Selector::parse("div.class#id").is_ok());
    }

    #[test]
    fn test_nth_expr() {
        let odd = NthExpr::parse("odd").unwrap();
        assert!(odd.matches(1));
        assert!(!odd.matches(2));
        assert!(odd.matches(3));

        let even = NthExpr::parse("even").unwrap();
        assert!(!even.matches(1));
        assert!(even.matches(2));

        let expr = NthExpr::parse("2n+1").unwrap();
        assert!(expr.matches(1));
        assert!(!expr.matches(2));
        assert!(expr.matches(3));
    }
}
