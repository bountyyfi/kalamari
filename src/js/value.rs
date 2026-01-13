// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript value representation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JavaScript value type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JsValue {
    /// Undefined value
    Undefined,
    /// Null value
    Null,
    /// Boolean value
    Boolean(bool),
    /// Number value (JavaScript only has f64)
    Number(f64),
    /// String value
    String(String),
    /// Array value
    Array(Vec<JsValue>),
    /// Object value (simplified)
    Object,
    /// Function reference
    Function,
    /// Symbol
    Symbol(String),
}

impl JsValue {
    /// Check if value is truthy
    pub fn is_truthy(&self) -> bool {
        match self {
            JsValue::Undefined | JsValue::Null => false,
            JsValue::Boolean(b) => *b,
            JsValue::Number(n) => *n != 0.0 && !n.is_nan(),
            JsValue::String(s) => !s.is_empty(),
            JsValue::Array(_) | JsValue::Object | JsValue::Function => true,
            JsValue::Symbol(_) => true,
        }
    }

    /// Check if value is falsy
    pub fn is_falsy(&self) -> bool {
        !self.is_truthy()
    }

    /// Check if undefined
    pub fn is_undefined(&self) -> bool {
        matches!(self, JsValue::Undefined)
    }

    /// Check if null
    pub fn is_null(&self) -> bool {
        matches!(self, JsValue::Null)
    }

    /// Check if null or undefined
    pub fn is_nullish(&self) -> bool {
        matches!(self, JsValue::Undefined | JsValue::Null)
    }

    /// Check if boolean
    pub fn is_boolean(&self) -> bool {
        matches!(self, JsValue::Boolean(_))
    }

    /// Check if number
    pub fn is_number(&self) -> bool {
        matches!(self, JsValue::Number(_))
    }

    /// Check if string
    pub fn is_string(&self) -> bool {
        matches!(self, JsValue::String(_))
    }

    /// Check if array
    pub fn is_array(&self) -> bool {
        matches!(self, JsValue::Array(_))
    }

    /// Check if object
    pub fn is_object(&self) -> bool {
        matches!(self, JsValue::Object)
    }

    /// Check if function
    pub fn is_function(&self) -> bool {
        matches!(self, JsValue::Function)
    }

    /// Get as boolean
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            JsValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as number
    pub fn as_number(&self) -> Option<f64> {
        match self {
            JsValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as string
    pub fn as_string(&self) -> Option<&str> {
        match self {
            JsValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as array
    pub fn as_array(&self) -> Option<&Vec<JsValue>> {
        match self {
            JsValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Convert to string (JavaScript-style coercion)
    pub fn to_string_value(&self) -> String {
        match self {
            JsValue::Undefined => "undefined".to_string(),
            JsValue::Null => "null".to_string(),
            JsValue::Boolean(b) => b.to_string(),
            JsValue::Number(n) => {
                if n.is_nan() {
                    "NaN".to_string()
                } else if n.is_infinite() {
                    if *n > 0.0 {
                        "Infinity".to_string()
                    } else {
                        "-Infinity".to_string()
                    }
                } else {
                    n.to_string()
                }
            }
            JsValue::String(s) => s.clone(),
            JsValue::Array(a) => a
                .iter()
                .map(|v| v.to_string_value())
                .collect::<Vec<_>>()
                .join(","),
            JsValue::Object => "[object Object]".to_string(),
            JsValue::Function => "[function]".to_string(),
            JsValue::Symbol(s) => format!("Symbol({})", s),
        }
    }

    /// Convert to number (JavaScript-style coercion)
    pub fn to_number_value(&self) -> f64 {
        match self {
            JsValue::Undefined => f64::NAN,
            JsValue::Null => 0.0,
            JsValue::Boolean(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            JsValue::Number(n) => *n,
            JsValue::String(s) => s.trim().parse().unwrap_or(f64::NAN),
            JsValue::Array(a) => {
                if a.is_empty() {
                    0.0
                } else if a.len() == 1 {
                    a[0].to_number_value()
                } else {
                    f64::NAN
                }
            }
            JsValue::Object | JsValue::Function | JsValue::Symbol(_) => f64::NAN,
        }
    }

    /// Convert to boolean (JavaScript-style coercion)
    pub fn to_boolean_value(&self) -> bool {
        self.is_truthy()
    }

    /// Create from JSON value
    pub fn from_json(json: &serde_json::Value) -> Self {
        match json {
            serde_json::Value::Null => JsValue::Null,
            serde_json::Value::Bool(b) => JsValue::Boolean(*b),
            serde_json::Value::Number(n) => {
                JsValue::Number(n.as_f64().unwrap_or(f64::NAN))
            }
            serde_json::Value::String(s) => JsValue::String(s.clone()),
            serde_json::Value::Array(a) => {
                JsValue::Array(a.iter().map(JsValue::from_json).collect())
            }
            serde_json::Value::Object(_) => JsValue::Object,
        }
    }

    /// Convert to JSON value
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            JsValue::Undefined | JsValue::Null => serde_json::Value::Null,
            JsValue::Boolean(b) => serde_json::Value::Bool(*b),
            JsValue::Number(n) => {
                serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            }
            JsValue::String(s) => serde_json::Value::String(s.clone()),
            JsValue::Array(a) => {
                serde_json::Value::Array(a.iter().map(|v| v.to_json()).collect())
            }
            JsValue::Object | JsValue::Function | JsValue::Symbol(_) => {
                serde_json::Value::Object(serde_json::Map::new())
            }
        }
    }
}

impl Default for JsValue {
    fn default() -> Self {
        JsValue::Undefined
    }
}

impl From<bool> for JsValue {
    fn from(b: bool) -> Self {
        JsValue::Boolean(b)
    }
}

impl From<f64> for JsValue {
    fn from(n: f64) -> Self {
        JsValue::Number(n)
    }
}

impl From<i32> for JsValue {
    fn from(n: i32) -> Self {
        JsValue::Number(n as f64)
    }
}

impl From<String> for JsValue {
    fn from(s: String) -> Self {
        JsValue::String(s)
    }
}

impl From<&str> for JsValue {
    fn from(s: &str) -> Self {
        JsValue::String(s.to_string())
    }
}

impl std::fmt::Display for JsValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truthy_falsy() {
        assert!(JsValue::Boolean(true).is_truthy());
        assert!(JsValue::Number(1.0).is_truthy());
        assert!(JsValue::String("hello".into()).is_truthy());

        assert!(JsValue::Undefined.is_falsy());
        assert!(JsValue::Null.is_falsy());
        assert!(JsValue::Boolean(false).is_falsy());
        assert!(JsValue::Number(0.0).is_falsy());
        assert!(JsValue::String("".into()).is_falsy());
    }

    #[test]
    fn test_coercion() {
        assert_eq!(JsValue::Boolean(true).to_number_value(), 1.0);
        assert_eq!(JsValue::Null.to_number_value(), 0.0);
        assert_eq!(JsValue::String("42".into()).to_number_value(), 42.0);
    }
}
