// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript runtime implementation using boa_engine

use std::sync::Arc;

use boa_engine::context::ContextBuilder;
use boa_engine::job::{FutureJob, JobQueue, NativeJob};
use boa_engine::property::Attribute;
use boa_engine::{Context, JsResult, JsValue as BoaJsValue, NativeFunction, Source};
use parking_lot::RwLock;

use super::value::JsValue;
use crate::dom::Document;
use crate::error::{Error, Result};
use crate::xss::{XssTrigger, XssTriggerType};

/// JavaScript runtime configuration
#[derive(Debug, Clone)]
pub struct JsRuntimeConfig {
    /// Maximum execution time in milliseconds
    pub timeout_ms: u64,
    /// Enable strict mode
    pub strict_mode: bool,
    /// Enable XSS detection hooks
    pub xss_detection: bool,
    /// Console output capture
    pub capture_console: bool,
}

impl Default for JsRuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            strict_mode: false,
            xss_detection: true,
            capture_console: true,
        }
    }
}

/// JavaScript runtime with XSS detection
pub struct JsRuntime {
    config: JsRuntimeConfig,
    /// XSS triggers detected during execution
    xss_triggers: Arc<RwLock<Vec<XssTrigger>>>,
    /// Console output
    console_output: Arc<RwLock<Vec<ConsoleMessage>>>,
    /// Current document URL
    current_url: Arc<RwLock<Option<String>>>,
}

/// Console message type
#[derive(Debug, Clone)]
pub struct ConsoleMessage {
    pub level: ConsoleLevel,
    pub message: String,
}

/// Console log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleLevel {
    Log,
    Info,
    Warn,
    Error,
    Debug,
}

impl JsRuntime {
    /// Create a new JavaScript runtime
    pub fn new(config: JsRuntimeConfig) -> Self {
        Self {
            config,
            xss_triggers: Arc::new(RwLock::new(Vec::new())),
            console_output: Arc::new(RwLock::new(Vec::new())),
            current_url: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a runtime with default config
    pub fn default_runtime() -> Self {
        Self::new(JsRuntimeConfig::default())
    }

    /// Set the current URL for context
    pub fn set_url(&self, url: impl Into<String>) {
        *self.current_url.write() = Some(url.into());
    }

    /// Execute JavaScript code
    pub fn execute(&self, code: &str) -> Result<JsValue> {
        let xss_triggers = self.xss_triggers.clone();
        let console_output = self.console_output.clone();
        let current_url = self.current_url.clone();
        let xss_detection = self.config.xss_detection;
        let capture_console = self.config.capture_console;

        // Create a new context for each execution
        let mut context = ContextBuilder::new()
            .job_queue(SimpleJobQueue)
            .build()
            .map_err(|e| Error::js(format!("Failed to create JS context: {:?}", e)))?;

        // Install XSS detection hooks
        if xss_detection {
            Self::install_xss_hooks(&mut context, xss_triggers.clone(), current_url.clone())?;
        }

        // Install console
        if capture_console {
            Self::install_console(&mut context, console_output)?;
        }

        // Install basic browser globals
        Self::install_browser_globals(&mut context, current_url)?;

        // Execute the code
        let result = context.eval(Source::from_bytes(code));

        match result {
            Ok(value) => Ok(Self::convert_value(&value, &mut context)),
            Err(e) => {
                let error_msg = e.to_string();
                // Check if the error itself is an XSS indication
                if error_msg.contains("XSS") {
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::ErrorBased,
                        payload: code.to_string(),
                        context: error_msg.clone(),
                        url: None,
                    });
                }
                Err(Error::js(error_msg))
            }
        }
    }

    /// Execute JavaScript and check for XSS triggers
    pub fn execute_with_xss_check(&self, code: &str) -> Result<(JsValue, Vec<XssTrigger>)> {
        // Clear previous triggers
        self.xss_triggers.write().clear();

        let result = self.execute(code)?;
        let triggers = self.xss_triggers.read().clone();

        Ok((result, triggers))
    }

    /// Get all XSS triggers
    pub fn get_xss_triggers(&self) -> Vec<XssTrigger> {
        self.xss_triggers.read().clone()
    }

    /// Clear XSS triggers
    pub fn clear_xss_triggers(&self) {
        self.xss_triggers.write().clear();
    }

    /// Get console output
    pub fn get_console_output(&self) -> Vec<ConsoleMessage> {
        self.console_output.read().clone()
    }

    /// Clear console output
    pub fn clear_console(&self) {
        self.console_output.write().clear();
    }

    /// Install XSS detection hooks (alert, confirm, prompt, etc.)
    fn install_xss_hooks(
        context: &mut Context,
        triggers: Arc<RwLock<Vec<XssTrigger>>>,
        current_url: Arc<RwLock<Option<String>>>,
    ) -> Result<()> {
        // alert() hook
        let triggers_alert = triggers.clone();
        let url_alert = current_url.clone();
        let alert_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            triggers_alert.write().push(XssTrigger {
                trigger_type: XssTriggerType::Alert,
                payload: msg.clone(),
                context: "alert() called".to_string(),
                url: url_alert.read().clone(),
            });

            Ok(BoaJsValue::undefined())
        });
        context
            .register_global_builtin_callable("alert", 1, alert_fn)
            .map_err(|e| Error::js(format!("Failed to register alert: {:?}", e)))?;

        // confirm() hook
        let triggers_confirm = triggers.clone();
        let url_confirm = current_url.clone();
        let confirm_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            triggers_confirm.write().push(XssTrigger {
                trigger_type: XssTriggerType::Confirm,
                payload: msg,
                context: "confirm() called".to_string(),
                url: url_confirm.read().clone(),
            });

            // Return false (user "cancelled")
            Ok(BoaJsValue::Boolean(false))
        });
        context
            .register_global_builtin_callable("confirm", 1, confirm_fn)
            .map_err(|e| Error::js(format!("Failed to register confirm: {:?}", e)))?;

        // prompt() hook
        let triggers_prompt = triggers.clone();
        let url_prompt = current_url.clone();
        let prompt_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            triggers_prompt.write().push(XssTrigger {
                trigger_type: XssTriggerType::Prompt,
                payload: msg,
                context: "prompt() called".to_string(),
                url: url_prompt.read().clone(),
            });

            // Return null (user "cancelled")
            Ok(BoaJsValue::null())
        });
        context
            .register_global_builtin_callable("prompt", 2, prompt_fn)
            .map_err(|e| Error::js(format!("Failed to register prompt: {:?}", e)))?;

        // eval() wrapper to detect eval-based XSS
        let triggers_eval = triggers.clone();
        let url_eval = current_url.clone();
        let eval_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let code = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            // Check for suspicious eval content
            if code.contains("alert")
                || code.contains("document.cookie")
                || code.contains("<script")
            {
                triggers_eval.write().push(XssTrigger {
                    trigger_type: XssTriggerType::Eval,
                    payload: code.clone(),
                    context: "Suspicious eval() detected".to_string(),
                    url: url_eval.read().clone(),
                });
            }

            // Execute the eval
            ctx.eval(Source::from_bytes(&code))
        });
        context
            .register_global_builtin_callable("eval", 1, eval_fn)
            .map_err(|e| Error::js(format!("Failed to register eval: {:?}", e)))?;

        // Function constructor hook (another eval vector)
        // Note: This is a simplified version, full implementation would require more work

        Ok(())
    }

    /// Install console object
    fn install_console(
        context: &mut Context,
        output: Arc<RwLock<Vec<ConsoleMessage>>>,
    ) -> Result<()> {
        // Create console object
        let console = boa_engine::JsObject::default();

        // console.log
        let output_log = output.clone();
        let log_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .iter()
                .map(|v| {
                    v.to_string(ctx)
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_else(|_| "[object]".to_string())
                })
                .collect::<Vec<_>>()
                .join(" ");

            output_log.write().push(ConsoleMessage {
                level: ConsoleLevel::Log,
                message: msg,
            });

            Ok(BoaJsValue::undefined())
        });
        console
            .set("log", log_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.log: {:?}", e)))?;

        // console.error
        let output_error = output.clone();
        let error_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .iter()
                .map(|v| {
                    v.to_string(ctx)
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_else(|_| "[object]".to_string())
                })
                .collect::<Vec<_>>()
                .join(" ");

            output_error.write().push(ConsoleMessage {
                level: ConsoleLevel::Error,
                message: msg,
            });

            Ok(BoaJsValue::undefined())
        });
        console
            .set("error", error_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.error: {:?}", e)))?;

        // console.warn
        let output_warn = output.clone();
        let warn_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .iter()
                .map(|v| {
                    v.to_string(ctx)
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_else(|_| "[object]".to_string())
                })
                .collect::<Vec<_>>()
                .join(" ");

            output_warn.write().push(ConsoleMessage {
                level: ConsoleLevel::Warn,
                message: msg,
            });

            Ok(BoaJsValue::undefined())
        });
        console
            .set("warn", warn_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.warn: {:?}", e)))?;

        // console.info
        let output_info = output.clone();
        let info_fn = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let msg = args
                .iter()
                .map(|v| {
                    v.to_string(ctx)
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_else(|_| "[object]".to_string())
                })
                .collect::<Vec<_>>()
                .join(" ");

            output_info.write().push(ConsoleMessage {
                level: ConsoleLevel::Info,
                message: msg,
            });

            Ok(BoaJsValue::undefined())
        });
        console
            .set("info", info_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.info: {:?}", e)))?;

        // Register console globally
        context
            .register_global_property("console", console, Attribute::all())
            .map_err(|e| Error::js(format!("Failed to register console: {:?}", e)))?;

        Ok(())
    }

    /// Install basic browser globals
    fn install_browser_globals(
        context: &mut Context,
        current_url: Arc<RwLock<Option<String>>>,
    ) -> Result<()> {
        // window object (self-referential)
        let window = boa_engine::JsObject::default();

        // location object
        let location = boa_engine::JsObject::default();
        let url = current_url.read().clone().unwrap_or_default();

        if let Ok(parsed) = url::Url::parse(&url) {
            location
                .set("href", parsed.as_str(), false, context)
                .ok();
            location
                .set("protocol", format!("{}:", parsed.scheme()), false, context)
                .ok();
            location
                .set("host", parsed.host_str().unwrap_or(""), false, context)
                .ok();
            location
                .set("hostname", parsed.host_str().unwrap_or(""), false, context)
                .ok();
            location
                .set("pathname", parsed.path(), false, context)
                .ok();
            location
                .set("search", parsed.query().unwrap_or(""), false, context)
                .ok();
            location
                .set("hash", parsed.fragment().unwrap_or(""), false, context)
                .ok();
            if let Some(port) = parsed.port() {
                location.set("port", port.to_string(), false, context).ok();
            } else {
                location.set("port", "", false, context).ok();
            }
            location
                .set(
                    "origin",
                    format!(
                        "{}://{}",
                        parsed.scheme(),
                        parsed.host_str().unwrap_or("")
                    ),
                    false,
                    context,
                )
                .ok();
        }

        window.set("location", location.clone(), false, context).ok();

        // navigator object
        let navigator = boa_engine::JsObject::default();
        navigator
            .set(
                "userAgent",
                "Kalamari/1.0 (Headless Browser)",
                false,
                context,
            )
            .ok();
        navigator
            .set("language", "en-US", false, context)
            .ok();
        navigator
            .set("platform", "Linux", false, context)
            .ok();
        navigator
            .set("cookieEnabled", true, false, context)
            .ok();
        window.set("navigator", navigator, false, context).ok();

        // Register globals
        context
            .register_global_property("window", window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property("self", window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property("globalThis", window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property("location", location, Attribute::all())
            .ok();

        // setTimeout/setInterval stubs (no-op for now)
        let timeout_fn = NativeFunction::from_copy_closure(|_, _, _| {
            Ok(BoaJsValue::Integer(0)) // Return fake timer ID
        });
        context
            .register_global_builtin_callable("setTimeout", 2, timeout_fn)
            .ok();

        let interval_fn = NativeFunction::from_copy_closure(|_, _, _| {
            Ok(BoaJsValue::Integer(0)) // Return fake timer ID
        });
        context
            .register_global_builtin_callable("setInterval", 2, interval_fn)
            .ok();

        let clear_fn = NativeFunction::from_copy_closure(|_, _, _| Ok(BoaJsValue::undefined()));
        context
            .register_global_builtin_callable("clearTimeout", 1, clear_fn)
            .ok();
        context
            .register_global_builtin_callable("clearInterval", 1, clear_fn)
            .ok();

        Ok(())
    }

    /// Convert boa JsValue to our JsValue
    fn convert_value(value: &BoaJsValue, context: &mut Context) -> JsValue {
        if value.is_undefined() {
            JsValue::Undefined
        } else if value.is_null() {
            JsValue::Null
        } else if let Some(b) = value.as_boolean() {
            JsValue::Boolean(b)
        } else if let Some(n) = value.as_number() {
            JsValue::Number(n)
        } else if let Ok(s) = value.to_string(context) {
            JsValue::String(s.to_std_string_escaped())
        } else {
            JsValue::Object
        }
    }
}

/// Simple job queue for boa_engine (no async support)
struct SimpleJobQueue;

impl JobQueue for SimpleJobQueue {
    fn enqueue_promise_job(&self, _job: NativeJob, _context: &mut Context) {
        // Ignore promise jobs for now
    }

    fn enqueue_future_job(&self, _future: FutureJob, _context: &mut Context) {
        // Ignore future jobs
    }

    fn run_jobs(&self, _context: &mut Context) {
        // No-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_execution() {
        let runtime = JsRuntime::default_runtime();
        let result = runtime.execute("1 + 2").unwrap();
        assert_eq!(result, JsValue::Number(3.0));
    }

    #[test]
    fn test_xss_detection_alert() {
        let runtime = JsRuntime::default_runtime();
        let (_, triggers) = runtime.execute_with_xss_check("alert('XSS')").unwrap();
        assert!(!triggers.is_empty());
        assert_eq!(triggers[0].trigger_type, XssTriggerType::Alert);
    }

    #[test]
    fn test_console_capture() {
        let runtime = JsRuntime::default_runtime();
        runtime.execute("console.log('test message')").unwrap();
        let output = runtime.get_console_output();
        assert!(!output.is_empty());
        assert_eq!(output[0].message, "test message");
    }
}
