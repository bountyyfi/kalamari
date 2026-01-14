// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript runtime implementation using boa_engine

use std::rc::Rc;
use std::sync::Arc;

use boa_engine::context::ContextBuilder;
use boa_engine::job::{FutureJob, JobQueue, NativeJob};
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsValue as BoaJsValue, NativeFunction, Source};
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
            .job_queue(Rc::new(SimpleJobQueue))
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
        Self::install_browser_globals(&mut context, current_url.clone())?;

        // Execute the code
        let result = context.eval(Source::from_bytes(code));

        match result {
            Ok(value) => Ok(Self::convert_value(&value, &mut context)),
            Err(e) => {
                let error_msg = e.to_string();
                let current_url_value = current_url.read().clone();

                // Parse XSS marker errors from our hooks
                if error_msg.contains("XSS_ALERT:") {
                    let payload = error_msg.replace("XSS_ALERT:", "");
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::Alert,
                        payload,
                        context: "alert() called".to_string(),
                        url: current_url_value,
                    });
                    return Ok(JsValue::Undefined);
                } else if error_msg.contains("XSS_CONFIRM:") {
                    let payload = error_msg.replace("XSS_CONFIRM:", "");
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::Confirm,
                        payload,
                        context: "confirm() called".to_string(),
                        url: current_url_value,
                    });
                    return Ok(JsValue::Boolean(false));
                } else if error_msg.contains("XSS_PROMPT:") {
                    let payload = error_msg.replace("XSS_PROMPT:", "");
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::Prompt,
                        payload,
                        context: "prompt() called".to_string(),
                        url: current_url_value,
                    });
                    return Ok(JsValue::Null);
                } else if error_msg.contains("XSS_EVAL:") {
                    let payload = error_msg.replace("XSS_EVAL:", "");
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::Eval,
                        payload,
                        context: "Suspicious eval() detected".to_string(),
                        url: current_url_value,
                    });
                    return Ok(JsValue::Undefined);
                } else if error_msg.contains("XSS_DOCWRITE:") {
                    let payload = error_msg.replace("XSS_DOCWRITE:", "");
                    xss_triggers.write().push(XssTrigger {
                        trigger_type: XssTriggerType::DocumentWrite,
                        payload,
                        context: "document.write() called".to_string(),
                        url: current_url_value,
                    });
                    return Ok(JsValue::Undefined);
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
    /// These hooks use simple closures that throw on XSS-related calls,
    /// which we catch and record as XSS triggers.
    fn install_xss_hooks(
        context: &mut Context,
        _triggers: Arc<RwLock<Vec<XssTrigger>>>,
        _current_url: Arc<RwLock<Option<String>>>,
    ) -> Result<()> {
        // alert() hook - throws a custom XSS marker error that we catch
        let alert_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            // Throw an error that includes XSS_ALERT marker for detection
            Err(boa_engine::JsError::from_opaque(
                BoaJsValue::from(js_string!(format!("XSS_ALERT:{}", msg)))
            ))
        });
        context
            .register_global_builtin_callable(js_string!("alert"), 1, alert_fn)
            .map_err(|e| Error::js(format!("Failed to register alert: {:?}", e)))?;

        // confirm() hook
        let confirm_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            Err(boa_engine::JsError::from_opaque(
                BoaJsValue::from(js_string!(format!("XSS_CONFIRM:{}", msg)))
            ))
        });
        context
            .register_global_builtin_callable(js_string!("confirm"), 1, confirm_fn)
            .map_err(|e| Error::js(format!("Failed to register confirm: {:?}", e)))?;

        // prompt() hook
        let prompt_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let msg = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            Err(boa_engine::JsError::from_opaque(
                BoaJsValue::from(js_string!(format!("XSS_PROMPT:{}", msg)))
            ))
        });
        context
            .register_global_builtin_callable(js_string!("prompt"), 2, prompt_fn)
            .map_err(|e| Error::js(format!("Failed to register prompt: {:?}", e)))?;

        // eval() - we let eval run but mark it in output
        let eval_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
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
                return Err(boa_engine::JsError::from_opaque(
                    BoaJsValue::from(js_string!(format!("XSS_EVAL:{}", code)))
                ));
            }

            // Execute the eval
            ctx.eval(Source::from_bytes(&code))
        });
        context
            .register_global_builtin_callable(js_string!("eval"), 1, eval_fn)
            .map_err(|e| Error::js(format!("Failed to register eval: {:?}", e)))?;

        Ok(())
    }

    /// Install console object
    /// Console output is not captured in this version - use browser-level logging instead
    fn install_console(
        context: &mut Context,
        _output: Arc<RwLock<Vec<ConsoleMessage>>>,
    ) -> Result<()> {
        // Create console object with no-op implementations
        // Console output capture is handled at a higher level if needed
        let console = boa_engine::JsObject::default();

        // console.log - no-op for security testing (we don't need console output)
        let log_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        console
            .set(js_string!("log"), log_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.log: {:?}", e)))?;

        // console.error
        let error_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        console
            .set(js_string!("error"), error_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.error: {:?}", e)))?;

        // console.warn
        let warn_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        console
            .set(js_string!("warn"), warn_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.warn: {:?}", e)))?;

        // console.info
        let info_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        console
            .set(js_string!("info"), info_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.info: {:?}", e)))?;

        // console.debug
        let debug_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        console
            .set(js_string!("debug"), debug_fn.to_js_function(context.realm()), false, context)
            .map_err(|e| Error::js(format!("Failed to set console.debug: {:?}", e)))?;

        // Register console globally
        context
            .register_global_property(js_string!("console"), console, Attribute::all())
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
                .set(js_string!("href"), BoaJsValue::from(js_string!(parsed.as_str())), false, context)
                .ok();
            location
                .set(js_string!("protocol"), BoaJsValue::from(js_string!(format!("{}:", parsed.scheme()))), false, context)
                .ok();
            location
                .set(js_string!("host"), BoaJsValue::from(js_string!(parsed.host_str().unwrap_or(""))), false, context)
                .ok();
            location
                .set(js_string!("hostname"), BoaJsValue::from(js_string!(parsed.host_str().unwrap_or(""))), false, context)
                .ok();
            location
                .set(js_string!("pathname"), BoaJsValue::from(js_string!(parsed.path())), false, context)
                .ok();
            location
                .set(js_string!("search"), BoaJsValue::from(js_string!(parsed.query().unwrap_or(""))), false, context)
                .ok();
            location
                .set(js_string!("hash"), BoaJsValue::from(js_string!(parsed.fragment().unwrap_or(""))), false, context)
                .ok();
            if let Some(port) = parsed.port() {
                location.set(js_string!("port"), BoaJsValue::from(js_string!(port.to_string())), false, context).ok();
            } else {
                location.set(js_string!("port"), BoaJsValue::from(js_string!("")), false, context).ok();
            }
            location
                .set(
                    js_string!("origin"),
                    BoaJsValue::from(js_string!(format!(
                        "{}://{}",
                        parsed.scheme(),
                        parsed.host_str().unwrap_or("")
                    ))),
                    false,
                    context,
                )
                .ok();
        }

        window.set(js_string!("location"), BoaJsValue::from(location.clone()), false, context).ok();

        // navigator object
        let navigator = boa_engine::JsObject::default();
        navigator
            .set(
                js_string!("userAgent"),
                BoaJsValue::from(js_string!("Kalamari/1.0 (Headless Browser)")),
                false,
                context,
            )
            .ok();
        navigator
            .set(js_string!("language"), BoaJsValue::from(js_string!("en-US")), false, context)
            .ok();
        navigator
            .set(js_string!("platform"), BoaJsValue::from(js_string!("Linux")), false, context)
            .ok();
        navigator
            .set(js_string!("cookieEnabled"), BoaJsValue::Boolean(true), false, context)
            .ok();
        window.set(js_string!("navigator"), BoaJsValue::from(navigator), false, context).ok();

        // Register globals
        context
            .register_global_property(js_string!("window"), window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property(js_string!("self"), window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property(js_string!("globalThis"), window.clone(), Attribute::all())
            .ok();
        context
            .register_global_property(js_string!("location"), location, Attribute::all())
            .ok();

        // setTimeout/setInterval stubs (no-op for now)
        let timeout_fn = NativeFunction::from_fn_ptr(|_, _, _| {
            Ok(BoaJsValue::Integer(0)) // Return stub timer ID
        });
        context
            .register_global_builtin_callable(js_string!("setTimeout"), 2, timeout_fn)
            .ok();

        let interval_fn = NativeFunction::from_fn_ptr(|_, _, _| {
            Ok(BoaJsValue::Integer(0)) // Return stub timer ID
        });
        context
            .register_global_builtin_callable(js_string!("setInterval"), 2, interval_fn)
            .ok();

        let clear_timeout_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        context
            .register_global_builtin_callable(js_string!("clearTimeout"), 1, clear_timeout_fn)
            .ok();
        let clear_interval_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(BoaJsValue::undefined()));
        context
            .register_global_builtin_callable(js_string!("clearInterval"), 1, clear_interval_fn)
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
