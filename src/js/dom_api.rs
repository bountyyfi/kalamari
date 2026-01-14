// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Full DOM API bindings for JavaScript runtime
//!
//! Implements browser-compatible DOM APIs that Lonkero's XSS scanner expects.

use std::sync::Arc;

use boa_engine::context::ContextBuilder;
use boa_engine::object::builtins::JsFunction;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsObject, JsValue, NativeFunction};
use parking_lot::RwLock;

use crate::dom::Document;
use crate::xss::{XssTrigger, XssTriggerType};

/// DOM API installer - adds full DOM API to JS context
pub struct DomApiInstaller {
    document: Arc<RwLock<Option<Document>>>,
    xss_triggers: Arc<RwLock<Vec<XssTrigger>>>,
    mutation_callbacks: Arc<RwLock<Vec<MutationCallback>>>,
    current_url: Arc<RwLock<Option<String>>>,
}

/// Mutation callback storage
#[derive(Clone)]
pub struct MutationCallback {
    pub callback_id: u64,
    pub target_selector: Option<String>,
    pub options: MutationObserverOptions,
}

/// MutationObserver options
#[derive(Clone, Default)]
pub struct MutationObserverOptions {
    pub child_list: bool,
    pub attributes: bool,
    pub character_data: bool,
    pub subtree: bool,
    pub attribute_old_value: bool,
    pub character_data_old_value: bool,
    pub attribute_filter: Vec<String>,
}

impl DomApiInstaller {
    /// Create a new DOM API installer
    pub fn new(
        document: Arc<RwLock<Option<Document>>>,
        xss_triggers: Arc<RwLock<Vec<XssTrigger>>>,
        current_url: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            document,
            xss_triggers,
            mutation_callbacks: Arc::new(RwLock::new(Vec::new())),
            current_url,
        }
    }

    /// Install all DOM APIs into the context
    pub fn install(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        self.install_document_api(context)?;
        self.install_element_api(context)?;
        self.install_mutation_observer(context)?;
        self.install_dom_parser(context)?;
        self.install_event_api(context)?;
        self.install_storage_api(context)?;
        self.install_xhr_api(context)?;
        self.install_fetch_api(context)?;
        Ok(())
    }

    /// Install document API
    fn install_document_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let document_obj = JsObject::default();
        let xss_triggers = self.xss_triggers.clone();
        let current_url = self.current_url.clone();
        let doc = self.document.clone();

        // document.createElement
        let create_element = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let tag = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "div".to_string());

            // Return a mock element object
            let element = create_mock_element(ctx, &tag)
                .map_err(|e| boa_engine::JsError::from_opaque(JsValue::from(js_string!(e.to_string()))))?;
            Ok(element.into())
        });
        document_obj
            .set(js_string!("createElement"), create_element.to_js_function(context.realm()), false, context)
            .ok();

        // document.createTextNode
        let create_text = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let text = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            let node = JsObject::default();
            node.set(js_string!("nodeType"), JsValue::Integer(3), false, ctx).ok();
            node.set(js_string!("textContent"), JsValue::from(js_string!(text.clone())), false, ctx).ok();
            node.set(js_string!("nodeValue"), JsValue::from(js_string!(text)), false, ctx).ok();
            Ok(node.into())
        });
        document_obj
            .set(js_string!("createTextNode"), create_text.to_js_function(context.realm()), false, context)
            .ok();

        // document.getElementById - returns null (DOM queries not supported in JS execution context)
        let get_by_id = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
            // DOM queries are handled at the Page level, not in JS context
            Ok(JsValue::null())
        });
        document_obj
            .set(js_string!("getElementById"), get_by_id.to_js_function(context.realm()), false, context)
            .ok();

        // document.querySelector - returns null (DOM queries handled at Page level)
        let query_selector = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
            Ok(JsValue::null())
        });
        document_obj
            .set(js_string!("querySelector"), query_selector.to_js_function(context.realm()), false, context)
            .ok();

        // document.querySelectorAll - returns empty array (DOM queries handled at Page level)
        let query_all = NativeFunction::from_fn_ptr(|_, _args, ctx| {
            Ok(JsValue::from(boa_engine::object::builtins::JsArray::new(ctx)))
        });
        document_obj
            .set(js_string!("querySelectorAll"), query_all.to_js_function(context.realm()), false, context)
            .ok();

        // document.write - XSS sink! Throws error with XSS marker for detection
        let doc_write = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let html = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            // Throw XSS marker error for document.write detection
            Err(boa_engine::JsError::from_opaque(
                JsValue::from(js_string!(format!("XSS_DOCWRITE:{}", html)))
            ))
        });
        document_obj
            .set(js_string!("write"), doc_write.to_js_function(context.realm()), false, context)
            .ok();
        // Create separate function for writeln
        let doc_writeln = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let html = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            Err(boa_engine::JsError::from_opaque(
                JsValue::from(js_string!(format!("XSS_DOCWRITE:{}", html)))
            ))
        });
        document_obj
            .set(js_string!("writeln"), doc_writeln.to_js_function(context.realm()), false, context)
            .ok();

        // document.cookie
        document_obj.set(js_string!("cookie"), JsValue::from(js_string!("")), false, context).ok();

        // document.domain
        let domain = current_url
            .read()
            .as_ref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        document_obj.set(js_string!("domain"), JsValue::from(js_string!(domain)), false, context).ok();

        // document.URL
        let url_str = current_url.read().clone().unwrap_or_default();
        document_obj.set(js_string!("URL"), JsValue::from(js_string!(url_str.clone())), false, context).ok();
        document_obj.set(js_string!("documentURI"), JsValue::from(js_string!(url_str)), false, context).ok();

        // document.referrer
        document_obj.set(js_string!("referrer"), JsValue::from(js_string!("")), false, context).ok();

        // document.body / document.head (mock elements)
        let body = create_mock_element(context, "body")?;
        let head = create_mock_element(context, "head")?;
        document_obj.set(js_string!("body"), JsValue::from(body), false, context).ok();
        document_obj.set(js_string!("head"), JsValue::from(head), false, context).ok();

        // document.documentElement
        let html = create_mock_element(context, "html")?;
        document_obj.set(js_string!("documentElement"), JsValue::from(html), false, context).ok();

        // Register document globally
        context
            .register_global_property(js_string!("document"), document_obj, Attribute::all())
            .ok();

        Ok(())
    }

    /// Install Element prototype methods
    fn install_element_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // Element methods are added to mock elements when created
        Ok(())
    }

    /// Install MutationObserver
    /// Provides a stub implementation for MutationObserver API compatibility
    fn install_mutation_observer(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // MutationObserver constructor - creates observer objects without actual DOM observation
        // This is sufficient for security testing where we're focused on XSS detection
        let mutation_observer_ctor = NativeFunction::from_fn_ptr(|_, _args, ctx| {
            let observer = JsObject::default();

            // observe method - no-op stub
            let observe_fn = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
                Ok(JsValue::undefined())
            });
            observer.set(js_string!("observe"), observe_fn.to_js_function(ctx.realm()), false, ctx).ok();

            // disconnect method
            let disconnect_fn = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });
            observer.set(js_string!("disconnect"), disconnect_fn.to_js_function(ctx.realm()), false, ctx).ok();

            // takeRecords method - returns empty array
            let take_records = NativeFunction::from_fn_ptr(|_, _, ctx| {
                Ok(JsValue::from(boa_engine::object::builtins::JsArray::new(ctx)))
            });
            observer.set(js_string!("takeRecords"), take_records.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(observer.into())
        });

        context
            .register_global_builtin_callable(js_string!("MutationObserver"), 1, mutation_observer_ctor)
            .ok();

        Ok(())
    }

    /// Install DOMParser
    fn install_dom_parser(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let dom_parser_ctor = NativeFunction::from_fn_ptr(|_, _, ctx| {
            let parser = JsObject::default();

            // parseFromString method
            let parse_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
                // Return mock document
                let doc = JsObject::default();
                let html_elem = create_mock_element(ctx, "html")
                    .map_err(|e| boa_engine::JsError::from_opaque(JsValue::from(js_string!(e.to_string()))))?;
                doc.set(js_string!("documentElement"), JsValue::from(html_elem), false, ctx).ok();
                Ok(doc.into())
            });
            parser.set(js_string!("parseFromString"), parse_fn.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(parser.into())
        });

        context
            .register_global_builtin_callable(js_string!("DOMParser"), 0, dom_parser_ctor)
            .ok();

        Ok(())
    }

    /// Install Event API
    fn install_event_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // Event constructor
        let event_ctor = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let event_type = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "event".to_string());

            let event = JsObject::default();
            event.set(js_string!("type"), JsValue::from(js_string!(event_type)), false, ctx).ok();
            event.set(js_string!("bubbles"), JsValue::Boolean(false), false, ctx).ok();
            event.set(js_string!("cancelable"), JsValue::Boolean(false), false, ctx).ok();
            event.set(js_string!("defaultPrevented"), JsValue::Boolean(false), false, ctx).ok();

            let prevent_default = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });
            event.set(js_string!("preventDefault"), prevent_default.to_js_function(ctx.realm()), false, ctx).ok();

            let stop_propagation = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });
            event.set(js_string!("stopPropagation"), stop_propagation.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(event.into())
        });

        context
            .register_global_builtin_callable(js_string!("Event"), 1, event_ctor)
            .ok();

        // CustomEvent - create separate constructor
        let custom_event_ctor = NativeFunction::from_fn_ptr(|_, args, ctx| {
            let event_type = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "customevent".to_string());

            let event = JsObject::default();
            event.set(js_string!("type"), JsValue::from(js_string!(event_type)), false, ctx).ok();
            event.set(js_string!("bubbles"), JsValue::Boolean(false), false, ctx).ok();
            event.set(js_string!("cancelable"), JsValue::Boolean(false), false, ctx).ok();
            event.set(js_string!("defaultPrevented"), JsValue::Boolean(false), false, ctx).ok();
            event.set(js_string!("detail"), JsValue::null(), false, ctx).ok();

            let prevent_default = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
            event.set(js_string!("preventDefault"), prevent_default.to_js_function(ctx.realm()), false, ctx).ok();

            let stop_propagation = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
            event.set(js_string!("stopPropagation"), stop_propagation.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(event.into())
        });
        context
            .register_global_builtin_callable(js_string!("CustomEvent"), 2, custom_event_ctor)
            .ok();

        Ok(())
    }

    /// Install localStorage/sessionStorage
    /// Provides stub implementations for Storage API compatibility in security testing
    fn install_storage_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // Create storage objects with basic stubs
        // Note: Storage is not persistent between executions - this is intentional for security testing
        fn create_storage(ctx: &mut Context) -> JsObject {
            let storage = JsObject::default();

            // getItem - returns null (no persistent storage)
            let get_item = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
                Ok(JsValue::null())
            });

            // setItem - no-op
            let set_item = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
                Ok(JsValue::undefined())
            });

            // removeItem - no-op
            let remove_item = NativeFunction::from_fn_ptr(|_, _args, _ctx| {
                Ok(JsValue::undefined())
            });

            // clear - no-op
            let clear = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });

            // key - returns null
            let key = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::null())
            });

            storage.set(js_string!("getItem"), get_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("setItem"), set_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("removeItem"), remove_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("clear"), clear.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("key"), key.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("length"), JsValue::Integer(0), false, ctx).ok();

            storage
        }

        let local_storage = create_storage(context);
        let session_storage = create_storage(context);

        context
            .register_global_property(js_string!("localStorage"), local_storage, Attribute::all())
            .ok();
        context
            .register_global_property(js_string!("sessionStorage"), session_storage, Attribute::all())
            .ok();

        Ok(())
    }

    /// Install XMLHttpRequest
    /// Provides a stub implementation for XMLHttpRequest API compatibility
    fn install_xhr_api(&self, _context: &mut Context) -> Result<(), crate::error::Error> {
        let xhr_ctor = NativeFunction::from_fn_ptr(|_, _, ctx| {
            let xhr = JsObject::default();

            xhr.set(js_string!("readyState"), JsValue::Integer(0), false, ctx).ok();
            xhr.set(js_string!("status"), JsValue::Integer(0), false, ctx).ok();
            xhr.set(js_string!("statusText"), JsValue::from(js_string!("")), false, ctx).ok();
            xhr.set(js_string!("responseText"), JsValue::from(js_string!("")), false, ctx).ok();
            xhr.set(js_string!("responseXML"), JsValue::null(), false, ctx).ok();

            // open method
            let open = NativeFunction::from_fn_ptr(|this, args, ctx| {
                let method = args
                    .first()
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_else(|| "GET".to_string());
                let url = args
                    .get(1)
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();

                if let Some(obj) = this.as_object() {
                    obj.set(js_string!("_method"), JsValue::from(js_string!(method)), false, ctx).ok();
                    obj.set(js_string!("_url"), JsValue::from(js_string!(url)), false, ctx).ok();
                    obj.set(js_string!("readyState"), JsValue::Integer(1), false, ctx).ok();
                }
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("open"), open.to_js_function(ctx.realm()), false, ctx).ok();

            // send method
            let send = NativeFunction::from_fn_ptr(|this, _args, ctx| {
                if let Some(obj) = this.as_object() {
                    obj.set(js_string!("readyState"), JsValue::Integer(4), false, ctx).ok();
                    obj.set(js_string!("status"), JsValue::Integer(200), false, ctx).ok();
                    obj.set(js_string!("statusText"), JsValue::from(js_string!("OK")), false, ctx).ok();
                }
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("send"), send.to_js_function(ctx.realm()), false, ctx).ok();

            // setRequestHeader
            let set_header = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("setRequestHeader"), set_header.to_js_function(ctx.realm()), false, ctx).ok();

            // getResponseHeader
            let get_header = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::null())
            });
            xhr.set(js_string!("getResponseHeader"), get_header.to_js_function(ctx.realm()), false, ctx).ok();

            // getAllResponseHeaders
            let get_all_headers = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::from(js_string!("")))
            });
            xhr.set(js_string!("getAllResponseHeaders"), get_all_headers.to_js_function(ctx.realm()), false, ctx).ok();

            // abort
            let abort = NativeFunction::from_fn_ptr(|_, _, _| {
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("abort"), abort.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(xhr.into())
        });

        _context
            .register_global_builtin_callable(js_string!("XMLHttpRequest"), 0, xhr_ctor)
            .ok();

        Ok(())
    }

    /// Install fetch API
    /// Provides a stub implementation for fetch API compatibility
    fn install_fetch_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // fetch returns a Promise-like object
        let fetch_fn = NativeFunction::from_fn_ptr(|_, _args, ctx| {
            // Return a promise-like object
            let promise = JsObject::default();

            let then_fn = NativeFunction::from_fn_ptr(|_, args, ctx| {
                // Mock response
                let response = JsObject::default();
                response.set(js_string!("ok"), JsValue::Boolean(true), false, ctx).ok();
                response.set(js_string!("status"), JsValue::Integer(200), false, ctx).ok();

                let text_fn = NativeFunction::from_fn_ptr(|_, _, ctx| {
                    let inner_promise = JsObject::default();
                    let inner_then = NativeFunction::from_fn_ptr(|_, args, ctx| {
                        if let Some(callback) = args.first().and_then(|v| v.as_callable()) {
                            callback.call(&JsValue::undefined(), &[JsValue::from(js_string!(""))], ctx).ok();
                        }
                        Ok(JsValue::undefined())
                    });
                    inner_promise.set(js_string!("then"), inner_then.to_js_function(ctx.realm()), false, ctx).ok();
                    Ok(inner_promise.into())
                });
                response.set(js_string!("text"), text_fn.to_js_function(ctx.realm()), false, ctx).ok();

                let json_fn = NativeFunction::from_fn_ptr(|_, _, ctx| {
                    let inner_promise = JsObject::default();
                    let inner_then = NativeFunction::from_fn_ptr(|_, args, ctx| {
                        if let Some(callback) = args.first().and_then(|v| v.as_callable()) {
                            callback.call(&JsValue::undefined(), &[JsObject::default().into()], ctx).ok();
                        }
                        Ok(JsValue::undefined())
                    });
                    inner_promise.set(js_string!("then"), inner_then.to_js_function(ctx.realm()), false, ctx).ok();
                    Ok(inner_promise.into())
                });
                response.set(js_string!("json"), json_fn.to_js_function(ctx.realm()), false, ctx).ok();

                // Call the callback with response
                if let Some(callback) = args.first().and_then(|v| v.as_callable()) {
                    callback.call(&JsValue::undefined(), &[response.into()], ctx).ok();
                }

                Ok(JsValue::undefined())
            });
            promise.set(js_string!("then"), then_fn.to_js_function(ctx.realm()), false, ctx).ok();

            let catch_fn = NativeFunction::from_fn_ptr(|this, _, _| {
                Ok(this.clone())
            });
            promise.set(js_string!("catch"), catch_fn.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(promise.into())
        });

        context
            .register_global_builtin_callable(js_string!("fetch"), 2, fetch_fn)
            .ok();

        Ok(())
    }
}

/// Create a mock element object
fn create_mock_element(ctx: &mut Context, tag: &str) -> Result<JsObject, crate::error::Error> {
    let element = JsObject::default();

    element.set(js_string!("tagName"), JsValue::from(js_string!(tag.to_uppercase())), false, ctx).ok();
    element.set(js_string!("nodeName"), JsValue::from(js_string!(tag.to_uppercase())), false, ctx).ok();
    element.set(js_string!("nodeType"), JsValue::Integer(1), false, ctx).ok();
    element.set(js_string!("innerHTML"), JsValue::from(js_string!("")), false, ctx).ok();
    element.set(js_string!("outerHTML"), JsValue::from(js_string!(format!("<{0}></{0}>", tag))), false, ctx).ok();
    element.set(js_string!("textContent"), JsValue::from(js_string!("")), false, ctx).ok();
    element.set(js_string!("className"), JsValue::from(js_string!("")), false, ctx).ok();
    element.set(js_string!("id"), JsValue::from(js_string!("")), false, ctx).ok();

    // children array
    let children = boa_engine::object::builtins::JsArray::new(ctx);
    element.set(js_string!("children"), JsValue::from(children.clone()), false, ctx).ok();
    element.set(js_string!("childNodes"), JsValue::from(children), false, ctx).ok();

    // parentNode/Element
    element.set(js_string!("parentNode"), JsValue::null(), false, ctx).ok();
    element.set(js_string!("parentElement"), JsValue::null(), false, ctx).ok();

    // getAttribute
    let get_attr = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::null())
    });
    element.set(js_string!("getAttribute"), get_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // setAttribute
    let set_attr = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("setAttribute"), set_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // removeAttribute
    let remove_attr = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("removeAttribute"), remove_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // hasAttribute
    let has_attr = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::Boolean(false))
    });
    element.set(js_string!("hasAttribute"), has_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // appendChild
    let append_child = NativeFunction::from_fn_ptr(|_, args, _| {
        Ok(args.first().cloned().unwrap_or(JsValue::undefined()))
    });
    element.set(js_string!("appendChild"), append_child.to_js_function(ctx.realm()), false, ctx).ok();

    // removeChild
    let remove_child = NativeFunction::from_fn_ptr(|_, args, _| {
        Ok(args.first().cloned().unwrap_or(JsValue::undefined()))
    });
    element.set(js_string!("removeChild"), remove_child.to_js_function(ctx.realm()), false, ctx).ok();

    // insertBefore
    let insert_before = NativeFunction::from_fn_ptr(|_, args, _| {
        Ok(args.first().cloned().unwrap_or(JsValue::undefined()))
    });
    element.set(js_string!("insertBefore"), insert_before.to_js_function(ctx.realm()), false, ctx).ok();

    // replaceChild
    let replace_child = NativeFunction::from_fn_ptr(|_, args, _| {
        Ok(args.first().cloned().unwrap_or(JsValue::undefined()))
    });
    element.set(js_string!("replaceChild"), replace_child.to_js_function(ctx.realm()), false, ctx).ok();

    // cloneNode
    let clone_node = NativeFunction::from_fn_ptr(|_, _, _ctx| {
        Ok(JsObject::default().into())
    });
    element.set(js_string!("cloneNode"), clone_node.to_js_function(ctx.realm()), false, ctx).ok();

    // addEventListener
    let add_event = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("addEventListener"), add_event.to_js_function(ctx.realm()), false, ctx).ok();

    // removeEventListener
    let remove_event = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("removeEventListener"), remove_event.to_js_function(ctx.realm()), false, ctx).ok();

    // dispatchEvent
    let dispatch = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::Boolean(true))
    });
    element.set(js_string!("dispatchEvent"), dispatch.to_js_function(ctx.realm()), false, ctx).ok();

    // querySelector/querySelectorAll
    let query = NativeFunction::from_fn_ptr(|_, _, _| {
        Ok(JsValue::null())
    });
    element.set(js_string!("querySelector"), query.to_js_function(ctx.realm()), false, ctx).ok();

    let query_all = NativeFunction::from_fn_ptr(|_, _, ctx| {
        Ok(JsValue::from(boa_engine::object::builtins::JsArray::new(ctx)))
    });
    element.set(js_string!("querySelectorAll"), query_all.to_js_function(ctx.realm()), false, ctx).ok();

    // classList
    let class_list = JsObject::default();
    let add_class = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    class_list.set(js_string!("add"), add_class.to_js_function(ctx.realm()), false, ctx).ok();
    let remove_class = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    class_list.set(js_string!("remove"), remove_class.to_js_function(ctx.realm()), false, ctx).ok();
    let toggle_class = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    class_list.set(js_string!("toggle"), toggle_class.to_js_function(ctx.realm()), false, ctx).ok();
    let contains = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::Boolean(false)));
    class_list.set(js_string!("contains"), contains.to_js_function(ctx.realm()), false, ctx).ok();
    element.set(js_string!("classList"), JsValue::from(class_list), false, ctx).ok();

    // style object
    let style = JsObject::default();
    element.set(js_string!("style"), JsValue::from(style), false, ctx).ok();

    // focus/blur/click
    let focus_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    element.set(js_string!("focus"), focus_fn.to_js_function(ctx.realm()), false, ctx).ok();
    let blur_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    element.set(js_string!("blur"), blur_fn.to_js_function(ctx.realm()), false, ctx).ok();
    let click_fn = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    element.set(js_string!("click"), click_fn.to_js_function(ctx.realm()), false, ctx).ok();

    Ok(element)
}

/// Create JS element from DOM Element
fn create_element_from_dom(
    ctx: &mut Context,
    elem: &crate::dom::Element,
) -> Result<JsObject, crate::error::Error> {
    let element = create_mock_element(ctx, &elem.local_name())?;

    // Set actual values from DOM
    element.set(js_string!("tagName"), JsValue::from(js_string!(elem.tag_name())), false, ctx).ok();
    element.set(js_string!("innerHTML"), JsValue::from(js_string!(elem.inner_html())), false, ctx).ok();
    element.set(js_string!("outerHTML"), JsValue::from(js_string!(elem.outer_html())), false, ctx).ok();
    element.set(js_string!("textContent"), JsValue::from(js_string!(elem.text_content())), false, ctx).ok();

    if let Some(id) = elem.id() {
        element.set(js_string!("id"), JsValue::from(js_string!(id)), false, ctx).ok();
    }

    let class = elem.get_attribute("class").unwrap_or_default();
    element.set(js_string!("className"), JsValue::from(js_string!(class)), false, ctx).ok();

    Ok(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_element() {
        let mut context = Context::default();
        let elem = create_mock_element(&mut context, "div").unwrap();
        assert!(elem.get("tagName", &mut context).is_ok());
    }
}
