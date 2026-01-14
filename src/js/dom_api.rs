// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Full DOM API bindings for JavaScript runtime
//!
//! Implements browser-compatible DOM APIs that Lonkero's XSS scanner expects.

use std::sync::Arc;

use boa_engine::context::ContextBuilder;
use boa_engine::object::builtins::JsFunction;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsObject, JsResult, JsValue, NativeFunction, Source};
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
        let create_element = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let tag = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "div".to_string());

            // Return a mock element object
            let element = create_mock_element(ctx, &tag)?;
            Ok(element.into())
        });
        document_obj
            .set(js_string!("createElement"), create_element.to_js_function(context.realm()), false, context)
            .ok();

        // document.createTextNode
        let create_text = NativeFunction::from_copy_closure(|_, args, ctx| {
            let text = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            let node = JsObject::default();
            node.set(js_string!("nodeType"), 3, false, ctx).ok();
            node.set(js_string!("textContent"), text.clone(), false, ctx).ok();
            node.set(js_string!("nodeValue"), text, false, ctx).ok();
            Ok(node.into())
        });
        document_obj
            .set(js_string!("createTextNode"), create_text.to_js_function(context.realm()), false, context)
            .ok();

        // document.getElementById
        let doc_clone = self.document.clone();
        let get_by_id = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let id = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            // Try to get from actual document
            if let Some(ref doc) = *doc_clone.read() {
                if let Some(elem) = doc.get_element_by_id(&id) {
                    return Ok(create_element_from_dom(ctx, &elem)?.into());
                }
            }

            Ok(JsValue::null())
        });
        document_obj
            .set(js_string!("getElementById"), get_by_id.to_js_function(context.realm()), false, context)
            .ok();

        // document.querySelector
        let doc_clone2 = self.document.clone();
        let query_selector = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let selector = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            if let Some(ref doc) = *doc_clone2.read() {
                if let Some(elem) = doc.query_selector(&selector) {
                    return Ok(create_element_from_dom(ctx, &elem)?.into());
                }
            }

            Ok(JsValue::null())
        });
        document_obj
            .set(js_string!("querySelector"), query_selector.to_js_function(context.realm()), false, context)
            .ok();

        // document.querySelectorAll
        let doc_clone3 = self.document.clone();
        let query_all = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let selector = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            let array = boa_engine::object::builtins::JsArray::new(ctx);

            if let Some(ref doc) = *doc_clone3.read() {
                for (i, elem) in doc.query_selector_all(&selector).iter().enumerate() {
                    if let Ok(js_elem) = create_element_from_dom(ctx, elem) {
                        array.set(i as u32, js_elem, false, ctx).ok();
                    }
                }
            }

            Ok(array.into())
        });
        document_obj
            .set(js_string!("querySelectorAll"), query_all.to_js_function(context.realm()), false, context)
            .ok();

        // document.write - XSS sink!
        let triggers_write = xss_triggers.clone();
        let url_write = current_url.clone();
        let doc_write = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let html = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            // Record as XSS sink
            triggers_write.write().push(XssTrigger {
                trigger_type: XssTriggerType::DocumentWrite,
                payload: html,
                context: "document.write() called".to_string(),
                url: url_write.read().clone(),
            });

            Ok(JsValue::undefined())
        });
        document_obj
            .set(js_string!("write"), doc_write.to_js_function(context.realm()), false, context)
            .ok();
        document_obj
            .set(js_string!("writeln"), doc_write.to_js_function(context.realm()), false, context)
            .ok();

        // document.cookie
        document_obj.set(js_string!("cookie"), "", false, context).ok();

        // document.domain
        let domain = current_url
            .read()
            .as_ref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        document_obj.set(js_string!("domain"), domain, false, context).ok();

        // document.URL
        let url_str = current_url.read().clone().unwrap_or_default();
        document_obj.set(js_string!("URL"), url_str.clone(), false, context).ok();
        document_obj.set(js_string!("documentURI"), url_str.clone(), false, context).ok();

        // document.referrer
        document_obj.set(js_string!("referrer"), "", false, context).ok();

        // document.body / document.head (mock elements)
        let body = create_mock_element(context, "body")?;
        let head = create_mock_element(context, "head")?;
        document_obj.set(js_string!("body"), body, false, context).ok();
        document_obj.set(js_string!("head"), head, false, context).ok();

        // document.documentElement
        let html = create_mock_element(context, "html")?;
        document_obj.set(js_string!("documentElement"), html, false, context).ok();

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
    fn install_mutation_observer(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let callbacks = self.mutation_callbacks.clone();

        // MutationObserver constructor
        let mutation_observer_ctor = NativeFunction::from_copy_closure(move |_, args, ctx| {
            let observer = JsObject::default();

            // Store callback reference
            let callback_id = {
                let mut cbs = callbacks.write();
                let id = cbs.len() as u64;
                cbs.push(MutationCallback {
                    callback_id: id,
                    target_selector: None,
                    options: MutationObserverOptions::default(),
                });
                id
            };

            observer.set(js_string!("_callbackId"), callback_id as f64, false, ctx).ok();

            // observe method
            let observe_fn = NativeFunction::from_copy_closure(|_, args, ctx| {
                // In real implementation, would track what to observe
                Ok(JsValue::undefined())
            });
            observer.set(js_string!("observe"), observe_fn.to_js_function(ctx.realm()), false, ctx).ok();

            // disconnect method
            let disconnect_fn = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::undefined())
            });
            observer.set(js_string!("disconnect"), disconnect_fn.to_js_function(ctx.realm()), false, ctx).ok();

            // takeRecords method
            let take_records = NativeFunction::from_copy_closure(|_, _, ctx| {
                Ok(boa_engine::object::builtins::JsArray::new(ctx).into())
            });
            observer.set(js_string!("takeRecords"), take_records.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(observer.into())
        });

        context
            .register_global_builtin_callable("MutationObserver", 1, mutation_observer_ctor)
            .ok();

        Ok(())
    }

    /// Install DOMParser
    fn install_dom_parser(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let dom_parser_ctor = NativeFunction::from_copy_closure(|_, _, ctx| {
            let parser = JsObject::default();

            // parseFromString method
            let parse_fn = NativeFunction::from_copy_closure(|_, args, ctx| {
                let html = args
                    .first()
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();

                // Return mock document
                let doc = JsObject::default();
                doc.set(js_string!("documentElement"), create_mock_element(ctx, "html")?, false, ctx).ok();
                Ok(doc.into())
            });
            parser.set(js_string!("parseFromString"), parse_fn.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(parser.into())
        });

        context
            .register_global_builtin_callable("DOMParser", 0, dom_parser_ctor)
            .ok();

        Ok(())
    }

    /// Install Event API
    fn install_event_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // Event constructor
        let event_ctor = NativeFunction::from_copy_closure(|_, args, ctx| {
            let event_type = args
                .first()
                .map(|v| v.to_string(ctx))
                .transpose()?
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "event".to_string());

            let event = JsObject::default();
            event.set(js_string!("type"), event_type, false, ctx).ok();
            event.set(js_string!("bubbles"), false, false, ctx).ok();
            event.set(js_string!("cancelable"), false, false, ctx).ok();
            event.set(js_string!("defaultPrevented"), false, false, ctx).ok();

            let prevent_default = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::undefined())
            });
            event.set(js_string!("preventDefault"), prevent_default.to_js_function(ctx.realm()), false, ctx).ok();

            let stop_propagation = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::undefined())
            });
            event.set(js_string!("stopPropagation"), stop_propagation.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(event.into())
        });

        context
            .register_global_builtin_callable("Event", 1, event_ctor)
            .ok();

        // CustomEvent
        context
            .register_global_builtin_callable("CustomEvent", 2, event_ctor)
            .ok();

        Ok(())
    }

    /// Install localStorage/sessionStorage
    fn install_storage_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let create_storage = |ctx: &mut Context| -> JsObject {
            let storage = JsObject::default();
            let data = Arc::new(RwLock::new(std::collections::HashMap::<String, String>::new()));

            let data_get = data.clone();
            let get_item = NativeFunction::from_copy_closure(move |_, args, ctx| {
                let key = args
                    .first()
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();

                Ok(data_get
                    .read()
                    .get(&key)
                    .map(|v| JsValue::from(v.clone()))
                    .unwrap_or(JsValue::null()))
            });

            let data_set = data.clone();
            let set_item = NativeFunction::from_copy_closure(move |_, args, ctx| {
                let key = args
                    .first()
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                let value = args
                    .get(1)
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();

                data_set.write().insert(key, value);
                Ok(JsValue::undefined())
            });

            let data_remove = data.clone();
            let remove_item = NativeFunction::from_copy_closure(move |_, args, ctx| {
                let key = args
                    .first()
                    .map(|v| v.to_string(ctx))
                    .transpose()?
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();

                data_remove.write().remove(&key);
                Ok(JsValue::undefined())
            });

            let data_clear = data.clone();
            let clear = NativeFunction::from_copy_closure(move |_, _, _| {
                data_clear.write().clear();
                Ok(JsValue::undefined())
            });

            storage.set(js_string!("getItem"), get_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("setItem"), set_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("removeItem"), remove_item.to_js_function(ctx.realm()), false, ctx).ok();
            storage.set(js_string!("clear"), clear.to_js_function(ctx.realm()), false, ctx).ok();

            storage
        };

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
    fn install_xhr_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        let xss_triggers = self.xss_triggers.clone();

        let xhr_ctor = NativeFunction::from_copy_closure(move |_, _, ctx| {
            let xhr = JsObject::default();

            xhr.set(js_string!("readyState"), 0, false, ctx).ok();
            xhr.set(js_string!("status"), 0, false, ctx).ok();
            xhr.set(js_string!("statusText"), "", false, ctx).ok();
            xhr.set(js_string!("responseText"), "", false, ctx).ok();
            xhr.set(js_string!("responseXML"), JsValue::null(), false, ctx).ok();

            // open method
            let open = NativeFunction::from_copy_closure(|this, args, ctx| {
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
                    obj.set(js_string!("_method"), method, false, ctx).ok();
                    obj.set(js_string!("_url"), url, false, ctx).ok();
                    obj.set(js_string!("readyState"), 1, false, ctx).ok();
                }
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("open"), open.to_js_function(ctx.realm()), false, ctx).ok();

            // send method
            let send = NativeFunction::from_copy_closure(|this, args, ctx| {
                if let Some(obj) = this.as_object() {
                    obj.set(js_string!("readyState"), 4, false, ctx).ok();
                    obj.set(js_string!("status"), 200, false, ctx).ok();
                    obj.set(js_string!("statusText"), "OK", false, ctx).ok();
                }
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("send"), send.to_js_function(ctx.realm()), false, ctx).ok();

            // setRequestHeader
            let set_header = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("setRequestHeader"), set_header.to_js_function(ctx.realm()), false, ctx).ok();

            // getResponseHeader
            let get_header = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::null())
            });
            xhr.set(js_string!("getResponseHeader"), get_header.to_js_function(ctx.realm()), false, ctx).ok();

            // getAllResponseHeaders
            let get_all_headers = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::from(""))
            });
            xhr.set(js_string!("getAllResponseHeaders"), get_all_headers.to_js_function(ctx.realm()), false, ctx).ok();

            // abort
            let abort = NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::undefined())
            });
            xhr.set(js_string!("abort"), abort.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(xhr.into())
        });

        context
            .register_global_builtin_callable("XMLHttpRequest", 0, xhr_ctor)
            .ok();

        Ok(())
    }

    /// Install fetch API
    fn install_fetch_api(&self, context: &mut Context) -> Result<(), crate::error::Error> {
        // fetch is async - stub it
        let fetch_fn = NativeFunction::from_copy_closure(|_, args, ctx| {
            // Return a promise-like object
            let promise = JsObject::default();

            let then_fn = NativeFunction::from_copy_closure(|_, args, ctx| {
                // Mock response
                let response = JsObject::default();
                response.set(js_string!("ok"), true, false, ctx).ok();
                response.set(js_string!("status"), 200, false, ctx).ok();

                let text_fn = NativeFunction::from_copy_closure(|_, _, ctx| {
                    let inner_promise = JsObject::default();
                    let inner_then = NativeFunction::from_copy_closure(|_, args, ctx| {
                        if let Some(callback) = args.first().and_then(|v| v.as_callable()) {
                            callback.call(&JsValue::undefined(), &[JsValue::from("")], ctx).ok();
                        }
                        Ok(JsValue::undefined())
                    });
                    inner_promise.set(js_string!("then"), inner_then.to_js_function(ctx.realm()), false, ctx).ok();
                    Ok(inner_promise.into())
                });
                response.set(js_string!("text"), text_fn.to_js_function(ctx.realm()), false, ctx).ok();

                let json_fn = NativeFunction::from_copy_closure(|_, _, ctx| {
                    let inner_promise = JsObject::default();
                    let inner_then = NativeFunction::from_copy_closure(|_, args, ctx| {
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

            let catch_fn = NativeFunction::from_copy_closure(|this, _, _| {
                Ok(this.clone())
            });
            promise.set(js_string!("catch"), catch_fn.to_js_function(ctx.realm()), false, ctx).ok();

            Ok(promise.into())
        });

        context
            .register_global_builtin_callable("fetch", 2, fetch_fn)
            .ok();

        Ok(())
    }
}

/// Create a mock element object
fn create_mock_element(ctx: &mut Context, tag: &str) -> Result<JsObject, crate::error::Error> {
    let element = JsObject::default();

    element.set(js_string!("tagName"), tag.to_uppercase(), false, ctx).ok();
    element.set(js_string!("nodeName"), tag.to_uppercase(), false, ctx).ok();
    element.set(js_string!("nodeType"), 1, false, ctx).ok();
    element.set(js_string!("innerHTML"), "", false, ctx).ok();
    element.set(js_string!("outerHTML"), format!("<{0}></{0}>", tag), false, ctx).ok();
    element.set(js_string!("textContent"), "", false, ctx).ok();
    element.set(js_string!("className"), "", false, ctx).ok();
    element.set(js_string!("id"), "", false, ctx).ok();

    // children array
    let children = boa_engine::object::builtins::JsArray::new(ctx);
    element.set(js_string!("children"), children.clone(), false, ctx).ok();
    element.set(js_string!("childNodes"), children, false, ctx).ok();

    // parentNode/Element
    element.set(js_string!("parentNode"), JsValue::null(), false, ctx).ok();
    element.set(js_string!("parentElement"), JsValue::null(), false, ctx).ok();

    // getAttribute
    let get_attr = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::null())
    });
    element.set(js_string!("getAttribute"), get_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // setAttribute
    let set_attr = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("setAttribute"), set_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // removeAttribute
    element.set(js_string!("removeAttribute"), set_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // hasAttribute
    let has_attr = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::Boolean(false))
    });
    element.set(js_string!("hasAttribute"), has_attr.to_js_function(ctx.realm()), false, ctx).ok();

    // appendChild
    let append_child = NativeFunction::from_copy_closure(|_, args, _| {
        Ok(args.first().cloned().unwrap_or(JsValue::undefined()))
    });
    element.set(js_string!("appendChild"), append_child.to_js_function(ctx.realm()), false, ctx).ok();

    // removeChild
    element.set(js_string!("removeChild"), append_child.to_js_function(ctx.realm()), false, ctx).ok();

    // insertBefore
    element.set(js_string!("insertBefore"), append_child.to_js_function(ctx.realm()), false, ctx).ok();

    // replaceChild
    element.set(js_string!("replaceChild"), append_child.to_js_function(ctx.realm()), false, ctx).ok();

    // cloneNode
    let clone_node = NativeFunction::from_copy_closure(move |_, _, ctx| {
        Ok(JsObject::default().into())
    });
    element.set(js_string!("cloneNode"), clone_node.to_js_function(ctx.realm()), false, ctx).ok();

    // addEventListener
    let add_event = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::undefined())
    });
    element.set(js_string!("addEventListener"), add_event.to_js_function(ctx.realm()), false, ctx).ok();

    // removeEventListener
    element.set(js_string!("removeEventListener"), add_event.to_js_function(ctx.realm()), false, ctx).ok();

    // dispatchEvent
    let dispatch = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::Boolean(true))
    });
    element.set(js_string!("dispatchEvent"), dispatch.to_js_function(ctx.realm()), false, ctx).ok();

    // querySelector/querySelectorAll
    let query = NativeFunction::from_copy_closure(|_, _, _| {
        Ok(JsValue::null())
    });
    element.set(js_string!("querySelector"), query.to_js_function(ctx.realm()), false, ctx).ok();

    let query_all = NativeFunction::from_copy_closure(|_, _, ctx| {
        Ok(boa_engine::object::builtins::JsArray::new(ctx).into())
    });
    element.set(js_string!("querySelectorAll"), query_all.to_js_function(ctx.realm()), false, ctx).ok();

    // classList
    let class_list = JsObject::default();
    let add_class = NativeFunction::from_copy_closure(|_, _, _| Ok(JsValue::undefined()));
    class_list.set(js_string!("add"), add_class.to_js_function(ctx.realm()), false, ctx).ok();
    class_list.set(js_string!("remove"), add_class.to_js_function(ctx.realm()), false, ctx).ok();
    class_list.set(js_string!("toggle"), add_class.to_js_function(ctx.realm()), false, ctx).ok();
    let contains = NativeFunction::from_copy_closure(|_, _, _| Ok(JsValue::Boolean(false)));
    class_list.set(js_string!("contains"), contains.to_js_function(ctx.realm()), false, ctx).ok();
    element.set(js_string!("classList"), class_list, false, ctx).ok();

    // style object
    let style = JsObject::default();
    element.set(js_string!("style"), style, false, ctx).ok();

    // focus/blur
    let noop = NativeFunction::from_copy_closure(|_, _, _| Ok(JsValue::undefined()));
    element.set(js_string!("focus"), noop.to_js_function(ctx.realm()), false, ctx).ok();
    element.set(js_string!("blur"), noop.to_js_function(ctx.realm()), false, ctx).ok();
    element.set(js_string!("click"), noop.to_js_function(ctx.realm()), false, ctx).ok();

    Ok(element)
}

/// Create JS element from DOM Element
fn create_element_from_dom(
    ctx: &mut Context,
    elem: &crate::dom::Element,
) -> Result<JsObject, crate::error::Error> {
    let element = create_mock_element(ctx, &elem.local_name())?;

    // Set actual values from DOM
    element.set(js_string!("tagName"), elem.tag_name(), false, ctx).ok();
    element.set(js_string!("innerHTML"), elem.inner_html(), false, ctx).ok();
    element.set(js_string!("outerHTML"), elem.outer_html(), false, ctx).ok();
    element.set(js_string!("textContent"), elem.text_content(), false, ctx).ok();

    if let Some(id) = elem.id() {
        element.set(js_string!("id"), id, false, ctx).ok();
    }

    let class = elem.get_attribute("class").unwrap_or_default();
    element.set(js_string!("className"), class, false, ctx).ok();

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
