//! The object runtime: one thread, one QuickJS context, the browser's object
//! code loaded from memory, and hark's host functions installed under
//! `globalThis.__hark`.
//!
//! Module names are flat (`controller.js`, `store.js`, …) whether they come
//! from `js/vendor/` (pinned cbcl-bus bytes) or `js/hark/` (hark's shims for
//! the three browser-bound modules: `hash.js`, `cbcl-verifier.js`,
//! `sandbox.js`). The vendored files import each other as `./name.js`, which
//! the builtin resolver maps onto those names.
//!
//! Every glue export is `async` and returns JSON text or `null`, so the actor
//! drives each call the same way: call, run the pending jobs to completion,
//! decode. A rejected promise surfaces as [`ObjectsError::Failed`] carrying
//! the SDK's own message.

use std::time::Duration;

use rquickjs::loader::{BuiltinLoader, BuiltinResolver};
use rquickjs::{Context, Ctx, Exception, Function, Module, Object, Persistent, Promise, Runtime};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::{
    ActOutcome, AgentIdentity, CheckOutcome, Command, ObjectState, ObjectSummary, ObjectsClient,
    ObjectsError, OpenOutcome,
};
use crate::daemon::{AgentHandle, AgentStore};
use crate::object_transport::{HISTORY_LIMIT_MAX, history_request_frame};

/// The cbcl-bus files run unchanged (`js/VENDOR.json`).
pub(crate) fn vendored_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("cbcl-read.js", include_str!("js/vendor/cbcl-read.js")),
        ("controller.js", include_str!("js/vendor/controller.js")),
        ("dialects.js", include_str!("js/vendor/dialects.js")),
        ("emit.js", include_str!("js/vendor/emit.js")),
        (
            "object-address.js",
            include_str!("js/vendor/object-address.js"),
        ),
        ("object-sdk.js", include_str!("js/vendor/object-sdk.js")),
        ("projection.js", include_str!("js/vendor/projection.js")),
        (
            "resource-policy.js",
            include_str!("js/vendor/resource-policy.js"),
        ),
        ("store.js", include_str!("js/vendor/store.js")),
    ]
}

/// hark's own modules: host-backed replacements for the browser-bound ones,
/// and the glue that builds a controller per agent.
fn hark_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("hash.js", include_str!("js/hark/hash.js")),
        ("cbcl-verifier.js", include_str!("js/hark/cbcl-verifier.js")),
        ("sandbox.js", include_str!("js/hark/sandbox.js")),
        ("hark-objects.js", include_str!("js/hark/hark-objects.js")),
    ]
}

const PRELUDE: &str = include_str!("js/hark/prelude.js");

/// How long a history request raised by a controller holds its room's
/// in-flight slot (SPEC-086 CON-002); the same window the API uses.
const HISTORY_WINDOW: Duration = Duration::from_secs(5);

/// Start the runtime on its own thread. `tokio` is the daemon's runtime
/// handle: the host `send` and `history` functions block on it from the actor
/// thread, which is not a tokio worker, so that is permitted and cannot
/// starve the executor.
pub fn spawn(store: AgentStore, tokio: tokio::runtime::Handle) -> ObjectsClient {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("hark-objects".to_owned())
        .spawn(move || run(rx, store, tokio))
        .expect("the object runtime thread spawns");
    ObjectsClient::new(tx)
}

/// A runtime for tests and tools: `send` is answered by `on_send` and
/// `history` by `on_history` instead of a live agent store.
#[cfg(test)]
pub(crate) fn spawn_with_hooks(
    on_send: impl Fn(&str, &str) -> bool + Send + 'static,
    on_history: impl Fn(&str, &str) -> bool + Send + 'static,
) -> ObjectsClient {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("hark-objects-test".to_owned())
        .spawn(move || run_with(rx, Box::new(on_send), Box::new(on_history)))
        .expect("the object runtime thread spawns");
    ObjectsClient::new(tx)
}

type SendHook = Box<dyn Fn(&str, &str) -> bool + Send>;
type HistoryHook = Box<dyn Fn(&str, &str) -> bool + Send>;

fn run(rx: mpsc::UnboundedReceiver<Command>, store: AgentStore, tokio: tokio::runtime::Handle) {
    let send_store = store.clone();
    let send_tokio = tokio.clone();
    let on_send: SendHook = Box::new(move |agent: &str, canonical: &str| {
        let Ok(handle) = AgentHandle::new(agent.to_owned()) else {
            return false;
        };
        match send_tokio.block_on(send_store.send_outbound(&handle, canonical.to_owned())) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(agent, %error, "object action could not be sent");
                false
            }
        }
    });
    let on_history: HistoryHook = Box::new(move |agent: &str, room: &str| {
        let Ok(handle) = AgentHandle::new(agent.to_owned()) else {
            return false;
        };
        let outcome = tokio.block_on(async {
            let from = store.begin_history(&handle, room, HISTORY_WINDOW).await?;
            let frame = history_request_frame(room, HISTORY_LIMIT_MAX, &from);
            if let Err(error) = store.send_control_outbound(&handle, frame).await {
                store.end_history(&handle).await;
                return Err(error);
            }
            Ok(())
        });
        match outcome {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(agent, %error, "controller history request not sent");
                false
            }
        }
    });
    run_with(rx, on_send, on_history);
}

fn run_with(mut rx: mpsc::UnboundedReceiver<Command>, on_send: SendHook, on_history: HistoryHook) {
    let rt = Runtime::new().expect("QuickJS runtime");
    let mut resolver = BuiltinResolver::default();
    let mut loader = BuiltinLoader::default();
    for (name, source) in vendored_files().into_iter().chain(hark_files()) {
        resolver = resolver.with_module(name);
        loader = loader.with_module(name, source);
    }
    rt.set_loader(resolver, loader);
    let ctx = Context::full(&rt).expect("QuickJS context");

    let glue: Persistent<Object<'static>> = ctx.with(|ctx| {
        install_host(&ctx, on_send, on_history);
        ctx.eval::<(), _>(PRELUDE).expect("prelude evaluates");
        let module: Object = Module::import(&ctx, "hark-objects.js")
            .and_then(|promise| promise.finish())
            .unwrap_or_else(|error| {
                panic!("hark-objects.js fails to load: {}", describe(&ctx, error))
            });
        Persistent::save(&ctx, module)
    });

    while let Some(command) = rx.blocking_recv() {
        ctx.with(|ctx| {
            let module = glue.clone().restore(&ctx).expect("glue module restores");
            dispatch(&ctx, &module, command);
        });
    }
}

/// `globalThis.__hark`: the host functions the shims and glue call.
fn install_host<'js>(ctx: &Ctx<'js>, on_send: SendHook, on_history: HistoryHook) {
    let host = Object::new(ctx.clone()).expect("host object");
    let set = |name: &str, function: Function<'js>| {
        host.set(name, function).expect("host function installs");
    };
    set(
        "sha256",
        Function::new(ctx.clone(), |text: String| {
            format!("{:x}", Sha256::digest(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "parseMessage",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, text: String| {
            verdict(&ctx, cbcl_wasm::parse_message_bytes(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "verifyDialect",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, text: String| {
            verdict(&ctx, cbcl_wasm::verify_dialect_bytes(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "verifyShape",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, text: String| {
            verdict(&ctx, cbcl_wasm::verify_message_shape_bytes(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "verifyProtocol",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, text: String| {
            verdict(&ctx, cbcl_wasm::verify_protocol_bytes(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "messageHash",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, text: String| {
            verdict(&ctx, cbcl_wasm::message_hash_bytes(text.as_bytes()))
        })
        .unwrap(),
    );
    set(
        "send",
        Function::new(ctx.clone(), move |agent: String, canonical: String| {
            on_send(&agent, &canonical)
        })
        .unwrap(),
    );
    set(
        "history",
        Function::new(ctx.clone(), move |agent: String, room: String| {
            on_history(&agent, &room)
        })
        .unwrap(),
    );
    set(
        "log",
        Function::new(ctx.clone(), |level: String, message: String| {
            match level.as_str() {
                "error" => tracing::warn!(target: "hark::objects", "{message}"),
                "warn" => tracing::warn!(target: "hark::objects", "{message}"),
                _ => tracing::debug!(target: "hark::objects", "{message}"),
            }
        })
        .unwrap(),
    );
    ctx.globals().set("__hark", host).expect("host installs");
}

/// A cbcl-wasm verdict as the wasm-bindgen export delivers it to the browser:
/// the `Ok` text, or a thrown exception carrying the `Err` text.
fn verdict(ctx: &Ctx<'_>, result: Result<Vec<u8>, Vec<u8>>) -> rquickjs::Result<String> {
    match result {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(bytes) => Err(Exception::throw_message(
            ctx,
            &String::from_utf8_lossy(&bytes),
        )),
    }
}

/// The message (and stack) of the pending JavaScript exception behind `error`.
fn describe(ctx: &Ctx<'_>, error: rquickjs::Error) -> String {
    match error {
        rquickjs::Error::Exception => {
            let caught = ctx.catch();
            match caught.as_exception() {
                Some(exception) => {
                    let message = exception
                        .message()
                        .unwrap_or_else(|| "JavaScript exception".to_owned());
                    match exception.stack() {
                        Some(stack) if !stack.is_empty() => format!("{message}\n{stack}"),
                        _ => message,
                    }
                }
                None => caught
                    .as_string()
                    .and_then(|text| text.to_string().ok())
                    .unwrap_or_else(|| "JavaScript exception".to_owned()),
            }
        }
        other => other.to_string(),
    }
}

/// Call one glue export and run it to completion. Every export is `async`
/// and yields JSON text or `null`.
fn call<'js>(
    ctx: &Ctx<'js>,
    module: &Object<'js>,
    name: &str,
    args: impl rquickjs::function::IntoArgs<'js>,
) -> Result<Option<String>, ObjectsError> {
    let function: Function<'js> = module.get(name).map_err(|error| {
        ObjectsError::Failed(format!("glue export {name}: {}", describe(ctx, error)))
    })?;
    let promise: Promise<'js> = function
        .call(args)
        .map_err(|error| ObjectsError::Failed(describe(ctx, error)))?;
    promise
        .finish::<Option<String>>()
        .map_err(|error| ObjectsError::Failed(describe(ctx, error)))
}

fn ensure<'js>(
    ctx: &Ctx<'js>,
    module: &Object<'js>,
    who: &AgentIdentity,
) -> Result<(), ObjectsError> {
    call(
        ctx,
        module,
        "ensure",
        (who.agent.as_str(), who.me.as_str(), who.room.as_str()),
    )
    .map(|_| ())
}

fn decode<T: serde::de::DeserializeOwned>(text: Option<String>) -> Result<Option<T>, ObjectsError> {
    match text {
        None => Ok(None),
        Some(text) => serde_json::from_str(&text).map(Some).map_err(|error| {
            ObjectsError::Failed(format!("glue returned malformed JSON: {error}"))
        }),
    }
}

fn dispatch<'js>(ctx: &Ctx<'js>, module: &Object<'js>, command: Command) {
    match command {
        Command::Ingest { who, signer, text } => {
            if let Err(error) = ensure(ctx, module, &who).and_then(|()| {
                call(
                    ctx,
                    module,
                    "ingest",
                    (
                        who.agent.as_str(),
                        text.as_str(),
                        signer.as_str(),
                        who.room.as_str(),
                    ),
                )
            }) {
                tracing::debug!(target: "hark::objects", agent = who.agent.as_str(), %error, "object message not ingested");
            }
        }
        Command::Read { who, thread, reply } => {
            let result = ensure(ctx, module, &who)
                .and_then(|()| call(ctx, module, "read", (who.agent.as_str(), thread.as_str())))
                .and_then(decode::<ObjectState>);
            let _ = reply.send(result);
        }
        Command::List { who, reply } => {
            let result = ensure(ctx, module, &who)
                .and_then(|()| call(ctx, module, "list", (who.agent.as_str(),)))
                .and_then(decode::<Vec<ObjectSummary>>)
                .map(Option::unwrap_or_default);
            let _ = reply.send(result);
        }
        Command::Act {
            who,
            thread,
            verb,
            fields,
            reply,
        } => {
            let result = ensure(ctx, module, &who)
                .and_then(|()| {
                    call(
                        ctx,
                        module,
                        "act",
                        (
                            who.agent.as_str(),
                            thread.as_str(),
                            verb.as_str(),
                            fields.to_string(),
                        ),
                    )
                })
                .and_then(decode::<ActOutcome>)
                .and_then(|outcome| {
                    outcome.ok_or_else(|| ObjectsError::Failed("act returned nothing".to_owned()))
                });
            let _ = reply.send(result);
        }
        Command::Open {
            who,
            definition,
            thread,
            fields,
            reply,
        } => {
            let result = ensure(ctx, module, &who)
                .and_then(|()| {
                    call(
                        ctx,
                        module,
                        "open",
                        (
                            who.agent.as_str(),
                            definition.to_string(),
                            thread.as_str(),
                            fields.to_string(),
                        ),
                    )
                })
                .and_then(decode::<OpenOutcome>)
                .and_then(|outcome| {
                    outcome.ok_or_else(|| ObjectsError::Failed("open returned nothing".to_owned()))
                });
            let _ = reply.send(result);
        }
        Command::Close { agent } => {
            let _ = call(ctx, module, "close", (agent.as_str(),));
        }
        Command::Check { definition, reply } => {
            let result = call(ctx, module, "check", (definition.to_string(),))
                .and_then(decode::<CheckOutcome>)
                .and_then(|outcome| {
                    outcome.ok_or_else(|| ObjectsError::Failed("check returned nothing".to_owned()))
                });
            let _ = reply.send(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn who(agent: &AgentHandle) -> AgentIdentity {
        AgentIdentity {
            agent: agent.clone(),
            me: "@aria".to_owned(),
            room: "@general".to_owned(),
        }
    }

    fn checklist() -> serde_json::Value {
        serde_json::json!({
            "name": "checklist",
            "verbs": {
                "open": { "causedBy": "begin", "fields": { "title": "string" } },
                "check": { "causedBy": ["open"], "fields": { "item": "string", "done": "bool" } }
            },
            "project": {
                "title": ["last", "open", "title"],
                "items": ["latestPerKey", "check", "item", "done"]
            }
        })
    }

    /// The whole loop, headless: define → open → (echo) → act → read, with
    /// the broker's send answered by a hook standing in for the hub.
    #[tokio::test]
    async fn open_act_and_read_run_the_browsers_code_headlessly() {
        let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&sent);
        let history_calls = Arc::new(Mutex::new(0usize));
        let history_counter = Arc::clone(&history_calls);
        let client = spawn_with_hooks(
            move |_agent, canonical| {
                recorder.lock().unwrap().push(canonical.to_owned());
                true
            },
            move |_agent, _room| {
                *history_counter.lock().unwrap() += 1;
                true
            },
        );
        let agent = AgentHandle::generate();

        let opened = client
            .open(
                who(&agent),
                checklist(),
                "list-1".to_owned(),
                serde_json::json!({ "title": "Groceries" }),
            )
            .await
            .expect("open runs");
        assert!(opened.ok, "{opened:?}");
        let dialect = opened.dialect.clone().expect("a contract digest");
        assert!(dialect.starts_with("object-") && dialect.len() == 7 + 64);
        let opener = opened.message.clone().expect("the opener text");
        assert_eq!(
            sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&opener)
        );
        assert!(
            opener.contains(":object-spec"),
            "the contract travels in the opener"
        );

        // Learned locally on open: readable before the hub's echo arrives.
        let state = client
            .read(who(&agent), "list-1".to_owned())
            .await
            .expect("read runs")
            .expect("known");
        assert_eq!(state.dialect, dialect);
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Groceries", "items": {} })
        );

        // The hub's echo deduplicates by cid: still one message, same state.
        client.ingest(who(&agent), "@aria".to_owned(), opener.clone());
        let acted = client
            .act(
                who(&agent),
                "list-1".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "milk", "done": true }),
            )
            .await
            .expect("act runs");
        assert!(acted.ok, "{acted:?}");
        let action = sent.lock().unwrap()[1].clone();
        assert!(
            action.contains(":caused-by sha256-"),
            "the broker picked the opener as predecessor: {action}"
        );
        assert!(action.contains(":done #t"), "{action}");

        let state = client
            .read(who(&agent), "list-1".to_owned())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Groceries", "items": { "milk": true } })
        );

        // cbcl-rs shape verdict, natively: a string where the contract wants a bool.
        let rejected = client
            .act(
                who(&agent),
                "list-1".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "milk", "done": "yes" }),
            )
            .await
            .expect("act runs");
        assert!(!rejected.ok);
        assert!(
            rejected
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("shape-violation"),
            "{rejected:?}"
        );
        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "a rejected action never reaches the wire"
        );

        let listed = client.list(who(&agent)).await.unwrap();
        assert_eq!(
            listed,
            vec![ObjectSummary {
                thread: "list-1".into(),
                dialect: dialect.clone()
            }]
        );
        assert_eq!(*history_calls.lock().unwrap(), 0, "no opener was missing");
    }

    /// An action whose opener has not arrived is held pending and triggers
    /// exactly one history request (SPEC-085 ADR-002); the opener's later
    /// arrival releases it, and a second agent's action ingests under the
    /// attested signer, not the inner `:from`.
    #[tokio::test]
    async fn a_missing_opener_requests_history_once_and_pending_actions_release() {
        let history_calls = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&history_calls);
        let client = spawn_with_hooks(
            |_, _| true,
            move |_, _| {
                *counter.lock().unwrap() += 1;
                true
            },
        );
        // Author the opener and an action with a separate controller.
        let alice = AgentHandle::generate();
        let alice_id = AgentIdentity {
            agent: alice.clone(),
            me: "@alice".into(),
            room: "@general".into(),
        };
        let opened = client
            .open(
                alice_id.clone(),
                checklist(),
                "list-2".to_owned(),
                serde_json::json!({ "title": "Trip" }),
            )
            .await
            .unwrap();
        let opener = opened.message.unwrap();
        let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&sent);
        let authoring = spawn_with_hooks(
            move |_, canonical| {
                recorder.lock().unwrap().push(canonical.to_owned());
                true
            },
            |_, _| true,
        );
        authoring.ingest(alice_id.clone(), "@alice".into(), opener.clone());
        let acted = authoring
            .act(
                alice_id.clone(),
                "list-2".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "tent", "done": true }),
            )
            .await
            .unwrap();
        assert!(acted.ok, "{acted:?}");
        let action = sent.lock().unwrap()[0].clone();

        // A fresh agent sees the action first: pending, one history request.
        let aria = AgentHandle::generate();
        client.ingest(who(&aria), "@alice".into(), action.clone());
        client.ingest(who(&aria), "@alice".into(), action.clone());
        assert_eq!(
            client.read(who(&aria), "list-2".to_owned()).await.unwrap(),
            None
        );
        assert_eq!(
            *history_calls.lock().unwrap(),
            1,
            "requested once per controller lifetime"
        );

        // The opener arrives (as a history reply would deliver it): released.
        client.ingest(who(&aria), "@alice".into(), opener);
        let state = client
            .read(who(&aria), "list-2".to_owned())
            .await
            .unwrap()
            .expect("known now");
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Trip", "items": { "tent": true } })
        );
    }

    fn with_view(mut definition: serde_json::Value, view: serde_json::Value) -> serde_json::Value {
        definition["view"] = view;
        definition
    }

    /// A definition with a view: the opener carries contract and view as one
    /// bundle, `check` reports the same digests without sending, a second
    /// controller learns the object from the opener alone, and every view
    /// kind the browser accepts is accepted here.
    #[tokio::test]
    async fn definitions_with_views_are_checked_opened_and_learned_on_the_fly() {
        let client = spawn_with_hooks(|_, _| true, |_, _| true);
        let declarative = with_view(
            checklist(),
            serde_json::json!([
                { "type": "value", "field": "title", "label": "List" },
                { "type": "value", "field": "items", "label": "Items" },
                { "type": "form", "verb": "check", "label": "Check", "fields": { "item": "Item", "done": "Done" } }
            ]),
        );
        let checked = client.check(declarative.clone()).await.expect("checks");
        assert!(checked.dialect.starts_with("object-"));
        assert_eq!(checked.opener.as_deref(), Some("open"));
        assert!(
            checked.view.as_deref().unwrap_or("").starts_with("view-"),
            "{checked:?}"
        );
        assert!(
            checked.cbcl.starts_with("(define object-"),
            "{}",
            checked.cbcl
        );
        assert!(checked.verbs["check"]["after"] == serde_json::json!(["open"]));

        let alice = AgentIdentity {
            agent: AgentHandle::generate(),
            me: "@alice".into(),
            room: "@general".into(),
        };
        let opened = client
            .open(
                alice.clone(),
                declarative.clone(),
                "list-3".to_owned(),
                serde_json::json!({ "title": "Trip" }),
            )
            .await
            .expect("opens");
        assert_eq!(
            (opened.dialect.as_deref(), opened.view.as_deref()),
            (Some(checked.dialect.as_str()), checked.view.as_deref())
        );
        let opener = opened.message.unwrap();
        assert!(opener.contains(":object-spec"), "{opener}");

        // Another agent learns contract and view from the opener alone.
        let aria = AgentHandle::generate();
        client.ingest(who(&aria), "@alice".into(), opener);
        let state = client
            .read(who(&aria), "list-3".to_owned())
            .await
            .unwrap()
            .expect("learned on the fly");
        assert_eq!(state.dialect, checked.dialect);
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Trip", "items": {} })
        );

        // The serialised bundle round-trips as text and as JSON.
        let as_text = client
            .check(serde_json::Value::String(checked.serialized.clone()))
            .await
            .unwrap();
        assert_eq!(
            (as_text.dialect.as_str(), as_text.view.as_deref()),
            (checked.dialect.as_str(), checked.view.as_deref())
        );
        let as_json: serde_json::Value = serde_json::from_str(&checked.serialized).unwrap();
        let as_object = client.check(as_json).await.unwrap();
        assert_eq!(as_object.dialect, checked.dialect);

        // Static HTML and custom render views, with a layout.
        let mut html = with_view(
            checklist(),
            serde_json::json!({ "html": "<h1>Groceries</h1>" }),
        );
        html["layout"] = serde_json::json!({ "width": "compact" });
        assert!(client.check(html).await.unwrap().view.is_some());
        let render = with_view(
            checklist(),
            serde_json::json!({ "render": "(state, {emit}) => html`<h1>${state.title}</h1>`" }),
        );
        assert!(client.check(render).await.unwrap().view.is_some());

        // The SDK's own view validation applies: a component naming an
        // unprojected field is refused.
        let bad = with_view(
            checklist(),
            serde_json::json!([{ "type": "value", "field": "nope", "label": "x" }]),
        );
        let error = client.check(bad).await.expect_err("refused");
        assert!(error.to_string().contains("unknown view field"), "{error}");
    }

    /// The definition must verify under cbcl-rs; a contract whose protocol
    /// cycles is refused before anything is sent.
    #[tokio::test]
    async fn an_invalid_definition_is_refused_before_send() {
        let sent = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&sent);
        let client = spawn_with_hooks(
            move |_, _| {
                *counter.lock().unwrap() += 1;
                true
            },
            |_, _| true,
        );
        let agent = AgentHandle::generate();
        let cyclic = serde_json::json!({
            "name": "loop",
            "verbs": { "open": { "causedBy": "begin", "fields": {} }, "step": { "causedBy": ["open", "step"], "fields": {} } },
            "project": { "steps": ["count", "step"] }
        });
        let error = client
            .open(who(&agent), cyclic, "t".to_owned(), serde_json::json!({}))
            .await
            .expect_err("refused");
        assert!(
            error.to_string().contains("CBCL verification failed"),
            "{error}"
        );
        assert_eq!(*sent.lock().unwrap(), 0);
    }
}
