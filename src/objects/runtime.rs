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

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// The QuickJS heap ceiling. Contracts are data and the vendored code is
/// fixed, so this bounds a pathological projection over a large history, not
/// hostile code; hitting it fails the one command with an exception.
const MEMORY_LIMIT: usize = 256 * 1024 * 1024;

/// The QuickJS stack ceiling (deep recursion in a projection).
const STACK_LIMIT: usize = 4 * 1024 * 1024;

/// How long one command may run JavaScript before the interrupt handler
/// stops it. Host calls that block (a send awaiting the hub's ack) extend
/// the deadline when they return, so a slow hub does not count as a runaway
/// script.
const COMMAND_DEADLINE: Duration = Duration::from_secs(20);

/// The moment after which the interrupt handler stops the running script.
type Deadline = Arc<Mutex<Option<Instant>>>;

fn bump(deadline: &Deadline, budget: Duration) {
    if let Ok(mut slot) = deadline.lock() {
        *slot = Some(Instant::now() + budget);
    }
}

/// The per-agent, per-room journal of delivered object messages (SPEC-086
/// CON-004).
///
/// A controller's state lives in the runtime. In a cleartext room it rebuilds
/// from the hub's backfill and history replies; in an MLS room it cannot —
/// replayed frames from earlier epochs do not decrypt, and this member's own
/// sends never did. So every object message delivered to a subscribed agent
/// is appended here, as the plaintext and the attested signer, and replayed
/// into a fresh controller before it serves its first command. The runtime
/// deduplicates by cid on replay, so the journal need only avoid repeating
/// identical lines. It lives beside the identity keys and the pairing
/// store, owner-only, because private-room plaintext is of that trust class.
struct Journal {
    dir: PathBuf,
    seen: HashMap<(String, String), HashSet<[u8; 32]>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalLine {
    signer: String,
    text: String,
}

impl Journal {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            seen: HashMap::new(),
        }
    }

    fn path(&self, me: &str, room: &str) -> PathBuf {
        self.dir
            .join(file_stem(me))
            .join(format!("{}.jsonl", file_stem(room)))
    }

    fn digest(signer: &str, text: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(signer.as_bytes());
        hasher.update(b"\n");
        hasher.update(text.as_bytes());
        hasher.finalize().into()
    }

    /// Every line for (`me`, `room`), oldest first, and remember them.
    fn load(&mut self, me: &str, room: &str) -> Vec<JournalLine> {
        let path = self.path(me, room);
        let seen = self
            .seen
            .entry((me.to_owned(), room.to_owned()))
            .or_default();
        let Ok(body) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let mut lines = Vec::new();
        for raw in body.lines() {
            let Ok(line) = serde_json::from_str::<JournalLine>(raw) else {
                tracing::warn!(target: "hark::objects", path = %path.display(), "skipping a malformed journal line");
                continue;
            };
            if seen.insert(Self::digest(&line.signer, &line.text)) {
                lines.push(line);
            }
        }
        lines
    }

    /// Append one delivered message unless an identical one is journalled.
    fn record(&mut self, me: &str, room: &str, signer: &str, text: &str) {
        let seen = self
            .seen
            .entry((me.to_owned(), room.to_owned()))
            .or_default();
        if !seen.insert(Self::digest(signer, text)) {
            return;
        }
        let path = self.path(me, room);
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
                }
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            let line = serde_json::to_string(&JournalLine {
                signer: signer.to_owned(),
                text: text.to_owned(),
            })
            .map_err(std::io::Error::other)?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")
        })();
        if let Err(error) = result {
            tracing::warn!(target: "hark::objects", path = %path.display(), %error, "could not journal an object message");
        }
    }
}

/// A handle or room as a filename: strip the `@`, keep filename-safe
/// characters (the same rule as the identity key files).
fn file_stem(handle: &str) -> String {
    let name: String = handle
        .trim_start_matches('@')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() {
        "agent".to_owned()
    } else {
        name
    }
}

/// Start the runtime on its own thread. `tokio` is the daemon's runtime
/// handle: the host `send` and `history` functions block on it from the actor
/// thread, which is not a tokio worker, so that is permitted and cannot
/// starve the executor.
///
/// `journal_dir` is where delivered object messages are journalled per agent
/// and room (CON-004); `None` keeps state in memory only.
pub fn spawn(
    store: AgentStore,
    tokio: tokio::runtime::Handle,
    journal_dir: Option<PathBuf>,
) -> ObjectsClient {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("hark-objects".to_owned())
        .spawn(move || run(rx, store, tokio, journal_dir))
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
    spawn_with_options(on_send, on_history, None, COMMAND_DEADLINE)
}

#[cfg(test)]
pub(crate) fn spawn_with_options(
    on_send: impl Fn(&str, &str) -> bool + Send + 'static,
    on_history: impl Fn(&str, &str) -> bool + Send + 'static,
    journal_dir: Option<PathBuf>,
    deadline: Duration,
) -> ObjectsClient {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("hark-objects-test".to_owned())
        .spawn(move || {
            run_with(
                rx,
                Box::new(on_send),
                Box::new(on_history),
                journal_dir,
                deadline,
            )
        })
        .expect("the object runtime thread spawns");
    ObjectsClient::new(tx)
}

type SendHook = Box<dyn Fn(&str, &str) -> bool + Send>;
type HistoryHook = Box<dyn Fn(&str, &str) -> bool + Send>;

fn run(
    rx: mpsc::UnboundedReceiver<Command>,
    store: AgentStore,
    tokio: tokio::runtime::Handle,
    journal_dir: Option<PathBuf>,
) {
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
    run_with(rx, on_send, on_history, journal_dir, COMMAND_DEADLINE);
}

fn run_with(
    mut rx: mpsc::UnboundedReceiver<Command>,
    on_send: SendHook,
    on_history: HistoryHook,
    journal_dir: Option<PathBuf>,
    budget: Duration,
) {
    let rt = Runtime::new().expect("QuickJS runtime");
    rt.set_memory_limit(MEMORY_LIMIT);
    rt.set_max_stack_size(STACK_LIMIT);
    let deadline: Deadline = Arc::new(Mutex::new(None));
    let watched = Arc::clone(&deadline);
    rt.set_interrupt_handler(Some(Box::new(move || {
        watched
            .lock()
            .map(|slot| slot.is_some_and(|at| Instant::now() > at))
            .unwrap_or(false)
    })));
    // A host call that blocks on the hub is not JavaScript running away:
    // give the script its full budget back once the call returns.
    let (send_deadline, history_deadline) = (Arc::clone(&deadline), Arc::clone(&deadline));
    let on_send: SendHook = Box::new(move |agent, canonical| {
        let sent = on_send(agent, canonical);
        bump(&send_deadline, budget);
        sent
    });
    let on_history: HistoryHook = Box::new(move |agent, room| {
        let requested = on_history(agent, room);
        bump(&history_deadline, budget);
        requested
    });
    let mut journal = journal_dir.map(Journal::new);
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
        bump(&deadline, budget);
        ctx.with(|ctx| {
            let module = glue.clone().restore(&ctx).expect("glue module restores");
            dispatch(&ctx, &module, command, journal.as_mut());
        });
        if let Ok(mut slot) = deadline.lock() {
            *slot = None;
        }
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

/// Make sure the agent's controller exists; on creation, replay its journal
/// so a restarted daemon serves the state it had (CON-004).
fn ensure<'js>(
    ctx: &Ctx<'js>,
    module: &Object<'js>,
    who: &AgentIdentity,
    journal: Option<&mut Journal>,
) -> Result<(), ObjectsError> {
    let created = call(
        ctx,
        module,
        "ensure",
        (who.agent.as_str(), who.me.as_str(), who.room.as_str()),
    )?;
    if created.as_deref() != Some("created") {
        return Ok(());
    }
    let Some(journal) = journal else {
        return Ok(());
    };
    let lines = journal.load(&who.me, &who.room);
    let count = lines.len();
    for line in lines {
        if let Err(error) = call(
            ctx,
            module,
            "ingest",
            (
                who.agent.as_str(),
                line.text.as_str(),
                line.signer.as_str(),
                who.room.as_str(),
            ),
        ) {
            tracing::debug!(target: "hark::objects", agent = who.agent.as_str(), %error, "journal line not ingested");
        }
    }
    if count > 0 {
        tracing::info!(target: "hark::objects", agent = who.agent.as_str(), room = who.room, count, "replayed the object journal");
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(text: Option<String>) -> Result<Option<T>, ObjectsError> {
    match text {
        None => Ok(None),
        Some(text) => serde_json::from_str(&text).map(Some).map_err(|error| {
            ObjectsError::Failed(format!("glue returned malformed JSON: {error}"))
        }),
    }
}

fn dispatch<'js>(
    ctx: &Ctx<'js>,
    module: &Object<'js>,
    command: Command,
    mut journal: Option<&mut Journal>,
) {
    match command {
        Command::Ingest { who, signer, text } => {
            if let Some(journal) = journal.as_deref_mut() {
                journal.record(&who.me, &who.room, &signer, &text);
            }
            if let Err(error) = ensure(ctx, module, &who, journal).and_then(|()| {
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
            let result = ensure(ctx, module, &who, journal)
                .and_then(|()| call(ctx, module, "read", (who.agent.as_str(), thread.as_str())))
                .and_then(decode::<ObjectState>);
            let _ = reply.send(result);
        }
        Command::List { who, reply } => {
            let result = ensure(ctx, module, &who, journal)
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
            let result = ensure(ctx, module, &who, journal)
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
            let result = ensure(ctx, module, &who, journal)
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
        #[cfg(test)]
        Command::Spin { reply } => {
            let _ = reply.send(call(ctx, module, "__spin", ()).map(|_| ()));
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

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    /// CON-004: everything delivered to a subscribed agent is journalled per
    /// room, owner-only, and a fresh runtime replays it before serving its
    /// first command — so a restarted daemon in a private room still knows
    /// the opener and this member's own acts, which no replay can decrypt.
    #[tokio::test]
    async fn the_journal_restores_object_state_into_a_fresh_runtime() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal_dir = dir.path().join("objects");
        let agent = AgentHandle::generate();
        {
            let first = spawn_with_options(
                |_, _| true,
                |_, _| true,
                Some(journal_dir.clone()),
                COMMAND_DEADLINE,
            );
            let opened = first
                .open(
                    who(&agent),
                    checklist(),
                    "list-4".to_owned(),
                    serde_json::json!({ "title": "Camp" }),
                )
                .await
                .unwrap();
            // Delivered messages (the opener's echo, an action) are journalled
            // on ingest; the optimistic local copy is not the journal's source.
            first.ingest(who(&agent), "@aria".into(), opened.message.clone().unwrap());
            let acted = first
                .act(
                    who(&agent),
                    "list-4".to_owned(),
                    "check".to_owned(),
                    serde_json::json!({ "item": "stove", "done": true }),
                )
                .await
                .unwrap();
            assert!(acted.ok);
            // The hub's echo of the action, journalled too; a duplicate delivery
            // adds no second line.
            let action = format!(
                "(lang {} (check @general () :item \"stove\" :done #t :from @aria :thread \"list-4\" :caused-by sha256-{}))",
                opened.dialect.clone().unwrap(),
                opened.cid.clone().unwrap()
            );
            first.ingest(who(&agent), "@aria".into(), action.clone());
            first.ingest(who(&agent), "@aria".into(), action);
            let state = first
                .read(who(&agent), "list-4".to_owned())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                state.state,
                serde_json::json!({ "title": "Camp", "items": { "stove": true } })
            );
        }
        let path = journal_dir.join("aria").join("general.jsonl");
        let body = std::fs::read_to_string(&path).expect("the journal was written");
        assert_eq!(
            body.lines().count(),
            2,
            "one line per distinct delivery: {body}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        // A new runtime — a restarted daemon — with nothing delivered yet.
        let second = spawn_with_options(
            |_, _| true,
            |_, _| true,
            Some(journal_dir.clone()),
            COMMAND_DEADLINE,
        );
        let state = second
            .read(who(&agent), "list-4".to_owned())
            .await
            .unwrap()
            .expect("replayed from the journal");
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Camp", "items": { "stove": true } })
        );
        // And the broker now knows this member's earlier write: a new act on
        // the same key replaces it rather than sitting beside it.
        let acted = second
            .act(
                who(&agent),
                "list-4".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "stove", "done": false }),
            )
            .await
            .unwrap();
        assert!(acted.ok, "{acted:?}");
        let state = second
            .read(who(&agent), "list-4".to_owned())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.state["items"], serde_json::json!({ "stove": false }));
        // Without a journal, a fresh runtime knows nothing.
        let bare = spawn_with_hooks(|_, _| true, |_, _| true);
        assert_eq!(
            bare.read(who(&agent), "list-4".to_owned()).await.unwrap(),
            None
        );
    }

    /// A script that never yields is stopped at the command deadline and
    /// reported as a failure; the runtime keeps serving afterwards.
    #[tokio::test]
    async fn a_runaway_script_is_interrupted_at_the_deadline() {
        let client = spawn_with_options(|_, _| true, |_, _| true, None, Duration::from_millis(300));
        let started = Instant::now();
        let error = client.spin().await.expect_err("interrupted");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stopped promptly"
        );
        assert!(error.to_string().contains("interrupted"), "{error}");
        let checked = client
            .check(checklist())
            .await
            .expect("the runtime still serves");
        assert!(checked.dialect.starts_with("object-"));
    }

    /// Version 1 definitions (the pre-v2 SDK's single artifact) are refused by
    /// name on `check`/`open`, and an incoming version 1 opener is skipped
    /// without becoming a pending thread — hark serves version 2 only.
    #[tokio::test]
    async fn version_one_definitions_are_refused_by_name() {
        let client = spawn_with_hooks(|_, _| true, |_, _| true);
        let v1 = serde_json::json!({
            "version": 1, "name": "old",
            "verbs": { "open": { "causedBy": "begin", "fields": { "title": "string" } } },
            "project": { "title": ["last", "open", "title"] },
            "view": []
        });
        let error = client.check(v1.clone()).await.expect_err("refused");
        assert!(error.to_string().contains("version 1"), "{error}");
        let error = client
            .check(serde_json::Value::String(v1.to_string()))
            .await
            .expect_err("refused as text too");
        assert!(error.to_string().contains("version 1"), "{error}");

        // A version 1 opener from the room: not loaded, not pending, no error.
        let agent = AgentHandle::generate();
        let spec = v1.to_string().replace('\\', "\\\\").replace('"', "\\\"");
        let opener = format!(
            "(lang object-{HEX} (open @general :title \"Old\" :object-spec \"{spec}\" :caused-by begin :thread \"old-1\" :from @bo))"
        );
        client.ingest(who(&agent), "@bo".into(), opener);
        assert_eq!(
            client.read(who(&agent), "old-1".to_owned()).await.unwrap(),
            None
        );
        assert!(client.list(who(&agent)).await.unwrap().is_empty());
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
