//! The object runtime: one actor thread, one controller per agent, every
//! judgement made by cbcl-rs linked natively (the `cbcl-wasm` crate at the
//! revision cbcl-bus ships to browsers).
//!
//! SPEC-019 put admission, the fold and the intent binder into cbcl-rs's
//! core; SPEC-087 made the JSON contract compile a cbcl-rs export too. What
//! is left for a host is bookkeeping, and this module is that bookkeeping,
//! the same the `cbcl` package's `runtime`, `broker` and `store` do for a
//! browser: which dialects are learned, which records each thread holds,
//! which admissions are decided, which acts wait for a dialect the room has
//! not taught yet, and the room's declared menu that maps a dialect's
//! self-address to the digest `fetchdialect` takes. Parity with browsers is
//! by cbcl-rs and by the conformance corpus (`tests/vectors/state`), not by
//! running the browser's JavaScript.
//!
//! Every command is dispatched on the actor thread; ingestion is
//! fire-and-forget from the receive loop, reads and writes are request/reply.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::PathBuf;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::{
    ActOutcome, AgentIdentity, CheckOutcome, Command, ObjectState, ObjectSummary, ObjectsClient,
    ObjectsError, OpenOutcome,
};
use crate::daemon::{AgentHandle, AgentStore};
use crate::object_transport::{HISTORY_LIMIT_MAX, history_request_frame, is_object_dialect_name};

/// SPEC-087 CON-001: the contract record version the compile takes.
pub const CONTRACT_VERSION: u64 = 3;
/// A room keeps at most this many learned dialects (SPEC-087 Controls).
const DIALECT_LIMIT: usize = 64;
/// The unknown-dialect queue: acts waiting for a definition (SPEC-087 Controls).
const PENDING_LIMIT: usize = 128;
const PENDING_BYTES_LIMIT: usize = 512 * 1024;
/// The verbs no contract may declare and no intent may name (core performatives).
const CORE_PERFORMATIVES: &[&str] = &[
    "tell", "ask", "reply", "error", "ok", "cancel", "hello", "bye", "lang",
];
/// Keywords the binder owns: never a contract field, never set by a caller.
const ROUTING_KEYWORDS: &[&str] = &[
    "from",
    "thread",
    "dialect",
    "caused-by",
    "to",
    "sender",
    "replaces",
    "audience",
    "sig",
    "key",
    "signing-key",
];
/// How long a controller's history request stays "in flight" for the store.
const HISTORY_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// cbcl-rs, natively
// ---------------------------------------------------------------------------

type Native = fn(&[u8]) -> Result<Vec<u8>, Vec<u8>>;

fn native(function: Native, input: &str) -> Result<String, String> {
    match function(input.as_bytes()) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(bytes) => Err(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

fn native_json(function: Native, input: &str) -> Result<Value, String> {
    let text = native(function, input)?;
    serde_json::from_str(&text).map_err(|error| format!("cbcl-rs returned malformed JSON: {error}"))
}

/// A CBCL string literal for a state-bearing value: strings quoted with the
/// escapes cbcl-rs reads, integers as digits, booleans as `#t`/`#f`, lists in
/// parentheses. The same rule as the `cbcl` package's `literal`.
fn literal(value: &Value) -> Result<String, String> {
    match value {
        Value::String(s) => Ok(quote(s)),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                Ok(n.to_string())
            } else {
                Err("state-bearing numbers are integers".to_owned())
            }
        }
        Value::Bool(b) => Ok(if *b { "#t" } else { "#f" }.to_owned()),
        Value::Array(items) => {
            let parts = items.iter().map(literal).collect::<Result<Vec<_>, _>>()?;
            Ok(format!("({})", parts.join(" ")))
        }
        Value::Null | Value::Object(_) => Err("unsupported field value".to_owned()),
    }
}

fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// A handle or thread as the wire carries it: bare when it is one token,
/// quoted otherwise.
fn token(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| !c.is_whitespace() && !matches!(c, '(' | ')' | '"' | '\\' | ';'))
    {
        value.to_owned()
    } else {
        quote(value)
    }
}

/// `:k v …` for a field record, in key order.
fn keyword_text(fields: &Map<String, Value>) -> Result<String, String> {
    let mut parts = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        parts.push(format!(":{key} {}", literal(value)?));
    }
    Ok(parts.join(" "))
}

/// The wire address of a canonical message: `sha256-<hex>` (SPEC-019 R.6).
fn wire_address(canonical: &str) -> Result<String, String> {
    let hash = native(cbcl_wasm::message_hash_bytes, canonical)?;
    Ok(match hash.strip_prefix("sha256:") {
        Some(hex) => format!("sha256-{hex}"),
        None => hash,
    })
}

/// The 64-hex digest an address carries (`sha256-<hex>` → `<hex>`).
fn hex_of(address: &str) -> String {
    address
        .strip_prefix("sha256-")
        .unwrap_or(address)
        .to_owned()
}

// ---------------------------------------------------------------------------
// Dialects and records
// ---------------------------------------------------------------------------

/// A learned dialect: its self-address, `(define …)` text, and cbcl-rs's
/// description of it (opener, verbs, state rules).
#[derive(Debug, Clone)]
struct Dialect {
    name: String,
    text: String,
    info: Value,
}

impl Dialect {
    /// Install `text` through R1–R7 and describe it. `expected` is the name
    /// the caller has for it: the self-address must match (SPEC-087 REQ-005).
    fn learn(expected: Option<&str>, text: &str) -> Result<Self, String> {
        let name = native(cbcl_wasm::dialect_hash_bytes, text)?;
        if !is_object_dialect_name(&name) {
            return Err("an object dialect is named by its self-address".to_owned());
        }
        if let Some(expected) = expected {
            if expected != name {
                return Err(format!(
                    "dialect self-address mismatch: {expected} declares {name}"
                ));
            }
        }
        match native(cbcl_wasm::verify_dialect_bytes, text) {
            Ok(verdict) if verdict == "ok" => {}
            Ok(verdict) => return Err(format!("CBCL dialect verification failed: {verdict}")),
            Err(reason) => return Err(format!("CBCL dialect verification failed: {reason}")),
        }
        let info = native_json(cbcl_wasm::describe_dialect_bytes, text)?;
        Ok(Self {
            name,
            text: text.to_owned(),
            info,
        })
    }

    fn opener(&self) -> Option<&str> {
        self.info["opener"].as_str()
    }

    fn has_verb(&self, verb: &str) -> bool {
        self.info["verbs"].get(verb).is_some()
    }

    fn opener_fields(&self) -> Vec<String> {
        let opener = self.opener().unwrap_or_default();
        self.info["verbs"][opener]["fields"]
            .as_object()
            .map(|fields| fields.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// One act as cbcl-rs read it: its wire address, verb, attested signer, and
/// the exact text every host judges.
#[derive(Debug, Clone)]
struct Record {
    address: String,
    verb: String,
    signer: String,
    canonical: String,
}

impl Record {
    fn entry(&self) -> String {
        format!("({} {})", quote(&self.signer), self.canonical)
    }
}

/// What `read_act` says about an incoming act.
struct ActInfo {
    dialect: String,
    address: String,
    verb: String,
    thread: Option<String>,
}

fn read_act(text: &str) -> Result<ActInfo, String> {
    let act = native_json(cbcl_wasm::read_act_bytes, text)?;
    let field = |key: &str| act[key].as_str().map(str::to_owned);
    Ok(ActInfo {
        dialect: field("dialect").unwrap_or_default(),
        address: field("address").unwrap_or_default(),
        verb: field("verb").unwrap_or_default(),
        thread: field("thread"),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Accepted,
    Pending,
    Rejected,
}

/// One object thread: the records it holds (a G-set keyed by address, so a
/// re-delivery is the same act), and the admissions that cannot change.
#[derive(Debug, Default)]
struct Thread {
    dialect: String,
    room: String,
    records: Vec<Record>,
    decided: HashMap<String, Verdict>,
}

impl Thread {
    fn insert(&mut self, record: Record) -> bool {
        if self.records.iter().any(|r| r.address == record.address) {
            return false;
        }
        self.records.push(record);
        true
    }

    /// The accepted set, retrying every pending admission as it grows: the
    /// same loop as the `cbcl` package's runtime (SPEC-019 R.4/R5/R6 are
    /// cbcl-rs's `admit`; this only feeds it).
    fn accepted(&mut self, thread: &str, dialect: &Dialect) -> Vec<Record> {
        let mut accepted: Vec<Record> = Vec::new();
        let mut pending: Vec<Record> = Vec::new();
        for record in &self.records {
            match self.decided.get(&record.address) {
                Some(Verdict::Accepted) => accepted.push(record.clone()),
                Some(Verdict::Rejected) => {}
                _ => pending.push(record.clone()),
            }
        }
        let mut progressed = true;
        while progressed && !pending.is_empty() {
            progressed = false;
            let mut index = 0;
            while index < pending.len() {
                let verdict = admit(dialect, thread, &accepted, &pending[index]).0;
                if verdict == Verdict::Pending {
                    index += 1;
                    continue;
                }
                let record = pending.remove(index);
                progressed = true;
                self.decided.insert(record.address.clone(), verdict);
                if verdict == Verdict::Accepted {
                    accepted.push(record);
                }
            }
        }
        accepted
    }
}

fn acts_frame(accepted: &[Record]) -> String {
    let entries: Vec<String> = accepted.iter().map(Record::entry).collect();
    format!("(acts {})", entries.join(" "))
}

fn instance(dialect: &Dialect, thread: &str, accepted: &[Record]) -> String {
    format!(
        "{} {} {}",
        dialect.text,
        quote(thread),
        acts_frame(accepted)
    )
}

/// cbcl-rs's admission of one act against the accepted set.
fn admit(
    dialect: &Dialect,
    thread: &str,
    accepted: &[Record],
    record: &Record,
) -> (Verdict, String) {
    let frame = format!(
        "(admit {} {})",
        instance(dialect, thread, accepted),
        record.entry()
    );
    match native_json(cbcl_wasm::admit_bytes, &frame) {
        Ok(verdict) => match verdict["verdict"].as_str() {
            Some("accepted") => (Verdict::Accepted, String::new()),
            Some("pending") => (Verdict::Pending, String::new()),
            _ => (
                Verdict::Rejected,
                verdict["reason"].as_str().unwrap_or("rejected").to_owned(),
            ),
        },
        Err(reason) => (Verdict::Rejected, reason),
    }
}

fn fold(dialect: &Dialect, thread: &str, accepted: &[Record]) -> Result<Value, String> {
    native_json(
        cbcl_wasm::fold_bytes,
        &format!("(fold {})", instance(dialect, thread, accepted)),
    )
}

/// The binder's outcome: the canonical act to sign, or its rejection.
enum Bound {
    Act(String),
    Rejected { reject: String, reason: String },
}

fn intend(
    dialect: &Dialect,
    thread: &str,
    accepted: &[Record],
    signer: &str,
    verb: &str,
    fields: &Map<String, Value>,
) -> Result<Bound, String> {
    let frame = format!(
        "(intend {} {} {verb} ({}))",
        instance(dialect, thread, accepted),
        quote(signer),
        keyword_text(fields)?
    );
    match native(cbcl_wasm::intend_bytes, &frame) {
        Ok(canonical) => Ok(Bound::Act(canonical)),
        Err(text) => {
            if let Ok(rejection) = serde_json::from_str::<Value>(&text) {
                if let Some(reject) = rejection["reject"].as_str() {
                    return Ok(Bound::Rejected {
                        reject: reject.to_owned(),
                        reason: rejection["reason"].as_str().unwrap_or("").to_owned(),
                    });
                }
            }
            Err(text)
        }
    }
}

// ---------------------------------------------------------------------------
// Definitions (SPEC-087 CON-001 and the authoring sugar)
// ---------------------------------------------------------------------------

const UNSUPPORTED_V1: &str = "version 1 object definitions are not supported; publish a version 3 contract (see docs/object-definitions.md)";
const UNSUPPORTED_V2: &str = "version 2 object definitions are not supported: the opener no longer carries a definition and views are a host package; publish a version 3 contract (see docs/object-definitions.md)";

/// A compiled contract: what `check` reports and `open` sends.
struct Compiled {
    contract: String,
    dialect: Dialect,
    label: String,
}

/// The authoring sugar the `cbcl` package accepts, normalised to the SPEC-087
/// record: `dialect` for `name`, `project` for `state`, `causedBy` for
/// `after`, `["string"]` for `list`, `version` defaulting to 3.
fn normalise_authoring(definition: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let mut out = definition.clone();
    if let Some(name) = out.remove("dialect") {
        out.insert("name".to_owned(), name);
    }
    if let Some(state) = out.remove("project") {
        out.insert("state".to_owned(), state);
    }
    out.entry("version".to_owned())
        .or_insert(Value::from(CONTRACT_VERSION));
    if let Some(Value::Object(verbs)) = out.get("verbs").cloned() {
        let mut next = Map::new();
        for (verb, rule) in verbs {
            let mut rule = rule.as_object().cloned().unwrap_or_default();
            if let Some(caused_by) = rule.remove("causedBy") {
                let after = match caused_by {
                    Value::Array(list) => Value::Array(list),
                    other => Value::Array(vec![other]),
                };
                rule.insert("after".to_owned(), after);
            }
            let fields = rule
                .get("fields")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let fields: Map<String, Value> = fields
                .into_iter()
                .map(|(key, value)| {
                    let value = match &value {
                        Value::Array(items)
                            if items.len() == 1 && items[0] == Value::String("string".into()) =>
                        {
                            Value::String("list".into())
                        }
                        _ => value,
                    };
                    (key, value)
                })
                .collect();
            rule.insert("fields".to_owned(), Value::Object(fields));
            next.insert(verb, Value::Object(rule));
        }
        out.insert("verbs".to_owned(), Value::Object(next));
    }
    Ok(out)
}

/// The exact contract bytes a definition compiles from: the serialised
/// artifact text, a `{kind: "contract"}` record, or an authoring definition.
fn contract_text(definition: &Value) -> Result<String, String> {
    let record: Map<String, Value> = match definition {
        Value::String(text) => {
            let parsed: Value = serde_json::from_str(text)
                .map_err(|error| format!("the definition is not valid JSON: {error}"))?;
            match parsed {
                Value::Object(record) => {
                    refuse_retired(&record)?;
                    // Exact bytes compile as given: identity is the body hash
                    // and the label is not part of it, so re-serialising is
                    // harmless, but the caller's own text is what is checked.
                    return Ok(text.clone());
                }
                _ => return Err("the definition must be a JSON object".to_owned()),
            }
        }
        Value::Object(record) => record.clone(),
        _ => return Err("the definition must be a JSON object".to_owned()),
    };
    refuse_retired(&record)?;
    if record.get("kind").and_then(Value::as_str) == Some("contract") {
        return serde_json::to_string(&Value::Object(record)).map_err(|error| error.to_string());
    }
    let normalised = normalise_authoring(&record)?;
    for key in ["view", "layout", "resources"] {
        if normalised.contains_key(key) {
            return Err(format!(
                "Object contract: a contract carries no presentation ({key}); views are a host package"
            ));
        }
    }
    if normalised.get("version") != Some(&Value::from(CONTRACT_VERSION)) {
        return Err(format!(
            "Object contract: contracts require version {CONTRACT_VERSION}"
        ));
    }
    let mut contract = Map::new();
    contract.insert("version".to_owned(), Value::from(CONTRACT_VERSION));
    contract.insert("kind".to_owned(), Value::String("contract".into()));
    for key in [
        "name",
        "author",
        "requirements",
        "bounds",
        "roles",
        "verbs",
        "state",
    ] {
        if let Some(value) = normalised.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    for key in normalised.keys() {
        if !matches!(
            key.as_str(),
            "version" | "name" | "author" | "requirements" | "bounds" | "roles" | "verbs" | "state"
        ) {
            return Err(format!("Object contract: unknown contract field {key}"));
        }
    }
    serde_json::to_string(&Value::Object(contract)).map_err(|error| error.to_string())
}

/// The two retired shapes, refused by name so the cause is said (the compile
/// would refuse them too, as an unknown field).
fn refuse_retired(record: &Map<String, Value>) -> Result<(), String> {
    match record.get("version").and_then(Value::as_u64) {
        Some(1) => Err(UNSUPPORTED_V1.to_owned()),
        Some(2) => Err(UNSUPPORTED_V2.to_owned()),
        _ => Ok(()),
    }
}

/// Compile a definition with cbcl-rs (SPEC-087 REQ-001): the dialect it
/// names by self-address, installed through R1–R7.
fn compile(definition: &Value) -> Result<Compiled, String> {
    let contract = contract_text(definition)?;
    let compiled = native_json(cbcl_wasm::compile_contract_bytes, &contract)?;
    let text = compiled["dialect"]
        .as_str()
        .ok_or_else(|| "cbcl-rs returned no dialect".to_owned())?;
    let dialect = Dialect::learn(compiled["name"].as_str(), text)?;
    Ok(Compiled {
        contract,
        dialect,
        label: compiled["label"].as_str().unwrap_or_default().to_owned(),
    })
}

fn describe(compiled: &Compiled) -> CheckOutcome {
    let info = &compiled.dialect.info;
    CheckOutcome {
        dialect: compiled.dialect.name.clone(),
        label: compiled.label.clone(),
        opener: compiled.dialect.opener().map(str::to_owned),
        verbs: info["verbs"].clone(),
        state: info["state"].clone(),
        roles: info["roles"].clone(),
        contract: compiled.contract.clone(),
        cbcl: compiled.dialect.text.clone(),
    }
}

/// The opener as the wire carries it: keyword form, every declared field,
/// `:caused-by begin` (the `cbcl` package's `openerText`).
fn opener_text(
    dialect: &Dialect,
    room: &str,
    thread: &str,
    from: &str,
    fields: &Map<String, Value>,
) -> Result<String, String> {
    let opener = dialect
        .opener()
        .ok_or_else(|| "Object contract: the dialect declares no opener".to_owned())?;
    let declared = dialect.opener_fields();
    let given: Vec<&String> = fields.keys().collect();
    if !(given.iter().all(|f| declared.contains(f))
        && declared.iter().all(|f| fields.contains_key(f)))
    {
        return Err(format!(
            "Object contract: opener fields are exactly {}",
            declared.join(", ")
        ));
    }
    let mut kw = String::new();
    for (key, value) in fields {
        kw.push_str(&format!(" :{key} {}", literal(value)?));
    }
    let text = format!(
        "(lang {} ({opener} {}{kw} :caused-by begin :thread {} :from {}))",
        dialect.name,
        token(room),
        quote(thread),
        token(from)
    );
    let inner = text
        .trim_start_matches(|c| c != ' ')
        .trim_start()
        .trim_start_matches(|c| c != ' ')
        .trim_start();
    let inner = &inner[..inner.len() - 1];
    match native(
        cbcl_wasm::verify_message_shape_bytes,
        &format!("(verify-shape {} {opener} {inner})", dialect.text),
    ) {
        Ok(verdict) if verdict == "ok" => {}
        Ok(reason) | Err(reason) => {
            return Err(format!("Object contract: invalid opener fields: {reason}"));
        }
    }
    match native(
        cbcl_wasm::verify_state_shape_bytes,
        &format!("(verify-state-shape {} {text})", dialect.text),
    ) {
        Ok(verdict) if verdict == "ok" => {}
        Ok(reason) | Err(reason) => {
            return Err(format!("Object contract: invalid opener fields: {reason}"));
        }
    }
    Ok(text)
}

/// The room's declaration of a dialect (SPEC-015 REQ-003, SPEC-087 REQ-005):
/// the hub content-addresses the `:def` bytes and serves them by digest.
fn declaration_frame(room: &str, name: &str, define: &str, from: &str) -> String {
    let escaped = define.replace('\\', "\\\\").replace('"', "\\\"");
    format!("(adddialect {room} :name {name} :def \"{escaped}\" :from {from})")
}

/// The acquisition of a declared dialect by digest (SPEC-015 REQ-005).
fn fetch_frame(room: &str, digest: &str, from: &str) -> String {
    format!("(fetchdialect {room} :digest {} :from {from})", quote(digest))
}

/// The teach frame an own declaration is journalled as, so a restarted daemon
/// knows the dialect without the room's reply.
fn teach_text(define: &str) -> String {
    format!("(meta {define}\n)")
}

/// The dialect a `(meta (define <name> …))` teach frame carries, when it is
/// an object dialect; textual so a frame is classified before it is parsed.
pub fn taught_dialect(text: &str) -> Option<&str> {
    let rest = text.trim_start().strip_prefix("(meta")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("(define")?;
    let rest = rest.strip_prefix(|c: char| c.is_whitespace())?.trim_start();
    let end = rest.find(|c: char| c.is_whitespace() || c == ')')?;
    let name = &rest[..end];
    is_object_dialect_name(name).then_some(name)
}

// ---------------------------------------------------------------------------
// The controller
// ---------------------------------------------------------------------------

/// A queued act of a dialect the room has not taught this controller yet.
struct Pending {
    dialect: String,
    signer: String,
    text: String,
}

/// One agent's controller: the browser room controller's job, for an agent.
struct Controller {
    me: String,
    room: String,
    learned: HashMap<String, Dialect>,
    threads: HashMap<String, Thread>,
    /// Thread order as learned, for `list`.
    order: Vec<String>,
    pending: Vec<Pending>,
    pending_bytes: usize,
    /// Dialects a `fetchdialect` went out for and has not been answered.
    requested: HashSet<String>,
    /// The room's declared menu: self-address → the hub's digest.
    menu: HashMap<String, String>,
    /// SPEC-086 CON-002: one history request per controller lifetime.
    history_requested: bool,
}

/// What a controller asks its host to do; the host owns identity, signing
/// and transport (the `cbcl` package's `BrokerHost`).
struct Host<'a> {
    agent: &'a str,
    on_send: &'a SendHook,
    on_control: &'a ControlHook,
    on_history: &'a HistoryHook,
}

impl Controller {
    fn new(me: String, room: String) -> Self {
        Self {
            me,
            room,
            learned: HashMap::new(),
            threads: HashMap::new(),
            order: Vec::new(),
            pending: Vec::new(),
            pending_bytes: 0,
            requested: HashSet::new(),
            menu: HashMap::new(),
            history_requested: false,
        }
    }

    /// Learn a dialect from its `(define …)` text and release the acts that
    /// waited for it. False when it was already learned.
    fn learn(
        &mut self,
        expected: Option<&str>,
        text: &str,
        host: &Host<'_>,
    ) -> Result<bool, String> {
        let name = native(cbcl_wasm::dialect_hash_bytes, text)?;
        if self.learned.contains_key(&name) {
            return Ok(false);
        }
        if self.learned.len() >= DIALECT_LIMIT {
            return Err("object definition limit".to_owned());
        }
        let dialect = Dialect::learn(expected, text)?;
        let name = dialect.name.clone();
        self.learned.insert(name.clone(), dialect);
        self.requested.remove(&name);
        let mut waiting: Vec<Pending> = {
            let (mine, rest): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
                .into_iter()
                .partition(|p| p.dialect == name);
            self.pending = rest;
            mine
        };
        // Openers first: an act released ahead of its opener would ask the
        // room for history the queue already holds.
        let opener = self.learned[&name].opener().unwrap_or_default().to_owned();
        waiting.sort_by_key(|item| {
            read_act(&item.text)
                .map(|act| act.verb != opener)
                .unwrap_or(true)
        });
        for item in waiting {
            self.pending_bytes = self.pending_bytes.saturating_sub(item.text.len());
            self.receive(&item.text, &item.signer, host);
        }
        Ok(true)
    }

    /// A `(meta (define …))` teach frame from the room (SPEC-019 R.6).
    fn teach(&mut self, text: &str, host: &Host<'_>) -> Result<bool, String> {
        let expected = taught_dialect(text).map(str::to_owned);
        let define = native(cbcl_wasm::define_text_bytes, text)?;
        self.learn(expected.as_deref(), &define, host)
    }

    /// The room's declared menu changed: ask again for every dialect the
    /// queue is waiting on.
    fn menu(&mut self, entries: Vec<(String, String)>, host: &Host<'_>) {
        tracing::debug!(target: "hark::objects", entries = entries.len(), pending = self.pending.len(), "room menu received");
        self.menu = entries.into_iter().collect();
        let waiting: HashSet<String> = self.pending.iter().map(|p| p.dialect.clone()).collect();
        for name in waiting {
            self.requested.remove(&name);
            self.request_dialect(&name, host);
        }
    }

    fn request_dialect(&mut self, name: &str, host: &Host<'_>) {
        if self.requested.contains(name) {
            return;
        }
        let Some(digest) = self.menu.get(name).cloned() else {
            tracing::debug!(target: "hark::objects", dialect = name, "dialect is not in the room's declared menu; waiting");
            return;
        };
        let frame = fetch_frame(&self.room, &digest, &self.me);
        let sent = (host.on_control)(host.agent, &frame);
        tracing::debug!(target: "hark::objects", dialect = name, sent, "dialect requested by digest");
        if sent {
            self.requested.insert(name.to_owned());
        }
    }

    fn request_history(&mut self, host: &Host<'_>) {
        if self.history_requested {
            return;
        }
        self.history_requested = true;
        if !(host.on_history)(host.agent, &self.room) {
            tracing::debug!(target: "hark::objects", "controller history request not sent");
        }
    }

    /// Ingest one delivered act (the bytes and the attested signer). The
    /// browser controller's `receive`, without the view.
    fn receive(&mut self, text: &str, signer: &str, host: &Host<'_>) -> Option<(String, String)> {
        let act = match read_act(text) {
            Ok(act) => act,
            Err(reason) => {
                tracing::debug!(target: "hark::objects", %reason, "object message not read");
                return None;
            }
        };
        if !is_object_dialect_name(&act.dialect) || signer.is_empty() {
            return None;
        }
        let thread = act.thread.filter(|t| !t.is_empty())?;
        if !self.learned.contains_key(&act.dialect) {
            if self.pending.len() >= PENDING_LIMIT
                || self.pending_bytes + text.len() > PENDING_BYTES_LIMIT
            {
                tracing::warn!(target: "hark::objects", dialect = %act.dialect, "pending object limit; act dropped");
                return None;
            }
            self.pending_bytes += text.len();
            self.pending.push(Pending {
                dialect: act.dialect.clone(),
                signer: signer.to_owned(),
                text: text.to_owned(),
            });
            self.request_dialect(&act.dialect, host);
            return None;
        }
        if let Some(bound) = self.threads.get(&thread) {
            if bound.dialect != act.dialect || bound.room != self.room {
                return None;
            }
        }
        let dialect = self.learned[&act.dialect].clone();
        if !dialect.has_verb(&act.verb) {
            return None;
        }
        let record = Record {
            address: act.address,
            verb: act.verb,
            signer: signer.to_owned(),
            canonical: text.to_owned(),
        };
        let entry = self.threads.entry(thread.clone()).or_default();
        if entry.dialect.is_empty() {
            entry.dialect = act.dialect.clone();
            entry.room = self.room.clone();
        }
        let accepted = entry.accepted(&thread, &dialect);
        let (verdict, reason) = admit(&dialect, &thread, &accepted, &record);
        if verdict == Verdict::Rejected {
            tracing::debug!(target: "hark::objects", thread = %thread, verb = %record.verb, %reason, "object act rejected");
            if entry.records.is_empty() {
                self.threads.remove(&thread);
            }
            return None;
        }
        let address = record.address.clone();
        let inserted = entry.insert(record);
        if inserted && !self.order.contains(&thread) {
            self.order.push(thread.clone());
        }
        let accepted = entry.accepted(&thread, &dialect);
        let opener = dialect.opener().unwrap_or_default();
        if !accepted.iter().any(|r| r.verb == opener) {
            self.request_history(host);
        }
        Some((address, thread))
    }

    fn read(&mut self, thread: &str) -> Result<Option<ObjectState>, String> {
        let Some(entry) = self.threads.get_mut(thread) else {
            return Ok(None);
        };
        let dialect = self.learned[&entry.dialect].clone();
        let accepted = entry.accepted(thread, &dialect);
        if accepted.is_empty() {
            // Held acts only: the thread is not in loaded history until its
            // opener is (SPEC-086 CON-002 asks the room for it).
            return Ok(None);
        }
        let state = fold(&dialect, thread, &accepted)?;
        Ok(Some(ObjectState {
            thread: thread.to_owned(),
            dialect: dialect.name,
            state,
        }))
    }

    fn list(&self) -> Vec<ObjectSummary> {
        self.order
            .iter()
            .filter_map(|thread| {
                self.threads.get(thread).map(|entry| ObjectSummary {
                    thread: thread.clone(),
                    dialect: entry.dialect.clone(),
                })
            })
            .collect()
    }

    /// Act on an object: the broker. A caller supplies a verb and its data
    /// fields only; cbcl-rs's `intend` binds recipients, `:thread`,
    /// `:caused-by` and `:replaces` from the accepted set and verifies the
    /// act; the host signs and sends; the store unions it optimistically.
    fn act(&mut self, thread: &str, verb: &str, fields: Value, host: &Host<'_>) -> ActOutcome {
        let reject = |reason: String| ActOutcome {
            ok: false,
            cid: None,
            reason: Some(reason),
        };
        let Some(entry) = self.threads.get_mut(thread) else {
            return reject("object is not in loaded history".to_owned());
        };
        let dialect = self.learned[&entry.dialect].clone();
        if CORE_PERFORMATIVES.contains(&verb) {
            return reject(format!(
                "'{verb}' is a core performative — never view-causable"
            ));
        }
        let Value::Object(raw) = fields else {
            return reject("intent keywords must be a record".to_owned());
        };
        let mut kw = Map::new();
        for (key, value) in raw {
            let lowered = key.to_lowercase();
            if ROUTING_KEYWORDS.contains(&lowered.as_str()) {
                let echoed = match lowered.as_str() {
                    "from" => value == Value::String(self.me.clone()),
                    "thread" => value == Value::String(thread.to_owned()),
                    "dialect" => value == Value::String(dialect.name.clone()),
                    _ => false,
                };
                if echoed {
                    continue;
                }
                return reject(match lowered.as_str() {
                    "from" => format!(
                        "view tried to set :from {} — client binds :from {}",
                        value.as_str().unwrap_or_default(),
                        self.me
                    ),
                    "replaces" => {
                        "view tried to set :replaces — client binds replacements".to_owned()
                    }
                    other => format!("view tried to set :{other} — client binds routing"),
                });
            }
            kw.insert(key, value);
        }
        let accepted = entry.accepted(thread, &dialect);
        let bound = match intend(&dialect, thread, &accepted, &self.me, verb, &kw) {
            Ok(Bound::Act(canonical)) => canonical,
            Ok(Bound::Rejected {
                reject: kind,
                reason,
            }) => {
                return reject(format!("{kind}: {reason}"));
            }
            Err(reason) => return reject(reason),
        };
        let canonical = match native(cbcl_wasm::parse_message_bytes, &bound) {
            Ok(canonical) => canonical,
            Err(reason) => return reject(reason),
        };
        if !(host.on_send)(host.agent, &canonical) {
            return reject("wire send blocked".to_owned());
        }
        let me = self.me.clone();
        match self.receive(&canonical, &me, host) {
            Some((address, _)) => ActOutcome {
                ok: true,
                cid: Some(hex_of(&address)),
                reason: None,
            },
            None => match wire_address(&canonical) {
                Ok(address) => ActOutcome {
                    ok: true,
                    cid: Some(hex_of(&address)),
                    reason: None,
                },
                Err(reason) => reject(reason),
            },
        }
    }

    /// Create an object: compile the definition, declare its dialect to the
    /// room (SPEC-087 REQ-005: the opener carries no definition), send the
    /// opener, and learn both locally so the next act need not wait for the
    /// hub's echo.
    fn open(
        &mut self,
        definition: &Value,
        thread: &str,
        fields: Value,
        host: &Host<'_>,
    ) -> Result<(OpenOutcome, Option<String>), String> {
        let compiled = compile(definition)?;
        let Value::Object(fields) = fields else {
            return Err("opener fields must be a record".to_owned());
        };
        let text = opener_text(&compiled.dialect, &self.room, thread, &self.me, &fields)?;
        let canonical = native(cbcl_wasm::parse_message_bytes, &text)?;
        let name = compiled.dialect.name.clone();
        let define = compiled.dialect.text.clone();
        let mut taught = None;
        if !self.learned.contains_key(&name) {
            let frame = declaration_frame(&self.room, &name, &define, &self.me);
            if !(host.on_control)(host.agent, &frame) {
                return Ok((
                    OpenOutcome {
                        ok: false,
                        thread: thread.to_owned(),
                        dialect: Some(name),
                        cid: None,
                        message: None,
                        reason: Some("dialect declaration refused".to_owned()),
                    },
                    None,
                ));
            }
            self.learn(Some(&name), &define, host)?;
            taught = Some(teach_text(&define));
        }
        if !(host.on_send)(host.agent, &canonical) {
            return Ok((
                OpenOutcome {
                    ok: false,
                    thread: thread.to_owned(),
                    dialect: Some(name),
                    cid: None,
                    message: None,
                    reason: Some("send refused".to_owned()),
                },
                taught,
            ));
        }
        let me = self.me.clone();
        self.receive(&canonical, &me, host);
        let address = wire_address(&canonical)?;
        Ok((
            OpenOutcome {
                ok: true,
                thread: thread.to_owned(),
                dialect: Some(name),
                cid: Some(hex_of(&address)),
                message: Some(canonical),
                reason: None,
            },
            taught,
        ))
    }
}

// ---------------------------------------------------------------------------
// The journal (SPEC-086 CON-004)
// ---------------------------------------------------------------------------

/// Delivered object messages and taught dialects, per agent and room,
/// replayed into a fresh controller before it serves its first command. In
/// an MLS room a controller cannot rebuild from the hub's replay (earlier
/// epochs do not decrypt, own sends never did); the journal is its archive.
/// Owner-only, beside the identity keys.
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

    /// Append one line unless an identical one is journalled.
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

// ---------------------------------------------------------------------------
// The actor
// ---------------------------------------------------------------------------

type SendHook = Box<dyn Fn(&str, &str) -> bool + Send>;
type ControlHook = Box<dyn Fn(&str, &str) -> bool + Send>;
type HistoryHook = Box<dyn Fn(&str, &str) -> bool + Send>;

/// Start the runtime on its own thread. `tokio` is the daemon's runtime
/// handle: the host `send`, `control` and `history` functions block on it
/// from the actor thread, which is not a tokio worker, so that is permitted
/// and cannot starve the executor.
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
/// `history` by `on_history` instead of a live agent store; declarations and
/// fetches are accepted.
#[cfg(test)]
pub(crate) fn spawn_with_hooks(
    on_send: impl Fn(&str, &str) -> bool + Send + 'static,
    on_history: impl Fn(&str, &str) -> bool + Send + 'static,
) -> ObjectsClient {
    spawn_with_options(on_send, |_, _| true, on_history, None)
}

#[cfg(test)]
pub(crate) fn spawn_with_options(
    on_send: impl Fn(&str, &str) -> bool + Send + 'static,
    on_control: impl Fn(&str, &str) -> bool + Send + 'static,
    on_history: impl Fn(&str, &str) -> bool + Send + 'static,
    journal_dir: Option<PathBuf>,
) -> ObjectsClient {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("hark-objects-test".to_owned())
        .spawn(move || {
            run_with(
                rx,
                Box::new(on_send),
                Box::new(on_control),
                Box::new(on_history),
                journal_dir,
            )
        })
        .expect("the object runtime thread spawns");
    ObjectsClient::new(tx)
}

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
    let control_store = store.clone();
    let control_tokio = tokio.clone();
    let on_control: ControlHook = Box::new(move |agent: &str, frame: &str| {
        let Ok(handle) = AgentHandle::new(agent.to_owned()) else {
            return false;
        };
        match control_tokio.block_on(control_store.send_control_outbound(&handle, frame.to_owned()))
        {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(agent, %error, "object control frame not sent");
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
    run_with(rx, on_send, on_control, on_history, journal_dir);
}

struct Runtime {
    controllers: HashMap<String, Controller>,
    journal: Option<Journal>,
    on_send: SendHook,
    on_control: ControlHook,
    on_history: HistoryHook,
}

impl Runtime {
    /// Build the agent's controller on first use, replaying its journal.
    fn ensure(&mut self, who: &AgentIdentity) {
        let key = who.agent.as_str().to_owned();
        if self.controllers.contains_key(&key) {
            return;
        }
        let mut controller = Controller::new(who.me.clone(), who.room.clone());
        let lines = self
            .journal
            .as_mut()
            .map(|journal| journal.load(&who.me, &who.room))
            .unwrap_or_default();
        {
            let host = Host {
                agent: &key,
                on_send: &self.on_send,
                on_control: &self.on_control,
                on_history: &self.on_history,
            };
            for line in lines {
                deliver(&mut controller, &line.text, &line.signer, &host);
            }
        }
        self.controllers.insert(key, controller);
    }

    fn with<T>(
        &mut self,
        who: &AgentIdentity,
        f: impl FnOnce(&mut Controller, &Host<'_>) -> T,
    ) -> T {
        self.ensure(who);
        let agent = who.agent.as_str();
        let host = Host {
            agent,
            on_send: &self.on_send,
            on_control: &self.on_control,
            on_history: &self.on_history,
        };
        let controller = self.controllers.get_mut(agent).expect("ensured above");
        f(controller, &host)
    }
}

/// One delivered line: a teach frame or an act.
fn deliver(controller: &mut Controller, text: &str, signer: &str, host: &Host<'_>) {
    if let Some(name) = taught_dialect(text) {
        match controller.teach(text, host) {
            Ok(learned) => tracing::debug!(target: "hark::objects", dialect = name, learned, "teach frame"),
            Err(reason) => tracing::debug!(target: "hark::objects", dialect = name, %reason, "dialect not learned"),
        }
    } else {
        controller.receive(text, signer, host);
    }
}

fn run_with(
    mut rx: mpsc::UnboundedReceiver<Command>,
    on_send: SendHook,
    on_control: ControlHook,
    on_history: HistoryHook,
    journal_dir: Option<PathBuf>,
) {
    let mut runtime = Runtime {
        controllers: HashMap::new(),
        journal: journal_dir.map(Journal::new),
        on_send,
        on_control,
        on_history,
    };
    while let Some(command) = rx.blocking_recv() {
        dispatch(&mut runtime, command);
    }
}

fn dispatch(runtime: &mut Runtime, command: Command) {
    match command {
        Command::Ingest { who, signer, text } => {
            if let Some(journal) = runtime.journal.as_mut() {
                journal.record(&who.me, &who.room, &signer, &text);
            }
            runtime.with(&who, |controller, host| {
                deliver(controller, &text, &signer, host)
            });
        }
        Command::Menu { who, entries } => {
            runtime.with(&who, |controller, host| controller.menu(entries, host));
        }
        Command::Read { who, thread, reply } => {
            let result = runtime
                .with(&who, |controller, _| controller.read(&thread))
                .map_err(ObjectsError::Failed);
            let _ = reply.send(result);
        }
        Command::List { who, reply } => {
            let listed = runtime.with(&who, |controller, _| controller.list());
            let _ = reply.send(Ok(listed));
        }
        Command::Act {
            who,
            thread,
            verb,
            fields,
            reply,
        } => {
            let outcome = runtime.with(&who, |controller, host| {
                controller.act(&thread, &verb, fields, host)
            });
            let _ = reply.send(Ok(outcome));
        }
        Command::Open {
            who,
            definition,
            thread,
            fields,
            reply,
        } => {
            let result = runtime.with(&who, |controller, host| {
                controller.open(&definition, &thread, fields, host)
            });
            let result = match result {
                Ok((outcome, taught)) => {
                    if let (Some(text), Some(journal)) = (taught, runtime.journal.as_mut()) {
                        journal.record(&who.me, &who.room, "", &text);
                    }
                    Ok(outcome)
                }
                Err(reason) => Err(ObjectsError::Failed(reason)),
            };
            let _ = reply.send(result);
        }
        Command::Close { agent } => {
            runtime.controllers.remove(agent.as_str());
        }
        Command::Check { definition, reply } => {
            let result = compile(&definition)
                .map(|compiled| describe(&compiled))
                .map_err(ObjectsError::Failed);
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
            me: "@aria".into(),
            room: "@general".into(),
        }
    }

    /// The authoring form: `causedBy` and `project` sugar over the SPEC-087
    /// contract record.
    fn checklist() -> Value {
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

    type Log = Arc<Mutex<Vec<String>>>;

    fn recording() -> (ObjectsClient, Log, Log, Arc<Mutex<usize>>) {
        let sent: Log = Arc::new(Mutex::new(Vec::new()));
        let control: Log = Arc::new(Mutex::new(Vec::new()));
        let history = Arc::new(Mutex::new(0usize));
        let (s, c, h) = (
            Arc::clone(&sent),
            Arc::clone(&control),
            Arc::clone(&history),
        );
        let client = spawn_with_options(
            move |_, canonical| {
                s.lock().unwrap().push(canonical.to_owned());
                true
            },
            move |_, frame| {
                c.lock().unwrap().push(frame.to_owned());
                true
            },
            move |_, _| {
                *h.lock().unwrap() += 1;
                true
            },
            None,
        );
        (client, sent, control, history)
    }

    /// The whole loop: define → declare → open → (echo) → act → read, every
    /// judgement cbcl-rs's, the sends answered by hooks standing in for the hub.
    #[tokio::test]
    async fn open_declares_the_dialect_then_acts_and_reads() {
        let (client, sent, control, history) = recording();
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
        let dialect = opened.dialect.clone().expect("a self-address");
        assert!(is_object_dialect_name(&dialect), "{dialect}");
        let opener = opened.message.clone().expect("the opener text");
        assert!(
            opener.starts_with(&format!("(lang {dialect} (open @general")),
            "{opener}"
        );
        assert!(
            !opener.contains(":object-spec"),
            "SPEC-087 ADR-003: the opener carries no definition"
        );
        // SPEC-087 REQ-005: the dialect was declared to the room, by name,
        // with its definition, before the opener went out.
        let declared = control.lock().unwrap().clone();
        assert_eq!(declared.len(), 1, "{declared:?}");
        assert!(
            declared[0].starts_with(&format!(
                "(adddialect @general :name {dialect} :def \"(define {dialect} "
            )),
            "{}",
            declared[0]
        );
        assert!(declared[0].ends_with(" :from @aria)"));
        assert_eq!(
            sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&opener)
        );

        // Learned locally on open: readable before the hub's echo arrives.
        let state = client
            .read(who(&agent), "list-1".to_owned())
            .await
            .unwrap()
            .expect("known");
        assert_eq!(state.dialect, dialect);
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Groceries", "items": {} })
        );
        assert_eq!(
            *history.lock().unwrap(),
            0,
            "the opener is accepted; no history request"
        );

        // The hub's echo deduplicates by address: still one message, same state.
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
        assert_eq!(acted.cid.as_deref().map(str::len), Some(64));
        let action = sent.lock().unwrap()[1].clone();
        assert!(
            action.contains(":caused-by sha256-"),
            "the binder picked the opener as predecessor: {action}"
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

        // cbcl-rs's shape verdict: a string where the contract wants a bool.
        let rejected = client
            .act(
                who(&agent),
                "list-1".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "eggs", "done": "yes" }),
            )
            .await
            .unwrap();
        assert!(!rejected.ok);
        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "nothing rejected reaches the wire"
        );
        // A forged routing keyword is refused before the binder.
        let forged = client
            .act(
                who(&agent),
                "list-1".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "x", "done": true, "from": "@bo" }),
            )
            .await
            .unwrap();
        assert!(
            forged
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains(":from"),
            "{forged:?}"
        );
        assert_eq!(
            client.list(who(&agent)).await.unwrap(),
            vec![ObjectSummary {
                thread: "list-1".into(),
                dialect
            }]
        );
    }

    /// SPEC-087 REQ-005: an act of a dialect the controller has not learned
    /// waits; the definition is fetched by the digest the room's menu gives
    /// for it, once; the room's teach frame releases the act.
    #[tokio::test]
    async fn an_unknown_dialect_is_fetched_by_digest_and_its_teach_frame_releases_the_acts() {
        let (author, sent, control, _) = recording();
        let alice = AgentHandle::generate();
        let alice_id = AgentIdentity {
            agent: alice.clone(),
            me: "@alice".into(),
            room: "@general".into(),
        };
        let opened = author
            .open(
                alice_id.clone(),
                checklist(),
                "list-2".to_owned(),
                serde_json::json!({ "title": "Trip" }),
            )
            .await
            .unwrap();
        let dialect = opened.dialect.clone().unwrap();
        let opener = opened.message.clone().unwrap();
        let acted = author
            .act(
                alice_id.clone(),
                "list-2".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "tent", "done": true }),
            )
            .await
            .unwrap();
        assert!(acted.ok, "{acted:?}");
        let action = sent.lock().unwrap()[1].clone();
        let define = control.lock().unwrap()[0]
            .split(" :def \"")
            .nth(1)
            .and_then(|rest| rest.strip_suffix("\" :from @alice)"))
            .map(|escaped| escaped.replace("\\\"", "\"").replace("\\\\", "\\"))
            .expect("the declaration carries the definition");

        let (client, _, control, history) = recording();
        let aria = AgentHandle::generate();
        client.ingest(who(&aria), "@alice".into(), action.clone());
        client.ingest(who(&aria), "@alice".into(), opener.clone());
        assert_eq!(
            client.read(who(&aria), "list-2".to_owned()).await.unwrap(),
            None
        );
        assert!(
            control.lock().unwrap().is_empty(),
            "no menu, no digest, no fetch yet"
        );
        // The room's menu names the dialect: the fetch goes out, once.
        client.menu(who(&aria), vec![(dialect.clone(), "ab".repeat(32))]);
        client.ingest(who(&aria), "@alice".into(), action.clone());
        let fetched = client
            .list(who(&aria))
            .await
            .map(|_| control.lock().unwrap().clone())
            .unwrap();
        assert_eq!(
            fetched,
            vec![format!(
                "(fetchdialect @general :digest \"{}\" :from @aria)",
                "ab".repeat(32)
            )]
        );
        // The hub answers with the teach frame: learned, verified by
        // self-address, and every waiting act judged.
        client.ingest(who(&aria), String::new(), format!("(meta {define}\n)"));
        let state = client
            .read(who(&aria), "list-2".to_owned())
            .await
            .unwrap()
            .expect("released");
        assert_eq!(state.dialect, dialect);
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Trip", "items": { "tent": true } })
        );
        assert_eq!(
            *history.lock().unwrap(),
            0,
            "the opener arrived with the action"
        );
        // A teach frame whose body does not hash to its name is refused.
        let forged = define.replacen(
            "(define ",
            "(define sha256-0000000000000000000000000000000000000000000000000000000000000000 ",
            1,
        );
        let forged = forged.replacen(&format!("{dialect} "), "", 1);
        client.ingest(who(&aria), String::new(), format!("(meta {forged}\n)"));
        assert_eq!(client.list(who(&aria)).await.unwrap().len(), 1);
    }

    /// SPEC-086 CON-002: an action before its opener is pending, one history
    /// request goes out per controller lifetime, and the opener releases it.
    #[tokio::test]
    async fn a_missing_opener_requests_history_once_and_pending_actions_release() {
        let (author, sent, control, _) = recording();
        let alice = AgentIdentity {
            agent: AgentHandle::generate(),
            me: "@alice".into(),
            room: "@general".into(),
        };
        let opened = author
            .open(
                alice.clone(),
                checklist(),
                "list-3".to_owned(),
                serde_json::json!({ "title": "Trip" }),
            )
            .await
            .unwrap();
        let opener = opened.message.unwrap();
        author
            .act(
                alice.clone(),
                "list-3".to_owned(),
                "check".to_owned(),
                serde_json::json!({ "item": "tent", "done": true }),
            )
            .await
            .unwrap();
        let action = sent.lock().unwrap()[1].clone();
        let teach = format!(
            "(meta {}\n)",
            control.lock().unwrap()[0]
                .split(" :def \"")
                .nth(1)
                .unwrap()
                .strip_suffix("\" :from @alice)")
                .unwrap()
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
        );

        let (client, _, _, history) = recording();
        let aria = AgentHandle::generate();
        client.ingest(who(&aria), String::new(), teach);
        client.ingest(who(&aria), "@alice".into(), action.clone());
        client.ingest(who(&aria), "@alice".into(), action.clone());
        assert_eq!(
            client.read(who(&aria), "list-3".to_owned()).await.unwrap(),
            None,
            "nothing accepted yet"
        );
        assert_eq!(
            *history.lock().unwrap(),
            1,
            "requested once per controller lifetime"
        );
        client.ingest(who(&aria), "@alice".into(), opener);
        let state = client
            .read(who(&aria), "list-3".to_owned())
            .await
            .unwrap()
            .expect("known now");
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Trip", "items": { "tent": true } })
        );
        assert_eq!(*history.lock().unwrap(), 1);
    }

    /// CON-004: everything delivered to a subscribed agent is journalled per
    /// room, owner-only, and a fresh runtime replays it, taught dialects
    /// included, before serving its first command.
    #[tokio::test]
    async fn the_journal_restores_object_state_into_a_fresh_runtime() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal_dir = dir.path().join("objects");
        let agent = AgentHandle::generate();
        let opener;
        {
            let first = spawn_with_options(
                |_, _| true,
                |_, _| true,
                |_, _| true,
                Some(journal_dir.clone()),
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
            opener = opened.message.unwrap();
            first.ingest(who(&agent), "@aria".into(), opener.clone());
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
            // Only the delivered echo is journalled for the act; the own send
            // is not, as for a browser. Deliver it as the hub would.
            let state = first
                .read(who(&agent), "list-4".to_owned())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.state["items"], serde_json::json!({ "stove": true }));
        }
        let path = journal_dir.join("aria").join("general.jsonl");
        let body = std::fs::read_to_string(&path).expect("journal written");
        assert_eq!(
            body.lines().count(),
            2,
            "the teach frame and the opener: {body}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let second = spawn_with_options(
            |_, _| true,
            |_, _| true,
            |_, _| true,
            Some(journal_dir.clone()),
        );
        let state = second
            .read(who(&agent), "list-4".to_owned())
            .await
            .unwrap()
            .expect("replayed");
        assert_eq!(
            state.state,
            serde_json::json!({ "title": "Camp", "items": {} })
        );
        // The next write on a key sees the replayed history.
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
        let bare = spawn_with_options(|_, _| true, |_, _| true, |_, _| true, None);
        assert_eq!(
            bare.read(who(&agent), "list-4".to_owned()).await.unwrap(),
            None
        );
        let _ = opener;
    }

    #[tokio::test]
    async fn check_reports_the_contract_without_sending() {
        let (client, sent, control, _) = recording();
        let checked = client.check(checklist()).await.expect("checks");
        assert!(is_object_dialect_name(&checked.dialect));
        assert_eq!(checked.label, "checklist");
        assert_eq!(checked.opener.as_deref(), Some("open"));
        assert_eq!(checked.verbs["check"]["after"], serde_json::json!(["open"]));
        assert_eq!(
            checked.state["items"],
            serde_json::json!(["latestPerKey", "check", "item", "done"])
        );
        assert!(
            checked
                .cbcl
                .starts_with(&format!("(define {} ", checked.dialect)),
            "{}",
            checked.cbcl
        );
        let contract: Value = serde_json::from_str(&checked.contract).unwrap();
        assert_eq!(contract["version"], serde_json::json!(3));
        assert_eq!(contract["kind"], serde_json::json!("contract"));
        // The exact contract text and the record compile to the same dialect.
        let as_text = client
            .check(Value::String(checked.contract.clone()))
            .await
            .unwrap();
        assert_eq!(as_text.dialect, checked.dialect);
        let as_record = client.check(contract).await.unwrap();
        assert_eq!(as_record.dialect, checked.dialect);
        assert!(sent.lock().unwrap().is_empty() && control.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retired_and_presentational_definitions_are_refused_by_name() {
        let (client, sent, _, _) = recording();
        let mut v1 = checklist();
        v1["version"] = serde_json::json!(1);
        let error = client.check(v1.clone()).await.expect_err("refused");
        assert!(error.to_string().contains("version 1"), "{error}");
        let error = client
            .check(Value::String(v1.to_string()))
            .await
            .expect_err("refused as text too");
        assert!(error.to_string().contains("version 1"), "{error}");
        let mut v2 = checklist();
        v2["version"] = serde_json::json!(2);
        assert!(
            client
                .check(v2)
                .await
                .expect_err("refused")
                .to_string()
                .contains("version 2")
        );
        let mut with_view = checklist();
        with_view["view"] =
            serde_json::json!([{ "type": "value", "field": "title", "label": "T" }]);
        let error = client.check(with_view).await.expect_err("refused");
        assert!(
            error.to_string().contains("views are a host package"),
            "{error}"
        );
        // cbcl-rs's own blame for a cyclic protocol: refused before send.
        let mut cyclic = checklist();
        cyclic["verbs"]["check"]["causedBy"] = serde_json::json!(["open", "check"]);
        let error = client
            .open(
                who(&AgentHandle::generate()),
                cyclic,
                "x".to_owned(),
                serde_json::json!({ "title": "T" }),
            )
            .await
            .expect_err("refused");
        assert!(
            error.to_string().contains("R5") || error.to_string().contains("cycle"),
            "{error}"
        );
        assert!(sent.lock().unwrap().is_empty());
        // An unknown act of an old-style `object-` dialect is not an object.
        let agent = AgentHandle::generate();
        client.ingest(who(&agent), "@bo".into(), "(lang object-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef (open @general :title \"x\" :caused-by begin :thread \"old-1\" :from @bo))".to_owned());
        assert!(client.list(who(&agent)).await.unwrap().is_empty());
    }

    /// SPEC-019 REQ-1931 as hark's regression net: every vector of the
    /// cbcl-rs conformance corpus reproduces through this runtime's
    /// bookkeeping — verdicts, state, and intents; forward, reversed, and
    /// duplicated. The vectors are copied from cbcl-rs `test-vectors/state`
    /// at the pinned revision (`tests/vectors/state/PROVENANCE.json`).
    #[test]
    fn the_conformance_corpus_reproduces() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/state");
        let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
            .expect("corpus present")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "json")
                    && !path.ends_with("PROVENANCE.json")
            })
            .collect();
        names.sort();
        assert!(names.len() >= 3, "{names:?}");
        for path in names {
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let id = path.file_name().unwrap().to_string_lossy().into_owned();
            let thread = vector["thread"].as_str().unwrap_or("t").to_owned();
            let dialect = Dialect::learn(None, vector["contract"].as_str().unwrap())
                .unwrap_or_else(|e| panic!("{id}: {e}"));
            let records: Vec<Record> = vector["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    let canonical = m["canonical"].as_str().unwrap().to_owned();
                    let act = read_act(&canonical).unwrap_or_else(|e| panic!("{id}: {e}"));
                    Record {
                        address: act.address,
                        verb: act.verb,
                        signer: m["signer"].as_str().unwrap().to_owned(),
                        canonical,
                    }
                })
                .collect();
            let addresses: Vec<Value> = records
                .iter()
                .map(|r| Value::String(r.address.clone()))
                .collect();
            assert_eq!(
                Value::Array(addresses),
                vector["expect"]["addresses"],
                "{id}: addresses"
            );
            let judge = |order: Vec<Record>| {
                let mut entry = Thread {
                    dialect: dialect.name.clone(),
                    room: "@r".into(),
                    records: Vec::new(),
                    decided: HashMap::new(),
                };
                for record in order {
                    entry.insert(record);
                }
                let accepted = entry.accepted(&thread, &dialect);
                let mut verdicts = Map::new();
                for record in &entry.records {
                    let name = match entry.decided.get(&record.address) {
                        Some(Verdict::Accepted) => "accepted",
                        Some(Verdict::Rejected) => "rejected",
                        _ => "pending",
                    };
                    verdicts.insert(record.address.clone(), Value::String(name.into()));
                }
                (
                    Value::Object(verdicts),
                    fold(&dialect, &thread, &accepted).unwrap(),
                    accepted,
                )
            };
            let (verdicts, state, accepted) = judge(records.clone());
            assert_eq!(verdicts, vector["expect"]["verdicts"], "{id}: verdicts");
            assert_eq!(state, vector["expect"]["state"], "{id}: state");
            let reversed: Vec<Record> = records.iter().rev().cloned().collect();
            assert_eq!(
                judge(reversed).1,
                vector["expect"]["state"],
                "{id}: reversed delivery"
            );
            let duplicated: Vec<Record> = records.iter().chain(records.iter()).cloned().collect();
            assert_eq!(
                judge(duplicated).1,
                vector["expect"]["state"],
                "{id}: duplicated delivery"
            );
            let intents: Vec<Value> = vector["intents"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .map(|it| {
                            let fields = it["fields"].as_object().cloned().unwrap_or_default();
                            match intend(
                                &dialect,
                                &thread,
                                &accepted,
                                it["signer"].as_str().unwrap(),
                                it["verb"].as_str().unwrap(),
                                &fields,
                            )
                            .unwrap()
                            {
                                Bound::Act(canonical) => {
                                    serde_json::json!({ "canonical": canonical })
                                }
                                Bound::Rejected { reject, .. } => {
                                    serde_json::json!({ "reject": reject })
                                }
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let expected = vector["expect"]["intents"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert_eq!(intents, expected, "{id}: intents");
        }
    }

    #[test]
    fn teach_frames_are_classified_textually() {
        let name = format!("sha256-{}", "ab".repeat(32));
        assert_eq!(
            taught_dialect(&format!("(meta (define {name} (cbcl) @a))")),
            Some(name.as_str())
        );
        assert_eq!(
            taught_dialect(&format!("  (meta\n (define {name}\n (cbcl) @a)\n)")),
            Some(name.as_str())
        );
        assert_eq!(taught_dialect("(meta (define hub (cbcl) @hub))"), None);
        assert_eq!(taught_dialect(&format!("(lang {name} (open @r))")), None);
        assert_eq!(
            literal(&serde_json::json!(["a", 2, true])).unwrap(),
            "(\"a\" 2 #t)"
        );
        assert!(literal(&serde_json::json!(1.5)).is_err());
        assert_eq!(token("@a b"), "\"@a b\"");
    }
}
