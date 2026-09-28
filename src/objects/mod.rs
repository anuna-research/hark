//! SPEC-086 Stage B — native object read/write for hark agents.
//!
//! Stage A ([`crate::object_transport`]) made hark a signing transport for
//! object agents: it carries object messages and attests their authorship.
//! Stage B lets a *shell* agent act on objects through hark itself — `hark
//! object read`, `act`, `open` — without a JavaScript process of its own.
//!
//! Every judgement is cbcl-rs's, linked natively (`cbcl-wasm` at the
//! revision cbcl-bus ships to browsers, so a wire address hark computes is
//! the address every browser computes): the SPEC-087 contract compile, the
//! SPEC-019 admission, fold and intent binder, and the reads. What is left
//! for a host is bookkeeping — learned dialects, each thread's records, the
//! acts waiting for a dialect the room has not taught yet — and [`runtime`]
//! is that bookkeeping, the same the `cbcl` package does for a browser.
//! Parity holds by cbcl-rs and by the conformance corpus the runtime replays
//! (`tests/vectors/state`), not by running the browser's code.
//!
//! The runtime is a single actor thread; every caller talks to it through
//! [`ObjectsClient`]. Ingestion is fire-and-forget from the receive loop
//! (never blocking the transport); reads and writes are request/reply.
//!
//! State is rebuilt from the hub's backfill on join, from history replies
//! (SPEC-086 REQ-003, REQ-004), and from the per-agent journal (CON-004);
//! only agents with the object subscription feed it.

pub mod runtime;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::daemon::AgentHandle;

/// One object thread the controller has learned, with the dialect (contract
/// digest) it is bound to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSummary {
    pub thread: String,
    pub dialect: String,
}

/// The projected state of one object thread — the same JSON the browser's
/// view receives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectState {
    pub thread: String,
    pub dialect: String,
    pub state: serde_json::Value,
}

/// The broker's verdict on an action (`{ok, cid}` or `{ok: false, reason}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A compiled definition, as `check` reports it: what an opener built from
/// it would establish, without sending anything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckOutcome {
    /// The dialect's self-address, `sha256-<64hex>` over its body (SPEC-019 R.6).
    pub dialect: String,
    /// The contract's label; no part of identity.
    pub label: String,
    /// The verb whose predecessor is `begin`.
    pub opener: Option<String>,
    /// Each verb's parameters, fields and predecessors, as cbcl-rs describes them.
    pub verbs: serde_json::Value,
    /// The state rules, `{field: [op, …]}`.
    pub state: serde_json::Value,
    /// The roles, when the contract declares any.
    #[serde(default)]
    pub roles: serde_json::Value,
    /// The exact contract bytes the dialect compiled from.
    pub contract: String,
    /// The `(define …)` text every host installs and the room declares.
    pub cbcl: String,
}

/// The outcome of creating an object: the opener that went out, and the
/// dialect (self-address) it established.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenOutcome {
    pub ok: bool,
    pub thread: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ObjectsError {
    /// The daemon runs without an object runtime, or it has stopped.
    #[error("the object runtime is not available")]
    Unavailable,
    /// cbcl-rs refused: an invalid definition, a malformed message, a
    /// rejected act. The message is cbcl-rs's own reason.
    #[error("{0}")]
    Failed(String),
}

/// The identity a controller is built with: the agent's wire handle (the
/// `:from` it signs as) and the room it joined.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent: AgentHandle,
    pub me: String,
    pub room: String,
}

pub(crate) enum Command {
    Ingest {
        who: AgentIdentity,
        signer: String,
        text: String,
    },
    Read {
        who: AgentIdentity,
        thread: String,
        reply: oneshot::Sender<Result<Option<ObjectState>, ObjectsError>>,
    },
    List {
        who: AgentIdentity,
        reply: oneshot::Sender<Result<Vec<ObjectSummary>, ObjectsError>>,
    },
    Act {
        who: AgentIdentity,
        thread: String,
        verb: String,
        fields: serde_json::Value,
        reply: oneshot::Sender<Result<ActOutcome, ObjectsError>>,
    },
    Open {
        who: AgentIdentity,
        definition: serde_json::Value,
        thread: String,
        fields: serde_json::Value,
        reply: oneshot::Sender<Result<OpenOutcome, ObjectsError>>,
    },
    Close {
        agent: AgentHandle,
    },
    Check {
        definition: serde_json::Value,
        reply: oneshot::Sender<Result<CheckOutcome, ObjectsError>>,
    },
    /// The room's declared dialect menu, `(self-address, digest)` pairs
    /// (SPEC-015 CON-001): what `fetchdialect` takes for an unknown dialect.
    Menu {
        who: AgentIdentity,
        entries: Vec<(String, String)>,
    },
}

/// A handle on the object runtime. Cheap to clone; every clone talks to the
/// one actor thread.
#[derive(Debug, Clone)]
pub struct ObjectsClient {
    tx: mpsc::UnboundedSender<Command>,
}

impl ObjectsClient {
    pub(crate) fn new(tx: mpsc::UnboundedSender<Command>) -> Self {
        Self { tx }
    }

    /// Feed one delivered object message (SPEC-086 CON-001: the bytes and
    /// the attested signer). Never blocks: the receive loop must not wait on
    /// the runtime, and the runtime may be waiting on the receive loop for a
    /// send acknowledgement.
    pub fn ingest(&self, who: AgentIdentity, signer: String, text: String) {
        let _ = self.tx.send(Command::Ingest { who, signer, text });
    }

    /// The room's declared dialect menu as the hub conveyed it (`roomcfg`).
    /// Never blocks. The controller asks for every dialect its queue is
    /// waiting on by the digest the menu gives.
    pub fn menu(&self, who: AgentIdentity, entries: Vec<(String, String)>) {
        let _ = self.tx.send(Command::Menu { who, entries });
    }

    pub async fn read(
        &self,
        who: AgentIdentity,
        thread: String,
    ) -> Result<Option<ObjectState>, ObjectsError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Read { who, thread, reply })
            .map_err(|_| ObjectsError::Unavailable)?;
        rx.await.map_err(|_| ObjectsError::Unavailable)?
    }

    pub async fn list(&self, who: AgentIdentity) -> Result<Vec<ObjectSummary>, ObjectsError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::List { who, reply })
            .map_err(|_| ObjectsError::Unavailable)?;
        rx.await.map_err(|_| ObjectsError::Unavailable)?
    }

    pub async fn act(
        &self,
        who: AgentIdentity,
        thread: String,
        verb: String,
        fields: serde_json::Value,
    ) -> Result<ActOutcome, ObjectsError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Act {
                who,
                thread,
                verb,
                fields,
                reply,
            })
            .map_err(|_| ObjectsError::Unavailable)?;
        rx.await.map_err(|_| ObjectsError::Unavailable)?
    }

    pub async fn open(
        &self,
        who: AgentIdentity,
        definition: serde_json::Value,
        thread: String,
        fields: serde_json::Value,
    ) -> Result<OpenOutcome, ObjectsError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Open {
                who,
                definition,
                thread,
                fields,
                reply,
            })
            .map_err(|_| ObjectsError::Unavailable)?;
        rx.await.map_err(|_| ObjectsError::Unavailable)?
    }

    /// The agent is gone: drop its controller.
    pub fn close(&self, agent: AgentHandle) {
        let _ = self.tx.send(Command::Close { agent });
    }

    /// Compile and verify a definition without sending anything.
    pub async fn check(&self, definition: serde_json::Value) -> Result<CheckOutcome, ObjectsError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Check { definition, reply })
            .map_err(|_| ObjectsError::Unavailable)?;
        rx.await.map_err(|_| ObjectsError::Unavailable)?
    }
}
