//! SPEC-086 Stage B — native object read/write for hark agents.
//!
//! Stage A ([`crate::object_transport`]) made hark a signing transport for
//! `@cbcl/object` SDK agents: it carries object messages and attests their
//! authorship, and a JavaScript process does the rest. Stage B lets a *shell*
//! agent act on objects through hark itself — `hark object read`, `act`,
//! `open` — without a JavaScript process of its own.
//!
//! It does so by running the browser's object code, not by porting it. The
//! SDK's controller, broker, projection combinators and store (`js/vendor/`,
//! byte-pinned to a cbcl-bus commit in `js/VENDOR.json`) run headlessly in an
//! embedded QuickJS runtime ([`runtime`]). Everything the browser injects into
//! that code is a host function backed by hark's Rust side:
//!
//! - canonical text and every CBCL verdict (dialect, shape, protocol,
//!   `message_hash`) come from `cbcl-wasm` linked natively **at the revision
//!   cbcl-bus ships to browsers**, so a cid hark computes is the cid every
//!   browser computes;
//! - the content address is `sha2`;
//! - `send` is the agent's own signed hub connection ([`crate::daemon::AgentStore::send_outbound`]);
//! - the history-on-missing-opener request is SPEC-086 CON-002.
//!
//! The runtime is a single actor thread owning the QuickJS context; every
//! caller talks to it through [`ObjectsClient`]. Ingestion is fire-and-forget
//! from the receive loop (never blocking the transport); reads and writes are
//! request/reply.
//!
//! State is not persisted. Like a browser tab, a controller rebuilds its store
//! from the hub's backfill on join and from history replies (SPEC-086 REQ-003,
//! REQ-004); only agents with the object subscription feed it.

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
    /// The contract digest: `object-<64hex>`.
    pub dialect: String,
    /// The verb whose predecessor is `begin`.
    pub opener: Option<String>,
    pub verbs: serde_json::Value,
    pub project: serde_json::Value,
    /// The view digest (`view-<64hex>`) when the definition carries one.
    #[serde(default)]
    pub view: Option<String>,
    /// The exact artifact text an opener carries in `:object-spec`.
    pub serialized: String,
    /// The native CBCL dialect the contract compiles to, verified by cbcl-rs.
    pub cbcl: String,
}

/// The outcome of creating an object: the opener that went out, and the
/// dialect (contract digest) it established.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenOutcome {
    pub ok: bool,
    pub thread: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
    /// The view digest distributed with the opener, when the definition
    /// carried a view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
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
    /// The vendored SDK threw: an invalid definition, a malformed message,
    /// or a JavaScript failure. The message is the SDK's own.
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

#[cfg(test)]
mod vendor_tests {
    use sha2::{Digest, Sha256};

    /// The vendored SDK is byte-pinned: `VENDOR.json` records the cbcl-bus
    /// commit and the SHA-256 of every vendored file, and this test holds the
    /// embedded bytes to it. An edit to a vendored file without a manifest
    /// update is a fork of the browser's code, which is exactly what running
    /// the browser's code exists to prevent.
    #[test]
    fn vendored_sdk_matches_its_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("js/VENDOR.json")).expect("manifest parses");
        let files = manifest["files"].as_object().expect("files map");
        let embedded = super::runtime::vendored_files();
        assert_eq!(
            files.len(),
            embedded.len(),
            "every vendored file is listed exactly once"
        );
        for (name, source) in embedded {
            let expected = files[name].as_str().expect("hex digest");
            let actual = format!("{:x}", Sha256::digest(source.as_bytes()));
            assert_eq!(
                actual, expected,
                "{name} differs from the pinned cbcl-bus copy"
            );
        }
        assert_eq!(
            manifest["cbcl_rs_sha"].as_str(),
            Some("58dbcfcfb286a97a9e1ea076c19d401bf15be918"),
            "the manifest names the cbcl-rs revision Cargo.toml pins for cbcl-wasm"
        );
    }
}
