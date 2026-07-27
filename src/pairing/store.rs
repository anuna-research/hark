//! [[SPEC-026 CON-002]] — the durable pairing store.
//!
//! Agent records used to live only in daemon memory: `hark daemon stop && hark
//! daemon start` dropped every agent and re-pairing was mandatory, even though
//! the hub remembers the membership durably. Reconnecting the socket
//! ([[crate::reconnect]]) fixes the redeploy case; this fixes the restart case,
//! and without both the recovery story stays half-finished.
//!
//! **Where it lives.** `<chat.identity_dir>/paired-agents.json`, beside the
//! per-handle Ed25519 seeds. Not the runtime directory: on Linux that is
//! `$XDG_RUNTIME_DIR`, which is wiped on reboot, and its contents are
//! deliberately ephemeral. The identity directory is already the durable,
//! owner-only home of exactly this class of material, is already configurable
//! (`CBCL_CHAT_IDENTITY_DIR`), and the record's most sensitive field — the
//! channel capability — is of the same trust class as the seeds already there
//! (SPEC-026 ADR-005).
//!
//! **Why the parsing is strict.** The record carries a bearer capability, so
//! this is a trust boundary in the [[LangSec]] sense even though the bytes came
//! from us: a permissively-parsed record is a record whose capability field may
//! not be the one that was written, and a store that half-parses is a store two
//! readers can disagree about. Recognition is therefore **total** — a store
//! that does not match the declared grammar *in full* yields no records at all
//! (REQ-010). In particular a valid record sitting beside a malformed one
//! yields zero, not one.
//!
//! Every field recogniser here is the *same function the live request path
//! uses* — [`AgentHandle::new`], [`validate_chat_handle`],
//! [`validate_dialect_id`] — never a second implementation, so a record that
//! round-trips through the store is accepted on exactly the same terms as one
//! that arrived over the wire (LangSec: one parser per language).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{validate_chat_handle, validate_dialect_id};
use crate::daemon::AgentHandle;

/// The store file's basename inside the chat identity directory.
pub const STORE_FILE: &str = "paired-agents.json";

/// The only version this recogniser accepts. An unknown version is rejected
/// whole rather than best-effort read: a future writer may mean something
/// different by a field this version thinks it understands.
const STORE_VERSION: u32 = 1;

/// Serialises the read-modify-write in [`PairingStore::upsert`] /
/// [`PairingStore::remove`] / [`PairingStore::save`].
///
/// One lock for every store path rather than one per path: a daemon has exactly
/// one chat identity directory, so there is nothing to gain from finer
/// granularity and a global is the shorter thing to reason about. No `.await`
/// happens under it — the store is synchronous — so a blocking mutex is safe in
/// the async callers.
static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Distinguishes concurrent writers' temp files within one process.
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One agent's re-establishable pairing ([[SPEC-026 REQ-007]]).
///
/// This is exactly the argument set [`crate::chat::create_chat_agent`] needs,
/// minus the things that are not the pairing: the identity (loaded from
/// `<identity_dir>/<handle>.key`), the timing knobs (configuration), and
/// `mls_create` — a rehydrated agent never re-creates the group, for the same
/// reason a reconnect never does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedAgent {
    /// The daemon-local handle. Preserved across a restart so an operator's
    /// exported `CBCL_AGENT_HANDLE` keeps working (SPEC-026 ADR-006).
    pub agent_handle: String,
    /// The chat wire identity (`@name`), which also names the signing key.
    pub wire_handle: String,
    pub channel: String,
    /// REQUIRED by the CON-002 grammar, not defaulted. An absent or misspelled
    /// key means the writer and this reader disagree about the format, and
    /// guessing on a capability-bearing record is how parser-differential bugs
    /// start.
    pub dialects: Vec<String>,
    /// The channel capability. A bearer credential — the reason for the `0600`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
    /// Provenance: who added this agent (SPEC-016 REQ-010).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    /// REQUIRED by the grammar. Defaulting a misspelled key to `false` would
    /// silently downgrade a firehose agent to an answer-only one across a
    /// restart, with nothing to show for it.
    pub receive_all: bool,
}

/// The store document. `deny_unknown_fields` on both levels is part of the
/// grammar, not pedantry: an unrecognised key means the writer and this reader
/// disagree about the format, and guessing is how parser-differential bugs
/// start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreDocument {
    version: u32,
    agents: Vec<PairedAgent>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("pairing store {path} could not be read: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("pairing store {path} could not be written: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("pairing store {path} is not recognised: {reason}")]
    Malformed { path: PathBuf, reason: String },
}

/// The durable pairing store for one chat identity directory.
#[derive(Debug, Clone)]
pub struct PairingStore {
    path: PathBuf,
}

impl PairingStore {
    /// The store inside `identity_dir`.
    pub fn new(identity_dir: impl AsRef<Path>) -> Self {
        Self {
            path: identity_dir.as_ref().join(STORE_FILE),
        }
    }

    /// Where the store lives — surfaced so diagnostics can name the file the
    /// operator has to look at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every persisted record, or an empty list.
    ///
    /// This is the caller most code wants: an unreadable or unrecognised store
    /// is not a reason to refuse to start a daemon, it is a reason to start with
    /// no persisted agents and say so. The diagnostic goes to the log; use
    /// [`Self::load_checked`] where the caller can act on the distinction.
    pub fn load(&self) -> Vec<PairedAgent> {
        match self.load_checked() {
            Ok(agents) => agents,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "ignoring the pairing store; no agents will be re-established from it"
                );
                Vec::new()
            }
        }
    }

    /// Recognise the store in full ([[SPEC-026 REQ-010]]).
    ///
    /// An absent file is `Ok(vec![])` — a first run is not a failure. Anything
    /// present but not matching the grammar is `Err`, and yields **no** records:
    /// there is deliberately no path that returns some-but-not-all.
    pub fn load_checked(&self) -> Result<Vec<PairedAgent>, StoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(StoreError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let document: StoreDocument =
            serde_json::from_slice(&bytes).map_err(|error| StoreError::Malformed {
                path: self.path.clone(),
                reason: error.to_string(),
            })?;
        if document.version != STORE_VERSION {
            return Err(StoreError::Malformed {
                path: self.path.clone(),
                reason: format!(
                    "unsupported version {} (this build recognises {STORE_VERSION})",
                    document.version
                ),
            });
        }
        // Recognise EVERY record before returning ANY of them. Validating
        // lazily, or filtering the bad ones out, would be the permissive
        // parsing REQ-010 prohibits.
        for agent in &document.agents {
            recognise(agent).map_err(|reason| StoreError::Malformed {
                path: self.path.clone(),
                reason,
            })?;
        }
        Ok(document.agents)
    }

    /// Replace the store with `agents`, owner-only.
    pub fn save(&self, agents: &[PairedAgent]) -> Result<(), StoreError> {
        let _guard = STORE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.save_locked(agents)
    }

    /// [`Self::save`], for callers already holding [`STORE_LOCK`].
    fn save_locked(&self, agents: &[PairedAgent]) -> Result<(), StoreError> {
        for agent in agents {
            recognise(agent).map_err(|reason| StoreError::Malformed {
                path: self.path.clone(),
                reason,
            })?;
        }
        let document = StoreDocument {
            version: STORE_VERSION,
            agents: agents.to_vec(),
        };
        let body = serde_json::to_vec_pretty(&document).map_err(|error| StoreError::Write {
            path: self.path.clone(),
            source: std::io::Error::other(error),
        })?;
        self.write_owner_only(&body)
    }

    /// Add or replace the record for `agent.agent_handle`.
    ///
    /// The whole read-modify-write runs under [`STORE_LOCK`]: two joins
    /// completing at once would otherwise both read the same old list and both
    /// write, and whichever renamed last would silently drop the other agent —
    /// which then does not come back on the next start, the exact failure this
    /// store exists to prevent.
    ///
    /// An unrecognised store is an **error**, not an empty list. Degrading here
    /// the way [`Self::load`] does would let the next join overwrite a file it
    /// could not parse with a single record, destroying every pairing in it and
    /// "repairing" input REQ-010 says must stay rejected.
    pub fn upsert(&self, agent: PairedAgent) -> Result<(), StoreError> {
        let _guard = STORE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut agents = self.load_checked()?;
        agents.retain(|existing| existing.agent_handle != agent.agent_handle);
        agents.push(agent);
        self.save_locked(&agents)
    }

    /// Forget the record for `agent_handle`. Removing an *absent* record is a
    /// no-op — a `hark close` on an agent whose record has already gone must not
    /// fail the close — but an *unreadable* store is still an error, for the
    /// same reason as [`Self::upsert`].
    pub fn remove(&self, agent_handle: &str) -> Result<(), StoreError> {
        let _guard = STORE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut agents = self.load_checked()?;
        let before = agents.len();
        agents.retain(|existing| existing.agent_handle != agent_handle);
        if agents.len() == before {
            return Ok(());
        }
        self.save_locked(&agents)
    }

    /// Write atomically (temp + rename) with owner-only permissions, matching
    /// how `daemon.json` and the MLS state files are written. The mode is set
    /// on the temp file *before* the rename so the store is never briefly
    /// world-readable — it holds a capability.
    fn write_owner_only(&self, body: &[u8]) -> Result<(), StoreError> {
        let write = |source| StoreError::Write {
            path: self.path.clone(),
            source,
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(write)?;
        }
        // A temp path unique to this writer. [`STORE_LOCK`] serialises writers
        // inside one process, but a second `hark` process sharing the same
        // config directory is not covered by it — and a shared temp path lets
        // that process truncate ours, or rename it out from under us, between
        // our write and our rename.
        let temp = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp).map_err(write)?;
            use std::io::Write as _;
            file.write_all(body).map_err(write)?;
            file.sync_all().map_err(write)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // `mode()` on OpenOptions only applies at creation; an existing temp
            // from an earlier run keeps its old mode, so set it explicitly.
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
                .map_err(write)?;
        }
        std::fs::rename(&temp, &self.path).map_err(write)
    }
}

/// The per-record half of the [[SPEC-026 CON-002]] grammar, delegating every
/// field to the recogniser the live request path already uses.
fn recognise(agent: &PairedAgent) -> Result<(), String> {
    AgentHandle::new(agent.agent_handle.clone())
        .map_err(|_| format!("malformed agent handle {:?}", agent.agent_handle))?;
    validate_chat_handle("wire_handle", &agent.wire_handle).map_err(|error| error.to_string())?;
    validate_chat_handle("channel", &agent.channel).map_err(|error| error.to_string())?;
    for dialect in &agent.dialects {
        validate_dialect_id(dialect).map_err(|error| error.to_string())?;
    }
    if let Some(added_by) = &agent.added_by {
        validate_chat_handle("added_by", added_by).map_err(|error| error.to_string())?;
    }
    Ok(())
}
