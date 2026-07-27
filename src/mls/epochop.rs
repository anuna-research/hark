//! [[SPEC-027 REQ-012]] — the durable operation record.
//!
//! A committer that has merged a Commit under an armed claim owes the group two
//! things: the Commit itself, and (for an Add) the Welcome. Until both are
//! delivered and the claim released, the group and this agent disagree about
//! the epoch — and the claim is *armed*, which means the hub will not take it
//! back, because releasing it would be a fork.
//!
//! That obligation therefore has to survive the process. The claim dies with
//! the connection; the merge does not. Die in between with nothing on disk and
//! the agent restarts holding epoch E+1 while the group is still at E, with its
//! claim released — another committer takes it, advances E differently, and the
//! agent has forked the group and cannot tell.
//!
//! **Why the Welcome is in here and not just the Commit.** `add_member` produces
//! both from one `add_members` call and then merges (`super::group`). After that
//! the Welcome bytes exist only in the returned value: the group has advanced,
//! and re-running `add_members` for the same member is refused by the
//! duplicate-leaf guard as *"already a member"* — which is cbcl-bus BUG-022's
//! trap approached from the other side. A record holding only the Commit leaves
//! an invitee in the ratchet tree that can never be seated, and an armed claim
//! that cannot honestly be released.
//!
//! In-memory retention is not a smaller version of this. It is the thing a
//! restart loses.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What a restart should do about a record it finds ([[SPEC-027 REQ-012]]).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Recovery {
    /// The merge never happened: the group is still at the epoch the record was
    /// claimed against. Nothing is owed to anyone, so **release** the claim
    /// rather than reacquiring it — holding an armed claim for work that was
    /// never done strands the room's epoch behind an agent that is not going to
    /// use it.
    Release,
    /// The merge happened and this agent is a step ahead of the group. The
    /// Commit and Welcome must reach it before the claim can be released.
    Resend,
    /// The group has moved beyond this record — somebody else's Commit landed,
    /// or ours did and we saw the epoch advance. The record is stale and its
    /// obligations are discharged or void.
    Discard,
}

/// Decide what to do with a record found at startup.
///
/// `record_epoch` is the epoch the claim was taken against, i.e. the epoch the
/// group was at when the operation began. `group_epoch` is where the durable
/// group state actually is now.
///
/// The comparison is the whole trick, and it needs no extra marker: the record
/// is written *before* the merge, so the two epochs being equal means the merge
/// did not happen (or was not persisted, which is the same thing), and
/// `record + 1 == group` means it did. Anything further along means the world
/// moved on without us.
pub fn decide(record_epoch: u64, group_epoch: u64) -> Recovery {
    match group_epoch.checked_sub(record_epoch) {
        Some(0) => Recovery::Release,
        Some(1) => Recovery::Resend,
        // Ahead by more than one, or behind: either way this record no longer
        // describes anything we can act on.
        _ => Recovery::Discard,
    }
}

/// One merged-but-undelivered epoch operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochOp {
    pub room: String,
    /// The epoch the claim was taken against — the group's epoch *before* the
    /// merge. [`decide`] reads this against the live group.
    pub epoch: u64,
    /// Proof of holdership, and the only thing tying a new process and a new
    /// connection to the claim it already holds. Without it the claim cannot be
    /// armed, released, or reacquired.
    pub token: String,
    /// The Commit, base64. Regenerable only by re-running a merge that has
    /// already happened, i.e. not at all.
    pub commit: String,
    /// The Welcome, base64, for an Add. `None` for a Remove, which seats nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
    /// The handle the Welcome seats. `None` when there is no Welcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl EpochOp {
    /// An Add: a Commit that seats `target`, so it owes a Welcome.
    pub fn add(room: &str, epoch: u64, token: &str, commit: &str, welcome: &str, target: &str) -> Self {
        Self {
            room: room.to_owned(),
            epoch,
            token: token.to_owned(),
            commit: commit.to_owned(),
            welcome: Some(welcome.to_owned()),
            target: Some(target.to_owned()),
        }
    }

    /// A Remove: a Commit that seats nobody, so there is no Welcome to defer.
    pub fn remove(room: &str, epoch: u64, token: &str, commit: &str) -> Self {
        Self {
            room: room.to_owned(),
            epoch,
            token: token.to_owned(),
            commit: commit.to_owned(),
            welcome: None,
            target: None,
        }
    }

    /// Whether a Welcome is still owed to somebody.
    pub fn owes_welcome(&self) -> bool {
        self.welcome.is_some()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpStoreError {
    #[error("epoch operation record {path} could not be read: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("epoch operation record {path} could not be written: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("epoch operation record {path} is not recognised: {reason}")]
    Malformed { path: PathBuf, reason: String },
}

/// The durable record for one session, beside its MLS state.
#[derive(Debug, Clone)]
pub struct OpStore {
    path: PathBuf,
}

impl OpStore {
    /// The record beside `meta_path` (the session's `.mlsmeta`), so it is keyed
    /// on `(wire handle, room)` exactly as the group state it describes is.
    pub fn beside(meta_path: &Path) -> Self {
        Self {
            path: meta_path.with_extension("epochop"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the record, if there is one.
    ///
    /// A malformed record is an **error**, not an absence. This one is not the
    /// pairing store's "start with nothing and say so": a record that exists but
    /// cannot be read means an armed claim is outstanding whose obligations are
    /// unknown, and proceeding as though there were none would merge again on
    /// top of a merge.
    pub fn load(&self) -> Result<Option<EpochOp>, OpStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(OpStoreError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| OpStoreError::Malformed {
                path: self.path.clone(),
                reason: error.to_string(),
            })
    }

    /// Make `op` durable. MUST complete before the merge it describes.
    pub fn record(&self, op: &EpochOp) -> Result<(), OpStoreError> {
        let body = serde_json::to_vec_pretty(op).map_err(|error| OpStoreError::Write {
            path: self.path.clone(),
            source: std::io::Error::other(error),
        })?;
        self.write_atomically(&body)
    }

    /// Discharge the record. Called only once both frames are delivered and the
    /// claim released.
    pub fn clear(&self) -> Result<(), OpStoreError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(OpStoreError::Write {
                path: self.path.clone(),
                source,
            }),
        }
    }

    /// Temp + fsync + rename, owner-only, with a per-writer temp name — the same
    /// discipline as the MLS state beside it. The record carries group
    /// ciphertext and a claim token; neither is a bearer credential for the hub,
    /// but both describe an in-flight group mutation.
    fn write_atomically(&self, body: &[u8]) -> Result<(), OpStoreError> {
        let write = |source| OpStoreError::Write {
            path: self.path.clone(),
            source,
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(write)?;
        }
        let temp = self
            .path
            .with_extension(format!("epochop.tmp.{}", std::process::id()));
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
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
                .map_err(write)?;
        }
        std::fs::rename(&temp, &self.path).map_err(write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hark-epochop-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// REQ-012 — the recovery decision, which is the whole point of the record.
    ///
    /// The record is written BEFORE the merge, so the epochs being equal is
    /// exactly "the merge did not happen". No extra marker, no second write, and
    /// no window where the marker and the merge disagree.
    #[test]
    fn the_epoch_comparison_decides_recovery() {
        // Claimed at 7, group still at 7: nothing was merged, so nothing is
        // owed. Release rather than reacquire — cbcl-bus's own guidance, and
        // holding an armed claim for work never done strands the room's epoch.
        assert_eq!(decide(7, 7), Recovery::Release);
        // Claimed at 7, group at 8: we merged and the group has not seen it.
        assert_eq!(decide(7, 8), Recovery::Resend);
        // Further along, or behind: the record describes nothing actionable.
        assert_eq!(decide(7, 9), Recovery::Discard);
        assert_eq!(decide(7, 6), Recovery::Discard);
        // Epoch 0 is a real epoch and must not underflow.
        assert_eq!(decide(0, 0), Recovery::Release);
        assert_eq!(decide(0, 1), Recovery::Resend);
        assert_eq!(decide(5, 0), Recovery::Discard);
    }

    /// REQ-012 — the Welcome is in the record, because after the merge it cannot
    /// be regenerated: the group has advanced and `add_members` refuses the same
    /// member as "already a member".
    #[test]
    fn an_add_record_carries_the_welcome_and_its_target() {
        let store = OpStore::beside(&dir("add").join("aria.research.mlsmeta"));
        let op = EpochOp::add("@research", 7, "tok", "Y29tbWl0", "d2VsY29tZQ", "@bo");
        assert!(op.owes_welcome());
        store.record(&op).expect("record");

        let loaded = store.load().expect("load").expect("a record is there");
        assert_eq!(loaded, op);
        assert_eq!(loaded.welcome.as_deref(), Some("d2VsY29tZQ"));
        assert_eq!(loaded.target.as_deref(), Some("@bo"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// A Remove seats nobody, so it owes no Welcome — and the record says so
    /// rather than carrying an empty string that a reader has to interpret.
    #[test]
    fn a_remove_record_owes_no_welcome() {
        let store = OpStore::beside(&dir("rm").join("aria.research.mlsmeta"));
        let op = EpochOp::remove("@research", 7, "tok", "Y29tbWl0");
        assert!(!op.owes_welcome());
        store.record(&op).expect("record");
        assert_eq!(store.load().expect("load"), Some(op));
    }

    /// The lifecycle: absent → recorded → discharged. Clearing twice is a no-op,
    /// because a release that raced a restart must not fail the second time.
    #[test]
    fn a_discharged_record_is_gone_and_clearing_is_idempotent() {
        let store = OpStore::beside(&dir("clear").join("aria.research.mlsmeta"));
        assert_eq!(store.load().expect("absent is not an error"), None);

        store
            .record(&EpochOp::remove("@research", 7, "tok", "Y29tbWl0"))
            .expect("record");
        assert!(store.load().expect("load").is_some());

        store.clear().expect("clear");
        assert_eq!(store.load().expect("load"), None);
        store.clear().expect("clearing an absent record is a no-op");
    }

    /// **A malformed record is an error, not an absence** — the opposite of the
    /// pairing store's posture, and deliberately.
    ///
    /// An unreadable pairing store means "start with no agents", which is safe.
    /// An unreadable *operation* record means an armed claim is outstanding whose
    /// obligations are unknown. Treating that as "nothing to do" would merge
    /// again on top of a merge, which is the fork this whole mechanism exists to
    /// prevent.
    #[test]
    fn a_malformed_record_is_an_error_not_an_absence() {
        let store = OpStore::beside(&dir("bad").join("aria.research.mlsmeta"));
        std::fs::write(store.path(), b"{not json").unwrap();
        assert!(
            matches!(store.load(), Err(OpStoreError::Malformed { .. })),
            "an unreadable record must not read as 'no work outstanding'"
        );

        // An unknown field is the same class: a record written by something we
        // do not understand is not a record we may act on.
        std::fs::write(
            store.path(),
            br#"{"room":"@r","epoch":1,"token":"t","commit":"c","future":1}"#,
        )
        .unwrap();
        assert!(matches!(store.load(), Err(OpStoreError::Malformed { .. })));

        // And a missing required field.
        std::fs::write(store.path(), br#"{"room":"@r","epoch":1}"#).unwrap();
        assert!(matches!(store.load(), Err(OpStoreError::Malformed { .. })));
    }
}
