//! Durable OpenMLS provider (ADR-004, REQ-009, NFR-004).
//!
//! OpenMLS delegates *all* secret retention — including pruning superseded
//! epoch secrets — to its `StorageProvider`'s delete calls. The web client
//! uses an in-memory provider; hark is a long-lived daemon, so group state
//! must survive restarts (REQ-009) *and* deletes must actually reach disk,
//! otherwise every superseded secret is silently retained forever with no API
//! symptom (NFR-004's residual, IMPL condition I).
//!
//! Design: the battle-tested `MemoryStorage` keeps the live map (so every
//! OpenMLS storage call behaves exactly as upstream tests it), and
//! [`DurableProvider::persist`] snapshots that map atomically to a single
//! `0600` file under `identity_dir`. A snapshot of the *current* map is by
//! construction free of deleted entries, so delete fidelity reduces to
//! "persist after every mutating group operation" — which the [`super::session`]
//! facade centralises. The on-disk format carries a version; a version bump is
//! a re-join, never a silent migration (OQ-005).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use super::MlsError;

/// Bump on any incompatible change to the persisted layout. A mismatch on
/// load discards the state (re-join), per OQ-005: stale secret state must
/// not be silently migrated.
const STATE_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct StateFile {
    version: u32,
    /// base64(key) → base64(value) of the OpenMLS storage map.
    values: HashMap<String, String>,
}

/// An [`OpenMlsProvider`] whose storage snapshots durably to one file.
pub struct DurableProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
    path: PathBuf,
}

impl OpenMlsProvider for DurableProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl DurableProvider {
    /// Open (or initialise) the durable state at `path`. A missing file is a
    /// fresh provider; an unreadable, malformed, or version-mismatched file is
    /// set aside as `<path>.stale` and the provider starts empty — the caller
    /// re-joins (REQ-009 failure mode: "missing/stale persisted state →
    /// re-join, logged").
    pub fn open(path: &Path) -> Result<Self, MlsError> {
        let provider = Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
            path: path.to_path_buf(),
        };
        match fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(provider),
            Err(e) => Err(MlsError::Storage(e)),
            Ok(bytes) => match Self::decode(&bytes) {
                Ok(values) => {
                    *provider.storage.values.write().unwrap() = values;
                    Ok(provider)
                }
                Err(reason) => {
                    tracing::warn!(
                        path = %path.display(),
                        reason,
                        "mls state unreadable; setting aside and re-joining"
                    );
                    fs::rename(path, path.with_extension("stale"))?;
                    Ok(provider)
                }
            },
        }
    }

    fn decode(bytes: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, String> {
        let state: StateFile =
            serde_json::from_slice(bytes).map_err(|e| format!("malformed state file: {e}"))?;
        if state.version != STATE_VERSION {
            return Err(format!(
                "state version {} != supported {STATE_VERSION} (re-join, no silent migration)",
                state.version
            ));
        }
        let mut values = HashMap::with_capacity(state.values.len());
        for (k, v) in state.values {
            let key = B64.decode(k).map_err(|e| format!("bad key b64: {e}"))?;
            let value = B64.decode(v).map_err(|e| format!("bad value b64: {e}"))?;
            values.insert(key, value);
        }
        Ok(values)
    }

    /// Snapshot the current storage map atomically: write a `0600` temp file
    /// in the same directory, fsync, rename over `path`. Entries OpenMLS has
    /// deleted are absent from the snapshot — that is the delete fidelity
    /// NFR-004 requires of this provider (IMPL condition I).
    pub fn persist(&self) -> Result<(), MlsError> {
        let values = {
            let map = self.storage.values.read().unwrap();
            map.iter()
                .map(|(k, v)| (B64.encode(k), B64.encode(v)))
                .collect()
        };
        let state = StateFile {
            version: STATE_VERSION,
            values,
        };
        let bytes = serde_json::to_vec(&state).map_err(std::io::Error::other)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Discard every in-memory mutation since the last [`Self::persist`] by
    /// reloading the durable file. This is the REQ-013 enforcement seam:
    /// openmls consumes a one-time init key from (in-memory) storage when a
    /// Welcome is *staged*, before app-level validation can run — so a
    /// Welcome that fails SPEC-013 validation is followed by a rollback,
    /// leaving the init key intact in memory AND on disk. Only a successful
    /// join persists, which is what finally deletes the consumed key.
    pub fn rollback_to_disk(&self) -> Result<(), MlsError> {
        let values = match fs::read(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(MlsError::Storage(e)),
            Ok(bytes) => {
                Self::decode(&bytes).map_err(|r| MlsError::Storage(std::io::Error::other(r)))?
            }
        };
        *self.storage.values.write().unwrap() = values;
        Ok(())
    }

    /// The durable state file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw bytes currently on disk (tests: condition-I absence assertions).
    #[cfg(test)]
    pub fn disk_bytes(&self) -> std::io::Result<Vec<u8>> {
        fs::read(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::storage::{CURRENT_VERSION, Entity, StorageProvider as _, traits};

    /// A stand-in for any OpenMLS-stored entity, so the tests can exercise the
    /// provider's write/delete/persist mechanics through the real trait.
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
    struct TestState(Vec<u8>);
    impl Entity<CURRENT_VERSION> for TestState {}
    impl traits::GroupState<CURRENT_VERSION> for TestState {}

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hark-mls-prov-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Condition I, the direct mechanism: a value written through the OpenMLS
    /// storage API, persisted, deleted, and persisted again is ABSENT from the
    /// on-disk bytes — the provider honours deletes on disk, not just in RAM.
    #[test]
    fn deletes_reach_disk() {
        let dir = tempdir("delete");
        let path = dir.join("agent.mls");
        let provider = DurableProvider::open(&path).unwrap();

        let group_id = openmls::group::GroupId::from_slice(b"condition-i-group");
        let secret = TestState(b"SUPERSEDED-EPOCH-SECRET-SENTINEL".to_vec());
        provider
            .storage()
            .write_group_state(&group_id, &secret)
            .unwrap();
        provider.persist().unwrap();
        let on_disk = provider.disk_bytes().unwrap();
        let sentinel_b64 = B64.encode(serde_json::to_vec(&secret).unwrap());
        assert!(
            String::from_utf8_lossy(&on_disk).contains(&sentinel_b64),
            "sanity: the secret must be on disk before the delete"
        );

        provider
            .storage()
            .delete_group_state::<openmls::group::GroupId>(&group_id)
            .unwrap();
        provider.persist().unwrap();
        let on_disk = provider.disk_bytes().unwrap();
        assert!(
            !String::from_utf8_lossy(&on_disk).contains(&sentinel_b64),
            "condition I: a deleted entry must be absent from the durable file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// REQ-009: state written by one provider instance is read back by a
    /// fresh instance opened at the same path (daemon restart).
    #[test]
    fn reloads_across_restart() {
        let dir = tempdir("reload");
        let path = dir.join("agent.mls");
        let provider = DurableProvider::open(&path).unwrap();
        let group_id = openmls::group::GroupId::from_slice(b"restart-group");
        provider
            .storage()
            .write_group_state(&group_id, &TestState(b"state".to_vec()))
            .unwrap();
        provider.persist().unwrap();
        drop(provider);

        let reopened = DurableProvider::open(&path).unwrap();
        let read: Option<TestState> = reopened.storage().group_state(&group_id).unwrap();
        assert_eq!(read, Some(TestState(b"state".to_vec())));
        let _ = fs::remove_dir_all(&dir);
    }

    /// OQ-005: a version bump is a re-join — the old state is set aside, the
    /// provider starts empty, and nothing is silently migrated.
    #[test]
    fn version_bump_is_a_rejoin_not_a_migration() {
        let dir = tempdir("version");
        let path = dir.join("agent.mls");
        fs::write(
            &path,
            serde_json::to_vec(&StateFile {
                version: STATE_VERSION + 1,
                values: HashMap::from([(B64.encode(b"k"), B64.encode(b"v"))]),
            })
            .unwrap(),
        )
        .unwrap();

        let provider = DurableProvider::open(&path).unwrap();
        assert!(
            provider.storage.values.read().unwrap().is_empty(),
            "future-version state must not be migrated"
        );
        assert!(
            path.with_extension("stale").exists(),
            "old state is set aside, not destroyed"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// NFR-004 (at-rest): the durable file is created 0600.
    #[cfg(unix)]
    #[test]
    fn state_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("perm");
        let path = dir.join("agent.mls");
        let provider = DurableProvider::open(&path).unwrap();
        provider.persist().unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "group secrets must be owner-only");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A corrupt state file is set aside (re-join), never a crash loop.
    #[test]
    fn corrupt_state_is_set_aside() {
        let dir = tempdir("corrupt");
        let path = dir.join("agent.mls");
        fs::write(&path, b"not json at all").unwrap();
        let provider = DurableProvider::open(&path).unwrap();
        assert!(provider.storage.values.read().unwrap().is_empty());
        assert!(path.with_extension("stale").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
