//! KeyPackage lifecycle (REQ-002, REQ-013, REQ-015, REQ-022).
//!
//! The directory is the untrusted hub, so single-use is enforced
//! **client-side**: a durable ledger of consumed `KeyPackageRef`s, and a
//! strictly ordered consume sequence — decrypt → validate → join succeeds →
//! ONLY THEN delete the one-time init key (openmls deletes the bundle when
//! `StagedWelcome::into_group` succeeds; a Welcome that fails validation
//! earlier leaves the init key intact, so a junk Welcome cannot burn the key
//! and brick the honest committer's Welcome).
//!
//! The pool: ≥1 one-time packages (preferred for every Add, replenished as
//! consumed) plus one **last-resort** package whose reuse is bounded by a
//! short MLS `lifetime` — `KeyPackageIn::validate()` rejects an expired
//! package at add time (`InvalidLifetime`, confirmed by the §10 spike), so
//! the bound is enforced by the primitive, not prose.

use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use openmls::prelude::{KeyPackage, KeyPackageIn, Lifetime, ProtocolVersion, Welcome};
use openmls_traits::OpenMlsProvider;
use tls_codec::{DeserializeBytes as _, Serialize as _};

use super::provider::DurableProvider;
use super::{MlsError, MlsIdentity, genesis_capabilities};

/// Directory input bound (REQ-015): a serialized KeyPackage at this suite is
/// a few hundred bytes; anything past this is malformed or hostile.
pub const MAX_KEYPACKAGE_BYTES: usize = 4096;

/// Last-resort lifetime (REQ-022): short, so a drained pool's exposure is
/// bounded by the primitive. Seven days.
pub const LAST_RESORT_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// One-time package lifetime: generous (they are deleted on use); 90 days.
pub const ONE_TIME_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// How many one-time packages to keep published (REQ-022 replenishment).
pub const ONE_TIME_POOL_TARGET: usize = 5;

const LEDGER_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct LedgerFile {
    version: u32,
    /// base64 `KeyPackageRef`s already consumed by a successful join.
    consumed: HashSet<String>,
}

/// Durable consumed-`KeyPackageRef` ledger (REQ-013). hark persists it (the
/// in-memory-only variant is the web client's documented weaker mode).
pub struct ConsumedLedger {
    path: PathBuf,
    consumed: HashSet<String>,
}

impl ConsumedLedger {
    pub fn open(path: &Path) -> Result<Self, MlsError> {
        let consumed = match fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => return Err(MlsError::Storage(e)),
            Ok(bytes) => {
                let file: LedgerFile = serde_json::from_slice(&bytes).map_err(|e| {
                    MlsError::Rejected(format!(
                        "consumed-ref ledger {} unreadable ({e}); refusing to forget consumed refs",
                        path.display()
                    ))
                })?;
                if file.version != LEDGER_VERSION {
                    return Err(MlsError::Rejected(format!(
                        "ledger version {} != supported {LEDGER_VERSION}",
                        file.version
                    )));
                }
                file.consumed
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            consumed,
        })
    }

    /// Has this `KeyPackageRef` (base64) already been consumed?
    pub fn is_consumed(&self, ref_b64: &str) -> bool {
        self.consumed.contains(ref_b64)
    }

    /// Fold another ledger file's refs into this one, ignoring duplicates.
    ///
    /// Used to consolidate the per-room ledgers this store used to be split
    /// across. Forgetting a consumed ref is the failure mode that matters, so a
    /// missing or unreadable file is skipped rather than fatal — but anything
    /// that IS readable is absorbed.
    pub fn absorb(&mut self, path: &Path) -> Result<(), MlsError> {
        let Ok(bytes) = fs::read(path) else { return Ok(()) };
        let Ok(file) = serde_json::from_slice::<LedgerFile>(&bytes) else {
            return Ok(());
        };
        let before = self.consumed.len();
        self.consumed.extend(file.consumed);
        if self.consumed.len() != before {
            self.persist()?;
        }
        Ok(())
    }

    /// Record a successful consume — called ONLY after a Welcome passed full
    /// validation and the join succeeded (REQ-013 step 4).
    pub fn mark_consumed(&mut self, ref_b64: &str) -> Result<(), MlsError> {
        if !self.consumed.insert(ref_b64.to_string()) {
            return Err(MlsError::Rejected(format!(
                "KeyPackageRef {ref_b64} already consumed (replay)"
            )));
        }
        self.persist()
    }

    fn persist(&self) -> Result<(), MlsError> {
        let file = LedgerFile {
            version: LEDGER_VERSION,
            consumed: self.consumed.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
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
        let mut f = options.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// A freshly built, TLS-serialized KeyPackage plus its ref.
pub struct BuiltKeyPackage {
    pub bytes: Vec<u8>,
    pub ref_b64: String,
    pub last_resort: bool,
}

/// Build one KeyPackage carrying the REQ-007 credential and the genesis
/// capability (REQ-016), with the given lifetime. The bundle (including the
/// init private key) is stored in the provider's storage by the builder.
fn build_key_package(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    lifetime_secs: u64,
    last_resort: bool,
) -> Result<BuiltKeyPackage, MlsError> {
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(genesis_capabilities())
        .key_package_lifetime(Lifetime::new(lifetime_secs))
        .build(
            super::CIPHERSUITE,
            provider,
            &identity.signer,
            identity.credential.clone(),
        )
        .map_err(MlsError::stack("build key package"))?;
    let key_package = bundle.key_package();
    let bytes = key_package
        .tls_serialize_detached()
        .map_err(MlsError::stack("serialize key package"))?;
    let hash_ref = key_package
        .hash_ref(provider.crypto())
        .map_err(MlsError::stack("hash ref"))?;
    let ref_b64 = B64.encode(hash_ref.as_slice());
    provider.persist()?;
    Ok(BuiltKeyPackage {
        bytes,
        ref_b64,
        last_resort,
    })
}

/// Build `n` one-time KeyPackages (REQ-002: at least one; REQ-022: the pool).
pub fn build_one_time(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    n: usize,
) -> Result<Vec<BuiltKeyPackage>, MlsError> {
    (0..n)
        .map(|_| build_key_package(provider, identity, ONE_TIME_LIFETIME_SECS, false))
        .collect()
}

/// Build the last-resort KeyPackage with its short, primitive-enforced
/// lifetime (REQ-022).
pub fn build_last_resort(
    provider: &DurableProvider,
    identity: &MlsIdentity,
) -> Result<BuiltKeyPackage, MlsError> {
    build_key_package(provider, identity, LAST_RESORT_LIFETIME_SECS, true)
}

/// Validate untrusted KeyPackage bytes from the directory (REQ-015 size and
/// structure; lifetime/signature via `KeyPackageIn::validate`, which rejects
/// an expired package — REQ-022's bound). The caller still performs the
/// REQ-008 target-handle + pinned-key checks.
pub fn validate_key_package_bytes(
    provider: &DurableProvider,
    bytes: &[u8],
) -> Result<KeyPackage, MlsError> {
    if bytes.is_empty() || bytes.len() > MAX_KEYPACKAGE_BYTES {
        return Err(MlsError::Rejected(format!(
            "key package size {} outside (0, {MAX_KEYPACKAGE_BYTES}]",
            bytes.len()
        )));
    }
    let kp_in = KeyPackageIn::tls_deserialize_exact_bytes(bytes)
        .map_err(|e| MlsError::Rejected(format!("key package deserialize: {e:?}")))?;
    kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::Rejected(format!("key package validate: {e:?}")))
}

/// The `KeyPackageRef`s a Welcome addresses (its `secrets[].new_member()`),
/// base64 — checked against the consumed ledger BEFORE processing (REQ-013:
/// a replayed Welcome to a consumed package must be inert).
pub fn welcome_refs(welcome: &Welcome) -> Vec<String> {
    welcome
        .secrets()
        .iter()
        .map(|s| B64.encode(s.new_member().as_slice()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ChatIdentity;

    fn setup(tag: &str) -> (PathBuf, DurableProvider, MlsIdentity) {
        let dir = std::env::temp_dir().join(format!("hark-kp-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let provider = DurableProvider::open(&dir.join("agent.mls")).unwrap();
        let wire = ChatIdentity::from_seed([21u8; 32]);
        let identity = MlsIdentity::from_wire_identity(&wire, "@aria");
        (dir, provider, identity)
    }

    /// REQ-002 (TEST-002): built packages carry the REQ-007 credential and
    /// pass directory validation.
    #[test]
    fn one_time_packages_build_and_validate() {
        let (_dir, provider, identity) = setup("build");
        let built = build_one_time(&provider, &identity, 2).unwrap();
        assert_eq!(built.len(), 2);
        for pkg in &built {
            assert!(!pkg.last_resort);
            let kp = validate_key_package_bytes(&provider, &pkg.bytes).unwrap();
            assert_eq!(
                kp.leaf_node().signature_key().as_slice(),
                identity.public_key(),
                "leaf key must be the wire identity key (REQ-007)"
            );
        }
        // Refs are distinct (each package is its own one-time key).
        assert_ne!(built[0].ref_b64, built[1].ref_b64);
    }

    /// REQ-015 (TEST-015): malformed and oversized inputs are rejected
    /// before any state mutation.
    #[test]
    fn malformed_and_oversized_inputs_rejected() {
        let (_dir, provider, _identity) = setup("malformed");
        assert!(validate_key_package_bytes(&provider, b"").is_err());
        assert!(validate_key_package_bytes(&provider, b"garbage").is_err());
        assert!(
            validate_key_package_bytes(&provider, &vec![0u8; MAX_KEYPACKAGE_BYTES + 1]).is_err()
        );
    }

    /// REQ-022 (TEST-022): an expired KeyPackage is rejected by the
    /// primitive at validate time (the §10 spike's r3_10, as a regression).
    #[test]
    fn expired_key_package_rejected() {
        let (_dir, provider, identity) = setup("expired");
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(genesis_capabilities())
            .key_package_lifetime(Lifetime::init(0, 1)) // expired in 1970
            .build(
                super::super::CIPHERSUITE,
                &provider,
                &identity.signer,
                identity.credential.clone(),
            )
            .unwrap();
        let bytes = bundle.key_package().tls_serialize_detached().unwrap();
        let err = validate_key_package_bytes(&provider, &bytes).unwrap_err();
        assert!(
            format!("{err}").contains("Lifetime") || format!("{err:?}").contains("Lifetime"),
            "expired package must reject with a lifetime error, got: {err}"
        );
    }

    /// REQ-013 (TEST-013): the consumed-ref ledger is durable and rejects
    /// double-consume.
    #[test]
    fn ledger_rejects_reuse_and_persists() {
        let dir = std::env::temp_dir().join(format!("hark-kp-ledger-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.kpledger");

        {
            let mut ledger = ConsumedLedger::open(&path).unwrap();
            assert!(!ledger.is_consumed("ref-1"));
            ledger.mark_consumed("ref-1").unwrap();
            assert!(ledger.is_consumed("ref-1"));
            assert!(ledger.mark_consumed("ref-1").is_err(), "double consume");
        }
        // Durable across restart.
        let ledger = ConsumedLedger::open(&path).unwrap();
        assert!(ledger.is_consumed("ref-1"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The init private key persists in durable storage at build time (it
    /// must survive until a *successful* join consumes it — REQ-013 ordering;
    /// the failed-Welcome-leaves-key-intact half is exercised end-to-end in
    /// the group tests).
    #[test]
    fn init_keys_are_durably_stored_at_build() {
        let (dir, provider, identity) = setup("initkey");
        let before = fs::read(dir.join("agent.mls"))
            .map(|b| b.len())
            .unwrap_or(0);
        build_one_time(&provider, &identity, 1).unwrap();
        let after = fs::read(dir.join("agent.mls")).unwrap().len();
        assert!(
            after > before,
            "building a package must persist its bundle (init key) durably"
        );
    }
}
