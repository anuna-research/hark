//! In-memory cache of dialects taught to this hark daemon by the router.
//!
//! When a hark subscribes via `(meta (subscribe (speak? <pattern>)))`,
//! the router pushes `(meta (teach @<self> (define ...)))` frames as new
//! matching dialects are registered upstream. The receive loop intercepts
//! those (via [`crate::cbcl_validation::classify_inbound`]) and stores
//! the `(define ...)` body here keyed by digest, so the daemon can:
//!
//!   1. dedupe identical re-pushes (content addressing — same digest →
//!      same body),
//!   2. answer "do I already know <name>?" without going back to the
//!      router,
//!   3. surface the body to the local agent for install (load skills,
//!      update its `dialects` advertisement on next re-hello).
//!
//! ## R1–R3 enforcement on install (NON-NEGOTIABLE)
//!
//! A push frame is, semantically, untrusted content arriving from the
//! router. Even though the router itself validates on accept (REQ-208 /
//! REQ-210), hark MUST re-run the cbcl-rs verification pipeline before
//! the define becomes part of this daemon's routing surface. The
//! invariants are the load-bearing reason CBCL is a sound substrate:
//!
//!   - R1 (no recursion): templates are declarative; no cycles or
//!     reflection. A malicious define that tries to expand into itself
//!     gets rejected here.
//!   - R2 (resource bounds): depth, expansion size, verification time
//!     are statically capped. Without this gate a pushed dialect could
//!     burn arbitrary resources on the next message that uses it.
//!   - R3 (core preservation): the eight core performatives (`tell`,
//!     `ask`, `reply`, `hello`, `bye`, `ok`, `error`, `cancel`) cannot
//!     be redefined. A pushed dialect that tries to redefine `tell` is
//!     a substrate compromise; reject before it touches local state.
//!
//! `cbcl_parser::run_pipeline` runs R1–R5 in one pass on meta forms
//! (REQ-210). We call it on `(meta <define>)` constructed from the
//! incoming inner define and only insert on Success.
//!
//! Persistence is out of scope for this sketch — the cache lives for the
//! life of the daemon process. SPEC-009 §"Open for follow-up work" notes
//! Mnesia / disk-backed promotion as a follow-up alongside `cbcl-storage`.

use cbcl_core::dialect::DialectRegistry;
use cbcl_parser::{PipelineResult, parse, parse_dialect, run_pipeline};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// One cached dialect.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedDialect {
    pub digest: String,
    pub name: String,
    pub define_form: String,
    pub cached_at_unix_ms: u128,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum InstallError {
    /// cbcl-rs's parser pipeline rejected the define form. Contains the
    /// upstream diagnostic so the caller can log / surface to operators.
    #[error("dialect failed R1–R5 validation: {0}")]
    Rejected(String),
    /// Pipeline returned Pending/Buffered — shouldn't happen for a
    /// self-contained meta-define but signalled defensively.
    #[error("dialect pipeline state unexpected: {0}")]
    Unexpected(String),
}

/// Thread-safe in-memory dialect cache. Cloneable handle around an
/// `Arc<RwLock<...>>` — cheap to pass to spawned tasks.
#[derive(Debug, Clone, Default)]
pub struct DialectCache {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    by_digest: HashMap<String, CachedDialect>,
    /// Parsed dialect bodies keyed by content-addressed digest. Kept in
    /// lock-step with `by_digest`; absent for digests installed via the
    /// test-only `install_unchecked` escape hatch when the body did not
    /// parse cleanly.
    parsed_by_digest: HashMap<String, cbcl_core::dialect::Dialect>,
    /// Name → latest-pushed digest. Latest-write-wins; versioned routing
    /// is future work, mirroring the router-side `resolve-name/1`.
    latest_by_name: HashMap<String, String>,
    /// First-install order of dialect names. Used to rebuild the
    /// registry deterministically so child dialects that `(extend …)`
    /// a custom parent get installed after their parent.
    install_order: Vec<String>,
    /// Memoised registry snapshot. Cleared whenever `latest_by_name`
    /// or `parsed_by_digest` mutate; rebuilt lazily on the next
    /// `registry_snapshot` / `with_registry` call. Without this
    /// invalidation, a same-name update (e.g. publish v1 then publish
    /// v2 of `greet-d`) would keep the registry pinned to v1 even
    /// though `latest_by_name` resolves to v2's digest, so the R5
    /// pipeline would enforce stale shape/protocol rules.
    cached_registry: Option<DialectRegistry>,
}

impl DialectCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate and install a dialect body. `define_form` MUST start with
    /// `(define <name> ...)`. Runs the cbcl-rs pipeline (R1–R5) on a
    /// synthetic `(meta <define_form>)` envelope and returns the SHA-256
    /// digest of the stored body on success. Identical content gives a
    /// stable digest (content addressing); the same digest is overwritten
    /// in place with a fresh timestamp.
    pub fn try_install(
        &self,
        name: impl Into<String>,
        define_form: impl Into<String>,
    ) -> Result<String, InstallError> {
        let define_form = define_form.into();
        let name = name.into();
        let envelope = format!("(meta {define_form})");
        match run_pipeline(&envelope) {
            PipelineResult::Success(_) => {
                // Pipeline already validated R1–R5; now parse into a
                // structured `Dialect` and install into the in-memory
                // registry. A parse error here is treated as a rejection:
                // if the pipeline accepted the form but we can't extract
                // a `Dialect`, the cache and registry would drift.
                let sexpr = parse(&define_form).map_err(|e| {
                    InstallError::Rejected(format!("define_form parse failed: {e}"))
                })?;
                let dialect = parse_dialect(&sexpr).map_err(InstallError::Rejected)?;
                Ok(self.install_unchecked_with_dialect(name, define_form, Some(dialect)))
            }
            PipelineResult::ParseError(error) => Err(InstallError::Rejected(error.to_string())),
            PipelineResult::ValidationError(error) => {
                Err(InstallError::Rejected(error.to_string()))
            }
            PipelineResult::Pending { .. } | PipelineResult::Buffered { .. } => {
                Err(InstallError::Unexpected(
                    "pipeline returned pending/buffered for self-contained define".to_owned(),
                ))
            }
        }
    }

    /// Bypass for tests that need to seed the cache without exercising the
    /// pipeline (e.g. when stubbing with fixture bytes that aren't full
    /// R1–R5-clean defines). Production code paths MUST go through
    /// `try_install`.
    #[doc(hidden)]
    pub fn install_unchecked(
        &self,
        name: impl Into<String>,
        define_form: impl Into<String>,
    ) -> String {
        let define_form = define_form.into();
        let name = name.into();
        // Test-only entrypoint: try to parse the form into a Dialect so
        // the registry stays in sync where possible, but tolerate fixture
        // strings that aren't well-formed defines.
        let parsed = parse(&define_form)
            .ok()
            .and_then(|sexpr| parse_dialect(&sexpr).ok());
        self.install_unchecked_with_dialect(name, define_form, parsed)
    }

    fn install_unchecked_with_dialect(
        &self,
        name: String,
        define_form: String,
        dialect: Option<cbcl_core::dialect::Dialect>,
    ) -> String {
        let digest = sha256_hex(define_form.as_bytes());
        let cached = CachedDialect {
            digest: digest.clone(),
            name: name.clone(),
            define_form,
            cached_at_unix_ms: now_unix_ms(),
        };
        let mut inner = self.inner.write().expect("dialect-cache lock poisoned");
        inner.by_digest.insert(digest.clone(), cached);
        if let Some(d) = dialect {
            inner.parsed_by_digest.insert(digest.clone(), d);
        }
        let previous = inner.latest_by_name.insert(name.clone(), digest.clone());
        if previous.is_none() {
            inner.install_order.push(name.clone());
        }
        // Any mutation invalidates the memoised registry. The next
        // `registry_snapshot` rebuilds from the current `latest_by_name`
        // → `parsed_by_digest` pair so same-name updates take effect
        // immediately, without leaving the prior version cached.
        inner.cached_registry = None;
        digest
    }

    /// Build a `DialectRegistry` from the currently-installed parsed
    /// dialects, in stable insertion order. Caller must hold the inner
    /// write lock.
    fn build_registry_locked(inner: &Inner) -> DialectRegistry {
        let mut registry = DialectRegistry::new();
        for name in &inner.install_order {
            let Some(digest) = inner.latest_by_name.get(name) else {
                continue;
            };
            let Some(dialect) = inner.parsed_by_digest.get(digest) else {
                // `install_unchecked` escape hatch may bypass parsing for
                // test fixtures; such dialects never join the registry.
                continue;
            };
            if let Err(err) = registry.install(dialect.clone()) {
                tracing::warn!(
                    target: "dialect_cache",
                    error = %err,
                    name = %name,
                    digest = %digest,
                    "registry rebuild rejected dialect that previously passed the pipeline"
                );
            }
        }
        registry
    }

    /// Lookup by digest.
    pub fn fetch(&self, digest: &str) -> Option<CachedDialect> {
        self.inner
            .read()
            .expect("dialect-cache lock poisoned")
            .by_digest
            .get(digest)
            .cloned()
    }

    /// Latest digest known for a dialect name, if any.
    pub fn resolve_name(&self, name: &str) -> Option<String> {
        self.inner
            .read()
            .expect("dialect-cache lock poisoned")
            .latest_by_name
            .get(name)
            .cloned()
    }

    /// True iff the cache already knows this name (any version).
    pub fn knows(&self, name: &str) -> bool {
        self.resolve_name(name).is_some()
    }

    /// Snapshot the in-memory dialect registry. Rebuilds lazily after
    /// any mutation so same-name updates (e.g. publishing v2 of a
    /// dialect that was already v1 in the cache) are reflected.
    /// Intended for building a `PipelineContext` per outbound/inbound
    /// message in the R5 pipeline.
    pub fn registry_snapshot(&self) -> DialectRegistry {
        // Fast path: registry is already memoised under a read lock.
        {
            let inner = self.inner.read().expect("dialect-cache lock poisoned");
            if let Some(cached) = inner.cached_registry.as_ref() {
                return cached.clone();
            }
        }
        // Slow path: rebuild under the write lock. Re-check the cache
        // after acquiring it so a concurrent rebuilder doesn't pay the
        // cost twice.
        let mut inner = self.inner.write().expect("dialect-cache lock poisoned");
        if inner.cached_registry.is_none() {
            inner.cached_registry = Some(Self::build_registry_locked(&inner));
        }
        inner
            .cached_registry
            .as_ref()
            .expect("registry built under write lock above")
            .clone()
    }

    /// Borrow the in-memory registry under the cache lock. Use when the
    /// caller only needs read access and wants to avoid cloning the
    /// underlying `Vec<Dialect>`.
    pub fn with_registry<R>(&self, f: impl FnOnce(&DialectRegistry) -> R) -> R {
        // Fast path: cached registry exists; borrow under read lock.
        {
            let inner = self.inner.read().expect("dialect-cache lock poisoned");
            if let Some(cached) = inner.cached_registry.as_ref() {
                return f(cached);
            }
        }
        let mut inner = self.inner.write().expect("dialect-cache lock poisoned");
        if inner.cached_registry.is_none() {
            inner.cached_registry = Some(Self::build_registry_locked(&inner));
        }
        f(inner
            .cached_registry
            .as_ref()
            .expect("registry built under write lock above"))
    }

    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("dialect-cache lock poisoned")
            .by_digest
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal R1–R5-clean define accepted by cbcl-rs's pipeline. Used
    // throughout these tests; identical content yields identical digest.
    const GOOD_DEFINE: &str = "(define cache-fixture (cbcl) @author)";

    #[test]
    fn try_install_then_fetch_round_trips() {
        let cache = DialectCache::new();
        let digest = cache
            .try_install("cache-fixture", GOOD_DEFINE)
            .expect("R1–R5-clean fixture must install");
        let fetched = cache.fetch(&digest).expect("just installed");
        assert_eq!(fetched.name, "cache-fixture");
        assert_eq!(fetched.define_form, GOOD_DEFINE);
    }

    #[test]
    fn identical_content_produces_stable_digest() {
        let cache = DialectCache::new();
        let d1 = cache.try_install("cache-fixture", GOOD_DEFINE).unwrap();
        let d2 = cache.try_install("cache-fixture", GOOD_DEFINE).unwrap();
        assert_eq!(d1, d2, "content-addressed digests must be stable");
    }

    #[test]
    fn knows_and_len_track_install() {
        let cache = DialectCache::new();
        assert!(cache.is_empty());
        assert!(!cache.knows("cache-fixture"));
        cache.try_install("cache-fixture", GOOD_DEFINE).unwrap();
        assert!(cache.knows("cache-fixture"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn r1_r5_violation_is_rejected_before_install() {
        // A define that fails the cbcl-rs pipeline (cyclic extend per
        // SPEC-002 §"protocol references" rules; pulled from cbcl-rs's
        // own pipeline tests). The specific shape doesn't matter — only
        // that the pipeline rejects it. The cache MUST refuse to store.
        let cache = DialectCache::new();
        let bad = "(define bad (cbcl) @author (extend tell () x))";
        let result = cache.try_install("bad", bad);
        assert!(matches!(result, Err(InstallError::Rejected(_))));
        assert!(!cache.knows("bad"), "rejected dialect must not be cached");
        assert!(cache.is_empty());
    }

    #[test]
    fn malformed_cbcl_is_rejected() {
        let cache = DialectCache::new();
        let result = cache.try_install("syntax", "(define oops");
        assert!(matches!(result, Err(InstallError::Rejected(_))));
    }

    #[test]
    fn try_install_populates_registry_snapshot() {
        let cache = DialectCache::new();
        cache
            .try_install("cache-fixture", GOOD_DEFINE)
            .expect("R1–R5-clean fixture must install");

        let snapshot = cache.registry_snapshot();
        assert!(
            snapshot.find_by_name("cache-fixture").is_some(),
            "registry must contain the installed dialect"
        );
        // Base dialect remains at index 0 alongside the installed one.
        assert!(snapshot.len() >= 2);

        // with_registry must observe the same state.
        cache.with_registry(|r| {
            let d = r
                .find_by_name("cache-fixture")
                .expect("with_registry must see the installed dialect");
            assert_eq!(d.name, "cache-fixture");
        });
    }

    #[test]
    fn same_name_update_refreshes_registry_snapshot() {
        // Reviewer's P2 case: install v1 of a dialect, take a snapshot,
        // install v2 of the same name with different content, take a
        // fresh snapshot. The new snapshot must reflect v2's parsed
        // dialect, not v1's. Before the cached-registry invalidation
        // fix this assertion failed: latest_by_name pointed at v2's
        // digest but the registry kept v1's Dialect.
        let cache = DialectCache::new();
        // v1 has no protocol; v2 introduces one.
        let v1 = "(define same-name-fixture (cbcl) @author)";
        let v2 = "(define same-name-fixture (cbcl) @author \
                  (protocol (then begin reply)))";
        cache
            .try_install("same-name-fixture", v1)
            .expect("v1 must install");
        let first = cache.registry_snapshot();
        let first_dialect = first
            .find_by_name("same-name-fixture")
            .expect("v1 must be in first snapshot");
        assert!(
            first_dialect.causal_protocol.is_none(),
            "v1 has no protocol clause"
        );

        cache
            .try_install("same-name-fixture", v2)
            .expect("v2 must install");
        let second = cache.registry_snapshot();
        let second_dialect = second
            .find_by_name("same-name-fixture")
            .expect("v2 must be in second snapshot");
        assert!(
            second_dialect.causal_protocol.is_some(),
            "v2 must surface its (protocol ...) clause in the new snapshot",
        );

        // with_registry must observe the same updated state.
        cache.with_registry(|r| {
            let d = r
                .find_by_name("same-name-fixture")
                .expect("with_registry must see v2");
            assert!(d.causal_protocol.is_some(), "with_registry must see v2");
        });
    }
}
