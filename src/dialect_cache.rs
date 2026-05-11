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

use cbcl_parser::{PipelineResult, run_pipeline};
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
    /// Name → latest-pushed digest. Latest-write-wins; versioned routing
    /// is future work, mirroring the router-side `resolve-name/1`.
    latest_by_name: HashMap<String, String>,
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
            PipelineResult::Success(_) => Ok(self.install_unchecked(name, define_form)),
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
        let digest = sha256_hex(define_form.as_bytes());
        let cached = CachedDialect {
            digest: digest.clone(),
            name: name.clone(),
            define_form,
            cached_at_unix_ms: now_unix_ms(),
        };
        let mut inner = self.inner.write().expect("dialect-cache lock poisoned");
        inner.by_digest.insert(digest.clone(), cached);
        inner.latest_by_name.insert(name, digest.clone());
        digest
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
}
