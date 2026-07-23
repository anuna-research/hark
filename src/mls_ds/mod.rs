//! SPEC-024 `mls-ds/v1` Delivery-Service client — IMPL-025. Real hark production module.
//!
//! CONSUMES the pinned role-layer cbcl-rs (ADR-031, no re-porting): `canonical_encode`, the
//! closed-world recogniser (the `cbcl-parser` pipeline + the installed full `mls-ds/v1`
//! dialect — CON-011), the SPEC-014 role layer, and the corrected `DomainTuple` crypto +
//! strict Ed25519 (CON-002/003, `mls-ds-proof`). PORTS the CON-005 decision/ordering logic
//! (ADR-032), computing every preimage via `DomainTuple`.
//!
//! This is the production home of the cores validated pre-pin in
//! `experiments/spec-024-mls-ds-canonical-spike/` (57 tests). Wiring into the live receive
//! path (`chat.rs` pull loop, ADR-035) is layered on top of this module.

pub mod attestation;
pub mod boundary;
pub mod closure;
pub mod genesis;
pub mod store;

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::mls_ds::{DomainTuple, ReadContext};
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_core::store::ThreadedMessageStore;
use cbcl_parser::{parse, parse_dialect, run_pipeline_full, PipelineContext, PipelineResult};
use sha2::{Digest, Sha256};

/// The normative `mls-ds/v1` dialect source (byte-authority; hash `sha256:922ba8…`).
const MLS_DS_V1: &str = include_str!("../../priv/dialects/mls-ds-v1.cbcl");

/// Install the closed-world `mls-ds/v1` dialect into a fresh registry (CON-011). The registry
/// IS the recogniser's language: `run_pipeline_full` validates every inbound payload against it.
pub fn install_dialect() -> DialectRegistry {
    let d = parse_dialect(&parse(MLS_DS_V1).expect("mls-ds-v1.cbcl parses"))
        .expect("parse_dialect(mls-ds/v1)");
    let mut registry = DialectRegistry::new();
    registry
        .install(d)
        .expect("mls-ds/v1 installs (R1–R6) — the closed-world language is recognised");
    registry
}

/// CON-011 ingress recognition: parse + validate an inbound DS payload against the installed
/// dialect, fail-closed (CON-206). `Ok` = a recognised, legal `mls-ds/v1` message; `Err` = the
/// diagnostic for a rejected/unrecognised one. The recogniser is the parser — never a bespoke
/// scan (ADR-031, LangSec one-parser-per-language).
pub fn recognize(registry: &DialectRegistry, payload: &str) -> Result<(), String> {
    let store = ThreadedMessageStore::new();
    let ctx = PipelineContext::new(registry, &store);
    match run_pipeline_full(payload, &ctx) {
        PipelineResult::Success(_) => Ok(()),
        other => Err(alloc_fmt(&other)),
    }
}

fn alloc_fmt(r: &PipelineResult) -> String {
    format!("{r:?}")
}

// ---------------------------------------------------------------------------
// CON-005 client reducer — exact-next admission core (ADR-032: semantic ported,
// crypto consumed via the corrected DomainTuple::Record).
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The bare record content hash (the cursor chain link).
pub fn record_hash(log_record: &SExpr) -> String {
    format!("sha256:{}", to_hex(&Sha256::digest(cbcl_core::canonical::canonical_encode(log_record))))
}

/// The client's per-room log cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientLog {
    pub cursor: i64,
    pub cursor_hash: String,
}

/// A verified DS response carrying a log record (post-CON-012 authentication).
pub struct RecordResponse {
    pub seq: i64,
    pub prev_hash: String,
    pub record_hash: String,
    pub record_signature: [u8; 64],
    pub log_record: SExpr,
}

/// The CON-005 record-admission verdict.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// C-APPLIED: advance the cursor by one; `cursor_hash := record_hash`.
    Applied { cursor: i64, cursor_hash: String },
    /// notNext (REQ-034): cursor preserved, no effect.
    NotNext,
    /// Violation(ds-equivocation): cursor + group held; bytes retained as fork evidence.
    Violation(&'static str),
}

/// `transition_client` record-admission core (CON-005 / REQ-034). `ds_vk` is the pinned DS key.
pub fn transition_record(log: &ClientLog, ds_vk: &[u8; 32], resp: &RecordResponse) -> Verdict {
    if record_hash(&resp.log_record) != resp.record_hash {
        return Verdict::Violation("ds-equivocation:record-hash-mismatch");
    }
    let record = DomainTuple::Record { log_record: resp.log_record.clone() };
    if !record.verify(ds_vk, &resp.record_signature) {
        return Verdict::Violation("ds-equivocation:record-signature-invalid");
    }
    if !(resp.seq == log.cursor + 1 && resp.prev_hash == log.cursor_hash) {
        return Verdict::NotNext;
    }
    Verdict::Applied { cursor: resp.seq, cursor_hash: resp.record_hash.clone() }
}

// ---------------------------------------------------------------------------
// CON-012 read-frame binding — response authentication (ADR-036). The recogniser-
// independent frame layer: verify the outer DS sig, then bind BOTH the retained
// frame context and the request-content hash to the outstanding request.
// ---------------------------------------------------------------------------

/// An outstanding read root the transport retains for a pending read request.
pub struct OutstandingRead {
    pub session_id: String,
    pub frame_id: i64,
    pub request_content_hash: String,
}

/// CON-012 response frame verification. Rejects response-frame-for-request-frame substitution.
pub fn verify_response_frame(
    o: &OutstandingRead,
    ds_vk: &[u8; 32],
    resp: &DomainTuple,
    sig: &[u8; 64],
) -> Result<(), &'static str> {
    if !resp.verify(ds_vk, sig) {
        return Err("response-signature-invalid");
    }
    let DomainTuple::Response { request_content_hash, read_context, .. } = resp else {
        return Err("not-a-response");
    };
    match read_context {
        ReadContext::Read { session_id, frame_id } => {
            if session_id != &o.session_id || *frame_id != o.frame_id {
                return Err("frame-transplant");
            }
        }
        ReadContext::None => return Err("read-context-missing"),
    }
    if request_content_hash != &o.request_content_hash {
        return Err("request-content-mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::mls_ds::Ed25519Keypair;

    fn sym(s: &str) -> SExpr {
        SExpr::Atom(Atom::Symbol(s.into()))
    }
    fn st(s: &str) -> SExpr {
        SExpr::Atom(Atom::Str(s.into()))
    }
    fn num(n: i64) -> SExpr {
        SExpr::Atom(Atom::Num(n))
    }

    const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn dialect_installs_and_recognises_fail_closed() {
        let reg = install_dialect();
        // a legal performative out of causal position is recognised then rejected (dialect-driven)
        assert!(recognize(&reg, "(commit-record \"x\")").is_err());
        // an unknown performative is not recognised
        assert!(recognize(&reg, "(totally-made-up-verb \"x\")").is_err());
    }

    fn signed_record(seq: i64, prev_hash: &str, ds: &Ed25519Keypair) -> RecordResponse {
        let rec = SExpr::List(vec![sym("log-v1"), st("room-alpha"), num(seq), st(prev_hash)]);
        let rh = record_hash(&rec);
        let sig = DomainTuple::Record { log_record: rec.clone() }.sign(ds);
        RecordResponse { seq, prev_hash: prev_hash.into(), record_hash: rh, record_signature: sig, log_record: rec }
    }

    #[test]
    fn reducer_exact_next_applies_and_holds() {
        let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
        let vk = ds.public_bytes();
        let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
        assert!(matches!(transition_record(&log, &vk, &signed_record(1, H0, &ds)), Verdict::Applied { cursor: 1, .. }));
        assert_eq!(transition_record(&log, &vk, &signed_record(2, H0, &ds)), Verdict::NotNext);
        let forger = Ed25519Keypair::from_seed(&[6u8; 32]);
        assert_eq!(
            transition_record(&log, &vk, &signed_record(1, H0, &forger)),
            Verdict::Violation("ds-equivocation:record-signature-invalid")
        );
    }
}
