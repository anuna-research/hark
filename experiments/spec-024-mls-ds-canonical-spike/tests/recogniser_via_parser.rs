//! IMPL-025 — the closed-world recogniser IS the cbcl-parser + the installed dialect.
//!
//! Correction (per Hugo): CON-011 closed-world recognition is NOT a bespoke artifact — it is
//! the general `cbcl-parser` recursive-descent parser + the dialect/role/causal validation
//! pipeline (`run_pipeline_full`, fail-closed per CON-206), driven entirely by the INSTALLED
//! dialect. "Recognising mls-ds/v1" = **install the full `mls-ds/v1` dialect and parse+validate
//! against it.** The `mls_ds.rs` typed-decode with `Other` shells is a proof-specific
//! convenience, not the recogniser. So there is nothing bespoke to build — H2 ingress consumes
//! the parser + the full dialect ([[IMPL-025-hark-mls-ds-client#ADR-031]] "one parser per
//! language, consumed not ported").
//!
//! This proves the full 40-performative dialect installs (the parser accepts the whole
//! closed-world language) and that `run_pipeline_full` recognises against it, fail-closed.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test recogniser_via_parser -- --nocapture

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::store::ThreadedMessageStore;
use cbcl_parser::{parse, parse_dialect, run_pipeline_full, PipelineContext, PipelineResult};

fn full_mls_ds_v1() -> cbcl_core::dialect::Dialect {
    let src = include_str!("../fixtures/mls-ds-v1.cbcl");
    parse_dialect(&parse(src).expect("parse mls-ds-v1.cbcl")).expect("parse_dialect")
}

/// The cbcl-parser INSTALLS the complete 40-performative mls-ds/v1 dialect — i.e. the parser
/// (the recogniser) accepts the whole closed-world language, R1–R6, no bespoke code.
#[test]
fn the_parser_installs_the_full_40_performative_mls_ds_v1_language() {
    let d = full_mls_ds_v1();
    assert_eq!(d.performatives.len(), 40, "the full dialect declares all 40 performatives");
    assert_eq!(d.roles.len(), 2, "roles {{client, ds}}");
    assert!(d.causal_protocol.is_some(), "the full causal protocol is present");

    let mut registry = DialectRegistry::new();
    registry
        .install(d)
        .expect("the full mls-ds/v1 dialect installs (R1–R6) — the closed-world language is recognised");
    println!("[recogniser] cbcl-parser installed the full 40-performative mls-ds/v1 dialect");
}

/// `run_pipeline_full` recognises messages against the installed dialect, fail-closed: a
/// ds→client performative sent without its request predecessor is a causal violation — the
/// dialect's causal protocol IS the closed-world rule, enforced by the parser pipeline.
#[test]
fn the_parser_pipeline_recognises_and_rejects_dialect_driven() {
    let mut registry = DialectRegistry::new();
    registry.install(full_mls_ds_v1()).expect("install");
    let store = ThreadedMessageStore::new();
    let ctx = PipelineContext::new(&registry, &store);

    // `commit-record` is a legal mls-ds/v1 performative, but the causal protocol says it may
    // only follow a `next-record` request. Sent bare, the parser pipeline rejects it — the
    // closed-world causal rule, enforced entirely from the installed dialect.
    let result = run_pipeline_full("(commit-record \"payload\")", &ctx);
    println!("[recogniser] bare `commit-record` -> {result:?}");
    assert!(
        !matches!(result, PipelineResult::Success(_)),
        "a ds->client record out of causal position must be rejected fail-closed, got {result:?}"
    );

    // A performative that is NOT in mls-ds/v1 (nor the base) is not recognised as this language.
    let unknown = run_pipeline_full("(totally-made-up-verb \"x\")", &ctx);
    println!("[recogniser] unknown verb -> {unknown:?}");
    assert!(
        !matches!(unknown, PipelineResult::Success(_)),
        "an unknown performative must not be recognised, got {unknown:?}"
    );
}
