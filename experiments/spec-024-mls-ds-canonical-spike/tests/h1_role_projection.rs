//! IMPL-025 H1 (partial) — mls-ds/v1 role-projection binding against the epp role layer.
//!
//! Consumes cbcl-core's SPEC-014 role verifier (`r6::r6_violations`) and role model over the
//! actual `mls-ds/v1` dialect — the "validate the mls-ds/v1 dialect / role verifier" half of
//! [[IMPL-025-hark-mls-ds-client#H1 — Bind the shared PRODUCTION role runtime]] that the `epp`
//! substrate supports. The verifier is CONSUMED, never ported (ADR-031). The mls-ds *message*
//! verifier (`verify_mls_ds_request`) is a further layer (see README topology); it is out of
//! scope here.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h1_role_projection -- --nocapture

use cbcl_core::dialect::Dialect;
use cbcl_core::r6::{derive_envelope_routes, r6_violations};
use cbcl_core::role::RoleCardinality;
use cbcl_parser::{parse, parse_dialect};

fn mls_ds_v1() -> Dialect {
    let src = include_str!("../fixtures/mls-ds-v1.cbcl");
    parse_dialect(&parse(src).expect("parse mls-ds-v1.cbcl into an SExpr"))
        .expect("parse_dialect(mls-ds/v1) under the epp role-layer runtime")
}

/// The load-bearing check — the SPEC-014 R6 verifier ACCEPTS the mls-ds/v1 role layer.
/// An empty violation set is the fail-closed recogniser's "well-formed" verdict.
#[test]
fn r6_verifier_accepts_the_mls_ds_v1_role_layer() {
    let d = mls_ds_v1();
    let violations = r6_violations(&d);
    println!("[H1 role] r6_violations = {} {:?}", violations.len(), violations);
    assert!(
        violations.is_empty(),
        "mls-ds/v1 must pass the SPEC-014 R6 role verifier with zero violations"
    );
}

/// The dialect declares exactly the two singleton roles the DS contract names.
#[test]
fn declares_client_and_ds_as_singletons() {
    let d = mls_ds_v1();
    let mut names: Vec<(&str, RoleCardinality)> =
        d.roles.iter().map(|r| (r.name.as_str(), r.cardinality)).collect();
    names.sort_by(|a, b| a.0.cmp(b.0));
    println!("[H1 role] roles = {names:?}");
    assert_eq!(d.roles.len(), 2, "mls-ds/v1 declares exactly {{client, ds}}");
    for name in ["client", "ds"] {
        let r = d
            .roles
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("role `{name}` not declared"));
        assert_eq!(
            r.cardinality,
            RoleCardinality::Singleton,
            "`{name}` must be a singleton role (bare name, not the `(* name)` indexed form)"
        );
    }
}

/// Every performative projects to an endpoint, and the split is the DS contract's
/// 15 client→ds requests + 25 ds→client responses = 40.
#[test]
fn projects_40_performatives_15_client_requests_25_ds_responses() {
    let d = mls_ds_v1();
    let (mut client_to_ds, mut ds_to_client, mut other) = (0usize, 0usize, Vec::new());
    for p in &d.performatives {
        match &p.role {
            Some(a) if a.from == "client" && a.to.contains("ds") => client_to_ds += 1,
            Some(a) if a.from == "ds" && a.to.contains("client") => ds_to_client += 1,
            _ => other.push(p.name.clone()),
        }
    }
    println!(
        "[H1 role] performatives={} client->ds={client_to_ds} ds->client={ds_to_client} other={other:?}",
        d.performatives.len()
    );
    assert!(other.is_empty(), "every mls-ds/v1 performative must route client<->ds: {other:?}");
    assert_eq!(client_to_ds, 15, "15 client->ds requests");
    assert_eq!(ds_to_client, 25, "25 ds->client responses");
    assert_eq!(client_to_ds + ds_to_client, 40, "40 performatives total");
}

/// Envelope-route derivation is total and deterministic over the dialect (SPEC-015 REQ-709).
#[test]
fn envelope_routes_derive_totally_and_deterministically() {
    let d = mls_ds_v1();
    let routes = derive_envelope_routes(&d);
    println!("[H1 role] envelope-route entries = {}", routes.0.len());
    assert_eq!(
        derive_envelope_routes(&d),
        routes,
        "derive_envelope_routes must be a pure deterministic function of the dialect"
    );
}
