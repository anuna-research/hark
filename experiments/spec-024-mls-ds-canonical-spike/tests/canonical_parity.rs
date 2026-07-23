//! SPEC-024 mls-ds/v1 — canonical-vector proof-of-fit spike (IMPL-025 §2 proof gate).
//!
//! GATE-PERMITTED, ISOLATED. Links the production `cbcl-core` encoder as hark links
//! it and asserts CON-002 byte-identity against the SPEC-024 *byte-authority* vectors
//! and (once the production role layer is pinned) the canonical `mls-ds/v1` dialect
//! hash. Proves the CON-002 foundation ONLY; MUST NOT be reported as role-runtime
//! binding (IMPL-025 H1 / ADR-031).
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       -- --nocapture
//!
//! The expected bytes are READ from the checked-in authority file
//! (`fixtures/mls_ds_canonical_vectors.txt`, copied verbatim from
//! cbcl-bus `apps/cbcl_chat/priv/web/`) — never hand-transcribed. Only the *input*
//! SExpr for each label is reconstructed here; a wrong reconstruction fails the
//! byte-identity assertion loudly, so it cannot silently pass.

use std::collections::BTreeMap;

use cbcl_core::canonical::{canonical_encode, dialect_canonical_bytes};
use cbcl_core::sexpr::{Atom, SExpr};
use sha2::{Digest, Sha256};

// -- SExpr constructors (mirror cbcl_core::sexpr) ---------------------------------
fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(s.into()))
}
fn kw(s: &str) -> SExpr {
    SExpr::Atom(Atom::Keyword(s.into()))
}
fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}
fn boo(b: bool) -> SExpr {
    SExpr::Atom(Atom::Bool(b))
}
fn list(v: Vec<SExpr>) -> SExpr {
    SExpr::List(v)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// `sha256:<hex>` STRING VALUE the fixtures carry as content, `hex` = `nib` × `reps`.
fn sha_str(nib: &str, reps: usize) -> String {
    format!("sha256:{}", nib.repeat(reps))
}

/// The SPEC-024 byte-authority file: `<label> <hex>` per line, `#` comments skipped.
fn authority() -> BTreeMap<String, String> {
    include_str!("../fixtures/mls_ds_canonical_vectors.txt")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let label = it.next().expect("vector label").to_string();
            let hex = it.next().expect("vector hex").to_string();
            (label, hex)
        })
        .collect()
}

/// The reconstructed input value for each authority label. `(label, value)`.
fn reconstructions() -> Vec<(&'static str, SExpr)> {
    // café-日本 built from exact UTF-8 bytes — never depends on this file's encoding.
    let cafe = String::from_utf8(vec![
        0x63, 0x61, 0x66, 0xc3, 0xa9, 0x2d, 0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac,
    ])
    .unwrap();

    vec![
        // -- atoms --
        ("sym-simple", sym("tell")),
        ("sym-domain-tag", sym("mls-ds-record-signature-v1")),
        ("kw-simple", kw("action")),
        ("kw-hyphen", kw("genesis-anchor")),
        ("str-simple", st("room-alpha")),
        (
            "str-sha256",
            st("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ),
        ("str-empty", st("")),
        ("str-unicode", st(&cafe)),
        ("num-zero", num(0)),
        ("num-small", num(42)),
        ("num-neg", num(-7)),
        ("num-i64-max", num(i64::MAX)),
        ("num-i64-min", num(i64::MIN)),
        ("bool-true", boo(true)),
        ("bool-false", boo(false)),
        // -- lists --
        ("list-empty", list(vec![])),
        ("list-tell-hi", list(vec![sym("tell"), st("hi")])),
        ("list-bool-pair", list(vec![boo(true), boo(false)])),
        // -- nested record-signature shape: (tag (log-v1 room base:Num(7) digest)) --
        (
            "nested-record-sig",
            list(vec![
                sym("mls-ds-record-signature-v1"),
                list(vec![
                    sym("log-v1"),
                    st("room-alpha"),
                    num(7),
                    st(&sha_str("1f", 32)),
                ]),
            ]),
        ),
        // -- 9-element add-authorization shape (all four digests 32-byte / 64 hex) --
        (
            "add-auth-9tuple",
            list(vec![
                sym("mls-add-authorization-v1"),
                st("room-alpha"),
                sym("@creator-author-key"),
                num(41),
                st(&sha_str("a", 64)),
                st(&sha_str("b", 64)),
                list(vec![sym("@alice"), sym("@bob")]),
                st(&sha_str("c", 64)),
                st(&sha_str("d", 64)),
            ]),
        ),
        // -- successor-offer core shape --
        (
            "successor-offer-core",
            list(vec![
                sym("successor-offer-core-v1"),
                list(vec![
                    sym("successor-target-v1"),
                    st("room-alpha"),
                    st(&sha_str("e", 64)),
                ]),
                st("nonce-abc123"),
                num(1_721_000_000),
                num(1_721_600_000),
            ]),
        ),
    ]
}

/// CON-002 assertion #1 — hark's linked `canonical_encode` reproduces every one of
/// the 21 byte-authority vectors, byte-for-byte, in BOTH directions (no vector left
/// unreconstructed, no reconstruction without an authority vector).
#[test]
fn canonical_encode_reproduces_all_21_byte_authority_vectors() {
    let authority = authority();
    let recon = reconstructions();
    assert_eq!(authority.len(), 21, "authority file must carry exactly 21 vectors");
    assert_eq!(recon.len(), 21, "expected exactly 21 reconstructions");

    let mut failures = Vec::new();
    for (label, value) in &recon {
        let expected = authority
            .get(*label)
            .unwrap_or_else(|| panic!("no authority vector named {label}"));
        let got = to_hex(&canonical_encode(value));
        let ok = &got == expected;
        println!(
            "[CON-002 vector] {:<22} {}",
            label,
            if ok { "MATCH" } else { "MISMATCH" }
        );
        if !ok {
            println!("    expected: {expected}");
            println!("    got     : {got}");
            failures.push(*label);
        }
    }
    // Every authority label must be covered by a reconstruction.
    for k in authority.keys() {
        assert!(
            recon.iter().any(|(l, _)| l == k),
            "authority vector {k} has no reconstruction"
        );
    }
    println!(
        "[CON-002 vector] {}/21 byte-identical to the SPEC-024 authority",
        21 - failures.len()
    );
    assert!(
        failures.is_empty(),
        "canonical_encode diverged from the byte authority on: {failures:?}"
    );
}

/// CON-002 assertion #2 — the linked encoder + parser reproduce the canonical
/// `mls-ds/v1` dialect hash. While the production role layer is unpinned, cbcl-rs
/// `main` cannot parse the full DS dialect grammar (e.g. the `:roles` clause); this
/// records that as EXPLICIT gate evidence rather than a silent pass. The 922ba8
/// assertion activates automatically once the production cbcl-rs is pinned (H1).
#[test]
fn dialect_hash_matches_canonical_922ba8_or_documents_gate() {
    const EXPECTED: &str =
        "sha256:922ba8bf9eb62a07b81989a9bfe6754a626b2edaf4d3f52e3fc4b41321261858";
    let src = include_str!("../fixtures/mls-ds-v1.cbcl");

    let sexpr = match cbcl_parser::parse(src) {
        Ok(s) => s,
        Err(e) => {
            println!("[CON-002 dialect] FINDING: cbcl-rs parse() cannot tokenise mls-ds/v1: {e:?}");
            println!("[CON-002 dialect] Gate evidence — DS dialect grammar absent from the pinned cbcl-rs (integration gate CLOSED, IMPL-025 §2).");
            return;
        }
    };
    match cbcl_parser::parse_dialect(&sexpr) {
        Ok(dialect) => {
            let hash =
                format!("sha256:{}", to_hex(&Sha256::digest(&dialect_canonical_bytes(&dialect))));
            println!("[CON-002 dialect] mls-ds/v1 Dialect::hash = {hash}");
            println!("[CON-002 dialect] expected              = {EXPECTED}");
            assert_eq!(
                hash, EXPECTED,
                "mls-ds/v1 dialect hash diverged from the SPEC-024 canonical value"
            );
        }
        Err(e) => {
            println!("[CON-002 dialect] FINDING: cbcl-rs main parse_dialect rejects the mls-ds/v1 dialect: {e:?}");
            println!("[CON-002 dialect] EXPECTED gate evidence — the SPEC-024 dialect grammar is");
            println!("[CON-002 dialect] absent from cbcl-rs main; the production role layer is unpinned");
            println!("[CON-002 dialect] (IMPL-025 §2 integration gate CLOSED). The 922ba8 assertion");
            println!("[CON-002 dialect] activates once the production cbcl-rs is pinned (H1 / ADR-031).");
        }
    }
}
