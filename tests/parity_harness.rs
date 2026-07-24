//! TEST-024 — cross-runtime parity harness (hark / Rust side).
//!
//! The production, standing half of [[IMPL-025-hark-mls-ds-client#TEST-024]]. It consumes
//! the shared vectors emitted by the cbcl-bus JS oracle
//! (`apps/cbcl_chat/priv/web/mls-ds-parity-harness.mjs` → `parity/parity_*`, copied verbatim
//! into `tests/fixtures/`) and asserts hark reproduces every oracle. Three DISTINCT oracles,
//! never conflated (ADR-032):
//!
//! 1. Canonical byte — `canonical_encode(value)` == the cbcl-rs BYTE AUTHORITY, per
//!    vector; +NI (malformed vector rejected) +NO (mutated preimage yields different bytes).
//! 2. Crypto admission — the COMPLETE corrected `DomainTuple` inventory: full
//!    domain-separation matrix (each sig verifies under its OWN tag, none under any of the
//!    other 14 → 210 transplant rejections) + a per-tuple field-mutation rejection.
//! 3. Semantic transition — the JS `{scenario -> normalized outcome}` manifest, replayed
//!    NATIVELY through hark's DECOMPOSED cores (`transition_record`,
//!    `boundary::validate_v1_commit`) and asserted equal in the normalized
//!    {ADMIT,HOLD,REJECT} space. The one JS-reducer-stricter divergence is asserted
//!    PRESENT + DOCUMENTED, never silently passed.
//!
//! Crypto + canonical are CONSUMED from `cbcl-core` (the pinned role layer, `mls-ds-proof`).
//! The semantic manifest is a CONTRACT, not transplanted bytes: each runtime builds the
//! scenario with its own keys/encoder and must reach the same outcome.
//!
//!   cargo test --test parity_harness -- --nocapture

use cbcl_core::canonical::canonical_encode;
use cbcl_core::mls_ds::{b64url_encode, DomainTuple, Ed25519Keypair, ReadContext};
use cbcl_core::sexpr::{Atom, SExpr};

use hark::mls_ds::boundary::{self, AddAuth, Commit};
use hark::mls_ds::genesis::{self, Candidate};
use hark::mls_ds::{
    bind_record_anchor, record_hash, transition_record, AnchorBinding, ClientLog, RecordResponse,
    Verdict,
};

// ── SExpr constructors (mirror cbcl_core::sexpr) ────────────────────────────────
fn sym(s: &str) -> SExpr { SExpr::Atom(Atom::Symbol(s.into())) }
fn kw(s: &str) -> SExpr { SExpr::Atom(Atom::Keyword(s.into())) }
fn st(s: &str) -> SExpr { SExpr::Atom(Atom::Str(s.into())) }
fn num(n: i64) -> SExpr { SExpr::Atom(Atom::Num(n)) }
fn boo(b: bool) -> SExpr { SExpr::Atom(Atom::Bool(b)) }
fn list(v: Vec<SExpr>) -> SExpr { SExpr::List(v) }

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
fn sha_str(nib: &str, reps: usize) -> String {
    format!("sha256:{}", nib.repeat(reps))
}
fn digest(nib: &str) -> String {
    sha_str(nib, 64)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORACLE 1 — CANONICAL BYTE
// ═══════════════════════════════════════════════════════════════════════════════

/// The SPEC-024 byte authority — `<label> <hex>` per line, `#`/blank skipped.
/// A malformed line (no separator) yields `None`, exercised by the NI check.
fn parse_authority_line(l: &str) -> Option<(String, String)> {
    let l = l.trim();
    if l.is_empty() || l.starts_with('#') {
        return Some((String::new(), String::new())); // skip sentinel
    }
    let mut it = l.split_whitespace();
    let label = it.next()?.to_string();
    let hex = it.next()?.to_string();
    Some((label, hex))
}

fn authority() -> Vec<(String, String)> {
    include_str!("fixtures/parity_canonical_vectors.txt")
        .lines()
        .filter_map(parse_authority_line)
        .filter(|(l, _)| !l.is_empty())
        .collect()
}

/// The reconstructed input value for each authority label — MUST mirror the JS oracle
/// (`mls-ds-parity-harness.mjs jsVectors`) and cbcl-rs `mls_ds_canonical_vectors.rs`. A
/// wrong reconstruction fails byte-identity LOUDLY, so it cannot silently pass.
fn reconstructions() -> Vec<(&'static str, SExpr)> {
    const H_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let cafe = String::from_utf8(vec![
        0x63, 0x61, 0x66, 0xc3, 0xa9, 0x2d, 0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac,
    ])
    .unwrap();
    vec![
        ("sym-simple", sym("tell")),
        ("sym-domain-tag", sym("mls-ds-record-signature-v1")),
        ("kw-simple", kw("action")),
        ("kw-hyphen", kw("genesis-anchor")),
        ("str-simple", st("room-alpha")),
        ("str-sha256", st(&format!("sha256:{H_EMPTY}"))),
        ("str-empty", st("")),
        ("str-unicode", st(&cafe)),
        ("num-zero", num(0)),
        ("num-small", num(42)),
        ("num-neg", num(-7)),
        ("num-i64-max", num(i64::MAX)),
        ("num-i64-min", num(i64::MIN)),
        ("bool-true", boo(true)),
        ("bool-false", boo(false)),
        ("list-empty", list(vec![])),
        ("list-tell-hi", list(vec![sym("tell"), st("hi")])),
        ("list-bool-pair", list(vec![boo(true), boo(false)])),
        (
            "nested-record-sig",
            list(vec![
                sym("mls-ds-record-signature-v1"),
                list(vec![sym("log-v1"), st("room-alpha"), num(7), st(&sha_str("1f", 32))]),
            ]),
        ),
        (
            "add-auth-9tuple",
            list(vec![
                sym("mls-add-authorization-v1"),
                st("room-alpha"),
                sym("@creator-author-key"),
                num(41),
                st(&digest("a")),
                st(&digest("b")),
                list(vec![sym("@alice"), sym("@bob")]),
                st(&digest("c")),
                st(&digest("d")),
            ]),
        ),
        (
            "successor-offer-core",
            list(vec![
                sym("successor-offer-core-v1"),
                list(vec![sym("successor-target-v1"), st("room-alpha"), st(&digest("e"))]),
                st("nonce-abc123"),
                num(1721000000),
                num(1721600000),
            ]),
        ),
    ]
}

#[test]
fn oracle1_canonical_byte_identity() {
    let auth: std::collections::BTreeMap<String, String> = authority().into_iter().collect();
    let recon = reconstructions();
    assert_eq!(auth.len(), 21, "authority has 21 vectors");
    assert_eq!(recon.len(), 21, "21 reconstructions");

    // P — byte-identity per vector.
    for (label, value) in &recon {
        let expected = auth.get(*label).unwrap_or_else(|| panic!("authority missing {label}"));
        let actual = to_hex(&canonical_encode(value));
        assert_eq!(&actual, expected, "canonical/P {label}: hark bytes != cbcl-rs authority");
    }
    // coverage: every authority label reconstructed.
    for label in auth.keys() {
        assert!(recon.iter().any(|(l, _)| l == label), "no reconstruction for {label}");
    }

    // NI — a malformed vector line (no separator) is rejected by the parser.
    assert_eq!(parse_authority_line("no-separator-here"), None, "canonical/NI: malformed line rejected");

    // NO — a mutated preimage (42 → 43) yields DIFFERENT bytes (injectivity).
    let mutated = to_hex(&canonical_encode(&num(43)));
    assert_ne!(&mutated, auth.get("num-small").unwrap(), "canonical/NO: mutation must be detected");

    // golden ASCII anchor — the encoder's human-checkable shape.
    let tell_hi = String::from_utf8(canonical_encode(&list(vec![sym("tell"), st("hi")]))).unwrap();
    assert_eq!(tell_hi, "(5:Stell3:Qhi)", "canonical/golden ASCII");
    println!("[oracle1] 21/21 vectors byte-identical to cbcl-rs authority; NI+NO+golden hold");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORACLE 2 — CRYPTO ADMISSION  (complete corrected DomainTuple inventory)
// ═══════════════════════════════════════════════════════════════════════════════

fn sx(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}

/// One representative valid instance of each of the 15 corrected `DomainTuple` variants.
fn all_15() -> Vec<(&'static str, DomainTuple)> {
    vec![
        ("Open", DomainTuple::Open { bindings: sx("b"), dialect_hash: digest("1"), opener_message: sx("m") }),
        ("Request", DomainTuple::Request { bindings: sx("b"), dialect_hash: digest("1"), h0: digest("0"), request: sx("r"), read_context: ReadContext::Read { session_id: "s".into(), frame_id: 1 } }),
        ("Response", DomainTuple::Response { bindings: sx("b"), dialect_hash: digest("1"), request_content_hash: digest("2"), response_message: sx("m"), read_context: ReadContext::None }),
        ("Source", DomainTuple::Source { source: sx("s") }),
        ("AddAuth", DomainTuple::AddAuth { room: "room-alpha".into(), source_author_key: "@k".into(), base_seq: 1, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: vec!["@alice".into()], welcome_digest: digest("c"), genesis_anchor_hash: digest("d") }),
        ("Record", DomainTuple::Record { log_record: sx("lr") }),
        ("Claim", DomainTuple::Claim { room_claim_core: sx("cc") }),
        ("ClaimDs", DomainTuple::ClaimDs { room_claim_core: sx("cc"), creator_signature: "csig".into() }),
        ("Genesis", DomainTuple::Genesis { room: "room-alpha".into(), genesis_blob_ref: sx("br"), creator_key: "@k".into() }),
        ("PredecessorOffer", DomainTuple::PredecessorOffer { successor_offer_core: sx("oc") }),
        ("SuccessorConsent", DomainTuple::SuccessorConsent { successor_offer: sx("o") }),
        ("SuccessorDs", DomainTuple::SuccessorDs { successor_proposal: sx("p") }),
        ("OfferHash", DomainTuple::OfferHash { successor_offer: sx("o") }),
        ("BridgeHash", DomainTuple::BridgeHash { successor_value: sx("v") }),
        ("ClosurePackageHash", DomainTuple::ClosurePackageHash { closure_package: sx("cp") }),
    ]
}

#[test]
fn oracle2_crypto_domain_separation_and_field_mutation() {
    let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
    let vk = kp.public_bytes();
    let tuples = all_15();
    assert_eq!(tuples.len(), 15, "complete corrected inventory");

    // sign each under its own tag.
    let sigs: Vec<[u8; 64]> = tuples.iter().map(|(_, t)| t.sign(&kp)).collect();

    // P — each sig verifies under its OWN tuple.
    for (i, (name, t)) in tuples.iter().enumerate() {
        assert!(t.verify(&vk, &sigs[i]), "crypto/P {name}: own-tag verify must hold");
    }
    // NI — full domain-separation matrix: NO sig verifies under ANY other tag (210 rejections).
    let mut transplant_rejections = 0;
    for (i, sig) in sigs.iter().enumerate() {
        for (j, (name_j, t_j)) in tuples.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(!t_j.verify(&vk, sig), "crypto/NI domain transplant {} -> {name_j} verified!", tuples[i].0);
            transplant_rejections += 1;
        }
    }
    assert_eq!(transplant_rejections, 15 * 14, "210 domain-transplant rejections");

    // NO — a field mutation on a representative tuple breaks its own verification.
    let base = DomainTuple::AddAuth { room: "room-alpha".into(), source_author_key: "@k".into(), base_seq: 1, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: vec!["@alice".into()], welcome_digest: digest("c"), genesis_anchor_hash: digest("d") };
    let sig = base.sign(&kp);
    let mutated_field = DomainTuple::AddAuth { room: "room-alpha".into(), source_author_key: "@k".into(), base_seq: 1, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: vec!["@MALLORY".into()], welcome_digest: digest("c"), genesis_anchor_hash: digest("d") };
    assert!(!mutated_field.verify(&vk, &sig), "crypto/NO: field mutation (targets) must reject");
    let mutated_scalar = DomainTuple::AddAuth { room: "room-alpha".into(), source_author_key: "@k".into(), base_seq: 2, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: vec!["@alice".into()], welcome_digest: digest("c"), genesis_anchor_hash: digest("d") };
    assert!(!mutated_scalar.verify(&vk, &sig), "crypto/NO: scalar mutation (base_seq) must reject");

    // NI — a wrong key never verifies.
    let forger = Ed25519Keypair::from_seed(&[9u8; 32]);
    assert!(!base.verify(&forger.public_bytes(), &sig), "crypto/NI: wrong key rejects");
    println!("[oracle2] 15/15 own-tag verify; {transplant_rejections} domain-transplant + field/scalar/wrong-key rejections");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORACLE 3 — SEMANTIC TRANSITION  (JS manifest replayed through hark's decomposed cores)
// ═══════════════════════════════════════════════════════════════════════════════

const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Normalized cross-runtime outcome LABEL — a per-oracle shared space over the
/// monolith↔module boundary (reducer: ADMIT/HOLD/REJECT; genesis: FIRST/EXISTING/
/// CONFLICT). Each runtime maps its NATIVE verdict to the SAME label; parity = equal.
fn norm_of_record(v: &Verdict) -> &'static str {
    match v {
        Verdict::Applied { .. } => "ADMIT",
        Verdict::NotNext => "HOLD",
        Verdict::AwaitingGenesis => "AWAITING",
        Verdict::Violation(_) => "REJECT",
    }
}
fn norm_of_boundary(v: &boundary::Verdict) -> &'static str {
    match v {
        boundary::Verdict::Accept => "ADMIT",
        boundary::Verdict::Reject(_) => "REJECT",
    }
}
fn norm_of_genesis(v: &genesis::Verdict) -> &'static str {
    match v {
        genesis::Verdict::FirstAccepted { .. } => "FIRST",
        genesis::Verdict::Existing { .. } => "EXISTING",
        genesis::Verdict::Conflict(_) => "CONFLICT",
    }
}
fn norm_of_anchor(v: &AnchorBinding) -> &'static str {
    match v {
        AnchorBinding::Bound => "BOUND",
        AnchorBinding::AwaitingGenesis => "AWAITING",
        AnchorBinding::Violation(_) => "REJECT",
    }
}

// -- record-core native builders (hark transition_record) --
fn signed_record(seq: i64, prev: &str, ds: &Ed25519Keypair) -> RecordResponse {
    let rec = list(vec![sym("log-v1"), st("room-alpha"), num(seq), st(prev)]);
    let rh = record_hash(&rec);
    let sig = DomainTuple::Record { log_record: rec.clone() }.sign(ds);
    RecordResponse { seq, prev_hash: prev.into(), record_hash: rh, record_signature: sig, log_record: rec, genesis_ref: "sha256:anchor".into() }
}
fn record_scenario(name: &str) -> &'static str {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let vk = ds.public_bytes();
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let v = match name {
        "commit-exact-next-applied" => transition_record(&log, &vk, &signed_record(1, H0, &ds)),
        "commit-wrong-seq-notNext" => transition_record(&log, &vk, &signed_record(2, H0, &ds)),
        "commit-wrong-prev-notNext" => transition_record(&log, &vk, &signed_record(1, "sha256:deadbeef", &ds)),
        "commit-bad-ds-sig-violation" => {
            let forger = Ed25519Keypair::from_seed(&[6u8; 32]);
            transition_record(&log, &vk, &signed_record(1, H0, &forger))
        }
        "commit-record-hash-mismatch-violation" => {
            let mut r = signed_record(1, H0, &ds);
            r.record_hash = "sha256:0000".into();
            transition_record(&log, &vk, &r)
        }
        other => panic!("unknown record scenario {other}"),
    };
    norm_of_record(&v)
}

// -- add-authorization native builders (hark boundary::validate_v1_commit) --
fn boundary_scenario(name: &str) -> &'static str {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let vk = creator.public_bytes();
    let owner = "@owner";
    let mk_auth = |targets: &[&str], signer: &Ed25519Keypair| -> AddAuth {
        let targets: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
        let t = DomainTuple::AddAuth { room: "r".into(), source_author_key: creator.key_id(), base_seq: 4, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: targets.clone(), welcome_digest: digest("c"), genesis_anchor_hash: digest("d") };
        let sig = t.sign(signer);
        AddAuth { room: "r".into(), source_author_key: creator.key_id(), base_seq: 4, base_hash: digest("a"), ciphertext_digest: digest("b"), targets, welcome_digest: digest("c"), genesis_anchor_hash: digest("d"), sig }
    };
    let v = match name {
        "add-valid-auth-admit" => boundary::validate_v1_commit(owner, &vk, &Commit { added: vec!["@a".into(), "@b".into()], removed: vec![], add_auth: Some(mk_auth(&["@a", "@b"], &creator)) }),
        "add-invalid-auth-violation" => {
            let wrong = Ed25519Keypair::from_seed(&[8u8; 32]);
            boundary::validate_v1_commit(owner, &vk, &Commit { added: vec!["@a".into()], removed: vec![], add_auth: Some(mk_auth(&["@a"], &wrong)) })
        }
        "commit-non-add-carries-auth-violation" => boundary::validate_v1_commit(owner, &vk, &Commit { added: vec![], removed: vec![], add_auth: Some(mk_auth(&["@a"], &creator)) }),
        other => panic!("unknown boundary scenario {other}"),
    };
    norm_of_boundary(&v)
}

// -- genesis native builders (hark genesis::validate_genesis, CON-008) --
fn genesis_scenario(name: &str) -> &'static str {
    let creator = Ed25519Keypair::from_seed(&[3u8; 32]);
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let (cvk, dvk) = (creator.public_bytes(), ds.public_bytes());
    let room = "room-alpha";
    let build = |grade: &'static str, link_room: &str, bad_claim: bool| -> Candidate {
        let creator_key = creator.key_id();
        let core = list(vec![sym("room-claim-v1"), st(room), st("L"), sym(&creator_key), num(1), st("m")]);
        let creator_sig = if bad_claim {
            DomainTuple::Claim { room_claim_core: core.clone() }.sign(&Ed25519Keypair::from_seed(&[99u8; 32]))
        } else {
            DomainTuple::Claim { room_claim_core: core.clone() }.sign(&creator)
        };
        let ds_sig = DomainTuple::ClaimDs { room_claim_core: core.clone(), creator_signature: b64url_encode(&creator_sig) }.sign(&ds);
        let blob_ref = list(vec![sym("blob-ref-v1"), sym("genesis"), st(&digest("a")), num(64)]);
        let genesis_sig = DomainTuple::Genesis { room: room.into(), genesis_blob_ref: blob_ref.clone(), creator_key: creator_key.clone() }.sign(&creator);
        Candidate { room: room.into(), grade, creator_key: creator_key.clone(), link_room: link_room.into(), link_creator_key: creator_key, room_claim_core: core, creator_sig, ds_sig, genesis_blob_ref: blob_ref, genesis_sig }
    };
    let v = match name {
        "genesis-valid-first-tofu" => genesis::validate_genesis(None, room, &cvk, &dvk, &build("tofu", room, false)),
        "genesis-existing-verified" => {
            let c = build("verified", room, false);
            let anchor = genesis::anchor_hash(&c.room_claim_core, &c.genesis_blob_ref);
            genesis::validate_genesis(Some(&anchor), room, &cvk, &dvk, &c)
        }
        "genesis-grade-lie-conflict" => genesis::validate_genesis(None, room, &cvk, &dvk, &build("verified", room, false)),
        "genesis-room-transplant-conflict" => genesis::validate_genesis(None, room, &cvk, &dvk, &build("tofu", "room-evil", false)),
        "genesis-bad-claim-sig-conflict" => genesis::validate_genesis(None, room, &cvk, &dvk, &build("tofu", room, true)),
        other => panic!("unknown genesis scenario {other}"),
    };
    norm_of_genesis(&v)
}

// -- immutable-anchor native builders (hark bind_record_anchor, CON-005 record-component) --
fn anchor_scenario(name: &str) -> &'static str {
    let saved = "sha256:anchor";
    let v = match name {
        "commit-genesis-anchor-mismatch-violation" => bind_record_anchor("sha256:foreign", Some(saved)),
        "commit-awaiting-genesis" => bind_record_anchor(saved, None),
        other => panic!("unknown anchor scenario {other}"),
    };
    norm_of_anchor(&v)
}

#[test]
fn oracle3_semantic_parity_against_js_manifest() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/parity_semantic_vectors.json")).expect("manifest parses");
    let scenarios = manifest["scenarios"].as_array().expect("scenarios array");

    let mut compared = 0;
    let mut divergences = 0;
    for sc in scenarios {
        let name = sc["name"].as_str().unwrap();
        let hark_comparable = sc["harkComparable"].as_bool().unwrap();
        let hark_module = sc["harkModule"].as_str().unwrap();

        if !hark_comparable {
            // A JS-only verdict (norm outside {ADMIT,HOLD,REJECT}), OR a documented divergence —
            // assert it is LABELLED, not silently dropped.
            if let Some(div) = sc["divergence"].as_str() {
                divergences += 1;
                println!("[oracle3] DIVERGENCE (surfaced, not asserted parity): {name} — {div}");
            }
            continue;
        }
        let js_norm = sc["norm"].as_str().unwrap();
        let hark_norm = match hark_module {
            "record" => record_scenario(name),
            "boundary" => boundary_scenario(name),
            "genesis" => genesis_scenario(name),
            "anchor" => anchor_scenario(name),
            other => panic!("scenario {name} marked comparable but harkModule={other} has no native driver"),
        };
        assert_eq!(hark_norm, js_norm, "semantic parity {name}: hark {hark_norm} != JS {js_norm}");
        compared += 1;
        println!("[oracle3] parity {name}: {js_norm} [{hark_module}]");
    }
    assert_eq!(compared, 15, "15 hark-comparable scenarios (5 record + 3 boundary + 5 genesis + 2 anchor)");
    assert_eq!(divergences, 0, "H4 anchor-binding (bind_record_anchor) closed the js-reducer-stricter divergence");
    println!("[oracle3] {compared}/15 semantic scenarios in cross-runtime parity; {divergences} divergence remaining");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORACLE 2b — CROSS-RUNTIME DS SIGNATURE (the LFE hub signs, hark verifies)
// The crypto honest-path of TEST-025: a real cbcl-bus hub (cbcl-mls-ds-sign, enacl/
// libsodium) DS-signs a record; a hark client pinned to the hub key ACCEPTS it and
// rejects any other signer. Proves key-derivation, record_hash, verify, and
// DETERMINISTIC-signature byte-parity across the two runtimes over the vector the LFE
// hub emits (tests/fixtures/ds_sign_vectors.txt).
// ═══════════════════════════════════════════════════════════════════════════════

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    let v = hex_bytes(s);
    assert_eq!(v.len(), N, "expected {N} bytes, got {}", v.len());
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    a
}

#[test]
fn oracle2b_lfe_hub_ds_signature_interop() {
    let raw = include_str!("fixtures/ds_sign_vectors.txt");
    let kv = |key: &str| -> String {
        raw.lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.starts_with('#') || l.is_empty() {
                    return None;
                }
                l.split_once(' ')
            })
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_else(|| panic!("interop vector missing {key}"))
    };
    let seed = hex_arr::<32>(&kv("seed_hex"));
    let ds_pubkey = hex_arr::<32>(&kv("ds_pubkey_hex"));
    let room = kv("room");
    let seq: i64 = kv("seq").parse().unwrap();
    let prev = kv("prev_hash");
    let expected_rh = kv("record_hash");
    let sig = hex_arr::<64>(&kv("sig_hex"));

    // 1. key-derivation parity — enacl seed->key == hark from_seed (RFC 8032).
    let kp = Ed25519Keypair::from_seed(&seed);
    assert_eq!(kp.public_bytes(), ds_pubkey, "seed->pubkey parity (enacl == cbcl-core)");

    // 2. record_hash parity over the rebuilt (log-v1 room seq prev) record.
    let rec = list(vec![sym("log-v1"), st(&room), num(seq), st(&prev)]);
    assert_eq!(record_hash(&rec), expected_rh, "record_hash parity");

    // 3. hark ACCEPTS the LFE hub's DS signature under the pinned key.
    let record = DomainTuple::Record { log_record: rec.clone() };
    assert!(record.verify(&ds_pubkey, &sig), "hark verifies the LFE hub DS signature");

    // 4. deterministic-signature byte-parity — hark's own sig equals the LFE sig.
    assert_eq!(record.sign(&kp), sig, "Ed25519 deterministic sig parity (enacl == cbcl-core)");

    // 5. NI — a non-pinned signer is rejected (ds-key-substitution).
    let forger = Ed25519Keypair::from_seed(&[0u8; 32]);
    assert!(!record.verify(&forger.public_bytes(), &sig), "non-pinned key rejects the signature");
    println!("[oracle2b] LFE hub -> hark DS-signature interop: key + record_hash + verify + deterministic-sig parity");
}
