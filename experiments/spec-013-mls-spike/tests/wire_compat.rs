//! NFR-001 — native OpenMLS 0.8 byte-roundtrip at the pinned ciphersuite.
//!
//! Run: `cargo test --test wire_compat -- --nocapture`
//!
//! This proves the create→add→welcome→encrypt→decrypt cycle round-trips through
//! TLS-serialized bytes at `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the
//! same OpenMLS 0.8 the web `cbcl-mls-wasm` artifact compiles. A full
//! native↔wasm-artifact cross-stack run (a node harness loading the actual .wasm)
//! is the follow-up; at the same crate version the byte formats are identical by
//! construction, so this native cycle is a sound first oracle.

use spec_013_mls_spike::*;

#[test]
fn two_member_roundtrip_through_bytes() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    let mut alice_g = alice.create_group();
    assert_eq!(alice_g.ciphersuite(), CIPHERSUITE, "pinned ciphersuite");

    let bob_kp = bob.key_package();
    let (_commit, welcome) = add_member(&mut alice_g, &alice, &bob_kp).expect("add bob");
    let mut bob_g = join(&bob, &welcome).expect("bob joins via Welcome bytes");

    let wire = encrypt(&mut alice_g, &alice, b"hello bob");
    match process(&mut bob_g, &bob, &wire).expect("bob decrypts") {
        Processed::App(pt, sender) => {
            assert_eq!(pt, b"hello bob");
            // REQ-018's hook: the authenticated sender leaf must read "alice".
            assert_eq!(leaf_identity(&bob_g, sender).as_deref(), Some(&b"alice"[..]));
            println!("[NFR-001] roundtrip OK; authenticated sender = alice");
        }
        Processed::Handshake => panic!("expected an application message"),
    }
    assert_eq!(alice_g.members().count(), 2);
    assert_eq!(bob_g.members().count(), 2);
}

#[test]
fn three_member_commit_processing() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");
    let charlie = Party::new("charlie");

    let mut alice_g = alice.create_group();
    let (_c, w_b) = add_member(&mut alice_g, &alice, &bob.key_package()).expect("add bob");
    let mut bob_g = join(&bob, &w_b).expect("bob joins");

    // Adding charlie produces a commit bob must process to stay in sync.
    let (commit_c, w_c) = add_member(&mut alice_g, &alice, &charlie.key_package()).expect("add charlie");
    assert!(matches!(process(&mut bob_g, &bob, &commit_c), Ok(Processed::Handshake)));
    let mut charlie_g = join(&charlie, &w_c).expect("charlie joins");

    let wire = encrypt(&mut alice_g, &alice, b"hi all");
    for (g, m) in [(&mut bob_g, &bob), (&mut charlie_g, &charlie)] {
        match process(g, m, &wire).expect("decrypt") {
            Processed::App(pt, _) => assert_eq!(pt, b"hi all"),
            Processed::Handshake => panic!("expected app message"),
        }
    }
    println!("[NFR-001] 3-member commit + broadcast OK");
}
