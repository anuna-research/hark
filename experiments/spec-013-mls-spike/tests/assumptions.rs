//! Behavioural probes for the round-3 review's "could NOT assess" OpenMLS-0.8
//! assumptions. Each test PRINTS what it observes — the output is the evidence
//! the human crypto sign-off needs, not a pass/fail of the design.
//!
//! Run: `cargo test --test assumptions -- --nocapture`
//!
//! These do NOT implement SPEC-013. They answer: does the *primitive* behave the
//! way the v0.6 REQs assume? If an assertion here flips, the relevant REQ needs
//! re-shaping BEFORE sign-off.

use openmls::prelude::*;
use spec_013_mls_spike::*;

/// R3-07 (Critical) — does OpenMLS let a member rebind its leaf **credential
/// identity** via a self-Update, and do peers accept it?
///
/// REQ-017's new clause (validate every leaf-changing object + credential
/// immutability) is load-bearing **iff** OpenMLS itself permits this. The attack:
/// Mallory (handle "bob") self-updates her leaf to claim identity "alice" while
/// keeping her own signer; if peers accept it, REQ-018's `:from` check then passes
/// for a forged "alice". This probe shows whether that rebind is possible at the
/// MLS layer.
#[test]
fn r3_07_self_update_credential_rebind() {
    let alice = Party::new("alice");
    let mallory = Party::new("bob"); // wire handle is "bob"

    let mut alice_g = alice.create_group();
    let (_c, w) = add_member(&mut alice_g, &alice, &mallory.key_package()).expect("add bob");
    let mut mallory_g = join(&mallory, &w).expect("bob joins");

    // Mallory forges a leaf credential claiming "alice", signed by her own key.
    let forged = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: mallory.signer.public().into(),
    };
    let params = LeafNodeParameters::builder()
        .with_credential_with_key(forged)
        .build();

    let self_update = mallory_g.self_update(&mallory.provider, &mallory.signer, params);

    match self_update {
        Err(e) => {
            println!("[R3-07] OpenMLS REJECTED a credential-changing self-update at the committer: {e:?}");
            println!("[R3-07] => the Update-path rebind is blocked by the primitive; REQ-017's clause is a defence-in-depth, not the sole barrier.");
        }
        Ok(bundle) => {
            mallory_g.merge_pending_commit(&mallory.provider).expect("merge self-update");
            let commit = bundle
                .commit()
                .tls_serialize_detached()
                .expect("serialize commit");
            match process(&mut alice_g, &alice, &commit) {
                Err(e) => println!("[R3-07] committer accepted, but PEER (alice) rejected the rebind: {e:?}"),
                Ok(_) => {
                    let bob_leaf = alice_g
                        .members()
                        .find(|m| BasicCredential::try_from(m.credential.clone())
                            .map(|bc| bc.identity() == b"alice")
                            .unwrap_or(false))
                        .map(|m| m.index);
                    println!(
                        "[R3-07] **CONFIRMED**: OpenMLS accepted a self-Update that rebound \
                         handle 'bob' -> credential 'alice' (peer-visible leaf: {bob_leaf:?}). \
                         REQ-017's credential-immutability clause is REQUIRED — without it, \
                         REQ-018's :from check passes for a forged 'alice'."
                    );
                }
            }
        }
    }
}

/// R3-10 — does `KeyPackageIn::validate` reject an **expired** KeyPackage?
///
/// REQ-022's bounded last-resort relies on a short leaf `lifetime` being enforced
/// at add time. This probe builds a KeyPackage whose lifetime is already in the
/// past and checks whether validation rejects it.
#[test]
fn r3_10_expired_keypackage_rejected() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    // A genuinely-expired lifetime: valid window [1970-01-01+0s, +1s], long past.
    // `Lifetime::init(not_before, not_after)` is the explicit constructor (unlike
    // `new(t)`, which sets not_after = now + t and so is NOT expired at check time).
    let expired = Lifetime::init(0, 1);
    let kp_bytes = bob.build_key_package(
        KeyPackage::builder().key_package_lifetime(expired),
    );

    match validate_key_package(&alice, &kp_bytes) {
        Err(e) => println!("[R3-10] validate REJECTED an expired KeyPackage: {e}\n[R3-10] => lifetime IS enforced by KeyPackageIn::validate() (openmls 0.8 key_package_in.rs:196-197). REQ-022's lifetime bound is implementable via the primitive."),
        Ok(_) => println!("[R3-10] **WARNING**: validate ACCEPTED a 1970-expired KeyPackage — lifetime is NOT enforced; REQ-022 must enforce expiry explicitly at add time."),
    }

    // Control: a default-lifetime KeyPackage must validate.
    let ok_bytes = bob.key_package();
    assert!(validate_key_package(&alice, &ok_bytes).is_ok(), "default-lifetime KP must validate");
    println!("[R3-10] control: default-lifetime KeyPackage validates OK");
}

/// R3-11 / OQ-005 — does `max_past_epochs` actually bound the past-message window?
///
/// NFR-004 claims pruning superseded epoch secrets bounds past-message exposure
/// after an `identity_dir` compromise. This probe shows the knob is real: with
/// `max_past_epochs(0)` a member cannot decrypt a prior-epoch message once it has
/// advanced; with `(1)` it can.
#[test]
fn r3_11_max_past_epochs_bounds_window() {
    for keep in [0usize, 1usize] {
        let alice = Party::new("alice");
        let bob = Party::new("bob");

        let cfg = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(keep)
            .build();
        let mut alice_g =
            MlsGroup::new(&alice.provider, &alice.signer, &cfg, alice.credential.clone())
                .expect("create");
        let (_c, w) = add_member(&mut alice_g, &alice, &bob.key_package()).expect("add bob");
        // Retention is the DECRYPTING group's property — set the window on bob's join.
        let mut bob_g = join_with_past_epochs(&bob, &w, keep).expect("bob joins");

        // Epoch e: alice encrypts but does not yet deliver.
        let stale = encrypt(&mut alice_g, &alice, b"prior-epoch secret");

        // Advance to epoch e+1 (alice self-update) and bring bob along.
        let bundle = alice_g
            .self_update(&alice.provider, &alice.signer, LeafNodeParameters::default())
            .expect("self update");
        alice_g.merge_pending_commit(&alice.provider).expect("merge");
        let commit = bundle.commit().tls_serialize_detached().expect("ser commit");
        process(&mut bob_g, &bob, &commit).expect("bob advances epoch");

        // Now the prior-epoch ciphertext arrives at bob (epoch e+1).
        let res = process(&mut bob_g, &bob, &stale);
        match (keep, res.is_ok()) {
            (0, false) => println!("[R3-11] max_past_epochs(0): prior-epoch message UNDECRYPTABLE — window bounded as NFR-004 claims"),
            (1, true) => println!("[R3-11] max_past_epochs(1): prior-epoch message decryptable — knob keeps exactly the configured window"),
            (k, ok) => println!("[R3-11] **UNEXPECTED**: max_past_epochs({k}) -> decrypt_ok={ok}; retention semantics differ from the NFR-004 assumption — confirm with a cryptographer"),
        }
    }
    println!("[R3-11] KNOBS CONFIRMED on MlsGroupJoinConfigBuilder (openmls 0.8 config.rs): \
              max_past_epochs, number_of_resumption_psks (the resumption-PSK retention bound \
              the review flagged), and sender_ratchet_configuration (out_of_order_tolerance / \
              maximum_forward_distance). NFR-004 can name these directly.");
    println!("[R3-11] STILL UNASSESSABLE here: that a *durable* StorageProvider (ADR-004, not \
              yet written) actually honours delete calls on disk — the in-memory provider can't \
              show it. Remains a provider-test item for sign-off.");
}

use openmls::prelude::tls_codec::Serialize as _;
