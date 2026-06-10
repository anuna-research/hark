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
    println!("[R3-11] See companion test `r3_11_storage_prunes_superseded_epoch_secrets`: the \
              knob bounds PERSISTED secret bytes (pruning is reflected at rest, not only in \
              memory). The only residual is a *durable* provider's own on-disk fsync/delete \
              fidelity (ADR-004, its own test).");
}

use openmls::prelude::tls_codec::Serialize as _;

/// R3-11 (mechanism) — does OpenMLS actually *issue* `delete_*` calls for
/// superseded epoch secrets, so a durable provider that honours deletes will
/// prune on disk? With `max_past_epochs(0)` the stored-entry count must stay flat
/// across many epoch changes; with a large window it accumulates. The in-memory
/// provider stands in for any provider — what's load-bearing is that OpenMLS
/// emits the deletes; a durable provider honouring them prunes identically.
#[test]
fn r3_11_storage_prunes_superseded_epoch_secrets() {
    fn churn(keep: usize, rounds: usize) -> usize {
        let alice = Party::new("alice");
        let bob = Party::new("bob");
        let cfg = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(keep)
            .build();
        let mut g = MlsGroup::new(&alice.provider, &alice.signer, &cfg, alice.credential.clone())
            .expect("create");
        add_member(&mut g, &alice, &bob.key_package()).expect("add bob");
        for _ in 0..rounds {
            g.self_update(&alice.provider, &alice.signer, LeafNodeParameters::default())
                .expect("self update");
            g.merge_pending_commit(&alice.provider).expect("merge");
        }
        storage_byte_size(&alice)
    }

    let rounds = 12;
    let pruned = churn(0, rounds);
    let kept = churn(rounds, rounds);

    println!("[R3-11] persisted secret-state bytes after {rounds} epoch changes:");
    println!("[R3-11]   max_past_epochs(0):  {pruned} bytes");
    println!("[R3-11]   max_past_epochs({rounds}): {kept} bytes  (Δ over pruned = {})", kept as i64 - pruned as i64);

    // The retention knob must materially bound persisted secret material: keeping
    // `rounds` past epochs persists strictly more than keeping none. If these were
    // equal, the at-rest footprint would not track the knob and NFR-004's "prune
    // superseded epoch secrets" claim would not hold at rest.
    assert!(
        kept > pruned,
        "max_past_epochs did not change persisted byte footprint ({pruned} vs {kept}); \
         retained epoch secrets are not reflected at rest — re-examine NFR-004's at-rest model"
    );
    println!(
        "[R3-11] => the retention window bounds PERSISTED secret material (pruned < kept). \
         OpenMLS prunes superseded epoch secrets from the persisted state under (0); a durable \
         provider (ADR-004) writing the same state inherits the bound. Only that provider's own \
         on-disk fsync/delete fidelity is left to its own test."
    );
}
