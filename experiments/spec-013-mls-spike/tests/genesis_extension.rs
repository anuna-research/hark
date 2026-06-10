//! R5-03 probe — the REQ-016 genesis GroupContext extension on openmls 0.8.1.
//!
//! Round 5 confirmed by SOURCE READING that an `Unknown` application extension in
//! the GroupContext is (a) carried to joiners inside the MLS-authenticated Welcome
//! and (b) gated by a leaf-capabilities obligation on EVERY member. This probe
//! converts that from source-read to observed behaviour. If any assertion here
//! flips, REQ-016's durable-delivery mechanism needs re-shaping BEFORE sign-off.
//!
//! Run: `cargo test --test genesis_extension -- --nocapture`

use openmls::prelude::*;
use spec_013_mls_spike::*;

const GENESIS: &[u8] = b"(genesis @room :creator @alice :group g1 :key K)";

/// Positive path: creator + joiner both advertise `Unknown(0xF013)` in leaf
/// capabilities; the genesis bytes must be readable by the joiner BOTH from the
/// StagedWelcome (pre-finalize — the REQ-016 inspection point) and from the live
/// group after joining, byte-identical to what the creator wrote. The group must
/// then function normally (commit + process round-trip).
#[test]
fn r5_03_genesis_roundtrip_with_capabilities() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    let mut alice_g = alice
        .create_group_with_genesis(GENESIS, true)
        .expect("create genesis group (creator capable)");
    println!("[R5-03] creator with capability: group created, genesis in GroupContext");

    let kp = bob.key_package_with_genesis_capability();
    let (_commit, welcome) =
        add_member(&mut alice_g, &alice, &kp).expect("add capability-bearing joiner");
    println!("[R5-03] Add of a capability-advertising KeyPackage: ACCEPTED");

    let (mut bob_g, pre, post) =
        join_reading_genesis(&bob, &welcome).expect("join genesis-bearing Welcome");
    assert_eq!(
        pre.as_deref(),
        Some(GENESIS),
        "genesis must be readable from the StagedWelcome GroupContext PRE-finalize"
    );
    assert_eq!(
        post.as_deref(),
        Some(GENESIS),
        "genesis must be readable from the live group post-join"
    );
    println!(
        "[R5-03] joiner read genesis pre-finalize (StagedWelcome::group_context) AND \
         post-join (MlsGroup::extensions), byte-identical ({} bytes)",
        GENESIS.len()
    );

    // The group must still operate: bob commits (his UpdatePath leaf is checked
    // against the GC extensions — commit_builder's own-leaf capability check),
    // alice processes; then an app message round-trips.
    let bundle = bob_g
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .expect("capability-bearing member can commit in a genesis-bearing group");
    bob_g.merge_pending_commit(&bob.provider).expect("merge own commit");
    use openmls::prelude::tls_codec::Serialize as _;
    let commit = bundle.commit().tls_serialize_detached().expect("ser commit");
    process(&mut alice_g, &alice, &commit).expect("peer processes the commit");
    let ct = encrypt(&mut alice_g, &alice, b"post-genesis traffic");
    match process(&mut bob_g, &bob, &ct).expect("decrypt") {
        Processed::App(pt, _) => assert_eq!(pt, b"post-genesis traffic"),
        _ => panic!("expected app message"),
    }
    assert_eq!(
        bob_g.extensions().unknown(GENESIS_EXT_TYPE).map(|u| u.0.as_slice()),
        Some(GENESIS),
        "genesis must survive a normal Commit unchanged"
    );
    println!("[R5-03] group functions normally post-genesis; genesis unchanged across a Commit");
    println!(
        "[R5-03] => POSITIVE PATH CONFIRMED: Unknown({GENESIS_EXT_TYPE:#06x}) GroupContext \
         extension round-trips create→add→welcome→read on openmls 0.8.1, given the \
         capabilities obligation is met on every leaf."
    );
}

/// Fail-closed half (joiner side): a KeyPackage with DEFAULT capabilities — what
/// the shipped `cbcl-mls-wasm` publishes today — must be REJECTED when added to a
/// genesis-bearing group. This is the load-bearing cross-repo obligation REQ-016
/// now states: a stack that omits the capability cannot silently join.
#[test]
fn r5_03_default_capability_joiner_fails_closed() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    let mut alice_g = alice
        .create_group_with_genesis(GENESIS, true)
        .expect("create genesis group");

    let default_kp = bob.key_package(); // default capabilities — no Unknown(0xF013)
    match add_member(&mut alice_g, &alice, &default_kp) {
        Err(e) => println!(
            "[R5-03] Add of a DEFAULT-capability KeyPackage to a genesis-bearing group: \
             REJECTED — {e}\n[R5-03] => FAIL-CLOSED CONFIRMED at the committer (the \
             valn0502/UnsupportedExtensions class): the shipped cbcl-mls-wasm KeyPackage \
             shape cannot enter a genesis-bearing group until the capability lands."
        ),
        Ok(_) => panic!(
            "[R5-03] **DESIGN-BREAKING**: openmls accepted a default-capability leaf into a \
             group with an Unknown GroupContext extension — the REQ-016 capabilities \
             obligation is NOT enforced by the primitive; REQ-017 must enforce it in app code"
        ),
    }
    assert_eq!(alice_g.members().count(), 1, "group membership must be unchanged");
}

/// Fail-closed half (creator side): where does the failure surface when the
/// CREATOR's own leaf omits the capability? hark/web both create groups, so the
/// answer locates the error the implementer will see.
#[test]
fn r5_03_default_capability_creator_observed() {
    let alice = Party::new("alice");
    match alice.create_group_with_genesis(GENESIS, false) {
        Err(e) => println!(
            "[R5-03] group creation with genesis ext + DEFAULT creator capabilities: \
             REJECTED at MlsGroup::new — {e}\n[R5-03] => fail-closed at creation; a stack \
             cannot even stand up a genesis-bearing group without advertising the capability."
        ),
        Ok(mut g) => {
            // Creation passed — probe whether the first path-commit catches it
            // (commit_builder checks the committer's own leaf against GC extensions).
            let r = g.self_update(&alice.provider, &alice.signer, LeafNodeParameters::default());
            match r {
                Err(e) => println!(
                    "[R5-03] creation ACCEPTED a default-capability creator, but its first \
                     path-commit is REJECTED — {e:?}\n[R5-03] => fail-closed surfaces at the \
                     first commit, not creation: implementers MUST set capabilities in the \
                     create config, or the group bricks on first use."
                ),
                Ok(_) => println!(
                    "[R5-03] **WARNING**: a default-capability creator created AND committed \
                     in a genesis-bearing group — the own-leaf capability check did not fire; \
                     REQ-017 must enforce the creator-side obligation in app code."
                ),
            }
        }
    }
}
