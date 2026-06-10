//! SPEC-013 integration: two hark agents in one encrypted private channel,
//! exercised through the public `mls::session` API exactly as the chat
//! receive loop drives it — create / add / welcome / encrypt / decrypt /
//! remove / restart — plus the NFR-004 on-disk retention assertion the
//! provider unit tests deferred (IMPL condition I, full form).

use hark::identity::ChatIdentity;
use hark::mls::session::{MlsSession, SessionEvent};
use std::fs;
use std::path::PathBuf;

fn setup(tag: &str, seed: u8, name: &str) -> (PathBuf, ChatIdentity) {
    let dir = std::env::temp_dir().join(format!(
        "hark-it-mls-{tag}-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    (dir, ChatIdentity::from_seed([seed; 32]))
}

fn extract_kw_str(frame: &str, key: &str) -> Option<String> {
    // Minimal scan for `:key "<value>"` in a frame the tests built themselves.
    let idx = frame.find(key)?;
    let rest = &frame[idx + key.len()..];
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    Some(rest[start..end].to_string())
}

/// TEST-001..TEST-010-shape: the full two-agent encrypted-channel lifecycle
/// over the exact wire frames the hub fans.
#[test]
fn two_agents_full_encrypted_channel_lifecycle() {
    let (a_dir, a_wire) = setup("life", 91, "alice");
    let (b_dir, b_wire) = setup("life", 92, "bob");

    let mut alice =
        MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, true).unwrap();
    let mut bob = MlsSession::open(&b_dir, "bob", "@research", "@bob", &b_wire, true).unwrap();

    // idkey exchange (REQ-019) → pins (REQ-011).
    let a_join = alice.join_frames().unwrap();
    let b_join = bob.join_frames().unwrap();
    assert!(matches!(
        bob.handle_frame(&a_join[1]),
        SessionEvent::Handled { .. }
    ));
    assert!(matches!(
        alice.handle_frame(&b_join[1]),
        SessionEvent::Handled { .. }
    ));

    // Alice creates; presence re-broadcasts her idkey (bob newly seen) AND,
    // since alice already pinned bob, prompts the keyget the hub answers.
    alice.create_group_as_creator().unwrap();
    let SessionEvent::Handled { outbound } =
        alice.handle_frame("(presence @research :members (@alice @bob))")
    else {
        panic!("presence");
    };
    assert!(
        outbound.iter().any(|f| f == "(keyget @hub :for @bob :from @alice)"),
        "presence prompts a keyget for the pinned, present non-member: {outbound:?}"
    );

    // Bob's one-time package from his keypub (first :onetime entry).
    let onetime_start = b_join[0].find(":onetime (").unwrap() + ":onetime (".len();
    let kp_b64 = {
        let rest = &b_join[0][onetime_start..];
        let start = rest.find('"').unwrap() + 1;
        let end = start + rest[start..].find('"').unwrap();
        &rest[start..end]
    };
    let SessionEvent::Handled { outbound } =
        alice.handle_frame(&format!("(keypkg @hub :for @bob :kp \"{kp_b64}\")"))
    else {
        panic!("keypkg");
    };
    assert_eq!(outbound.len(), 2, "commit + welcome");

    // Bob joins via the fanned welcome.
    let _ = bob.handle_frame(&outbound[0]); // pre-membership commit: inert
    assert!(matches!(
        bob.handle_frame(&outbound[1]),
        SessionEvent::Handled { .. }
    ));
    assert!(bob.joined());

    // Encrypted exchange both ways (REQ-005/REQ-006/REQ-018, NFR-002: the
    // wire frame carries only base64 ciphertext, never the content).
    let to_bob = alice
        .encrypt_outbound("(say @research :from @alice :text \"the plan is GREEN\")")
        .unwrap();
    assert!(
        !to_bob.contains("GREEN"),
        "NFR-002: content must not appear in the wire frame"
    );
    match bob.handle_frame(&to_bob) {
        SessionEvent::Plaintext { text, sender } => {
            assert_eq!(sender, "@alice");
            assert!(text.contains("GREEN"));
        }
        other => panic!("expected plaintext, got {other:?}"),
    }
    let to_alice = bob
        .encrypt_outbound("(say @research :from @bob :text \"ack\")")
        .unwrap();
    match alice.handle_frame(&to_alice) {
        SessionEvent::Plaintext { sender, .. } => assert_eq!(sender, "@bob"),
        other => panic!("expected plaintext, got {other:?}"),
    }

    // Safety numbers agree (REQ-021/REQ-024) — the out-of-band comparison.
    assert_eq!(
        alice.safety_numbers().unwrap().identity,
        bob.safety_numbers().unwrap().identity
    );

    // Voluntary leave: bye evidence → owner removes → validator merges
    // (REQ-014); bob can no longer decrypt subsequent traffic.
    let bye = bob.leave_frame().unwrap();
    let evidence_b64 = extract_kw_str(&bye, ":evidence").unwrap();
    use base64::Engine as _;
    let evidence_bytes = base64::engine::general_purpose::STANDARD
        .decode(evidence_b64)
        .unwrap();
    let evidence: hark::mls::removal::RemovalEvidence =
        serde_json::from_slice(&evidence_bytes).unwrap();
    let remove_frame = alice.remove_with_evidence(&evidence).unwrap();
    assert!(matches!(
        bob.handle_frame(&remove_frame),
        SessionEvent::Handled { .. }
    ));
    let post_removal = alice
        .encrypt_outbound("(say @research :from @alice :text \"bob must not read this\")")
        .unwrap();
    match bob.handle_frame(&post_removal) {
        SessionEvent::Dropped { .. } => {}
        other => panic!("a removed member must not decrypt, got {other:?}"),
    }

    // Restart resilience (REQ-009): alice reloads and still operates.
    drop(alice);
    let mut alice2 =
        MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, false).unwrap();
    assert!(alice2.joined());
    assert!(alice2.encrypted());
    alice2
        .encrypt_outbound("(say @research :from @alice :text \"post-restart\")")
        .unwrap();

    let _ = fs::remove_dir_all(&a_dir);
    let _ = fs::remove_dir_all(&b_dir);
}

/// NFR-004 / condition I (full form): with `max_past_epochs = 0`, superseded
/// epoch secrets are pruned from the DURABLE state — the on-disk file does
/// not grow with epoch churn (the §10 spike observed ~2.3 KB retained per
/// epoch when retention is unbounded).
#[test]
fn epoch_churn_does_not_accumulate_secrets_on_disk() {
    let (dir, wire) = setup("churn", 93, "alice");
    let mut alice =
        MlsSession::open(&dir, "alice", "@research", "@alice", &wire, true).unwrap();
    alice.create_group_as_creator().unwrap();

    // Each encrypt persists; sample the state size across heavy ratchet use.
    alice
        .encrypt_outbound("(say @research :from @alice :text \"warmup\")")
        .unwrap();
    let size_after_one = fs::metadata(dir.join("alice.mls")).unwrap().len();

    for i in 0..50 {
        alice
            .encrypt_outbound(&format!("(say @research :from @alice :text \"m{i}\")"))
            .unwrap();
    }
    let size_after_many = fs::metadata(dir.join("alice.mls")).unwrap().len();

    assert!(
        size_after_many < size_after_one * 3,
        "durable state must not accumulate superseded secrets: {size_after_one}B → \
         {size_after_many}B after 50 more messages"
    );
    let _ = fs::remove_dir_all(&dir);
}
