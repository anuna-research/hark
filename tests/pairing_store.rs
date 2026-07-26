//! SPEC-026 CON-002 — the durable pairing store.
//!
//! The store carries a channel **capability**, so it is a trust boundary in the
//! LangSec sense even though the bytes came from us: a permissively-parsed
//! record is a record whose capability field may not be the one that was
//! written. Recognition is therefore total — a store that does not match the
//! declared grammar in full yields *nothing*, never a partial list.
//!
//!   cargo test --test pairing_store -- --nocapture

use hark::pairing::store::{PairedAgent, PairingStore};

fn record(handle: &str) -> PairedAgent {
    PairedAgent {
        agent_handle: handle.to_owned(),
        wire_handle: "@aria".to_owned(),
        channel: "@research".to_owned(),
        dialects: vec!["cite".to_owned()],
        cap: Some("cap-abc123".to_owned()),
        added_by: Some("@hugo".to_owned()),
        receive_all: true,
    }
}

/// TEST-009 (SPEC-026 REQ-007, positive) — a saved record round-trips, and the
/// file is owner-only. It holds a bearer credential; the mode is part of the
/// contract, not a nicety.
#[test]
fn a_saved_record_round_trips_and_the_file_is_owner_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());

    store
        .upsert(record("1K65XWE7NSPZMCVJFFAWS02SHR"))
        .expect("upsert should succeed");

    let loaded = store.load();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0], record("1K65XWE7NSPZMCVJFFAWS02SHR"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.path())
            .expect("the store file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the store holds a capability: owner-only");
    }
}

/// TEST-014 (SPEC-026 REQ-007/REQ-010, property) — `load(save(records)) ==
/// records` over a set, including the shapes where fields are absent.
#[test]
fn the_store_round_trips_every_valid_record_shape() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());

    let records = vec![
        record("1K65XWE7NSPZMCVJFFAWS02SHR"),
        PairedAgent {
            agent_handle: "2M76YXF8PTQANDWKGGBXT13TJS".to_owned(),
            wire_handle: "@bo".to_owned(),
            channel: "@general".to_owned(),
            dialects: vec![],
            cap: None,      // a public channel
            added_by: None, // joined directly, not paired in
            receive_all: false,
        },
        PairedAgent {
            agent_handle: "3N87ZYG9PVRBPEXMHHCYV24VKT".to_owned(),
            wire_handle: "@cy".to_owned(),
            channel: "@ops".to_owned(),
            dialects: vec!["cite".to_owned(), "vote".to_owned()],
            cap: Some("cap-xyz".to_owned()),
            added_by: None,
            receive_all: true,
        },
    ];

    store.save(&records).expect("save should succeed");
    assert_eq!(store.load(), records, "load(save(records)) == records");
}

/// TEST-012 (SPEC-026 REQ-009) — closing an agent removes its record, and only
/// its record. A deliberately closed agent must not come back on the next
/// daemon start.
#[test]
fn removing_one_record_leaves_the_others() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());
    let mut second = record("2M76YXF8PTQANDWKGGBXT13TJS");
    second.wire_handle = "@bo".to_owned();

    store.upsert(record("1K65XWE7NSPZMCVJFFAWS02SHR")).unwrap();
    store.upsert(second.clone()).unwrap();
    assert_eq!(store.load().len(), 2);

    store
        .remove("1K65XWE7NSPZMCVJFFAWS02SHR")
        .expect("remove should succeed");

    let left = store.load();
    assert_eq!(left, vec![second], "only the closed agent is forgotten");

    // Removing something absent is not an error: `hark close` on an agent whose
    // record was already gone must not fail the close.
    store
        .remove("1K65XWE7NSPZMCVJFFAWS02SHR")
        .expect("removing an absent record is a no-op");
}

/// TEST-009 (positive) — an upsert replaces the record for the same agent
/// handle rather than appending a duplicate.
#[test]
fn upsert_replaces_rather_than_duplicates() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());

    store.upsert(record("1K65XWE7NSPZMCVJFFAWS02SHR")).unwrap();
    let mut updated = record("1K65XWE7NSPZMCVJFFAWS02SHR");
    updated.channel = "@ops".to_owned();
    store.upsert(updated.clone()).unwrap();

    assert_eq!(store.load(), vec![updated]);
}

/// TEST-013 (SPEC-026 REQ-010, negative-input) — the recognition is **total**.
/// Every malformed store yields zero records. The last case is the one that
/// matters most: a valid record sitting next to a malformed one yields *zero*,
/// not one. Skipping the bad record and using the rest is precisely the
/// permissive parsing that lets a store disagree with itself.
#[test]
fn every_malformed_store_yields_no_records() {
    let good = r#"{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","dialects":["cite"],"cap":"cap-abc123","added_by":"@hugo","receive_all":true}"#;

    let cases: Vec<(&str, String)> = vec![
        ("non-JSON bytes", "not json at all".to_owned()),
        ("truncated JSON", r#"{"version":1,"agents":["#.to_owned()),
        (
            "unknown version",
            format!(r#"{{"version":2,"agents":[{good}]}}"#),
        ),
        (
            "missing the version",
            format!(r#"{{"agents":[{good}]}}"#),
        ),
        (
            "a record missing `channel`",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","dialects":[],"receive_all":false}]}"#.to_owned(),
        ),
        (
            "a channel that is not an @-handle",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"research","dialects":[],"receive_all":false}]}"#.to_owned(),
        ),
        (
            "a wire handle that is not an @-handle",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"aria","channel":"@research","dialects":[],"receive_all":false}]}"#.to_owned(),
        ),
        (
            "an agent handle the AgentHandle recogniser rejects",
            r#"{"version":1,"agents":[{"agent_handle":"not a handle!","wire_handle":"@aria","channel":"@research","dialects":[],"receive_all":false}]}"#.to_owned(),
        ),
        (
            "a dialect id the dialect recogniser rejects",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","dialects":["9bad id"],"receive_all":false}]}"#.to_owned(),
        ),
        (
            "one good record ALONGSIDE one malformed record",
            format!(
                r#"{{"version":1,"agents":[{good},{{"agent_handle":"2M76YXF8PTQANDWKGGBXT13TJS","wire_handle":"bo","channel":"@ops","dialects":[],"receive_all":false}}]}}"#
            ),
        ),
    ];

    for (name, body) in cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PairingStore::new(dir.path());
        std::fs::write(store.path(), body).expect("the fixture writes");
        assert!(
            store.load().is_empty(),
            "{name}: a store that does not fully match the grammar must yield NO records"
        );
    }
}

/// TEST-013 (negative-input) — an absent store is a valid state meaning "no
/// persisted agents", not an error. A first run must not be a failure.
#[test]
fn an_absent_store_is_empty_not_an_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path().join("does-not-exist-yet"));
    assert!(store.load().is_empty());
}

/// TEST-013 (positive) — the empty store round-trips as empty rather than
/// tripping the "malformed" path. The boundary between "nothing recorded" and
/// "unreadable" has to be crisp, or a fresh install looks like corruption.
#[test]
fn an_empty_agent_list_is_recognised() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());
    std::fs::write(store.path(), r#"{"version":1,"agents":[]}"#).expect("the fixture writes");
    assert!(store.load().is_empty());

    // And it is distinguishable from malformed by the diagnostic channel.
    assert!(
        store.load_checked().is_ok(),
        "an empty list parses cleanly; only malformed input reports an error"
    );
}

/// SPEC-026 REQ-010 (negative-output) — an unrecognised store must not be
/// *destroyed* by the next write.
///
/// `load` deliberately degrades to "no agents" so a daemon can still start. But
/// `upsert` and `remove` are read-modify-write: if they degrade the same way,
/// the next successful join overwrites the unreadable file with a single record
/// and silently deletes every pairing it could not parse — repairing input that
/// REQ-010 says must stay rejected, and losing data while doing it.
#[test]
fn a_write_against_an_unrecognised_store_fails_instead_of_clobbering_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = PairingStore::new(dir.path());
    let corrupt = r#"{"version":2,"agents":[]}"#;
    std::fs::write(store.path(), corrupt).expect("the fixture writes");

    store
        .upsert(record("1K65XWE7NSPZMCVJFFAWS02SHR"))
        .expect_err("an upsert must refuse to overwrite an unrecognised store");
    store
        .remove("1K65XWE7NSPZMCVJFFAWS02SHR")
        .expect_err("a remove must refuse to rewrite an unrecognised store");

    assert_eq!(
        std::fs::read_to_string(store.path()).expect("the file is still there"),
        corrupt,
        "the unrecognised bytes are left exactly as found, for the operator to inspect"
    );
}

/// SPEC-026 CON-002 (negative-input) — the per-record grammar is enforced as
/// declared. `receive_all` and `dialects` are REQUIRED by the grammar, and an
/// unknown key means the writer and this reader disagree about the format.
///
/// The `receive_all` case is the one with teeth: defaulting a misspelled key to
/// `false` silently downgrades a firehose agent to an answer-only one, on a
/// record that also carries a capability.
#[test]
fn the_per_record_grammar_rejects_missing_and_unknown_keys() {
    let cases: Vec<(&str, &str)> = vec![
        (
            "a misspelled receive_all",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","dialects":[],"recieve_all":true}]}"#,
        ),
        (
            "receive_all absent entirely",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","dialects":[]}]}"#,
        ),
        (
            "dialects absent entirely",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","receive_all":false}]}"#,
        ),
        (
            "an unknown extra key",
            r#"{"version":1,"agents":[{"agent_handle":"1K65XWE7NSPZMCVJFFAWS02SHR","wire_handle":"@aria","channel":"@research","dialects":[],"receive_all":false,"future_field":1}]}"#,
        ),
    ];

    for (name, body) in cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PairingStore::new(dir.path());
        std::fs::write(store.path(), body).expect("the fixture writes");
        assert!(
            store.load_checked().is_err(),
            "{name}: the record does not match the declared grammar and must be rejected"
        );
        assert!(store.load().is_empty(), "{name}: and yields no records");
    }
}

/// SPEC-026 CON-002 — concurrent joins must not lose each other's records.
///
/// `upsert` is a read-modify-write over a whole file. Two joins completing at
/// once can both read the same old list and then both write, and whichever
/// renames last silently drops the other agent — which then does not come back
/// on the next daemon start, the exact failure this store exists to prevent.
#[test]
fn concurrent_upserts_do_not_lose_records() {
    let dir = tempfile::tempdir().expect("temp dir");
    let handles = [
        "1K65XWE7NSPZMCVJFFAWS02SHR",
        "2M76YXF8PTQANDWKGGBXT13TJS",
        "3N87ZYG9PVRBPEXMHHCYV24VKT",
        "4P98A0H9QWSCQFYNJJDZW35WMV",
    ];

    std::thread::scope(|scope| {
        for handle in handles {
            let path = dir.path().to_owned();
            scope.spawn(move || {
                PairingStore::new(path)
                    .upsert(record(handle))
                    .expect("each concurrent upsert succeeds");
            });
        }
    });

    let loaded = PairingStore::new(dir.path()).load();
    let mut got: Vec<String> = loaded.iter().map(|a| a.agent_handle.clone()).collect();
    got.sort();
    let mut want: Vec<String> = handles.iter().map(|h| (*h).to_owned()).collect();
    want.sort();
    assert_eq!(got, want, "every concurrently-joined agent survives");
}
