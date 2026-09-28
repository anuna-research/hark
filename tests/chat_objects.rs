//! SPEC-086 — object transport over a real socket.
//!
//! Every test drives the *production* `create_chat_agent` against the
//! scriptable fake hub in `support::chat_hub` (cleartext rooms; the MLS
//! attestation path is covered by the `object_transport` unit tests and the
//! `mls_private_channel` session tests). What is asserted is exactly what the
//! spec's TEST-001..TEST-003 ask of the transport: which frames reach `recv`,
//! with which record, byte-for-byte.
//!
//!   cargo test --test chat_objects -- --nocapture

mod support;

use std::sync::Arc;
use std::time::Duration;

use hark::chat::create_chat_agent;
use hark::daemon::{AgentError, AgentState, AgentStore, AgentStoreConfig, Inbound};
use hark::identity::ChatIdentity;
use hark::object_transport::{AttestedBy, ObjectRecord, history_request_frame};
use hark::objects::runtime::spawn as spawn_objects;
use support::chat_hub::{Act, FakeHub};
use url::Url;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// An SDK object action as the browser's `emit.js` builds it, with an
/// uninstalled contract digest — hark has no definition for it and must not
/// care (SPEC-086 REQ-007).
fn object(from: &str, item: &str) -> String {
    format!(
        "(lang sha256-{HEX} (check @general :item \"{item}\" :caused-by sha256-{HEX} \
         :thread \"list-1\" :from {from}))"
    )
}

fn backfilltimes(count: usize) -> String {
    let times = (0..count)
        .map(|index| (1_786_007_287_642u64 + index as u64).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("(backfilltimes @general :times ({times}))")
}

fn store() -> AgentStore {
    AgentStore::new(AgentStoreConfig {
        agent_id_prefix: "hark-spec086".to_owned(),
        max_messages_per_handle: 64,
        max_bytes_per_handle: 65_536,
    })
}

fn identity() -> Arc<ChatIdentity> {
    Arc::new(ChatIdentity::from_seed([8u8; 32]))
}

async fn join(
    store: AgentStore,
    hub: &FakeHub,
    objects: bool,
    receive_all: bool,
) -> hark::daemon::AgentHandle {
    let ws_url = Url::parse(&hub.ws_url()).expect("fake hub url parses");
    let (handle, _warnings) = create_chat_agent(
        store,
        &ws_url,
        "@general",
        "@aria",
        vec![],
        None,
        None,
        Duration::from_millis(50),
        Duration::from_millis(100),
        identity(),
        None,
        false,
        receive_all,
        objects,
        None,
    )
    .await
    .expect("the join succeeds");
    handle
}

async fn next(store: &AgentStore, handle: &hark::daemon::AgentHandle) -> Inbound {
    store
        .recv_inbound(handle, Some(Duration::from_secs(3)))
        .await
        .expect("a message reaches recv")
}

async fn nothing_more(store: &AgentStore, handle: &hark::daemon::AgentHandle) {
    let extra = store
        .recv_inbound(handle, Some(Duration::from_millis(500)))
        .await;
    assert!(
        matches!(extra, Err(AgentError::RecvTimeout)),
        "nothing else should reach recv, but got {extra:?}"
    );
}

fn record(signer: &str, own: bool, replayed: bool) -> ObjectRecord {
    ObjectRecord {
        room: "@general".to_owned(),
        signer: signer.to_owned(),
        attested_by: AttestedBy::Hub,
        own,
        replayed,
    }
}

/// TEST-001 / TEST-003 (cleartext): an object message is delivered with a
/// hub-attested record, byte-for-byte; a non-object message is not delivered
/// to an agent with only the object subscription; an object message without
/// `:from` yields no record; the agent's own message comes back marked `own`.
#[tokio::test]
async fn object_messages_reach_recv_with_a_record_and_nothing_else_does() {
    let anonymous = format!("(lang sha256-{HEX} (check @general :item \"eggs\" :thread \"t\"))");
    let hub = FakeHub::start(vec![Act::AcceptAndServe {
        enc: false,
        send: vec![
            backfilltimes(3),
            "(tell @general \"hello\" :from @bo)".to_owned(),
            anonymous,
            object("@alice", "milk"),
        ],
        history: vec![],
    }])
    .await;
    let store = store();
    let handle = join(store.clone(), &hub, true, false).await;

    // REQ-001/REQ-002/REQ-005: the object frame, its bytes untouched, with a
    // record; replayed because it came in the announced backfill (CON-001).
    let first = next(&store, &handle).await;
    assert_eq!(first.message, object("@alice", "milk"));
    assert_eq!(first.record, Some(record("@alice", false, true)));
    // The tell and the :from-less object are not delivered (REQ-006, TEST-001
    // negative input, TEST-003 negative input).
    nothing_more(&store, &handle).await;

    // REQ-001: delivery includes the agent's own messages. The hub fans the
    // send back; it arrives with `own: true` and is live, not replayed.
    let own = object("@aria", "bread");
    store
        .send_outbound(&handle, own.clone())
        .await
        .expect("the send is accepted");
    let echo = next(&store, &handle).await;
    assert_eq!(echo.message, own, "byte-for-byte (REQ-005)");
    assert_eq!(echo.record, Some(record("@aria", true, false)));
    nothing_more(&store, &handle).await;

    assert!(
        hub.wait_for_frame(0, &own, Duration::from_secs(2)).await,
        "the hub received the agent's bytes unchanged; transcript={:?}",
        hub.transcript(0)
    );
}

/// TEST-002 (REQ-003): after a reconnect the hub replays its backfill; the
/// object message reaches `recv` again (the SDK deduplicates by cid), while a
/// replayed non-object message stays suppressed exactly as before.
#[tokio::test]
async fn replayed_object_history_is_redelivered_after_a_reconnect_and_other_replays_are_not() {
    let backfill = vec![
        backfilltimes(2),
        "(tell @general \"the same message\" :from @bo)".to_owned(),
        object("@alice", "milk"),
    ];
    let hub = FakeHub::start(vec![
        Act::AcceptThenDropAfterSending {
            enc: false,
            send: backfill.clone(),
        },
        Act::AcceptAndSend {
            enc: false,
            send: backfill,
        },
    ])
    .await;
    let store = store();
    // receive-all AND objects: the tell is observed on the firehose, the
    // object message as a record — once each, never twice.
    let handle = join(store.clone(), &hub, true, true).await;

    // Receive-all is a firehose: the hub's `backfilltimes` control frame
    // reaches it too, exactly as before SPEC-086 (REQ-001: the object
    // subscription changes no other delivery).
    let announcement = next(&store, &handle).await;
    assert!(
        announcement.message.starts_with("(backfilltimes"),
        "got {announcement:?}"
    );
    assert_eq!(announcement.record, None);
    let tell = next(&store, &handle).await;
    assert!(tell.message.starts_with("(tell @general"), "got {tell:?}");
    assert_eq!(
        tell.record, None,
        "receive-all delivers non-objects without a record"
    );
    let first = next(&store, &handle).await;
    assert_eq!(first.record, Some(record("@alice", false, true)));
    nothing_more(&store, &handle).await;

    // The socket drops; the agent reconnects; the hub replays the same run.
    assert!(
        hub.wait_for_connections(2, Duration::from_secs(6)).await,
        "the agent re-joins"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        let state = store
            .status_snapshots()
            .await
            .into_iter()
            .find(|snapshot| snapshot.agent_handle == handle.as_str())
            .map(|snapshot| snapshot.state);
        if state == Some(AgentState::Connected) && hub.connections() == 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the agent came back"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // REQ-003: the replayed object message arrives again, still `replayed`;
    // the replayed tell (and the byte-identical announcement) do not
    // (SPEC-026 REQ-003 unchanged).
    let again = next(&store, &handle).await;
    assert_eq!(again.message, object("@alice", "milk"));
    assert_eq!(again.record, Some(record("@alice", false, true)));
    nothing_more(&store, &handle).await;
}

/// TEST-002 (REQ-004 / CON-002): a history request goes out on the agent's
/// own connection as `(history <room> :limit <n> :from <handle>)`; the hub's
/// raw reply frames reach `recv` as replayed object records; the room's one
/// in-flight slot refuses a second request; an unjoined room is refused.
#[tokio::test]
async fn history_replies_reach_recv_as_replayed_object_records() {
    let hub = FakeHub::start(vec![Act::AcceptAndServe {
        enc: false,
        send: vec![],
        history: vec![
            "(tell @general \"older\" :from @bo)".to_owned(),
            object("@alice", "opener"),
        ],
    }])
    .await;
    let store = store();
    let handle = join(store.clone(), &hub, true, false).await;

    assert!(
        matches!(
            store
                .begin_history(&handle, "@elsewhere", Duration::from_secs(5))
                .await,
            Err(AgentError::RoomNotJoined)
        ),
        "an unjoined room is refused"
    );
    let from = store
        .begin_history(&handle, "@general", Duration::from_secs(5))
        .await
        .expect("the first request is admitted");
    assert_eq!(
        from, "@aria",
        "the request is signed :from the agent's wire handle"
    );
    assert!(
        matches!(
            store
                .begin_history(&handle, "@general", Duration::from_secs(5))
                .await,
            Err(AgentError::HistoryInFlight)
        ),
        "a second request while one is unanswered is refused"
    );

    let request = history_request_frame("@general", 5, &from);
    store
        .send_control_outbound(&handle, request.clone())
        .await
        .expect("the request is sent");
    assert!(
        hub.wait_for_frame(0, &request, Duration::from_secs(2))
            .await,
        "the hub received the request; transcript={:?}",
        hub.transcript(0)
    );

    let replayed = next(&store, &handle).await;
    assert_eq!(replayed.message, object("@alice", "opener"));
    assert_eq!(replayed.record, Some(record("@alice", false, true)));
    // The tell in the reply is not an object message.
    nothing_more(&store, &handle).await;
}

/// SPEC-086 Stage B over a real socket: with the object runtime attached, a
/// hark agent creates an object, the hub receives and echoes the opener, the
/// agent acts, and the state it reads is the projection of exactly the bytes
/// on the wire. The echoes deduplicate: still one thread, one opener.
#[tokio::test]
async fn a_hark_agent_creates_reads_and_acts_on_an_object_through_the_hub() {
    let hub = FakeHub::start(vec![Act::AcceptAndServe {
        enc: false,
        send: vec![],
        history: vec![],
    }])
    .await;
    let store = store();
    store
        .attach_objects(spawn_objects(
            store.clone(),
            tokio::runtime::Handle::current(),
            None,
        ))
        .await;
    let handle = join(store.clone(), &hub, true, false).await;
    let (objects, who) = store
        .objects_for(&handle)
        .await
        .expect("subscribed, runtime attached");

    let definition = serde_json::json!({
        "name": "checklist",
        "verbs": {
            "open": { "causedBy": "begin", "fields": { "title": "string" } },
            "check": { "causedBy": ["open"], "fields": { "item": "string", "done": "bool" } }
        },
        "project": { "title": ["last", "open", "title"], "items": ["latestPerKey", "check", "item", "done"] }
    });
    let opened = objects
        .open(
            who.clone(),
            definition,
            "list-1".to_owned(),
            serde_json::json!({ "title": "Groceries" }),
        )
        .await
        .expect("open runs");
    assert!(opened.ok, "{opened:?}");
    let opener = opened.message.clone().unwrap();
    assert!(
        hub.wait_for_frame(0, &opener, Duration::from_secs(2)).await,
        "the opener reached the hub byte-for-byte; transcript={:?}",
        hub.transcript(0)
    );
    // The hub fans the opener back; it arrives as an own object record.
    let echo = next(&store, &handle).await;
    assert_eq!(echo.message, opener);
    assert_eq!(echo.record, Some(record("@aria", true, false)));

    let acted = objects
        .act(
            who.clone(),
            "list-1".to_owned(),
            "check".to_owned(),
            serde_json::json!({ "item": "milk", "done": true }),
        )
        .await
        .expect("act runs");
    assert!(acted.ok, "{acted:?}");
    let echo = next(&store, &handle).await;
    assert!(echo.message.contains(":item \"milk\""), "{}", echo.message);
    assert!(
        hub.wait_for_frame(0, &echo.message, Duration::from_secs(2))
            .await,
        "the action reached the hub byte-for-byte"
    );

    let state = objects
        .read(who.clone(), "list-1".to_owned())
        .await
        .expect("read runs")
        .expect("known");
    assert_eq!(
        state.state,
        serde_json::json!({ "title": "Groceries", "items": { "milk": true } })
    );
    let listed = objects.list(who).await.unwrap();
    assert_eq!(listed.len(), 1, "echoes deduplicated by cid: {listed:?}");
}
