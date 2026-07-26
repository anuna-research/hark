//! SPEC-026 — transport resilience over a real socket.
//!
//! Every test here drives the *production* `create_chat_agent` against the
//! scriptable fake hub in `support::chat_hub`. Nothing of hark is mocked; the
//! fake is the peer, because the behaviour under test is what hark does when a
//! real socket to a real peer ends.
//!
//!   cargo test --test chat_reconnect -- --nocapture

mod support;

use std::sync::Arc;
use std::time::Duration;

use hark::chat::create_chat_agent;
use hark::daemon::{AgentState, AgentStore, AgentStoreConfig};
use hark::identity::ChatIdentity;
use support::chat_hub::{Act, FakeHub};
use url::Url;

/// A fresh store with generous queue limits — none of these tests are about
/// overflow.
fn store() -> AgentStore {
    AgentStore::new(AgentStoreConfig {
        agent_id_prefix: "hark-spec026".to_owned(),
        max_messages_per_handle: 64,
        max_bytes_per_handle: 65_536,
    })
}

fn identity() -> Arc<ChatIdentity> {
    Arc::new(ChatIdentity::from_seed([7u8; 32]))
}

/// Join the fake hub as `@aria` on `@general`, advertising `cite`, with a
/// capability so the re-join has something non-trivial to replay.
async fn join(
    store: AgentStore,
    hub: &FakeHub,
) -> Result<(hark::daemon::AgentHandle, Vec<String>), hark::chat::ChatError> {
    let ws_url = Url::parse(&hub.ws_url()).expect("fake hub url parses");
    create_chat_agent(
        store,
        &ws_url,
        "@general",
        "@aria",
        vec!["cite".to_owned()],
        Some("cap-abc123".to_owned()),
        Some("@hugo".to_owned()),
        Duration::from_millis(50),
        Duration::from_millis(100),
        identity(),
        None,  // no MLS session: this channel is not pinned encrypted
        false, // mls_create
        true,  // receive_all
        None,  // a fresh join, not a resume
    )
    .await
}

async fn state_of(store: &AgentStore, handle: &hark::daemon::AgentHandle) -> AgentState {
    store
        .status_snapshots()
        .await
        .into_iter()
        .find(|snapshot| snapshot.agent_handle == handle.as_str())
        .expect("the agent is in the store")
        .state
}

/// Poll until `predicate` holds over the agent's snapshot, or `timeout` elapses.
/// Returns the last snapshot seen either way, so a failing assertion can report
/// what the state actually was.
async fn await_snapshot(
    store: &AgentStore,
    handle: &hark::daemon::AgentHandle,
    timeout: Duration,
    predicate: impl Fn(&hark::daemon::AgentStatusSnapshot) -> bool,
) -> hark::daemon::AgentStatusSnapshot {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let snapshot = store
            .status_snapshots()
            .await
            .into_iter()
            .find(|snapshot| snapshot.agent_handle == handle.as_str())
            .expect("the agent is in the store");
        if predicate(&snapshot) || tokio::time::Instant::now() >= deadline {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The harness's own smoke test (IMPL-026 task-fake-hub). Everything downstream
/// asserts *changes* to what happens over this socket, so this test pins what
/// happens over it today: the production join path completes against the fake
/// hub, and the hub sees a `hello` followed by an `announce`.
#[tokio::test]
async fn fake_hub_drives_the_production_join_path() {
    let hub = FakeHub::start(vec![Act::Accept { enc: false }]).await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    assert_eq!(hub.connections(), 1, "exactly one connection was made");
    assert!(
        hub.wait_for_frame(0, "(announce", Duration::from_secs(2))
            .await,
        "the announce should reach the hub; transcript={:?}",
        hub.transcript(0)
    );

    let transcript = hub.transcript(0);
    assert!(
        transcript[0].starts_with("(hello @general"),
        "the first client frame is the signed hello; got {:?}",
        transcript[0]
    );
    assert!(
        transcript[0].contains(":cap \"cap-abc123\"") || transcript[0].contains("cap-abc123"),
        "the hello carries the capability; got {:?}",
        transcript[0]
    );
    let announce = transcript
        .iter()
        .find(|frame| frame.starts_with("(announce"))
        .expect("an announce was recorded");
    assert!(
        announce.contains("@aria") && announce.contains("cite"),
        "the announce names the agent and its dialects; got {announce:?}"
    );

    assert_eq!(
        state_of(&store, &handle).await,
        AgentState::Connected,
        "a freshly joined agent is connected"
    );
}

/// TEST-001 / TEST-001b (SPEC-026 REQ-001) — **the issue-#25 regression.**
///
/// The hub accepts, then drops the socket the way a redeploy does, then accepts
/// again. Before this fix the agent went `unhealthy / hub_closed` and stayed
/// there forever; now it re-joins and the handle is never terminally unhealthy.
///
/// The two assertions are deliberately both here: the positive one (a second
/// connection happened) would pass on a buggy implementation that reconnected
/// *and* poisoned the handle, and the negative one (never unhealthy) would pass
/// on one that did nothing at all but never noticed the drop.
#[tokio::test]
async fn a_dropped_socket_is_reconnected_and_never_marks_the_handle_unhealthy() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1, // drop after the announce
        },
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    // The first delay is ~1 s (jittered down to ≥ 750 ms), plus a handshake.
    assert!(
        hub.wait_for_connections(2, Duration::from_secs(5)).await,
        "the agent must come back after the drop; connections={}",
        hub.connections()
    );

    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Connected && snapshot.reconnect_attempts == 0
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Connected,
        "the agent is connected again after the blip"
    );
    // TEST-001b: the exact observed symptom must be absent.
    assert_eq!(
        snapshot.unhealthy_reason, None,
        "a transport drop must never produce unhealthy_reason=hub_closed"
    );
}

/// TEST-003 (SPEC-026 REQ-003) — the reconnect replays the *whole* join, not
/// just the socket. A reconnected socket that skipped the handshake would be a
/// member of nothing, and the hub would drop everything it sent.
#[tokio::test]
async fn the_reconnect_replays_the_hello_with_its_capability_and_the_announce() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1,
        },
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (_handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");
    assert!(hub.wait_for_connections(2, Duration::from_secs(5)).await);
    assert!(
        hub.wait_for_frame(1, "(announce", Duration::from_secs(5))
            .await,
        "the re-join must re-announce; transcript={:?}",
        hub.transcript(1)
    );

    let replay = hub.transcript(1);
    assert!(
        replay[0].starts_with("(hello @general"),
        "the re-join leads with a signed hello; got {:?}",
        replay[0]
    );
    assert!(
        replay[0].contains("cap-abc123"),
        "the re-join presents the ORIGINAL capability, or a private channel \
         would refuse it; got {:?}",
        replay[0]
    );
    let announce = replay
        .iter()
        .find(|frame| frame.starts_with("(announce"))
        .expect("the re-join announces");
    assert!(
        announce.contains("@aria") && announce.contains("cite") && announce.contains("@hugo"),
        "the re-announce carries the original identity, dialects and provenance; \
         got {announce:?}"
    );
}

/// TEST-004 (SPEC-026 REQ-004, NFR-003) — the handle stays usable across the
/// gap. An `emit` is refused as *retryable*, never as terminal, and a `recv`
/// outstanding across the gap receives a message delivered after recovery
/// rather than erroring.
#[tokio::test]
async fn the_handle_stays_usable_across_the_gap() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1,
        },
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    // Wait until the loop has noticed the drop and entered the schedule.
    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(3), |snapshot| {
        snapshot.state == AgentState::Reconnecting
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Reconnecting,
        "the gap is visible as `reconnecting`, not as a death"
    );

    // The load-bearing distinction: NotReady (retry me), not Unhealthy (I am
    // dead). This is the same partition SPEC-013 REQ-023 already established
    // for the MLS membership race.
    let error = store
        .send_outbound(&handle, "(tell @general \"hi\" :from @aria)".to_owned())
        .await
        .expect_err("a send during the gap is refused");
    assert!(
        matches!(error, hark::daemon::AgentError::NotReady { .. }),
        "a send during the gap must be retryable, got {error:?}"
    );

    // The agent is still the session's active handle — an operator's exported
    // CBCL_AGENT_HANDLE keeps working through the blip.
    assert_eq!(
        store.active_handle().await.as_ref().map(|h| h.as_str()),
        Some(handle.as_str())
    );

    // And it recovers.
    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Connected
    })
    .await;
    assert_eq!(snapshot.state, AgentState::Connected);
}

/// TEST-005 (SPEC-026 REQ-005a) — an *active rejection* is terminal. The hub
/// answering the re-join with `(error @room "slug")` means the membership is
/// genuinely gone: retrying would be a loop against a settled answer.
#[tokio::test]
async fn a_hub_rejection_on_re_join_is_terminal() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1,
        },
        Act::Reject {
            slug: "forbidden-room".to_owned(),
        },
        // A third slot: if the agent wrongly kept retrying past the rejection it
        // would take this one, and the connection-count assertion below fails.
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(6), |snapshot| {
        snapshot.state == AgentState::Unhealthy
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Unhealthy,
        "a hub that says no is terminal"
    );
    let detail = format!(
        "{:?} {:?}",
        snapshot.unhealthy_reason, snapshot.unhealthy_detail
    );
    assert!(
        detail.contains("forbidden-room"),
        "the operator is told which slug the hub returned; got {detail}"
    );

    // Negative-output: the schedule stopped. Give it well past one backoff
    // period and confirm no third connection was attempted.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        hub.connections(),
        2,
        "no further attempt is made after a settled rejection"
    );
}

/// TEST-006 (SPEC-026 REQ-005b) — a re-join that would violate the SPEC-013
/// REQ-023 encryption pin is terminal, and fails *closed*. A hub that comes back
/// offering plaintext for a channel pinned encrypted is either misconfigured or
/// hostile; either way the agent must not resume in the clear.
#[tokio::test]
async fn a_downgraded_re_join_on_a_pinned_channel_is_terminal() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: true,
            after_frames: 1,
        },
        Act::Accept { enc: false }, // the downgrade
        Act::Accept { enc: true },  // never reached if the pin holds
    ])
    .await;
    let store = store();
    let dir = tempfile::tempdir().expect("temp dir");
    let identity = identity();
    let mls = hark::mls::session::MlsSession::open_if_relevant(
        dir.path(),
        "aria",
        "@general",
        "@aria",
        identity.as_ref(),
        true, // pinned encrypted: this join presented a capability
    )
    .expect("the session opens")
    .expect("a pinned channel gets a session");

    let ws_url = Url::parse(&hub.ws_url()).expect("fake hub url parses");
    let (handle, _warnings) = create_chat_agent(
        store.clone(),
        &ws_url,
        "@general",
        "@aria",
        vec![],
        Some("cap-abc123".to_owned()),
        None,
        Duration::from_millis(50),
        Duration::from_millis(100),
        identity,
        Some(mls),
        false,
        true,
        None,
    )
    .await
    .expect("the first join succeeds");

    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(6), |snapshot| {
        snapshot.state == AgentState::Unhealthy
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Unhealthy,
        "a refused downgrade is terminal, not a retry"
    );
    let detail = format!(
        "{:?} {:?}",
        snapshot.unhealthy_reason, snapshot.unhealthy_detail
    );
    assert!(
        detail.contains("downgrade") || detail.contains("pinned"),
        "the operator is told the pin was violated; got {detail}"
    );

    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        hub.connections(),
        2,
        "the agent does not keep trying to rejoin a channel it refuses to enter"
    );
}

/// TEST-007 (SPEC-026 REQ-003, negative-output) — the re-join must NOT re-create
/// the MLS group. `create_group_as_creator` a second time would fork the group,
/// silently splitting the channel into two ciphertext worlds.
#[tokio::test]
async fn the_re_join_does_not_recreate_the_mls_group() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: true,
            after_frames: 3, // let the keypub/idkey/keyready + announce through
        },
        Act::Accept { enc: true },
    ])
    .await;
    let store = store();
    let dir = tempfile::tempdir().expect("temp dir");
    let identity = identity();
    let mls = hark::mls::session::MlsSession::open_if_relevant(
        dir.path(),
        "aria",
        "@general",
        "@aria",
        identity.as_ref(),
        true,
    )
    .expect("the session opens")
    .expect("a pinned channel gets a session");

    let ws_url = Url::parse(&hub.ws_url()).expect("fake hub url parses");
    let (handle, _warnings) = create_chat_agent(
        store.clone(),
        &ws_url,
        "@general",
        "@aria",
        vec![],
        Some("cap-abc123".to_owned()),
        None,
        Duration::from_millis(50),
        Duration::from_millis(100),
        identity,
        Some(mls),
        true, // mls_create: this agent IS the room creator
        true,
        None,
    )
    .await
    .expect("the creating join succeeds");

    assert!(
        hub.wait_for_connections(2, Duration::from_secs(5)).await,
        "the agent comes back"
    );
    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Connected
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Connected,
        "an encrypted creator agent reconnects too; snapshot={snapshot:?}"
    );

    // The group is created once. A second create would either error (the group
    // already exists) and fail the re-join — caught by the assertion above — or
    // silently replace it, which would show up as a *different* group id. The
    // republished key material is expected (SPEC-026 OQ-001); a second create is
    // not.
    assert!(
        hub.wait_for_frame(1, "(keypub", Duration::from_secs(5))
            .await,
        "the re-join re-publishes its KeyPackages, as the browser does on reopen; \
         transcript={:?}",
        hub.transcript(1)
    );
}

/// TEST-015 (SPEC-026 REQ-001 write side, REQ-004) — the socket can just as
/// easily die while the agent is *writing*. Fixing only the read side would
/// leave the reported failure intact for an agent that happened to be emitting
/// when the hub went away.
///
/// The failing emit must come back retryable, the agent must reconnect, and the
/// re-offered emit must then succeed — which is the whole contract ADR-003
/// makes with the caller in exchange for not queueing.
#[tokio::test]
async fn a_write_that_fails_on_a_dead_socket_reconnects_and_the_emit_is_retryable() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1, // drop right after the announce
        },
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    // Emit into the gap until one call is refused. Depending on how the OS
    // surfaces the drop, the loop may notice on the read side first — either
    // way the refusal must be retryable, never terminal. That is the assertion:
    // no interleaving produces `Unhealthy`.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut refusal = None;
    while tokio::time::Instant::now() < deadline {
        match store
            .send_outbound(&handle, "(tell @general \"hi\" :from @aria)".to_owned())
            .await
        {
            Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }
    let refusal = refusal.expect("the dropped socket eventually refuses an emit");
    assert!(
        matches!(refusal, hark::daemon::AgentError::NotReady { .. }),
        "a write onto a dead socket must be retryable, got {refusal:?}"
    );

    // ...and the re-offered emit succeeds once the agent is back.
    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Connected
    })
    .await;
    assert_eq!(snapshot.state, AgentState::Connected);
    store
        .send_outbound(
            &handle,
            "(tell @general \"hi again\" :from @aria)".to_owned(),
        )
        .await
        .expect("the re-offered emit succeeds after recovery");
}

/// TEST-008 (SPEC-026 REQ-006, OBS-002) — a reconnecting agent is *visible*.
///
/// This is the requirement that lets the schedule retry indefinitely without
/// stranding the operator (ADR-004): the trade for never giving up is that the
/// gap is never silent. Without it an agent retrying every 15 s against a dead
/// hub would be indistinguishable from a healthy one.
#[tokio::test]
async fn a_reconnecting_agent_reports_its_attempts_and_the_error_that_caused_them() {
    // Only two acts: after the drop, the second attempt is refused (the listener
    // is gone), so the agent stays in the schedule long enough to observe.
    let hub = FakeHub::start(vec![Act::AcceptThenDrop {
        enc: false,
        after_frames: 1,
    }])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Reconnecting && snapshot.reconnect_attempts >= 1
    })
    .await;
    assert_eq!(snapshot.state, AgentState::Reconnecting);
    assert!(
        snapshot.reconnect_attempts >= 1,
        "the operator can see how many attempts have been made; got {}",
        snapshot.reconnect_attempts
    );
    assert!(
        snapshot
            .reconnect_detail
            .as_deref()
            .is_some_and(|detail| !detail.is_empty()),
        "the operator can see WHY, not just that; got {:?}",
        snapshot.reconnect_detail
    );
    // Negative-output: the terminal fields stay empty. "Coming back" must not
    // read as "dead" to anything that keys off unhealthy_reason.
    assert_eq!(snapshot.unhealthy_reason, None);
    assert_eq!(snapshot.unhealthy_detail, None);
}

/// TEST-008 (recovery half) — the progress fields clear on recovery, so the
/// next outage is reported from zero rather than inheriting a stale count.
#[tokio::test]
async fn recovery_clears_the_reconnect_progress() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1,
        },
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");
    let reconnecting = await_snapshot(&store, &handle, Duration::from_secs(3), |snapshot| {
        snapshot.reconnect_attempts >= 1
    })
    .await;
    assert!(reconnecting.reconnect_attempts >= 1);

    let recovered = await_snapshot(&store, &handle, Duration::from_secs(5), |snapshot| {
        snapshot.state == AgentState::Connected
    })
    .await;
    assert_eq!(recovered.state, AgentState::Connected);
    assert_eq!(
        recovered.reconnect_attempts, 0,
        "a recovered agent reports no outstanding attempts"
    );
    assert_eq!(
        recovered.reconnect_detail, None,
        "a recovered agent reports no outstanding error"
    );
}

/// TEST-005 (SPEC-026 REQ-005, negative-output) — a hub that accepts the socket
/// and then says nothing is **not** terminal.
///
/// This is a real deploy state, not a contrived one: the machine is up and the
/// proxy is answering before the app is serving. A join that times out must go
/// back on the schedule; treating "no answer" like "no" would strand the agent
/// on exactly the transient the schedule exists for.
#[tokio::test]
async fn a_hub_that_accepts_but_never_answers_is_retried_not_terminal() {
    let hub = FakeHub::start(vec![
        Act::AcceptThenDrop {
            enc: false,
            after_frames: 1,
        },
        Act::Stall,
        Act::Accept { enc: false },
    ])
    .await;
    let store = store();

    let (handle, _warnings) = join(store.clone(), &hub).await.expect("the join succeeds");

    // The stalled attempt has to time out (JOIN_TIMEOUT is 10 s) before the
    // third connection is made, so allow for it generously.
    assert!(
        hub.wait_for_connections(3, Duration::from_secs(20)).await,
        "a stalled hub is retried, not accepted as a verdict; connections={}",
        hub.connections()
    );
    let snapshot = await_snapshot(&store, &handle, Duration::from_secs(10), |snapshot| {
        snapshot.state == AgentState::Connected
    })
    .await;
    assert_eq!(
        snapshot.state,
        AgentState::Connected,
        "the agent rides out a stalled hub and joins on the next attempt"
    );
    assert_eq!(
        snapshot.unhealthy_reason, None,
        "a join timeout is a transport failure, not a settled refusal"
    );
}
