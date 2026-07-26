//! SPEC-026 REQ-008/REQ-009 — a daemon restart re-establishes every paired
//! agent, without a human.
//!
//! These drive the real `hark` binary through `TestEnv` (isolated `HOME`, so the
//! pairing store lands in a temp config directory) against the scriptable fake
//! hub. Reconnecting the socket fixes the *redeploy* case; this is the *restart*
//! case, and without both the recovery story stays half-finished.
//!
//!   cargo test --test pairing_rehydrate -- --nocapture

mod support;

use std::time::Duration;

use support::chat_hub::{Act, FakeHub};
use support::{assert_success, output_debug, TestEnv};

/// The `active: <handle>` line from `hark daemon status`, if any.
fn active_handle(env: &TestEnv) -> Option<String> {
    let output = env.command(["daemon", "status"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("active: "))
        .map(|handle| handle.trim().to_owned())
}

/// Poll `hark daemon status` until `predicate` holds over its stdout.
fn await_status(env: &TestEnv, timeout: Duration, predicate: impl Fn(&str) -> bool) -> String {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let output = env
            .command(["daemon", "status"])
            .output()
            .expect("status runs");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if predicate(&stdout) || std::time::Instant::now() >= deadline {
            return stdout;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// TEST-010 (SPEC-026 REQ-008, ADR-006) — `hark daemon stop && hark daemon
/// start` brings the agent back, under the **same** agent handle.
///
/// Before this, a restart dropped every agent (`agents: 0`) and re-pairing was
/// mandatory, even though the hub remembers the membership durably. The handle
/// is preserved so an operator's exported `CBCL_AGENT_HANDLE` survives too.
#[test]
fn a_daemon_restart_re_establishes_the_agent_under_the_same_handle() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let hub = runtime.block_on(FakeHub::start_for(
        vec![
            Act::Accept { enc: false },
            Act::Accept { enc: false },
            Act::Accept { enc: false },
        ],
        "@demo",
    ));
    let env = TestEnv::new();

    let join = env
        .command(["join", "@demo", "--as", "@aria", "--hub", &hub.ws_url()])
        .output()
        .expect("join runs");
    assert_success(&join);
    let before = active_handle(&env).expect("the joined agent is the active handle");

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    assert_success(
        &env.command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );

    let status = await_status(&env, Duration::from_secs(15), |stdout| {
        stdout.contains(&before)
    });
    assert!(
        status.contains(&before),
        "the same agent handle must come back after a restart; wanted {before}\n{status}"
    );
    assert!(
        status.contains("connected"),
        "the re-established agent is connected\n{status}"
    );

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
}

/// TEST-011 (SPEC-026 REQ-008, negative-output) — the hub being down at start
/// must not lose the agent, and must not block the daemon from reporting ready.
///
/// This is the load-bearing negative: an implementation that only re-establishes
/// agents it can reach *right now* would quietly turn "the hub was restarting
/// when I rebooted" back into "re-pair by hand".
#[test]
fn a_restart_with_no_hub_keeps_the_agent_and_still_reports_ready() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    // One connection only: the join succeeds, and every later dial is refused.
    let hub = runtime.block_on(FakeHub::start_for(vec![Act::Accept { enc: false }], "@demo"));
    let env = TestEnv::new();

    let join = env
        .command(["join", "@demo", "--as", "@aria", "--hub", &hub.ws_url()])
        .output()
        .expect("join runs");
    assert_success(&join);
    let before = active_handle(&env).expect("the joined agent is the active handle");

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    let start = env
        .command(["daemon", "start"])
        .output()
        .expect("start runs");
    // Ready is reported without waiting on a hub that is not there.
    assert_success(&start);

    let status = await_status(&env, Duration::from_secs(15), |stdout| {
        stdout.contains(&before)
    });
    assert!(
        status.contains(&before),
        "the agent is kept and retried, not dropped; wanted {before}\n{status}"
    );
    assert!(
        status.contains("reconnecting"),
        "an agent whose hub is down at start is visibly reconnecting\n{status}"
    );
    assert!(
        !status.contains("unhealthy"),
        "an unreachable hub is not a terminal condition\n{status}"
    );

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
}

/// TEST-012 (SPEC-026 REQ-009) — a deliberately closed agent stays closed. If
/// `hark close` did not forget the pairing, closing an agent would be undone by
/// the next restart, which is worse than not persisting at all.
#[test]
fn a_closed_agent_does_not_come_back_on_the_next_start() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let hub = runtime.block_on(FakeHub::start_for(
        vec![Act::Accept { enc: false }, Act::Accept { enc: false }],
        "@demo",
    ));
    let env = TestEnv::new();

    let join = env
        .command(["join", "@demo", "--as", "@aria", "--hub", &hub.ws_url()])
        .output()
        .expect("join runs");
    assert_success(&join);
    let handle = active_handle(&env).expect("the joined agent is the active handle");

    let close = env
        .command_with_handle(["close"], &handle)
        .output()
        .expect("close runs");
    assert_success(&close);

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    assert_success(
        &env.command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );

    // Give rehydration the time it would need if it were (wrongly) going to
    // bring the agent back.
    std::thread::sleep(Duration::from_secs(2));
    let status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("agents: 0"),
        "a closed agent must not be resurrected: {}",
        output_debug(&status)
    );

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
}
