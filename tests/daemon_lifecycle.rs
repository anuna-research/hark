use std::net::SocketAddr;

use hark::{constants::LOCAL_API_VERSION, daemon::DiscoveryRecord};
use time::OffsetDateTime;

mod support;
use support::{TestEnv, assert_success, output_debug, secure_dir, secure_file};

#[test]
fn daemon_start_status_stop_lifecycle() {
    let env = TestEnv::new();

    let start = env
        .command(["daemon", "start"])
        .output()
        .expect("start runs");
    assert_success(&start);

    let second_start = env
        .command(["daemon", "start"])
        .output()
        .expect("start runs");
    assert_success(&second_start);

    let status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");
    assert_success(&status);
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(stdout.contains("daemon: running"));
    assert!(stdout.contains("agents: 0"));

    let run = env.command(["daemon", "run"]).output().expect("run exits");
    assert_eq!(run.status.code(), Some(4), "{}", output_debug(&run));

    let stop = env.command(["daemon", "stop"]).output().expect("stop runs");
    assert_success(&stop);

    let stopped_status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");
    assert_eq!(
        stopped_status.status.code(),
        Some(3),
        "{}",
        output_debug(&stopped_status)
    );
}

#[test]
fn daemon_start_does_not_require_router_config() {
    let env = TestEnv::new();

    let start = env
        .command(["daemon", "start"])
        .output()
        .expect("start runs");
    assert_success(&start);

    let stop = env.command(["daemon", "stop"]).output().expect("stop runs");
    assert_success(&stop);
}

#[test]
fn daemon_status_reports_not_running() {
    let env = TestEnv::new();

    let status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");

    assert_eq!(status.status.code(), Some(3), "{}", output_debug(&status));
    assert!(String::from_utf8_lossy(&status.stdout).contains("daemon: not running"));
}

#[test]
fn daemon_stop_cleans_stale_discovery_when_lock_is_free() {
    let env = TestEnv::new();
    let runtime_dir = env.runtime_dir();
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir should be created");
    secure_dir(&runtime_dir);
    let discovery = runtime_dir.join("daemon.json");
    let record = DiscoveryRecord {
        pid: 12345,
        addr: "127.0.0.1:9"
            .parse::<SocketAddr>()
            .expect("addr should parse"),
        token: "stale-test-token".to_owned(),
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("timestamp should be valid"),
        version: "0.1.0".to_owned(),
        api_version: LOCAL_API_VERSION,
    };
    std::fs::write(
        &discovery,
        serde_json::to_vec(&record).expect("record should serialize"),
    )
    .expect("discovery should be written");
    secure_file(&discovery);

    let stop = env.command(["daemon", "stop"]).output().expect("stop runs");

    assert_success(&stop);
    assert!(!discovery.exists());
}
