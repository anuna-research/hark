use std::net::SocketAddr;

use hark::{
    constants::LOCAL_API_VERSION,
    daemon::{
        DiscoveryRecord, DiscoveryState, ProbeResult, RuntimePaths, classify_discovery_with_probe,
        create_runtime_dir, generate_daemon_token, load_discovery_record, write_discovery_record,
    },
    local_api::PingResponse,
};
use tempfile::TempDir;
use time::OffsetDateTime;

#[test]
fn discovery_record_round_trips_through_public_api() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let paths = RuntimePaths::new(temp_dir.path().join("runtime"));
    create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
    let record = sample_record();

    write_discovery_record(&paths, &record).expect("discovery should be written");

    assert_eq!(
        load_discovery_record(&paths).expect("discovery should load"),
        Some(record)
    );
}

#[test]
fn discovery_classifier_reports_live_daemon_through_public_api() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let paths = RuntimePaths::new(temp_dir.path().join("runtime"));
    create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
    let record = sample_record();
    write_discovery_record(&paths, &record).expect("discovery should be written");

    let state =
        classify_discovery_with_probe(&paths, |_| ProbeResult::Live(PingResponse::current()))
            .expect("classification should succeed");

    assert!(matches!(state, DiscoveryState::Live { .. }));
}

#[test]
fn generated_daemon_tokens_are_shell_safe() {
    let token = generate_daemon_token();

    assert_eq!(token.len(), 43);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

fn sample_record() -> DiscoveryRecord {
    DiscoveryRecord {
        pid: 12345,
        addr: "127.0.0.1:49152"
            .parse::<SocketAddr>()
            .expect("addr should parse"),
        token: "integration-test-token".to_owned(),
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("timestamp should be valid"),
        version: "0.1.0".to_owned(),
        api_version: LOCAL_API_VERSION,
    }
}
