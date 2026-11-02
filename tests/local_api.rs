use std::{net::SocketAddr, path::PathBuf};

use hark::{
    constants::LOCAL_API_VERSION,
    daemon::DiscoveryRecord,
    local_api::{AgentsResponse, LocalApiClient, PingResponse, serve_local_api},
};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};

#[tokio::test]
async fn local_api_ping_and_status_work_over_loopback() {
    let server = TestServer::start(None).await;
    let client = server.client();

    assert_eq!(
        client.ping().await.expect("ping should succeed"),
        PingResponse::current()
    );

    let status = client.agents().await.expect("status should succeed");
    assert_eq!(
        status,
        AgentsResponse {
            daemon: hark::local_api::DaemonStatus {
                pid: server.record.pid,
                addr: server.record.addr,
                version: server.record.version.clone(),
                api_version: server.record.api_version,
            },
            agents: Vec::new(),
            active_agent_handle: None,
        }
    );

    server.stop().await;
}

#[tokio::test]
async fn local_api_stop_removes_discovery_file() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let discovery_file = temp_dir.path().join("daemon.json");
    std::fs::write(&discovery_file, "{}").expect("discovery should be written");
    let server = TestServer::start(Some(discovery_file.clone())).await;

    assert!(
        server
            .client()
            .stop()
            .await
            .expect("stop should succeed")
            .ok
    );
    server.await_stopped().await;

    assert!(!discovery_file.exists());
}

struct TestServer {
    record: DiscoveryRecord,
    task: JoinHandle<Result<(), hark::local_api::LocalApiError>>,
}

impl TestServer {
    async fn start(discovery_file: Option<PathBuf>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        let record = sample_record(addr);
        let task_record = record.clone();
        let task =
            tokio::spawn(
                async move { serve_local_api(listener, task_record, discovery_file).await },
            );
        let server = Self { record, task };
        server.wait_until_ready().await;
        server
    }

    fn client(&self) -> LocalApiClient {
        LocalApiClient::from_discovery(&self.record).expect("client should build")
    }

    async fn wait_until_ready(&self) {
        let client = self.client();
        for _ in 0..20 {
            if client.ping().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("server did not become ready");
    }

    async fn stop(self) {
        let _ = self.client().stop().await;
        self.await_stopped().await;
    }

    async fn await_stopped(self) {
        self.task
            .await
            .expect("server task should not panic")
            .expect("server should stop cleanly");
    }
}

fn sample_record(addr: SocketAddr) -> DiscoveryRecord {
    DiscoveryRecord {
        pid: 12345,
        addr,
        token: "local-api-integration-token".to_owned(),
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("timestamp should be valid"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: LOCAL_API_VERSION,
    }
}

mod support;

#[tokio::test]
async fn media_cli_rejects_api4_daemon_before_issuing_operations() {
    use axum::{Json, Router, routing::get};
    use hark::daemon::{RuntimePaths, create_runtime_dir, write_discovery_record};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let env = support::TestEnv::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut record = sample_record(listener.local_addr().unwrap());
    record.api_version = 4;
    let paths = RuntimePaths::new(env.runtime_dir());
    create_runtime_dir(&paths.runtime_dir).unwrap();
    write_discovery_record(&paths, &record).unwrap();
    let unexpected = Arc::new(AtomicUsize::new(0));
    let calls = unexpected.clone();
    let app = Router::new()
        .route(
            "/v1/ping",
            get(|| async {
                Json(PingResponse {
                    ok: true,
                    version: "0.7.0".into(),
                    api_version: 4,
                })
            }),
        )
        .fallback(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { axum::http::StatusCode::UNPROCESSABLE_ENTITY }
        });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    for args in [
        vec!["media", "list"],
        vec!["media", "upload", "tests/vectors/media/sample.png"],
    ] {
        let result = tokio::process::Command::from(env.command(args))
            .output()
            .await
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(12),
            "{}",
            support::output_debug(&result)
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains("daemon_api_incompatible"), "{error}");
        assert!(error.contains("restart the daemon"), "{error}");
    }
    assert_eq!(unexpected.load(Ordering::SeqCst), 0);
    // TestEnv cleanup is synchronous; remove the mock discovery before Drop.
    std::fs::remove_file(&paths.discovery_file).unwrap();
    server.abort();
}
