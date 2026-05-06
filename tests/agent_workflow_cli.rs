use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use cbcl_router_client::config::{AppConfig, SAMPLE_CONFIG};
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use tokio_tungstenite::{accept_async, tungstenite::Message};

mod support;
use support::{TestEnv, assert_success, output_debug};

const DISPATCH: &str = "(lang elf (ask @router \"work\" :thread \"rcp-1\"))";

#[test]
fn cli_workflow_init_recv_and_close_keeps_stdout_clean() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let router = runtime.block_on(MockRouter::start());
    let env = TestEnv::new().with_router(router.ws_url(), "shr_test.secret");

    assert_success(
        &env.command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );

    let init = env
        .command(["init", "--capability", "code:edit"])
        .output()
        .expect("init runs");
    assert_success(&init);
    assert!(init.stderr.is_empty(), "{}", output_debug(&init));
    let init_stdout = String::from_utf8_lossy(&init.stdout);
    assert!(init_stdout.starts_with("export CBCL_AGENT_HANDLE='"));
    assert!(init_stdout.ends_with("'\n"));
    let handle = init_stdout
        .trim()
        .strip_prefix("export CBCL_AGENT_HANDLE='")
        .and_then(|value| value.strip_suffix('\''))
        .expect("export output should contain handle")
        .to_owned();

    let recv = env
        .command_with_handle(["recv", "--timeout", "2s"], &handle)
        .output()
        .expect("recv runs");
    assert_success(&recv);
    assert_eq!(
        String::from_utf8_lossy(&recv.stdout),
        format!("{DISPATCH}\n")
    );
    assert!(recv.stderr.is_empty(), "{}", output_debug(&recv));

    let close = env
        .command_with_handle(["close"], &handle)
        .output()
        .expect("close runs");
    assert_success(&close);
    assert!(close.stdout.is_empty(), "{}", output_debug(&close));

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(router.wait());
}

#[test]
fn cli_init_json_outputs_api_response_only() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let router = runtime.block_on(MockRouter::start());
    let env = TestEnv::new().with_router(router.ws_url(), "shr_test.secret");

    assert_success(
        &env.command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );

    let init = env
        .command(["init", "--capability", "code:edit", "--json"])
        .output()
        .expect("init runs");
    assert_success(&init);
    assert!(init.stderr.is_empty(), "{}", output_debug(&init));
    let json: serde_json::Value =
        serde_json::from_slice(&init.stdout).expect("init JSON should parse");
    assert!(json["agent_handle"].as_str().is_some());
    assert_eq!(json["capabilities"], serde_json::json!(["code:edit"]));
    assert_eq!(json["state"], "connected");

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(router.wait());
}

#[test]
fn cli_rejects_missing_handle_and_duplicate_init_values() {
    let env = TestEnv::new().with_router("ws://127.0.0.1:9/agent/v1", "shr_test.secret");

    let recv = env
        .command(["recv", "--timeout", "1ms"])
        .output()
        .expect("recv runs");
    assert_eq!(recv.status.code(), Some(6), "{}", output_debug(&recv));

    let duplicate_capability = env
        .command([
            "init",
            "--capability",
            "code:edit",
            "--capability",
            "code:edit",
        ])
        .output()
        .expect("init runs");
    assert_eq!(
        duplicate_capability.status.code(),
        Some(2),
        "{}",
        output_debug(&duplicate_capability)
    );

    let duplicate_dialect = env
        .command([
            "init",
            "--capability",
            "code:edit",
            "--dialect",
            "elf",
            "--dialect",
            "elf",
        ])
        .output()
        .expect("init runs");
    assert_eq!(
        duplicate_dialect.status.code(),
        Some(2),
        "{}",
        output_debug(&duplicate_dialect)
    );
}

#[test]
fn cli_config_commands_show_path_example_and_initialize_file() {
    let env = TestEnv::new();

    let path = env.command(["config", "path"]).output().expect("path runs");
    assert_success(&path);
    assert_eq!(
        String::from_utf8_lossy(&path.stdout),
        format!("{}\n", env.config_file().display())
    );
    assert!(path.stderr.is_empty(), "{}", output_debug(&path));

    let example = env
        .command(["config", "show-example"])
        .output()
        .expect("show-example runs");
    assert_success(&example);
    assert_eq!(String::from_utf8_lossy(&example.stdout), SAMPLE_CONFIG);
    assert!(example.stderr.is_empty(), "{}", output_debug(&example));

    let init = env.command(["config", "init"]).output().expect("init runs");
    assert_success(&init);
    assert_eq!(
        String::from_utf8_lossy(&init.stdout),
        format!("{}\n", env.config_file().display())
    );
    assert_eq!(
        std::fs::read_to_string(env.config_file()).expect("config should be written"),
        SAMPLE_CONFIG
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.config_file())
            .expect("config metadata should load")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    let loaded = AppConfig::load_from(Some(env.config_file())).expect("sample config should parse");
    assert_eq!(
        loaded.router.ws_url.as_deref(),
        Some("wss://cbcl-lfe.anuna.io/agent/v1")
    );
    assert_eq!(
        loaded.router.auth_token.as_deref(),
        Some("shr_prod-agent.REPLACE_ME")
    );

    let second_init = env
        .command(["config", "init"])
        .output()
        .expect("second init runs");
    assert_eq!(second_init.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&second_init.stderr).contains("refusing to overwrite"),
        "{}",
        output_debug(&second_init)
    );
    assert_eq!(
        std::fs::read_to_string(env.config_file()).expect("config should remain"),
        SAMPLE_CONFIG
    );
}

#[derive(Clone)]
struct MockRouter {
    addr: SocketAddr,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl MockRouter {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("router should bind");
        let addr = listener.local_addr().expect("router addr should exist");
        let task = tokio::spawn(async move {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let Ok(mut websocket) = accept_async(stream).await else {
                return;
            };
            let _ = websocket.next().await;
            let _ = websocket
                .send(Message::Binary(DISPATCH.as_bytes().to_vec().into()))
                .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        Self {
            addr,
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    fn ws_url(&self) -> String {
        format!("ws://{}/agent/v1", self.addr)
    }

    async fn wait(&self) {
        let task = self.task.lock().expect("task should lock").take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}
