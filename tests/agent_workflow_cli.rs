use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
};

use futures_util::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const DISPATCH: &str = "(lang elf (ask @router \"work\" :thread \"rcp-1\"))";

#[test]
fn cli_workflow_init_recv_and_close_keeps_stdout_clean() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let router = runtime.block_on(MockRouter::start());
    let env = TestEnv::new(router.ws_url());

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
    let env = TestEnv::new(router.ws_url());

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
    let env = TestEnv::new("ws://127.0.0.1:9/agent/v1".to_owned());

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

struct TestEnv {
    _temp_dir: TempDir,
    home: PathBuf,
    xdg_runtime_dir: PathBuf,
    router_ws_url: String,
}

impl TestEnv {
    fn new(router_ws_url: String) -> Self {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let home = temp_dir.path().join("home");
        let xdg_runtime_dir = temp_dir.path().join("xdg-runtime");
        std::fs::create_dir_all(&home).expect("home should be created");
        std::fs::create_dir_all(&xdg_runtime_dir).expect("runtime should be created");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("home permissions should be set");
            std::fs::set_permissions(&xdg_runtime_dir, std::fs::Permissions::from_mode(0o700))
                .expect("runtime permissions should be set");
        }

        Self {
            _temp_dir: temp_dir,
            home,
            xdg_runtime_dir,
            router_ws_url,
        }
    }

    fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(binary_path());
        command
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_RUNTIME_DIR", &self.xdg_runtime_dir)
            .env("CBCL_ROUTER_WS", &self.router_ws_url)
            .env("CBCL_ROUTER_AUTH_TOKEN", "shr_test.secret")
            .env_remove("CBCL_DAEMON_BIND")
            .env_remove("CBCL_AGENT_ID_PREFIX")
            .env_remove("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE")
            .env_remove("CBCL_DAEMON_MAX_BYTES_PER_HANDLE")
            .env_remove("CBCL_DAEMON_OVERFLOW_POLICY")
            .env_remove("CBCL_AGENT_HANDLE");
        command
    }

    fn command_with_handle<I, S>(&self, args: I, handle: &str) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = self.command(args);
        command.env("CBCL_AGENT_HANDLE", handle);
        command
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = self.command(["daemon", "stop"]).output();
    }
}

fn binary_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cbcl-router-client"))
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_debug(output));
}

fn output_debug(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
