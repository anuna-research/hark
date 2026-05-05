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
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse as WsErrorResponse, Request, Response},
        http::StatusCode as WsStatusCode,
    },
};

const ROUTER_SECRET: &str = "shr_test.secret";
const DISPATCH: &str = "(lang elf (ask @router \"work\" :thread \"rcp-1\"))";

#[test]
fn e2e_mvp_happy_path_start_init_recv_progress_reply_close_stop() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let router = runtime.block_on(MockRouter::start(RouterBehavior::HappyPath));
    let env = TestEnv::new().with_router(router.ws_url(), ROUTER_SECRET);

    assert_success(
        &env.command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );

    let init = env
        .command(["init", "--capability", "code:edit", "--dialect", "elf"])
        .output()
        .expect("init runs");
    assert_success(&init);
    let handle = parse_exported_handle(&init);

    let recv = env
        .command_with_handle(["recv", "--timeout", "2s"], &handle)
        .output()
        .expect("recv runs");
    assert_success(&recv);
    assert_eq!(
        String::from_utf8_lossy(&recv.stdout),
        format!("{DISPATCH}\n")
    );

    let progress = env
        .command_with_handle(
            ["progress", "--thread", "rcp-1", "--text", "running"],
            &handle,
        )
        .output()
        .expect("progress runs");
    assert_success(&progress);
    assert!(progress.stdout.is_empty(), "{}", output_debug(&progress));

    let reply = env
        .command_with_handle(
            ["reply", r#"(lang elf (reply "done" :thread "rcp-1"))"#],
            &handle,
        )
        .output()
        .expect("reply runs");
    assert_success(&reply);
    assert!(reply.stdout.is_empty(), "{}", output_debug(&reply));

    let close = env
        .command_with_handle(["close"], &handle)
        .output()
        .expect("close runs");
    assert_success(&close);

    let stop = env.command(["daemon", "stop"]).output().expect("stop runs");
    assert_success(&stop);
    assert!(
        !env.discovery_file().exists(),
        "daemon stop should remove daemon.json"
    );

    runtime.block_on(router.wait());
    let frames = router.frames();
    assert!(frames.iter().any(|frame| frame.contains("\"progress\"")));
    assert!(
        frames
            .iter()
            .any(|frame| frame == r#"(lang elf (reply "done" :thread "rcp-1"))"#)
    );
    assert_no_token_leak(&init, &env);
    assert_no_token_leak(&recv, &env);
    assert_no_token_leak(&progress, &env);
    assert_no_token_leak(&reply, &env);
    assert_no_token_leak(&close, &env);
    assert_no_token_leak(&stop, &env);
}

#[test]
fn e2e_daemon_start_does_not_require_router_config() {
    let env = TestEnv::new();

    let start = env
        .command(["daemon", "start"])
        .output()
        .expect("start runs");
    assert_success(&start);

    let init = env
        .command(["init", "--capability", "code:edit"])
        .output()
        .expect("init runs");
    assert_eq!(init.status.code(), Some(9), "{}", output_debug(&init));
    assert_no_token_leak(&init, &env);

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    assert!(!env.discovery_file().exists());
}

#[test]
fn e2e_init_reports_missing_malformed_and_rejected_router_config() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");

    let missing = TestEnv::new();
    assert_success(
        &missing
            .command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );
    let output = missing
        .command(["init", "--capability", "code:edit"])
        .output()
        .expect("init runs");
    assert_eq!(output.status.code(), Some(9), "{}", output_debug(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing_router_ws_url"));
    assert_success(
        &missing
            .command(["daemon", "stop"])
            .output()
            .expect("stop runs"),
    );

    let malformed = TestEnv::new().with_router("https://router.example/agent/v1", ROUTER_SECRET);
    assert_success(
        &malformed
            .command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );
    let output = malformed
        .command(["init", "--capability", "code:edit"])
        .output()
        .expect("init runs");
    assert_eq!(output.status.code(), Some(9), "{}", output_debug(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid_router_ws_url"));
    assert_success(
        &malformed
            .command(["daemon", "stop"])
            .output()
            .expect("stop runs"),
    );

    let router = runtime.block_on(MockRouter::start(RouterBehavior::RejectAuth));
    let rejected = TestEnv::new().with_router(router.ws_url(), ROUTER_SECRET);
    assert_success(
        &rejected
            .command(["daemon", "start"])
            .output()
            .expect("start runs"),
    );
    let output = rejected
        .command(["init", "--capability", "code:edit"])
        .output()
        .expect("init runs");
    assert_eq!(output.status.code(), Some(9), "{}", output_debug(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("router_auth_rejected"));
    assert_success(
        &rejected
            .command(["daemon", "stop"])
            .output()
            .expect("stop runs"),
    );
    runtime.block_on(router.wait());
}

#[test]
fn e2e_unhealthy_handles_surface_for_router_close_error_and_queue_overflow() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");

    for (behavior, expected_status_text) in [
        (RouterBehavior::CloseAfterHello, "unhealthy"),
        (RouterBehavior::SendError, "unhealthy"),
        (RouterBehavior::OverflowDispatch, "unhealthy"),
    ] {
        let router = runtime.block_on(MockRouter::start(behavior));
        let env = TestEnv::new()
            .with_router(router.ws_url(), ROUTER_SECRET)
            .with_queue_limits(1, 512);
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
        let handle = parse_exported_handle(&init);
        runtime.block_on(router.wait());
        std::thread::sleep(Duration::from_millis(100));

        let recv = env
            .command_with_handle(["recv", "--timeout", "1ms"], &handle)
            .output()
            .expect("recv runs");
        assert_eq!(recv.status.code(), Some(7), "{}", output_debug(&recv));

        let status = env
            .command(["daemon", "status"])
            .output()
            .expect("status runs");
        assert_success(&status);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains(expected_status_text),
            "{}",
            output_debug(&status)
        );

        assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    }
}

#[test]
fn e2e_local_send_failure_marks_handle_unusable() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let router = runtime.block_on(MockRouter::start(RouterBehavior::AbortAfterHello));
    let env = TestEnv::new().with_router(router.ws_url(), ROUTER_SECRET);
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
    let handle = parse_exported_handle(&init);
    runtime.block_on(router.wait());
    std::thread::sleep(Duration::from_millis(100));

    let reply = env
        .command_with_handle(["reply", r#"(reply "done" :thread "rcp-1")"#], &handle)
        .output()
        .expect("reply runs");
    assert_eq!(reply.status.code(), Some(7), "{}", output_debug(&reply));

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
}

#[derive(Debug, Clone, Copy)]
enum RouterBehavior {
    HappyPath,
    RejectAuth,
    CloseAfterHello,
    SendError,
    OverflowDispatch,
    AbortAfterHello,
}

#[derive(Clone)]
struct MockRouter {
    addr: SocketAddr,
    shared: Arc<Mutex<MockRouterState>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Default)]
struct MockRouterState {
    frames: Vec<String>,
}

impl MockRouter {
    async fn start(behavior: RouterBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("router should bind");
        let addr = listener.local_addr().expect("router addr should exist");
        let shared = Arc::new(Mutex::new(MockRouterState::default()));
        let task_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let callback = move |_request: &Request, response: Response| {
                if matches!(behavior, RouterBehavior::RejectAuth) {
                    let mut response = WsErrorResponse::new(Some("unauthorized".to_owned()));
                    *response.status_mut() = WsStatusCode::UNAUTHORIZED;
                    return Err(response);
                }
                Ok(response)
            };
            let Ok(mut websocket) = accept_hdr_async(stream, callback).await else {
                return;
            };

            if let Some(Ok(message)) = websocket.next().await {
                task_shared
                    .lock()
                    .expect("mock state should lock")
                    .frames
                    .push(message_to_string(message));
            }

            match behavior {
                RouterBehavior::HappyPath => {
                    let _ = websocket
                        .send(Message::Binary(DISPATCH.as_bytes().to_vec().into()))
                        .await;
                    for _ in 0..2 {
                        if let Some(Ok(message)) = websocket.next().await {
                            task_shared
                                .lock()
                                .expect("mock state should lock")
                                .frames
                                .push(message_to_string(message));
                        }
                    }
                }
                RouterBehavior::CloseAfterHello => {
                    let _ = websocket.close(None).await;
                }
                RouterBehavior::SendError => {
                    let _ = websocket
                        .send(Message::Binary(
                            b"(lang cbcl-router (error @router \"bad hello\"))"
                                .to_vec()
                                .into(),
                        ))
                        .await;
                }
                RouterBehavior::OverflowDispatch => {
                    for index in 0..3 {
                        let frame = format!(
                            "(lang elf (ask @router \"work-{index}\" :thread \"rcp-{index}\"))"
                        );
                        let _ = websocket
                            .send(Message::Binary(frame.into_bytes().into()))
                            .await;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                RouterBehavior::AbortAfterHello | RouterBehavior::RejectAuth => {}
            }
        });

        Self {
            addr,
            shared,
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    fn ws_url(&self) -> String {
        format!("ws://{}/agent/v1", self.addr)
    }

    fn frames(&self) -> Vec<String> {
        self.shared
            .lock()
            .expect("mock state should lock")
            .frames
            .clone()
    }

    async fn wait(&self) {
        let task = self.task.lock().expect("task should lock").take();
        if let Some(task) = task {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }
}

struct TestEnv {
    _temp_dir: TempDir,
    home: PathBuf,
    xdg_runtime_dir: PathBuf,
    router_ws_url: Option<String>,
    router_auth_token: Option<String>,
    max_messages: Option<usize>,
    max_bytes: Option<usize>,
}

impl TestEnv {
    fn new() -> Self {
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
            router_ws_url: None,
            router_auth_token: None,
            max_messages: None,
            max_bytes: None,
        }
    }

    fn with_router(mut self, ws_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        self.router_ws_url = Some(ws_url.into());
        self.router_auth_token = Some(auth_token.into());
        self
    }

    fn with_queue_limits(mut self, max_messages: usize, max_bytes: usize) -> Self {
        self.max_messages = Some(max_messages);
        self.max_bytes = Some(max_bytes);
        self
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
            .env_remove("CBCL_DAEMON_BIND")
            .env_remove("CBCL_AGENT_ID_PREFIX")
            .env_remove("CBCL_DAEMON_OVERFLOW_POLICY")
            .env_remove("CBCL_AGENT_HANDLE")
            .env_remove("CBCL_ROUTER_WS")
            .env_remove("CBCL_ROUTER_AUTH_TOKEN")
            .env_remove("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE")
            .env_remove("CBCL_DAEMON_MAX_BYTES_PER_HANDLE");
        if let Some(value) = &self.router_ws_url {
            command.env("CBCL_ROUTER_WS", value);
        }
        if let Some(value) = &self.router_auth_token {
            command.env("CBCL_ROUTER_AUTH_TOKEN", value);
        }
        if let Some(value) = self.max_messages {
            command.env("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE", value.to_string());
        }
        if let Some(value) = self.max_bytes {
            command.env("CBCL_DAEMON_MAX_BYTES_PER_HANDLE", value.to_string());
        }
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

    fn discovery_file(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            self.xdg_runtime_dir
                .join("cbcl-router-client")
                .join("daemon.json")
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("cbcl-router-client")
                .join("runtime")
                .join("daemon.json")
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.home
                .join(".local")
                .join("state")
                .join("cbcl-router-client")
                .join("runtime")
                .join("daemon.json")
        }
    }

    fn daemon_token(&self) -> Option<String> {
        let bytes = std::fs::read(self.discovery_file()).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        value["token"].as_str().map(ToOwned::to_owned)
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

fn parse_exported_handle(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .strip_prefix("export CBCL_AGENT_HANDLE='")
        .and_then(|value| value.strip_suffix('\''))
        .expect("export output should contain handle")
        .to_owned()
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_debug(output));
}

fn assert_no_token_leak(output: &Output, env: &TestEnv) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains(ROUTER_SECRET),
        "{}",
        output_debug(output)
    );
    if let Some(token) = env.daemon_token() {
        assert!(!combined.contains(&token), "{}", output_debug(output));
    }
}

fn message_to_string(message: Message) -> String {
    match message {
        Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Message::Text(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

fn output_debug(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
