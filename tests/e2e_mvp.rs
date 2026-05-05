use std::{
    net::SocketAddr,
    process::Output,
    sync::{Arc, Mutex},
};

use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse as WsErrorResponse, Request, Response},
        http::StatusCode as WsStatusCode,
    },
};

mod support;
use support::{TestEnv, assert_success, output_debug};

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

    let status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");
    assert_success(&status);
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status_stdout.contains("router_agent_id=local-agent-"));
    assert!(status_stdout.contains("capabilities=[code:edit]"));
    assert!(status_stdout.contains("dialects=[elf]"));

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
        let status_stdout = String::from_utf8_lossy(&status.stdout);
        assert!(
            status_stdout.contains(expected_status_text),
            "{}",
            output_debug(&status)
        );
        assert!(status_stdout.contains("unhealthy_reason="));
        if behavior == RouterBehavior::SendError {
            assert!(status_stdout.contains("unhealthy_detail="));
            assert!(status_stdout.contains("bad hello"));
        }

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

fn parse_exported_handle(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .strip_prefix("export CBCL_AGENT_HANDLE='")
        .and_then(|value| value.strip_suffix('\''))
        .expect("export output should contain handle")
        .to_owned()
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
