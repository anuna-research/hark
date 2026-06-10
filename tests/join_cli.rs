//! SPEC-016 REQ-002 (TEST-002): `hark join` is a one-shot — from a clean HOME
//! it scaffolds config, starts the daemon, and joins the channel, with no TOML
//! edit, no `eval`, and no `/chat/v1` transport knowledge.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use tokio_tungstenite::{accept_async, tungstenite::Message};

mod support;
use support::{TestEnv, assert_success, output_debug};

const BOOTSTRAP: &str =
    "(tell @client \"conn-nonce\" :from @cbcl-chat :nonce \"AAAAAAAAAAAAAAAAAAAAAA==\" :hub \"cbcl-chat\")";

#[test]
fn cli_join_scaffolds_config_starts_daemon_and_joins() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let hub = runtime.block_on(MockChatHub::start("@demo"));
    // A clean HOME: no config file, no daemon.
    let env = TestEnv::new();

    let join = env
        .command(["join", "@demo", "--as", "@aria", "--hub", &hub.ws_url()])
        .output()
        .expect("join runs");
    assert_success(&join);
    let stdout = String::from_utf8_lossy(&join.stdout);
    assert!(
        stdout.contains("joined @demo as @aria"),
        "{}",
        output_debug(&join)
    );

    // The config was scaffolded with the chat hub URL — no hand-editing.
    let config =
        std::fs::read_to_string(env.config_file()).expect("config should be scaffolded");
    assert!(config.contains("/chat/v1"), "config:\n{config}");

    // The hub saw a hello for the requested channel + handle.
    let hello = hub.hello().expect("hub should have received a hello");
    assert!(hello.contains("(hello @demo"), "hello: {hello}");
    assert!(hello.contains(":from @aria"), "hello: {hello}");

    // The agent is live, channel-tagged, and the session's active handle —
    // follow-up commands need no exported env var (REQ-003).
    let status = env
        .command(["daemon", "status"])
        .output()
        .expect("status runs");
    assert_success(&status);
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status_stdout.contains("active: "), "{status_stdout}");

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(hub.wait());
}

#[test]
fn cli_join_announces_itself_as_an_agent() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let hub = runtime.block_on(MockChatHub::start("@demo"));
    let env = TestEnv::new();

    let join = env
        .command([
            "join", "@demo", "--as", "@aria", "--speak", "cite", "--hub", &hub.ws_url(),
        ])
        .output()
        .expect("join runs");
    assert_success(&join);

    // REQ-006 (SPEC-016, TEST-006): after the roomcfg ack the agent emits
    // exactly one `announce` so chat clients render it as an agent.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let announces: Vec<String> = loop {
        let announces: Vec<String> = hub
            .received()
            .into_iter()
            .filter(|frame| frame.contains("(announce "))
            .collect();
        if !announces.is_empty() {
            break announces;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "hub never received an announce; got {:?}",
            hub.received()
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    assert_eq!(announces.len(), 1, "exactly one announce: {announces:?}");
    assert!(
        announces[0].contains(":agent @aria"),
        "announce carries the handle: {}",
        announces[0]
    );
    assert!(
        announces[0].contains("\"cite\""),
        "announce carries the advertised dialects: {}",
        announces[0]
    );

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(hub.wait());
}

#[test]
fn cli_join_validates_speak_against_declared_menu() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    // REQ-008 (SPEC-016, TEST-008): the channel declares a menu; an
    // undeclared --speak dialect is rejected before the agent joins.
    let hub = runtime.block_on(MockChatHub::start_with_roomcfg(
        r#"(roomcfg @demo :enc false :dialects (("cite" "abc123")))"#,
    ));
    let env = TestEnv::new();

    let join = env
        .command([
            "join", "@demo", "--as", "@aria", "--speak", "vote", "--hub", &hub.ws_url(),
        ])
        .output()
        .expect("join runs");
    assert_eq!(join.status.code(), Some(2), "{}", output_debug(&join));
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(stderr.contains("vote"), "{}", output_debug(&join));
    assert!(stderr.contains("cite"), "names the declared menu: {stderr}");

    runtime.block_on(hub.wait());
}

#[test]
fn cli_join_accepts_declared_speak_subset() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let hub = runtime.block_on(MockChatHub::start_with_roomcfg(
        r#"(roomcfg @demo :enc false :dialects (("cite" "abc123") ("vote" "def456")))"#,
    ));
    let env = TestEnv::new();

    // HP-5: only the chosen subset, never the whole menu.
    let join = env
        .command([
            "join", "@demo", "--as", "@aria", "--speak", "cite", "--hub", &hub.ws_url(),
        ])
        .output()
        .expect("join runs");
    assert_success(&join);
    let stdout = String::from_utf8_lossy(&join.stdout);
    assert!(
        stdout.contains("speaking: cite"),
        "{}",
        output_debug(&join)
    );
    assert!(!stdout.contains("vote"), "never the whole menu: {stdout}");

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(hub.wait());
}

#[test]
fn cli_join_warns_when_channel_declares_no_menu() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    // Today's hub conveys no :dialects in roomcfg; the validation soft-passes
    // with an explicit warning, never silently.
    let hub = runtime.block_on(MockChatHub::start("@demo"));
    let env = TestEnv::new();

    let join = env
        .command([
            "join", "@demo", "--as", "@aria", "--speak", "cite", "--hub", &hub.ws_url(),
        ])
        .output()
        .expect("join runs");
    assert_success(&join);
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(
        stderr.contains("declare"),
        "warns about the missing menu: {}",
        output_debug(&join)
    );

    assert_success(&env.command(["daemon", "stop"]).output().expect("stop runs"));
    runtime.block_on(hub.wait());
}

#[test]
fn cli_join_rejects_undeclared_channel_handles() {
    let env = TestEnv::new();
    let join = env
        .command(["join", "demo", "--as", "@aria"])
        .output()
        .expect("join runs");
    assert_eq!(join.status.code(), Some(2), "{}", output_debug(&join));
    assert!(
        String::from_utf8_lossy(&join.stderr).contains("channel"),
        "{}",
        output_debug(&join)
    );
}

#[derive(Clone)]
struct MockChatHub {
    addr: SocketAddr,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
    hello: Arc<Mutex<Option<String>>>,
    received: Arc<Mutex<Vec<String>>>,
}

impl MockChatHub {
    async fn start(channel: &str) -> Self {
        Self::start_with_roomcfg(&format!("(roomcfg {channel} :enc false)")).await
    }

    async fn start_with_roomcfg(roomcfg: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("hub should bind");
        let addr = listener.local_addr().expect("hub addr should exist");
        let hello = Arc::new(Mutex::new(None));
        let hello_writer = hello.clone();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_writer = received.clone();
        let roomcfg = roomcfg.to_owned();
        let task = tokio::spawn(async move {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let Ok(mut websocket) = accept_async(stream).await else {
                return;
            };
            // SPEC-012: the hub's first frame is the conn-nonce bootstrap.
            let _ = websocket
                .send(Message::Text(BOOTSTRAP.to_owned().into()))
                .await;
            // The signed hello (binary frame embedding the payload).
            if let Some(Ok(message)) = websocket.next().await {
                let text = match message {
                    Message::Text(text) => text.to_string(),
                    Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    _ => String::new(),
                };
                *hello_writer.lock().expect("hello should lock") = Some(text);
            }
            // Acknowledge the join.
            let _ = websocket
                .send(Message::Text(roomcfg.into()))
                .await;
            // Record every post-ack frame and keep the socket open so the
            // agent stays healthy.
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(5), websocket.next()).await;
                let Ok(Some(Ok(message))) = frame else {
                    return;
                };
                let text = match message {
                    Message::Text(text) => text.to_string(),
                    Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    _ => continue,
                };
                received_writer
                    .lock()
                    .expect("received should lock")
                    .push(text);
            }
        });

        Self {
            addr,
            task: Arc::new(Mutex::new(Some(task))),
            hello,
            received,
        }
    }

    fn received(&self) -> Vec<String> {
        self.received.lock().expect("received should lock").clone()
    }

    fn ws_url(&self) -> String {
        format!("ws://{}/chat/v1", self.addr)
    }

    fn hello(&self) -> Option<String> {
        self.hello.lock().expect("hello should lock").clone()
    }

    async fn wait(&self) {
        let task = self.task.lock().expect("task should lock").take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}
