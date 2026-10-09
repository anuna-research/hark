//! Issue #51: session selection, inspection, and persistent receive over a real daemon.
use std::process::Output;

mod support;
use support::chat_hub::{Act, FakeHub};
use support::{TestEnv, assert_success};

fn json(output: Output) -> serde_json::Value {
    assert_success(&output);
    serde_json::from_slice(&output.stdout).expect("structured output")
}

fn serving(send: Vec<String>) -> Act {
    Act::AcceptAndServe {
        enc: false,
        send,
        history: vec![],
    }
}

#[test]
fn explicit_selection_overrides_environment_and_implicit_selection_rejects_multiple_agents() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let hub = runtime.block_on(FakeHub::start(vec![serving(vec![]), serving(vec![])]));
    let env = TestEnv::new();
    let url = hub.ws_url().to_string();
    for name in ["@first", "@second"] {
        assert_success(
            &env.command(["join", "@general", "--as", name, "--hub", &url])
                .output()
                .unwrap(),
        );
    }
    let list = json(env.command(["agents", "--json"]).output().unwrap());
    assert_eq!(list["agents"].as_array().unwrap().len(), 2);
    let status = json(
        env.command(["daemon", "status", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(status["agents"].as_array().unwrap().len(), 2);
    for command in ["whoami", "recv", "close"] {
        let output = env.command([command]).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("multiple agents"));
    }
    let selected = json(
        env.command_with_handle(["whoami", "--agent", "@first", "--json"], "@second")
            .output()
            .unwrap(),
    );
    assert_eq!(selected["router_agent_id"], "@first");
    assert_eq!(selected["channel"], "@general");
    assert_eq!(selected["connection"]["backend"], "chat");
    assert_eq!(selected["connection"]["socket"], "connected");
    assert_eq!(selected["connection"]["ready"], true);
    assert_eq!(selected["connection"]["encryption"], "none");
    let second = json(
        env.command_with_handle(["whoami", "--json"], "@second")
            .output()
            .unwrap(),
    );
    assert_eq!(second["router_agent_id"], "@second");
    let first_handle = selected["agent_handle"].as_str().unwrap();
    assert_success(
        &env.command(["--agent", first_handle, "close"])
            .output()
            .unwrap(),
    );
    let sole = json(env.command(["whoami", "--json"]).output().unwrap());
    assert_eq!(sole["router_agent_id"], "@second");
    assert_success(&env.command(["daemon", "stop"]).output().unwrap());
}

#[test]
fn follow_outputs_json_lines_and_exits_on_inactivity_without_replaying_consumed_messages() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let messages = vec![
        "(tell @general \"one\" :from @peer)".to_owned(),
        "(tell @general \"two\" :from @peer)".to_owned(),
    ];
    let hub = runtime.block_on(FakeHub::start(vec![serving(messages.clone())]));
    let env = TestEnv::new();
    let url = hub.ws_url().to_string();
    assert_success(
        &env.command([
            "join",
            "@general",
            "--as",
            "@listener",
            "--hub",
            &url,
            "--speak",
            "*",
        ])
        .output()
        .unwrap(),
    );
    let output = env
        .command(["recv", "--follow", "--timeout", "250ms"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let delivered: Vec<&str> = records
        .iter()
        .filter_map(|record| record["message"].as_str())
        .filter(|message| messages.iter().any(|expected| expected == message))
        .collect();
    assert_eq!(
        delivered,
        messages.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert!(
        records
            .iter()
            .all(|record| record["agent_handle"].is_string())
    );
    let empty = env.command(["recv", "--timeout", "20ms"]).output().unwrap();
    assert_eq!(empty.status.code(), Some(10));
    assert!(empty.stdout.is_empty());
    assert_success(&env.command(["daemon", "stop"]).output().unwrap());
}

#[test]
fn config_show_reports_daemon_settings_not_the_callers_environment() {
    let env = TestEnv::new().with_router(
        "wss://user:password@example.org/agent/v1?token=secret#private",
        "secret-auth",
    );
    assert_success(&env.command(["daemon", "start"]).output().unwrap());
    let config = json(
        env.command(["config", "show"])
            .env("CBCL_ROUTER_WS", "wss://different.example/agent/v1")
            .output()
            .unwrap(),
    );
    assert_eq!(config["router"]["ws_url"], "wss://example.org/agent/v1");
    assert_eq!(config["router"]["auth_token"], "<redacted>");
    assert_eq!(config["chat"]["channel"], "@general");
    assert_eq!(config["chat"]["claim_window_ms"], 400);
    let text = config.to_string();
    for secret in ["password", "secret", "private", "different.example"] {
        assert!(!text.contains(secret));
    }
    assert_success(&env.command(["daemon", "stop"]).output().unwrap());
}

#[test]
fn connected_encrypted_chat_reports_not_ready_until_welcome() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let hub = runtime.block_on(FakeHub::start(vec![Act::AcceptAndServe {
        enc: true,
        send: vec![],
        history: vec![],
    }]));
    let env = TestEnv::new();
    let url = hub.ws_url().to_string();
    assert_success(
        &env.command([
            "join",
            "@general",
            "--as",
            "@waiting",
            "--hub",
            &url,
            "--cap",
            "test-invite",
        ])
        .output()
        .unwrap(),
    );
    let selected = json(env.command(["whoami", "--json"]).output().unwrap());
    assert_eq!(selected["connection"]["socket"], "connected");
    assert_eq!(selected["connection"]["encryption"], "mls");
    assert_eq!(selected["connection"]["ready"], false);
    assert_eq!(selected["connection"]["reason"], "awaiting MLS Welcome");
    assert!(
        selected["connection"]["recovery"]
            .as_str()
            .unwrap()
            .contains("whoami")
    );
    assert_success(&env.command(["daemon", "stop"]).output().unwrap());
}

#[test]
fn follow_flushes_live_messages_and_keeps_its_selection_when_another_agent_joins() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (url, senders) = runtime.block_on(streaming_hub());
    let env = TestEnv::new();
    assert_success(
        &env.command([
            "join", "@general", "--as", "@first", "--hub", &url, "--speak", "*",
        ])
        .output()
        .unwrap(),
    );
    let mut follower = env
        .command(["--agent", "@first", "recv", "--follow", "--timeout", "5s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = follower.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let wait_for = |needle: &str| {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let line = rx
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("line flushed before the follow process exits");
            let record: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(
                !record["message"]
                    .as_str()
                    .unwrap()
                    .contains("wrong-agent-marker")
            );
            if record["message"].as_str().unwrap().contains(needle) {
                break;
            }
        }
    };
    senders[0]
        .send("(tell @general \"first-marker\" :from @peer)".to_owned())
        .unwrap();
    wait_for("first-marker");
    assert!(follower.try_wait().unwrap().is_none());
    assert_success(
        &env.command([
            "join", "@general", "--as", "@second", "--hub", &url, "--speak", "*",
        ])
        .output()
        .unwrap(),
    );
    senders[1]
        .send("(tell @general \"wrong-agent-marker\" :from @peer)".to_owned())
        .unwrap();
    senders[0]
        .send("(tell @general \"second-marker\" :from @peer)".to_owned())
        .unwrap();
    wait_for("second-marker");
    follower.kill().unwrap();
    follower.wait().unwrap();
    reader.join().unwrap();
    assert_success(&env.command(["daemon", "stop"]).output().unwrap());
}

// Push peer messages on demand, without relying on self-echoes (which recv suppresses).
async fn streaming_hub() -> (String, Vec<tokio::sync::mpsc::UnboundedSender<String>>) {
    use futures_util::{SinkExt, StreamExt};
    use support::chat_hub::hub_frame;
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/chat/v1", listener.local_addr().unwrap());
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..2 {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        senders.push(tx);
        receivers.push(rx);
    }
    tokio::spawn(async move {
        for mut rx in receivers {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let bootstrap = "(tell @client \"conn-nonce\" :from @cbcl-chat :nonce \"BwcHBwcHBwcHBwcHBwcHBw==\" :hub \"cbcl-chat\")";
                socket
                    .send(Message::Binary(hub_frame(bootstrap).into()))
                    .await
                    .unwrap();
                loop {
                    tokio::select! {
                        frame = rx.recv() => {
                            let Some(frame) = frame else { break; };
                            if socket.send(Message::Binary(hub_frame(&frame).into())).await.is_err() { break; }
                        }
                        incoming = socket.next() => {
                            let Some(Ok(Message::Binary(bytes))) = incoming else { break; };
                            if let Some((_, payload, _)) = hark::signed_frame::decode_frame(&bytes) {
                                if payload.starts_with(b"(hello ") {
                                    socket.send(Message::Binary(hub_frame("(roomcfg @general :enc false)").into())).await.unwrap();
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    (url, senders)
}
