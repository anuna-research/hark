#[cfg(target_os = "macos")]
use super::policy::Program;
use super::{
    kernel::{Authority, Decision, Effect},
    policy::{Manifest, Policy},
    *,
};
use crate::{
    local_api::RecvResponse,
    object_transport::{AttestedBy, ObjectRecord},
};
use serde_json::{Value, json};
#[cfg(target_os = "macos")]
use std::time::Instant;
use std::{fs, time::Duration};

fn manifest() -> Manifest {
    serde_json::from_value(json!({"version":1,"controller":"@controller","worker":"@worker",
        "room":"@test","hub":"wss://chat.anuna.io/chat/v1","provenance":"mls",
        "lifetime_seconds":900,"max_commands":100,"min_interval_ms":100,"resources":{},"programs":{}})).unwrap()
}

fn fixture() -> (tempfile::TempDir, Authority) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("README.md"), "safe snapshot").unwrap();
    let mut config = manifest();
    config.resources.insert("readme".into(), "README.md".into());
    let authority = Authority::new(Policy::prepare(config, dir.path()).unwrap()).unwrap();
    (dir, authority)
}

fn record(message: String) -> RecvResponse {
    RecvResponse {
        agent_handle: "test-agent".into(),
        message,
        record: Some(ObjectRecord {
            room: "@test".into(),
            signer: "@controller".into(),
            attested_by: AttestedBy::Mls,
            own: false,
            replayed: false,
        }),
    }
}

fn opener(authority: &Authority, thread: &str) -> RecvResponse {
    record(format!(
        "(lang {} (open @test :session {} :caused-by begin :thread {} :from @controller))",
        authority.dialect.name,
        json!(authority.session),
        json!(thread)
    ))
}

fn entry(record: &RecvResponse) -> String {
    format!("(\"@controller\" {})", record.message)
}

fn request(
    authority: &Authority,
    open: &RecvResponse,
    thread: &str,
    verb: &str,
    fields: Value,
) -> RecvResponse {
    record(
        authority
            .dialect
            .intend(thread, &[entry(open)], "@controller", verb, &fields)
            .unwrap(),
    )
}

#[test]
fn admitted_read_materializes_an_immutable_snapshot() {
    let (dir, mut authority) = fixture();
    let thread = "shill-read";
    let open = opener(&authority, thread);
    let read = request(
        &authority,
        &open,
        thread,
        "read",
        json!({"resource":"readme"}),
    );
    assert!(matches!(authority.receive(open).unwrap(), Decision::Opened));
    fs::write(dir.path().join("README.md"), "changed after startup").unwrap();
    let Decision::Valid(capability) = authority.receive(read).unwrap() else {
        panic!("expected authority");
    };
    let Effect::Read(snapshot) = capability.effect else {
        panic!("expected read");
    };
    assert_eq!(&*snapshot, "safe snapshot");
}

#[test]
fn missing_ancestry_is_unknown_then_retries_when_opener_arrives() {
    let (_dir, mut authority) = fixture();
    let open = opener(&authority, "shill-reorder");
    let read = request(
        &authority,
        &open,
        "shill-reorder",
        "read",
        json!({"resource":"readme"}),
    );
    assert!(matches!(
        authority.receive(read).unwrap(),
        Decision::Unknown
    ));
    assert_eq!(authority.pending.len(), 1);
    assert!(matches!(authority.receive(open).unwrap(), Decision::Opened));
    let pending = std::mem::take(&mut authority.pending)
        .into_values()
        .next()
        .unwrap();
    assert!(matches!(
        authority.receive(pending).unwrap(),
        Decision::Valid(_)
    ));
}

#[test]
fn transport_sender_room_provenance_and_replay_are_checked_before_parsing() {
    let (_dir, mut authority) = fixture();
    for variant in 0..5 {
        let mut envelope = record("not even CBCL".into());
        let transport = envelope.record.as_mut().unwrap();
        match variant {
            0 => transport.signer = "@attacker".into(),
            1 => transport.room = "@other".into(),
            2 => transport.attested_by = AttestedBy::Hub,
            3 => transport.replayed = true,
            _ => transport.own = true,
        }
        assert!(matches!(
            authority.receive(envelope).unwrap(),
            Decision::Ignored
        ));
    }
    let mut forged = opener(&authority, "shill-forged");
    forged.message = forged
        .message
        .replace(":from @controller", ":from @attacker");
    assert!(authority.receive(forged).is_err());
    let wrong_recipient = opener(&authority, "shill-wrong-to")
        .message
        .replace("open @test", "open @other");
    assert!(authority.receive(record(wrong_recipient)).is_err());
}

#[test]
fn old_sessions_wrong_ids_and_extra_fields_cannot_authorize_effects() {
    let (_dir, mut authority) = fixture();
    let mut old = opener(&authority, "shill-old");
    old.message = old.message.replace(&authority.session, "old-session");
    assert!(authority.receive(old).is_err());
    let open = opener(&authority, "shill-invalid");
    authority.receive(open.clone()).unwrap();
    for resource in [
        "../../secret",
        "/etc/passwd",
        "$(touch OWNED)",
        "not-granted",
    ] {
        let command = request(
            &authority,
            &open,
            "shill-invalid",
            "read",
            json!({"resource":resource}),
        );
        assert!(authority.receive(command).is_err());
    }
    assert!(
        authority
            .dialect
            .intend(
                "shill-invalid",
                &[entry(&open)],
                "@controller",
                "read",
                &json!({"resource":"readme","path":"/etc/passwd"})
            )
            .is_err()
    );
    assert!(
        authority
            .dialect
            .intend(
                "shill-invalid",
                &[entry(&open)],
                "@controller",
                "exec",
                &json!({"command":"whoami"})
            )
            .is_err()
    );
}

#[test]
fn output_and_done_are_not_controller_effects() {
    let (_dir, mut authority) = fixture();
    let open = opener(&authority, "shill-output");
    authority.receive(open.clone()).unwrap();
    let read = request(
        &authority,
        &open,
        "shill-output",
        "read",
        json!({"resource":"readme"}),
    );
    let records = [entry(&open), entry(&read)];
    let output = authority
        .dialect
        .intend(
            "shill-output",
            &records,
            "@controller",
            "output",
            &json!({"seq":1,"data":"forged"}),
        )
        .unwrap();
    assert!(authority.receive(record(output)).is_err());
}

#[test]
fn session_and_pending_storage_are_bounded() {
    let (_dir, mut authority) = fixture();
    for i in 0..32 {
        let thread = format!("shill-pending-{i}");
        let open = opener(&authority, &thread);
        let read = request(
            &authority,
            &open,
            &thread,
            "read",
            json!({"resource":"readme"}),
        );
        assert!(matches!(
            authority.receive(read).unwrap(),
            Decision::Unknown
        ));
    }
    let open = opener(&authority, "shill-overflow");
    let read = request(
        &authority,
        &open,
        "shill-overflow",
        "read",
        json!({"resource":"readme"}),
    );
    assert!(authority.receive(read).is_err());
    assert_eq!(authority.pending.len(), 32);
}

#[test]
fn journal_locks_and_claims_survive_restart_and_cover_competing_branches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let mut journal = Journal::open(&path, 2).unwrap();
    assert!(Journal::open(&path, 2).is_err());
    let claim = journal
        .claim("@test", "@controller", "shill-one", "sha256-first")
        .unwrap();
    drop(claim); // crash/uncertain; must not execute again
    assert!(
        journal
            .claim("@test", "@controller", "shill-one", "sha256-branch")
            .is_err()
    );
    drop(journal);
    let mut journal = Journal::open(&path, 2).unwrap();
    assert!(
        journal
            .claim("@test", "@controller", "shill-one", "sha256-first")
            .is_err()
    );
    journal
        .claim("@test", "@controller", "shill-two", "sha256-second")
        .unwrap()
        .complete(0)
        .unwrap();
    assert!(
        journal
            .claim("@test", "@controller", "shill-three", "sha256-third")
            .is_err()
    );
    drop(journal);
    assert!(Journal::open(&path, 2).is_err());
}

#[test]
fn expired_sessions_and_command_rate_limits_fail_closed() {
    let (_dir, mut authority) = fixture();
    let open = opener(&authority, "shill-rate");
    let read = request(
        &authority,
        &open,
        "shill-rate",
        "read",
        json!({"resource":"readme"}),
    );
    authority.receive(open).unwrap();
    assert!(matches!(
        authority.receive(read.clone()).unwrap(),
        Decision::Valid(_)
    ));
    assert!(authority.receive(read.clone()).is_err());
    std::thread::sleep(Duration::from_millis(105));
    assert!(matches!(
        authority.receive(read).unwrap(),
        Decision::Valid(_)
    )); // durable claim rejects it
    authority.policy.manifest.max_commands = 1;
    let open = opener(&authority, "shill-quota");
    assert!(authority.receive(open).is_err());
    authority.expire();
    assert!(authority.expired());
    let open = opener(&authority, "shill-expired");
    assert!(authority.receive(open).is_err());
}

#[test]
fn chunking_preserves_unicode_and_bounds() {
    let source = "🦜".repeat(8192);
    let chunks = chunks(&source);
    assert!(chunks.len() <= 20);
    assert!(chunks.iter().all(|chunk| chunk.len() <= 1800));
    assert_eq!(chunks.concat(), source);
    assert_eq!(super::chunks(""), vec![""]);
}

#[test]
fn manifest_rejects_unknown_authority_and_oversized_resources() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("big"), vec![b'x'; 32769]).unwrap();
    let mut policy = manifest();
    policy.resources.insert("big".into(), "big".into());
    assert!(Policy::prepare(policy, dir.path()).is_err());
    let mut value = serde_json::to_value(json!({"version":1,"ambient":true})).unwrap();
    assert!(serde_json::from_value::<Manifest>(value.take()).is_err());
}

#[cfg(target_os = "macos")]
fn program(file: &str, args: &[&str]) -> Program {
    Program {
        executable: PathBuf::from(file),
        arguments: args.iter().map(|s| s.to_string()).collect(),
        parameters: Vec::new(),
        timeout_ms: 1000,
        max_output_bytes: 4096,
        memory_mb: 256,
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_runs_a_fixed_program_without_inheriting_environment() {
    let result = process::run(&program("/usr/bin/env", &[])).await.unwrap();
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert!(result.stdout.contains("HOME=/private/"));
    let keys = result
        .stdout
        .lines()
        .map(|line| line.split('=').next().unwrap())
        .collect::<Vec<_>>();
    assert!(
        keys.iter()
            .all(|key| ["HOME", "TMPDIR", "PATH", "LANG"].contains(key)),
        "{}",
        result.stdout
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_denies_an_ungranted_read_and_write() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    fs::write(&secret, "secret that must stay on host").unwrap();
    let result = process::run(&program("/bin/cat", &[secret.to_str().unwrap()]))
        .await
        .unwrap();
    assert_ne!(result.code, 0);
    assert!(!result.stdout.contains("secret that must stay on host"));
    // /System/Volumes/Data is a second spelling of writable host files. Never
    // grant /System recursively merely to make dyld happy.
    let canonical = secret.canonicalize().unwrap();
    let alias = PathBuf::from("/System/Volumes/Data").join(canonical.strip_prefix("/").unwrap());
    if alias.exists() {
        let result = process::run(&program("/bin/cat", &[alias.to_str().unwrap()]))
            .await
            .unwrap();
        assert_ne!(result.code, 0);
        assert!(!result.stdout.contains("secret that must stay on host"));
    }
    let target = dir.path().join("must-not-exist");
    let result = process::run(&program("/usr/bin/touch", &[target.to_str().unwrap()]))
        .await
        .unwrap();
    assert_ne!(result.code, 0);
    assert!(!target.exists());
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn watchdog_kills_a_program_that_ignores_term_and_bounds_output() {
    let mut spinning = program(
        "/bin/bash",
        &[
            "--noprofile",
            "--norc",
            "-c",
            "trap '' TERM; while :; do :; done",
        ],
    );
    spinning.timeout_ms = 150;
    let started = Instant::now();
    assert!(
        process::run(&spinning)
            .await
            .unwrap_err()
            .to_string()
            .contains("wall-clock")
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let mut noisy = program("/usr/bin/yes", &[]);
    noisy.max_output_bytes = 256;
    assert!(
        process::run(&noisy)
            .await
            .unwrap_err()
            .to_string()
            .contains("output limit")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_probe() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.iter().any(|arg| arg == "shill-probe-network") {
        let error = std::net::TcpListener::bind("127.0.0.1:0").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        let error = std::process::Command::new("/bin/echo")
            .arg("must not run")
            .status()
            .unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::EPERM | libc::EAGAIN)
        ));
        println!("NETWORK_AND_SPAWN_DENIED");
    }
    if arguments.iter().any(|arg| arg == "shill-probe-memory") {
        let bytes = vec![1u8; 128 * 1024 * 1024];
        std::hint::black_box(&bytes);
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_denies_network_and_spawning_and_monitors_memory() {
    let executable = std::env::current_exe().unwrap();
    let mut probe = program(
        executable.to_str().unwrap(),
        &[
            "--exact",
            "shill::tests::sandbox_probe",
            "--nocapture",
            "--test-threads=1",
            "--skip",
            "shill-probe-network",
        ],
    );
    let result = process::run(&probe).await.unwrap();
    assert_eq!(result.code, 0, "{} {}", result.stdout, result.stderr);
    assert!(result.stdout.contains("NETWORK_AND_SPAWN_DENIED"));
    probe.arguments.pop();
    probe.arguments.push("shill-probe-memory".into());
    probe.memory_mb = 32;
    probe.timeout_ms = 2000;
    assert!(
        process::run(&probe)
            .await
            .unwrap_err()
            .to_string()
            .contains("memory budget")
    );
}

#[tokio::test]
async fn admitted_request_executes_once_and_returns_native_admissible_output() {
    use crate::{daemon::DiscoveryRecord, local_api::SendResponse};
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::{Arc, Mutex};
    let (_dir, mut authority) = fixture();
    let open = opener(&authority, "shill-end-to-end");
    let read = request(
        &authority,
        &open,
        "shill-end-to-end",
        "read",
        json!({"resource":"readme"}),
    );
    authority.receive(open.clone()).unwrap();
    let Decision::Valid(capability) = authority.receive(read.clone()).unwrap() else {
        panic!("expected capability");
    };
    let delivered = Arc::new(Mutex::new(Vec::<String>::new()));
    async fn collect(
        State(messages): State<Arc<Mutex<Vec<String>>>>,
        Json(request): Json<SendRequest>,
    ) -> Json<SendResponse> {
        messages.lock().unwrap().push(request.message);
        Json(SendResponse {
            ok: true,
            agent_handle: "test-agent".into(),
        })
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = LocalApiClient::from_discovery(&DiscoveryRecord {
        pid: std::process::id(),
        addr: listener.local_addr().unwrap(),
        token: "test-token".into(),
        started_at: time::OffsetDateTime::now_utc(),
        version: env!("CARGO_PKG_VERSION").into(),
        api_version: crate::constants::LOCAL_API_VERSION,
    })
    .unwrap();
    let router = Router::new()
        .route("/v1/agents/{handle}/send", post(collect))
        .with_state(delivered.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let journal_dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&journal_dir.path().join("journal"), 10).unwrap();
    let handle = AgentHandle::generate();
    perform(&authority, &mut journal, &client, &handle, capability)
        .await
        .unwrap();
    let messages = delivered.lock().unwrap().clone();
    assert_eq!(messages.len(), 2);
    let records = [entry(&open), entry(&read)];
    for message in &messages {
        let frame = format!(
            "(admit {} \"shill-end-to-end\" (acts {}) (\"@worker\" {}))",
            authority.dialect.cbcl,
            records.join(" "),
            message
        );
        let verdict: Value =
            serde_json::from_str(&kernel::native(cbcl_wasm::admit_bytes, &frame).unwrap()).unwrap();
        assert_eq!(verdict["verdict"], "accepted");
    }
    assert!(messages[0].contains("safe snapshot"));
    assert!(messages[1].contains("(done "));
    tokio::time::sleep(Duration::from_millis(105)).await;
    let Decision::Valid(duplicate) = authority.receive(read).unwrap() else {
        panic!("expected admission, before use gate");
    };
    assert!(
        perform(&authority, &mut journal, &client, &handle, duplicate)
            .await
            .is_err()
    );
    assert_eq!(delivered.lock().unwrap().len(), 2);
    server.abort();
}

#[cfg(target_os = "macos")]
fn parameter_fixture() -> (tempfile::TempDir, Authority) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("docs")).unwrap();
    fs::write(dir.path().join("docs/guide.txt"), "original grant").unwrap();
    let mut config = manifest();
    config.directories.insert("docs".into(), "docs".into());
    let mut list = program("/bin/ls", &[]);
    list.parameters = serde_json::from_value(json!([
        {"kind":"enum","values":{"short":["-1"],"long":["-l"]}},
        {"kind":"directory","allow":["docs"]}
    ]))
    .unwrap();
    config.programs.insert("list".into(), list);
    let authority = Authority::new(Policy::prepare(config, dir.path()).unwrap()).unwrap();
    (dir, authority)
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn typed_directory_arguments_run_ls_against_a_snapshot() {
    let (dir, mut authority) = parameter_fixture();
    let open = opener(&authority, "shill-list");
    let invoke = request(
        &authority,
        &open,
        "shill-list",
        "invoke",
        json!({"program":"list","arguments":["short","docs"]}),
    );
    authority.receive(open).unwrap();
    let Decision::Valid(capability) = authority.receive(invoke).unwrap() else {
        panic!("expected capability");
    };
    let Effect::Invoke(program, arguments) = capability.effect else {
        panic!("expected invocation");
    };
    // Changing the host directory after startup must not redirect the capability.
    fs::rename(dir.path().join("docs"), dir.path().join("old-docs")).unwrap();
    fs::create_dir(dir.path().join("docs")).unwrap();
    fs::write(
        dir.path().join("docs/ungranted-secret.txt"),
        "not in the snapshot",
    )
    .unwrap();
    let output = process::invoke(&program, &arguments).await.unwrap();
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert!(output.stdout.contains("guide.txt"));
    assert!(!output.stdout.contains("ungranted-secret"));
    // The same materialized grant must be read-only even to a configured native writer.
    let writer = super::tests::program("/usr/bin/touch", &[]);
    let directory = arguments
        .into_iter()
        .filter(|argument| matches!(argument, policy::Argument::Directory(_)))
        .collect::<Vec<_>>();
    let output = process::invoke(&writer, &directory).await.unwrap();
    assert_ne!(
        output.code, 0,
        "a directory capability must not grant writes"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn caller_arguments_cannot_become_flags_paths_or_extra_argv() {
    let (_dir, mut authority) = parameter_fixture();
    let open = opener(&authority, "shill-bad-arguments");
    authority.receive(open.clone()).unwrap();
    for arguments in [
        json!(["-R", "docs"]),
        json!(["short", "/etc"]),
        json!(["short", "../../"]),
        json!(["short", "$(touch OWNED)"]),
        json!(["short", "docs", "extra"]),
        json!(["short"]),
        json!([42, "docs"]),
    ] {
        let invoke = request(
            &authority,
            &open,
            "shill-bad-arguments",
            "invoke",
            json!({"program":"list","arguments":arguments}),
        );
        assert!(authority.receive(invoke).is_err());
    }
    let fixed = request(
        &authority,
        &open,
        "shill-bad-arguments",
        "run",
        json!({"program":"list"}),
    );
    assert!(authority.receive(fixed).is_err());
}

#[cfg(unix)]
#[test]
fn directory_snapshot_rejects_symlinks_and_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("docs")).unwrap();
    fs::write(dir.path().join("secret"), "not granted").unwrap();
    std::os::unix::fs::symlink(dir.path().join("secret"), dir.path().join("docs/link")).unwrap();
    let mut config = manifest();
    config.directories.insert("docs".into(), "docs".into());
    assert!(Policy::prepare(config, dir.path()).is_err());
    fs::remove_file(dir.path().join("docs/link")).unwrap();
    fs::write(dir.path().join("docs/big"), vec![0u8; 32769]).unwrap();
    let mut config = manifest();
    config.directories.insert("docs".into(), "docs".into());
    assert!(Policy::prepare(config, dir.path()).is_err());
}
