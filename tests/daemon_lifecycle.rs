use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use cbcl_router_client::{constants::LOCAL_API_VERSION, daemon::DiscoveryRecord};
use tempfile::TempDir;
use time::OffsetDateTime;

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

struct TestEnv {
    _temp_dir: TempDir,
    home: PathBuf,
    xdg_runtime_dir: PathBuf,
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
            .env_remove("CBCL_ROUTER_WS")
            .env_remove("CBCL_ROUTER_AUTH_TOKEN")
            .env_remove("CBCL_DAEMON_BIND")
            .env_remove("CBCL_AGENT_ID_PREFIX")
            .env_remove("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE")
            .env_remove("CBCL_DAEMON_MAX_BYTES_PER_HANDLE")
            .env_remove("CBCL_DAEMON_OVERFLOW_POLICY");
        command
    }

    fn runtime_dir(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            self.xdg_runtime_dir.join("cbcl-router-client")
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("cbcl-router-client")
                .join("runtime")
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.home
                .join(".local")
                .join("state")
                .join("cbcl-router-client")
                .join("runtime")
        }
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

fn secure_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("dir permissions should be set");
    }
}

fn secure_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("file permissions should be set");
    }
}
