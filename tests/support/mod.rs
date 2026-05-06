#![allow(dead_code)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

pub struct TestEnv {
    _temp_dir: TempDir,
    home: PathBuf,
    xdg_runtime_dir: PathBuf,
    router_ws_url: Option<String>,
    router_auth_token: Option<String>,
    max_messages: Option<usize>,
    max_bytes: Option<usize>,
}

impl TestEnv {
    pub fn new() -> Self {
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

    pub fn with_router(mut self, ws_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        self.router_ws_url = Some(ws_url.into());
        self.router_auth_token = Some(auth_token.into());
        self
    }

    pub fn with_queue_limits(mut self, max_messages: usize, max_bytes: usize) -> Self {
        self.max_messages = Some(max_messages);
        self.max_bytes = Some(max_bytes);
        self
    }

    pub fn command<I, S>(&self, args: I) -> Command
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

    pub fn command_with_handle<I, S>(&self, args: I, handle: &str) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = self.command(args);
        command.env("CBCL_AGENT_HANDLE", handle);
        command
    }

    pub fn runtime_dir(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            self.xdg_runtime_dir.join("hark")
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("hark")
                .join("runtime")
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.home
                .join(".local")
                .join("state")
                .join("hark")
                .join("runtime")
        }
    }

    pub fn config_file(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            self.home.join(".config").join("hark").join("config.toml")
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("hark")
                .join("config.toml")
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.home.join(".config").join("hark").join("config.toml")
        }
    }

    pub fn discovery_file(&self) -> PathBuf {
        self.runtime_dir().join("daemon.json")
    }

    pub fn daemon_token(&self) -> Option<String> {
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

pub fn binary_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_hark"))
}

pub fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_debug(output));
}

pub fn output_debug(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn secure_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("dir permissions should be set");
    }
}

pub fn secure_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("file permissions should be set");
    }
}
