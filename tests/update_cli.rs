use std::{fs, process::Command};

use axum::{Router, extract::Path, routing::get};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn update_installs_without_a_daemon_and_explicit_directory_overrides_environment() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let binary = b"verified release fixture".to_vec();
    let fixture = binary.clone();
    let digest = format!("{:x}", Sha256::digest(&binary));
    let (base, server) = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let manifest =
            serde_json::json!({"version":"9.9.0", "download_url":format!("{base}/v9.9.0")})
                .to_string();
        let app = Router::new()
            .route("/version.json", get(move || async move { manifest }))
            .route(
                "/v9.9.0/{file}",
                get(move |Path(file): Path<String>| {
                    let binary = fixture.clone();
                    let digest = digest.clone();
                    async move {
                        if file.ends_with(".sha256") {
                            format!("{digest}  {}\n", file.trim_end_matches(".sha256")).into_bytes()
                        } else {
                            binary
                        }
                    }
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, task)
    });
    let install = TempDir::new().unwrap();
    let overridden = TempDir::new().unwrap();
    let update = || {
        Command::new(env!("CARGO_BIN_EXE_hark"))
            .args(["update", "--install-dir"])
            .arg(install.path())
            .env("HARK_BASE_URL", &base)
            .env("HARK_INSTALL_DIR", overridden.path())
            .env(
                "CBCL_AGENT_HANDLE",
                "invalid-selection-is-irrelevant-to-updates",
            )
            .output()
            .unwrap()
    };
    let output = update();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Installed hark 9.9.0"));
    assert_eq!(fs::read(install.path().join("hark")).unwrap(), binary);
    assert!(!overridden.path().join("hark").exists());
    let output = update();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("already installed"));
    server.abort();
}
