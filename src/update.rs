//! Install the latest published release using the installer's artifact layout.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{Client, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::errors::{AppError, AppResult};

const DEFAULT_BASE_URL: &str = "https://files.anuna.io/hark";
const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    version: String,
    download_url: String,
}

pub struct UpdateResult {
    pub version: String,
    pub path: PathBuf,
    pub changed: bool,
}

pub async fn install_latest(install_dir: Option<PathBuf>) -> AppResult<UpdateResult> {
    let directory = install_dir
        .or_else(|| std::env::var_os("HARK_INSTALL_DIR").map(PathBuf::from))
        .or_else(|| directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".local/bin")))
        .ok_or_else(|| {
            AppError::Usage("cannot resolve install directory; use --install-dir".into())
        })?;
    let base = std::env::var("HARK_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
    install_from(
        &base,
        &directory,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
    .await
}

async fn install_from(
    base: &str,
    directory: &Path,
    os: &str,
    arch: &str,
) -> AppResult<UpdateResult> {
    let artifact = artifact_name(os, arch)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| failure("create download client", error))?;
    let base = directory_url(base)?;
    let manifest_url = base
        .join("version.json")
        .map_err(|error| failure("resolve release metadata", error))?;
    let metadata = download(&client, manifest_url, 64 * 1024).await?;
    let release: Release = serde_json::from_slice(&metadata)
        .map_err(|error| failure("decode release metadata", error))?;
    if release.version.is_empty()
        || !release
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
    {
        return Err(AppError::Internal(
            "update: release metadata has an invalid version".into(),
        ));
    }
    let release_url = directory_url(&release.download_url)?;
    let binary_url = release_url
        .join(&artifact)
        .map_err(|error| failure("resolve binary URL", error))?;
    let checksum_url = release_url
        .join(&format!("{artifact}.sha256"))
        .map_err(|error| failure("resolve checksum URL", error))?;
    let checksum = download(&client, checksum_url, 4096).await?;
    let expected = parse_checksum(&checksum)?;
    let target = directory.join("hark");
    // Compare bytes rather than the invoking CLI version: the install directory
    // may hold an older binary, and development builds may share a release version.
    if let Ok(existing) = fs::read(&target) {
        if hex_digest(&existing) == expected && executable(&target) {
            return Ok(UpdateResult {
                version: release.version,
                path: target,
                changed: false,
            });
        }
    }
    let binary = download(&client, binary_url, MAX_BINARY_BYTES).await?;
    if hex_digest(&binary) != expected {
        return Err(AppError::Internal(
            "update: SHA-256 checksum mismatch; installed binary was not changed".into(),
        ));
    }
    install_verified(&binary, directory, &target)?;
    Ok(UpdateResult {
        version: release.version,
        path: target,
        changed: true,
    })
}

fn artifact_name(os: &str, arch: &str) -> AppResult<String> {
    let os = match os {
        "macos" => "darwin",
        "linux" => "linux",
        _ => {
            return Err(AppError::Usage(format!(
                "update: unsupported operating system {os}; build from source"
            )));
        }
    };
    let arch = match arch {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => {
            return Err(AppError::Usage(format!(
                "update: unsupported architecture {arch}; build from source"
            )));
        }
    };
    Ok(format!("hark-{os}-{arch}"))
}

fn directory_url(raw: &str) -> AppResult<Url> {
    let url = Url::parse(&format!("{}/", raw.trim_end_matches('/')))
        .map_err(|_| AppError::Usage("update: invalid release URL".into()))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::Usage("update: release URLs must use HTTPS without credentials, query parameters, or fragments (loopback HTTP is allowed for testing)".into()));
    }
    Ok(url)
}

async fn download(client: &Client, url: Url, limit: usize) -> AppResult<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| failure("download release file", error))?
        .error_for_status()
        .map_err(|error| failure("download release file", error))?;
    if !response.status().is_success() {
        return Err(AppError::Internal(format!(
            "update: unexpected download status {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(AppError::Internal(
            "update: release file exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| failure("read release file", error))?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(AppError::Internal(
                "update: release file exceeds size limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(AppError::Internal("update: release file is empty".into()));
    }
    Ok(bytes)
}

fn parse_checksum(bytes: &[u8]) -> AppResult<String> {
    let digest = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.split_whitespace().next())
        .unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Internal(
            "update: missing or malformed SHA-256 checksum; installed binary was not changed"
                .into(),
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn install_verified(bytes: &[u8], directory: &Path, target: &Path) -> AppResult<()> {
    fs::create_dir_all(directory).map_err(|error| {
        failure(
            "create install directory (use --install-dir for a writable location)",
            error,
        )
    })?;
    let path = directory.join(format!(
        ".hark-update-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| failure("stage downloaded binary", error))?;
    let _staged = StagedFile(path.clone());
    file.write_all(bytes)
        .map_err(|error| failure("write downloaded binary", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| failure("make binary executable", error))?;
    }
    file.sync_all()
        .map_err(|error| failure("sync downloaded binary", error))?;
    drop(file);
    fs::rename(&path, target).map_err(|error| {
        failure(
            "replace installed binary (use --install-dir for a writable location)",
            error,
        )
    })?;
    Ok(())
}

struct StagedFile(PathBuf);
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn failure(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Internal(format!("update: failed to {context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::get};
    use tempfile::TempDir;

    async fn release_server(
        binary: Vec<u8>,
        checksum: Option<String>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let manifest =
            serde_json::json!({"version":"9.9.0", "download_url":format!("{base}/v9.9.0")})
                .to_string();
        let app = Router::new()
            .route("/version.json", get(move || async move { manifest }))
            .route("/v9.9.0/hark-linux-x64", get(move || async move { binary }))
            .route(
                "/v9.9.0/hark-linux-x64.sha256",
                get(move || async move {
                    match checksum {
                        Some(value) => (StatusCode::OK, value),
                        None => (StatusCode::NOT_FOUND, String::new()),
                    }
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, task)
    }

    #[tokio::test]
    async fn installs_verified_release_and_detects_already_installed_bytes() {
        let bytes = b"published binary".to_vec();
        let checksum = format!("{}  hark-linux-x64\n", hex_digest(&bytes));
        let (base, server) = release_server(bytes.clone(), Some(checksum)).await;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("hark");
        fs::write(&target, "previous binary").unwrap();
        let result = install_from(&base, dir.path(), "linux", "x86_64")
            .await
            .unwrap();
        assert!(result.changed);
        assert_eq!(result.version, "9.9.0");
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert!(executable(&target));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        let result = install_from(&base, dir.path(), "linux", "x86_64")
            .await
            .unwrap();
        assert!(!result.changed);
        server.abort();
    }

    #[tokio::test]
    async fn missing_malformed_and_mismatched_checksums_preserve_existing_installation() {
        for checksum in [None, Some("invalid".into()), Some("0".repeat(64))] {
            let (base, server) = release_server(b"replacement".to_vec(), checksum).await;
            let dir = TempDir::new().unwrap();
            let target = dir.path().join("hark");
            fs::write(&target, "previous binary").unwrap();
            assert!(
                install_from(&base, dir.path(), "linux", "x86_64")
                    .await
                    .is_err()
            );
            assert_eq!(fs::read(&target).unwrap(), b"previous binary");
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
            server.abort();
        }
    }

    #[tokio::test]
    async fn failed_replacement_removes_staged_file() {
        let bytes = b"replacement".to_vec();
        let (base, server) = release_server(bytes.clone(), Some(hex_digest(&bytes))).await;
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("hark")).unwrap();
        assert!(
            install_from(&base, dir.path(), "linux", "x86_64")
                .await
                .is_err()
        );
        assert!(dir.path().join("hark").is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        server.abort();
    }

    #[test]
    fn resolves_supported_platforms_and_rejects_insecure_release_urls() {
        for (os, arch, artifact) in [
            ("macos", "aarch64", "hark-darwin-arm64"),
            ("macos", "x86_64", "hark-darwin-x64"),
            ("linux", "aarch64", "hark-linux-arm64"),
            ("linux", "x86_64", "hark-linux-x64"),
        ] {
            assert_eq!(artifact_name(os, arch).unwrap(), artifact);
        }
        assert!(artifact_name("windows", "x86_64").is_err());
        assert!(artifact_name("linux", "arm").is_err());
        assert!(directory_url("http://example.org/hark").is_err());
        assert!(directory_url("https://user:password@example.org/hark").is_err());
        assert!(directory_url("http://127.0.0.1:8080/hark").is_ok());
    }
}
