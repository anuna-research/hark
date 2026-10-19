#[cfg(target_os = "macos")]
use std::path::Path;
use std::{io, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

use super::{
    Result, fail,
    policy::{Argument, Program},
};

#[derive(Debug)]
pub(super) struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

pub(super) fn require_sandbox() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            return Ok(());
        }
    }
    fail(
        "external programs require macOS sandbox-exec in this experiment; read snapshots work on Unix",
    )
}

#[cfg(target_os = "macos")]
fn profile(program: &Path, scratch: &Path) -> Result<String> {
    fn literal(path: &Path) -> Result<String> {
        let text = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF8 sandbox path"))?;
        // SBPL quoting is deliberately smaller than arbitrary paths. Reject rather than interpolate.
        if text
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return fail("unsafe sandbox path");
        }
        Ok(format!("\"{text}\""))
    }
    let program = literal(program)?;
    let grants = literal(&scratch.join("grants"))?;
    let scratch = literal(scratch)?;
    Ok(format!(
        r#"(version 1)
(deny default)
(allow process-exec (literal {program}))
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read* (literal "/") (literal {program}) (subpath "/System/Library") (subpath "/usr/lib")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS/System/Library")
  (subpath "/private/var/db/dyld") (subpath "/usr/share/zoneinfo")
  (subpath {scratch}) (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random"))
(allow file-write* (require-all (subpath {scratch}) (require-not (subpath {grants}))) (literal "/dev/null"))
"#
    ))
}

pub(super) async fn run(program: &Program) -> Result<Output> {
    if !program.parameters.is_empty() {
        return fail("program requires bound parameters");
    }
    invoke(program, &[]).await
}

pub(super) async fn invoke(program: &Program, arguments: &[Argument]) -> Result<Output> {
    require_sandbox()?;
    let scratch = tempfile::Builder::new()
        .prefix("hark-shill-child-")
        .tempdir()?;
    let scratch_path = scratch.path().canonicalize()?;
    verify_pinned_executable(program)?;
    let mut words = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        match argument {
            Argument::Words(values) => words.extend(values.iter().map(std::ffi::OsString::from)),
            Argument::Directory(snapshot) => {
                let relative = PathBuf::from(format!("grants/arg-{index}"));
                let root = scratch_path.join(&relative);
                std::fs::create_dir_all(&root)?;
                for entry in &snapshot.entries {
                    let path = root.join(&entry.path);
                    if let Some(bytes) = &entry.bytes {
                        std::fs::write(path, bytes)?;
                    } else {
                        std::fs::create_dir(&path)?;
                    }
                }
                words.push(relative.into_os_string());
            }
        }
    }
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &profile(&program.executable, &scratch_path)?, "--"]);
        command.arg(&program.executable);
        command
    };
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new(&program.executable); // unreachable after require_sandbox
    command
        .args(&program.arguments)
        .args(words)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("HOME", &scratch_path)
        .env("TMPDIR", &scratch_path)
        .current_dir(&scratch_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    unsafe {
        let cpu = program.timeout_ms.div_ceil(1000) + 1;
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            fn limit(resource: libc::c_int, value: u64) -> io::Result<()> {
                let bound = libc::rlimit {
                    rlim_cur: value as libc::rlim_t,
                    rlim_max: value as libc::rlim_t,
                };
                if unsafe { libc::setrlimit(resource as _, &bound) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
            limit(libc::RLIMIT_CPU as _, cpu)?;
            // Darwin rejects finite DATA limits here and AS aliases advisory RSS.
            // A parent-side footprint watcher below handles the experimental memory budget.
            limit(libc::RLIMIT_FSIZE as _, 65536)?;
            limit(libc::RLIMIT_NOFILE as _, 64)?;
            limit(libc::RLIMIT_NPROC as _, 32)?;
            limit(libc::RLIMIT_CORE as _, 0)?;
            // This timer survives exec and provides a backstop if the Hark parent is killed.
            // The parent watchdog remains the precise wall-clock/process-group enforcer.
            libc::alarm(cpu.saturating_add(1) as libc::c_uint);
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let group = ProcessGroup(
        child
            .id()
            .ok_or_else(|| anyhow::anyhow!("missing child PID"))?,
    );
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stderr"))?;
    let deadline = Duration::from_millis(program.timeout_ms);
    // The same deadline covers child exit AND pipe EOF (including descendants holding pipes open).
    let execution = async {
        let (stdout, stderr, status) = tokio::try_join!(
            bounded(stdout, program.max_output_bytes),
            bounded(stderr, program.max_output_bytes),
            child.wait()
        )?;
        Ok::<_, io::Error>((stdout, stderr, status))
    };
    #[cfg(target_os = "macos")]
    let execution = async {
        tokio::select! {
            result = execution => result,
            result = memory_budget(group.0, program.memory_mb * 1024 * 1024) => {
                result?;
                Err(io::Error::other("memory watcher stopped unexpectedly"))
            }
        }
    };
    let result = tokio::time::timeout(deadline, execution).await;
    // Always kill surviving descendants, including after a normally exiting parent.
    drop(group);
    let _ = child.wait().await;
    let (stdout, stderr, status) =
        result.map_err(|_| anyhow::anyhow!("process wall-clock limit exceeded"))??;
    if stdout.len() + stderr.len() > program.max_output_bytes {
        return fail("combined output limit exceeded");
    }
    Ok(Output {
        stdout: String::from_utf8(stdout)?,
        stderr: String::from_utf8(stderr)?,
        code: status.code().unwrap_or(128),
    })
}

#[cfg(unix)]
fn verify_pinned_executable(program: &Program) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let pinned = program
        .executable_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("program executable was not pinned at policy load"))?
        .metadata()?;
    let current = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&program.executable)?
        .metadata()?;
    if pinned.dev() != current.dev()
        || pinned.ino() != current.ino()
        || pinned.len() != current.len()
        || pinned.mtime() != current.mtime()
        || pinned.mtime_nsec() != current.mtime_nsec()
    {
        return fail("program executable changed after policy load");
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_pinned_executable(_program: &Program) -> Result<()> {
    fail("experimental shill requires Unix")
}

#[cfg(target_os = "macos")]
async fn memory_budget(pid: u32, limit: u64) -> io::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        let result = unsafe {
            libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast())
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        if unsafe { info.assume_init() }.ri_phys_footprint > limit {
            return Err(io::Error::other("process memory budget exceeded"));
        }
    }
}

async fn bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            return Ok(output);
        }
        if output.len() + length > limit {
            return Err(io::Error::other("process output limit exceeded"));
        }
        output.extend_from_slice(&buffer[..length]);
    }
}

struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // Own process group, created in pre_exec. This guard also runs on cancellation.
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}
