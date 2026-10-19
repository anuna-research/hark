use fs2::FileExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use super::{Result, fail};

pub(super) struct Journal {
    directory: PathBuf,
    _lock: File,
    count: usize,
    limit: usize,
}

pub(super) struct Claim {
    file: File,
}

impl Drop for Journal {
    fn drop(&mut self) {
        // Concurrent process spawning can briefly inherit this open description
        // between fork and CLOEXEC. Release ownership explicitly rather than
        // waiting for that child's inherited descriptor to close.
        let _ = FileExt::unlock(&self._lock);
    }
}

impl Journal {
    pub fn open(directory: &Path, limit: usize) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return fail("journal must be an owned, non-symlink directory with mode 0700");
            }
        }
        #[cfg(not(unix))]
        {
            return fail("experimental shill requires Unix");
        }
        let lock = private_file(&directory.join("worker.lock"), false)?;
        lock.try_lock_exclusive()
            .map_err(|_| anyhow::anyhow!("another shill worker owns this journal"))?;
        let mut count = 0;
        for entry in fs::read_dir(directory)? {
            if entry?.file_name().to_string_lossy().ends_with(".claim") {
                count += 1;
            }
        }
        if count >= limit {
            return fail("journal command quota exhausted; rotate it explicitly while stopped");
        }
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            count,
            limit,
        })
    }

    pub fn claim(
        &mut self,
        room: &str,
        controller: &str,
        thread: &str,
        cid: &str,
    ) -> Result<Claim> {
        if self.count >= self.limit {
            return fail("journal command quota exhausted");
        }
        // One effect per thread, including competing valid branches and across restarts.
        let key = serde_json::to_vec(&(room, controller, thread))?;
        let path = self
            .directory
            .join(format!("{:x}.claim", Sha256::digest(key)));
        let mut file = private_file(&path, true)?;
        self.count += 1;
        writeln!(
            file,
            "{}",
            json!({"status":"claimed","thread":thread,"act":cid})
        )?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(Claim { file })
    }
}

fn private_file(path: &Path, exclusive: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return fail("journal files must be owned regular files with mode 0600");
        }
    }
    Ok(file)
}

impl Claim {
    pub fn complete(mut self, code: i32) -> Result<()> {
        writeln!(
            self.file,
            "{}",
            json!({"status":"completed","exit_code":code})
        )?;
        self.file.sync_all()?;
        Ok(())
    }
}
