use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;

use super::{Result, fail};
use crate::object_transport::AttestedBy;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub version: u32,
    pub controller: String,
    pub worker: String,
    pub room: String,
    pub hub: String,
    pub provenance: AttestedBy,
    pub lifetime_seconds: u64,
    pub max_commands: usize,
    pub min_interval_ms: u64,
    #[serde(default)]
    pub resources: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub programs: BTreeMap<String, Program>,
    #[serde(default)]
    pub directories: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Program {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub memory_mb: u64,
}

/// Positional parameters are schema-selected argv fragments, never shell source.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum Parameter {
    Enum {
        values: BTreeMap<String, Vec<String>>,
    },
    Directory {
        allow: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub(super) enum Argument {
    Words(Vec<String>),
    Directory(Arc<DirectorySnapshot>),
}

#[derive(Debug)]
pub(super) struct DirectorySnapshot {
    pub entries: Vec<SnapshotEntry>,
}

#[derive(Debug)]
pub(super) struct SnapshotEntry {
    pub path: PathBuf,
    pub bytes: Option<Vec<u8>>,
}

pub(super) struct Policy {
    pub manifest: Manifest,
    pub snapshots: BTreeMap<String, Arc<str>>,
    pub directories: BTreeMap<String, Arc<DirectorySnapshot>>,
}

fn words_valid(words: &[String]) -> bool {
    words.len() <= 32
        && words
            .iter()
            .all(|word| word.len() <= 2048 && !word.contains('\0'))
}

impl DirectorySnapshot {
    fn load(root: &Path, count: &mut usize, bytes: &mut usize) -> Result<Self> {
        fn visit(
            root: &Path,
            relative: &Path,
            depth: usize,
            count: &mut usize,
            bytes: &mut usize,
            entries: &mut Vec<SnapshotEntry>,
        ) -> Result<()> {
            if depth > 4 {
                return fail("directory snapshot depth exceeds 4");
            }
            for item in std::fs::read_dir(root.join(relative))? {
                let item = item?;
                *count += 1;
                if *count > 256 {
                    return fail("directory snapshots exceed 256 total entries");
                }
                let path = relative.join(item.file_name());
                let metadata = std::fs::symlink_metadata(root.join(&path))?;
                if metadata.file_type().is_symlink() {
                    return fail("directory snapshots must not contain symlinks");
                }
                if metadata.is_dir() {
                    entries.push(SnapshotEntry {
                        path: path.clone(),
                        bytes: None,
                    });
                    visit(root, &path, depth + 1, count, bytes, entries)?;
                } else if metadata.is_file() {
                    let mut contents = Vec::new();
                    File::open(root.join(&path))?
                        .take(32769)
                        .read_to_end(&mut contents)?;
                    *bytes += contents.len();
                    if contents.len() > 32768 || *bytes > 1024 * 1024 {
                        return fail(
                            "directory snapshots require files <=32 KiB and <=1 MiB total",
                        );
                    }
                    entries.push(SnapshotEntry {
                        path,
                        bytes: Some(contents),
                    });
                } else {
                    return fail("directory snapshots require regular files and directories");
                }
            }
            Ok(())
        }
        if !root.is_dir() {
            return fail("directory grant must name a directory");
        }
        let mut entries = Vec::new();
        visit(root, Path::new(""), 0, count, bytes, &mut entries)?;
        Ok(Self { entries })
    }
}

pub(super) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(super) fn handle(s: &str) -> bool {
    s.strip_prefix('@').is_some_and(identifier)
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return fail("manifest exceeds 64 KiB");
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        Self::prepare(manifest, path.parent().unwrap_or(Path::new(".")))
    }

    pub fn prepare(mut manifest: Manifest, base: &Path) -> Result<Self> {
        if manifest.version != 1
            || !handle(&manifest.controller)
            || !handle(&manifest.worker)
            || !handle(&manifest.room)
            || manifest.controller == manifest.worker
            || !manifest.hub.starts_with("wss://")
        {
            return fail(
                "version 1, distinct @controller/@worker, @room and a wss:// hub are required",
            );
        }
        if !(1..=3600).contains(&manifest.lifetime_seconds)
            || !(1..=1024).contains(&manifest.max_commands)
            || !(100..=60000).contains(&manifest.min_interval_ms)
        {
            return fail(
                "limits require lifetime 1..3600 seconds, commands 1..1024, interval 100..60000 ms",
            );
        }
        if manifest.resources.len() > 32
            || manifest.programs.len() > 16
            || manifest.directories.len() > 8
            || manifest
                .resources
                .keys()
                .chain(manifest.programs.keys())
                .chain(manifest.directories.keys())
                .any(|id| !identifier(id))
        {
            return fail("at most 32 resources and 16 programs with simple IDs are allowed");
        }
        let mut directories = BTreeMap::new();
        let (mut count, mut bytes) = (0, 0);
        for (id, path) in &manifest.directories {
            directories.insert(
                id.clone(),
                Arc::new(DirectorySnapshot::load(
                    &base.join(path),
                    &mut count,
                    &mut bytes,
                )?),
            );
        }
        let mut snapshots = BTreeMap::new();
        for (id, path) in &manifest.resources {
            let path = base.join(path);
            // Configuration is local authority. Resolve it ONCE, not from a remote pathname.
            let file = File::open(&path)?;
            if !file.metadata()?.is_file() {
                return fail("resources must be regular files");
            }
            let mut bytes = Vec::new();
            file.take(32769).read_to_end(&mut bytes)?;
            if bytes.len() > 32768 {
                return fail("resource exceeds 32 KiB");
            }
            let text = String::from_utf8(bytes)?;
            snapshots.insert(id.clone(), Arc::from(text));
        }
        for program in manifest.programs.values_mut() {
            if !program.executable.is_absolute()
                || !program.executable.is_file()
                || !words_valid(&program.arguments)
                || program.parameters.len() > 8
                || !(1..=5000).contains(&program.timeout_ms)
                || !(1..=32768).contains(&program.max_output_bytes)
                || !(16..=512).contains(&program.memory_mb)
            {
                return fail(
                    "programs require an absolute executable, fixed bounded argv, <=5 seconds, <=32 KiB output and 16..512 MiB memory",
                );
            }
            for parameter in &program.parameters {
                match parameter {
                    Parameter::Enum { values }
                        if !values.is_empty()
                            && values.len() <= 16
                            && values.iter().all(|(name, words)| {
                                identifier(name) && words_valid(words) && words.len() <= 4
                            }) => {}
                    Parameter::Directory { allow }
                        if !allow.is_empty()
                            && allow.len() <= 8
                            && allow.iter().all(|id| directories.contains_key(id)) => {}
                    _ => {
                        return fail(
                            "parameters require bounded enum choices or declared directory grants",
                        );
                    }
                }
            }
            program.executable = program.executable.canonicalize()?;
            let mut header = [0; 2];
            File::open(&program.executable)?.read_exact(&mut header)?;
            if header == *b"#!" {
                return fail("program bindings require native executables, not scripts");
            }
            super::process::require_sandbox()?;
        }
        Ok(Self {
            manifest,
            snapshots,
            directories,
        })
    }

    pub fn bind_arguments(
        &self,
        program: &Program,
        values: &serde_json::Value,
    ) -> Result<Vec<Argument>> {
        let values = values
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("arguments must be a list"))?;
        if values.len() != program.parameters.len() {
            return fail("argument count differs from the declared parameters");
        }
        program
            .parameters
            .iter()
            .zip(values)
            .map(|(parameter, value)| {
                let value = value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("arguments must be choice or directory IDs"))?;
                match parameter {
                    Parameter::Enum { values } => Ok(Argument::Words(
                        values
                            .get(value)
                            .ok_or_else(|| anyhow::anyhow!("argument is not an allowed choice"))?
                            .clone(),
                    )),
                    Parameter::Directory { allow } => {
                        if !allow.iter().any(|id| id == value) {
                            return fail("directory ID is not granted to this program");
                        }
                        Ok(Argument::Directory(
                            self.directories
                                .get(value)
                                .ok_or_else(|| anyhow::anyhow!("directory grant unavailable"))?
                                .clone(),
                        ))
                    }
                }
            })
            .collect()
    }
}
