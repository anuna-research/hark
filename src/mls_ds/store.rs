//! CON-013 — durable client-state store atomic-commit boundary (H5, ADR-033). Immutable
//! per-generation files (`gen-N.group` = OpenMLS snapshot, `gen-N.client` = the v1 client
//! tuple) fsynced first, then ONE fsynced manifest flip (atomic `rename`) commits both. A
//! crash at any phase leaves the store whole-old or whole-new, never mixed (TEST-017/REQ-083).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CrashAt {
    None,
    AfterGroupWrite,
    AfterClientWrite,
    AfterManifestTmp,
}

pub struct DurableStore {
    pub dir: PathBuf,
}

fn fsync(p: &Path) -> io::Result<()> {
    fs::File::open(p)?.sync_all()
}

impl DurableStore {
    pub fn open(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Self { dir }
    }

    /// The CON-013 atomic commit. The manifest `rename` is the single commit point.
    pub fn commit(&self, generation: u64, group: &[u8], client: &[u8], crash: CrashAt) -> io::Result<()> {
        let g = self.dir.join(format!("gen-{generation}.group"));
        let c = self.dir.join(format!("gen-{generation}.client"));
        fs::write(&g, group)?;
        fsync(&g)?;
        if crash == CrashAt::AfterGroupWrite {
            return Ok(());
        }
        fs::write(&c, client)?;
        fsync(&c)?;
        if crash == CrashAt::AfterClientWrite {
            return Ok(());
        }
        let tmp = self.dir.join("manifest.tmp");
        fs::write(&tmp, generation.to_string())?;
        fsync(&tmp)?;
        if crash == CrashAt::AfterManifestTmp {
            return Ok(());
        }
        fs::rename(&tmp, self.dir.join("manifest"))?;
        let _ = fsync(&self.dir);
        Ok(())
    }

    /// Read the committed generation — never a half-written one.
    pub fn load(&self) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        let generation: u64 = fs::read_to_string(self.dir.join("manifest")).ok()?.trim().parse().ok()?;
        let group = fs::read(self.dir.join(format!("gen-{generation}.group"))).ok()?;
        let client = fs::read(self.dir.join(format!("gen-{generation}.client"))).ok()?;
        Some((generation, group, client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> DurableStore {
        let dir = std::env::temp_dir().join(format!("hark-h5-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        DurableStore::open(dir)
    }

    #[test]
    fn crash_atomic_whole_old_or_whole_new() {
        for (name, crash, expect_gen) in [
            ("none", CrashAt::None, 2u64),
            ("group", CrashAt::AfterGroupWrite, 1),
            ("client", CrashAt::AfterClientWrite, 1),
            ("tmp", CrashAt::AfterManifestTmp, 1),
        ] {
            let s = store(name);
            s.commit(1, b"G1", b"C1", CrashAt::None).unwrap();
            s.commit(2, b"G2", b"C2", crash).unwrap();
            let (generation, group, client) = s.load().unwrap();
            assert_eq!(generation, expect_gen, "crash {crash:?}");
            let expected = if generation == 2 { (b"G2".to_vec(), b"C2".to_vec()) } else { (b"G1".to_vec(), b"C1".to_vec()) };
            assert_eq!((group, client), expected, "never torn");
        }
    }
}
