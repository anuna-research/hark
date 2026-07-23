//! IMPL-025 H5 (partial) — CON-013 single atomic-commit boundary + crash recovery.
//!
//! Prototypes the [[IMPL-025-hark-mls-ds-client#ADR-033]] atomic-commit design: immutable
//! per-generation files (`gen-N.group` = the OpenMLS provider snapshot, `gen-N.client` = the
//! v1 client-state tuple) made durable, then ONE fsynced manifest flip (atomic `rename`) that
//! commits both together. The load path reads the manifest → the committed generation, so a
//! crash at ANY phase leaves the store readable as **whole-old or whole-new, never mixed**
//! ([[SPEC-024-mls-delivery-service#CON-005]] `C-APPLIED` / [[SPEC-024-mls-delivery-service#REQ-083]],
//! acceptance [[SPEC-024-mls-delivery-service#TEST-017]]).
//!
//! This proves the MECHANISM in isolation (group/client modelled as opaque bytes — the
//! atomicity is independent of their content). DEFERRED to the hark-integration H5: binding
//! it to hark's real `DurabilityState` + the OpenMLS provider, and the full CON-005 field set
//! (receipts, pending acks, recovery campaigns, closure pins). No recogniser needed. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h5_durable_store -- --nocapture

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The crash phase to stop at, interrupting the commit mid-flight.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CrashAt {
    None,
    AfterGroupWrite,   // gen-N.group durable, gen-N.client NOT written
    AfterClientWrite,  // both gen files durable, manifest NOT touched
    AfterManifestTmp,  // manifest.tmp written, NOT yet renamed over manifest
}

struct DurableStore {
    dir: PathBuf,
}

fn fsync(p: &Path) -> io::Result<()> {
    fs::File::open(p)?.sync_all()
}

impl DurableStore {
    fn open(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Self { dir }
    }

    /// The CON-013 atomic commit. Durability order: both generation files fsynced FIRST, then
    /// the manifest flip. The flip (`rename`) is the single atomic commit point.
    fn commit(&self, gen: u64, group: &[u8], client: &[u8], crash: CrashAt) -> io::Result<()> {
        let g = self.dir.join(format!("gen-{gen}.group"));
        let c = self.dir.join(format!("gen-{gen}.client"));

        fs::write(&g, group)?;
        fsync(&g)?;
        if crash == CrashAt::AfterGroupWrite {
            return Ok(()); // client half never written; manifest still points at the old gen
        }

        fs::write(&c, client)?;
        fsync(&c)?;
        if crash == CrashAt::AfterClientWrite {
            return Ok(()); // both new files durable, but not yet committed by the manifest
        }

        let tmp = self.dir.join("manifest.tmp");
        fs::write(&tmp, gen.to_string())?;
        fsync(&tmp)?;
        if crash == CrashAt::AfterManifestTmp {
            return Ok(()); // tmp staged, but the real manifest not yet flipped
        }

        fs::rename(&tmp, self.dir.join("manifest"))?; // ← ATOMIC COMMIT POINT
        fsync(&self.dir).ok(); // best-effort dir fsync for the rename durability
        Ok(())
    }

    /// Read the committed generation. Returns `(gen, group, client)` or None (uninitialised).
    /// Because the manifest only ever names a generation whose BOTH files were fsynced before
    /// the flip, this can never observe a half-written generation.
    fn load(&self) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        let gen: u64 = fs::read_to_string(self.dir.join("manifest")).ok()?.trim().parse().ok()?;
        let group = fs::read(self.dir.join(format!("gen-{gen}.group"))).ok()?;
        let client = fs::read(self.dir.join(format!("gen-{gen}.client"))).ok()?;
        Some((gen, group, client))
    }
}

fn store(name: &str) -> DurableStore {
    let dir = std::env::temp_dir().join(format!("h5-store-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    DurableStore::open(dir)
}

/// A clean commit round-trips.
#[test]
fn clean_commit_loads_the_committed_generation() {
    let s = store("clean");
    s.commit(1, b"group-1", b"client-1", CrashAt::None).unwrap();
    assert_eq!(s.load(), Some((1, b"group-1".to_vec(), b"client-1".to_vec())));
    println!("[H5 store] clean commit gen=1 -> load OK");
}

/// A crash after the group half is written (before the client half) leaves the store WHOLE-OLD.
#[test]
fn crash_after_group_write_recovers_whole_old() {
    let s = store("crash-group");
    s.commit(1, b"group-1", b"client-1", CrashAt::None).unwrap();
    s.commit(2, b"group-2", b"client-2", CrashAt::AfterGroupWrite).unwrap();
    let (gen, group, client) = s.load().unwrap();
    println!("[H5 store] crash after gen-2 group-write -> load gen={gen}");
    assert_eq!(gen, 1, "manifest must still point at the committed gen-1");
    assert_eq!((group, client), (b"group-1".to_vec(), b"client-1".to_vec()), "WHOLE-OLD, never mixed");
}

/// A crash after both new files are durable but before the manifest flip is WHOLE-OLD.
#[test]
fn crash_before_manifest_flip_recovers_whole_old() {
    let s = store("crash-preflip");
    s.commit(1, b"group-1", b"client-1", CrashAt::None).unwrap();
    s.commit(2, b"group-2", b"client-2", CrashAt::AfterClientWrite).unwrap();
    assert_eq!(s.load(), Some((1, b"group-1".to_vec(), b"client-1".to_vec())));

    // A staged-but-not-renamed manifest.tmp also does not commit.
    let s2 = store("crash-tmp");
    s2.commit(1, b"group-1", b"client-1", CrashAt::None).unwrap();
    s2.commit(2, b"group-2", b"client-2", CrashAt::AfterManifestTmp).unwrap();
    assert_eq!(s2.load(), Some((1, b"group-1".to_vec(), b"client-1".to_vec())));
    println!("[H5 store] crash before/at manifest flip -> WHOLE-OLD (both cases)");
}

/// A completed commit after the flip is WHOLE-NEW.
#[test]
fn commit_after_flip_recovers_whole_new() {
    let s = store("whole-new");
    s.commit(1, b"group-1", b"client-1", CrashAt::None).unwrap();
    s.commit(2, b"group-2", b"client-2", CrashAt::None).unwrap();
    assert_eq!(s.load(), Some((2, b"group-2".to_vec(), b"client-2".to_vec())));
    println!("[H5 store] committed gen=2 -> WHOLE-NEW");
}

/// The load NEVER mixes generations: (group, client) always come from ONE generation, across
/// every crash phase.
#[test]
fn load_never_mixes_group_and_client_across_generations() {
    for (name, crash) in [
        ("m-none", CrashAt::None),
        ("m-group", CrashAt::AfterGroupWrite),
        ("m-client", CrashAt::AfterClientWrite),
        ("m-tmp", CrashAt::AfterManifestTmp),
    ] {
        let s = store(name);
        s.commit(1, b"G1", b"C1", CrashAt::None).unwrap();
        s.commit(2, b"G2", b"C2", crash).unwrap();
        let (gen, group, client) = s.load().unwrap();
        let expected = if gen == 2 { (b"G2".to_vec(), b"C2".to_vec()) } else { (b"G1".to_vec(), b"C1".to_vec()) };
        assert_eq!((group.clone(), client.clone()), expected, "crash {crash:?}: group+client must be same gen");
        // never the mixed (G2, C1) / (G1, C2) states
        assert!(!(group == b"G2" && client == b"C1"), "torn: new group with old client");
        assert!(!(group == b"G1" && client == b"C2"), "torn: old group with new client");
        println!("[H5 store] crash {crash:?} -> whole gen={gen}, no torn mix");
    }
}
