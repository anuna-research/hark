//! SPEC-061 cross-stack interop: a hark agent owns a private channel, and a
//! WEB client admits itself to it by external Commit while the agent is the only
//! member present.
//!
//!   cargo run --example spec061_interop -- emit   <dir>
//!   node  …/spec061-interop-join.mjs              <dir>
//!   cargo run --example spec061_interop -- verify <dir>
//!
//! WHY THIS EXISTS, AND WHY THE SHARED VECTOR IS NOT ENOUGH.
//! `invite_signing_bytes_cross_stack_vector` proves the two stacks agree on the
//! bytes a grant is signed over. It cannot prove they agree on everything ELSE an
//! admission touches: the genesis extension type, the leaf capabilities, the
//! GroupInfo encoding, the AAD framing, the proposal allowlist, the pin rules. A
//! signature vector that matches while a Welcome or a Commit does not is exactly
//! the shape of a cross-stack bug that ships. So this drives a REAL admission
//! across the boundary and asserts the agent's own tree afterwards.
//!
//! The direction is the one that matters in production and the one the shared
//! vector cannot cover from either side alone: the CREATOR is the agent (it signs
//! the grant), and the JOINER is the web client (it mints the external Commit,
//! which hark can validate but never produces). Neither stack exercises both
//! halves on its own.

use std::path::{Path, PathBuf};

use hark::identity::ChatIdentity;
use hark::mls::group::AdmissionGrant;
use hark::mls::session::{MlsSession, SessionEvent};

const ROOM: &str = "@interop";
const AGENT: &str = "@agent";
/// Fixed so `emit` and `verify` are the same agent across two processes.
const AGENT_SEED: u8 = 0x5A;

fn state_dir(dir: &Path) -> PathBuf {
    dir.join("agent-state")
}

fn open_session(dir: &Path) -> MlsSession {
    let sd = state_dir(dir);
    std::fs::create_dir_all(&sd).expect("state dir");
    let wire = ChatIdentity::from_seed([AGENT_SEED; 32]);
    MlsSession::open(&sd, "interop", ROOM, AGENT, &wire, true).expect("session opens")
}

fn emit(dir: &Path) {
    std::fs::create_dir_all(dir).expect("out dir");
    let _ = std::fs::remove_dir_all(state_dir(dir));

    let mut session = open_session(dir);
    session
        .create_group_as_creator()
        .expect("agent creates the private channel");

    // The GroupInfo the web joiner needs. This is hark's whole contribution to an
    // external admission: it publishes, it never joins this way.
    let frame = session
        .group_info_frame()
        .expect("agent publishes a GroupInfo for the epoch it is at");
    let gi = frame
        .split(":gi \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("groupinfo frame carries :gi");

    // The creator-signed admission grant, over a token, exactly as minting an
    // invite would produce. This is the only moment the agent is involved in the
    // admission that follows.
    let token = b"interop-token-0001";
    let wire = ChatIdentity::from_seed([AGENT_SEED; 32]);
    let key: [u8; 32] = wire.verifying_key_bytes();
    let not_after = 4_102_444_800_000u64; // 2100-01-01, so the fixture never rots
    let grant = AdmissionGrant::mint(&wire, AGENT, &key, ROOM, token, not_after);

    std::fs::write(dir.join("groupinfo.b64"), gi).unwrap();
    std::fs::write(dir.join("token.txt"), token).unwrap();
    std::fs::write(dir.join("grant.json"), serde_json::to_vec(&grant).unwrap()).unwrap();
    std::fs::write(dir.join("room.txt"), ROOM).unwrap();
    std::fs::write(dir.join("creator.txt"), AGENT).unwrap();

    println!("emitted: groupinfo.b64 token.txt grant.json (room {ROOM}, creator {AGENT})");
}

fn verify(dir: &Path) {
    let mut session = open_session(dir);
    let commit_b64 = std::fs::read_to_string(dir.join("commit.b64"))
        .expect("the web side wrote commit.b64 — run the node step first");
    let joiner = std::fs::read_to_string(dir.join("joiner.txt")).unwrap_or_default();
    let joiner = joiner.trim();

    // The agent must accept a commit built by the OTHER stack, on nothing but the
    // grant it signed itself.
    let frame = format!(
        "(deliver {ROOM} :enc mls :ct \"{}\" :from {joiner})",
        commit_b64.trim()
    );
    match session.handle_frame(&frame) {
        SessionEvent::Handled { .. } => {}
        other => {
            eprintln!("FAIL: agent refused the web client's external Commit: {other:?}");
            std::process::exit(1);
        }
    }

    // Accepting is not enough — assert the agent's OWN tree changed, or a
    // "Handled" that quietly dropped the frame would read as success.
    let sn = session.safety_numbers().expect("safety numbers after admission");
    let members = session.member_handles().unwrap_or_default();
    if !members.iter().any(|h| h == joiner) {
        eprintln!("FAIL: {joiner} is not in the agent's ratchet tree after the commit: {members:?}");
        std::process::exit(1);
    }
    println!("PASS: hark admitted the web client by external Commit");
    println!("      members: {members:?}");
    println!("      safety : {}", sn.identity);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, dir) = match (args.get(1).map(String::as_str), args.get(2)) {
        (Some(m), Some(d)) => (m, PathBuf::from(d)),
        _ => {
            eprintln!("usage: spec061_interop <emit|verify> <dir>");
            std::process::exit(2);
        }
    };
    match mode {
        "emit" => emit(&dir),
        "verify" => verify(&dir),
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}
