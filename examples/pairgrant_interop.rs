//! SPEC-061 REQ-008 cross-stack interop, in the direction production uses: a WEB
//! member signs a pairing admission grant, and a hark AGENT seats itself with it.
//!
//!   cargo run --example pairgrant_interop -- key  <dir>
//!   node  …/pairgrant-interop.mjs mint            <dir>
//!   cargo run --example pairgrant_interop -- seat <dir>
//!   node  …/pairgrant-interop.mjs verify          <dir>
//!
//! WHY THIS EXISTS. `pairgrant_signing_bytes_cross_stack_vector` proves the two
//! stacks agree on the bytes a grant is signed over, and nothing more. It cannot
//! prove they agree on the genesis extension type, the leaf capabilities, the
//! GroupInfo encoding, the AAD framing, the proposal allowlist or the pin rules —
//! and a matching signature vector beside a Commit that does not validate is
//! exactly the shape of a cross-stack bug that ships.
//!
//! It matters more here than it does for the invite flavour
//! (`spec061_interop`), because a pairing grant is NEVER minted and redeemed on
//! one stack: a member signs, an agent redeems. There is no same-stack path that
//! would notice a drift, so this harness is the only thing standing between a
//! divergence and every pairing admission silently refusing.
//!
//! The roles are also the mirror image of `spec061_interop`, deliberately. There
//! the agent creates and signs and the web client seats itself; here the web
//! client signs and the AGENT seats itself — the half hark had never implemented
//! at all until REQ-008, because an agent is never the party redeeming an invite.

use std::path::{Path, PathBuf};

use hark::identity::ChatIdentity;
use hark::mls::session::{MlsSession, SessionEvent};

const ROOM: &str = "@interop-pair";
const AGENT: &str = "@agent6";
/// Fixed so `key` and `seat` are the same agent across two processes.
const AGENT_SEED: u8 = 0x6B;

fn state_dir(dir: &Path) -> PathBuf {
    dir.join("agent-state")
}

fn open_session(dir: &Path) -> MlsSession {
    let sd = state_dir(dir);
    std::fs::create_dir_all(&sd).expect("state dir");
    let wire = ChatIdentity::from_seed([AGENT_SEED; 32]);
    MlsSession::open(&sd, "pairinterop", ROOM, AGENT, &wire, true).expect("session opens")
}

/// Publish the agent's wire key, which is what the web member will bind its grant
/// to. This step exists BECAUSE the grant is subject-bound: an invite grant can be
/// minted before the invitee exists, and this one cannot — the key is half of what
/// is signed (SPEC-061 ADR-004).
fn key(dir: &Path) {
    std::fs::create_dir_all(dir).expect("out dir");
    let _ = std::fs::remove_dir_all(state_dir(dir));
    let _ = open_session(dir); // create the state the `seat` step will resume

    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let wire = ChatIdentity::from_seed([AGENT_SEED; 32]);
    std::fs::write(dir.join("room.txt"), ROOM).unwrap();
    std::fs::write(dir.join("agent.txt"), AGENT).unwrap();
    std::fs::write(
        dir.join("agent-key.b64"),
        B64.encode(wire.verifying_key_bytes()),
    )
    .unwrap();
    println!("emitted: agent {AGENT} in {ROOM}, key published for the member to bind");
}

/// Redeem the grant the web member signed: seat ourselves by external Commit and
/// write the commit out for the member to validate.
///
/// Driven through `handle_frame` rather than by calling `join_by_grant` directly,
/// so what is proven is the path a live agent actually takes — the pairgrant frame
/// arriving, being stored, and the GroupInfo turning it into a commit.
fn seat(dir: &Path) {
    let mut session = open_session(dir);
    let grant_b64 = std::fs::read_to_string(dir.join("grant.b64"))
        .expect("the web side wrote grant.b64 — run the node mint step first");
    let gi_b64 = std::fs::read_to_string(dir.join("groupinfo.b64")).expect("groupinfo.b64");

    let pairgrant = format!(
        "(pairgrant {ROOM} :for {AGENT} :grant \"{}\" :from @member)",
        grant_b64.trim()
    );
    match session.handle_frame(&pairgrant) {
        SessionEvent::Handled { outbound } => {
            // Holding a grant and no group, the agent must ASK for the GroupInfo.
            // If it does not, nothing else in this flow can happen, and it would
            // fail later in a way that looks like a crypto problem.
            assert!(
                outbound.iter().any(|f| f.starts_with("(groupinfoget ")),
                "an agent holding a grant and no group must ask for a GroupInfo, got {outbound:?}"
            );
        }
        other => {
            eprintln!("FAIL: agent refused the member's pairing grant: {other:?}");
            std::process::exit(1);
        }
    }

    let groupinfo = format!("(groupinfo {ROOM} :epoch 1 :gi \"{}\" :from @member)", gi_b64.trim());
    let commit = match session.handle_frame(&groupinfo) {
        SessionEvent::Handled { outbound } => outbound
            .iter()
            .find(|f| f.starts_with("(deliver "))
            .cloned()
            .unwrap_or_else(|| {
                eprintln!("FAIL: the agent produced no external Commit: {outbound:?}");
                std::process::exit(1);
            }),
        other => {
            eprintln!("FAIL: agent could not seat itself: {other:?}");
            std::process::exit(1);
        }
    };
    let ct = commit
        .split(":ct \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("deliver frame carries :ct");

    std::fs::write(dir.join("commit.b64"), ct).unwrap();
    std::fs::write(dir.join("joiner.txt"), AGENT).unwrap();

    let members = session.member_handles().unwrap_or_default();
    println!("PASS: hark seated itself by external Commit on a member-signed grant");
    println!("      members: {members:?}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, dir) = match (args.get(1).map(String::as_str), args.get(2)) {
        (Some(m), Some(d)) => (m, PathBuf::from(d)),
        _ => {
            eprintln!("usage: pairgrant_interop <key|seat> <dir>");
            std::process::exit(2);
        }
    };
    match mode {
        "key" => key(&dir),
        "seat" => seat(&dir),
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}
