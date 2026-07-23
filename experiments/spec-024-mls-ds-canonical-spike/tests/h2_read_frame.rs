//! IMPL-025 H2 (partial) — CON-012 read-frame binding + response authentication.
//!
//! Implements the recogniser-INDEPENDENT half of
//! [[IMPL-025-hark-mls-ds-client#CON-012]] / [[IMPL-025-hark-mls-ds-client#ADR-036]]: a read
//! request binds to an allocated `(session_id, frame_id)` (the `READ-CONTEXT`), and the client
//! verifies each DS response under the pinned DS key, checking that the response's retained
//! frame context AND its `request_content_hash` match the OUTSTANDING request — so a
//! **response-frame-for-request-frame substitution** is rejected. The inner closed-world
//! recogniser (CON-011) is a SEPARATE step this frame layer merely feeds; it is out of scope
//! here (the one genuinely recogniser-gated piece is the *ingress classification*, not this
//! frame binding).
//!
//! Crypto CONSUMED via `DomainTuple::{Request,Response}` + `ReadContext`. Acceptance essence of
//! [[SPEC-024-mls-delivery-service#TEST-013]] (read-frame `(session_id,frame_id)`, both
//! contexts, replay/substitution). The authenticated clock (OQ-003b) + the actual socket are
//! the hark-integration H2. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h2_read_frame -- --nocapture

use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair, ReadContext};
use cbcl_core::sexpr::{Atom, SExpr};

fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}

const DIALECT: &str = "sha256:922ba8bf9eb62a07b81989a9bfe6754a626b2edaf4d3f52e3fc4b41321261858";
const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject(&'static str),
}

/// The outstanding read root the transport retains for a pending read request.
struct Outstanding {
    session_id: String,
    frame_id: i64,
    request_content_hash: String,
}

/// A simple transport frame-id allocator (`allocate_read_frame`).
struct Allocator {
    session_id: String,
    next: i64,
}
impl Allocator {
    fn allocate(&mut self) -> (String, i64) {
        let f = self.next;
        self.next += 1;
        (self.session_id.clone(), f)
    }
}

/// Build a read request bound to `(session_id, frame_id)` and return the outstanding row.
fn issue_read(session_id: String, frame_id: i64, op: &str) -> Outstanding {
    let request = DomainTuple::Request {
        bindings: st("client-bindings"),
        dialect_hash: DIALECT.into(),
        h0: H0.into(),
        request: SExpr::List(vec![st("ds-request"), st(op)]),
        read_context: ReadContext::Read { session_id: session_id.clone(), frame_id },
    };
    Outstanding {
        session_id,
        frame_id,
        request_content_hash: request.content_hash(),
    }
}

/// The DS builds a response for a given frame + request hash and signs it.
fn ds_respond(
    ds: &Ed25519Keypair,
    session_id: &str,
    frame_id: i64,
    request_content_hash: &str,
    body: &str,
) -> (DomainTuple, [u8; 64]) {
    let resp = DomainTuple::Response {
        bindings: st("ds-bindings"),
        dialect_hash: DIALECT.into(),
        request_content_hash: request_content_hash.into(),
        response_message: SExpr::List(vec![st("ds-response"), st(body)]),
        read_context: ReadContext::Read {
            session_id: session_id.into(),
            frame_id,
        },
    };
    let sig = resp.sign(ds);
    (resp, sig)
}

/// The H2 verification: retain+verify the outer sig, then bind BOTH contexts to the outstanding
/// request — never substituting one frame's response for another's.
fn verify_response(o: &Outstanding, ds_vk: &[u8; 32], resp: &DomainTuple, sig: &[u8; 64]) -> Verdict {
    // (1) verify under the pinned DS key BEFORE trusting any field.
    if !resp.verify(ds_vk, sig) {
        return Verdict::Reject("response-signature-invalid");
    }
    let DomainTuple::Response {
        request_content_hash,
        read_context,
        ..
    } = resp
    else {
        return Verdict::Reject("not-a-response");
    };
    // (2) the retained response frame must equal the OUTSTANDING request frame (no transplant).
    match read_context {
        ReadContext::Read { session_id, frame_id } => {
            if session_id != &o.session_id || *frame_id != o.frame_id {
                return Verdict::Reject("frame-transplant");
            }
        }
        ReadContext::None => return Verdict::Reject("read-context-missing"),
    }
    // (3) the response must answer THIS request (the distinct request-content binding).
    if request_content_hash != &o.request_content_hash {
        return Verdict::Reject("request-content-mismatch");
    }
    Verdict::Accept
}

/// The honest end-to-end: allocate a frame, issue a read, the DS answers that exact frame.
#[test]
fn a_response_for_the_outstanding_frame_is_accepted() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let mut alloc = Allocator { session_id: "sess-1".into(), next: 1 };
    let (sid, fid) = alloc.allocate();
    let o = issue_read(sid.clone(), fid, "next-record");
    let (resp, sig) = ds_respond(&ds, &sid, fid, &o.request_content_hash, "record-payload");
    let v = verify_response(&o, &ds.public_bytes(), &resp, &sig);
    println!("[H2 frame] matched frame ({sid},{fid}) -> {v:?}");
    assert_eq!(v, Verdict::Accept);
}

/// A response carrying a DIFFERENT frame id is a substitution — rejected (ADR-036/TEST-013).
#[test]
fn a_response_for_a_different_frame_is_rejected() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let o = issue_read("sess-1".into(), 7, "next-record");
    // The DS (or a MITM) answers frame 9, not our outstanding frame 7.
    let (resp, sig) = ds_respond(&ds, "sess-1", 9, &o.request_content_hash, "x");
    let v = verify_response(&o, &ds.public_bytes(), &resp, &sig);
    println!("[H2 frame] frame transplant (7 vs 9) -> {v:?}");
    assert_eq!(v, Verdict::Reject("frame-transplant"));
}

/// A well-signed response to a DIFFERENT request (different content hash) is rejected.
#[test]
fn a_response_to_a_different_request_is_rejected() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let o = issue_read("sess-1".into(), 7, "next-record");
    let other = issue_read("sess-1".into(), 7, "get-welcome"); // different request, same frame slot
    let (resp, sig) = ds_respond(&ds, "sess-1", 7, &other.request_content_hash, "x");
    let v = verify_response(&o, &ds.public_bytes(), &resp, &sig);
    println!("[H2 frame] request-content mismatch -> {v:?}");
    assert_eq!(v, Verdict::Reject("request-content-mismatch"));
}

/// A response signed by a non-pinned key is dropped before any field is trusted.
#[test]
fn a_response_under_a_non_pinned_key_is_rejected() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let impostor = Ed25519Keypair::from_seed(&[6u8; 32]);
    let o = issue_read("sess-1".into(), 7, "next-record");
    let (resp, sig) = ds_respond(&impostor, "sess-1", 7, &o.request_content_hash, "x");
    let v = verify_response(&o, &ds.public_bytes(), &resp, &sig);
    println!("[H2 frame] non-pinned DS key -> {v:?}");
    assert_eq!(v, Verdict::Reject("response-signature-invalid"));
}
