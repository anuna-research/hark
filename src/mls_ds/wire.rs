//! The production `mls-ds/v1` PULL WIRE (ADR-035 shell layer). CBCL-dialect frames only —
//! every outbound request and inbound response passes through the closed-world recogniser
//! (CON-011, fail-closed CON-206) before any semantic handling. The recogniser is STATEFUL:
//! the dialect's `(protocol (then begin next-record (any commit-record …)))` clauses bind
//! responses to requests causally, so one [`DsWire`] (one registry + one message store)
//! lives per DS connection and feeds BOTH directions through one pipeline in order.
//!
//! CON-012 at this layer rides the dialect's own `:caused-by` hash chain: every request is a
//! thread start (`:caused-by "begin"`); the DS response MUST name the request's content hash
//! (`:caused-by "sha256:…"` over the request's canonical bytes). The pipeline enforces the
//! verb pairing; [`DsWire::inbound`] additionally pins the hash to THE outstanding request,
//! so a genuine DS response transplanted from another request/room is rejected before any
//! admission logic runs. (The DS-signed `DomainTuple::Response` binding — the crypto half,
//! `verify_response_frame` — composes on top when the hub signs read responses.)
//!
//! Body schema (this module is its normative definition; the hub's LFE handler mirrors it):
//!   request:  `(next-record (read "<room>" <after_seq>) :caused-by "begin")`
//!             `(genesis-get (read-genesis "<room>") :caused-by "begin")`
//!   response: `(commit-record (record "<room>" <seq> "<prev>" "<record_hash>" "<sig_hex>"
//!                                     "<genesis_ref>" <log_record>) :caused-by "<req-hash>")`
//!             `(at-head (head "<room>" <seq>) :caused-by "<req-hash>")`
//!             `(genesis-anchor (anchor "<room>" "<anchor_hash>") :caused-by "<req-hash>")`
//!             `(ds-rejected (reject "<room>" "<reason>") :caused-by "<req-hash>")`
//!
//! Content hash recipe (both runtimes): `"sha256:" + hex(sha256(canonical_encode(frame)))` —
//! the same encoder as record hashing (CON-002), so the LFE hub reuses its byte-parity
//! canonical encoder to compute what its responses must name.

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_core::store::{ContentHash, MessageStore, ThreadId, ThreadedMessageStore};
use cbcl_parser::{run_pipeline_full, PipelineContext, PipelineResult};
use sha2::{Digest, Sha256};

use super::{install_dialect, RecordResponse};

/// A recognised, parsed inbound DS message the pull loop acts on.
#[derive(Debug)]
pub enum DsInbound {
    /// A served log record (the `next-record` honest-path response).
    Record(RecordResponse),
    /// The cursor is at the head — nothing to pull; poll again later.
    AtHead { seq: i64 },
    /// The room's pinned immutable genesis anchor (CON-008 `genesis-get` response).
    GenesisAnchor { anchor: String },
    /// The DS refused the request (recognised, legal refusal).
    Rejected(String),
    /// The room reached closure (H10) — stop pulling.
    RoomClosed,
}

/// The per-connection production wire: closed-world recogniser + frame codec.
pub struct DsWire {
    registry: DialectRegistry,
    store: ThreadedMessageStore,
    room: String,
    /// CON-012: the content hash of the ONE outstanding request, if any. The
    /// response must name exactly this hash in `:caused-by`.
    outstanding: Option<String>,
}

fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}
fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(s.into()))
}
fn kw(s: &str) -> SExpr {
    SExpr::Atom(Atom::Keyword(s.into()))
}

/// Standard CBCL text (`Display`) — the wire form. (`canonical_encode` is only
/// for hashing/signing, never the wire.)
fn render(e: &SExpr) -> String {
    e.to_string()
}

/// The shared content-hash recipe: canonical bytes → sha256, `sha256:<hex>` form.
pub fn frame_content_hash(e: &SExpr) -> String {
    let d = Sha256::digest(cbcl_core::canonical::canonical_encode(e));
    let mut hex = String::with_capacity(64);
    for b in d {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("sha256:{hex}")
}

impl DsWire {
    pub fn new(room: &str) -> Self {
        Self {
            registry: install_dialect(),
            store: ThreadedMessageStore::new(),
            room: room.to_string(),
            outstanding: None,
        }
    }

    /// CON-011: run one payload through the recogniser (fail-closed), and on success
    /// append it to the causal store so later frames may name it in `:caused-by`.
    fn recognize_and_store(&mut self, payload: &str, frame: &SExpr) -> Result<(), String> {
        let result = {
            let ctx = PipelineContext::new(&self.registry, &self.store);
            run_pipeline_full(payload, &ctx)
        };
        match result {
            PipelineResult::Success(message) => {
                let thread = ThreadId(
                    message.thread().unwrap_or("default").to_string(),
                );
                self.store.append(ContentHash(frame_content_hash(frame)), thread, message);
                Ok(())
            }
            other => Err(format!("{other:?}")),
        }
    }

    fn request(&mut self, verb: &str, body: SExpr) -> Result<String, String> {
        if self.outstanding.is_some() {
            return Err("a read is already outstanding (single-outstanding-pull)".into());
        }
        let frame = SExpr::List(vec![sym(verb), body, kw("caused-by"), st("begin")]);
        let text = render(&frame);
        self.recognize_and_store(&text, &frame)?;
        self.outstanding = Some(frame_content_hash(&frame));
        Ok(text)
    }

    /// Build (and self-recognise) the `next-record` request for the record after `after_seq`.
    pub fn next_record_request(&mut self, after_seq: i64) -> Result<String, String> {
        let body = SExpr::List(vec![sym("read"), st(&self.room), num(after_seq)]);
        self.request("next-record", body)
    }

    /// Build (and self-recognise) the `genesis-get` request (AwaitingGenesis → anchor fetch).
    pub fn genesis_get_request(&mut self) -> Result<String, String> {
        let body = SExpr::List(vec![sym("read-genesis"), st(&self.room)]);
        self.request("genesis-get", body)
    }

    /// Recognise + decode one inbound DS payload. Fail-closed at every step: an unrecognised
    /// frame, a malformed body, a wrong room, or a `:caused-by` naming anything but THE
    /// outstanding request (CON-012 transplant) is an `Err` — the caller drops the frame and
    /// holds the cursor.
    pub fn inbound(&mut self, payload: &str) -> Result<DsInbound, String> {
        let frame: SExpr = payload
            .parse()
            .map_err(|e| format!("not cbcl: {e:?}"))?;
        // CON-012 structural binding FIRST: the response must name the outstanding
        // request's content hash. (The pipeline then re-checks the causal pairing.)
        let caused = frame_caused_by(&frame).ok_or("response missing :caused-by")?;
        match self.outstanding.as_deref() {
            Some(expected) if caused == expected => {}
            Some(expected) => {
                return Err(format!(
                    "frame-transplant: :caused-by {caused} != outstanding {expected}"
                ))
            }
            None => return Err("response with no outstanding request".into()),
        }
        self.recognize_and_store(payload, &frame)?;
        self.outstanding = None;

        let SExpr::List(items) = &frame else { return Err("not a list frame".into()) };
        let Some(SExpr::Atom(Atom::Symbol(verb))) = items.first() else {
            return Err("no verb".into());
        };
        let body = items.get(1).ok_or("missing body")?;
        match verb.as_str() {
            "commit-record" | "commit-add-record" | "proposal-record" | "recovery-record" => {
                self.decode_record(body).map(DsInbound::Record)
            }
            "at-head" => {
                let items = body_items(body, "head")?;
                self.bind_room(&str_at(items, 1, "room")?)?;
                Ok(DsInbound::AtHead { seq: num_at(items, 2, "seq")? })
            }
            "genesis-anchor" => {
                let items = body_items(body, "anchor")?;
                self.bind_room(&str_at(items, 1, "room")?)?;
                Ok(DsInbound::GenesisAnchor { anchor: str_at(items, 2, "anchor-hash")? })
            }
            "ds-rejected" | "genesis-none" | "log-behind" | "log-truncated" | "stale-head" => {
                Ok(DsInbound::Rejected(render(body)))
            }
            "room-closed" => Ok(DsInbound::RoomClosed),
            other => Err(format!("recognised but unhandled ds verb: {other}")),
        }
    }

    /// The wire body must name THIS wire's room — a genuine response for another
    /// room is a transplant even if its hash chain were somehow satisfied.
    fn bind_room(&self, room: &str) -> Result<(), String> {
        if room == self.room {
            Ok(())
        } else {
            Err(format!("frame-transplant: room {room} != {}", self.room))
        }
    }

    fn decode_record(&mut self, body: &SExpr) -> Result<RecordResponse, String> {
        let items = body_items(body, "record")?;
        self.bind_room(&str_at(items, 1, "room")?)?;
        let seq = num_at(items, 2, "seq")?;
        let prev_hash = str_at(items, 3, "prev")?;
        let record_hash = str_at(items, 4, "record-hash")?;
        let sig_hex = str_at(items, 5, "sig")?;
        let genesis_ref = str_at(items, 6, "genesis-ref")?;
        let log_record = items.get(7).ok_or("missing log-record")?.clone();
        Ok(RecordResponse {
            seq,
            prev_hash,
            record_hash,
            record_signature: sig64(&sig_hex)?,
            log_record,
            genesis_ref,
        })
    }
}

/// Extract the `:caused-by` value from a frame's top-level keyword args.
fn frame_caused_by(frame: &SExpr) -> Option<String> {
    let SExpr::List(items) = frame else { return None };
    let mut it = items.iter();
    while let Some(item) = it.next() {
        if matches!(item, SExpr::Atom(Atom::Keyword(k)) if k == "caused-by") {
            return match it.next() {
                Some(SExpr::Atom(Atom::Str(s))) => Some(s.clone()),
                Some(SExpr::Atom(Atom::Symbol(s))) => Some(s.clone()),
                _ => None,
            };
        }
    }
    None
}

fn body_items<'a>(body: &'a SExpr, tag: &str) -> Result<&'a [SExpr], String> {
    let SExpr::List(items) = body else { return Err(format!("{tag}: body not a list")) };
    match items.first() {
        Some(SExpr::Atom(Atom::Symbol(s))) if s == tag => Ok(items),
        _ => Err(format!("body tag != {tag}")),
    }
}
fn str_at(items: &[SExpr], i: usize, what: &str) -> Result<String, String> {
    match items.get(i) {
        Some(SExpr::Atom(Atom::Str(s))) => Ok(s.clone()),
        _ => Err(format!("missing/kind {what} at {i}")),
    }
}
fn num_at(items: &[SExpr], i: usize, what: &str) -> Result<i64, String> {
    match items.get(i) {
        Some(SExpr::Atom(Atom::Num(n))) => Ok(*n),
        _ => Err(format!("missing/kind {what} at {i}")),
    }
}
fn sig64(hex: &str) -> Result<[u8; 64], String> {
    if hex.len() != 128 {
        return Err("sig not 64 bytes hex".into());
    }
    let mut out = [0u8; 64];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "sig not utf8")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "sig not hex")?;
    }
    Ok(out)
}

/// Test/hub-mirror helper: build a DS response frame for a request hash. Kept in the
/// production module (not cfg(test)) because the LFE hub handler mirrors this exact shape
/// and the e2e harness uses it as the reference encoder.
pub fn response_frame(verb: &str, body: SExpr, req_hash: &str) -> SExpr {
    SExpr::List(vec![sym(verb), body, kw("caused-by"), st(req_hash)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_ds::record_hash;
    use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};

    const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn record_frame(room: &str, req_hash: &str, seq: i64, prev: &str, ds: &Ed25519Keypair) -> String {
        let log_record = SExpr::List(vec![sym("log-v1"), st(room), num(seq), st(prev)]);
        let rh = record_hash(&log_record);
        let sig = DomainTuple::Record { log_record: log_record.clone() }.sign(ds);
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        render(&response_frame(
            "commit-record",
            SExpr::List(vec![
                sym("record"), st(room), num(seq), st(prev), st(&rh), st(&hex),
                st("sha256:anchor"), log_record,
            ]),
            req_hash,
        ))
    }

    fn req_hash_of(w: &DsWire) -> String {
        w.outstanding.clone().expect("outstanding request")
    }

    #[test]
    fn request_then_matching_record_roundtrips() {
        let ds = Ed25519Keypair::from_seed(&[42u8; 32]);
        let mut w = DsWire::new("room-alpha");
        let req = w.next_record_request(0).expect("request recognised");
        assert!(req.contains("next-record"));
        let resp = record_frame("room-alpha", &req_hash_of(&w), 1, H0, &ds);
        match w.inbound(&resp).expect("recognised + bound") {
            DsInbound::Record(r) => {
                assert_eq!(r.seq, 1);
                assert_eq!(r.prev_hash, H0);
                assert_eq!(r.genesis_ref, "sha256:anchor");
            }
            other => panic!("expected Record, got {other:?}"),
        }
        // the slot is freed: a new pull can go out
        assert!(w.next_record_request(1).is_ok());
    }

    #[test]
    fn con012_transplant_room_and_unsolicited_rejected() {
        let ds = Ed25519Keypair::from_seed(&[42u8; 32]);
        // a response naming a DIFFERENT request hash is a frame transplant
        let mut w = DsWire::new("room-alpha");
        w.next_record_request(0).unwrap();
        let stale = record_frame("room-alpha", "sha256:not-the-request", 1, H0, &ds);
        assert!(w.inbound(&stale).unwrap_err().contains("frame-transplant"));
        // a genuine-shaped response for the WRONG room is rejected
        let mut w2 = DsWire::new("room-alpha");
        w2.next_record_request(0).unwrap();
        let h2 = req_hash_of(&w2);
        let foreign = record_frame("room-beta", &h2, 1, H0, &ds);
        assert!(w2.inbound(&foreign).unwrap_err().contains("frame-transplant"));
        // a response with NO outstanding request is rejected
        let mut w3 = DsWire::new("room-alpha");
        assert!(w3
            .inbound(&record_frame("room-alpha", "sha256:whatever", 1, H0, &ds))
            .unwrap_err()
            .contains("no outstanding request"));
    }

    #[test]
    fn unrecognised_frames_fail_closed() {
        let mut w = DsWire::new("room-alpha");
        w.next_record_request(0).unwrap();
        let h = req_hash_of(&w);
        // right hash, but an alien verb: rejected by the recogniser, fail-closed
        let alien = render(&response_frame("totally-made-up-verb", st("x"), &h));
        assert!(w.inbound(&alien).is_err());
        assert!(w.inbound("not even cbcl").is_err());
    }

    #[test]
    fn at_head_and_genesis_anchor_decode() {
        let mut w = DsWire::new("room-alpha");
        w.next_record_request(3).unwrap();
        let head = render(&response_frame(
            "at-head",
            SExpr::List(vec![sym("head"), st("room-alpha"), num(3)]),
            &req_hash_of(&w),
        ));
        assert!(matches!(w.inbound(&head).unwrap(), DsInbound::AtHead { seq: 3 }));

        let mut w2 = DsWire::new("room-alpha");
        w2.genesis_get_request().unwrap();
        let anchor = render(&response_frame(
            "genesis-anchor",
            SExpr::List(vec![sym("anchor"), st("room-alpha"), st("sha256:abc")]),
            &req_hash_of(&w2),
        ));
        match w2.inbound(&anchor).unwrap() {
            DsInbound::GenesisAnchor { anchor } => assert_eq!(anchor, "sha256:abc"),
            other => panic!("expected GenesisAnchor, got {other:?}"),
        }
    }

    #[test]
    fn single_outstanding_pull_enforced_on_the_wire() {
        let mut w = DsWire::new("room-alpha");
        w.next_record_request(0).unwrap();
        assert!(w.next_record_request(1).unwrap_err().contains("outstanding"));
    }
}
