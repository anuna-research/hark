//! ADR-035 pull-loop driver (H6). The client-side control flow that replaces SPEC-013 push:
//! maintain exactly ONE outstanding `next-record` per room, feed each verified response to the
//! reducer, advance the cursor by one. This is the pure driver; the socket + async runtime are
//! the `chat.rs` shell (it calls `next_pull` to get the frame to send, and `on_record` with each
//! verified response).

use super::{bind_record_anchor, transition_record, AnchorBinding, ClientLog, RecordResponse, Verdict};

/// The per-room pull state.
pub struct PullDriver {
    log: ClientLog,
    outstanding: bool,
    /// The client's persisted immutable genesis anchor (CON-008), or `None` until anchored.
    saved_anchor: Option<String>,
}

/// What the shell should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum PullAction {
    /// Send a `next-record` read requesting the record after `after_seq` (= cursor + 1).
    Pull { after_seq: i64 },
    /// A pull is already in flight — exactly one outstanding at a time (REQ-034); wait.
    Waiting,
}

impl PullDriver {
    pub fn new(log: ClientLog, saved_anchor: Option<String>) -> Self {
        Self { log, outstanding: false, saved_anchor }
    }

    pub fn cursor(&self) -> &ClientLog {
        &self.log
    }

    /// The single-outstanding-pull rule: at most one `next-record` in flight. No live/replay
    /// interleave — the next pull is issued only after the previous response is processed.
    pub fn next_pull(&mut self) -> PullAction {
        if self.outstanding {
            return PullAction::Waiting;
        }
        self.outstanding = true;
        PullAction::Pull { after_seq: self.log.cursor }
    }

    /// Feed a verified record response through the composed CON-005 record admission: the
    /// immutable-anchor binding (REQ-127) precedes positional admission, then hash + DS-sig +
    /// exact-next. A foreign anchor is ds-equivocation; an absent saved anchor holds the cursor
    /// pending `genesis-get`; on C-APPLIED advance by one; on notNext/Violation hold. The
    /// outstanding-pull slot is freed either way so the loop can re-pull.
    ///
    /// NOTE: Add-authorization (`boundary::validate_v1_commit`) and the MLS apply/join outcome
    /// (CON-006) are the effectful shell's steps — they need the openmls engine and are invoked
    /// by the daemon around this call, not composed here.
    pub fn on_record(&mut self, ds_vk: &[u8; 32], resp: &RecordResponse) -> Verdict {
        self.outstanding = false;
        match bind_record_anchor(&resp.genesis_ref, self.saved_anchor.as_deref()) {
            AnchorBinding::Bound => {}
            AnchorBinding::AwaitingGenesis => return Verdict::AwaitingGenesis,
            AnchorBinding::Violation(code) => return Verdict::Violation(code),
        }
        let verdict = transition_record(&self.log, ds_vk, resp);
        if let Verdict::Applied { cursor, cursor_hash } = &verdict {
            self.log = ClientLog { cursor: *cursor, cursor_hash: cursor_hash.clone() };
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_ds::record_hash;
    use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};
    use cbcl_core::sexpr::{Atom, SExpr};

    const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const ANCHOR: &str = "sha256:anchor";

    fn signed_record(seq: i64, prev_hash: &str, ds: &Ed25519Keypair) -> RecordResponse {
        let rec = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("log-v1".into())),
            SExpr::Atom(Atom::Str("room-alpha".into())),
            SExpr::Atom(Atom::Num(seq)),
            SExpr::Atom(Atom::Str(prev_hash.into())),
        ]);
        let rh = record_hash(&rec);
        let sig = DomainTuple::Record { log_record: rec.clone() }.sign(ds);
        RecordResponse { seq, prev_hash: prev_hash.into(), record_hash: rh, record_signature: sig, log_record: rec, genesis_ref: ANCHOR.into() }
    }
    fn driver() -> PullDriver {
        PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() }, Some(ANCHOR.into()))
    }

    #[test]
    fn single_outstanding_pull_and_cursor_advance() {
        let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
        let vk = ds.public_bytes();
        let mut d = driver();

        // one pull issued; a second before the response is Waiting (no interleave)
        assert_eq!(d.next_pull(), PullAction::Pull { after_seq: 0 });
        assert_eq!(d.next_pull(), PullAction::Waiting);

        // feed the exact-next record → C-APPLIED, cursor advances to 1
        let r1 = signed_record(1, H0, &ds);
        assert!(matches!(d.on_record(&vk, &r1), Verdict::Applied { cursor: 1, .. }));

        // now the next pull is for cursor 1, and the chained record advances to 2
        assert_eq!(d.next_pull(), PullAction::Pull { after_seq: 1 });
        let r2 = signed_record(2, &d.cursor().cursor_hash, &ds);
        assert!(matches!(d.on_record(&vk, &r2), Verdict::Applied { cursor: 2, .. }));
        assert_eq!(d.cursor().cursor, 2);
    }

    // The anchor binding is COMPOSED into the live driver, ahead of positional admission.
    #[test]
    fn on_record_binds_the_immutable_anchor_before_admission() {
        let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
        let vk = ds.public_bytes();

        // a record naming a FOREIGN anchor is ds-equivocation (before the positional/sig clause).
        let mut d = driver(); // saved_anchor = Some(ANCHOR)
        let mut foreign = signed_record(1, H0, &ds);
        foreign.genesis_ref = "sha256:foreign".into();
        assert_eq!(d.on_record(&vk, &foreign), Verdict::Violation("ds-equivocation:genesis-anchor-mismatch"));
        assert_eq!(d.cursor().cursor, 0, "cursor held on a foreign-anchor record");

        // a client with NO saved anchor holds the cursor pending genesis-get.
        let mut d2 = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() }, None);
        assert_eq!(d2.on_record(&vk, &signed_record(1, H0, &ds)), Verdict::AwaitingGenesis);
        assert_eq!(d2.cursor().cursor, 0);
    }
}
