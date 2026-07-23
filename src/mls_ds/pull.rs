//! ADR-035 pull-loop driver (H6). The client-side control flow that replaces SPEC-013 push:
//! maintain exactly ONE outstanding `next-record` per room, feed each verified response to the
//! reducer, advance the cursor by one. This is the pure driver; the socket + async runtime are
//! the `chat.rs` shell (it calls `next_pull` to get the frame to send, and `on_record` with each
//! verified response).

use super::{transition_record, ClientLog, RecordResponse, Verdict};

/// The per-room pull state.
pub struct PullDriver {
    log: ClientLog,
    outstanding: bool,
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
    pub fn new(log: ClientLog) -> Self {
        Self { log, outstanding: false }
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

    /// Feed a verified record response to the reducer. On C-APPLIED advance the cursor by one;
    /// on notNext hold it; on Violation hold the cursor and group (the shell surfaces it). The
    /// outstanding-pull slot is freed either way so the loop can re-pull.
    pub fn on_record(&mut self, ds_vk: &[u8; 32], resp: &RecordResponse) -> Verdict {
        self.outstanding = false;
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

    fn signed_record(seq: i64, prev_hash: &str, ds: &Ed25519Keypair) -> RecordResponse {
        let rec = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("log-v1".into())),
            SExpr::Atom(Atom::Str("room-alpha".into())),
            SExpr::Atom(Atom::Num(seq)),
            SExpr::Atom(Atom::Str(prev_hash.into())),
        ]);
        let rh = record_hash(&rec);
        let sig = DomainTuple::Record { log_record: rec.clone() }.sign(ds);
        RecordResponse { seq, prev_hash: prev_hash.into(), record_hash: rh, record_signature: sig, log_record: rec }
    }

    #[test]
    fn single_outstanding_pull_and_cursor_advance() {
        let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
        let vk = ds.public_bytes();
        let mut d = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() });

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
}
