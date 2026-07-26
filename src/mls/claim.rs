//! [[SPEC-027 CON-001]] — the epoch claim, pure half.
//!
//! RFC 9420 §14 requires an application to have an established way to resolve
//! Commits that conflict in an epoch. hark's is prevention: a committer takes an
//! exclusive claim on the epoch before it generates anything, so no second
//! Commit for that epoch can exist. Holding the claim is what §3.2 calls "a
//! promise from an orchestration server" that this Commit is next — and holding
//! it is what makes hark's eager merge conformant rather than merely lucky.
//!
//! This module is the part with no I/O: building the request, recognising the
//! two answers, and counting refusals against the starvation budget. The state
//! machine that uses it lives in [`super::session`].
//!
//! **The claim confers no authority** ([[SPEC-027 ADR-003]]). It sequences; it
//! does not admit. Every member still validates every Commit on exactly the
//! terms it does today, and a Commit from a claim holder is admitted on no
//! different terms from any other. If members deferred to the claim, admission
//! would have passed to whoever grants claims — the hub — which is the property
//! [[SPEC-061]] NFR-001 exists to protect.

use cbcl_core::sexpr::{Atom, SExpr};

/// The error slug the hub answers a contended claim with. Deliberately the same
/// slug `groupinfoget` already uses: both verbs contend for one claim, because
/// an external joiner and a member committer both move the epoch and must
/// therefore exclude each other.
pub const CLAIMED_SLUG: &str = "groupinfo-claimed";

/// [[SPEC-027 NFR-001]]: consecutive refusals tolerated before the condition is
/// surfaced rather than retried again.
///
/// RFC 9420 §14 names this failure — "a given member may never be able to send a
/// Commit message because they always lose to other members" — and declines to
/// solve it, leaving it to the application. Ten is not a tuned number: it is a
/// threshold above which the *dynamics* have gone wrong rather than any
/// individual attempt. The requirement is that it becomes visible, not that it
/// be resolved automatically.
pub const REFUSAL_BUDGET: u32 = 10;

/// The claim request for `room` at `epoch`, sent by `from`.
pub fn epochclaim_frame(room: &str, epoch: u64, from: &str) -> String {
    format!("(epochclaim {room} :epoch {epoch} :from {from})")
}

/// The epoch an `(epochgranted @room :epoch N)` frame grants, if `text` is one
/// for `room`.
///
/// The room is checked here rather than by the caller because a grant for
/// another room is not a grant — and a session that accepted one would commit
/// against an epoch nobody promised it.
pub fn granted_epoch(text: &str, room: &str) -> Option<u64> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(head)) if head == "epochgranted" => {}
        _ => return None,
    }
    match items.get(1)? {
        SExpr::Atom(Atom::Symbol(named)) if named == room => {}
        _ => return None,
    }
    let mut index = 2;
    while index + 1 < items.len() {
        if let SExpr::Atom(Atom::Keyword(keyword)) = &items[index] {
            if keyword == "epoch" {
                return match items.get(index + 1) {
                    Some(SExpr::Atom(Atom::Num(epoch))) if *epoch >= 0 => Some(*epoch as u64),
                    _ => None,
                };
            }
        }
        index += 2;
    }
    None
}

/// Whether `text` is the hub refusing a claim for `room` — the retry answer.
pub fn is_claim_refusal(text: &str, room: &str) -> bool {
    error_slug_for(text, room).as_deref() == Some(CLAIMED_SLUG)
}

/// The slug of an `(error @room "slug")` frame addressed to `room`.
fn error_slug_for(text: &str, room: &str) -> Option<String> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(head)) if head == "error" => {}
        _ => return None,
    }
    match items.get(1)? {
        SExpr::Atom(Atom::Symbol(named)) if named == room => {}
        _ => return None,
    }
    items.iter().find_map(|item| match item {
        SExpr::Atom(Atom::Str(slug)) => Some(slug.clone()),
        _ => None,
    })
}

/// Tracks consecutive refusals for one pending commit ([[SPEC-027 NFR-001]]).
#[derive(Debug, Clone, Default)]
pub struct RefusalBudget {
    consecutive: u32,
}

impl RefusalBudget {
    /// A refusal arrived. Returns `true` while the budget still permits a retry,
    /// `false` once it is exhausted and the caller must surface the condition.
    pub fn refused(&mut self) -> bool {
        self.consecutive = self.consecutive.saturating_add(1);
        self.consecutive < REFUSAL_BUDGET
    }

    /// A claim was granted: the run of refusals is over.
    pub fn granted(&mut self) {
        self.consecutive = 0;
    }

    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }

    pub fn exhausted(&self) -> bool {
        self.consecutive >= REFUSAL_BUDGET
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST-001/CON-001 (positive) — the request is well-formed CBCL and carries
    /// the epoch it is claiming, which is the whole content of the promise.
    #[test]
    fn the_request_names_the_room_epoch_and_sender() {
        let frame = epochclaim_frame("@research", 7, "@aria");
        assert_eq!(frame, "(epochclaim @research :epoch 7 :from @aria)");
        assert!(
            cbcl_parser::parse(&frame).is_ok(),
            "the claim must be valid CBCL or the hub will not parse it"
        );
    }

    /// CON-001 (positive) — a grant for this room at this epoch is recognised.
    #[test]
    fn a_grant_for_this_room_yields_its_epoch() {
        assert_eq!(
            granted_epoch("(epochgranted @research :epoch 7)", "@research"),
            Some(7)
        );
        assert_eq!(
            granted_epoch("(epochgranted @research :epoch 0)", "@research"),
            Some(0),
            "epoch zero is a real epoch — a group's first"
        );
    }

    /// CON-001 (negative-input) — the load-bearing one. A grant for ANOTHER room
    /// is not a grant. Accepting it would let a session commit against an epoch
    /// nobody promised it, which is the exact failure the claim prevents.
    #[test]
    fn a_grant_for_another_room_is_not_a_grant() {
        assert_eq!(
            granted_epoch("(epochgranted @other :epoch 7)", "@research"),
            None
        );
        // Nor is a differently-shaped frame that merely mentions the room.
        assert_eq!(
            granted_epoch("(tell @research \"epochgranted\" :epoch 7)", "@research"),
            None
        );
        assert_eq!(granted_epoch("(epochgranted @research)", "@research"), None);
        assert_eq!(
            granted_epoch("(epochgranted @research :epoch -1)", "@research"),
            None,
            "a negative epoch is malformed, not epoch 0"
        );
        assert_eq!(granted_epoch("not cbcl at all", "@research"), None);
    }

    /// CON-001 (positive + negative-input) — a refusal is recognised only for
    /// this room, and only for the claim slug. `no-groupinfo` is a different
    /// answer and must not be read as "someone else holds it".
    #[test]
    fn only_this_rooms_claim_slug_is_a_refusal() {
        assert!(is_claim_refusal(
            "(error @research \"groupinfo-claimed\")",
            "@research"
        ));
        assert!(!is_claim_refusal(
            "(error @other \"groupinfo-claimed\")",
            "@research"
        ));
        assert!(!is_claim_refusal(
            "(error @research \"no-groupinfo\")",
            "@research"
        ));
        assert!(!is_claim_refusal(
            "(error @research \"not-a-member\")",
            "@research"
        ));
    }

    /// NFR-001 — the budget permits nine retries and then stops, rather than
    /// retrying for ever. A silent eleventh attempt is the failure mode §14
    /// warns about and the operator cannot see.
    #[test]
    fn the_refusal_budget_stops_at_the_threshold() {
        let mut budget = RefusalBudget::default();
        for attempt in 1..REFUSAL_BUDGET {
            assert!(
                budget.refused(),
                "refusal {attempt} is within the budget of {REFUSAL_BUDGET}"
            );
            assert!(!budget.exhausted());
        }
        assert!(
            !budget.refused(),
            "the {REFUSAL_BUDGET}th refusal exhausts the budget"
        );
        assert!(budget.exhausted());
        assert_eq!(budget.consecutive(), REFUSAL_BUDGET);
    }

    /// NFR-001 — "consecutive" is load-bearing: a grant resets the run, so an
    /// agent that loses nine races and then wins is not one refusal away from
    /// being reported as starved for the rest of its life.
    #[test]
    fn a_grant_resets_the_run_of_refusals() {
        let mut budget = RefusalBudget::default();
        for _ in 0..(REFUSAL_BUDGET - 1) {
            budget.refused();
        }
        assert_eq!(budget.consecutive(), REFUSAL_BUDGET - 1);

        budget.granted();

        assert_eq!(budget.consecutive(), 0);
        assert!(!budget.exhausted());
        assert!(budget.refused(), "the budget is whole again");
    }
}
