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

/// The hub's refusal when the room has not activated `epoch-claim/v1` — the
/// capability is not unanimous across present members
/// ([[SPEC-063-one-committer-per-epoch]] REQ-006).
///
/// **This is the trap, and it is why refusals are classified rather than
/// counted.** It looks exactly like contention and is nothing like it: a
/// contended claim clears when the holder is done, in seconds, so retrying is
/// correct. An inactive room clears only when its *membership* changes — a
/// legacy client leaving, or upgrading. Retrying it on a backoff turns an
/// ordinary rollout into a hot loop against a hub that will refuse every
/// attempt for as long as that client stays connected.
pub const INACTIVE_SLUG: &str = "epoch-claim-inactive";

/// Which claim state the hub reports ([[SPEC-063-one-committer-per-epoch]]).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClaimState {
    /// A reservation. The holder has merged nothing, so nothing is promised and
    /// the hub may take it back on death or epoch advance.
    Claimed,
    /// The holder has declared it is about to merge. From here a release is a
    /// fork, so it survives the holder's death and the hub's restart, and only
    /// the holder can release it.
    Armed,
}

/// A grant the hub issued: the epoch it covers and the state it is in.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Grant {
    pub epoch: u64,
    pub state: ClaimState,
}

/// How to treat a refusal ([[SPEC-027 REQ-002]]).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Refusal {
    /// Another committer holds the epoch. It will clear; retry on the schedule.
    Contended,
    /// The room has not activated the capability. Retrying cannot help — this
    /// clears on a membership change, not with time — so it must NOT consume
    /// the retry schedule or the starvation budget.
    Inactive,
}

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

/// The grant an `(epochgranted @room :epoch N :state claimed|armed)` frame
/// carries, if `text` is one for `room` **and the hub is the party that said
/// it**.
///
/// The state is read from the frame, never assumed from what we asked for.
/// [[SPEC-063-one-committer-per-epoch]] REQ-007 makes `:state armed` the
/// observable that gates a merge — precisely because "hold the grant before
/// merging" named no frame, so a client could obey it sincerely and still merge
/// on a reservation. A client that inferred the state from its own request
/// would reintroduce that: a holder reacquiring after a restart asks with
/// `epochclaim` while it is still *armed*, and must be told so.
///
/// The room is checked here rather than by the caller because a grant for
/// another room is not a grant — and a session that accepted one would commit
/// against an epoch nobody promised it.
///
/// **Provenance is checked, and it is the load-bearing part.** The grant is the
/// whole of RFC 9420 §3.2's promise; a committer that accepts a forged one
/// merges eagerly with no exclusivity behind it, which is exactly the conflict
/// the claim exists to prevent — reached by trusting the thing that prevents it.
/// Any member can publish arbitrary room frames and the hub fans them, so
/// `(epochgranted @room :epoch 7 :from @mallory)` would otherwise be
/// indistinguishable from a real grant.
///
/// The discriminator is the **absence of `:from`**. cbcl-chat requires `:from`
/// on every member-authored room frame and refuses one without it as
/// `missing-from`, never fanning it — so a frame that reached us carrying no
/// `:from` cannot have come from a member. Hub-originated frames carry none.
///
/// This is the client half only. The hub MUST also refuse a member-authored
/// `epochgranted` at ingress ([[SPEC-027 REQ-011]]): a rule enforced solely by
/// the party it protects is not a rule, and a client that dropped this check
/// would be the only thing standing between a member and a forged promise.
pub fn granted(text: &str, room: &str) -> Option<Grant> {
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
    // A member cannot omit `:from` (the hub refuses the frame); the hub does not
    // add one. So its presence means this did not come from the hub.
    if items.iter().any(
        |item| matches!(item, SExpr::Atom(Atom::Keyword(keyword)) if keyword == "from"),
    ) {
        return None;
    }
    let mut epoch: Option<u64> = None;
    let mut state: Option<ClaimState> = None;
    let mut index = 2;
    while index + 1 < items.len() {
        if let SExpr::Atom(Atom::Keyword(keyword)) = &items[index] {
            match (keyword.as_str(), items.get(index + 1)) {
                ("epoch", Some(SExpr::Atom(Atom::Num(value)))) if *value >= 0 => {
                    epoch = Some(*value as u64);
                }
                ("state", Some(SExpr::Atom(Atom::Symbol(word))))
                | ("state", Some(SExpr::Atom(Atom::Str(word)))) => {
                    state = match word.as_str() {
                        "claimed" => Some(ClaimState::Claimed),
                        "armed" => Some(ClaimState::Armed),
                        // An unknown state is not a state. Guessing here is how
                        // a client merges on something it does not understand.
                        _ => return None,
                    };
                }
                _ => {}
            }
        }
        index += 2;
    }
    Some(Grant {
        epoch: epoch?,
        state: state?,
    })
}

/// Classify a hub refusal for `room`, or `None` if `text` is not one.
///
/// The two are deliberately not merged into a boolean. They differ in the only
/// dimension that matters to a retry loop: what makes them clear.
pub fn refusal(text: &str, room: &str) -> Option<Refusal> {
    match error_slug_for(text, room).as_deref() {
        Some(CLAIMED_SLUG) => Some(Refusal::Contended),
        Some(INACTIVE_SLUG) => Some(Refusal::Inactive),
        _ => None,
    }
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

    /// CON-001 (positive) — a grant for this room is recognised, and its STATE
    /// is read from the frame.
    #[test]
    fn a_grant_for_this_room_yields_its_epoch_and_state() {
        assert_eq!(
            granted("(epochgranted @research :epoch 7 :state claimed)", "@research"),
            Some(Grant {
                epoch: 7,
                state: ClaimState::Claimed
            })
        );
        assert_eq!(
            granted("(epochgranted @research :epoch 7 :state armed)", "@research"),
            Some(Grant {
                epoch: 7,
                state: ClaimState::Armed
            })
        );
        assert_eq!(
            granted("(epochgranted @research :epoch 0 :state claimed)", "@research"),
            Some(Grant {
                epoch: 0,
                state: ClaimState::Claimed
            }),
            "epoch zero is a real epoch — a group's first"
        );
    }

    /// SPEC-063 REQ-007 — **the state is never inferred from what we asked
    /// for.** A holder reacquiring after a restart asks with `epochclaim` while
    /// it is still armed, and the hub answers `armed`. A client that assumed
    /// `claimed` because it sent `epochclaim` would read "I lost my promise"
    /// exactly when it most needs to know it hasn't — and would then re-merge
    /// on a reservation.
    #[test]
    fn the_state_comes_from_the_frame_not_from_the_request() {
        let reacquired = granted(
            "(epochgranted @research :epoch 7 :state armed)",
            "@research",
        )
        .expect("a reacquisition is a grant");
        assert_eq!(
            reacquired.state,
            ClaimState::Armed,
            "the reply to an epochclaim can legitimately be `armed`"
        );

        // A grant with no state is not a grant: there is nothing to gate on.
        assert_eq!(granted("(epochgranted @research :epoch 7)", "@research"), None);
        // Nor is an unrecognised state — guessing is how a client merges on
        // something it does not understand.
        assert_eq!(
            granted("(epochgranted @research :epoch 7 :state pending)", "@research"),
            None
        );
    }

    /// CON-001 (negative-input) — **a member cannot forge a grant.**
    ///
    /// The hub fans arbitrary member-authored room frames, so without a
    /// provenance check `(epochgranted @research :epoch 7 :from @mallory)` reads
    /// as a hub grant. A committer accepting it merges eagerly with nothing
    /// guaranteeing exclusivity — the very conflict the claim prevents, produced
    /// by trusting the mechanism that prevents it.
    #[test]
    fn a_member_authored_grant_is_not_a_grant() {
        for forged in [
            "(epochgranted @research :epoch 7 :state armed :from @mallory)",
            "(epochgranted @research :from @mallory :epoch 7 :state armed)",
            // Our own handle confers nothing: provenance is about the hub, not
            // about who looks friendly.
            "(epochgranted @research :epoch 7 :state armed :from @aria)",
        ] {
            assert_eq!(
                granted(forged, "@research"),
                None,
                "a frame carrying :from came from a member, not the hub: {forged}"
            );
        }
        assert!(
            granted("(epochgranted @research :epoch 7 :state armed)", "@research").is_some(),
            "and the genuine hub frame, which carries no :from, still works"
        );
    }

    /// CON-001 (negative-input) — a grant for ANOTHER room is not a grant.
    /// Accepting one would let a session merge against an epoch nobody promised
    /// it, which is the exact failure the claim prevents.
    #[test]
    fn a_grant_for_another_room_is_not_a_grant() {
        assert_eq!(
            granted("(epochgranted @other :epoch 7 :state armed)", "@research"),
            None
        );
        assert_eq!(
            granted(
                "(tell @research \"epochgranted\" :epoch 7 :state armed)",
                "@research"
            ),
            None
        );
        assert_eq!(
            granted("(epochgranted @research :state armed)", "@research"),
            None
        );
        assert_eq!(
            granted("(epochgranted @research :epoch -1 :state armed)", "@research"),
            None,
            "a negative epoch is malformed, not epoch 0"
        );
        assert_eq!(granted("not cbcl at all", "@research"), None);
    }

    /// SPEC-027 REQ-002 — the two refusals are classified, not counted.
    ///
    /// They differ in the only dimension a retry loop cares about: what makes
    /// them clear. Contention clears when the holder finishes, in seconds.
    /// `epoch-claim-inactive` clears on a MEMBERSHIP change — a legacy client
    /// leaving or upgrading — so retrying it on a backoff turns an ordinary
    /// rollout into a hot loop against a hub that will refuse every attempt.
    #[test]
    fn refusals_are_classified_by_what_makes_them_clear() {
        assert_eq!(
            refusal("(error @research \"groupinfo-claimed\")", "@research"),
            Some(Refusal::Contended)
        );
        assert_eq!(
            refusal("(error @research \"epoch-claim-inactive\")", "@research"),
            Some(Refusal::Inactive)
        );
        // Another room's refusal is not ours.
        assert_eq!(
            refusal("(error @other \"groupinfo-claimed\")", "@research"),
            None
        );
        // And an unrelated error is neither.
        assert_eq!(
            refusal("(error @research \"not-a-member\")", "@research"),
            None
        );
        assert_eq!(
            refusal("(error @research \"no-groupinfo\")", "@research"),
            None
        );
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
