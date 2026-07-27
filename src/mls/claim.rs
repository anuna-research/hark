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

/// Contention on the EPOCH path. Deliberately distinct from `groupinfo-claimed`,
/// which is the same underlying claim refusing a *joiner* — a client that cannot
/// tell which mechanism refused it cannot tell what to do about it.
pub const CLAIMED_SLUG: &str = "epoch-claimed";

/// The requester holds no claim to arm or release. **Not** a retry: it means
/// take a claim first. A client that conflates this with contention either
/// spins waiting for a holder that does not exist, or gives up on a claim it
/// could simply have taken.
pub const NO_CLAIM_SLUG: &str = "epoch-no-claim";

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

/// A grant the hub issued: the epoch it covers, the token that proves
/// holdership, and the state it is in.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Grant {
    pub epoch: u64,
    /// **The thing that survives a restart.** A returning committer has a new
    /// process and a new connection, so the token is the only evidence tying it
    /// to what it reserved — and `epocharm` is available *only* to the holder,
    /// matched by token. Losing it means losing the claim and the promise with
    /// it, which is why it belongs in the durable operation record
    /// ([[SPEC-027 REQ-012]]) and not merely in memory.
    pub token: String,
    pub state: ClaimState,
}

/// How to treat a refusal ([[SPEC-027 REQ-002]]).
///
/// Three classes, not two, and they are distinguished by **what makes each one
/// clear** — which is the only thing a retry loop can act on.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Refusal {
    /// Another committer holds the epoch. It will clear; retry on the schedule.
    Contended,
    /// We hold no claim to arm or release. Clears immediately by taking one —
    /// so it is neither a wait nor a failure, and treating it as either is a
    /// spin or a needless abandonment.
    NoClaim,
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
///
/// `token` is `None` on a first claim — the hub mints one and returns it in the
/// grant — and `Some` when reacquiring, which is the path that matters: after a
/// restart the process and the connection are both new, and the token is the
/// only thing that identifies us as the existing holder rather than a rival.
pub fn epochclaim_frame(room: &str, epoch: u64, from: &str, token: Option<&str>) -> String {
    epoch_frame("epochclaim", room, epoch, from, token)
}

/// Turn a reservation into the promise ([[SPEC-063]] REQ-007). Requires the
/// token: arming is available only to the holder, and the hub matches on it.
pub fn epocharm_frame(room: &str, epoch: u64, from: &str, token: &str) -> String {
    epoch_frame("epocharm", room, epoch, from, Some(token))
}

/// End the claim, once the Commit has been echoed AND any deferred Welcome
/// sent ([[SPEC-027 REQ-014]]).
pub fn epochrelease_frame(room: &str, epoch: u64, from: &str, token: &str) -> String {
    epoch_frame("epochrelease", room, epoch, from, Some(token))
}

fn epoch_frame(verb: &str, room: &str, epoch: u64, from: &str, token: Option<&str>) -> String {
    match token {
        Some(token) => format!("({verb} {room} :epoch {epoch} :token \"{token}\" :from {from})"),
        None => format!("({verb} {room} :epoch {epoch} :from {from})"),
    }
}

/// The capability name hark declares to say it implements the epoch protocol:
/// the lowercase-hex SHA-256 of the `mls-epoch` grammar, computed from the bytes
/// hark itself holds ([[SPEC-063]] CON-004).
///
/// Not a hand-written version string. Two stacks can both write `v1` and mean
/// different things; two stacks cannot both present the same digest and mean
/// different things. And because the digest is computed rather than told, there
/// is no bootstrap frame to trust and nothing to spoof.
///
/// The sharp edge, which is deliberate: **editing that file is a protocol
/// change.** Even a comment changes the digest, which empties the capability
/// intersection and deactivates the mechanism in every mixed room until both
/// stacks carry the new bytes. Fail-closed, and silent unless something checks —
/// which is what `mls_epoch_fixture_matches_the_canonical_cbcl_bus_grammar`
/// is for.
pub fn capability_name() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(EPOCH_GRAMMAR);
    format!("{:x}", hasher.finalize())
}

/// The grammar whose digest is the capability. Byte-identical to the hub's
/// canonical copy, enforced by a drift guard in `tests/join_cli.rs`.
pub const EPOCH_GRAMMAR: &[u8] = include_bytes!("../dialects/mls-epoch.cbcl");

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
    let mut token: Option<String> = None;
    let mut state: Option<ClaimState> = None;
    let mut index = 2;
    while index + 1 < items.len() {
        if let SExpr::Atom(Atom::Keyword(keyword)) = &items[index] {
            match (keyword.as_str(), items.get(index + 1)) {
                ("epoch", Some(SExpr::Atom(Atom::Num(value)))) if *value >= 0 => {
                    epoch = Some(*value as u64);
                }
                ("token", Some(SExpr::Atom(Atom::Str(value))))
                | ("token", Some(SExpr::Atom(Atom::Symbol(value)))) => {
                    token = Some(value.clone());
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
        token: token?,
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
        Some(NO_CLAIM_SLUG) => Some(Refusal::NoClaim),
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

/// Evidence that an **armed** claim is held for a particular room and epoch.
///
/// Constructible only from a hub grant that says `:state armed`, so a value of
/// this type *is* RFC 9420 §3.2's promise. That is the point of it being a type
/// rather than a boolean: [`super::group::add_member`] cannot be called without
/// one, so "arm before merging" ([[SPEC-027 REQ-001]]) is a thing the compiler
/// checks rather than a thing the state machine must remember.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArmedClaim {
    room: String,
    epoch: u64,
    token: String,
}

impl ArmedClaim {
    /// Promote a grant to evidence, if it is armed and names `room`.
    ///
    /// A `claimed` grant is a reservation, not a promise, and returns `None`.
    /// The distinction is the one cbcl-bus's intent-stamping bug got wrong, and
    /// the one a merge must not blur.
    pub fn from_grant(grant: &Grant, room: &str) -> Option<Self> {
        match grant.state {
            ClaimState::Armed => Some(Self {
                room: room.to_owned(),
                epoch: grant.epoch,
                token: grant.token.clone(),
            }),
            ClaimState::Claimed => None,
        }
    }

    /// Does this promise cover a commit against `room` at `epoch`?
    ///
    /// The epoch check is not ceremony. A grant is for the epoch it names, and
    /// the group can move underneath us between arming and merging — another
    /// member's Commit landing, or our own reconnect replaying history. Merging
    /// against a different epoch than the one promised is merging on nothing.
    pub fn covers(&self, room: &str, epoch: u64) -> bool {
        self.room == room && self.epoch == epoch
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// What a caller of the commit path is standing on ([[SPEC-027 REQ-001]],
/// [[SPEC-027 REQ-002]]).
///
/// Two variants and no default, so every call site says which world it is in.
/// A default would make the dangerous case the quiet one: committing unclaimed
/// in a room that *has* activated the protocol is exactly the false promise
/// SPEC-063 exists to prevent, and it would look like ordinary code.
#[derive(Debug, Clone, Copy)]
pub enum CommitPromise<'a> {
    /// The room has not activated the epoch protocol — the capability is not
    /// unanimous across present members, so the hub refuses claims with
    /// `epoch-claim-inactive` and every client commits as it did before.
    ///
    /// RFC 9420 §14 is unsatisfied for such a room. That is the status quo
    /// rather than a regression, and it is why activation is unanimous: a
    /// promise some members keep is worse than one nobody makes.
    Inactive,
    /// An armed claim is held for this room and epoch.
    Armed(&'a ArmedClaim),
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
        // First claim: no token yet — the hub mints one and returns it.
        let first = epochclaim_frame("@research", 7, "@aria", None);
        assert_eq!(first, "(epochclaim @research :epoch 7 :from @aria)");

        // Reacquisition: the token is the ONLY thing tying a new process and a
        // new connection to what it already reserved.
        let again = epochclaim_frame("@research", 7, "@aria", Some("deadbeef"));
        assert_eq!(
            again,
            "(epochclaim @research :epoch 7 :token \"deadbeef\" :from @aria)"
        );

        // Arming and releasing are holder-only, so both always carry it.
        assert_eq!(
            epocharm_frame("@research", 7, "@aria", "deadbeef"),
            "(epocharm @research :epoch 7 :token \"deadbeef\" :from @aria)"
        );
        assert_eq!(
            epochrelease_frame("@research", 7, "@aria", "deadbeef"),
            "(epochrelease @research :epoch 7 :token \"deadbeef\" :from @aria)"
        );

        for frame in [first, again] {
            assert!(
                cbcl_parser::parse(&frame).is_ok(),
                "every claim frame must be valid CBCL or the hub will not parse it"
            );
        }
    }

    /// SPEC-063 CON-004 — the capability is the grammar's digest, computed from
    /// the bytes hark holds rather than from a version string it asserts.
    ///
    /// Pinned against the hub's canonical value. If this fails, hark and the hub
    /// disagree about what "implements the epoch protocol" means, and the
    /// consequence is *silence*: the room's capability intersection empties and
    /// the mechanism deactivates rather than misbehaving.
    #[test]
    fn the_capability_is_the_epoch_grammar_digest() {
        assert_eq!(
            capability_name(),
            "ae36fe37a70e714e9159a532c14c2ed2395b76b795b0c5d27fa950c9cde43e80",
            "hark's declared capability must equal the hub's \
             cbcl-chat-dialects:epoch-dialect-digest for the same bytes"
        );
        assert_eq!(capability_name().len(), 64, "lowercase hex sha256");
        assert!(
            capability_name()
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "lowercase, matching the hub's binary:encode_hex(_, 'lowercase)"
        );
    }

    /// CON-001 (positive) — a grant for this room is recognised, and its STATE
    /// is read from the frame.
    #[test]
    fn a_grant_for_this_room_yields_its_epoch_and_state() {
        assert_eq!(
            granted(
                "(epochgranted @research :epoch 7 :token \"ab12\" :state claimed)",
                "@research"
            ),
            Some(Grant {
                epoch: 7,
                token: "ab12".to_owned(),
                state: ClaimState::Claimed
            })
        );
        assert_eq!(
            granted(
                "(epochgranted @research :epoch 7 :token \"ab12\" :state armed)",
                "@research"
            ),
            Some(Grant {
                epoch: 7,
                token: "ab12".to_owned(),
                state: ClaimState::Armed
            })
        );
        // A grant with no token is not usable: arming and releasing are
        // holder-only and matched on it, so we could never do either.
        assert_eq!(
            granted("(epochgranted @research :epoch 7 :state armed)", "@research"),
            None,
            "a tokenless grant cannot be armed or released, so it is not a grant"
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
            "(epochgranted @research :epoch 7 :token \"ab12\" :state armed)",
            "@research",
        )
        .expect("a reacquisition is a grant");
        assert_eq!(
            reacquired.state,
            ClaimState::Armed,
            "the reply to an epochclaim can legitimately be `armed`"
        );

        // A grant with no state is not a grant: there is nothing to gate on.
        assert_eq!(
            granted("(epochgranted @research :epoch 7 :token \"ab12\")", "@research"),
            None
        );
        // Nor is an unrecognised state — guessing is how a client merges on
        // something it does not understand.
        assert_eq!(
            granted(
                "(epochgranted @research :epoch 7 :token \"ab12\" :state pending)",
                "@research"
            ),
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
            "(epochgranted @research :epoch 7 :token \"ab12\" :state armed :from @mallory)",
            "(epochgranted @research :from @mallory :epoch 7 :token \"ab12\" :state armed)",
            // Our own handle confers nothing: provenance is about the hub, not
            // about who looks friendly.
            "(epochgranted @research :epoch 7 :token \"ab12\" :state armed :from @aria)",
        ] {
            assert_eq!(
                granted(forged, "@research"),
                None,
                "a frame carrying :from came from a member, not the hub: {forged}"
            );
        }
        assert!(
            granted(
                "(epochgranted @research :epoch 7 :token \"ab12\" :state armed)",
                "@research"
            )
            .is_some(),
            "and the genuine hub frame, which carries no :from, still works"
        );
    }

    /// CON-001 (negative-input) — a grant for ANOTHER room is not a grant.
    /// Accepting one would let a session merge against an epoch nobody promised
    /// it, which is the exact failure the claim prevents.
    #[test]
    fn a_grant_for_another_room_is_not_a_grant() {
        assert_eq!(
            granted(
                "(epochgranted @other :epoch 7 :token \"ab12\" :state armed)",
                "@research"
            ),
            None
        );
        assert_eq!(
            granted(
                "(tell @research \"epochgranted\" :epoch 7 :token \"ab12\" :state armed)",
                "@research"
            ),
            None
        );
        assert_eq!(
            granted("(epochgranted @research :token \"ab12\" :state armed)", "@research"),
            None
        );
        assert_eq!(
            granted(
                "(epochgranted @research :epoch -1 :token \"ab12\" :state armed)",
                "@research"
            ),
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
            refusal("(error @research \"epoch-claimed\")", "@research"),
            Some(Refusal::Contended)
        );
        assert_eq!(
            refusal("(error @research \"epoch-no-claim\")", "@research"),
            Some(Refusal::NoClaim),
            "no-claim clears by taking a claim — neither a wait nor a failure"
        );
        // The JOINER path's contention slug is a different mechanism refusing a
        // different thing, and must not be read as an epoch refusal.
        assert_eq!(
            refusal("(error @research \"groupinfo-claimed\")", "@research"),
            None
        );
        assert_eq!(
            refusal("(error @research \"epoch-claim-inactive\")", "@research"),
            Some(Refusal::Inactive)
        );
        // Another room's refusal is not ours.
        assert_eq!(
            refusal("(error @other \"epoch-claimed\")", "@research"),
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

    /// REQ-001 — a *reservation* is not a promise, and cannot become one by
    /// being mistaken for one.
    #[test]
    fn only_an_armed_grant_becomes_evidence() {
        let claimed = Grant {
            epoch: 7,
            token: "tok".to_owned(),
            state: ClaimState::Claimed,
        };
        assert_eq!(
            ArmedClaim::from_grant(&claimed, "@research"),
            None,
            "a claimed grant is a reservation the hub may take back — merging on \
             it is merging on nothing"
        );

        let armed = Grant {
            state: ClaimState::Armed,
            ..claimed
        };
        let evidence = ArmedClaim::from_grant(&armed, "@research").expect("armed is a promise");
        assert_eq!(evidence.token(), "tok");
        assert_eq!(evidence.epoch(), 7);
    }

    /// REQ-001 — the promise covers ONE room at ONE epoch. The group can move
    /// under us between arming and merging (another member's Commit, or a
    /// reconnect replaying history), and a promise for a different epoch is not
    /// a promise for this one.
    #[test]
    fn a_promise_covers_only_the_room_and_epoch_it_names() {
        let armed = Grant {
            epoch: 7,
            token: "tok".to_owned(),
            state: ClaimState::Armed,
        };
        let evidence = ArmedClaim::from_grant(&armed, "@research").expect("armed");

        assert!(evidence.covers("@research", 7));
        assert!(
            !evidence.covers("@research", 8),
            "the epoch moved under us: this promise no longer applies"
        );
        assert!(
            !evidence.covers("@research", 6),
            "nor does it apply backwards"
        );
        assert!(!evidence.covers("@other", 7), "nor to another room");
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
