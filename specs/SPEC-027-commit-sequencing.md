---
id: SPEC-027
title: Commit Sequencing — hark's obligations under the epoch claim (RFC 9420 §14)
status: draft
tier: 1 (MLS group state and admission — cross-model adversarial review AND human security sign-off REQUIRED before merge; green tests are not sufficient)
version: 0.3.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 5)
last-updated: 2026-07-27
owner-repo: hark
affects-repos: none — cbcl-bus owns the protocol in SPEC-063; this document owns only what hark must do to honour it
depends-on: SPEC-063 (one committer per epoch — cbcl-bus; OWNS the wire contract, the claim states and the activation rule), SPEC-013 (MLS private channels — REQ-012b elected committer), SPEC-061 (external Commit admission — REQ-005, the GroupInfo claim), SPEC-024 ADR-011 (`seq == head + 1`, which supersedes this for its own rooms)
traces-to: "anuna-research/hark#27, raised from cbcl-bus#44; cbcl-bus PR#45 built the first half"
---

# SPEC-027 — Commit Sequencing: Honouring the Epoch Claim

## Orientation

**Intent.** Two members of one MLS group can generate Commits for the same epoch at the same
moment. RFC 9420 requires an application to have an *established* way to resolve that, and
hark currently has none: it merges and persists its own Commit before anyone has accepted it.
The remedy is an exclusive per-epoch claim, and **[[SPEC-063-one-committer-per-epoch]]
(cbcl-bus) owns it** — the wire verbs, the claim states, and when the behaviour activates.

**This document owns hark's half and nothing else**: what hark must do to hold the promise
honestly, what it must make durable, and what it must not do while holding one. Where a
statement here would restate SPEC-063, it points instead — two documents describing one
contract is how they drift.

**Metaphor.** *A talking stick.* Anyone may want to speak; only the holder does. The stick
does not decide who is right, and handing it over is not endorsement — it is only the rule
that stops two people speaking at once. Whoever holds it may speak immediately, without
waiting to hear themselves back.

**Structure.**

```
   hark agent                     hub (cbcl-bus)                 web client
  ┌──────────────┐               ┌───────────────┐             ┌────────────┐
  │ MlsSession   │──epochclaim──▶│ claim table   │◀──epochclaim─│ mls.js     │
  │  (CON-001)   │◀──granted /───│ room→(epoch,  │──granted /──▶│            │
  │              │   claimed     │  connection)  │   claimed    │            │
  │              │               │  (SPEC-061)   │             │            │
  │  add_member  │               └───────┬───────┘             └────────────┘
  │  remove_member│                      │ released by: epoch advance,
  │   (CON-002)  │                       │ connection death
  └──────┬───────┘
         │ holds the claim ⇒ §3.2 promise ⇒ eager merge is legal
         ▼
   merge + persist + send commit, THEN welcome (CON-003)
```

**Decisions.** [[#ADR-001]] claim rather than stage · [[#ADR-004]] bounded deferral with a
starvation escape. ([[#ADR-002]], [[#ADR-003]] and [[#ADR-005]] were settled here and are now
owned by [[SPEC-063-one-committer-per-epoch]]; they are retained as the record of *why*.)

**Load-bearing.** [[#REQ-001]] arm the claim before merging · [[#REQ-003]] the Welcome waits
for acceptance · [[#REQ-012]] one durable operation record carrying the Commit *and* the
Welcome · [[#REQ-014]] release only after both are out · [[#NFR-001]] starvation bound.

**Open.** [[#OQ-001]] what a committer does against a hub that serves no claim; [[#OQ-002]]
whether [[SPEC-024-mls-ds-v1]] rooms need this at all, given `seq == head + 1` already sequences
them. ([[#OQ-003]], what counts as "accepted", was raised as blocking and is resolved — the
hub fans a sender its own frame back, and that echo is the signal.)

**Detail.** [[IMPL-027-commit-sequencing]] is the execution plan.
[[SPEC-063-one-committer-per-epoch]] is the protocol this implements.

---

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14
([RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119),
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174)) when, and only when, they appear
in all capitals.

## 1. What the RFC actually says

Quoted verbatim from [RFC 9420 §14](https://www.rfc-editor.org/rfc/rfc9420.txt), *Sequencing
of State Changes*, because every requirement below is a reading of it and a paraphrase would
let the reading drift:

> Applications MUST have an established way to resolve conflicting Commit messages for the
> same epoch. They can do this either by preventing conflicting messages from occurring in the
> first place, or by developing rules for deciding which Commit out of several sent in an
> epoch will be canonical. The approach chosen MUST minimize the amount of time that forked or
> previous group states are kept in memory, and promptly delete them once they're no longer
> necessary to ensure forward secrecy.
>
> The generation of Commit messages MUST NOT modify a client's state, since the client doesn't
> know at that time whether the changes implied by the Commit message will conflict with
> another Commit or not. Similarly, the Welcome message corresponding to a Commit MUST NOT be
> delivered to a new joiner until it's clear that the Commit has been accepted.
>
> Regardless of how messages are kept in sequence, there is a risk that in a sufficiently busy
> group, a given member may never be able to send a Commit message because they always lose to
> other members. The degree to which this is a practical problem will depend on the dynamics
> of the application.

And from [§3.2](https://www.rfc-editor.org/rfc/rfc9420.txt), *Group Evolution*:

> The sender of a Commit doesn't necessarily have to wait to receive its own Commit back before
> advancing its state. It only needs to know that its Commit will be the next one applied by
> the group, say based on a promise from an orchestration server.

**Three consequences, and the third is the one that shapes this design.**

1. The "MUST NOT modify state" of §14 is *conditioned*: it holds "since the client doesn't know
   at that time" whether its Commit will conflict. §3.2 names the escape explicitly — a promise
   from an orchestration server that this Commit is next. Hold the promise and the premise of
   the prohibition is gone.
2. The Welcome prohibition is **not** so conditioned. It is unqualified: not until it is clear
   the Commit has been accepted.
3. The paragraph the issue does not quote — *"MUST minimize the amount of time that forked or
   previous group states are kept in memory"* — is an argument **against** the obvious
   alternative. Staging a Commit and merging it on acceptance means holding a forked state for
   a network round trip, every time. Preventing the conflict holds no fork at all. The RFC lists
   prevention first for a reason, and this is it.

The last paragraph names **starvation** as a known cost of any sequencing scheme. Nothing in
issue #27 addresses it; [[#NFR-001]] does.

## 2. What hark does today

Two production paths generate Commits. Both have the same shape.

`src/mls/group.rs:535-541` (Add):

```rust
let (commit, welcome, _group_info) = group.add_members(provider, &identity.signer, &[kp])?;
group.merge_pending_commit(provider)?;   // state modified…
provider.persist()?;                      // …and made durable…
Ok(AddOutcome { commit_bytes, welcome_bytes })   // …before either is sent
```

`src/mls/removal.rs:255-262` (Remove) is identical in structure.

Three defects, and they are the same three the web client had:

- **State is modified at generation** — §14's unconditioned-on-a-promise prohibition, and hark
  holds no promise.
- **It is also persisted**, so a Commit that loses the race survives a daemon restart. The
  agent comes back into a group state the group never adopted.
- **The Welcome is returned for sending** in the same breath as the Commit, with no acceptance
  in between — §14's second, *unqualified* prohibition.

The conflict is real rather than theoretical: `src/mls/session.rs:720` commits an Add whenever
a `keypkg` arrives for a pinned, present, unadded member, and `src/mls/session.rs:836` commits
a Remove on evidence. Two agents that both consider themselves the elected owner, or an agent
and a web member acting at once, generate two Commits for one epoch. Today exactly one wins by
validation order and the loser silently desyncs — which is, in the issue's words, an accident
rather than a rule.

### BUG-001 — a self-commit leaves the room's GroupInfo stale

*Discovered while specifying this; adjacent, and fixed here because this work rewrites the
path.* **Severity:** S3 · **Priority:** P2 · **Status:** confirmed.

`MlsSession::on_keypkg` returns `deliver` + `welcome` after a successful Add and nothing else.
The fresh `(groupinfo …)` publication lives only on the *inbound* handshake path
(`src/mls/session.rs:686`), which does not fire for hark's own Commit. So after hark commits,
the hub still holds a GroupInfo for the epoch hark has just left. The hub's `put` is
forward-only, so it stays stale until some *other* member commits and publishes.

Consequence: an invitee redeeming an invitation into a channel whose most recent committer was
an agent fetches a GroupInfo whose epoch has passed, builds an external Commit on it, and is
refused for `WrongEpoch` — the exact failure [[SPEC-061]] REQ-005 exists to prevent, reached by
a different road. It is invisible today because the same agent usually receives another
member's handshake soon after.

**Resolution:** [[#REQ-004]], verified by [[#TEST-006]].

### 2.1 Where this work lives, and why it moved

[[SPEC-061]] BUG-021 is the parent. Its external-join half was fixed by REQ-005's second clause;
its remaining half was recorded there as needing *"a Delivery Service acceptance signal (SPEC-024
ADR-011 `seq == head + 1`)"*, and [[SPEC-061]] v0.8.0 said the artefact should be adopted by
SPEC-024.

**Settled otherwise, by cbcl-bus, and this document defers to it.** The protocol lives in
[[SPEC-063-one-committer-per-epoch]] — a separate spec rather than a SPEC-024 section, because
folding a chat-path claim into SPEC-024 would put two sequencing mechanisms for two kinds of room
in one document, and every later reader of ADR-011 would have to work out which applied to them.

The substantive half of that question is also settled: **the chat path gets a claim now, and
`mls-ds/v1` rooms are exempt** — `seq == head + 1` is a stronger and more general form of the same
property, and layering both would be two mechanisms on one path. See [[#OQ-002]].

## 3. Scope

**In scope — hark's obligations.** Arming before merging and the state machine that requires;
the durable operation record and its recovery rules; the Welcome deferral and release discipline;
deferral, retry and the starvation bound on refusal; rejecting an unauthenticated grant; and the
stale-GroupInfo defect below.

**Owned by [[SPEC-063-one-committer-per-epoch]], not here.** The wire verbs and their grammar; the
claim states and their release conditions; the hub's ingress refusal of member-authored hub verbs;
the `epoch-claim/v1` capability negotiation and activation rule; and the hub-side durability of an
armed claim.

**Out of scope entirely.** The election rule ([[SPEC-013-mls-private-channels]] REQ-012b decides
*who* should commit; this decides *that only one does*). `mls-ds/v1` rooms, which are exempt
([[#OQ-002]]).

hark **redeeming** an invitation is also out of scope, because hark does not do it: it declares
`groupinfoget` in `src/dialects/hub.cbcl:78` and never sends one. Recorded rather than omitted,
because the day that changes two obligations attach at once and neither is obvious from hark's own
code: `groupinfo-claimed` is a **retry**, distinct from `no-groupinfo`; and per cbcl-bus
**BUG-022**, the grant MUST NOT be spent until the join is acknowledged — spending it early left a
joiner that lost the race with no group *and* no grant, permanently unable to re-seat.

## 4. Requirements

### REQ-001 — Arm the claim before merging

hark SHALL NOT call `merge_pending_commit` until it has received an
`(epochgranted @room :epoch N :state armed)` naming the group's current epoch. It SHALL NOT arm
and merge in parallel, and SHALL NOT infer the state from the request it sent.

**The gate is that frame, not a belief about having armed.** An earlier revision of this
requirement — and of [[SPEC-063-one-committer-per-epoch]] ADR-003, which it followed — said the
grant must be "in hand" and named no observable, so a client could obey it sincerely and still
merge on a reservation. SPEC-063 REQ-007 now makes `:state armed` the acknowledgement.

Reading the state from the frame rather than from the request is load-bearing on exactly the path
[[#REQ-012]] exists for: a holder reacquiring after a restart asks with `epochclaim` **while it is
still armed**, and is answered `armed`. A client that assumed `claimed` because that is what it
asked for would read "I lost my promise" at the moment it most needs to know it has not — and
would then re-merge on a reservation.

The states are [[SPEC-063-one-committer-per-epoch]]'s: a *claimed* epoch is a reservation the hub
may take back (the holder has merged nothing, so nothing is promised); an *armed* one is a
declaration that the holder is about to merge, from which a release is a fork. Arming is therefore
the moment hark acquires §3.2's promise, and merging before it is merging on nothing.

Ordering, and why it is cheap here: `add_members` alone mutates nothing durable — OpenMLS stages
into the in-memory provider, and hark's own `provider.persist()` sits *after*
`merge_pending_commit` (`src/mls/group.rs`). The fork-visible boundary is that pair, so arming any
time before `add_member` is called satisfies the rule with room to spare.

**Consequence for the code, and it is the whole restructure.** `on_keypkg` is synchronous —
`handle_frame` returns a `SessionEvent` and cannot await a hub round trip — so the Add path becomes
a state machine: `keypkg` → record intent, emit `epochclaim` → granted → emit `epocharm` → armed →
`add_member`.

Trace: [[#TEST-001]], [[#CON-002]]

### REQ-002 — Classify a refusal by what makes it clear

When a claim is refused, hark SHALL treat the refusal as a **retry** or as **not retryable**
according to [[SPEC-063-one-committer-per-epoch]] CON-003's table, and SHALL NOT collapse the two.
In neither case SHALL it mark a handle unhealthy or generate the Commit.

- A **contended** refusal (`groupinfo-claimed`) means another committer holds the epoch. It clears
  when that holder is done, in seconds. Retry on the [[#ADR-004]] schedule, counting against the
  [[#NFR-001]] budget.
- **`epoch-claim-inactive`** means the room has not activated the capability, because it is not
  unanimous across present members. It clears on a **membership change** — a legacy client leaving
  or upgrading — and never with time. hark SHALL NOT retry it on the schedule and SHALL NOT count
  it against the starvation budget; it waits for a roster change and commits unclaimed in the
  meantime, exactly as it does today.

*This distinction is the trap in the whole design.* The two refusals look identical — the hub says
no, the epoch is unavailable — and differ in the only dimension a retry loop cares about. Retrying
the inactive one on a backoff turns an ordinary rollout into a hot loop against a hub that will
refuse every attempt for as long as one un-upgraded client stays connected, and counting it against
the starvation budget would report a room as starved when nothing is contending at all.

Trace: [[#TEST-002]], [[#TEST-002b]], [[#CON-002]]

### REQ-003 — The Welcome waits for acceptance

hark SHALL NOT emit the `welcome` frame for a Commit until that Commit has been accepted by the
group. Sending the Commit and observing the epoch advance to the one the Commit produces is
acceptance.

Concretely: hark SHALL hold the `welcome` frame until it observes the hub fan its own
`deliver` back to it, matched by the frame bytes it sent ([[#OQ-003]]).

This is the one §14 prohibition the claim does **not** license away: it is stated without the
"since the client doesn't know" conditional. A Welcome delivered for a Commit that was never
accepted seats a joiner into a group state no one else holds.

Trace: [[#TEST-004]], [[#TEST-005]], [[#CON-003]], [[#OQ-003]]

### REQ-004 — Publish a fresh GroupInfo after every self-commit

On merging its own Commit, hark SHALL publish a `(groupinfo …)` frame for the resulting epoch,
as it already does on merging another member's.

Trace: [[#TEST-006]], [[#BUG-001]]

### REQ-005 — hark declares the capability only when its half is complete

hark SHALL NOT advertise the `epoch-claim/v1` capability on its `hello` until its own claim
handling is implemented and reviewed.

*Reduced.* This began as "neither stack ships alone", enforced as a merge gate. That was the wrong
mechanism and [[SPEC-063-one-committer-per-epoch]] REQ-006 replaces it with the right one: the hub
computes a room's active set as the **intersection over present members** and refuses
`epochclaim`/`epocharm` with `epoch-claim-inactive` unless the capability is unanimous. Merging a
repository never upgraded a running daemon or an open tab, so a repository gate could never have
delivered what it promised.

What remains hark's is the honesty of its own declaration: the capability is a claim to honour the
protocol, and advertising it early makes every other client's promise false while looking like
compliance.

Trace: [[#TEST-005]], [[SPEC-063-one-committer-per-epoch]] REQ-006

### REQ-006 — Release a claim hark no longer needs

hark SHALL release an armed claim as soon as its obligations under it are discharged
([[#REQ-014]]), and SHALL release a *claimed* — not yet armed — epoch rather than holding it when
it will not commit ([[#REQ-016]]).

*Restated.* The original read "a held claim never survives the process that holds it", which is
true of a reservation and false of an armed claim: an armed claim survives death deliberately,
because releasing it is a fork ([[SPEC-063-one-committer-per-epoch]]). The obligation that
survives is hark's, not the hub's — nothing else can release it.

Trace: [[#TEST-006]], [[#REQ-012]]

### REQ-011 — Reject a grant that did not come from the hub

hark SHALL reject any `epochgranted` bearing a `:from`, and SHALL treat only a grant naming its own
room as a grant.

The grant **is** the promise, so a forged one is a licence to merge eagerly with nothing behind it
— the conflict this exists to prevent, reached by trusting the mechanism that prevents it. The
discriminator is the absence of `:from`: cbcl-chat requires it on every member-authored room frame
and refuses one without it as `missing-from`, never fanning it, while hub-originated frames carry
none.

*The hub half is [[SPEC-063-one-committer-per-epoch]]'s and is done* — and it was a wider hazard
than reported here: unrecognised performatives were routed to the publish path and **fanned**, so
the hub relayed forged `keypkg`, `invited`, `paircode`, `roomcfg` and `agent-removed` as well as
grants. hark's check stands regardless: a client whose safety depends on the hub having got its
ingress right has no defence the day it hasn't.

Trace: [[#TEST-011]], [[#CON-002]]

### REQ-012 — One durable operation record, carrying the Commit **and** the Welcome

Before merging, hark SHALL make durable a single record of the operation it is about to perform,
containing at least: the room, the epoch, the claim token, the serialised Commit, the serialised
Welcome, and the target handle. The record SHALL be removed only when both frames have been
delivered and the claim released.

**Why the Welcome must be in it, and this is settled by the code rather than by preference.**
`add_member` produces the Commit and the Welcome from one `add_members` call and then merges
(`src/mls/group.rs`). Once that has run the Welcome bytes exist only in the returned value, and
they cannot be regenerated: the group has advanced, and re-running `add_members` for the same
member is refused as *"already a member"* by the duplicate-leaf guard — which is cbcl-bus BUG-022's
trap approached from the other side. A restart holding the Commit but not the Welcome therefore has
an invitee in the ratchet tree it can **never** seat, and an armed claim it cannot legitimately
release.

This subsumes what were two requirements. A missing echo is *ambiguous*, not a refusal — the
commonest reason it does not arrive is that hark disconnected, and the hub may well have fanned the
Commit anyway. So the record is also what reconciliation reads: on restart hark resends from it and
re-observes acceptance, rather than discarding a Welcome and leaving the invitee added and mute.

**On recovery, per [[SPEC-063-one-committer-per-epoch]]'s residual.** A holder that arms, merges,
then loses its connection *and* this record holds that room's epoch permanently, and there is
deliberately no hub-side break — a break that exists gets reached for, and reaching for it is a
fork. The primary recovery is hark's: on restart, read the record and **release** rather than
reacquire when it shows no merge happened.

In-memory retention is not sufficient and is not a partial answer: it is precisely what a restart
loses. This does not reopen [[#ADR-001]] — a durable *operation record* is not a staged Commit, and
no fork is held.

Trace: [[#TEST-012]], [[#TEST-013]], [[#CON-002]], [[#CON-003]]

### REQ-014 — Release only after the Commit is accepted **and** the Welcome is out

hark SHALL NOT release an armed claim until it has observed acceptance of its Commit
([[#OQ-003]]) and delivered the corresponding Welcome.

The hub cannot infer this and does not try: `deliver` is opaque to it, so it can tell neither a
Commit from a message nor a Welcome-bearing exchange from a bare one. Release-on-epoch-advance is
therefore gone for armed claims, and the obligation is entirely hark's.

What it prevents: the epoch advances when *another* member merges and publishes GroupInfo for E+1,
which can happen before hark has received its own echo and emitted the deferred Welcome. A third
committer granted the claim then moves to E+2, and the invitee — still groupless — drops that
Commit and later joins against a stale E+1.

Trace: [[#TEST-014]], [[#CON-003]]

### REQ-016 — Release a grant hark took and will not spend

Where Commit generation fails after the grant, hark SHALL release the claim rather than hold it.

Neither of the hub's automatic release conditions applies here: the epoch has not advanced and the
connection is perfectly healthy. A holder that took a grant, failed to generate, and said nothing
blocks every other committer in the room having done nothing at all. `epochrelease`
([[SPEC-063-one-committer-per-epoch]]) is the verb; using it on every failure path is hark's
obligation.

Trace: [[#TEST-016]], [[#CON-002]]

## 5. Non-functional requirements

### NFR-001 — Starvation bound

A committer that is refused the claim **for contention** SHALL succeed in generating a Commit, or
escalate visibly, within **10 consecutive refusals**. `epoch-claim-inactive` is not contention and
SHALL NOT count against this budget ([[#REQ-002]]). On exhausting that budget hark SHALL log at `warn`
naming the room and the pending operation, and SHALL surface the condition in `hark daemon
status`, rather than retrying silently and indefinitely.

RFC 9420 §14 names this failure explicitly ("a given member may never be able to send a Commit
message because they always lose to other members") and declines to solve it, leaving it to the
application. Ten is not a tuned number — it is a threshold above which the *dynamics* have gone
wrong rather than any individual attempt, and the requirement is that it becomes visible, not
that it be automatically resolved.

[[SPEC-063-one-committer-per-epoch]] REQ-004 carries the cross-stack starvation requirement; the
ten-refusal figure here is hark's, and is offered for promotion to a normative shared bound so both
clients starve visibly on the same terms rather than each choosing its own threshold.

Trace: [[#TEST-008]], [[#OBS-001]]

### NFR-002 — No forked state held across a round trip

hark SHALL NOT hold an un-merged, generated Commit across a network round trip. Where a Commit
is generated, it is merged immediately under the claim.

This is RFC 9420 §14's "MUST minimize the amount of time that forked or previous group states
are kept in memory" discharged by construction rather than by a deletion policy — a claimed
epoch has no fork to keep. See [[#ADR-001]].

Trace: [[#ADR-001]], [[#TEST-001]]

## 6. Architecture decisions

### ADR-001 — Claim the epoch; do not stage the Commit

**Context.** RFC 9420 §14 offers two routes: prevent conflicting Commits, or rule which is
canonical. The obvious local fix is to *stage* — generate the Commit without merging, send it,
and merge only when the group accepts it. That is what "MUST NOT modify a client's state" reads
like at first sight.

**Decision.** Prevent the conflict with an exclusive per-epoch claim, and keep the eager merge.

**Rationale.** Three reasons, in ascending order of weight.

*It is what the RFC prefers.* Prevention is listed first, and §3.2 sanctions eager advancement
outright when the client holds a promise. The claim IS that promise; with it, the current merge
is conformant rather than merely lucky.

*Staging holds a fork.* §14's own next sentence requires minimising the time forked or previous
group states are kept in memory, for forward secrecy. Staging holds exactly such a state for a
full round trip on every commit, and needs a policy to delete it on every failure path. The
claim holds none.

*Staging is a much larger change with worse failure modes.* `merge_pending_commit` is where
hark's provider persistence, its pin updates, and its safety-number recomputation hang. Making
that conditional on a later network event means a state machine spanning the transport — with
its own timeouts, its own restart semantics, and a new class of "staged forever" bug. The claim
is a request/response before a synchronous operation that already works.

**Consequences.** hark depends on the hub for sequencing where it previously depended on luck.
That dependency is a liveness dependency only, never a safety one — see [[#ADR-003]]. A hub
that refuses every claim stops hark committing, which is the denial of service it could already
achieve by dropping the Commit frames.

### ADR-002 — A distinct `epochclaim` verb, not an overloaded `groupinfoget` *(adopted by SPEC-063)*

**Context.** The hub already has exactly the mechanism needed: `cbcl-chat-groupinfo:claim/2`
grants a room's current epoch to one live connection, releasing on epoch advance or holder
death. A member committer could simply call `groupinfoget` and take the same claim, needing no
new hub verb at all.

**Decision.** A new verb, `(epochclaim @room :epoch N :from @a)`, answered by
`(epochgranted @room :epoch N)` or the existing `(error @room "groupinfo-claimed")`, sharing
the same claim table and the same `claim/2` transaction.

**Rationale.** Overloading was genuinely tempting — Simplicity Ladder rung 4, reuse what is
there — and it fails on a case that is not an edge case. `claim/2` returns `#(error none)` when
the room holds **no GroupInfo**, because for a joiner "no GroupInfo" means "nothing to join
against". For a *committer* it means nothing of the sort: a freshly created group has no
published GroupInfo and its creator must still be able to commit the first Add. Overloading
would deadlock exactly the case every private channel starts in.

A second, independent reason emerged from reading [[SPEC-061]] itself: its **CON-004**
(`selfAdmitDecision`) makes `'fetch-groupinfo'` — *and only that answer* — the thing that
authorises a `groupinfoget` frame, and a client that already holds the group answers
`'have-group'`. Under SPEC-061's own gate a member therefore never emits `groupinfoget` at all.
Overloading it would mean rewriting that gate to let a member fetch an object it does not want,
which is a larger change to a Tier-1 admission path than adding a verb beside it.

Two lesser reasons: a member does not want the GroupInfo (up to 256 KB on a path that needs
none), and a verb named `get` that mutates exclusive state is the kind of naming that survives
into someone else's bug.

**Outcome.** Adopted in [[SPEC-063-one-committer-per-epoch]] as `epochclaim` / `epocharm` /
`epochrelease`, sharing one transaction with `groupinfoget` so both verbs contend for a single
claim. cbcl-bus added a refinement this analysis missed: `groupinfoget` now answers `#(error none)`
**without taking the claim**, so a joiner that cannot proceed does not hold a reservation against
the committer who would publish the object it is waiting for — the same argument pointed the other
way.

**Consequences.** One new verb in the hub dialect and one new hub handler, both thin — the
transaction, which is the part that is hard to get right, is shared verbatim. `groupinfoget`
keeps its meaning and its behaviour, and both verbs contend for one claim, which is what "one
committer per epoch" requires: an external joiner and a member committer must exclude each
other, since both move the epoch.

### ADR-003 — The claim is a sequencing device, never an admission decision *(owned by SPEC-063)*

**Decision.** Holding the claim confers no authority. Every member SHALL continue to validate
every Commit exactly as it does today, and a Commit from a claim holder SHALL be admitted on
no different terms from any other.

**Rationale.** [[SPEC-061]] NFR-001 requires that the hub cannot cause a member to be admitted.
If members deferred to the claim, admission would have passed to whoever grants claims — the
hub — which is the property the whole external-Commit design protects. This is also why the
issue's rejected non-fix (a claim token carried on the Commit) is correctly rejected: it would
make exclusivity end-to-end at the cost of making members check a hub-issued token.

**Consequences.** A malicious hub can grant the claim to two clients and produce exactly the
conflict this prevents. That is accepted: the result is the status quo ante (one Commit wins,
one loses), not a security failure. The claim buys conformance and orderly behaviour against an
honest hub; it is not asked to buy anything against a dishonest one.

### ADR-004 — Bounded deferral with a visible escape

**Decision.** Refusal defers with the [[crate::reconnect|bounded backoff]] already in the tree,
capped by [[#NFR-001]]'s budget, after which the condition is surfaced rather than retried
silently.

**Rationale.** §14 names starvation and leaves it to the application. Silent infinite retry is
the wrong answer for the same reason it was the wrong answer in [[SPEC-026-transport-resilience]]
ADR-004: an operator cannot act on what they cannot see. Unlike that case, an unbounded wait
here is not merely invisible — a never-committed Add means a member who was invited never gets
in, which looks to them like a permission problem.

### ADR-005 — Neither stack ships alone *(superseded by SPEC-063 REQ-006)*

**Decision.** The hark and cbcl-bus implementations merge together or not at all, enforced as a
merge gate on both pull requests rather than as an intention.

**Rationale.** Recorded because the reasoning is the kind that gets lost: "we can land our half
safely and the other side will follow" is true for most protocol changes and false for this one,
precisely because the claim's value is a promise that licenses eager state advancement.

**Superseded, and the mechanism was wrong even though the reasoning was right.** A merge gate
between repositories says nothing about deployed software: merging never upgraded a running daemon
or an open browser tab. [[SPEC-063-one-committer-per-epoch]] REQ-006 replaces it with capability
negotiation — a room's active set is the intersection over present members, and the hub refuses
`epochclaim`/`epocharm` when it is not unanimous — so a mixed room degrades to today's behaviour
rather than to something new. hark's residual obligation is [[#REQ-005]]: do not declare the
capability until the implementation is real.

## 7. Contracts

### CON-001 — The epoch claim (wire) — **owned by [[SPEC-063-one-committer-per-epoch]]**

The verbs (`epochclaim` / `epocharm` / `epochrelease` / `epochgranted`), their grammar, the claim
states and their release conditions, and the `epoch-claim/v1` activation rule are specified there
and are not restated here. An earlier revision of this document carried a draft wire contract; it
has been removed rather than kept in parallel, because two documents describing one protocol is
how the two stacks end up disagreeing about it.

What hark relies on from that contract, and would need re-checking if it changed:

- a grant names an epoch, and arming is a distinct, ordered step before merging ([[#REQ-001]]);
- an armed claim survives the holder's connection and the hub's restart, and is released only by
  the holder ([[#REQ-014]]);
- a contended refusal is a **retry**, distinct from `epoch-claim-inactive`, which is not
  ([[#REQ-002]]);
- a claim can be released without spending it ([[#REQ-016]]).

Verified by: [[#TEST-011]], and cross-stack by SPEC-063's own interop tests.

### CON-002 — Claim-gated commit generation (hark)

**Interface.** `add_member` and `remove_member` gain an armed-claim precondition and a durable
record; neither generates a Commit without one.

**Pre-conditions.**
- A grant for `group.epoch()` is held and **armed**. *(REQ-001)*
- The [[#REQ-012]] operation record is durable *before* `merge_pending_commit`. *(REQ-012)*
- The grant was authenticated as the hub's. *(REQ-011)*

**Post-conditions.**
- On success, generation, merge and persist proceed under §3.2's promise. *(REQ-001, NFR-002)*
- On a refusal, no Commit is generated, no state is modified, no handle is marked unhealthy, and
  the operation is re-attempted later. *(REQ-002)*
- On a generation failure *after* the grant, the claim is released rather than held. *(REQ-016)*
- If the group's epoch moved between grant and generation, the attempt is abandoned and retried
  against the new epoch. *(REQ-001)*

Implements: [[#REQ-001]], [[#REQ-002]], [[#REQ-011]], [[#REQ-012]], [[#REQ-016]] ·
Verified by: [[#TEST-001]], [[#TEST-002]], [[#TEST-011]], [[#TEST-016]]

### CON-003 — Commit, Welcome, and release ordering (hark)

**Interface.** The frames the session emits after a merged Commit, and when.

**Pre-conditions.** A Commit has been generated and merged under an armed claim, and the
[[#REQ-012]] record is durable.

**Post-conditions.**
- The `deliver` carrying the Commit is emitted immediately. *(REQ-001)*
- The `welcome` is emitted **only** once the Commit is accepted. *(REQ-003)*
- A fresh `(groupinfo …)` for the new epoch is emitted on acceptance. *(REQ-004)*
- `epochrelease` is sent only after both the acceptance and the Welcome. *(REQ-014)*
- The record is removed only after the release. *(REQ-012)*
- If acceptance never arrives, no `welcome` is emitted **and the record is retained** for
  reconciliation after reconnect — a missing echo is ambiguous, not a refusal. *(REQ-003, REQ-012)*

Implements: [[#REQ-003]], [[#REQ-004]], [[#REQ-012]], [[#REQ-014]] ·
Verified by: [[#TEST-004]], [[#TEST-005]], [[#TEST-006]], [[#TEST-012]], [[#TEST-013]],
[[#TEST-014]]

## 8. Test specification

Techniques: the claim transaction is concurrent state at a trust boundary → **integration
testing against a real hub** plus **property testing of exclusivity**; the ordering
requirements are a state machine → **example-based testing with a scripted peer**; the
cross-stack contract → **two vehicles, because neither alone reaches it**.

**On the cross-stack vehicle.** SPEC-061 TEST-008's harness drives the web client from files
emitted by hark, with no hub process and no socket in it, so it can establish frame-level agreement
and nothing about contention. That is why cross-stack contention is
[[SPEC-063-one-committer-per-epoch]]'s TEST-006 against the WebSocket pipeline rather than an
extension of TEST-008 — a test written against the wrong vehicle goes green while verifying
nothing, which is what an earlier revision of this section specified.

| TEST |

| TEST | Validates | Type | Scenario |
|------|-----------|------|----------|
| **TEST-001b** | [[#REQ-001]] | negative-output | The merge is gated on an `epochgranted :state armed` frame, and the state is read from the frame rather than inferred: a reacquisition answered `armed` after a restart is recognised as still holding the promise. **Implemented and mutation-checked.** |
| **TEST-001** | [[#REQ-001]], [[#NFR-002]] | positive | With a grant held, an Add generates, merges and persists as today, and the `deliver` goes out. No un-merged Commit is retained at any point. |
| **TEST-002** | [[#REQ-002]] | negative-input | A **contended** refusal: no Commit generated, no state changed, no handle unhealthy, and the attempt is retried on the schedule. |
| **TEST-002b** | [[#REQ-002]], [[#NFR-001]] | negative-output | `epoch-claim-inactive` is **not** retried on the schedule and does **not** consume the starvation budget. Collapsing the two refusals into one turns a rollout into a hot loop and reports a room as starved when nothing is contending. **Implemented and mutation-checked.** |
| **TEST-003** | [[#REQ-002]] | positive | After a refusal, the epoch advances (another member commits); the retry is granted and succeeds against the new epoch. |
| **TEST-004** | [[#REQ-003]] | negative-output | A Commit that is never accepted produces **no** `welcome` frame, ever. |
| **TEST-005** | [[#REQ-003]], [[#REQ-005]] | positive | On acceptance, the `welcome` is emitted, and not before the `deliver`. hark does not advertise `epoch-claim/v1` until its half is complete. |
| **TEST-006** | [[#REQ-004]], [[#BUG-001]] | positive | After hark commits its own Add, a `(groupinfo …)` for the NEW epoch is emitted. Regression for BUG-001. |
| **TEST-007** | [[#REQ-006]], [[#CON-001]] | positive + negative-output | Two connections contend: exactly one grant. The loser is granted after the winner's connection dies, and after the epoch advances — but not while the winner lives at that epoch. |
| **TEST-008** | [[#NFR-001]] | negative-output | Ten consecutive refusals produce one `warn` and a visible status, not a silent eleventh retry. |
| **TEST-009** | [[#REQ-001]] | positive | Cross-stack contention, owned by [[SPEC-063-one-committer-per-epoch]]'s interop tests rather than restated here. hark's obligation is to be one of the two stacks under test. The SPEC-061 TEST-008 harness cannot carry it — files, no hub, no socket — which is why SPEC-063 records it as TEST-006 against the WebSocket pipeline instead. |
| **TEST-011** | [[#REQ-011]] | negative-input | `(epochgranted @room :epoch 7 :from @mallory)` is not a grant, in any field order, including when `:from` is our own handle. **Implemented and mutation-checked.** |
| **TEST-012** | [[#REQ-012]] | negative-output | Kill the process between the merge and the delivery. On restart the record is read, the Commit resent and the claim reacquired — the agent does NOT resume into a silently forked epoch. A record showing no merge is **released**, not reacquired. |
| **TEST-012b** | [[#REQ-012]] | negative-output | The record carries the Welcome: kill the process after the merge, restart, and the invitee is still seated. Without it the Welcome is unregenerable — `add_members` refuses the same member as "already a member" — so the invitee is in the tree and can never be seated. |
| **TEST-013** | [[#REQ-012]] | positive | The Commit is fanned but the sender disconnects before its echo. After reconnecting, the Welcome is still delivered — the invitee is not left in the tree without secrets. |
| **TEST-014** | [[#REQ-014]] | negative-output | `epochrelease` is not sent while a Welcome is outstanding — the acceptance alone does not release it. |
| **TEST-016** | [[#REQ-016]] | positive | A grant taken, then Commit generation fails: the claim is released without a Commit and another committer is granted it promptly, on a healthy connection. |
| **TEST-010** | [[#ADR-002]] | positive | A committer in a room with **no** published GroupInfo is granted the claim. This is the case overloading `groupinfoget` would have deadlocked. |

## 9. Open questions

### OQ-001 — What should a committer do against a hub that serves no claim?

A hub predating this change answers `epochclaim` with an unknown-verb error or silence. hark
then either refuses to commit (safe, but bricks every agent against an older hub) or commits
without the promise (today's behaviour).

**Leaning:** commit without the promise, with a `warn` naming the hub as not serving the claim
— today's behaviour is no worse than today, and refusing turns a conformance improvement into
an outage. **Owner:** hark. **Blocking:** no, but it MUST be settled before merge, because it
is the difference between a rollout and an incident.

### OQ-003 — What counts as "accepted" on the chat path? **(RESOLVED)**

*Raised as blocking, and closed by reading the hub rather than by choosing.*

[[#REQ-003]] forbids emitting the Welcome until it is clear the Commit has been accepted, and
the chat path has no Delivery Service to say so. hark cannot use its own epoch as the signal: it
merges eagerly under the claim, so its epoch advances at generation.

**Resolution: the hub's fan-back of the sender's own frame.** `cbcl-chat-room:fanout/2` sends to
every member pid with no sender exclusion, and the module's own header states the contract —
*"fans out exactly once to every present member (including the sender)"*. So a committer that
sends a `deliver` receives it back, and that echo is carriage confirmation.

Correlation is by **frame bytes**, not by MLS processing: hark records the `:ct` it sent and
matches the echoed frame against it. This matters because hark's session would reject its own
echoed Commit as already-merged, so the signal has to be read below the MLS layer.

**The limit of the signal, stated rather than glossed.** The echo proves the *hub* accepted and
fanned the Commit, not that every member applied it. Under an exclusive claim no competing
Commit can exist, so the remaining ways acceptance could fail are a member finding the Commit
invalid — a bug, not a race — or the frame never reaching a member, which the hub's fan-out
makes indistinguishable from any other delivery failure. This is the strongest signal available
to a group whose Delivery Service has no acceptance protocol, and it is unambiguously stronger
than the status quo, which sends the Welcome unconditionally and immediately. Where
[[SPEC-024-mls-ds-v1]] runs, `seq == head + 1` is a genuine acceptance signal and should be
preferred — see [[#OQ-002]].

### OQ-002 — Do `mls-ds/v1` rooms need this at all? **(RESOLVED — exempt)**

[[SPEC-024-mls-ds-v1]] ADR-011 already sequences records with `seq == head + 1`, which is a
stronger and more general form of the same property. **v1 rooms are exempt**, per
[[SPEC-063-one-committer-per-epoch]]; layering both would be two sequencing mechanisms on one path.

What remains open is only the end state — whether the claim retires on migration or persists as the
chat path's mechanism with the DS owning DS rooms — and that is SPEC-063 OQ-001, a decision for
whoever migrates. Nothing here forecloses either.

## 9a. Defects found in SPEC-061 while specifying this — **all fixed**

Reported to cbcl-bus and resolved there; recorded because two of them mattered to this document
rather than only to SPEC-061.

- **`run-spec061-interop.sh` printed "cross-stack parity NOT checked" and exited 0.** Fixed: a skip
  now exits 1, with `SPEC061_ALLOW_SKIP=1` for someone who genuinely has no checkout. It was
  load-bearing here and not merely hygiene — whatever spec owns the cross-stack requirement has
  that test as its only evidence, and a harness reporting success while skipping leaves the
  requirement unenforced.
- **TEST-011 asserted a rule and its negation** — *"a claim older than the lease no longer blocks"*
  and *"a claim is not released by elapsed time"*. Fixed. Worth keeping the diagnosis: the lease
  assertion had already been deleted from the code and only the spec still claimed it, and a suite
  asserting both P and ¬P is green either way, so nothing but a reader was ever going to surface
  it.
- **CON-003 kept v0.6.0 "unexpired claim" language.** Struck.
- **Member-authored hub verbs were relayed, not ignored.** This is the one where the reported
  finding was narrower than the defect: unrecognised performatives were routed to the publish path
  and fanned, so the hub relayed forged `keypkg`, `invited`, `paircode`, `roomcfg` and
  `agent-removed` as well as grants. Fixed hub-side as a refusal set consulted before the routing
  table. [[#REQ-011]] keeps hark's own check regardless — a client whose safety depends on the hub
  having got its ingress right has no defence the day it hasn't.

## 10. Review gate

**Tier 1.** [[PROTO-001]] requires, before merge:

- cross-model adversarial review from a clean context, given this specification and the
  deliverable only, with an explicit mandate to find defects;
- human domain-expert security sign-off;
- the synthesis trajectory recorded ([[PROTO-001]] AI Trust Boundaries) — initial draft, the
  failing tests at each iteration and their requirement attribution, and the adversarial tests
  generated with their disposition.

Green tests are explicitly **not** sufficient. This document does not reach `approved` on the
strength of its own author's confidence.

## Changelog

<details>
<summary>Revision history — 0.1.0 → 0.3.0</summary>

- 0.3.0 — **reduced to hark's obligations.** cbcl-bus settled the home question this document was
  blocked on: the protocol lives in [[SPEC-063-one-committer-per-epoch]], a separate spec rather
  than a SPEC-024 section, because folding a chat-path claim into SPEC-024 would put two
  sequencing mechanisms for two kinds of room in one document. So the draft wire contract
  ([[#CON-001]]) is **removed rather than kept in parallel** — two documents describing one
  protocol is how the stacks end up disagreeing about it — and [[#ADR-002]], [[#ADR-003]] and
  [[#ADR-005]] are retained only as the record of why, marked as owned or superseded there.

  Three corrections came back with that decision, and two of them are to things this document had
  wrong:

  - **[[#REQ-001]] is now "arm before merging", not "hold a claim".** SPEC-063 splits the claim
    into *claimed* (a reservation the hub may take back — nothing is promised) and *armed* (the
    holder has declared it will merge, from which a release is a fork). My flat "never released by
    connection death" would have stranded a channel the first time an invitee closed a tab
    mid-fetch — the common case, not the tail.
  - **[[#REQ-005]] was the wrong mechanism.** I wrote the cross-stack constraint as a merge gate
    between repositories; merging never upgraded a running daemon or an open tab. SPEC-063 REQ-006
    replaces it with capability negotiation over the *present members*. What remains hark's is not
    declaring `epoch-claim/v1` until its half is real, and [[#REQ-015]] is gone as a separate
    requirement.
  - **[[#REQ-012]] and REQ-013 are one durable operation record**, and it must carry the
    **Welcome** as well as the Commit. Settled by hark's code rather than by preference:
    `add_members` produces both in one call and then the group advances, so a restart holding only
    the Commit has an invitee in the ratchet tree it can never seat — `add_members` refuses the
    same member as "already a member", which is cbcl-bus BUG-022's trap from the other side.

  [[#OQ-002]] closes: `mls-ds/v1` rooms are exempt, since `seq == head + 1` is the stronger form.

- 0.2.0 — folded an external review of the first implementation. Six requirements added, and
  the first is a defect in shipped code rather than a gap in the text: [[#REQ-011]], because
  `granted_epoch` ignored `:from` and so read a member's `(epochgranted … :from @mallory)` as
  the hub's promise — a forged licence to merge eagerly, which is the conflict this spec
  prevents reached by trusting the mechanism that prevents it. The other five are lifecycle
  holes the original draft did not consider: the claim dies with the connection but the merge is
  durable ([[#REQ-012]]); a missing echo is ambiguous rather than a refusal, and suppressing the
  Welcome forever leaves an invitee added and mute ([[#REQ-013]]); the epoch can advance, and so
  release the claim, before the deferred Welcome is out ([[#REQ-014]]); merging both
  repositories does not upgrade running clients, so [[#REQ-005]] needs a live-client gate rather
  than a repository one ([[#REQ-015]]); and a grant taken but not spent had no release path at
  all, letting a healthy connection block every committer in the room ([[#REQ-016]]).

  [[#ADR-001]] is unchanged and [[#REQ-012]] deliberately does not reopen it: the answer to the
  restart hole is a durable *operation record*, not a staged Commit, so no fork is held.

- 0.1.1 — folded a briefing from the cbcl-bus side, after verifying both of its checkable
  claims against `origin/main`. [[#TEST-009]] was **misspecified** and is split into
  [[#TEST-009a]] (file-mediated) and [[#TEST-009b]] (hub-mediated): SPEC-061 TEST-008's harness
  has no hub in it, so contention for a hub-served claim cannot be tested through it, and the
  original entry named a vehicle that could not carry it. Recorded the harness's silent skip as
  a defect that undermines [[#REQ-005]]'s enforcement rather than only SPEC-061's, and attached
  the cbcl-bus BUG-022 discipline to the out-of-scope note on redeeming invitations, so it is
  not lost the day hark starts doing so.
- 0.1.0 — initial draft, from `anuna-research/hark#27` (raised from cbcl-bus#44). RFC 9420 §14
  and §3.2 quoted from the published text rather than from the issue. Two things the issue does
  not cover are specified here because §14 raises them: the starvation bound ([[#NFR-001]]) and
  the forked-state argument that decides [[#ADR-001]]. One adjacent defect found while
  specifying ([[#BUG-001]], a self-commit leaving the room's GroupInfo stale) is fixed here
  because this work rewrites that path.

</details>
