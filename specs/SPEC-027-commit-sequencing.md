---
id: SPEC-027
title: Commit Sequencing — Honouring the Epoch Claim (RFC 9420 §14)
status: draft
tier: 1 (MLS group state and admission — cross-model adversarial review AND human security sign-off REQUIRED before merge; green tests are not sufficient)
version: 0.2.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 5)
last-updated: 2026-07-27
owner-repo: hark
affects-repos: cbcl-bus (the hub serves the claim; the web client must honour it identically)
depends-on: SPEC-013 (MLS private channels — REQ-012b elected committer), SPEC-061 (external Commit admission — REQ-005, the GroupInfo claim), SPEC-024 ADR-011 (`seq == head + 1`, the general form of this)
traces-to: "anuna-research/hark#27, raised from cbcl-bus#44; cbcl-bus PR#45 built the first half"
---

# SPEC-027 — Commit Sequencing: Honouring the Epoch Claim

## Orientation

**Intent.** Two members of one MLS group can generate Commits for the same epoch at the same
moment. RFC 9420 requires an application to have an *established* way to resolve that, and
hark currently has none: it merges and persists its own Commit before anyone has accepted it.
This specification gives hark a promise to hold — an exclusive, per-epoch claim served by the
hub — so that its eager merge becomes the RFC-sanctioned behaviour it is today only by
accident.

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

**Decisions.** [[#ADR-001]] claim rather than stage · [[#ADR-002]] a distinct `epochclaim`
verb rather than overloading `groupinfoget` · [[#ADR-003]] the claim is advisory to the hub and
never an admission decision · [[#ADR-004]] bounded deferral with a starvation escape ·
[[#ADR-005]] neither stack ships alone.

**Load-bearing.** [[#REQ-001]] hold the claim before committing · [[#REQ-003]] the Welcome
waits for acceptance · [[#REQ-005]] no partial adoption · [[#REQ-011]] the grant is
authenticated · [[#REQ-012]] the promise survives a restart · [[#REQ-015]] activation is gated
on live clients, not on merged repositories · [[#NFR-001]] starvation bound.

**Open.** [[#OQ-001]] what a committer does against a hub that serves no claim; [[#OQ-002]]
whether [[SPEC-024-mls-ds-v1]] rooms need this at all, given `seq == head + 1` already sequences
them. ([[#OQ-003]], what counts as "accepted", was raised as blocking and is resolved — the
hub fans a sender its own frame back, and that echo is the signal.)

**Detail.** [[IMPL-027-commit-sequencing]] is the execution plan. The hub half amends
[[SPEC-061]] REQ-005; this document owns hark's half and the cross-stack contract they share.

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

### 2.1 This supersedes a different proposal, deliberately

[[SPEC-061]] **BUG-021** is the parent of this work. Its external-join half was fixed by
REQ-005's second clause (the GroupInfo claim, cbcl-bus PR #45). Its still-open half is recorded
there as needing *"a Delivery Service acceptance signal (SPEC-024 ADR-011 `seq == head + 1`)"* —
a different resolution from the one specified here.

Both are recorded because a reviewer will otherwise find two proposals and no statement of which
governs. **This specification supersedes that note for the chat path**, on the following grounds,
and issue #27 proposes the same:

- The `seq == head + 1` mechanism belongs to [[SPEC-024-mls-ds-v1]], which the chat path does not
  run. Requiring it here would mean either shipping the DS for every private channel, or building
  a second acceptance channel beside it.
- A DS acceptance signal *rules which Commit is canonical* — §14's second route. A claim
  *prevents the conflict* — §14's first route, which the RFC lists first and which holds no forked
  state ([[#ADR-001]]).
- The claim mechanism already exists in the hub, in production, reviewed. The acceptance signal
  does not.

Where the DS *does* run, [[#OQ-002]] asks whether the claim should be skipped entirely rather
than layered on top of a stronger guarantee.

## 3. Scope

**In scope.** The claim protocol shared by both stacks and its wire contract; hark taking the
claim before every Commit it generates; hark's ordering of merge, Commit send, and Welcome
send; the deferral and retry behaviour on refusal; the starvation bound; the stale-GroupInfo
defect above; and the corresponding amendment to [[SPEC-061]] REQ-005 in cbcl-bus.

**Out of scope.** The election rule itself ([[SPEC-013-mls-private-channels]] REQ-012b decides
*who* should commit; this decides *that only one does*). Any change to admission — see
[[#ADR-003]]. The `mls-ds/v1` rooms of [[SPEC-024-mls-ds-v1]], pending [[#OQ-002]].

hark **redeeming** an invitation is also out of scope, because hark does not do it: it declares
`groupinfoget` in `src/dialects/hub.cbcl:78` and never sends one. Recorded here rather than
omitted, because the day that changes two obligations attach at once and neither is obvious
from hark's own code: `groupinfo-claimed` is a **retry**, distinct from `no-groupinfo`; and per
cbcl-bus **BUG-022**, the grant MUST NOT be spent until the join is acknowledged — spending it
early left a joiner that lost the race with no group *and* no grant, permanently unable to
re-seat.

## 4. Requirements

### REQ-001 — Hold the claim before generating a Commit

hark SHALL obtain an exclusive claim on the group's current epoch before generating any Commit,
and SHALL NOT call `add_members` or `remove_members` without holding it.

The claim is what turns hark's existing eager merge from an accident into §3.2's promise. It is
therefore REQUIRED *before generation*, not before sending: generation is the step §14 governs.

Trace: [[#TEST-001]], [[#CON-001]], [[#CON-002]]

### REQ-002 — Defer, do not fail, on a refused claim

When the claim is refused because another party holds it, hark SHALL treat the refusal as a
**retry**, not an error: it SHALL NOT generate the Commit, SHALL NOT mark any handle unhealthy,
and SHALL re-attempt once the epoch has advanced or the holder has released it.

A refusal means another committer is about to move the epoch. Whatever hark wanted to commit is
either accomplished by that Commit (the member gets added by someone else) or still wanted
afterwards, at which point the re-attempt is against the new epoch and is the correct thing to
do anyway.

Trace: [[#TEST-002]], [[#TEST-003]], [[#CON-002]]

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

### REQ-005 — Neither stack honours the claim alone

The claim SHALL NOT be adopted by one stack without the other. An implementation MUST NOT be
merged into either repository until the corresponding implementation in the other is ready to
merge.

A claim honoured by one client is a promise the group does not keep. It is strictly worse than
no claim, because §3.2 licenses a holder to advance its state eagerly on the strength of it:
the honouring client would advance on a promise the other client is free to break. Partial
adoption makes conformance worse, not better.

Trace: [[#ADR-005]], and the merge gate in [[IMPL-027-commit-sequencing]]

### REQ-006 — A held claim never survives the process that holds it

hark SHALL hold a claim only for the duration of a single commit attempt, and SHALL release it
— or allow it to be released — when the attempt completes, fails, or its connection dies.

Trace: [[#TEST-007]], [[#CON-001]]

### REQ-011 — The hub refuses a member-authored grant

The hub SHALL refuse an `epochclaim`-response verb (`epochgranted`) submitted by a member,
and SHALL NOT fan it. A client SHALL independently reject any `epochgranted` bearing a `:from`,
which a member-authored room frame must carry and a hub-originated frame does not.

*Found in review of the first implementation.* The grant **is** [[#REQ-001]]'s promise, so a
forged one is not a nuisance — it is a licence to merge eagerly with nothing behind it, which
is the exact conflict this specification prevents, reached by trusting the mechanism that
prevents it. Any member can publish arbitrary room frames and the hub fans them.

Both halves are REQUIRED. A client-only check leaves the forgery on the wire for every other
implementation to get wrong; a hub-only check makes every client's safety depend on the party
[[#ADR-003]] declines to trust for anything else.

Trace: [[#TEST-011]], [[#CON-001]]

### REQ-012 — The promise survives a restart, or the merge does not happen

Where hark has merged a Commit under a claim but not yet delivered it, that obligation SHALL be
durable: on restart the system SHALL either resend the undelivered Commit and reacquire the
claim for its epoch, or refuse to resume the group until it can.

*Found in review.* [[#ADR-001]]'s eager merge is sound only while the promise holds, and a
connection-scoped claim dies with the connection. If the process dies after
`merge_pending_commit` + `persist` but before the Commit is accepted, the claim is released,
the durable state says epoch E+1, and the group is still at E — so another committer takes the
claim and advances E differently. The agent restarts into a fork it created and cannot detect.

In-memory retention of the unsent frames is **not** sufficient: it is exactly the thing a
restart loses. This does not reopen [[#ADR-001]] — the answer is a durable *operation record*
(the frames to resend plus the epoch to reclaim), not a staged Commit; the group state stays
merged and no fork is held in memory.

Trace: [[#TEST-012]], [[#CON-002]]

### REQ-013 — A missing echo is ambiguous, and SHALL be reconciled rather than treated as refusal

Where the acceptance signal of [[#OQ-003]] does not arrive, the system SHALL persist the
pending Welcome and reconcile acceptance after reconnecting — by observing the group's epoch, or
by re-sending. It SHALL NOT discard the Welcome, and SHALL NOT treat the missing echo as
evidence the Commit was refused.

*Found in review.* [[#REQ-003]] holds the Welcome until the Commit is accepted, and the echo is
the signal. But the commonest reason the echo does not arrive is that *we* disconnected — and
the hub may well have persisted and fanned the Commit regardless. Then the invitee is in the
ratchet tree, visible to every member, holding none of the group's secrets and with no Welcome
coming: added and mute, permanently. Suppressing the Welcome forever converts an ambiguous
outcome into a certain failure, and it is the failure that looks to the invitee like a
permissions problem.

Trace: [[#TEST-013]], [[#CON-003]]

### REQ-014 — The claim is held until the Welcome is ordered, not merely until the epoch advances

A claim SHALL NOT be released while its holder has a Welcome outstanding for the Commit taken
under it.

*Found in review.* The release conditions of [[SPEC-061]] REQ-005 are epoch advance and
connection death. The epoch advances the moment **another** member merges the Add and publishes
GroupInfo for E+1 — which can happen before the committer has received its own echo and emitted
the deferred Welcome. A waiting committer then takes the claim and advances to E+2. The invitee,
still groupless, drops that Commit and later joins against a stale E+1. Holding the barrier
through Welcome delivery, or buffering and replaying the Commits that land in between, is what
closes it.

Trace: [[#TEST-014]], [[#CON-001]]

### REQ-015 — Activation is gated on every live committer, not on both repositories having merged

The claimed-eager-merge behaviour SHALL NOT be enabled for a room until every client that can
commit in it honours the claim. Room-wide capability or version negotiation, or hub-side
enforcement, is REQUIRED before activation.

*Found in review, and it is the sharpest form of [[#REQ-005]].* Merging both repositories does
not upgrade a running hark daemon or an open browser tab. During any rollout a new client can
hold a grant and merge eagerly while an old client, which never took a claim, emits a conflicting
Commit for the same epoch. That is strictly worse than the status quo, because the new client has
advanced its state on a promise the old one was never told about — the "false promise" of
[[#ADR-005]] arriving through time rather than through a repository boundary.

Trace: [[#TEST-015]], [[#ADR-005]]

### REQ-016 — A claim taken and not spent SHALL be releasable before sending

The system SHALL be able to release a claim it holds without sending a Commit, and SHALL do so
whenever Commit generation fails after the grant.

*Found in review.* `add_members` / `remove_members` can fail after the grant — a validation
refusal, a ledger rejection, a provider error. Neither release condition then applies: the epoch
has not advanced, and the connection is perfectly healthy. The holder blocks every other
committer in the room indefinitely, having done nothing at all. Without an explicit release the
only remedy is to drop the connection, which is a poor thing to require of a client whose only
error was to decline to commit.

Trace: [[#TEST-016]], [[#CON-001]]

## 5. Non-functional requirements

### NFR-001 — Starvation bound

A committer that is refused the claim SHALL succeed in generating a Commit, or escalate
visibly, within **10 consecutive refusals**. On exhausting that budget hark SHALL log at `warn`
naming the room and the pending operation, and SHALL surface the condition in `hark daemon
status`, rather than retrying silently and indefinitely.

RFC 9420 §14 names this failure explicitly ("a given member may never be able to send a Commit
message because they always lose to other members") and declines to solve it, leaving it to the
application. Ten is not a tuned number — it is a threshold above which the *dynamics* have gone
wrong rather than any individual attempt, and the requirement is that it becomes visible, not
that it be automatically resolved.

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

### ADR-002 — A distinct `epochclaim` verb, not an overloaded `groupinfoget`

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

**Consequences.** One new verb in the hub dialect and one new hub handler, both thin — the
transaction, which is the part that is hard to get right, is shared verbatim. `groupinfoget`
keeps its meaning and its behaviour, and both verbs contend for one claim, which is what "one
committer per epoch" requires: an external joiner and a member committer must exclude each
other, since both move the epoch.

### ADR-003 — The claim is a sequencing device, never an admission decision

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

### ADR-005 — Neither stack ships alone

**Decision.** The hark and cbcl-bus implementations merge together or not at all, enforced as a
merge gate on both pull requests rather than as an intention.

**Rationale.** [[#REQ-005]]. Recorded as an ADR because the reasoning is the kind that gets lost:
"we can land our half safely and the other side will follow" is true for most protocol changes
and false for this one, precisely because the claim's value is a promise that licenses eager
state advancement.

## 7. Contracts

### CON-001 — The epoch claim (wire)

**Interface.**

```
request   (epochclaim @room :epoch <n> :from @a)
granted   (epochgranted @room :epoch <n>)
refused   (error @room "groupinfo-claimed")     ; the existing slug, deliberately reused
no-group  (error @room "no-group")              ; the room has no MLS group at all
```

**Grammar** (the hub's recogniser; regular, and an extension of the existing hub dialect):

```abnf
epochclaim = "(" %s"epochclaim" SP room SP %s":epoch" SP 1*DIGIT
             SP %s":from" SP handle ")"
room       = "@" 1*63(ALPHA / DIGIT / "-" / "_")
handle     = room
```

**Pre-conditions.**
- The requester is a member of the room (the hub's existing `current-member-pid` check).
- `:epoch` is the epoch the requester intends to commit against. *(REQ-001)*

**Post-conditions.**
- On `epochgranted`, no other live connection holds this room at this epoch, and none will be
  granted it until this connection dies or the epoch advances. *(REQ-001, REQ-006)*
- On `groupinfo-claimed`, another live connection holds it. The requester MUST retry, not
  fail. *(REQ-002)*
- A grant is idempotent for the same connection: re-requesting after a lost reply succeeds
  rather than self-blocking. *(REQ-002)*
- A room with no GroupInfo published is **grantable** — unlike `groupinfoget`, which needs the
  object itself. *(ADR-002)*
- The grant confers no admission authority whatsoever. *(ADR-003)*

**Error model.** `groupinfo-claimed` is a retry. `not-a-member` and `no-group` are terminal for
this attempt. Any other error is treated as a refusal and retried under [[#NFR-001]]'s budget.

Implements: [[#REQ-001]], [[#REQ-002]], [[#REQ-006]] · Verified by: [[#TEST-001]],
[[#TEST-002]], [[#TEST-003]], [[#TEST-007]]

### CON-002 — Claim-gated commit generation (hark)

**Interface.** `add_member` and `remove_member` gain a claim precondition; neither generates a
Commit without one.

**Pre-conditions.** A grant for `group.epoch()` is held. *(REQ-001)*

**Post-conditions.**
- On a grant, generation, merge and persist proceed as today, under the §3.2 promise.
  *(REQ-001, NFR-002)*
- On a refusal, no Commit is generated, no state is modified, no handle is marked unhealthy,
  and the operation is re-attempted later. *(REQ-002)*
- The epoch named in the claim is the epoch the Commit is generated against; if the group's
  epoch has moved between grant and generation, the attempt is abandoned and retried.
  *(REQ-001)*

Implements: [[#REQ-001]], [[#REQ-002]] · Verified by: [[#TEST-001]], [[#TEST-002]]

### CON-003 — Commit and Welcome ordering (hark)

**Interface.** The frames `MlsSession::on_keypkg` emits, and when.

**Pre-conditions.** A Commit has been generated and merged under a held claim.

**Post-conditions.**
- The `deliver` frame carrying the Commit is emitted immediately. *(REQ-001)*
- The `welcome` frame is emitted **only** once the Commit is accepted. *(REQ-003)*
- A fresh `(groupinfo …)` for the new epoch is emitted on acceptance. *(REQ-004)*
- If acceptance never arrives, no `welcome` is ever emitted. *(REQ-003)*

Implements: [[#REQ-003]], [[#REQ-004]] · Verified by: [[#TEST-004]], [[#TEST-005]],
[[#TEST-006]]

## 8. Test specification

Techniques: the claim transaction is concurrent state at a trust boundary → **integration
testing against a real hub** plus **property testing of exclusivity**; the ordering
requirements are a state machine → **example-based testing with a scripted peer**; the
cross-stack contract → **two vehicles, because neither alone reaches it**.

**On the cross-stack vehicles, and why there are two.** SPEC-061 TEST-008's harness drives the
web client from files emitted by hark (`hark emit → $DIR → node join.mjs → hark verify`); there
is no hub process and no socket in it. It therefore cannot exercise a hub-served claim at all,
and a test of contention written against it would be verifying nothing. Frame-level agreement is
what it *can* prove ([[#TEST-009a]]); contention needs the TEST-011 vehicle, which has a real
WebSocket pipeline ([[#TEST-009b]]). Conflating them is how a cross-stack requirement ends up
with no cross-stack evidence.

| TEST | Validates | Type | Scenario |
|------|-----------|------|----------|
| **TEST-001** | [[#REQ-001]], [[#NFR-002]] | positive | With a grant held, an Add generates, merges and persists as today, and the `deliver` goes out. No un-merged Commit is retained at any point. |
| **TEST-002** | [[#REQ-002]] | negative-input | The hub refuses the claim. No Commit is generated, no group state changes, no handle goes unhealthy, and the attempt is retried. |
| **TEST-003** | [[#REQ-002]] | positive | After a refusal, the epoch advances (another member commits); the retry is granted and succeeds against the new epoch. |
| **TEST-004** | [[#REQ-003]] | negative-output | A Commit that is never accepted produces **no** `welcome` frame, ever. |
| **TEST-005** | [[#REQ-003]] | positive | On acceptance, the `welcome` is emitted, and not before the `deliver`. |
| **TEST-006** | [[#REQ-004]], [[#BUG-001]] | positive | After hark commits its own Add, a `(groupinfo …)` for the NEW epoch is emitted. Regression for BUG-001. |
| **TEST-007** | [[#REQ-006]], [[#CON-001]] | positive + negative-output | Two connections contend: exactly one grant. The loser is granted after the winner's connection dies, and after the epoch advances — but not while the winner lives at that epoch. |
| **TEST-008** | [[#NFR-001]] | negative-output | Ten consecutive refusals produce one `warn` and a visible status, not a silent eleventh retry. |
| **TEST-009a** | [[#REQ-005]], [[#CON-001]] | positive | **File-mediated** (the SPEC-061 TEST-008 vehicle): both stacks produce and recognise byte-identical `epochclaim` / `epochgranted` frames. This is all that harness can verify — it has no hub (see below). |
| **TEST-009b** | [[#REQ-005]], [[#ADR-003]] | positive | **Hub-mediated** (the SPEC-061 TEST-011 vehicle — store level plus a real WebSocket): a hark connection and a web connection contend for one epoch against a running hub; exactly one is granted, the loser is refused with `groupinfo-claimed` and retries, and both stacks agree on membership and on the safety number afterwards. |
| **TEST-011** | [[#REQ-011]] | negative-input | `(epochgranted @room :epoch 7 :from @mallory)` is not a grant, in any field order, including when `:from` is our own handle. The hub refuses to fan a member-authored one. |
| **TEST-012** | [[#REQ-012]] | negative-output | Kill the process between the merge and the delivery. On restart the Commit is resent and the claim reacquired — the agent does NOT resume into a silently forked epoch. |
| **TEST-013** | [[#REQ-013]] | positive | The Commit is fanned but the sender disconnects before its echo. After reconnecting, the Welcome is still delivered — the invitee is not left in the tree without secrets. |
| **TEST-014** | [[#REQ-014]] | negative-output | Another member advances the epoch while a Welcome is outstanding. A third committer must NOT be granted the claim until that Welcome is ordered. |
| **TEST-015** | [[#REQ-015]] | negative-output | A room containing one claim-honouring and one legacy client does not enable claimed eager merge. |
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

### OQ-002 — Do `mls-ds/v1` rooms need this at all?

[[SPEC-024-mls-ds-v1]] ADR-011 already sequences records with `seq == head + 1`, which is a
stronger and more general form of the same property: the DS refuses a record that is not the
exact next one. A v1 room may therefore already satisfy §14 without any claim.

**Leaning:** exempt v1 rooms and say so explicitly, rather than layering two sequencing
mechanisms. **Owner:** hark. **Blocking:** no — v1 is not yet the default — but leaving it
unstated would invite someone to add the claim there later "for consistency".

## 9a. Defects found in SPEC-061 while specifying this

Reported here so they reach cbcl-bus rather than being silently worked around; neither blocks
this work, and neither is mine to fix unilaterally.

- **TEST-011 verifies both the old lease rule and its replacement.** It asserts *"A claim older
  than the lease no longer blocks"* (back-dating frees it) and, twenty lines later, *"A claim is
  **not** released by elapsed time"*. REQ-005's normative clause says `SHALL NOT be released by
  elapsed time`, so the first assertion contradicts the requirement it is attributed to. A test
  suite that verifies both a rule and its negation cannot fail on that rule.
- **CON-003 retains v0.6.0 lease language.** It still reads *"another requester holds an
  **unexpired** claim"*, three paragraphs above the text stating release is never by a clock.
- **TEST-008's harness passes when it checks nothing, and this one is load-bearing here.**
  `run-spec061-interop.sh` opens with

  ```bash
  if [ ! -d "$HARK" ]; then
    echo "SKIPPED: no hark checkout at $HARK — cross-stack parity NOT checked"
    exit 0
  fi
  ```

  The message is honest and the exit status is not: anything reading the status — CI, a release
  gate, a person running it in a loop — sees a pass. It is how the harness went unrun against
  cbcl-bus PR #45 and #46 twice without anyone noticing, which the cbcl-bus side found and
  reported.

  **Why it matters to this specification and not only to that one.** [[#REQ-005]] says neither
  stack honours the claim alone, and the *evidence* for that claim is the cross-stack test. A
  harness that reports success while skipping gives REQ-005 no enforcement whatsoever — the
  merge gate would be satisfied by a run that checked nothing. Exiting non-zero (or requiring an
  explicit `SPEC061_ALLOW_SKIP=1`) is a precondition for [[#TEST-009a]] being worth running.

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
<summary>Revision history — 0.1.0 → 0.2.0</summary>

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
