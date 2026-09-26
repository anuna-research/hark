---
id: SPEC-086
title: Object transport for SDK agents
status: draft
tier: 2 (hark attests message authorship to an agent that acts on it)
version: 0.2.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 5.5)
last-updated: 2026-09-26
owner-repo: hark
affects-repos: none (cbcl-bus already serves the frames; SPEC-085 owns the SDK side)
depends-on: SPEC-085 (agent object SDK — REQ-008 message identity, REQ-009 predecessor), SPEC-013 (MLS private channels — authenticated sender), SPEC-026 (reconnect and backfill replay)
stage: B of 2 — transport (Stage A) plus native read/act/open by running the SDK headlessly (ADR-004)
---
# SPEC-086 — Object transport for SDK agents

## Orientation
Intent: A JavaScript agent using the `@cbcl/object` SDK can use hark as its signing transport. It then acts on hypermedia objects exactly as a browser does.
Hark carries bytes and attests authorship. The SDK inside the agent recognises, verifies with cbcl-rs wasm, computes cids, and projects.

Structure:
```
  JS agent process                          hark daemon (Rust)                     hub
 ┌──────────────────────────┐   HTTP    ┌───────────────────────────────┐   WS   ┌─────┐
 │ @cbcl/object (SPEC-085)  │◀─recv────│ object subscription (REQ-001)  │◀──────│     │
 │  canonicalise → cid      │  message  │  signer attestation (REQ-006)  │ join/ │     │
 │  verify, store, project  │ + record  │  backfill pass-through (REQ-003)│ reconn│     │
 │  broker picks :caused-by │ (CON-001) │                                │ replay│     │
 │                          │──send────▶│  byte-preserving sign (REQ-005)│──────▶│     │
 │                          │─history──▶│  (history …) request (CON-002) │──────▶│     │
 └──────────────────────────┘           └───────────────────────────────┘        └─────┘
   one canonicaliser, one projection: hark never interprets object content (REQ-007)
```
The agent passes `message` to the SDK and takes the signer from `record`. The record carries no cid; only the SDK computes cids. The SDK parses verb, keywords, and `:caused-by` from `message`.
The hub replays about 50 frames on every join and reconnect; hark passes object frames through. For anything older, the agent calls the history endpoint.

Decisions: [[SPEC-086-hark-object-transport#ADR-001]] hark transports and the SDK computes · [[SPEC-086-hark-object-transport#ADR-002]] additive `record` member on `recv` · [[SPEC-086-hark-object-transport#ADR-003]] duplicates reach the agent, which deduplicates by cid.

Load-bearing: [[SPEC-086-hark-object-transport#REQ-006]] signer attestation · [[SPEC-086-hark-object-transport#REQ-005]] byte preservation · [[SPEC-086-hark-object-transport#REQ-003]] history reaches the agent · [[SPEC-086-hark-object-transport#REQ-001]] subscription independent of `--speak`.

Controls:
- Hark MUST NOT deliver an object record without an established signer → [[SPEC-086-hark-object-transport#REQ-006]].
- In an MLS room, the signer is the MLS sender, and a message whose `:from` differs is dropped. In a cleartext room, the signer is the `:from` of a hub-delivered frame → [[SPEC-086-hark-object-transport#REQ-006]].
- Hark MUST NOT re-render, re-canonicalise, or alter object message bytes → [[SPEC-086-hark-object-transport#REQ-005]].
- Hark MUST NOT drop an object message for an uninstalled dialect → [[SPEC-086-hark-object-transport#REQ-007]].
- A history request asks for at most 1000 frames. Hark allows one unanswered request per room. The once-per-controller budget of [[SPEC-085-agent-object-sdk#ADR-002]] binds the agent's SDK, not hark → [[SPEC-086-hark-object-transport#CON-002]].
- The subscription is opt-in and off by default. It persists in the pairing record, so a daemon restart resumes it → [[SPEC-086-hark-object-transport#CON-003]].

Open:
- The hark maintainer verifies the hub's reply to `(history …)` from a signed-member agent connection, including its order. Hark has never sent one.
- The hark maintainer verifies that a restarted daemon decrypts replayed MLS frames from earlier epochs. Undecryptable frames leave the opener unreachable.
- The repository owner decides the MLS `:from` mismatch rule. Hark drops such a message; the browser projects it under the MLS sender. [[SPEC-085-agent-object-sdk#REQ-004]] needs one rule.
- The hark maintainer states the bound on the per-handle inbound queue. Replayed history makes an unbounded queue observable.
- The hark maintainer verifies that `emit` of an `object-*` dialect passes in a room that declares a dialect menu.
- Hark stores nothing while offline. Messages beyond the replay window and the 1000-frame history limit are unavailable to the agent, as to a browser.
- The hark maintainer specifies Stage B, native projection in Rust. It is gated on the [[SPEC-085-agent-object-sdk#REQ-007]] corpus. It also needs a cbcl-rs pin exporting `verify_message_shape`, `verify_protocol`, and `message_hash`, as cbcl-bus `cbcl-rs.sha` does.

Detail: Implementers follow [[SPEC-086-hark-object-transport#CON-001]] → [[SPEC-086-hark-object-transport#TEST-001]] → [[SPEC-086-hark-object-transport#REQ-002]]. Reviewers follow the ADRs and `Open`.
Artefact IDs repeat across the two specs; always qualify them, as in `SPEC-086 CON-001`.

## Failure mechanism
An agent that drives hark cannot act correctly on an object. Four gaps combine:
- `recv` returns bare text. It carries no attested signer. In an MLS room, the inner `:from` is the only authorship the agent sees.
- On reconnect, `ReplayGuard` suppresses the hub's backfill. The hub also replays only 50 frames on join. An opener older than that never reaches the agent.
- Object dialect names derive from contract digests. They cannot be declared ahead of time, so `--speak` cannot select them. Only receive-all `*` delivers them.
- Receive-all skips the agent's own messages. After a daemon restart, the agent's own prior acts are missing from its store. Its broker then picks a wrong `:caused-by`.
The SDK's broker needs the thread's complete accepted history to choose a predecessor and fill `replaces`/`removes` ([[SPEC-085-agent-object-sdk#REQ-009]]). Without it, the agent emits actions that other clients reject or that silently lose writes.

## REQ-001
WHEN an agent joins with the object subscription, hark MUST deliver every `object-*` content message to `recv`.
This applies in every room the agent joined.
Delivery MUST NOT depend on `--speak`, the capability set, or the room's declared dialect menu.
Delivery MUST include messages the agent itself sent.
The object subscription MUST NOT change delivery of any other message.

## REQ-002
Each object message delivered by `recv` MUST carry a `record` member in the form of [[SPEC-086-hark-object-transport#CON-001]].
The existing `message` member MUST keep its current meaning.

## REQ-003
WHEN the object subscription is active, hark MUST deliver object messages from hub backfill on join and on every reconnect.
`ReplayGuard` MUST NOT suppress them. It MUST keep suppressing replayed non-object messages as today.

## REQ-004
An agent MUST be able to request older room history through [[SPEC-086-hark-object-transport#CON-002]].
Hark MUST deliver object messages from the reply through `recv`, like any other object message.

## REQ-005
Hark MUST sign and send object messages byte-for-byte as the agent supplied them.
In an MLS room, the encrypted plaintext MUST equal the supplied bytes.
Hark MUST deliver received object plaintext byte-for-byte as decoded or decrypted.
These rules keep the SDK's cid equal to the cid every browser computes ([[SPEC-085-agent-object-sdk#REQ-008]]).

## REQ-006
In an MLS room, the record's signer MUST be the MLS-authenticated sender handle. Hark MUST drop a message whose `:from` differs from that sender.
In a cleartext room, the signer MUST be the `:from` of a frame the hub delivered. The record MUST state that the hub attested it.
Hark MUST NOT deliver an object record without an established signer.

## REQ-007
Hark MUST NOT parse object contracts, verify object actions, or project state.
Hark MUST NOT drop an object message because its dialect is not installed locally.
Recognition, verification, and projection belong to the SDK ([[SPEC-085-agent-object-sdk#REQ-002]], [[SPEC-085-agent-object-sdk#REQ-004]]).

## ADR-001
Hark transports object messages; the agent's `@cbcl/object` SDK computes cids, verifies, and projects.
Only one canonicaliser and one projection implementation then exist until the SPEC-085 corpus can check a second.
Rejected alternative: hark computes the cid. That needs a Rust canonicaliser byte-identical to the browser's wasm `parse_message`. Without the corpus, divergence stays invisible.
Rejected alternative: embed a JS runtime in hark. That adds a large dependency to do what a separate agent process already does.
Consequence: Stage A agents are JavaScript processes. A shell agent cannot act on objects until Stage B.

## ADR-002
The `record` member is additive in the `recv` JSON response. Existing consumers ignore it.
`hark recv` keeps printing only the message bytes. `hark recv --record` prints the JSON record instead.

## ADR-003
Hark delivers duplicates, including backfill overlap and the hub's echo of the agent's own sends.
The SDK store deduplicates by cid ([[SPEC-085-agent-object-sdk#REQ-004]]). Hark-side deduplication needs the cid, which ADR-001 keeps out of hark.
The cost is repeated delivery of up to one backfill window per reconnect.

## ADR-004
Status: accepted 2026-09-26 (repository owner's instruction; supersedes the second rejected alternative of [[SPEC-086-hark-object-transport#ADR-001]]).
Hark reads, acts on, and creates objects by running the SDK's own code — `controller.js`, `emit.js`, `projection.js`, `store.js`, `object-sdk.js`, `dialects.js` — headlessly in an embedded QuickJS runtime (`rquickjs`), not by porting the projection to Rust.
The vendored files are byte-pinned to a cbcl-bus commit (`src/objects/js/VENDOR.json`, checked by a test). Every browser-bound dependency is replaced by a host function: the content address is `sha2`; canonical text and the dialect, shape, protocol and `message_hash` verdicts are `cbcl-wasm` linked natively at the revision cbcl-bus ships (`cbcl-rs.sha`); `send` is the agent's signed hub connection; the missing-opener history request is [[SPEC-086-hark-object-transport#CON-002]]. Views and the sandbox are excluded: they carry author code and belong to a rendering host.
Why the reversal: ADR-001 weighed a JavaScript runtime against the transport, where a separate agent process already did the work. Weighed against a Rust port of the projection semantics, embedding four hundred lines of pure functions is the smaller risk: parity with browsers holds by construction, and the [[SPEC-085-agent-object-sdk#REQ-007]] corpus becomes a regression net for pin bumps rather than the gate on correctness.
Consequence: hark carries a second cbcl-rs pin. Hark's own pin serialises a quoted `:caused-by` differently from cbcl-bus's, so a cid computed with hark's parser would not equal the browser's; only the cbcl-bus pin may canonicalise object messages. The two pins bump together with `cbcl-rs.sha`.
Consequence: object state is not persisted; a controller rebuilds it from backfill and history replies, as a browser tab does.
Interface: `hark object list|read|act|open`; `GET/POST /v1/agents/{handle}/objects[/{thread}[/act]]` (see `specs/local-api.md`, `specs/cli.md`).

## CON-004
The object journal. Every object message delivered to a subscribed agent is appended, as plaintext plus the attested signer, to `<chat.identity_dir>/objects/<agent>/<room>.jsonl` (directory `0700`, file `0600`), one line per distinct (signer, bytes). A fresh controller — a restarted daemon — replays its journal before serving its first command. The runtime deduplicates by cid, so a journal replay is idempotent.
Why: in a cleartext room a controller rebuilds from backfill and [[SPEC-086-hark-object-transport#CON-002]]; in an MLS room it cannot, because replayed frames from earlier epochs do not decrypt and this member's own sends never did. Without the journal a restarted agent in a private room would fill `replaces`/`removes` blind to its own earlier writes. The journal is the browser's archive, for an agent.
Queue rule: with the runtime attached, a full `recv` queue sheds the oldest object records rather than marking the handle unhealthy — the runtime holds them, and an agent acting through `hark object` need not drain `recv`. Non-object messages overflow as before; without a runtime nothing is shed.
Limits: the runtime runs with a 256 MiB heap, a 4 MiB stack, and a 20 s per-command deadline that a blocking host call (a send awaiting the hub) extends on return.

## CON-001
`recv` response for an object message, as RFC 8259 JSON:
```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "message": "(lang object-<64hex> (check @room :item \"milk\" … :from @alice))",
  "record": {
    "room": "@room",
    "signer": "@alice",
    "attested_by": "mls",
    "own": false,
    "replayed": true
  }
}
```
- `room`: the room handle the frame arrived on.
- `signer`: the handle established by [[SPEC-086-hark-object-transport#REQ-006]].
- `attested_by`: `"mls"` or `"hub"`.
- `own`: true when `signer` equals the agent's handle.
- `replayed`: true when the frame arrived in backfill or a history reply.
The record carries no cid, per [[SPEC-086-hark-object-transport#ADR-001]].

## CON-002
`POST /v1/agents/{handle}/history`, body `{"room": "<room>", "limit": <n>}`.
`limit` is an integer in 1–1000. Any other value returns `400` with `error.code = "malformed_history_request"`.
Hark sends `(history <room> :limit <n> :from <agent-handle>)` on the agent's connection.
While a request for that room is unanswered, a second returns `409` with `error.code = "history_in_flight"`.
An unjoined room returns `409` with `error.code = "room_not_joined"`.
Success returns `202 {"ok": true}`. Replies arrive through `recv`.

## CON-003
Opt-in, off by default:
- CLI: `hark join … --objects`, `hark pair … --objects`.
- API: `POST /v1/agents` accepts `"objects": true`.
- An object dialect name (`object-<64hex>`) in the dialect set is the subscription: a pairing record whose adder chose an object from the room's menu arrives subscribed. Object dialects are stripped before advertisement; they are not capabilities.
- The flag persists in the pairing record (SPEC-026 CON-002), so a restarted daemon resumes it.
Rollback: rejoin without the flag. No other agent or room is affected.

## TEST-001
Core: A browser opens a checklist. A Node agent using `@cbcl/object` over hark `recv`/`send` checks an item. The browser shows it.
The agent's `read` result equals the browser's projected state, compared as JSON.
Negative input: A non-object message is not delivered to an agent with only the object subscription.
Negative output: The browser-computed cid of the agent's action equals the cid the agent's SDK computed before sending.
Traces: [[SPEC-086-hark-object-transport#REQ-001]], [[SPEC-086-hark-object-transport#REQ-002]], [[SPEC-086-hark-object-transport#REQ-005]].

## TEST-002
Core: Restart the hub under a running agent. After reconnect, the agent receives the replayed object messages, and its projected state is unchanged.
Core: Restart the daemon. After more than 50 later frames, the opener is outside backfill. A history request restores it, and the agent's next action is accepted by the browser.
Negative input: A second history request for the same room while one is in flight returns `history_in_flight`.
Negative output: Replayed non-object messages still do not reach `recv`.
Traces: [[SPEC-086-hark-object-transport#REQ-003]], [[SPEC-086-hark-object-transport#REQ-004]].

## TEST-004
Core: `hark object check` on an authoring definition with a view reports the contract and view digests; `open` sends one opener carrying both; a second controller that receives only that opener reads the object's state.
Core: with the object runtime attached, `open` → hub echo → `act` → `read` over a real socket yields the projection of exactly the bytes on the wire, and the echoes deduplicate.
Negative input: an action whose field type contradicts the contract is refused with cbcl-rs's shape blame and never reaches the wire; a contract whose protocol cycles is refused before send.
Negative output: an action received before its opener stays pending, triggers one history request, and is released when the opener arrives.
Traces: [[SPEC-086-hark-object-transport#ADR-004]].

## TEST-005
Core: after a runtime restart with the journal, `read` returns the state the agent had, and the broker's next write on a key replaces the agent's earlier one.
Negative input: a runaway script is stopped at the deadline and the runtime keeps serving.
Negative output: a full `recv` queue sheds the oldest object records and the handle stays connected; a plain message still overflows.
Traces: [[SPEC-086-hark-object-transport#CON-004]].

## TEST-003
Core: In an MLS room, an object message delivers a record with `attested_by: "mls"` and the MLS sender.
Negative input: An MLS message whose `:from` names another member is not delivered.
Negative input: A frame without `:from` in a cleartext room is not delivered as an object record.
Negative output: An object message with an uninstalled dialect is still delivered.
Traces: [[SPEC-086-hark-object-transport#REQ-006]], [[SPEC-086-hark-object-transport#REQ-007]].

## Amendment Channels
The repository owner authorizes scope through task instructions and reviews the resulting PR.
Changes to [[SPEC-085-agent-object-sdk#REQ-008]] require a matching revision here.
Hard stops: [[SPEC-086-hark-object-transport#REQ-005]], [[SPEC-086-hark-object-transport#REQ-006]].

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.2.0 (2026-09-26) — Stage B: native read/act/open by running the SDK headlessly (ADR-004); Stage A implemented.
- 0.1.0 (2026-09-26) — draft: Stage A transport, from the SPEC-085 v0.2.0 review of what hark lacks.
</details>
