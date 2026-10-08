# Candidate report: hark pairing v3 (`cbcl-mls-pairgrant/v3`, grants bound to the MLS GroupContext)

- **Branch:** `circus/svelte-pairing-context-hark/1`. The full candidate history is on this branch:
  - `5c86075`, the v2 candidate, which was rejected;
  - `59ca6c6`, the v3 repair;
  - this evidence commit.
- **Author:** Claude Opus 5.5 (Anthropic), as an implementation candidate.
- **Status:** CANDIDATE. Not pushed, not merged, and **not independently reviewed**.

Passing tests show that the code does what these tests ask. They are not cross-model or human
review, and none has happened yet. The contract is `docs/decisions/SPEC-061-pairing-context-v3.md`.

## Why this exists

cbcl-bus `549c0d80` (OpenAI Codex review) reproduced a bypass of the v2 Chat candidate, and its
`review.json` recorded that hark had the matching predicate "by source inspection; native copied-ID
test not yet executed". The bypass:

- the rival creator reuses the genuine group's **public** GroupId with OpenMLS `new_with_group_id`;
- she mints her own valid genesis for that id;
- she Adds a copy of the signer's public leaf.

Under the rival, the genuine v2 grant then admits the agent. The human domain reviewer approved the
recommended resolution: bind the grant to the canonical TLS GroupContext at the signer's admitted
epoch, which makes a grant single-epoch.

## Native reproduction of the bypass (hark)

Mutant **C3** puts back the v2 predicate: no context equality and no `lp(GroupContext)`. Under it,
`a_rival_under_the_copied_public_group_id_is_refused` fails with **"the joiner installed a group it
must refuse: rival under copied group id"**, so the agent seated itself in the rival. The log is
`c3-copied-id-admitted.red.log`. With v3 the same test is green.

In that test the rival has:
- the copied id (`group_info_group_id(rival_gi) == genuine id`);
- its own genesis for that id, graded TOFU;
- the same epoch as the genuine group;
- a `@bob` leaf equal to the agent's pin for Bob.

The genuine grant is refused with "stale or different MLS group state":
- by the joiner, with no group in the provider, the durable `agent.mls`/`agent.pins` bytes
  unchanged, and the in-memory pins unchanged;
- by the rival's member, before merge.

The same unchanged grant then seats the agent in the genuine group, and the member admits it.

## Required acceptance → evidence

All tests use real OpenMLS 0.8.1 groups with no mocks. They are `src/mls/group.rs` tests unless
noted.

| Requirement | Test |
|---|---|
| Copied public GroupId + own valid genesis + copied signer leaf: genuine v3 grant refused before any Commit, install, persistence or pin effect | `a_rival_under_the_copied_public_group_id_is_refused` (joiner and member). Session frame path: `session.rs::a_rival_group_info_yields_no_commit_and_leaves_the_grant_redeemable`, which now uses the copied id. It asserts no `deliver`, no pending seat, no installed group, nothing left in the provider, and the grant unspent. The genuine GroupInfo still seats the agent |
| Fresh-id rival (the v1 attack) is still refused | `a_rival_same_room_group_info_with_the_signers_copied_leaf_is_refused` |
| Wrong context: same id, other state | `a_grant_for_another_group_state_is_refused_by_joiner_and_member` |
| Relabelled context: `group_context_b64` rewritten, signature kept, so the signature breaks | same test (joiner and member) |
| Stale epoch: any Commit makes an unexpired grant stale; reissue works | `a_grant_is_stale_after_any_commit_until_reissued`. Alice Adds Carol, Bob merges, and the old grant is refused by joiner and member. Bob's reissued grant seats the agent |
| Positive matching context; first-contact, non-creator pairing for an unchanged group | `a_member_authorises_an_agent_that_seats_itself`. Asserts creator, signer and GroupInfo contexts are equal. Bob is a non-creator signer and the creator is unpinned (TOFU) |
| Joiner uses the verified pre-join context, not the post-external-Commit one | `group_info_context_is_the_pre_join_context`. Asserts `pre_join_context` equals the minted context, which differs from the built group's own context because OpenMLS already merged it. Also mutant C4 |
| Member uses its pre-merge context | mutant C5 (judging against the staged/post-merge context) is killed |
| v1, v2, unknown and non-string kinds refused, never routed to invite; v3 record without context refused; closed record | `old_unknown_and_malformed_pairing_records_are_refused_not_routed_to_invite`. Includes a genuine v2 grant for this very group |
| Forged, expired, subject-mismatch, non-member and re-pointed signer (joiner **and** member) | `a_member_authorises_an_agent_that_seats_itself`, cases 1–5 |
| Joiner pin checks (creator pin, tree pin, wrong room) | `joiner_refuses_group_info_conflicting_with_its_pins` |
| Shared bytes and verdicts | `tests/pairgrant_v3_vector.rs`, 4 tests: digest, canonical OpenMLS contexts, context, signature and JSON, and 11 verdict cases |

## Mutation suite

`run_mutations.py` weakens one guard at a time, runs the named tests, and restores the files
byte-for-byte. Its output is in `mutation-results.txt`: **ALL MUTANTS KILLED**, which is 17 of 17
killable mutants.

- **M1–M8** are the v2 guards, re-sited for v3: group id, `lp(group_id)`, kind dispatch, joiner
  verification, rollback, closed record, tree pins, and a member trusting the grant's group id.
- **C1** drops the context equality. The signature over the *judged* context still refuses, but
  with the wrong reason, and the copied-id, stale, wrong-context and vector tests catch that.
- **C2** drops `lp(context)` from the signed bytes.
- **C3** drops both C1 and C2, which is the v2 predicate. The rival is admitted (red log above).
- **C4** has the joiner judge against the post-Commit context.
- **C5** has the member judge against the post-merge context.
- **C6** has the member trust the grant's own context.
- **C7** has the joiner trust the grant's own context.
- **C8** mints over an empty context.
- **C9** has the GroupInfo reader accept a wrong wire format.
- **C10** removes the canonical-prefix check from the GroupInfo context reader, and it is an
  **equivalent mutant** under tls_codec 0.4 / OpenMLS 0.8.1. The codec itself refuses the
  non-minimal varint, which `group_info_context_is_the_pre_join_context` asserts directly, and every
  other GroupContext field has a single encoding. The check is kept as defence in depth. The runner
  reports it as "survived as expected", not as killed.

## Cross-stack (Chat candidate) — actually run

The Chat state used was worktree `cbcl-bus-svelte-pairing-context-chat-1` at HEAD `f9b67131`. Its
v3 work was **uncommitted** when this ran, so it is identified by file digest:

- `crates/cbcl-mls-wasm/src/lib.rs`: `27ac7ce5…bd89`
- `apps/cbcl_chat/test/web/pairgrant-interop.mjs`: `8a1f0d96…f1c`
- `pkg-node/cbcl_mls_wasm_bg.wasm`: `bcf731e2…2482423`

The hark side was `59ca6c6`.

| Check | Result |
|---|---|
| `HARK_DIR=<this worktree> bash apps/cbcl_chat/test/e2e/run-pairgrant-interop.sh` | **PASS** (`interop-pairgrant.log`). In the honest case, a web member that is not the creator mints v3. Hark seats itself by external Commit and the web member admits it. In the forged and wrong-key cases, hark refuses before building a Commit. The web-minted grant left by the run (from the final, wrong-key case, which uses the same member mint path) was checked to be `kind = cbcl-mls-pairgrant/v3` with a 403-byte `group_context_b64` |
| `run-spec061-interop.sh` (invite path, unchanged) | **PASS** (`interop-spec061.log`) |
| Chat consumes hark's vector byte-identically | Reported by the Chat session: it holds a copy of hark's vector (sha256 `91f656e1…ba0e`, confirmed here) as `crates/cbcl-mls-wasm/vectors/hark-pairgrant-v3-context-vector.json`, and its `pairgrant_v3_hark_vector_agrees` passes. Hark did not run that Chat test itself |
| Hark consumes Chat's own Node vector | `crates/cbcl-mls-wasm/vectors/pairgrant-v3.json` (sha256 `2fff7b3c…4d76`). Checked with hark's real `pairgrant_signing_bytes` and `verify_admission_authority` using a throwaway test, kept as `check_chat_node_vector.rs.txt`. It depends on the Chat path and is not committed as a test. Both vectors, including a 1-byte group with a Unicode room, give equal signing bytes. In both, the genuine grant is accepted and the stale and rival contexts are refused as `reject:context` |

The cross-stack harness has no copied-id or stale-epoch case, because it creates and advances
groups internally. Cross-stack agreement on those verdicts rests on the shared vectors, both
directions above, and not on a live interop run.

## Commands run (results at commit time)

```
cargo clippy --all-targets -- -D warnings            # clean
cargo test                                           # all suites ok; 507 passed, 0 failed (lib 391)
cargo test --test pairgrant_v3_vector                # 4 passed
python3 docs/evidence/pairing-context-v3/run_mutations.py   # ALL MUTANTS KILLED (C10 equivalent)
python3 tests/vectors/gen_pairgrant_v3_vector.py     # regenerates the vector byte-identically
```

`cargo fmt --check` and zetl were not used as gates, because both are already red on `main` for
unrelated files. The new test file is rustfmt-formatted.

## Not done / residual risk

1. **No independent review** of this repair. The decision requires an independent protocol
   verifier before migration entry closes.
2. **The Chat side was uncommitted** at the time of the interop run. A re-run against a committed
   Chat candidate is needed for a reproducible pair.
3. **SPEC-061 CON-006 amendment** for v3 belongs to cbcl-bus, under SPEC-103 REQ-013.
4. **Single-epoch usability.** Concurrent redemptions, and any member activity between pairing and
   redemption, force a reissue. Hark surfaces this as the fixed "stale or different MLS group state"
   refusal on `SessionEvent::Dropped`. Nothing in hark *requests* a reissue automatically.
5. **Liveness, unchanged from v2.** `on_groupinfo` records `seen_gi_epoch` before verifying, so a
   refused rival carrying a high hub-asserted `:epoch` can delay seating. This does not widen the
   hub's power.
6. **Persisted v1/v2 grants** are refused by design, and re-pairing is needed.
