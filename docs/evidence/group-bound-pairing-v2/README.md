# Candidate report: hark group-bound pairing (`cbcl-mls-pairgrant/v2`)

- **Branch:** `circus/svelte-group-bound-pairing-hark/1`, based on `50acfba` (v0.4.1).
- **Author:** Claude Opus 5.5 (Anthropic), as an implementation candidate.
- **Status:** CANDIDATE. Not pushed, not merged, and **not independently reviewed**.

Tests passing is evidence that the code does what these tests ask. It is not evidence of
cross-model or human review, and none has happened. The contract is in
`docs/decisions/SPEC-061-group-bound-pairing-v2.md`.

## What changed

| File | Change |
|---|---|
| `src/mls/mod.rs` | `DS_MLS_PAIRGRANT` changed to `cbcl-mls-pairgrant/v2`, with the reason recorded |
| `src/mls/pins.rs` | `pairgrant_signing_bytes` takes `group_id` and adds `lp(group_id)` after `lp(room)`; the KAT is updated to v2 and asserts that the group is load-bearing |
| `src/mls/group.rs` | Closed `PairingGrant` with `group_id_b64`. `mint` takes `&MlsGroup`. `verify` judges group id and live leaves. Shared `verify_admission_authority` (unsupported kinds are refused, never treated as invites). `join_by_grant` now verifies genesis, tree pins and the grant, rolling back on refusal. `build_external_join` is the unverified builder used by tests |
| `src/mls/validation.rs` | The member path uses the shared predicate against its own group id and tree |
| `src/mls/session.rs` | `sign_pairing_grant` mints from the installed group only. `on_groupinfo` passes the clock. Doc updates |
| `tests/vectors/*`, `tests/pairgrant_v2_vector.rs` | Shared known-answer vector, its independent Python generator, and the hark checks |

## Required acceptance → evidence

All tests below are real native OpenMLS 0.8.1 groups (no mocks): `src/mls/group.rs` tests unless
noted.

| Requirement | Test |
|---|---|
| Reproduced rival same-room GroupInfo (copied pinned signer leaf, unchanged genuine v2 grant) is refused | `a_rival_same_room_group_info_with_the_signers_copied_leaf_is_refused`. It also asserts the attack's preconditions: same room, TOFU genesis, the rival's `@bob` leaf equal to the pinned key. The same grant then seats the agent in the genuine group |
| Same, on the agent's real frame path: no Commit, no ciphertext, nothing pending or installed, grant unspent | `session.rs::a_rival_group_info_yields_no_commit_and_leaves_the_grant_redeemable` |
| First-contact, non-creator pairing still works | `a_member_authorises_an_agent_that_seats_itself`: Bob is a non-creator signer, the creator is unpinned (TOFU), and the member admits the agent. Session tests `a_self_seat_is_not_a_membership_until_the_hub_echoes_it` and others still pass |
| Wrong group refused by joiner and member; relabelled `group_id_b64` breaks the signature | `a_grant_for_another_group_is_refused_by_joiner_and_member` |
| Old version / unknown kind / non-string kind / v2 without group / unknown key refused, not routed to invite | `old_unknown_and_malformed_pairing_records_are_refused_not_routed_to_invite` |
| Forged, expired, subject mismatch, non-member signer, re-pointed signer refused by joiner **and** member | `a_member_authorises_an_agent_that_seats_itself` (cases 1–5) |
| Joiner genesis creator-pin conflict, tree pin conflict, and wrong room | `joiner_refuses_group_info_conflicting_with_its_pins` |
| Joiner refusal leaves no install, persistence or pin change | `joiner_refuses` helper. After every refusal it asserts: no group for that id in the provider, durable `agent.mls`/`agent.pins` bytes unchanged, in-memory pins unchanged |
| Shared known-answer context vector | `tests/pairgrant_v2_vector.rs` against `tests/vectors/pairgrant-v2-context-vector.json` (sha256 `4aff66e7…4856`) |

## Red / mutation evidence

`run_mutations.py` weakens one guard at a time, runs the named tests, and restores the file. The
output is recorded in `mutation-results.txt`, and all 8 mutants were killed:

- **M1** removes the group-id equality, which restores v1 authority. The rival test goes red, which
  shows the native reproduction of the reported attack succeeds without the v2 check.
- **M2** removes `lp(group_id)` from the context.
- **M3** routes unsupported kinds to the invite path.
- **M4** lets the joiner install without verification.
- **M5** skips the rollback on refusal.
- **M6** makes the record open.
- **M7** skips the joiner's tree pin check.
- **M8** has the member trust the grant's own group id.

I did not run the new tests against the untouched v0.4.1 tree, because the v1 API has no group
parameter. M1 and M4 together are the closest equivalent: the v1 verifier with v1's joiner
behaviour.

## Commands run (results at commit time)

```
cargo clippy --all-targets -- -D warnings            # clean
cargo test                                           # all suites ok; lib 387 passed, 0 failed
cargo test --test pairgrant_v2_vector                # 3 passed
python3 docs/evidence/group-bound-pairing-v2/run_mutations.py   # ALL MUTANTS KILLED
python3 tests/vectors/gen_pairgrant_v2_vector.py     # regenerates the vector byte-identically
```

`cargo fmt --check` and zetl were not used as gates, because both are already red on `main` for
unrelated files. The one new Rust file, `tests/pairgrant_v2_vector.rs`, was rustfmt-formatted.

## Not done / residual risk

1. **No cross-stack run.** The browser worktree (`cbcl-bus-svelte-group-bound-pairing-chat-1`,
   merge `952c75d1` of R1 candidate `5f496150`) still implements v1 and has no v2 changes, so the
   following are expected to fail until the browser lands v2 against the shared vector:
   - `examples/pairgrant_interop.rs` with `run-pairgrant-interop.sh`, a web-minted grant redeemed
     by hark;
   - cbcl-bus `external-admission-unanchored-pairing.test.mjs`.

   I did not run them, and nothing here claims they pass.
2. **No independent review.** Per the decision, cross-stack tests and an independent protocol
   verifier must validate this before migration entry closes.
3. **SPEC-061 amendment.** SPEC-061 CON-006 lives in cbcl-bus and still describes v1. Its
   amendment is a separate reviewed change under SPEC-103 REQ-013. The hark-side contract note is
   `docs/decisions/SPEC-061-group-bound-pairing-v2.md`.
4. **Liveness, not authority.** `on_groupinfo` records `seen_gi_epoch` before verifying. A refused
   GroupInfo carrying a high hub-asserted `:epoch` therefore makes later genuine GroupInfos at lower
   epochs read as stale. The hub can already withhold GroupInfos, so this does not widen the hub's
   power. It does mean a refused rival can delay seating, and it is left unchanged here.
5. **Existing v1 grants** persisted in agent meta are now refused at every join attempt, by design
   (no legacy path). Re-pairing is needed.
6. Error-message order matches the browser's v1 order with the group check inserted after the room
   check. The browser v2 should use the same order (contract doc, "Parity points").
