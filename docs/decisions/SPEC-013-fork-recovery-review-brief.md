# SPEC-013 fork recovery — cross-vendor adversarial review brief

**Status:** open. **Tier 1, no-go area.** **Reviewer must not be Claude.**

[[SPEC-013-mls-private-channels]] REQ-025 and REQ-026 are `normative-DRAFT`. Their own status
block requires a **cross-vendor** Principle-12 pass before approval — both prior reviews were
same-family Claude, and the round-6 precedent used GPT-5.x. The implementation described here was
written by Claude Opus 5 across a single session, and revised twice inside it in response to
review. It therefore cannot be certified by a fresh Claude context either: same family, same
priors, and by now the same blind spots.

This brief exists so that review can happen without the conversation that produced the code. It is
deliberately front-loaded with **where the defects have actually been**, because that is the most
useful thing a reviewer can be told and the thing a PR description is worst at conveying.

## 1. What to review

| Repo | Landed | Open |
|---|---|---|
| hark | REQ-025 member half (`main`, PR #32) | REQ-026 creator half (PR #33) |
| cbcl-bus | SPEC-063 client half, Add path (`main`, PR #57) | Remove gate (#58), staged commit (#59) |

Primary surface, hark: `src/mls/session.rs` — `begin_resync`, `resync_frames`, `drop_or_recover`,
`clear_resync_state`, `on_keyready`, `admit_resync`, `heal_member`, `on_groupinfo`,
`note_own_seat_echo`. Secondary: `src/mls/validation.rs` (`is_foreign_group`), `src/chat.rs`
(the `SessionEvent::Forked` arm and the status reconciliation after each frame).

Primary surface, cbcl-bus: `apps/cbcl_chat/priv/web/mls-epoch-claim.mjs` (pure),
`mls.js` (`performCommit`, `performRemove`, `startQueuedAdd`, `recoverEpochOps`,
`resetInFlightCommits`), `app.js` (`loadMlsSnapshot`, `epochTokenAll`).

## 2. Where the defects have been — read this before reading the code

Eleven defects have been found **after** the implementer believed the work complete. Their
distribution is the signal:

| Found by | Defect | Class |
|---|---|---|
| Deploying | Group installed in memory, meta on disk pointed at it — `persisted group state missing` | durability ordering |
| Deploying | `WrongGroupId` counted toward the fork threshold → discard/re-seat loop, ~578 epochs burned | trigger false-positive |
| Deploying | After a discard the agent asked only for re-admission, never for a self-seat it could have done | recovery routing |
| Review | `ForkSignal` never reset by a Commit or a join — one bad frame re-discarded a freshly recovered group | recovery bookkeeping |
| Review | Exhausted recovery reached only `tracing`, which nothing collects | observability |
| Review | Status flag cleared only on `Plaintext`; Welcome and Commit both report `Handled` | recovery bookkeeping |
| Review | `hark daemon status` did not print the new diagnostic at all | observability |
| Review | Armed claim orphaned when the tab died before the record existed — permanent room-wide DoS | lifecycle window |
| Own test | Unanswered claim wedged `pendingCommit` forever, blocking all later commits in the room | lifecycle window |
| Own test | REQ-025(d) counters not reset on a **join**, only on a Commit | recovery bookkeeping |
| Own test | Record written after the merge because the binding could not stage | ordering, unsatisfiable |

**Almost none were in the cryptography or the protocol logic.** They were in the bookkeeping
*around* recovery: what gets reset, when a flag clears, which window a crash falls in, what an
operator can see. Three separate rounds landed in that same seam, which suggests it is not
exhausted.

**A reviewer's time is best spent there**, not on the MLS operations, which are thin wrappers over
OpenMLS and were never where this went wrong.

## 3. Specific hypotheses worth attacking

Offered as leads, not as a checklist — and deliberately phrased as claims to be falsified.

1. **Every state-clearing path is complete.** `clear_resync_state` resets `resync_attempts`,
   `resync_exhausted`, `fork_active` and `ForkSignal`. Is there a *fifth* piece of state that
   survives a recovery and shouldn't? `seen_gi_epoch`, `seat_refusals`, `pending_seat`,
   `resync_heal`, `resync_nonces` — which of those should or should not survive a fork, a
   re-admission, a reconnect, a restart? The bug found in review was exactly one such omission.
2. **The fork trigger has no other false positives.** `WrongGroupId` was one. What about
   `TooDistantInThePast` (a legitimately old replayed message), or a frame that fails to
   deserialise because the hub truncated it? Each currently counts toward a threshold that
   discards group state.
3. **REQ-026 cannot be used to evict someone.** The gate is signature-under-pin, strictly
   monotonic nonce, creator ∧ owner, live-leaf, rate limit. Is there an ordering or a state where
   one of those is skipped? Note the rate-limit counter is incremented *before* the eviction is
   known to succeed.
4. **The two-claim heal cannot interleave with anything.** `queuedAfterRemove` holds an Add across
   a release and a fresh claim. What happens if a resync for the *same* member arrives in that
   window? Or a roster change? Or the room's capability is withdrawn between the two?
5. **`resetInFlightCommits` cannot drop an obligation.** It skips rooms with a `deferredWelcome`.
   Is that predicate exactly "merged"? Consider a Remove, which sets `deferredWelcome` with a null
   welcome.
6. **Nonce monotonicity is per-requester and in memory.** `resync_nonces` does not survive a hark
   restart. Can a captured resync be replayed across one?

## 4. What is deliberately not done

- `RESYNC_WAIT_MS` is approximated by roster changes (`SIMPLIFY:` annotated at `resync_frames`).
- REQ-026(c)'s stated residual stands: the pin pre-check is not a full dry-run of the Add.
- cbcl-bus's Remove path does not yet use the staged form (#59 adds the API, #58 adds the path;
  the wiring lands when both are on main).
- `EPOCH_CLAIM_READY` is `false`, so cbcl-bus's half is inert in production.

## 5. Running it

```
cd hark && cargo test && cargo clippy --all-targets     # 437 tests
cd cbcl-bus && node --test apps/cbcl_chat/priv/web/*.test.mjs
cd cbcl-bus/crates/cbcl-mls-wasm && RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build --release --target wasm32-unknown-unknown && \
  wasm-bindgen target/wasm32-unknown-unknown/release/cbcl_mls_wasm.wasm \
    --target nodejs --out-dir pkg-node --out-name cbcl_mls_wasm
cd cbcl-bus/apps/cbcl_chat/priv/web && node test-mls-integration.mjs
cd cbcl-bus && HARK_DIR=../hark bash apps/cbcl_chat/test/e2e/run-spec061-interop.sh
cd cbcl-bus && HARK_DIR=../hark bash apps/cbcl_chat/test/e2e/run-pairgrant-interop.sh
```

Every test added in this work was **red-gated** — observed failing against the previous behaviour
before the fix. That is evidence the tests have teeth; it is **not** evidence the requirements are
the right ones, and it says nothing about the cases nobody thought to write.

## 6. What a green result would and would not mean

PROTO-001's convergence signal is that a review pass yields only cosmetic findings. The most recent
pass found a permanent room-wide denial of service. On that measure this work has **not**
converged, and the honest reading of eleven post-completion defects is that the twelfth exists.

Approval should turn on a reviewer who did not write this failing to find it — not on the tests
being green, which they were at every point above.
