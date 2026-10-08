# Pairing grants bound to the MLS group state (`cbcl-mls-pairgrant/v3`): hark contract

Status: **candidate implementation in hark; not independently reviewed.**

- **Supersedes:** the rejected v2 candidate (`5c86075`,
  `docs/decisions/SPEC-061-group-bound-pairing-v2.md`), which is kept as history.
- **Approved direction:** the human domain reviewer approved binding grants to the canonical
  TLS-serialized MLS GroupContext at the signer's admitted epoch. The single-epoch grant lifetime
  was part of that approval.
- **Decision record:** cbcl-bus plan commit `549c0d80`,
  `docs/planning/svelte-chat-migration/implementation/extraction/copied-group-id/`, files
  `decision-candidate.md`, `probe.diff`, `red.log` and `review.json`.
- **Ownership:** SPEC-061 is owned by cbcl-bus, and its normative CON-006 amendment belongs there
  under [[SPEC-103-embeddable-svelte-chat#REQ-013]]. This file records what hark implements and does
  not amend SPEC-061.

## History (kept, not rewritten)

1. **v1.** The original SPEC-061 CON-006 grant was bound to a room NAME. A rival same-room group
   holding a copy of the signer's public leaf satisfied every check.
2. **v2.** Candidate `5c86075` added the raw MLS GroupId. Independent OpenAI Codex review
   (`549c0d80`, `review.json`) reproduced a bypass against the Chat candidate. Hark used the same
   predicate.
   - A rival creator calls OpenMLS `MlsGroup::new_with_group_id` with the genuine group's PUBLIC
     identifier.
   - She signs her own valid genesis for that identifier.
   - She Adds another public KeyPackage of the genuine signer.

   The joining agent's pin matches the copied leaf, the genesis grades TOFU, and the group id is
   equal, so the genuine v2 grant admits the agent into the rival. A public identifier is a name,
   not an anchor.

## v3 contract (as implemented)

- **Label:** `cbcl-mls-pairgrant/v3` (`DS_MLS_PAIRGRANT`).
- **Signed context** (`pins::pairgrant_signing_bytes`). Ed25519 and `lp(x) = u32be(len x) ‖ x` are
  unchanged:

  ```
  lp(label) ‖ lp(room) ‖ lp(raw GroupId) ‖ lp(raw canonical TLS GroupContext)
    ‖ lp(signer_handle) ‖ lp(signer_key) ‖ lp(subject_handle) ‖ lp(subject_key) ‖ u64be(not_after_ms)
  ```

  This is v2 plus `lp(GroupContext)` immediately after `lp(GroupId)`. The GroupContext is the RFC
  9420 §8.1 structure, TLS-serialized by OpenMLS 0.8.1. It carries the protocol version, the
  ciphersuite, the group id, the epoch, the tree hash, the confirmed transcript hash and the
  extensions (the genesis assertion included).
- **Record:** a closed JSON record (`deny_unknown_fields`). Every key is required: `kind, room,
  group_id_b64, group_context_b64, signer_handle, signer_key_b64, subject_handle, subject_key_b64,
  not_after_ms, sig_b64`. Base64 is standard with padding. JSON key order is not normative.
- **Minting** (`PairingGrant::mint(&MlsGroup) -> Result`): the id and the context come only from
  the group passed in. `MlsSession::sign_pairing_grant` passes only the session's installed,
  admitted group. With no admitted group it returns `NotReady`.
  - The context is `group::canonical_group_context`. OpenMLS 0.8.1 makes
    `MlsGroup::export_group_context` available only with `test-utils`, so hark exports a GroupInfo
    signed by a no-op `ContextOnlySigner`. It then reads the context through `group_info_context`,
    the same reader the joiner uses. The GroupInfo's TBS embeds `self.context()` unchanged. Nothing
    is signed and nothing leaves the function.
  - No hub-supplied or caller-chosen id or context is minting authority. The private
    `mint_for_group_state` exists for tests.
- **Judged context.** The stack judging the grant supplies the context. The grant never supplies
  it.
  - **Joiner** (`group::join_by_grant`): the joiner judges against the GroupInfo's own GroupContext,
    which is the state *before* the joiner's external Commit.
    - `group_info_context` reads it from the wire with OpenMLS's own codec, parsing `MLSMessage` as
      u16 version ‖ u16 wire_format = 4 ‖ GroupContext ‖ ….
    - It re-serializes the context and requires the result to be a byte prefix of the body, so a
      non-canonical encoding is refused.
    - `build_external_join` returns the context as `ExternalJoin::pre_join_context`, and only after
      `build_group` has verified the GroupInfo signature. That signature covers exactly these
      re-serialized bytes.
    - The joiner never uses the built group's context. OpenMLS 0.8.1's
      `ExternalCommitBuilder::finalize` merges the Commit before returning, so the built group is
      already one epoch on. `group_info_context_is_the_pre_join_context` asserts this.
  - **Member** (`validation::validate_external_commit`): judges against `canonical_group_context`
    of its own group, before `merge_staged_commit`.
- **Verification order** (`PairingGrant::verify`):
  1. kind;
  2. room;
  3. group id equality (`…different MLS group than…`);
  4. **group context byte-equality**, which refuses with `pairing grant is bound to a stale or
     different MLS group state than the one being joined; …`. This is the fixed stale-grant
     observation, and it surfaces through `SessionEvent::Dropped` on the agent;
  5. expiry;
  6. the signer is exactly one live leaf with the signed key;
  7. subject handle;
  8. subject key;
  9. the signature over the context built from the **judged** id and context.

  The context is compared as bytes, and no new parser is introduced.
- **Dispatch** (`verify_admission_authority`, shared by the joiner and the member):
  - `kind` absent: an invite grant (CON-002, unchanged).
  - `kind` equal to v3: a pairing grant.
  - Any other `kind` is refused and never re-read as an invite: v1, v2, an unknown version, or a
    non-string.
- **Lifetime: single epoch.** Any Commit to the group makes an outstanding grant stale, even before
  its wall-clock expiry: another member's Add, an update, or a removal. Another agent redeeming its
  own grant counts too, so concurrent redemptions need a reissue after the first one lands.
  - A member reissues by calling `sign_pairing_grant` again from its current group.
  - Hark never redeems a grant against a later context and never falls back to id-only authority.
  - An agent holding a stale grant keeps it in meta. Every GroupInfo refuses it, and it seats on
    the next reissued grant it receives.
- **Preserved:**
  - Rollback on any joiner refusal: nothing is installed or persisted, no pin is written, and no
    Commit leaves the session.
  - First-contact, non-creator pairing, for a group that has not changed since the grant was
    issued.
  - Invite grants.
  - The `ExternalAdmission` AAD carriage.
  - Outer CBCL frames.
- **No legacy path:** v1 and v2 grants persisted in agent meta are refused at every join, with
  `kind … is not supported`. Re-pairing is required.

## Shared known-answer vector

- **Vector:** `tests/vectors/pairgrant-v3-context-vector.json`, sha256
  `91f656e1d1fedec4803264861b381edcb1522447c82c33f318011f98de0bba0e`.
- **Generator:** `tests/vectors/gen_pairgrant_v3_vector.py`, an independent Python implementation.
  It hand-encodes the GroupContext with RFC 9420 varints and has no OpenMLS dependency.
- **Hark checks** (`tests/pairgrant_v3_vector.rs`):
  - every vector context parses as an OpenMLS GroupContext and re-serializes canonically;
  - context bytes;
  - signature;
  - grant JSON;
  - all 11 cases through the shared dispatch: `genuine`, `other-group`,
    `copied-group-id-other-context`, `stale-epoch`, `relabelled-context`, `relabelled-group`,
    `v2-record`, `v1-record`, `v3-missing-context`, `unknown-key` and `expired`.
- **Chat:** the Chat candidate session reported that it holds a byte-identical copy at
  `crates/cbcl-mls-wasm/vectors/hark-pairgrant-v3-context-vector.json` and reaches the same
  verdicts. See the evidence README for what hark itself observed.
