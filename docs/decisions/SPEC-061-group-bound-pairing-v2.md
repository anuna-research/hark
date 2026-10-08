# Group-bound pairing grants (`cbcl-mls-pairgrant/v2`): hark contract

Status: **candidate implementation in hark; not independently reviewed.** The domain choice was
approved by the user (self-appointed human protocol/media domain reviewer), who chose "Bind pairing
grants to the MLS group (Recommended)". The decision is recorded in cbcl-bus at
`docs/planning/svelte-chat-migration/implementation/extraction/pairing-domain-decision.md` and
`group-bound-pairing-domain-decision.json`. SPEC-061 is owned by cbcl-bus. Under
[[SPEC-103-embeddable-svelte-chat#REQ-013]], the normative amendment to SPEC-061 CON-006 belongs
there and needs its own review. This file records what hark implements and why. It does not amend
SPEC-061.

## History (kept, not rewritten)

SPEC-061 REQ-008 / CON-006 introduced the pairing admission grant `cbcl-mls-pairgrant/v1`. A member
that paired an agent signs it, so the agent can seat itself by external Commit while nobody who
could commit an Add is online. Its signed context was:

```
lp("cbcl-mls-pairgrant/v1") ‖ lp(room) ‖ lp(signer_handle) ‖ lp(signer_key)
  ‖ lp(subject_handle) ‖ lp(subject_key) ‖ u64be(not_after_ms)
```

Verifiers required the signer to be exactly one live leaf of the group being judged, with the
signed key. They also required the joining leaf to be exactly the subject handle and key, the room
to match, and the grant to be unexpired. The v1 design and its hark implementation (`hark` ≤
v0.4.1) are attributed to the SPEC-061 authors and to the commits that introduced
`PairingGrant`/`pairgrant_signing_bytes`.

## Defect corrected by v2

The defect was found by independent OpenAI review of the R1 browser candidate. It was reproduced in
cbcl-bus `external-admission-unanchored-pairing.test.mjs`, and natively here by
`a_rival_same_room_group_info_with_the_signers_copied_leaf_is_refused`.

The v1 context names a room, but not a group:

1. Mallory takes another public KeyPackage of the signer (Bob).
2. She Adds that leaf to a rival group that she creates under the same room name. Bob never
   processes her Welcome.
3. The agent has pinned Bob's genuine key. Mallory's genesis is self-signed by an unpinned creator,
   so it grades TOFU and the agent does not refuse it.

In the resulting rival GroupInfo, Bob's copied leaf matches the pin and the genuine v1 grant
verifies, so the agent seats itself in Mallory's group. First-contact TOFU is the intended trust
model for Welcome joins, so the genesis check cannot close this. A pairing grant had no group
anchor, while an invite does: the genesis creator's signature.

## v2 contract (as implemented)

- **Label:** `cbcl-mls-pairgrant/v2` (`DS_MLS_PAIRGRANT`).
- **Signed context** (`pins::pairgrant_signing_bytes`), using the existing `lp` and Ed25519:

  ```
  lp(label) ‖ lp(room) ‖ lp(raw MLS group id) ‖ lp(signer_handle) ‖ lp(signer_key)
    ‖ lp(subject_handle) ‖ lp(subject_key) ‖ u64be(not_after_ms)
  ```

- **Record:** a closed JSON record (`#[serde(deny_unknown_fields)]`) with all keys required:
  `kind, room, group_id_b64, signer_handle, signer_key_b64, subject_handle, subject_key_b64,
  not_after_ms, sig_b64`. `group_id_b64` uses standard base64 (the same engine as every other
  `_b64` field). JSON key order is not normative.
- **Minting:** `PairingGrant::mint` takes `&MlsGroup` and reads the id from it. The private
  `mint_for_group_id` exists only for tests. `MlsSession::sign_pairing_grant` uses only the
  session's installed (admitted) group, never a pending self-seat. Without an admitted group it
  returns `NotReady`. A hub-supplied group id is never minting authority.
- **Dispatch** (`group::verify_admission_authority`), shared by the joiner and the member:
  - If `kind` is absent, the grant is a CON-002 invite grant (unchanged).
  - If `kind` is present and equals v2, it is a pairing grant.
  - If `kind` is present with any other value (v1, an unknown version, or a non-string), the grant
    is refused. It is never re-read as an invite.
- **Verification order** (`PairingGrant::verify`): kind, room, **group id equality with the group
  being judged**, expiry, signer as exactly one live leaf with the signed key, subject handle,
  subject key, and finally the signature over the v2 context. The context is built from the
  *judged* group id, so it never depends on `group_id_b64`.
- **Joiner** (`group::join_by_grant`, used by `MlsSession::on_groupinfo`): checks run on the built
  group before anything is returned, installed, persisted, pinned, or sent:
  - genesis (room, group id, self-signature, creator pin);
  - leaf-vs-pin over the whole tree, the joiner's own leaf included (REQ-012d);
  - admission authority, judged over the tree minus the joiner's own leaf.

  Any refusal rolls the provider back to disk. `pins` is not written. `group::build_external_join`
  is the unverified builder, and only the test suites use it, to build hostile Commits.
- **Member** (`validation::validate_external_commit`): uses the same `verify_admission_authority`.
  The group id comes from the member's own group, and the live leaves come from its current tree,
  before merge.
- **Unchanged:** invite grants, the `ExternalAdmission` AAD carriage, outer CBCL frames
  (`pairgrant`, `groupinfo`, `deliver`), and the signature algorithm.
- **No legacy path:** hark neither produces nor accepts v1. An agent holding a persisted v1 grant
  in its meta will have every join refused, with "kind … is not supported". A member has to issue
  a v2 grant for that agent.

## Shared known-answer vector

- **Vector:** `tests/vectors/pairgrant-v2-context-vector.json`, with its sha256 in
  `pairgrant-v2-context-vector.sha256`.
- **Generator:** `tests/vectors/gen_pairgrant_v2_vector.py`, an independent Python implementation
  written from the decision text.
- **Checks in hark:** `tests/pairgrant_v2_vector.rs` covers the context bytes, the Ed25519
  signature, the grant JSON, and seven accept/reject cases through the shared dispatch.
- **Browser obligation:** the browser contract must consume the byte-identical file (same sha256)
  and reach the same verdicts. Hark cannot verify that side.

## Parity points for the browser candidate

These are what a browser v2 must match, or a grant one stack admits will be refused by the other.

1. The record is closed: an unknown key refuses. The browser's v1 struct was not closed.
2. Dispatch is on whether `kind` is present. The browser's v1 dispatch sent every non-pairing
   `kind` to the invite path, which this correction forbids.
3. The group check comes after the room check and before the expiry check. A different order
   produces different refusal messages, though not different verdicts.
4. `sign_pairing_grant` takes group bytes from the signer's own room group.
5. The joiner runs the same predicate before installing anything, over the tree minus its own
   leaf.
