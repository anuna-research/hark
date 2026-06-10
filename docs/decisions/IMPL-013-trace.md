# IMPL-013 — SPEC-013 REQ → TEST trace

hark-side implementation of [[SPEC-013-mls-private-channels]] (gate CLEARED
2026-06-10). Module: `src/mls/` (`provider`, `pins`, `keypackages`, `group`,
`validation`, `removal`, `safety`, `session`), wired into `src/chat.rs`,
`src/local_api.rs`, and the `hark safety-number` CLI. Plan + execution
journal: `plans/impl-013-mls.spl` (hence).

| REQ | Obligation (short) | Test(s) |
|---|---|---|
| REQ-001 | Join via Welcome | `mls::group::tests::create_add_join_roundtrip_with_genesis`; `tests/mls_private_channel.rs::two_agents_full_encrypted_channel_lifecycle` |
| REQ-002 | Publish last-resort + one-time KeyPackages on pinned-encrypted join | `mls::keypackages::tests::one_time_packages_build_and_validate`; `mls::session::tests::join_frames_publish_packages_and_idkey` |
| REQ-003 | Commit members when owner | `mls::group::tests::create_add_join_roundtrip_with_genesis` (owner-only enforced in `add_member`); `mls::session::tests::full_session_flow_over_frames` |
| REQ-004 | Deterministic election agreement | `mls::group::tests::election_is_deterministic_over_permutations` |
| REQ-005 | Encrypt outbound; no plaintext content | `mls::validation::tests::encrypt_decrypt_roundtrip_with_authenticated_sender`; NFR-002 assertion in `tests/mls_private_channel.rs` |
| REQ-006 | Decrypt / advance epoch; drop-but-count fork signal | `mls::validation::tests::decrypt_failures_count_toward_fork_signal` |
| REQ-007 | Leaf signer IS the wire Ed25519 key | `mls::tests::leaf_signature_key_is_the_wire_identity_key`, `bound_signer_signs_under_the_wire_key` |
| REQ-008 | Adder verification: target handle + pinned key | `mls::group::tests::adder_verification_rejects_wrong_target_and_unpinned_keys` |
| REQ-009 | Durable group state; reload on restart | `mls::provider::tests::reloads_across_restart`; restart leg of `tests/mls_private_channel.rs` |
| REQ-010 | Web interop (pinned ciphersuite/encoding) | ciphersuite pinned (`CIPHERSUITE`); §10 spike cross-stack round-trip is the standing oracle; live web interop re-run tracked under task-affected |
| REQ-011 | Pins from own verified signatures; rotation ceremony | `mls::pins::tests::tofu_then_conflict_flags_not_rotates`, `rekey_requires_both_signatures_and_fresh_epoch`, `stale_idkey_nonce_rejected_after_rotation` |
| REQ-012 | App-bound, full-tree, pin-checked Welcome validation | `mls::group::tests::pin_violating_welcome_rejected_and_init_key_survives`, `wrong_room_existing_group_and_conflicting_genesis_rejected`, `first_contact_join_is_tofu_with_safety_number_required` |
| REQ-013 | Client-enforced single-use; delete-after-successful-join | `mls::keypackages::tests::ledger_rejects_reuse_and_persists`, `init_keys_are_durably_stored_at_build`; failed-Welcome-keeps-key leg of `pin_violating_welcome_rejected_and_init_key_survives` |
| REQ-014 | Authenticated removal evidence; exact-epoch freshness | `mls::removal::tests::*` (binding/freshness/transplant); `mls::validation::tests::remove_without_evidence_rejected`, `remove_with_stale_evidence_rejected`, `remove_with_fresh_evidence_merges`; creator fallback + third-party rejection in `mls::removal::tests::live_group` |
| REQ-015 | Directory input validation (client side) | `mls::keypackages::tests::malformed_and_oversized_inputs_rejected` |
| REQ-016 | Authority from MLS tree; genesis assertion + capability | `mls::group::tests::k2_guard_rejects_capability_free_creator` (K-2), genesis legs of the round-trip tests; capability check in `validate_leaf_against_pins` |
| REQ-017 | Validate every leaf-changing object; allowlist | `mls::validation::tests::credential_rebinding_self_update_rejected` (the R3-07 oracle), `group_context_extensions_commit_rejected`, `benign_self_update_merges`, remove-evidence tests above |
| REQ-018 | Sender-authenticated `:from` | `mls::validation::tests::encrypt_decrypt_roundtrip_with_authenticated_sender` (`enforce_sender` negative leg) |
| REQ-019 | Self-signed idkey assertion, own DS label | `mls::pins::tests::idkey_assertion_verifies_and_pins`; `mls::session::tests::join_frames_publish_packages_and_idkey` |
| REQ-020 | No unbacked E2EE claim in UI | cbcl-bus change, already done in the live tree per SPEC-013 §8 (R3-15) |
| REQ-021 | Identity safety number + epoch state hash, pinned encoding | `mls::safety::tests::identity_safety_number_vector` (byte-exact vector), `number_binds_group_and_membership`, `live_group_stability_and_flip` |
| REQ-022 | Replenishment + bounded last-resort lifetime | `mls::keypackages::tests::expired_key_package_rejected` (r3_10 regression); pool target + short last-resort lifetime in `join_frames` |
| REQ-023 | Mode pin from admission path; fail closed on downgrade | `mls::session::tests::downgrade_refused_and_fails_closed`, `no_plaintext_before_join`, `mode_pin_persists` |
| REQ-024 | Agent safety-number surface | `hark safety-number` (CLI) over `mls::session::offline_safety_numbers`, exercised in `full_session_flow_over_frames` |
| NFR-001 | Wire-byte compatibility | pinned ciphersuite + TLS serialization throughout; safety-number vector above; live cross-client round-trip tracked under task-affected |
| NFR-002 | No plaintext leak | wire-frame content assertion in `tests/mls_private_channel.rs` |
| NFR-004 | Retention knobs + delete fidelity (condition I) | `mls::provider::tests::deletes_reach_disk`, `state_file_is_0600`; `tests/mls_private_channel.rs::epoch_churn_does_not_accumulate_secrets_on_disk` |
| OQ-001 (A-t) | No cross-protocol signature collision | `mls::pins::tests::no_cross_protocol_signature_collision` |
| OQ-005 | Version bump = re-join | `mls::provider::tests::version_bump_is_a_rejoin_not_a_migration` |
| K-1 | Remove-race retry | `mls::removal::tests::live_group::remove_race_rejected_then_retry_succeeds` |
| K-2 | Creator-capability guard at creation | `mls::group::tests::k2_guard_rejects_capability_free_creator` |

Out of this implementation (tracked elsewhere): condition **J** (`cbcl_ristretto`
audit) is IMPL-016; the affected-repo wire changes (`bye` fan-out with preserved
signature, creator-handle bookkeeping at claim, `cbcl-mls-wasm` identity binding
+ genesis capability, web election from MLS leaves) are the `task-affected`
follow-on in `plans/impl-013-mls.spl`.

## Live playtest findings (2026-06-10, against the cbcl-bus hub on `:8080`)

Driven end to end against a running hub (web client via Playwright; hark via the
daemon). What works live, and the gaps an integration test can't see:

- **Web create-private + persist + creator + mode-pin** — works after fixing a
  Mnesia 4→5 schema-migration bug the playtest surfaced (cbcl-bus
  `fix(hub): make the cbcl-room creator migration actually fire`). The channel
  comes up `private, end-to-end encrypted`, persists with the creator recorded.
- **hark transport + REQ-023 fail-closed** — a hark agent joins an encrypted
  channel by cap, pins the mode encrypted, and **refuses to send** when it is not
  yet an MLS group member (`will not fall back to plaintext — REQ-023`). No
  plaintext leak. (Rough edge: the refused send marks the agent handle unhealthy;
  the security behaviour is correct, the handle lifecycle is not ideal.)
- **`hark init --mls-create`** — bootstraps the MLS group as the room creator on
  join (REQ-016 operator intent): verified live that the agent becomes the sole
  member/owner, the genesis is present, and `hark safety-number` reports it.

- **GAP — cross-agent Add blocked by `idkey` delivery timing.** Two hark agents
  in one encrypted channel do **not** form a 2-member group over the live wire.
  The creator sends `keyget`, the hub pops the target's one-time KeyPackage, but
  the Add then fails REQ-008 locally: the adder has no **pinned** wire key for the
  target. The pin can only come from the target's **self-signed `idkey`
  assertion** (REQ-019) — which the hub fans **once at join, to then-connected
  members only**, and never replays to a peer that connects later (unlike the
  genesis, which rides durably in the GroupContext). Confirmed on disk: each
  creator's pin store contained only its own handle. The session-level
  `full_session_flow_over_frames` test passes precisely because it feeds the
  `idkey` deterministically before the Add. **Fix direction (design, not a
  one-liner):** make a member's `idkey` available to late joiners — re-broadcast
  on observing a new member in `presence`, carry the most-recent `idkey` as a
  queryable directory entry alongside the KeyPackage, or have the adder obtain
  and verify the target's `idkey` before adding. This is a SPEC-013 wiring
  refinement (REQ-019/REQ-011 distribution), independent of the `--mls-create`
  trigger added here.
