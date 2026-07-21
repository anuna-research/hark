//! Signed removal evidence (REQ-014).
//!
//! A Remove is merged only on **authenticated evidence**, never on unsigned
//! hub presence. The evidence object binds the removal it authorises —
//! `(room, group_id, epoch, target handle + concrete leaf)` — under its own
//! domain-separation label `cbcl-mls-remove/v1`, so it cannot be transplanted
//! across rooms, groups, epochs, or targets (the REQ-019 pattern). `leaf` is
//! the concrete MLS leaf identity — leaf index + leaf signature key at the
//! evidence epoch — not the handle alone (round-6 K-1): a re-added member is
//! a new leaf in a later epoch, so stale evidence can never remove it.
//!
//! Validity is exact-epoch: evidence minted at epoch N is valid only when the
//! validator's current pre-merge epoch is N. Evidence that loses a race to a
//! concurrent Commit is rejected and the remover re-mints at the new epoch —
//! an accepted availability/retry cost (K-1), not a replay hole.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::pins::lp;
use super::{DS_MLS_REMOVE, MlsError};
use crate::chat_frame::FrameSigner;

/// Who may sign removal evidence for a target (REQ-014 (a)/(b)).
#[derive(Debug, Clone, PartialEq)]
pub enum RemovalAuthority {
    /// The subject's own pinned key — a voluntary leave (`bye`).
    Subject,
    /// The remover's pinned key: the target's `added_by` adder, or the room
    /// creator (the REQ-016 genesis principal — a documented unilateral
    /// eviction authority, attributable and membership-visible).
    Remover { handle: String },
}

/// A signed removal-evidence object, carried with (or referenced by) every
/// Remove proposal/Commit so each member verifies it independently at merge.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RemovalEvidence {
    pub room: String,
    /// MLS GroupId opaque bytes, base64 on the wire.
    pub group_id_b64: String,
    /// The MLS group epoch the evidence is minted at — the current epoch
    /// before applying the Remove Commit. Exact match required at merge.
    pub epoch: u64,
    /// The target's canonical handle (with `@`).
    pub target_handle: String,
    /// The target's concrete leaf: index at the evidence epoch…
    pub target_leaf_index: u32,
    /// …and leaf signature key (base64, 32 bytes) at the evidence epoch.
    pub target_leaf_key_b64: String,
    /// Handle of the principal whose key signed this evidence.
    pub signer_handle: String,
    /// Ed25519 signature (base64) over [`evidence_signing_bytes`].
    pub signature_b64: String,
}

/// The `cbcl-mls-remove/v1` signed context: label, room, group, epoch,
/// target handle, and the concrete leaf (index + key).
pub fn evidence_signing_bytes(
    room: &str,
    group_id: &[u8],
    epoch: u64,
    target_handle: &str,
    target_leaf_index: u32,
    target_leaf_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, DS_MLS_REMOVE.as_bytes());
    lp(&mut out, room.as_bytes());
    lp(&mut out, group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    lp(&mut out, target_handle.as_bytes());
    out.extend_from_slice(&target_leaf_index.to_be_bytes());
    lp(&mut out, target_leaf_key);
    out
}

impl RemovalEvidence {
    /// Mint evidence with `signer` (the subject for a `bye`, or an authorized
    /// remover). The caller binds the *current* epoch; on an epoch race the
    /// evidence is rejected at merge and must be re-minted fresh (K-1).
    #[allow(clippy::too_many_arguments)]
    pub fn mint<S: FrameSigner>(
        signer: &S,
        signer_handle: &str,
        room: &str,
        group_id: &[u8],
        epoch: u64,
        target_handle: &str,
        target_leaf_index: u32,
        target_leaf_key: &[u8; 32],
    ) -> Self {
        let signed = evidence_signing_bytes(
            room,
            group_id,
            epoch,
            target_handle,
            target_leaf_index,
            target_leaf_key,
        );
        Self {
            room: room.to_string(),
            group_id_b64: B64.encode(group_id),
            epoch,
            target_handle: target_handle.to_string(),
            target_leaf_index,
            target_leaf_key_b64: B64.encode(target_leaf_key),
            signer_handle: signer_handle.to_string(),
            signature_b64: B64.encode(signer.sign(&signed)),
        }
    }

    /// Verify this evidence authorises removing exactly `(target_handle,
    /// leaf_index, leaf_key)` from `(room, group_id)` at the validator's
    /// **current pre-merge epoch** (exact, no tolerance window — R5-01), and
    /// that the signature verifies under `signer_key` — the **pinned** key of
    /// the subject or an authorized remover; the caller resolves authority
    /// (REQ-014 (a)/(b)) and supplies the pin.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        signer_key: &[u8; 32],
        room: &str,
        group_id: &[u8],
        current_epoch: u64,
        target_handle: &str,
        target_leaf_index: u32,
        target_leaf_key: &[u8; 32],
    ) -> Result<(), MlsError> {
        if self.room != room {
            return Err(MlsError::Rejected(format!(
                "removal evidence bound to room {}, not {room}",
                self.room
            )));
        }
        let bound_group = B64
            .decode(&self.group_id_b64)
            .map_err(|e| MlsError::Rejected(format!("removal evidence group id: {e}")))?;
        if bound_group != group_id {
            return Err(MlsError::Rejected(
                "removal evidence bound to a different group".into(),
            ));
        }
        if self.epoch != current_epoch {
            return Err(MlsError::Rejected(format!(
                "removal evidence epoch {} != current epoch {current_epoch} (stale or future; \
                 re-mint at the live epoch)",
                self.epoch
            )));
        }
        if self.target_handle != target_handle {
            return Err(MlsError::Rejected(format!(
                "removal evidence targets {}, not {target_handle}",
                self.target_handle
            )));
        }
        if self.target_leaf_index != target_leaf_index {
            return Err(MlsError::Rejected(format!(
                "removal evidence targets leaf {}, not leaf {target_leaf_index}",
                self.target_leaf_index
            )));
        }
        let bound_leaf_key = B64
            .decode(&self.target_leaf_key_b64)
            .map_err(|e| MlsError::Rejected(format!("removal evidence leaf key: {e}")))?;
        if bound_leaf_key != target_leaf_key {
            return Err(MlsError::Rejected(
                "removal evidence bound to a different leaf key (re-added member?)".into(),
            ));
        }

        let signed = evidence_signing_bytes(
            room,
            group_id,
            self.epoch,
            target_handle,
            target_leaf_index,
            target_leaf_key,
        );
        let signature = B64
            .decode(&self.signature_b64)
            .map_err(|e| MlsError::Rejected(format!("removal evidence signature: {e}")))?;
        let vk = VerifyingKey::from_bytes(signer_key)
            .map_err(|_| MlsError::Rejected("removal evidence signer key invalid".into()))?;
        let sig = Signature::from_slice(&signature)
            .map_err(|_| MlsError::Rejected("removal evidence signature malformed".into()))?;
        vk.verify(&signed, &sig)
            .map_err(|_| MlsError::Rejected("removal evidence signature invalid".into()))
    }
}

/// Committer-side removal (REQ-014): the elected owner removes `target`
/// after verifying the evidence itself — the same predicate every validator
/// re-checks at merge — and returns the Commit plus the evidence to fan with
/// it. On an epoch race (evidence minted at an older epoch) this REJECTS;
/// the caller re-mints fresh evidence at the live epoch and retries (K-1).
/// Merges and persists — the one-step convenience over
/// [`stage_remove_member`] + [`merge_staged_commit`](super::group::merge_staged_commit).
pub fn remove_member(
    provider: &super::provider::DurableProvider,
    identity: &super::MlsIdentity,
    group: &mut openmls::prelude::MlsGroup,
    room: &str,
    evidence: &RemovalEvidence,
    pins: &super::pins::PinStore,
    creator_handle: &str,
) -> Result<Vec<u8>, MlsError> {
    let commit = stage_remove_member(
        provider,
        identity,
        group,
        room,
        evidence,
        pins,
        creator_handle,
    )?;
    super::group::merge_staged_commit(provider, group, "merge remove commit")
        .map_err(|failure| failure.error)?;
    Ok(commit)
}

/// Validate and STAGE a Remove without merging it — same crash-safety split
/// as [`stage_add_member`](super::group::stage_add_member): the caller
/// write-aheads the returned Commit before merging, because after the merge
/// nothing can regenerate it for peers that missed the fan.
pub fn stage_remove_member(
    provider: &super::provider::DurableProvider,
    identity: &super::MlsIdentity,
    group: &mut openmls::prelude::MlsGroup,
    room: &str,
    evidence: &RemovalEvidence,
    pins: &super::pins::PinStore,
    creator_handle: &str,
) -> Result<Vec<u8>, MlsError> {
    use super::group::{credential_handle, is_owner};

    if !is_owner(group, identity)? {
        return Err(MlsError::Rejected(
            "not the elected owner; refusing to commit a Remove (REQ-016)".into(),
        ));
    }
    let target = group
        .members()
        .find(|m| {
            credential_handle(&m.credential)
                .map(|h| h == evidence.target_handle)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            MlsError::Rejected(format!(
                "{} is not a member of this group",
                evidence.target_handle
            ))
        })?;
    let target_key = <[u8; 32]>::try_from(target.signature_key.as_slice())
        .map_err(|_| MlsError::Rejected("target leaf key is not 32 bytes".into()))?;

    // Authority + binding + exact-epoch freshness — identical to the
    // validator-side check (REQ-017d), so a committer can never fan a
    // Commit its peers would reject for evidence reasons.
    if evidence.signer_handle != evidence.target_handle && evidence.signer_handle != creator_handle
    {
        return Err(MlsError::Rejected(format!(
            "removal evidence signed by {}, who is neither the subject nor the room creator",
            evidence.signer_handle
        )));
    }
    let signer_pin = pins.pinned(&evidence.signer_handle).ok_or_else(|| {
        MlsError::Rejected(format!(
            "removal evidence signer {} has no pinned key",
            evidence.signer_handle
        ))
    })?;
    evidence.verify(
        &signer_pin.key,
        room,
        group.group_id().as_slice(),
        group.epoch().as_u64(),
        &evidence.target_handle,
        target.index.u32(),
        &target_key,
    )?;

    let (commit, _welcome, _gi) = group
        .remove_members(provider, &identity.signer, &[target.index])
        .map_err(MlsError::stack("remove members"))?;
    use tls_codec::Serialize as _;
    commit
        .tls_serialize_detached()
        .map_err(MlsError::stack("serialize remove commit"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ChatIdentity;

    fn subject() -> ChatIdentity {
        ChatIdentity::from_seed([11u8; 32])
    }

    fn mint_at(epoch: u64) -> (RemovalEvidence, [u8; 32]) {
        let id = subject();
        let key = id.verifying_key_bytes();
        let evidence =
            RemovalEvidence::mint(&id, "@bob", "@research", b"group-1", epoch, "@bob", 3, &key);
        (evidence, key)
    }

    /// REQ-014 (TEST-014): valid subject-signed evidence verifies at the
    /// exact live epoch.
    #[test]
    fn subject_bye_evidence_verifies() {
        let (evidence, key) = mint_at(7);
        evidence
            .verify(&key, "@research", b"group-1", 7, "@bob", 3, &key)
            .expect("fresh, exactly-bound evidence verifies");
    }

    /// K-1 freshness: evidence minted at N is rejected at N+1 (lost the race
    /// to a concurrent Commit) AND at N-1 (future evidence) — exact match,
    /// no tolerance window.
    #[test]
    fn stale_or_future_evidence_rejected() {
        let (evidence, key) = mint_at(7);
        for wrong_epoch in [6, 8, 0, u64::MAX] {
            let err = evidence
                .verify(&key, "@research", b"group-1", wrong_epoch, "@bob", 3, &key)
                .unwrap_err();
            assert!(
                matches!(err, MlsError::Rejected(_)),
                "epoch {wrong_epoch} must reject"
            );
        }
    }

    /// K-1 re-add: evidence bound to the old leaf cannot remove a re-added
    /// member (different leaf index / key at the new epoch).
    #[test]
    fn old_leaf_evidence_cannot_remove_readded_member() {
        let (evidence, key) = mint_at(7);
        // Re-added at a new leaf index…
        assert!(
            evidence
                .verify(&key, "@research", b"group-1", 7, "@bob", 5, &key)
                .is_err()
        );
        // …or with a rotated leaf key.
        let other_key = ChatIdentity::from_seed([12u8; 32]).verifying_key_bytes();
        assert!(
            evidence
                .verify(&key, "@research", b"group-1", 7, "@bob", 3, &other_key)
                .is_err()
        );
    }

    mod live_group {
        use super::super::*;
        use crate::identity::ChatIdentity;
        use crate::mls::group::{add_member, create_group, join_from_welcome};
        use crate::mls::keypackages::{ConsumedLedger, build_one_time};
        use crate::mls::pins::PinStore;
        use crate::mls::provider::DurableProvider;
        use crate::mls::validation::{ForkSignal, Inbound, process_inbound};
        use crate::mls::{MlsError, MlsIdentity};
        use std::fs;
        use std::path::PathBuf;

        struct Party {
            dir: PathBuf,
            provider: DurableProvider,
            identity: MlsIdentity,
            pins: PinStore,
            ledger: ConsumedLedger,
            wire: ChatIdentity,
        }

        fn party(tag: &str, seed: u8, handle: &str) -> Party {
            let dir = std::env::temp_dir()
                .join(format!("hark-mls-rm-{tag}-{handle}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let provider = DurableProvider::open(&dir.join("agent.mls")).unwrap();
            let wire = ChatIdentity::from_seed([seed; 32]);
            let identity = MlsIdentity::from_wire_identity(&wire, handle);
            let pins = PinStore::open(&dir.join("agent.pins")).unwrap();
            let ledger = ConsumedLedger::open(&dir.join("agent.kpledger")).unwrap();
            Party {
                dir,
                provider,
                identity,
                pins,
                ledger,
                wire,
            }
        }

        /// Condition K-1 (TEST-014, round-6 carry): evidence minted at epoch
        /// N loses a race to a concurrent Commit — the committer refuses it
        /// at N+1 — and removal succeeds on retry with evidence re-minted at
        /// the live epoch, which the peer validator then merges.
        #[test]
        fn remove_race_rejected_then_retry_succeeds() {
            let mut alice = party("k1", 61, "@alice");
            let mut bob = party("k1", 62, "@bob");
            let keys = [
                ("@alice".to_string(), alice.wire.verifying_key_bytes()),
                ("@bob".to_string(), bob.wire.verifying_key_bytes()),
            ];
            for p in [&mut alice, &mut bob] {
                for (h, k) in &keys {
                    p.pins.observe_verified(h, k).unwrap();
                }
            }
            let (mut alice_group, genesis) =
                create_group(&alice.provider, &alice.identity, "@research").unwrap();
            let kp = build_one_time(&bob.provider, &bob.identity, 1)
                .unwrap()
                .remove(0);
            let outcome = add_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                &kp.bytes,
                "@bob",
                &alice.pins,
                &alice.ledger,
            )
            .unwrap();
            let mut bob_group = join_from_welcome(
                &bob.provider,
                &bob.identity,
                &outcome.welcome_bytes,
                "@research",
                &mut bob.pins,
                &mut bob.ledger,
                None,
            )
            .unwrap()
            .group;

            // Bob mints his bye at epoch N…
            let bob_member = alice_group
                .members()
                .find(|m| m.signature_key == bob.wire.verifying_key_bytes())
                .unwrap();
            let bob_key = <[u8; 32]>::try_from(bob_member.signature_key.as_slice()).unwrap();
            let epoch_n = alice_group.epoch().as_u64();
            let stale_evidence = RemovalEvidence::mint(
                &bob.wire,
                "@bob",
                "@research",
                alice_group.group_id().as_slice(),
                epoch_n,
                "@bob",
                bob_member.index.u32(),
                &bob_key,
            );

            // …but a concurrent Commit advances the group to N+1 first.
            use openmls::prelude::LeafNodeParameters;
            use tls_codec::Serialize as _;
            let bundle = alice_group
                .self_update(
                    &alice.provider,
                    &alice.identity.signer,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            alice_group.merge_pending_commit(&alice.provider).unwrap();
            let race_commit = bundle.commit().tls_serialize_detached().unwrap();
            let mut fork = ForkSignal::default();
            let merged = process_inbound(
                &bob.provider,
                &mut bob_group,
                &race_commit,
                "@research",
                &mut bob.pins,
                &genesis,
                None,
                &mut fork,
                false,
            )
            .unwrap();
            assert!(matches!(merged, Inbound::Handshake { .. }));
            assert_eq!(alice_group.epoch().as_u64(), epoch_n + 1);

            // The stale evidence is correctly REJECTED — by the committer.
            let err = remove_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                "@research",
                &stale_evidence,
                &alice.pins,
                "@alice",
            )
            .unwrap_err();
            assert!(matches!(err, MlsError::Rejected(_)), "{err}");
            assert_eq!(
                alice_group.members().count(),
                2,
                "stale evidence must not remove anyone"
            );

            // Honest retry: bob re-mints at the live epoch automatically…
            let bob_member = alice_group
                .members()
                .find(|m| m.signature_key == bob.wire.verifying_key_bytes())
                .unwrap();
            let fresh_evidence = RemovalEvidence::mint(
                &bob.wire,
                "@bob",
                "@research",
                alice_group.group_id().as_slice(),
                alice_group.epoch().as_u64(),
                "@bob",
                bob_member.index.u32(),
                &bob_key,
            );
            let commit_wire = remove_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                "@research",
                &fresh_evidence,
                &alice.pins,
                "@alice",
            )
            .expect("retry with fresh evidence succeeds");
            assert_eq!(alice_group.members().count(), 1);

            // …and the peer validator merges it with the fresh evidence.
            let merged = process_inbound(
                &bob.provider,
                &mut bob_group,
                &commit_wire,
                "@research",
                &mut bob.pins,
                &genesis,
                Some(&fresh_evidence),
                &mut fork,
                false,
            )
            .unwrap();
            assert!(matches!(merged, Inbound::Handshake { .. }));
            assert_eq!(bob_group.members().count(), 1);

            let _ = fs::remove_dir_all(&alice.dir);
            let _ = fs::remove_dir_all(&bob.dir);
        }

        /// REQ-014 (b): the room creator's signed evidence is an accepted
        /// authority (the documented unilateral, attributable eviction path
        /// for a crashed member that can never sign a bye).
        #[test]
        fn creator_fallback_evidence_accepted() {
            let mut alice = party("creator", 63, "@alice");
            let mut bob = party("creator", 64, "@bob");
            let keys = [
                ("@alice".to_string(), alice.wire.verifying_key_bytes()),
                ("@bob".to_string(), bob.wire.verifying_key_bytes()),
            ];
            for p in [&mut alice, &mut bob] {
                for (h, k) in &keys {
                    p.pins.observe_verified(h, k).unwrap();
                }
            }
            let (mut alice_group, _genesis) =
                create_group(&alice.provider, &alice.identity, "@research").unwrap();
            let kp = build_one_time(&bob.provider, &bob.identity, 1)
                .unwrap()
                .remove(0);
            add_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                &kp.bytes,
                "@bob",
                &alice.pins,
                &alice.ledger,
            )
            .unwrap();

            // Bob crashed; alice (creator) signs the eviction herself.
            let bob_member = alice_group
                .members()
                .find(|m| m.signature_key == bob.wire.verifying_key_bytes())
                .unwrap();
            let bob_key = <[u8; 32]>::try_from(bob_member.signature_key.as_slice()).unwrap();
            let evidence = RemovalEvidence::mint(
                &alice.wire,
                "@alice",
                "@research",
                alice_group.group_id().as_slice(),
                alice_group.epoch().as_u64(),
                "@bob",
                bob_member.index.u32(),
                &bob_key,
            );
            remove_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                "@research",
                &evidence,
                &alice.pins,
                "@alice",
            )
            .expect("creator-signed evidence is an accepted authority");
            assert_eq!(alice_group.members().count(), 1);

            let _ = fs::remove_dir_all(&alice.dir);
            let _ = fs::remove_dir_all(&bob.dir);
        }

        /// A third party (neither subject nor creator) cannot author
        /// removal evidence, even with a valid signature under its own pin.
        #[test]
        fn third_party_evidence_rejected() {
            let mut alice = party("3p", 65, "@alice");
            let mut bob = party("3p", 66, "@bob");
            let carol = party("3p", 67, "@carol");
            let keys = [
                ("@alice".to_string(), alice.wire.verifying_key_bytes()),
                ("@bob".to_string(), bob.wire.verifying_key_bytes()),
                ("@carol".to_string(), carol.wire.verifying_key_bytes()),
            ];
            for p in [&mut alice, &mut bob] {
                for (h, k) in &keys {
                    p.pins.observe_verified(h, k).unwrap();
                }
            }
            let (mut alice_group, _genesis) =
                create_group(&alice.provider, &alice.identity, "@research").unwrap();
            let kp = build_one_time(&bob.provider, &bob.identity, 1)
                .unwrap()
                .remove(0);
            add_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                &kp.bytes,
                "@bob",
                &alice.pins,
                &alice.ledger,
            )
            .unwrap();

            let bob_member = alice_group
                .members()
                .find(|m| m.signature_key == bob.wire.verifying_key_bytes())
                .unwrap();
            let bob_key = <[u8; 32]>::try_from(bob_member.signature_key.as_slice()).unwrap();
            let evidence = RemovalEvidence::mint(
                &carol.wire,
                "@carol",
                "@research",
                alice_group.group_id().as_slice(),
                alice_group.epoch().as_u64(),
                "@bob",
                bob_member.index.u32(),
                &bob_key,
            );
            let err = remove_member(
                &alice.provider,
                &alice.identity,
                &mut alice_group,
                "@research",
                &evidence,
                &alice.pins,
                "@alice",
            )
            .unwrap_err();
            assert!(matches!(err, MlsError::Rejected(_)));
            assert_eq!(alice_group.members().count(), 2);

            let _ = fs::remove_dir_all(&alice.dir);
            let _ = fs::remove_dir_all(&bob.dir);
            let _ = fs::remove_dir_all(&carol.dir);
        }
    }

    /// Transplant resistance: evidence cannot move across rooms, groups, or
    /// targets, and a non-signer key fails verification.
    #[test]
    fn evidence_cannot_be_transplanted() {
        let (evidence, key) = mint_at(7);
        assert!(
            evidence
                .verify(&key, "@other-room", b"group-1", 7, "@bob", 3, &key)
                .is_err()
        );
        assert!(
            evidence
                .verify(&key, "@research", b"group-2", 7, "@bob", 3, &key)
                .is_err()
        );
        assert!(
            evidence
                .verify(&key, "@research", b"group-1", 7, "@carol", 3, &key)
                .is_err()
        );
        let wrong_signer = ChatIdentity::from_seed([13u8; 32]).verifying_key_bytes();
        assert!(
            evidence
                .verify(&wrong_signer, "@research", b"group-1", 7, "@bob", 3, &key)
                .is_err()
        );
    }
}
