//! Inbound validation and the encrypt/decrypt path (REQ-005, REQ-006,
//! REQ-017, REQ-018).
//!
//! The shipped wasm glue merges protocol messages with **no** app checks —
//! the defect REQ-017 corrects. Here, before merging any Commit or storing
//! any proposal, **every leaf-changing object** is inspected: Add, Update,
//! and Remove proposals AND the committer's UpdatePath leaf. Credential
//! identity is immutable per member (the §10 spike proved openmls happily
//! accepts a credential-rebinding self-Update — clause (c) is load-bearing,
//! not defence-in-depth); Removes carry merge-time-verified evidence
//! (REQ-014, clause (d)); everything outside the Add/Update/Remove allowlist
//! is rejected fail-closed (clause (e)), including any proposal that would
//! touch the immutable genesis extension.

use openmls::prelude::{
    LeafNode, MlsGroup, MlsMessageIn, ProcessedMessageContent, Sender, StagedCommit,
};
use tls_codec::{DeserializeBytes as _, Serialize as _};

use super::group::{
    GenesisAssertion, credential_handle, elect_committer, group_genesis_creator, member_bindings,
};
use super::pins::PinStore;
use super::provider::DurableProvider;
use super::removal::RemovalEvidence;
use super::{GENESIS_EXT_TYPE, MlsError, MlsIdentity};

/// REQ-006: how many consecutive decrypt/process failures constitute a
/// probable fork / equivocation signal.
pub const FORK_SIGNAL_THRESHOLD: u32 = 3;

/// Drop-but-count state (REQ-006): an undecryptable frame is dropped without
/// aborting, but a persistent run is surfaced as a probable-fork signal that
/// feeds the REQ-021 safety-number comparison — silent drop must not mask a
/// hub that forked the group by equivocating Commit order.
#[derive(Debug, Default)]
pub struct ForkSignal {
    consecutive_failures: u32,
}

impl ForkSignal {
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    /// True once the failure run crosses the threshold: surface a
    /// probable-fork warning and prompt an epoch-state-hash comparison.
    pub fn probable_fork(&self) -> bool {
        self.consecutive_failures >= FORK_SIGNAL_THRESHOLD
    }
}

/// A processed inbound MLS frame.
#[derive(Debug)]
pub enum Inbound {
    /// A decrypted application message from an authenticated member leaf.
    /// `sender_handle` is the leaf's pinned handle — the value the inner
    /// CBCL `:from` MUST match (REQ-018).
    App {
        plaintext: Vec<u8>,
        sender_handle: String,
    },
    /// A validated, merged Commit or stored proposal.
    Handshake,
    /// An undecryptable/unprocessable frame — dropped, counted (REQ-006).
    Dropped { reason: String, probable_fork: bool },
}

/// REQ-005: encrypt one outbound channel message as an MLS application
/// message. The caller (session) guarantees no plaintext fallback exists.
pub fn encrypt_message(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group: &mut MlsGroup,
    plaintext: &[u8],
) -> Result<Vec<u8>, MlsError> {
    let out = group
        .create_message(provider, &identity.signer, plaintext)
        .map_err(MlsError::stack("create message"))?;
    provider.persist()?;
    out.tls_serialize_detached()
        .map_err(MlsError::stack("serialize message"))
}

/// REQ-018: the inner CBCL `:from` must equal the authenticated MLS sender's
/// pinned handle; a mismatch is rejected, not rendered.
pub fn enforce_sender(from_field: &str, sender_handle: &str) -> Result<(), MlsError> {
    if from_field != sender_handle {
        return Err(MlsError::Rejected(format!(
            "inner :from {from_field} does not match the authenticated MLS sender \
             {sender_handle} (REQ-018 forgery)"
        )));
    }
    Ok(())
}

/// Process one inbound MLS wire frame (REQ-006 + REQ-017). Commits are
/// merged ONLY after full validation; proposals are stored ONLY after the
/// same per-object validation; application messages return the sender's
/// authenticated handle. Process/decrypt failures are dropped-but-counted.
#[allow(clippy::too_many_arguments)]
pub fn process_inbound(
    provider: &DurableProvider,
    group: &mut MlsGroup,
    wire: &[u8],
    room: &str,
    pins: &mut PinStore,
    genesis: &GenesisAssertion,
    evidence: Option<&RemovalEvidence>,
    fork: &mut ForkSignal,
) -> Result<Inbound, MlsError> {
    let msg = match MlsMessageIn::tls_deserialize_exact_bytes(wire) {
        Ok(msg) => msg,
        Err(e) => {
            fork.record_failure();
            return Ok(Inbound::Dropped {
                reason: format!("frame deserialize: {e:?}"),
                probable_fork: fork.probable_fork(),
            });
        }
    };
    let protocol = match msg.try_into_protocol_message() {
        Ok(p) => p,
        Err(e) => {
            fork.record_failure();
            return Ok(Inbound::Dropped {
                reason: format!("not a protocol message: {e:?}"),
                probable_fork: fork.probable_fork(),
            });
        }
    };
    // NOTE (replay handling): benign replays — the committer's intentional
    // retained-transition re-drives, echoes of own commits, hub re-fans —
    // are recognized by the SESSION before this function runs, by exact
    // ciphertext match against commits it authored or previously verified
    // and applied. No exemption is granted here from the frame's own
    // headers: epoch and content type ride unauthenticated on the wire
    // (verified only when the AEAD opens below), so an active hub could
    // relabel a divergent member's application frame as a Commit to dodge
    // the fork counter. Everything unrecognized that fails to process is
    // counted (REQ-006) — including past-epoch application traffic, which
    // is a live member sending from divergent state.
    let processed = match group.process_message(provider, protocol) {
        Ok(p) => p,
        Err(e) => {
            // Undecryptable / unprocessable: drop WITHOUT aborting, but
            // count toward the fork signal (REQ-006).
            fork.record_failure();
            return Ok(Inbound::Dropped {
                reason: format!("process: {e:?}"),
                probable_fork: fork.probable_fork(),
            });
        }
    };

    // REQ-017(e): only member senders. External joins / external proposals
    // (NewMemberCommit, NewMemberProposal, External) are fail-closed.
    let sender_index = match processed.sender() {
        Sender::Member(idx) => *idx,
        other => {
            return Err(MlsError::Rejected(format!(
                "non-member sender {other:?} rejected (REQ-017e: external joins are fail-closed)"
            )));
        }
    };

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let members = member_bindings(group)?;
            let (sender_handle, sender_key) = group
                .members()
                .find(|m| m.index == sender_index)
                .map(|m| (credential_handle(&m.credential), m.signature_key))
                .map(|(h, k)| h.map(|h| (h, k)))
                .transpose()?
                .ok_or_else(|| {
                    MlsError::Rejected("application message from unknown leaf".into())
                })?;
            // The sender leaf must match its handle's pin — the leaf was
            // validated on entry, but the pin may have moved (flagged).
            match pins.pinned(&sender_handle) {
                Some(pin) if pin.key == sender_key.as_slice() => {}
                Some(_) => {
                    return Err(MlsError::Rejected(format!(
                        "sender {sender_handle} leaf key no longer matches its pin"
                    )));
                }
                None => {
                    return Err(MlsError::Rejected(format!(
                        "sender {sender_handle} has no pin (validated members are always pinned)"
                    )));
                }
            }
            debug_assert!(!members.is_empty());
            fork.record_success();
            Ok(Inbound::App {
                plaintext: app.into_bytes(),
                sender_handle,
            })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            validate_staged_commit(
                group,
                &staged,
                sender_index.u32(),
                room,
                pins,
                genesis,
                evidence,
            )?;
            // Collect TOFU pins for validated Adds before merging.
            let tofu: Vec<(String, [u8; 32])> = staged
                .add_proposals()
                .filter_map(|add| {
                    let leaf = add.add_proposal().key_package().leaf_node();
                    let handle = credential_handle(leaf.credential()).ok()?;
                    if pins.pinned(&handle).is_none() {
                        let key = <[u8; 32]>::try_from(leaf.signature_key().as_slice()).ok()?;
                        Some((handle, key))
                    } else {
                        None
                    }
                })
                .collect();
            group
                .merge_staged_commit(provider, *staged)
                .map_err(MlsError::stack("merge staged commit"))?;
            for (handle, key) in tofu {
                pins.observe_verified(&handle, &key)?;
            }
            provider.persist()?;
            Ok(Inbound::Handshake)
        }
        ProcessedMessageContent::ProposalMessage(proposal) => {
            // Standalone proposals get the same per-object validation BEFORE
            // being stored (REQ-017: unvalidated proposals are not stored).
            validate_standalone_proposal(group, &proposal, room, pins, genesis, evidence)?;
            group
                .store_pending_proposal(
                    openmls_traits::OpenMlsProvider::storage(provider),
                    *proposal,
                )
                .map_err(MlsError::stack("store proposal"))?;
            provider.persist()?;
            Ok(Inbound::Handshake)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => Err(MlsError::Rejected(
            "external join proposal rejected (REQ-017e fail-closed allowlist)".into(),
        )),
    }
}

/// REQ-017 (a)–(e) over a staged commit, pre-merge.
fn validate_staged_commit(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer_index: u32,
    room: &str,
    pins: &PinStore,
    genesis: &GenesisAssertion,
    evidence: Option<&RemovalEvidence>,
) -> Result<(), MlsError> {
    use openmls::prelude::Proposal;

    // (e) Fail-closed allowlist: ONLY Add, Update, Remove.
    for queued in staged.queued_proposals() {
        match queued.proposal() {
            Proposal::Add(_) | Proposal::Update(_) | Proposal::Remove(_) => {}
            other => {
                return Err(MlsError::Rejected(format!(
                    "proposal {other:?} rejected (REQ-017e allowlist: only Add/Update/Remove; \
                     the genesis extension is immutable)"
                )));
            }
        }
    }

    let members = member_bindings(group)?;
    let committer = group
        .members()
        .find(|m| m.index.u32() == committer_index)
        .ok_or_else(|| MlsError::Rejected("commit from unknown leaf".into()))?;
    let committer_handle = credential_handle(&committer.credential)?;

    // Authorised committer (REQ-016): membership-changing commits come from
    // the elected owner; a self-update-only commit (key rotation / ratchet
    // hygiene) is allowed from any member because it changes no membership.
    let changes_membership = staged.add_proposals().next().is_some()
        || staged.remove_proposals().next().is_some()
        || staged
            .update_proposals()
            .any(|u| u.sender() != &Sender::Member(committer.index));
    if changes_membership {
        match elect_committer(&members, group_genesis_creator(group).as_ref()) {
            Some((owner_handle, owner_key))
                if owner_handle == committer_handle && owner_key == committer.signature_key => {}
            Some((owner_handle, _)) => {
                return Err(MlsError::Rejected(format!(
                    "membership-changing commit from {committer_handle}, but the elected \
                     owner is {owner_handle} (REQ-016)"
                )));
            }
            None => return Err(MlsError::Rejected("group has no members".into())),
        }
    }

    // (a)+(b) Adds: every added leaf must carry the genesis capability and
    // satisfy the pin predicate (pinned handle → exact key; unpinned →
    // first-contact TOFU, pinned after merge).
    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        validate_leaf_against_pins(leaf, pins, "Add")?;
    }

    // (c) Updates: credential identity is immutable per member; a rebind is
    // rejected unless a verified REQ-011 rotation already re-pinned exactly
    // that handle→new-key binding.
    for update in staged.update_proposals() {
        let updater_index = match update.sender() {
            Sender::Member(idx) => *idx,
            other => {
                return Err(MlsError::Rejected(format!(
                    "update proposal from non-member {other:?}"
                )));
            }
        };
        validate_updated_leaf(
            group,
            update.update_proposal().leaf_node(),
            updater_index.u32(),
            pins,
        )?;
    }

    // (c) The committer's UpdatePath leaf — the path the §10 spike proved
    // openmls does NOT police for credential continuity.
    if let Some(path_leaf) = staged.update_path_leaf_node() {
        validate_updated_leaf(group, path_leaf, committer_index, pins)?;
    }

    // (d) Removes: merge-time evidence verification by EVERY validator
    // (R4-02/R5-01): signed by the subject or an authorized remover's
    // pinned key, bound to this room/group/target/leaf and the validator's
    // current pre-merge epoch, exactly.
    for remove in staged.remove_proposals() {
        let removed_index = remove.remove_proposal().removed();
        let target = group
            .members()
            .find(|m| m.index == removed_index)
            .ok_or_else(|| {
                MlsError::Rejected(format!(
                    "remove targets unknown leaf {}",
                    removed_index.u32()
                ))
            })?;
        let target_handle = credential_handle(&target.credential)?;
        let target_key = <[u8; 32]>::try_from(target.signature_key.as_slice())
            .map_err(|_| MlsError::Rejected("target leaf key is not 32 bytes".into()))?;

        let ev = evidence.ok_or_else(|| {
            MlsError::Rejected(format!(
                "remove of {target_handle} carries no removal evidence (REQ-014: unsigned \
                 hub presence never causes a Remove)"
            ))
        })?;

        // Authority (REQ-014 (a)/(b)): the subject itself, or the room
        // creator (the genesis principal; documented unilateral authority).
        if ev.signer_handle != target_handle && ev.signer_handle != genesis.creator_handle {
            return Err(MlsError::Rejected(format!(
                "removal evidence signed by {}, who is neither the subject nor the room \
                 creator (REQ-014 authority)",
                ev.signer_handle
            )));
        }
        let signer_pin = pins.pinned(&ev.signer_handle).ok_or_else(|| {
            MlsError::Rejected(format!(
                "removal evidence signer {} has no pinned key",
                ev.signer_handle
            ))
        })?;
        ev.verify(
            &signer_pin.key,
            room,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            &target_handle,
            removed_index.u32(),
            &target_key,
        )?;
    }

    Ok(())
}

/// Validation for a standalone (non-commit) proposal before it is stored.
fn validate_standalone_proposal(
    group: &MlsGroup,
    proposal: &openmls::prelude::QueuedProposal,
    room: &str,
    pins: &PinStore,
    genesis: &GenesisAssertion,
    evidence: Option<&RemovalEvidence>,
) -> Result<(), MlsError> {
    use openmls::prelude::Proposal;
    match proposal.proposal() {
        Proposal::Add(add) => {
            validate_leaf_against_pins(add.key_package().leaf_node(), pins, "Add")
        }
        Proposal::Update(update) => {
            let updater_index = match proposal.sender() {
                Sender::Member(idx) => idx.u32(),
                other => {
                    return Err(MlsError::Rejected(format!(
                        "update proposal from non-member {other:?}"
                    )));
                }
            };
            validate_updated_leaf(group, update.leaf_node(), updater_index, pins)
        }
        Proposal::Remove(remove) => {
            let removed_index = remove.removed();
            let target = group
                .members()
                .find(|m| m.index == removed_index)
                .ok_or_else(|| MlsError::Rejected("remove targets unknown leaf".into()))?;
            let target_handle = credential_handle(&target.credential)?;
            let target_key = <[u8; 32]>::try_from(target.signature_key.as_slice())
                .map_err(|_| MlsError::Rejected("target leaf key is not 32 bytes".into()))?;
            let ev = evidence.ok_or_else(|| {
                MlsError::Rejected("remove proposal carries no removal evidence (REQ-014)".into())
            })?;
            if ev.signer_handle != target_handle && ev.signer_handle != genesis.creator_handle {
                return Err(MlsError::Rejected(
                    "removal evidence signer is not the subject or creator".into(),
                ));
            }
            let signer_pin = pins.pinned(&ev.signer_handle).ok_or_else(|| {
                MlsError::Rejected("removal evidence signer has no pinned key".into())
            })?;
            ev.verify(
                &signer_pin.key,
                room,
                group.group_id().as_slice(),
                group.epoch().as_u64(),
                &target_handle,
                removed_index.u32(),
                &target_key,
            )
        }
        other => Err(MlsError::Rejected(format!(
            "proposal {other:?} rejected (REQ-017e allowlist)"
        ))),
    }
}

/// A new/added leaf: must advertise the genesis capability and satisfy the
/// pin predicate for its handle.
fn validate_leaf_against_pins(
    leaf: &LeafNode,
    pins: &PinStore,
    object: &str,
) -> Result<(), MlsError> {
    use openmls::prelude::ExtensionType;
    let handle = credential_handle(leaf.credential())?;
    let advertises_genesis = leaf
        .capabilities()
        .extensions()
        .contains(&ExtensionType::Unknown(GENESIS_EXT_TYPE));
    if !advertises_genesis {
        return Err(MlsError::Rejected(format!(
            "{object} leaf for {handle} does not advertise the genesis extension capability \
             (REQ-016/REQ-017)"
        )));
    }
    if let Some(pin) = pins.pinned(&handle) {
        if leaf.signature_key().as_slice() != pin.key {
            return Err(MlsError::Rejected(format!(
                "{object} leaf for {handle} does not match the pinned wire key (REQ-017b)"
            )));
        }
    }
    Ok(())
}

/// REQ-017 (c): an updated leaf (Update proposal or UpdatePath) must keep
/// the member's credential identity, and may change the key ONLY to a key a
/// verified rotation has already re-pinned for that handle.
fn validate_updated_leaf(
    group: &MlsGroup,
    new_leaf: &LeafNode,
    updated_index: u32,
    pins: &PinStore,
) -> Result<(), MlsError> {
    let current = group
        .members()
        .find(|m| m.index.u32() == updated_index)
        .ok_or_else(|| MlsError::Rejected("update for unknown leaf".into()))?;
    let current_handle = credential_handle(&current.credential)?;
    let new_handle = credential_handle(new_leaf.credential())?;
    if new_handle != current_handle {
        return Err(MlsError::Rejected(format!(
            "Update rebinds leaf {updated_index} from {current_handle} to {new_handle} — \
             credential identity is immutable per member (REQ-017c; closes the R3-07 \
             `:from`-forgery path)"
        )));
    }
    let new_key = new_leaf.signature_key().as_slice();
    if new_key != current.signature_key.as_slice() {
        // Key change: only a verified REQ-011 rotation (already re-pinned)
        // authorises exactly this handle→new-key rebind.
        match pins.pinned(&new_handle) {
            Some(pin) if pin.key == new_key && pin.pin_epoch > 0 => {}
            _ => {
                return Err(MlsError::Rejected(format!(
                    "Update changes {new_handle}'s leaf key without a verified rotation \
                     assertion (REQ-017c / REQ-011)"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ChatIdentity;
    use openmls::prelude::{BasicCredential, CredentialWithKey, LeafNodeParameters};
    use std::fs;
    use std::path::PathBuf;

    use super::super::group::{GenesisTrust, add_member, create_group, join_from_welcome};
    use super::super::keypackages::{ConsumedLedger, build_one_time};
    use super::super::removal::RemovalEvidence;

    struct Party {
        dir: PathBuf,
        provider: DurableProvider,
        identity: MlsIdentity,
        pins: PinStore,
        ledger: ConsumedLedger,
        wire: ChatIdentity,
    }

    fn party(tag: &str, seed: u8, handle: &str) -> Party {
        let dir = std::env::temp_dir().join(format!(
            "hark-mls-val-{tag}-{handle}-{}",
            std::process::id()
        ));
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

    /// Build the standard two-member fixture: alice creates @research and
    /// adds bob; both fully pinned; bob joined.
    fn two_member_group(
        tag: &str,
    ) -> (
        Party,
        Party,
        openmls::prelude::MlsGroup,
        openmls::prelude::MlsGroup,
        GenesisAssertion,
    ) {
        let mut alice = party(tag, 51, "@alice");
        let mut bob = party(tag, 52, "@bob");
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
        let joined = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        )
        .unwrap();
        assert_eq!(joined.trust, GenesisTrust::Authoritative);
        (alice, bob, alice_group, joined.group, genesis)
    }

    /// TEST-005/TEST-006/TEST-018 (positive): encrypt → decrypt round trip
    /// with the authenticated sender handle, and the REQ-018 enforcement.
    #[test]
    fn encrypt_decrypt_roundtrip_with_authenticated_sender() {
        let (alice, bob, mut alice_group, mut bob_group, genesis) = two_member_group("rt");
        let mut bob_pins_mut = bob.pins;
        let mut fork = ForkSignal::default();

        let wire = encrypt_message(
            &alice.provider,
            &alice.identity,
            &mut alice_group,
            b"(say @research :from @alice :text \"hi\")",
        )
        .unwrap();
        let inbound = process_inbound(
            &bob.provider,
            &mut bob_group,
            &wire,
            "@research",
            &mut bob_pins_mut,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap();
        match inbound {
            Inbound::App {
                plaintext,
                sender_handle,
            } => {
                assert_eq!(plaintext, b"(say @research :from @alice :text \"hi\")");
                assert_eq!(sender_handle, "@alice");
                // REQ-018: matching :from passes; forged :from rejects.
                enforce_sender("@alice", &sender_handle).unwrap();
                assert!(enforce_sender("@bob", &sender_handle).is_err());
            }
            other => panic!("expected App, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// TEST-017 / R3-07 oracle: a self-Update rebinding the leaf credential
    /// from @bob to @alice — which openmls ACCEPTS — is rejected by the
    /// validator (clause (c) is load-bearing).
    #[test]
    fn credential_rebinding_self_update_rejected() {
        let (alice, bob, mut alice_group, mut bob_group, genesis) = two_member_group("r307");
        let mut alice_pins = alice.pins;
        let mut fork = ForkSignal::default();

        // Bob (mallory-style) forges a leaf claiming to be @alice with his
        // own signature key.
        let forged = CredentialWithKey {
            credential: BasicCredential::new(b"@alice".to_vec()).into(),
            signature_key: bob.identity.signer.public().into(),
        };
        let params = LeafNodeParameters::builder()
            .with_credential_with_key(forged)
            .build();
        let bundle = bob_group
            .self_update(&bob.provider, &bob.identity.signer, params)
            .expect("openmls accepts the rebind (the spike-proven trap)");
        bob_group.merge_pending_commit(&bob.provider).unwrap();
        let commit_wire = bundle.commit().tls_serialize_detached().unwrap();

        // Alice's validator rejects the commit at merge.
        let err = process_inbound(
            &alice.provider,
            &mut alice_group,
            &commit_wire,
            "@research",
            &mut alice_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("immutable"),
            "must reject as a credential rebind, got: {err}"
        );
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// A benign self-update (same credential, same key) from a non-owner
    /// member merges fine — rotation hygiene must not be owner-gated.
    #[test]
    fn benign_self_update_merges() {
        let (alice, bob, mut alice_group, mut bob_group, genesis) = two_member_group("benign");
        let mut alice_pins = alice.pins;
        let mut fork = ForkSignal::default();

        let bundle = bob_group
            .self_update(
                &bob.provider,
                &bob.identity.signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        bob_group.merge_pending_commit(&bob.provider).unwrap();
        let commit_wire = bundle.commit().tls_serialize_detached().unwrap();

        let inbound = process_inbound(
            &alice.provider,
            &mut alice_group,
            &commit_wire,
            "@research",
            &mut alice_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap();
        assert!(matches!(inbound, Inbound::Handshake));
        assert_eq!(alice_group.epoch(), bob_group.epoch());
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// Fixture: alice (owner) builds a Remove commit for bob, returning the
    /// wire bytes and matching subject-signed (bye) evidence. One fixture per
    /// scenario: a rejected encrypted commit consumes its ratchet secret, so
    /// each validation outcome needs a fresh wire.
    fn remove_fixture(
        tag: &str,
    ) -> (
        Party,
        Party,
        openmls::prelude::MlsGroup,
        GenesisAssertion,
        Vec<u8>,
        RemovalEvidence,
    ) {
        let (alice, bob, mut alice_group, bob_group, genesis) = two_member_group(tag);
        let bob_member = alice_group
            .members()
            .find(|m| credential_handle(&m.credential).unwrap() == "@bob")
            .unwrap();
        let bob_key = <[u8; 32]>::try_from(bob_member.signature_key.as_slice()).unwrap();
        let epoch = alice_group.epoch().as_u64();
        let evidence = RemovalEvidence::mint(
            &bob.wire,
            "@bob",
            "@research",
            alice_group.group_id().as_slice(),
            epoch,
            "@bob",
            bob_member.index.u32(),
            &bob_key,
        );
        let (commit, _welcome, _gi) = alice_group
            .remove_members(&alice.provider, &alice.identity.signer, &[bob_member.index])
            .unwrap();
        alice_group.merge_pending_commit(&alice.provider).unwrap();
        let commit_wire = commit.tls_serialize_detached().unwrap();
        (alice, bob, bob_group, genesis, commit_wire, evidence)
    }

    /// TEST-014/TEST-017(d): a Remove without evidence is rejected by the
    /// validator — unsigned hub presence can never cause a Remove.
    #[test]
    fn remove_without_evidence_rejected() {
        let (alice, bob, mut bob_group, genesis, commit_wire, _evidence) =
            remove_fixture("rm-none");
        let mut bob_pins = bob.pins;
        let mut fork = ForkSignal::default();
        let err = process_inbound(
            &bob.provider,
            &mut bob_group,
            &commit_wire,
            "@research",
            &mut bob_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("evidence"), "{err}");
        assert_eq!(bob_group.members().count(), 2, "nothing merged");
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// R5-01/K-1 freshness at the validator: evidence whose epoch is not the
    /// validator's exact current pre-merge epoch is rejected.
    #[test]
    fn remove_with_stale_evidence_rejected() {
        let (alice, bob, mut bob_group, genesis, commit_wire, evidence) =
            remove_fixture("rm-stale");
        let mut bob_pins = bob.pins;
        let mut fork = ForkSignal::default();
        let stale = RemovalEvidence {
            epoch: evidence.epoch + 1,
            ..evidence
        };
        let err = process_inbound(
            &bob.provider,
            &mut bob_group,
            &commit_wire,
            "@research",
            &mut bob_pins,
            &genesis,
            Some(&stale),
            &mut fork,
        )
        .unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)), "{err}");
        assert_eq!(bob_group.members().count(), 2, "nothing merged");
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// TEST-014 positive: fresh, exactly-bound subject (bye) evidence lets
    /// every validator merge the Remove.
    #[test]
    fn remove_with_fresh_evidence_merges() {
        let (alice, bob, mut bob_group, genesis, commit_wire, evidence) = remove_fixture("rm-ok");
        let mut bob_pins = bob.pins;
        let mut fork = ForkSignal::default();
        let inbound = process_inbound(
            &bob.provider,
            &mut bob_group,
            &commit_wire,
            "@research",
            &mut bob_pins,
            &genesis,
            Some(&evidence),
            &mut fork,
        )
        .unwrap();
        assert!(matches!(inbound, Inbound::Handshake));
        assert_eq!(bob_group.members().count(), 1, "bob sees himself removed");
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// TEST-017(e): a GroupContextExtensions commit — which would mutate the
    /// immutable genesis — is rejected by the allowlist.
    #[test]
    fn group_context_extensions_commit_rejected() {
        let (alice, bob, mut alice_group, mut bob_group, genesis) = two_member_group("gce");
        let mut bob_pins = bob.pins;
        let mut fork = ForkSignal::default();

        use openmls::prelude::{
            Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension, UnknownExtension,
        };
        // Both members advertise 0xF013, so openmls accepts this GCE shape —
        // the app-level allowlist is what must stop it.
        let evil = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(GENESIS_EXT_TYPE)],
                &[],
                &[],
            )),
            Extension::Unknown(GENESIS_EXT_TYPE, UnknownExtension(b"evil-genesis".to_vec())),
        ])
        .unwrap();
        let (commit, _welcome, _gi) = alice_group
            .update_group_context_extensions(&alice.provider, evil, &alice.identity.signer)
            .unwrap();
        alice_group.merge_pending_commit(&alice.provider).unwrap();
        let commit_wire = commit.tls_serialize_detached().unwrap();

        let err = process_inbound(
            &bob.provider,
            &mut bob_group,
            &commit_wire,
            "@research",
            &mut bob_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("allowlist"),
            "GCE must hit the allowlist, got: {err}"
        );
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// TEST-006 (REQ-006): undecryptable frames are dropped-but-counted; a
    /// run of three surfaces the probable-fork signal; a successful decrypt
    /// resets the run.
    #[test]
    fn decrypt_failures_count_toward_fork_signal() {
        let (alice, bob, mut alice_group, mut bob_group, genesis) = two_member_group("fork");
        let mut bob_pins = bob.pins;
        let mut fork = ForkSignal::default();

        let wire =
            encrypt_message(&alice.provider, &alice.identity, &mut alice_group, b"once").unwrap();
        // First processing succeeds…
        let ok = process_inbound(
            &bob.provider,
            &mut bob_group,
            &wire,
            "@research",
            &mut bob_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap();
        assert!(matches!(ok, Inbound::App { .. }));

        // …then replays/garbage are dropped-but-counted until the signal.
        for i in 0..FORK_SIGNAL_THRESHOLD {
            let inbound = process_inbound(
                &bob.provider,
                &mut bob_group,
                &wire, // replay: undecryptable (ratchet key consumed)
                "@research",
                &mut bob_pins,
                &genesis,
                None,
                &mut fork,
            )
            .unwrap();
            match inbound {
                Inbound::Dropped { probable_fork, .. } => {
                    assert_eq!(
                        probable_fork,
                        i + 1 >= FORK_SIGNAL_THRESHOLD,
                        "signal fires exactly at the threshold"
                    );
                }
                other => panic!("expected Dropped, got {other:?}"),
            }
        }
        assert!(fork.probable_fork());

        // A successful decrypt resets the run.
        let wire2 =
            encrypt_message(&alice.provider, &alice.identity, &mut alice_group, b"again").unwrap();
        let ok = process_inbound(
            &bob.provider,
            &mut bob_group,
            &wire2,
            "@research",
            &mut bob_pins,
            &genesis,
            None,
            &mut fork,
        )
        .unwrap();
        assert!(matches!(ok, Inbound::App { .. }));
        assert!(!fork.probable_fork());
        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }
}
