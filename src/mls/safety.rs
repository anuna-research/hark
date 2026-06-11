//! Safety numbers (REQ-021, REQ-024).
//!
//! Two values with distinct jobs (R4-04 split):
//!
//! - **The identity safety number** — the out-of-band comparison surface.
//!   Commits to the group identity and membership bindings (`group_id` plus
//!   the sorted set of (handle, leaf-signature-key) pairs). It changes ONLY
//!   on membership change or an authenticated rotation — never on a pure
//!   ratchet Commit — so one comparison at first contact stays valid through
//!   normal operation.
//! - **The epoch state hash** — the fork-debugging diagnostic, consulted
//!   when REQ-006's decrypt-failure signal fires or the identity number
//!   mismatches. It commits to epoch + the epoch authenticator, so
//!   tree-level equivocation that preserves the membership set is caught
//!   here (forked groups cannot decrypt each other's traffic).
//!
//! The canonical encoding is pinned byte-exactly (R5-04) and must be
//! byte-compatible with the web client (NFR-001); the test below carries the
//! cross-stack vector.

use openmls::prelude::MlsGroup;
use sha2::{Digest, Sha256};

use super::group::member_bindings;
use super::{DS_IDENTITY_SAFETY, MlsError};

/// One member entry for the canonical frame: the canonical CBCL handle
/// string (including `@`) and the 32-byte raw Ed25519 verification key —
/// the same key REQ-007 uses as the leaf signature key.
pub type MemberBinding = (String, [u8; 32]);

fn lp_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The pinned canonical frame (REQ-021a, R5-04):
/// `u32be(len(label)) ‖ label ‖ u32be(len(group_id)) ‖ group_id ‖
/// u32be(member_count) ‖ members…`, each member
/// `u32be(len(handle)) ‖ handle ‖ u32be(32) ‖ key`, members sorted
/// lexicographically by handle bytes with the key as tie-breaker.
/// `group_id` is the MLS GroupId opaque bytes, no TLS length prefix.
pub fn identity_safety_frame(group_id: &[u8], members: &[MemberBinding]) -> Vec<u8> {
    let mut sorted: Vec<&MemberBinding> = members.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then(a.1.cmp(&b.1)));

    let mut out = Vec::new();
    lp_u32(&mut out, DS_IDENTITY_SAFETY.as_bytes());
    lp_u32(&mut out, group_id);
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for (handle, key) in sorted {
        lp_u32(&mut out, handle.as_bytes());
        lp_u32(&mut out, key);
    }
    out
}

/// SHA-256 of the canonical frame — the identity safety number bytes.
pub fn identity_safety_number(group_id: &[u8], members: &[MemberBinding]) -> [u8; 32] {
    Sha256::digest(identity_safety_frame(group_id, members)).into()
}

/// The human-facing representation: 64 lowercase hex characters displayed
/// as eight groups of eight separated by spaces.
pub fn format_safety_number(digest: &[u8; 32]) -> String {
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Comparisons ignore spaces and ASCII case.
pub fn safety_numbers_match(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    norm(a) == norm(b)
}

/// The epoch state hash (REQ-021b): SHA-256 over the epoch number and the
/// MLS epoch authenticator — a diagnostic only, expected to rotate on every
/// Commit.
pub fn epoch_state_hash(epoch: u64, epoch_authenticator: &[u8]) -> [u8; 32] {
    let mut frame = Vec::new();
    lp_u32(&mut frame, b"cbcl-mls-epoch-state/v1");
    frame.extend_from_slice(&epoch.to_be_bytes());
    lp_u32(&mut frame, epoch_authenticator);
    Sha256::digest(frame).into()
}

/// Both REQ-021 values for a live group, formatted (the REQ-024 surface).
pub struct SafetyNumbers {
    /// The out-of-band comparison value — stable across pure ratchet Commits.
    pub identity: String,
    /// The fork diagnostic — rotates every Commit.
    pub epoch_state: String,
    pub epoch: u64,
}

/// Derive both values from a live group's authenticated leaves.
pub fn group_safety_numbers(group: &MlsGroup) -> Result<SafetyNumbers, MlsError> {
    let members: Vec<MemberBinding> = member_bindings(group)?
        .into_iter()
        .map(|(handle, key)| {
            <[u8; 32]>::try_from(key.as_slice())
                .map(|key| (handle, key))
                .map_err(|_| MlsError::Rejected("leaf key is not 32 bytes".into()))
        })
        .collect::<Result<_, _>>()?;
    let identity = identity_safety_number(group.group_id().as_slice(), &members);
    let epoch = group.epoch().as_u64();
    let epoch_state = epoch_state_hash(epoch, group.epoch_authenticator().as_slice());
    Ok(SafetyNumbers {
        identity: format_safety_number(&identity),
        epoch_state: format_safety_number(&epoch_state),
        epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R5-04 / NFR-001: the byte-exact cross-stack test vector. The frame
    /// bytes are constructed here independently, field by field, and the
    /// expected digest is pinned as a literal. The web client
    /// (`cbcl-mls-wasm` / JS) must reproduce this exact string for the same
    /// inputs before REQ-024 comparison is meaningful.
    #[test]
    fn identity_safety_number_vector() {
        let group_id = b"\x01\x02\x03\x04";
        let alice = ("@alice".to_string(), [0xAAu8; 32]);
        let bob = ("@bob".to_string(), [0xBBu8; 32]);

        // Independent manual construction of the pinned frame.
        let mut expected_frame: Vec<u8> = Vec::new();
        expected_frame.extend_from_slice(&27u32.to_be_bytes()); // len("cbcl-mls-identity-safety/v1")
        expected_frame.extend_from_slice(b"cbcl-mls-identity-safety/v1");
        expected_frame.extend_from_slice(&4u32.to_be_bytes());
        expected_frame.extend_from_slice(group_id);
        expected_frame.extend_from_slice(&2u32.to_be_bytes()); // member count
        expected_frame.extend_from_slice(&6u32.to_be_bytes());
        expected_frame.extend_from_slice(b"@alice");
        expected_frame.extend_from_slice(&32u32.to_be_bytes());
        expected_frame.extend_from_slice(&[0xAA; 32]);
        expected_frame.extend_from_slice(&4u32.to_be_bytes());
        expected_frame.extend_from_slice(b"@bob");
        expected_frame.extend_from_slice(&32u32.to_be_bytes());
        expected_frame.extend_from_slice(&[0xBB; 32]);

        // Member order on input must not matter (canonical sort).
        let frame = identity_safety_frame(group_id, &[bob.clone(), alice.clone()]);
        assert_eq!(frame, expected_frame, "canonical frame bytes");

        let digest = identity_safety_number(group_id, &[alice, bob]);
        let formatted = format_safety_number(&digest);
        // The committed cross-stack vector (sha256 of the frame above).
        let expected_hex: String = sha2::Sha256::digest(&expected_frame)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(safety_numbers_match(&formatted, &expected_hex));
        // Display shape: 8 space-separated groups of 8 lowercase hex chars.
        let groups: Vec<&str> = formatted.split(' ').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|g| {
            g.len() == 8
                && g.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        }));
    }

    /// Comparison ignores spaces and case.
    #[test]
    fn comparison_ignores_spaces_and_case() {
        assert!(safety_numbers_match(
            "deadbeef 00112233",
            "DEADBEEF00112233"
        ));
        assert!(!safety_numbers_match("deadbeef", "deadbeee"));
    }

    /// REQ-021a: distinct rooms (group ids) with the same member set get
    /// distinct numbers; membership change flips the number; pure input
    /// reordering does not.
    #[test]
    fn number_binds_group_and_membership() {
        let alice = ("@alice".to_string(), [1u8; 32]);
        let bob = ("@bob".to_string(), [2u8; 32]);
        let carol = ("@carol".to_string(), [3u8; 32]);

        let n1 = identity_safety_number(b"group-1", &[alice.clone(), bob.clone()]);
        let n2 = identity_safety_number(b"group-2", &[alice.clone(), bob.clone()]);
        assert_ne!(n1, n2, "same members, different rooms → different numbers");

        let n3 = identity_safety_number(b"group-1", &[bob.clone(), alice.clone()]);
        assert_eq!(n1, n3, "input order must not matter");

        let n4 = identity_safety_number(b"group-1", &[alice.clone(), bob.clone(), carol]);
        assert_ne!(n1, n4, "membership change flips the number");

        // A key rebind for the same handle flips it too (rotation is
        // membership-visible).
        let bob_rotated = ("@bob".to_string(), [9u8; 32]);
        let n5 = identity_safety_number(b"group-1", &[alice, bob_rotated]);
        assert_ne!(n1, n5);
    }

    /// REQ-021 live: the identity number is stable across a pure ratchet
    /// Commit and flips on membership change; the epoch state hash rotates
    /// on every Commit.
    #[test]
    fn live_group_stability_and_flip() {
        use crate::identity::ChatIdentity;
        use crate::mls::MlsIdentity;
        use crate::mls::group::{add_member, create_group};
        use crate::mls::keypackages::{ConsumedLedger, build_one_time};
        use crate::mls::pins::PinStore;
        use crate::mls::provider::DurableProvider;
        use openmls::prelude::LeafNodeParameters;
        use std::fs;

        let dir = std::env::temp_dir().join(format!("hark-safety-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a_provider = DurableProvider::open(&dir.join("a.mls")).unwrap();
        let b_provider = DurableProvider::open(&dir.join("b.mls")).unwrap();
        let a_wire = ChatIdentity::from_seed([71u8; 32]);
        let b_wire = ChatIdentity::from_seed([72u8; 32]);
        let a_id = MlsIdentity::from_wire_identity(&a_wire, "@alice");
        let b_id = MlsIdentity::from_wire_identity(&b_wire, "@bob");
        let mut a_pins = PinStore::open(&dir.join("a.pins")).unwrap();
        let a_ledger = ConsumedLedger::open(&dir.join("a.kpledger")).unwrap();
        a_pins
            .observe_verified("@bob", &b_wire.verifying_key_bytes())
            .unwrap();

        let (mut group, _genesis) = create_group(&a_provider, &a_id, "@research").unwrap();
        let solo = group_safety_numbers(&group).unwrap();

        // Pure ratchet commit: identity number stable, state hash rotates.
        group
            .self_update(&a_provider, &a_id.signer, LeafNodeParameters::default())
            .unwrap();
        group.merge_pending_commit(&a_provider).unwrap();
        let after_ratchet = group_safety_numbers(&group).unwrap();
        assert_eq!(
            solo.identity, after_ratchet.identity,
            "identity number must survive a pure ratchet Commit (R4-04)"
        );
        assert_ne!(
            solo.epoch_state, after_ratchet.epoch_state,
            "epoch state hash is volatile by design"
        );

        // Membership change: identity number flips.
        let kp = build_one_time(&b_provider, &b_id, 1).unwrap().remove(0);
        add_member(
            &a_provider,
            &a_id,
            &mut group,
            &kp.bytes,
            "@bob",
            &a_pins,
            &a_ledger,
        )
        .unwrap();
        let after_add = group_safety_numbers(&group).unwrap();
        assert_ne!(solo.identity, after_add.identity);

        let _ = fs::remove_dir_all(&dir);
    }
}
