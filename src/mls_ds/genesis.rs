//! CON-008 — singleton genesis-anchor validation (H8). Ports the JS
//! `mls-ds-genesis-validator.mjs` VERDICT logic; crypto CONSUMED via
//! `DomainTuple::{Claim,ClaimDs,Genesis}` (ADR-031/032).

use cbcl_core::mls_ds::{b64url_encode, tuple_content_hash, DomainTuple};
use cbcl_core::sexpr::SExpr;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    FirstAccepted { grade: &'static str, anchor_hash: String },
    Existing { anchor_hash: String },
    Conflict(&'static str),
}

/// A decoded genesis candidate (post-recognition).
pub struct Candidate {
    pub room: String,
    pub grade: &'static str, // "tofu" | "verified"
    pub creator_key: String,
    pub link_room: String,
    pub link_creator_key: String,
    pub room_claim_core: SExpr,
    pub creator_sig: [u8; 64],
    pub ds_sig: [u8; 64],
    pub genesis_blob_ref: SExpr,
    pub genesis_sig: [u8; 64],
}

/// Injective domain-tagged anchor id over the core identity.
pub fn anchor_hash(core: &SExpr, blob_ref: &SExpr) -> String {
    tuple_content_hash("mls-genesis-anchor-hash-v1", &[core.clone(), blob_ref.clone()])
}

/// The CON-008 decision (transplant guard, 3-signature verification, singleton + grade rule).
pub fn validate_genesis(
    saved_anchor: Option<&str>,
    expected_room: &str,
    creator_vk: &[u8; 32],
    ds_vk: &[u8; 32],
    c: &Candidate,
) -> Verdict {
    if c.room != expected_room || c.link_room != expected_room {
        return Verdict::Conflict("room-transplant");
    }
    if c.link_creator_key != c.creator_key {
        return Verdict::Conflict("key-transplant");
    }
    let claim = DomainTuple::Claim { room_claim_core: c.room_claim_core.clone() };
    if !claim.verify(creator_vk, &c.creator_sig) {
        return Verdict::Conflict("claim-sig-invalid");
    }
    let claim_ds = DomainTuple::ClaimDs {
        room_claim_core: c.room_claim_core.clone(),
        creator_signature: b64url_encode(&c.creator_sig),
    };
    if !claim_ds.verify(ds_vk, &c.ds_sig) {
        return Verdict::Conflict("claim-ds-sig-invalid");
    }
    let genesis = DomainTuple::Genesis {
        room: c.room.clone(),
        genesis_blob_ref: c.genesis_blob_ref.clone(),
        creator_key: c.creator_key.clone(),
    };
    if !genesis.verify(creator_vk, &c.genesis_sig) {
        return Verdict::Conflict("genesis-sig-invalid");
    }
    let anchor = anchor_hash(&c.room_claim_core, &c.genesis_blob_ref);
    match saved_anchor {
        Some(saved) => {
            if anchor != saved {
                return Verdict::Conflict("saved-anchor-mismatch"); // singleton: no extension
            }
            if c.grade != "verified" {
                return Verdict::Conflict("grade-contradiction");
            }
            Verdict::Existing { anchor_hash: anchor }
        }
        None => {
            if c.grade != "tofu" {
                return Verdict::Conflict("grade-lie");
            }
            Verdict::FirstAccepted { grade: "tofu", anchor_hash: anchor }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::mls_ds::Ed25519Keypair;
    use cbcl_core::sexpr::{Atom, SExpr};

    fn sym(s: &str) -> SExpr { SExpr::Atom(Atom::Symbol(s.into())) }
    fn st(s: &str) -> SExpr { SExpr::Atom(Atom::Str(s.into())) }
    fn num(n: i64) -> SExpr { SExpr::Atom(Atom::Num(n)) }

    fn build(room: &str, grade: &'static str, creator: &Ed25519Keypair, ds: &Ed25519Keypair) -> Candidate {
        let creator_key = creator.key_id();
        let core = SExpr::List(vec![sym("room-claim-v1"), st(room), st("L"), sym(&creator_key), num(1), st("m")]);
        let creator_sig = DomainTuple::Claim { room_claim_core: core.clone() }.sign(creator);
        let ds_sig = DomainTuple::ClaimDs { room_claim_core: core.clone(), creator_signature: b64url_encode(&creator_sig) }.sign(ds);
        let blob_ref = SExpr::List(vec![sym("blob-ref-v1"), sym("genesis"), st(&format!("sha256:{}", "a".repeat(64))), num(64)]);
        let genesis_sig = DomainTuple::Genesis { room: room.into(), genesis_blob_ref: blob_ref.clone(), creator_key: creator_key.clone() }.sign(creator);
        Candidate { room: room.into(), grade, creator_key: creator_key.clone(), link_room: room.into(), link_creator_key: creator_key, room_claim_core: core, creator_sig, ds_sig, genesis_blob_ref: blob_ref, genesis_sig }
    }

    #[test]
    fn singleton_grade_and_transplant() {
        let (creator, ds) = (Ed25519Keypair::from_seed(&[3u8; 32]), Ed25519Keypair::from_seed(&[5u8; 32]));
        let (cvk, dvk) = (creator.public_bytes(), ds.public_bytes());
        let c = build("room-alpha", "tofu", &creator, &ds);
        assert!(matches!(validate_genesis(None, "room-alpha", &cvk, &dvk, &c), Verdict::FirstAccepted { .. }));
        assert_eq!(validate_genesis(Some("sha256:dead"), "room-alpha", &cvk, &dvk, &build("room-alpha", "verified", &creator, &ds)), Verdict::Conflict("saved-anchor-mismatch"));
        let v = build("room-alpha", "verified", &creator, &ds);
        assert_eq!(validate_genesis(None, "room-alpha", &cvk, &dvk, &v), Verdict::Conflict("grade-lie"));
    }
}
