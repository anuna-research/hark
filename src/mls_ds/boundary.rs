//! CON-006 — MLS semantic boundary (H7). v1 owner-removal rejection (REQ-098) and
//! ADD-AUTH ↔ membership-delta consistency; crypto via `DomainTuple::AddAuth`.

use cbcl_core::mls_ds::DomainTuple;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject(&'static str),
}

/// A creator admission proof mirroring the `DomainTuple::AddAuth` fields + its signature.
pub struct AddAuth {
    pub room: String,
    pub source_author_key: String,
    pub base_seq: i64,
    pub base_hash: String,
    pub ciphertext_digest: String,
    pub targets: Vec<String>,
    pub welcome_digest: String,
    pub genesis_anchor_hash: String,
    pub sig: [u8; 64],
}

/// A modelled MLS commit's membership delta.
pub struct Commit {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub add_auth: Option<AddAuth>,
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// The H7 v1 commit validation decision.
pub fn validate_v1_commit(owner: &str, creator_vk: &[u8; 32], c: &Commit) -> Verdict {
    if c.removed.iter().any(|k| k == owner) {
        return Verdict::Reject("owner-removal-rejected");
    }
    let is_add = !c.added.is_empty();
    match (&c.add_auth, is_add) {
        (Some(auth), true) => {
            let tuple = DomainTuple::AddAuth {
                room: auth.room.clone(),
                source_author_key: auth.source_author_key.clone(),
                base_seq: auth.base_seq,
                base_hash: auth.base_hash.clone(),
                ciphertext_digest: auth.ciphertext_digest.clone(),
                targets: auth.targets.clone(),
                welcome_digest: auth.welcome_digest.clone(),
                genesis_anchor_hash: auth.genesis_anchor_hash.clone(),
            };
            if !tuple.verify(creator_vk, &auth.sig) {
                return Verdict::Reject("add-auth-sig-invalid");
            }
            if sorted(&c.added) != sorted(&auth.targets) {
                return Verdict::Reject("add-auth-membership-mismatch");
            }
            Verdict::Accept
        }
        (None, true) => Verdict::Reject("add-missing-authorization"),
        (Some(_), false) => Verdict::Reject("non-add-carries-add-auth"),
        (None, false) => Verdict::Accept,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::mls_ds::Ed25519Keypair;

    fn d(nib: &str) -> String { format!("sha256:{}", nib.repeat(64)) }
    fn auth_for(targets: &[&str], creator: &Ed25519Keypair) -> AddAuth {
        let targets: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
        let t = DomainTuple::AddAuth { room: "r".into(), source_author_key: creator.key_id(), base_seq: 4, base_hash: d("a"), ciphertext_digest: d("b"), targets: targets.clone(), welcome_digest: d("c"), genesis_anchor_hash: d("d") };
        let sig = t.sign(creator);
        AddAuth { room: "r".into(), source_author_key: creator.key_id(), base_seq: 4, base_hash: d("a"), ciphertext_digest: d("b"), targets, welcome_digest: d("c"), genesis_anchor_hash: d("d"), sig }
    }

    const OWNER: &str = "@owner";

    #[test]
    fn owner_removal_and_add_consistency() {
        let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
        let vk = creator.public_bytes();
        assert_eq!(validate_v1_commit(OWNER, &vk, &Commit { added: vec![], removed: vec![OWNER.into()], add_auth: None }), Verdict::Reject("owner-removal-rejected"));
        assert_eq!(validate_v1_commit(OWNER, &vk, &Commit { added: vec!["@a".into(), "@b".into()], removed: vec![], add_auth: Some(auth_for(&["@a", "@b"], &creator)) }), Verdict::Accept);
        assert_eq!(validate_v1_commit(OWNER, &vk, &Commit { added: vec!["@a".into(), "@evil".into()], removed: vec![], add_auth: Some(auth_for(&["@a"], &creator)) }), Verdict::Reject("add-auth-membership-mismatch"));
    }
}
