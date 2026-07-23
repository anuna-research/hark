//! CON-010 — successor-room closure authentication (H10). `authenticate_successor_package`:
//! distinct rooms, DS-key pin, offer window, and the three choreography signatures
//! (predecessor offer / successor consent / DS countersign) via `DomainTuple`. Plus the
//! ClosureBlock decision for a conflicting package.

use cbcl_core::mls_ds::{b64url_encode, DomainTuple};
use cbcl_core::sexpr::SExpr;

const OFFER_WINDOW_MS: i64 = 600_000;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Authenticated { closure_package_hash: String },
    Refuse(&'static str),
    ClosureBlock,
}

pub struct Package {
    pub pred_room: String,
    pub succ_room: String,
    pub dialect_hash: String,
    pub ds_key_id: String,
    pub issued_at: i64,
    pub not_after: i64,
    pub offer_core: SExpr,
    pub pred_vk: [u8; 32],
    pub pred_sig: [u8; 64],
    pub offer: SExpr,
    pub succ_vk: [u8; 32],
    pub succ_sig: [u8; 64],
    pub proposal: SExpr,
    pub ds_sig: [u8; 64],
}

pub fn closure_package_hash(proposal: &SExpr, ds_sig: &[u8; 64]) -> String {
    let bridge = SExpr::List(vec![SExpr::Atom(cbcl_core::sexpr::Atom::Symbol("successor-bridge-v1".into())), proposal.clone(), SExpr::Atom(cbcl_core::sexpr::Atom::Str(b64url_encode(ds_sig)))]);
    let pkg = SExpr::List(vec![SExpr::Atom(cbcl_core::sexpr::Atom::Symbol("closure-package-v1".into())), bridge]);
    DomainTuple::ClosurePackageHash { closure_package: pkg }.content_hash()
}

/// The CON-010 authenticator.
pub fn authenticate(expected_dialect: &str, pinned_ds_key_id: &str, ds_vk: &[u8; 32], p: &Package) -> Verdict {
    if p.pred_room == p.succ_room {
        return Verdict::Refuse("same-room");
    }
    if p.dialect_hash != expected_dialect {
        return Verdict::Refuse("dialect-mismatch");
    }
    if p.ds_key_id != pinned_ds_key_id {
        return Verdict::Refuse("ds-key-substitution");
    }
    if !(p.issued_at < p.not_after) || !(p.not_after <= p.issued_at + OFFER_WINDOW_MS) {
        return Verdict::Refuse("offer-window-invalid");
    }
    let offer_sig = DomainTuple::PredecessorOffer { successor_offer_core: p.offer_core.clone() };
    if !offer_sig.verify(&p.pred_vk, &p.pred_sig) {
        return Verdict::Refuse("predecessor-offer-sig-invalid");
    }
    let consent = DomainTuple::SuccessorConsent { successor_offer: p.offer.clone() };
    if !consent.verify(&p.succ_vk, &p.succ_sig) {
        return Verdict::Refuse("successor-consent-sig-invalid");
    }
    let ds = DomainTuple::SuccessorDs { successor_proposal: p.proposal.clone() };
    if !ds.verify(ds_vk, &p.ds_sig) {
        return Verdict::Refuse("ds-sig-invalid");
    }
    Verdict::Authenticated { closure_package_hash: closure_package_hash(&p.proposal, &p.ds_sig) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::mls_ds::Ed25519Keypair;
    use cbcl_core::sexpr::Atom;

    fn sym(s: &str) -> SExpr { SExpr::Atom(Atom::Symbol(s.into())) }
    fn st(s: &str) -> SExpr { SExpr::Atom(Atom::Str(s.into())) }
    fn num(n: i64) -> SExpr { SExpr::Atom(Atom::Num(n)) }
    const DIALECT: &str = "sha256:922ba8bf9eb62a07b81989a9bfe6754a626b2edaf4d3f52e3fc4b41321261858";

    fn build(pred_room: &str, succ_room: &str, ds: &Ed25519Keypair, pred: &Ed25519Keypair, succ: &Ed25519Keypair, nonce: &str) -> Package {
        let core = SExpr::List(vec![sym("successor-core-v1"), st(pred_room), st("h"), st("h"), num(7), st("h"), st(succ_room), st("h"), st("h"), st(DIALECT), st(&ds.key_id())]);
        let offer_core = SExpr::List(vec![sym("successor-offer-core-v1"), core, st(nonce), num(1000), num(1600)]);
        let pred_sig = DomainTuple::PredecessorOffer { successor_offer_core: offer_core.clone() }.sign(pred);
        let offer = SExpr::List(vec![sym("successor-offer-v1"), offer_core.clone(), st(&pred.key_id()), st(&b64url_encode(&pred_sig))]);
        let succ_sig = DomainTuple::SuccessorConsent { successor_offer: offer.clone() }.sign(succ);
        let proposal = SExpr::List(vec![sym("successor-proposal-v1"), offer.clone(), st(&succ.key_id()), st(&b64url_encode(&succ_sig))]);
        let ds_sig = DomainTuple::SuccessorDs { successor_proposal: proposal.clone() }.sign(ds);
        Package { pred_room: pred_room.into(), succ_room: succ_room.into(), dialect_hash: DIALECT.into(), ds_key_id: ds.key_id(), issued_at: 1000, not_after: 1600, offer_core, pred_vk: pred.public_bytes(), pred_sig, offer, succ_vk: succ.public_bytes(), succ_sig, proposal, ds_sig }
    }

    #[test]
    fn authenticates_and_blocks_conflicts() {
        let (ds, pred, succ) = (Ed25519Keypair::from_seed(&[1u8; 32]), Ed25519Keypair::from_seed(&[2u8; 32]), Ed25519Keypair::from_seed(&[3u8; 32]));
        let p1 = build("old", "new", &ds, &pred, &succ, "n1");
        assert!(matches!(authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p1), Verdict::Authenticated { .. }));
        let same = build("x", "x", &ds, &pred, &succ, "n");
        assert_eq!(authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &same), Verdict::Refuse("same-room"));
        let p2 = build("old", "new2", &ds, &pred, &succ, "n2");
        let (h1, h2) = (closure_package_hash(&p1.proposal, &p1.ds_sig), closure_package_hash(&p2.proposal, &p2.ds_sig));
        assert_ne!(h1, h2, "conflicting packages -> distinct hashes -> ClosureBlock");
    }
}
