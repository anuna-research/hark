//! Decentralised answerer selection (SPEC-003 CON-004, IMPL-003 §3).
//!
//! The pure core of "which one of the capable agents answers this ask". Given
//! an ask id and the set of contenders that claimed for it, produce a
//! deterministic ranking: the winner is `ranking[0]`, and `ranking[k+1]` is the
//! liveness fallback for `ranking[k]` (SPEC-003 REQ-007). Every member that
//! computes over the same contender set derives the identical ranking, so the
//! election needs no coordinator.
//!
//! The V1 selector is [`RendezvousHash`] — `argmin H(ask_id ‖ handle)`, with no
//! keys and no proofs (IMPL-003: no audited RFC-9381 VRF crate exists yet). The
//! VRF selector (SPEC-003 ADR-003, Tier-1 gated) will implement the same
//! [`Selector`] trait and slot in behind it.
//!
//! This module is side-effect free: no I/O, no clock, no RNG (SPEC-003 Purity
//! Boundary). The contender set is assembled by the transport's claim round and
//! passed in; selection itself is a pure function of `(ask_id, contenders)`.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

/// A deterministic answerer-selection function over the contenders for an ask.
pub trait Selector {
    /// Rank `contenders` for `ask_id`, winner first.
    ///
    /// Deterministic and order-independent: the same `ask_id` and the same
    /// *set* of contenders always yield the same ordering, regardless of the
    /// order `contenders` is given in or any duplicates it contains.
    fn rank(&self, ask_id: &str, contenders: &[String]) -> Vec<String>;

    /// The elected answerer (the winner), or `None` if there are no contenders.
    fn winner(&self, ask_id: &str, contenders: &[String]) -> Option<String> {
        self.rank(ask_id, contenders).into_iter().next()
    }
}

/// Rendezvous (highest-random-weight) hashing over `H(ask_id ‖ handle)`.
///
/// Verifiable by public recompute, deterministic, and needs no key material.
/// It is *predictable*: because the hash is public, an adversary can pre-compute
/// which contender wins a crafted ask and target it. That is accepted for V1's
/// cooperative coop setting; the VRF selector removes the predictability when it
/// lands (SPEC-003 ADR-003).
#[derive(Debug, Clone, Copy, Default)]
pub struct RendezvousHash;

impl RendezvousHash {
    /// The draw for one contender: `SHA-256(ask_id ‖ 0x00 ‖ handle)`.
    ///
    /// The `0x00` separator makes the concatenation unambiguous, so
    /// `("a", "bc")` and `("ab", "c")` cannot produce the same preimage.
    fn draw(ask_id: &str, handle: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ask_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(handle.as_bytes());
        hasher.finalize().into()
    }
}

impl Selector for RendezvousHash {
    fn rank(&self, ask_id: &str, contenders: &[String]) -> Vec<String> {
        // Dedup by handle (a contender that claimed twice counts once), keeping
        // first occurrence, then sort by (draw, handle). A tie on the 256-bit
        // draw is astronomically unlikely but is broken deterministically by
        // the handle so the ranking is always a total order.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut scored: Vec<([u8; 32], &str)> = contenders
            .iter()
            .filter(|handle| seen.insert(handle.as_str()))
            .map(|handle| (Self::draw(ask_id, handle), handle.as_str()))
            .collect();
        scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
        scored
            .into_iter()
            .map(|(_, handle)| handle.to_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{RendezvousHash, Selector};

    fn handles(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn empty_has_no_winner() {
        let s = RendezvousHash;
        assert!(s.winner("ask-1", &[]).is_none());
        assert!(s.rank("ask-1", &[]).is_empty());
    }

    #[test]
    fn single_contender_wins() {
        let s = RendezvousHash;
        assert_eq!(
            s.winner("ask-1", &handles(&["@aria"])),
            Some("@aria".to_owned())
        );
    }

    #[test]
    fn ranking_is_order_independent() {
        let s = RendezvousHash;
        let a = s.rank("H7", &handles(&["@aria", "@kairos", "@sol"]));
        let b = s.rank("H7", &handles(&["@sol", "@aria", "@kairos"]));
        let c = s.rank("H7", &handles(&["@kairos", "@sol", "@aria"]));
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn ranking_contains_each_contender_once() {
        let s = RendezvousHash;
        let ranking = s.rank("H7", &handles(&["@aria", "@kairos", "@sol"]));
        let mut sorted = ranking.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            3,
            "every contender appears exactly once: {ranking:?}"
        );
    }

    #[test]
    fn duplicate_claims_count_once() {
        let s = RendezvousHash;
        let ranking = s.rank("H7", &handles(&["@aria", "@aria", "@kairos"]));
        assert_eq!(ranking.len(), 2);
    }

    #[test]
    fn deterministic_across_calls() {
        let s = RendezvousHash;
        let set = handles(&["@a", "@b", "@c", "@d"]);
        assert_eq!(s.rank("ask-x", &set), s.rank("ask-x", &set));
    }

    #[test]
    fn different_asks_can_pick_different_winners() {
        // Not guaranteed for any single pair, but across many asks the winner
        // should vary — confirms selection actually depends on the ask id.
        let s = RendezvousHash;
        let set = handles(&["@aria", "@kairos", "@sol", "@mat", "@hugo"]);
        let mut winners = std::collections::BTreeSet::new();
        for i in 0..50 {
            if let Some(w) = s.winner(&format!("ask-{i}"), &set) {
                winners.insert(w);
            }
        }
        assert!(
            winners.len() > 1,
            "winner never varied across 50 asks: {winners:?}"
        );
    }

    #[test]
    fn winner_is_argmin_of_the_draw() {
        // The winner must be the contender with the lexicographically smallest
        // draw — recomputed here independently, the public-verifiability path.
        let s = RendezvousHash;
        let set = handles(&["@aria", "@kairos", "@sol"]);
        let ask = "H7";
        let expected = set
            .iter()
            .min_by(|a, b| {
                RendezvousHash::draw(ask, a)
                    .cmp(&RendezvousHash::draw(ask, b))
                    .then_with(|| a.cmp(b))
            })
            .cloned();
        assert_eq!(s.winner(ask, &set), expected);
    }
}
