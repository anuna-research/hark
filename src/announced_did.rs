//! SPEC-053 `CON-005` — an account value carried on `announce`.
//!
//! `(announce @room :agent @aria :did "did:crdt:9f3a…")`. One additive keyword,
//! recognised by the existing CBCL recogniser. The hub relays it and decides
//! nothing; a client shows attribution only when it has independently verified
//! the key→account binding, and a value it cannot recognise is treated as
//! **absent** rather than as an error.
//!
//! # Why this is its own module, and why it is only a recogniser
//!
//! "Malformed is absent" is what makes a second implementation dangerous here.
//! A stack that reads this grammar differently does not fail — it renders an
//! unmarked member where another renders an attributed one, and nobody sees a
//! divergence. So the grammar is pinned by a vector file shared with the
//! browser, and this module does recognition and nothing else: no resolver, no
//! pin store, no attribution decision. Those are `REQ-027`'s and they need
//! evidence this function does not have.
//!
//! Recognising a value is NOT attribution. `CON-005` post-condition 1 requires
//! a key verified under `REQ-027`, in an MLS-authenticated channel, under a
//! resolution no older than 86 400 s. This answers only "is this the wire form".

/// The closed grammar: `did:crdt:` followed by exactly 64 lowercase hex digits.
///
/// Matched by hand rather than with a regex crate — the grammar is fixed and
/// tiny, and a dependency here would be a second place for it to change.
///
/// Case is significant in both the scheme and the digest. RFC 3986 would fold
/// the scheme, but this is a wire token that gets keyed on and pinned, not a
/// URI anybody dereferences: one account with two spellings is two pins.
pub fn recognise_announced_did(value: &str) -> Option<&str> {
    const PREFIX: &str = "did:crdt:";
    const DIGEST_LEN: usize = 64;

    let digest = value.strip_prefix(PREFIX)?;
    if digest.len() != DIGEST_LEN {
        return None;
    }
    // `bytes()` rather than `chars()`: the length check above is in bytes, so a
    // multi-byte character would otherwise let a 64-byte value carry fewer than
    // 64 characters past it.
    if !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_form_is_returned_unchanged() {
        let did = format!("did:crdt:{}", "a".repeat(64));
        assert_eq!(recognise_announced_did(&did), Some(did.as_str()));
    }

    /// The shared vectors. This file is vendored from cbcl-bus, where the
    /// browser recogniser is the authority; both stacks answering it the same
    /// way is the whole point of `CON-005` parity.
    ///
    /// Its digest is asserted so a local edit to the copy fails here rather
    /// than silently letting the two stacks drift apart. Drift from the SOURCE
    /// is caught by re-vendoring, the same bound the wasm vendor check has —
    /// this test cannot reach across repositories.
    #[test]
    fn the_shared_vectors_are_answered_identically() {
        let raw = include_str!("../tests/fixtures/con-005-announce-did-vectors.json");
        let expected = include_str!("../tests/fixtures/con-005-announce-did-vectors.sha256").trim();

        use sha2::{Digest, Sha256};
        // Formatted here rather than pulling in a hex crate for one line.
        let actual: String = Sha256::digest(raw.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            actual, expected,
            "the vendored CON-005 vectors were edited locally; re-vendor from cbcl-bus instead"
        );

        let vectors: serde_json::Value = serde_json::from_str(raw).expect("vectors are JSON");
        assert_eq!(vectors["grammar"], "^did:crdt:[0-9a-f]{64}$");

        let accept = vectors["accept"].as_array().expect("accept cases");
        let reject = vectors["reject"].as_array().expect("reject cases");
        assert!(
            accept.len() >= 3 && reject.len() >= 12,
            "the vector file has lost cases; an empty one would pass vacuously"
        );

        for case in accept {
            let value = case["value"].as_str().expect("a string value");
            assert_eq!(
                recognise_announced_did(value),
                Some(value),
                "should accept: {}",
                case["why"].as_str().unwrap_or("")
            );
        }
        for case in reject {
            let value = case["value"].as_str().expect("a string value");
            assert_eq!(
                recognise_announced_did(value),
                None,
                "should reject: {}",
                case["why"].as_str().unwrap_or("")
            );
        }
    }

    /// A multi-byte character is 64 BYTES and fewer than 64 characters, so a
    /// length check in one unit and an alphabet check in the other disagree.
    /// Not in the shared vectors because it is a property of this
    /// implementation's types rather than of the wire grammar.
    #[test]
    fn a_multibyte_digest_is_refused() {
        let did = format!("did:crdt:{}{}", "é".repeat(32), "");
        assert_eq!(did.len() - "did:crdt:".len(), 64);
        assert_eq!(recognise_announced_did(&did), None);
    }
}
