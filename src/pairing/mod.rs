//! SPEC-016 REQ-007 agent pairing — the `hark pair` client side.
//!
//! The agent is the SPAKE2 *initiator*: the operator pastes a Magic-Wormhole
//! style code `<pairing-id>-<word>-<word>-<word>-<word>`, where the public
//! `pairing_id` locates the hub record and the four BIP39 words are the PAKE
//! secret (never sent on the wire). On a successful handshake the hub releases
//! the record bound to K (`AEAD(K, record)` + `mac_b`); the agent verifies the
//! hub via `mac_b`, decrypts the record, derives its encryption pin from the
//! invite-cap *presence* (R4-01), and joins under the adder-set name.
//!
//! The crypto is byte-for-byte compatible with the hub responder, pinned by
//! the shared known-answer vectors (`tests/pairing_vectors.rs`).

pub mod bip39;
pub mod client;
pub mod record;
pub mod spake2;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

/// The AEAD additional-data + nonce the hub binds the record under
/// (`cbcl-chat-pairing:record-aad` / `record-nonce`). The nonce is fixed
/// because K is fresh per handshake and the record is sealed exactly once.
const RECORD_AAD: &[u8] = b"cbcl-chat-pair-record-v1";
const RECORD_NONCE: [u8; 12] = [0u8; 12];

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("pairing code must be `<pairing-id>-word-word-word-word`")]
    MalformedCode,
    #[error(transparent)]
    Phrase(#[from] bip39::PhraseError),
    #[error(transparent)]
    Spake2(#[from] spake2::Spake2Error),
    #[error("the released record did not decrypt under the pairing key")]
    RecordUndecryptable,
    #[error(transparent)]
    Record(#[from] record::RecordError),
}

/// A parsed pairing code: the public locator + the secret phrase words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCode {
    pub pairing_id: String,
    pub words: Vec<String>,
}

/// Parse `<pairing-id>-rocket-anchor-velvet-quantum`. The leading token is the
/// public record locator; the trailing four are the BIP39 secret. Hyphens or
/// whitespace separate tokens, so a pasted `42 rocket anchor velvet quantum`
/// works too.
pub fn parse_code(code: &str) -> Result<PairingCode, PairError> {
    let tokens: Vec<String> = code
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect();
    if tokens.len() != 5 {
        return Err(PairError::MalformedCode);
    }
    Ok(PairingCode {
        pairing_id: tokens[0].clone(),
        words: tokens[1..5].to_vec(),
    })
}

/// Decrypt the hub-released record ciphertext under the agreed key K.
pub fn open_record(
    session_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<record::PairingRecord, PairError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(session_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&RECORD_NONCE),
            Payload {
                msg: ciphertext,
                aad: RECORD_AAD,
            },
        )
        .map_err(|_| PairError::RecordUndecryptable)?;
    Ok(record::PairingRecord::decode(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wormhole_style_code() {
        let c = parse_code("00112233-account-clinic-text-wheel").unwrap();
        assert_eq!(c.pairing_id, "00112233");
        assert_eq!(c.words, ["account", "clinic", "text", "wheel"]);

        // whitespace-separated paste also works
        let c = parse_code("42 account clinic text wheel").unwrap();
        assert_eq!(c.pairing_id, "42");
        assert_eq!(c.words.len(), 4);

        assert!(matches!(
            parse_code("too-few-words"),
            Err(PairError::MalformedCode)
        ));
    }
}
