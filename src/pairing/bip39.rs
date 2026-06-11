//! 2-word BIP39 phrase → word-index bytes (`wib`), matching the hub's
//! `cbcl-chat-pairing-store:phrase->wib`. The two 11-bit indices are packed
//! `<<i1:11, i2:11, 0:2>>` = 3 bytes, the ikm into derive-w.

use std::collections::HashMap;
use std::sync::OnceLock;

const WORDLIST: &str = include_str!("bip39-english.txt");

fn index_of() -> &'static HashMap<&'static str, u16> {
    static MAP: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        WORDLIST
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .enumerate()
            .map(|(i, w)| (w, i as u16))
            .collect()
    })
}

#[derive(Debug, thiserror::Error)]
pub enum PhraseError {
    #[error("a pairing phrase must be exactly 2 words")]
    WrongLength,
    #[error("not a BIP39 word: {0}")]
    UnknownWord(String),
}

/// Decode a 2-word phrase to its word-index bytes. Words are matched
/// case-insensitively against the BIP39 English list.
pub fn phrase_to_wib(words: &[String]) -> Result<[u8; 3], PhraseError> {
    if words.len() != 2 {
        return Err(PhraseError::WrongLength);
    }
    let map = index_of();
    let mut idx = [0u16; 2];
    for (slot, word) in idx.iter_mut().zip(words) {
        let lw = word.trim().to_lowercase();
        *slot = *map
            .get(lw.as_str())
            .ok_or_else(|| PhraseError::UnknownWord(word.clone()))?;
    }
    Ok(pack(idx))
}

/// `<<i1:11, i2:11, 0:2>>` as 3 big-endian bytes.
fn pack(idx: [u16; 2]) -> [u8; 3] {
    // 22 bits of indices + 2 zero bits = 24 bits.
    let mut acc: u32 = 0;
    for &i in &idx {
        acc = (acc << 11) | (i as u32 & 0x7ff);
    }
    acc <<= 2; // trailing 0:2
    let b = acc.to_be_bytes(); // 4 bytes; the value occupies the low 24 bits
    let mut out = [0u8; 3];
    out.copy_from_slice(&b[1..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_phrase_packs_to_expected_wib() {
        // From the shared fixture: indices 12/345 → 018564.
        let words = ["account", "clinic"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let wib = phrase_to_wib(&words).expect("known phrase decodes");
        assert_eq!(hex(&wib), "018564");
    }

    #[test]
    fn rejects_wrong_length_and_unknown_words() {
        assert!(matches!(
            phrase_to_wib(&["a".into(), "b".into(), "c".into()]),
            Err(PhraseError::WrongLength)
        ));
        let two_bad = vec!["notaword".to_string(); 2];
        assert!(matches!(
            phrase_to_wib(&two_bad),
            Err(PhraseError::UnknownWord(_))
        ));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
