//! 4-word BIP39 phrase → word-index bytes (`wib`), matching the hub's
//! `cbcl-chat-pairing-store:phrase->wib`. The four 11-bit indices are packed
//! `<<i1:11, i2:11, i3:11, i4:11, 0:4>>` = 6 bytes, the ikm into derive-w.

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
    #[error("a pairing phrase must be exactly 4 words")]
    WrongLength,
    #[error("not a BIP39 word: {0}")]
    UnknownWord(String),
}

/// Decode a 4-word phrase to its word-index bytes. Words are matched
/// case-insensitively against the BIP39 English list.
pub fn phrase_to_wib(words: &[String]) -> Result<[u8; 6], PhraseError> {
    if words.len() != 4 {
        return Err(PhraseError::WrongLength);
    }
    let map = index_of();
    let mut idx = [0u16; 4];
    for (slot, word) in idx.iter_mut().zip(words) {
        let lw = word.trim().to_lowercase();
        *slot = *map.get(lw.as_str()).ok_or_else(|| PhraseError::UnknownWord(word.clone()))?;
    }
    Ok(pack(idx))
}

/// `<<i1:11, i2:11, i3:11, i4:11, 0:4>>` as 6 big-endian bytes.
fn pack(idx: [u16; 4]) -> [u8; 6] {
    // 44 bits of indices + 4 zero bits = 48 bits.
    let mut acc: u64 = 0;
    for &i in &idx {
        acc = (acc << 11) | (i as u64 & 0x7ff);
    }
    acc <<= 4; // trailing 0:4
    let b = acc.to_be_bytes(); // 8 bytes; the value occupies the low 48 bits
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[2..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_phrase_packs_to_expected_wib() {
        // From the shared fixture: indices 12/345/1789/2000 → 0185677efd00.
        let words = ["account", "clinic", "text", "wheel"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let wib = phrase_to_wib(&words).expect("known phrase decodes");
        assert_eq!(hex(&wib), "0185677efd00");
    }

    #[test]
    fn rejects_wrong_length_and_unknown_words() {
        assert!(matches!(
            phrase_to_wib(&["a".into(), "b".into(), "c".into()]),
            Err(PhraseError::WrongLength)
        ));
        let four_bad = vec!["notaword".to_string(); 4];
        assert!(matches!(
            phrase_to_wib(&four_bad),
            Err(PhraseError::UnknownWord(_))
        ));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
