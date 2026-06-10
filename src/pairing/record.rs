//! The pairing record (the hub-released payload) and its wire codec. Decodes
//! the length-prefixed binary form produced by `cbcl-chat-pairing:encode-record`
//! after AEAD-decrypting it under K.

/// One declared dialect the record carries: `(name, digest-hex)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialectEntry {
    pub name: String,
    pub digest: String,
}

/// The released pairing record: the agent's channel name, the channel, the
/// encryption mode (advisory — the real pin derives from cap presence, R4-01),
/// the `cbcl-chat-invite` cap, the adder, the chosen dialects, and an expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    pub agent_name: String,
    pub channel: String,
    pub enc: bool,
    /// The invite cap bytes; empty for a public channel (no cap).
    pub cap: Vec<u8>,
    pub adder: String,
    pub dialects: Vec<DialectEntry>,
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("pairing record is malformed (truncated or trailing bytes)")]
    Malformed,
    #[error("pairing record field is not valid UTF-8")]
    NotUtf8,
}

impl PairingRecord {
    /// Whether the record admits to a private channel — the presence of a
    /// `cbcl-chat-invite` cap. This is the authoritative encryption-pin source
    /// (REQ-007 / R4-01): a cap ⇒ private ⇒ encrypted, independent of the
    /// advisory `enc` bit a hub could flip.
    pub fn has_cap(&self) -> bool {
        !self.cap.is_empty()
    }

    /// Decode the length-prefixed binary form (the AEAD plaintext).
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader::new(bytes);
        let agent_name = r.lv_str()?;
        let channel = r.lv_str()?;
        let enc = r.u8()? == 1;
        let cap = r.lv_bytes()?.to_vec();
        let adder = r.lv_str()?;
        let exp = r.i64()?;
        let dcount = r.u16()?;
        let mut dialects = Vec::with_capacity(dcount as usize);
        for _ in 0..dcount {
            let name = r.lv_str()?;
            let digest = r.lv_str()?;
            dialects.push(DialectEntry { name, digest });
        }
        if !r.is_empty() {
            return Err(RecordError::Malformed);
        }
        Ok(Self { agent_name, channel, enc, cap, adder, dialects, exp })
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos == self.b.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> {
        let end = self.pos.checked_add(n).ok_or(RecordError::Malformed)?;
        if end > self.b.len() {
            return Err(RecordError::Malformed);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RecordError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn i64(&mut self) -> Result<i64, RecordError> {
        let s = self.take(8)?;
        Ok(i64::from_be_bytes(s.try_into().unwrap()))
    }
    fn lv_bytes(&mut self) -> Result<&'a [u8], RecordError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
    fn lv_str(&mut self) -> Result<String, RecordError> {
        let b = self.lv_bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| RecordError::NotUtf8)
    }
}
