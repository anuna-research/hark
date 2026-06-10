//! cbcl-chat frame decoding + the signing seam (SPEC-001 CON-006, IMPL-003 §5).
//!
//! A `/chat/v1` hub→client frame is `u32 big-endian payload length ‖ payload ‖
//! 64-byte Ed25519 signature`, byte-identical to what the browser client reads
//! (`apps/cbcl_chat/priv/web/app.js`, `onFrame`). This module decodes that
//! framing and defines the [`FrameSigner`] seam the identity key plugs into.
//!
//! There is deliberately **no bare-payload encoder here**. Outbound frames are
//! produced only by `signed_transport::SignedConn`, which signs the
//! domain-separated `signed_frame::envelope` — never raw payload bytes. The old
//! `encode_frame(payload, signer)` API was a raw-bytes signing oracle on the
//! identity key and was retired per SPEC-013 OQ-001 / R4-06; do not reintroduce
//! one.
//!
//! The agent does **not** verify inbound signatures: the hub verifies every
//! signer and reconciles it with `:from` before fan-out (cbcl-chat-session-ws
//! `verify-sender`), so a delivered frame's payload is already custody-checked,
//! exactly as the browser treats it.

/// Length of an Ed25519 signature in bytes.
pub const SIG_LEN: usize = 64;
/// Length of the big-endian `u32` payload-length prefix.
pub const LEN_PREFIX: usize = 4;

/// Produces a 64-byte Ed25519 signature over the given bytes. Implemented by
/// [`crate::identity::ChatIdentity`]; invoked only by
/// `signed_transport::SignedConn`, which always passes the domain-separated
/// envelope (`signed_frame::envelope`), never bare payload bytes (SPEC-013
/// OQ-001).
pub trait FrameSigner: Send + Sync {
    fn sign(&self, payload: &[u8]) -> [u8; SIG_LEN];
}

/// Extract the payload bytes from a hub-delivered frame, or `None` if the frame
/// is malformed (drop it, keep the connection — SPEC-001 REQ-016). The trailing
/// signature is not verified by the agent (see module docs) but it MUST be
/// present and the frame MUST be exactly `len(4) ‖ payload(len) ‖ sig(64)`: a
/// frame whose total length is not `LEN_PREFIX + len + SIG_LEN` is malformed
/// (truncated, over-long, or framed against a different format) and is rejected
/// rather than silently treating trailing bytes as absent.
pub fn decode_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let expected = LEN_PREFIX.checked_add(len)?.checked_add(SIG_LEN)?;
    if frame.len() != expected {
        return None;
    }
    Some(&frame[LEN_PREFIX..LEN_PREFIX + len])
}

#[cfg(test)]
mod tests {
    use super::{LEN_PREFIX, SIG_LEN, decode_payload};

    /// Build a hub-shaped frame by hand: `len(4, big-endian) ‖ payload ‖ sig(64)`.
    /// Test-local on purpose — production has no bare-payload encoder (R4-06).
    fn frame(payload: &[u8], sig_byte: u8) -> Vec<u8> {
        let mut f = Vec::with_capacity(LEN_PREFIX + payload.len() + SIG_LEN);
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(payload);
        f.extend_from_slice(&[sig_byte; SIG_LEN]);
        f
    }

    #[test]
    fn round_trips_payload() {
        let payload = b"(tell @research \"hi\" :from @aria)";
        assert_eq!(decode_payload(&frame(payload, 0)), Some(&payload[..]));
    }

    #[test]
    fn layout_matches_browser_format() {
        // 4-byte big-endian length, then payload, then 64-byte sig.
        let f = frame(b"hi", 0xAB);
        assert_eq!(f.len(), LEN_PREFIX + 2 + SIG_LEN);
        assert_eq!(&f[0..4], &[0, 0, 0, 2]); // len = 2, big-endian
        assert_eq!(&f[4..6], b"hi");
        assert!(f[6..].iter().all(|&b| b == 0xAB)); // 64-byte sig region
    }

    #[test]
    fn rejects_short_frames() {
        assert_eq!(decode_payload(&[]), None);
        assert_eq!(decode_payload(&[0, 0]), None); // shorter than length prefix
        // Declares len=10 but only 2 payload bytes present.
        assert_eq!(decode_payload(&[0, 0, 0, 10, b'a', b'b']), None);
    }

    #[test]
    fn rejects_frame_missing_signature() {
        // len=2 ‖ "hi" but no trailing 64-byte signature: malformed.
        let mut f = Vec::new();
        f.extend_from_slice(&2u32.to_be_bytes());
        f.extend_from_slice(b"hi");
        assert_eq!(decode_payload(&f), None);
        // Payload + partial signature is also rejected (not exactly SIG_LEN).
        f.extend_from_slice(&[0u8; SIG_LEN - 1]);
        assert_eq!(decode_payload(&f), None);
    }

    #[test]
    fn rejects_overlong_frame() {
        // A correctly framed payload with extra trailing bytes is rejected
        // rather than silently truncated to the declared length.
        let mut f = frame(b"hi", 0);
        f.push(0xFF);
        assert_eq!(decode_payload(&f), None);
    }

    #[test]
    fn empty_payload_is_valid() {
        assert_eq!(decode_payload(&frame(b"", 0)), Some(&b""[..]));
    }
}
