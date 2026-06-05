//! cbcl-chat signed-frame codec (SPEC-001 CON-006, IMPL-003 §5).
//!
//! A `/chat/v1` frame is `u32 big-endian payload length ‖ payload ‖ 64-byte
//! Ed25519 signature`, byte-identical to the browser client
//! (`apps/cbcl_chat/priv/web/app.js`, `sendCBCL`/`onFrame`).
//!
//! The framing is plain bytes and lives here, ungated. The *signature* is the
//! only crypto, and it is isolated behind [`FrameSigner`] so the gated
//! `ed25519-dalek` implementation (IMPL-003 Phase 2) plugs in at one seam. The
//! agent does **not** verify inbound signatures: the hub verifies every signer
//! and reconciles it with `:from` before fan-out (cbcl-chat-session-ws
//! `verify-sender`), so a delivered frame's payload is already custody-checked,
//! exactly as the browser treats it.

/// Length of an Ed25519 signature in bytes.
pub const SIG_LEN: usize = 64;
/// Length of the big-endian `u32` payload-length prefix.
pub const LEN_PREFIX: usize = 4;

/// Produces the 64-byte signature over a canonical CBCL payload. Phase 1 ships
/// [`NullSigner`]; the real `ed25519-dalek` signer lands in Phase 2 (the
/// crypto-gate boundary). Keeping it a trait means the transport, claim round,
/// and selector all compile and test with no crypto present.
pub trait FrameSigner: Send + Sync {
    fn sign(&self, payload: &[u8]) -> [u8; SIG_LEN];
}

/// Encode a signed frame: `len(4, big-endian) ‖ payload ‖ sig(64)`.
pub fn encode_frame(payload: &[u8], signer: &dyn FrameSigner) -> Vec<u8> {
    let sig = signer.sign(payload);
    let mut frame = Vec::with_capacity(LEN_PREFIX + payload.len() + SIG_LEN);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&sig);
    frame
}

/// Extract the payload bytes from a hub-delivered frame, or `None` if the frame
/// is malformed/short (drop it, keep the connection — SPEC-001 REQ-016). The
/// trailing signature is intentionally ignored (see module docs).
pub fn decode_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let end = LEN_PREFIX.checked_add(len)?;
    if frame.len() < end {
        return None;
    }
    Some(&frame[LEN_PREFIX..end])
}

/// A stub signer for Phase 1 — emits an all-zero signature. The real hub will
/// reject this with `bad-signature`; it exists only so the transport seam
/// compiles and is testable before the Ed25519 codec (Phase 2) lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSigner;

impl FrameSigner for NullSigner {
    fn sign(&self, _payload: &[u8]) -> [u8; SIG_LEN] {
        [0u8; SIG_LEN]
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_payload, encode_frame, FrameSigner, NullSigner, LEN_PREFIX, SIG_LEN};

    /// A signer that fills the signature with a constant, to check placement.
    struct ConstSigner(u8);
    impl FrameSigner for ConstSigner {
        fn sign(&self, _payload: &[u8]) -> [u8; SIG_LEN] {
            [self.0; SIG_LEN]
        }
    }

    #[test]
    fn round_trips_payload() {
        let payload = b"(tell @research \"hi\" :from @aria)";
        let frame = encode_frame(payload, &NullSigner);
        assert_eq!(decode_payload(&frame), Some(&payload[..]));
    }

    #[test]
    fn layout_matches_browser_format() {
        // 4-byte big-endian length, then payload, then 64-byte sig.
        let payload = b"hi";
        let frame = encode_frame(payload, &ConstSigner(0xAB));
        assert_eq!(frame.len(), LEN_PREFIX + payload.len() + SIG_LEN);
        assert_eq!(&frame[0..4], &[0, 0, 0, 2]); // len = 2, big-endian
        assert_eq!(&frame[4..6], b"hi");
        assert!(frame[6..].iter().all(|&b| b == 0xAB)); // 64-byte sig region
    }

    #[test]
    fn null_signer_is_all_zero() {
        let frame = encode_frame(b"x", &NullSigner);
        assert!(frame[LEN_PREFIX + 1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_short_frames() {
        assert_eq!(decode_payload(&[]), None);
        assert_eq!(decode_payload(&[0, 0]), None); // shorter than length prefix
        // Declares len=10 but only 2 payload bytes present.
        assert_eq!(decode_payload(&[0, 0, 0, 10, b'a', b'b']), None);
    }

    #[test]
    fn empty_payload_is_valid() {
        let frame = encode_frame(b"", &NullSigner);
        assert_eq!(decode_payload(&frame), Some(&b""[..]));
    }
}
