//! Signed-member wire codec (SPEC-012 v0.5.2) — the Rust peer of the LFE
//! `cbcl-signed-frame` (cbcl-bus `apps/cbcl_bus`) and the chat browser client.
//!
//! Wire frame: `len(4, big-endian) ‖ seq(8, big-endian) ‖ payload ‖ sig(64)`.
//! The signature covers the domain-separated **envelope**, NOT the bare payload:
//!
//! ```text
//! DS_TAG ‖ hub_id ‖ audience ‖ seq(8) ‖ conn_nonce ‖ payload
//! ```
//!
//! where every variable field is length-prefixed (`u32-be ‖ bytes`), so no two
//! distinct field assignments can produce identical signed bytes. The hub issues
//! `conn_nonce` per connection (binds each signature to this live connection);
//! `seq` is a per-connection monotonic counter the hub uses to reject
//! replay/reorder. This replaces hark's old bare-payload chat codec and its
//! bearer-token router path with one signed-member transport (slice-6).

/// Protocol domain-separation tag bound into every signed envelope.
pub const DS_TAG: &[u8] = b"cbcl-signed-member/v1";

/// Ed25519 signature length in bytes.
pub const SIG_LEN: usize = 64;

/// `len(4) ‖ seq(8)` header length.
const HEADER_LEN: usize = 12;

/// Length-prefix a field into `out`: `u32` big-endian length ‖ bytes.
fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the domain-separated envelope that the Ed25519 signature covers.
pub fn envelope(hub_id: &[u8], audience: &[u8], seq: u64, conn_nonce: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, DS_TAG);
    lp(&mut out, hub_id);
    lp(&mut out, audience);
    out.extend_from_slice(&seq.to_be_bytes());
    lp(&mut out, conn_nonce);
    lp(&mut out, payload);
    out
}

/// Encode a wire frame: `len(4) ‖ seq(8) ‖ payload ‖ sig(64)`.
pub fn encode_frame(seq: u64, payload: &[u8], sig: &[u8; SIG_LEN]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + SIG_LEN);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(sig);
    frame
}

/// Decode a wire frame into `(seq, payload, sig)`, or `None` if malformed
/// (shorter than the 12-byte header, or body length ≠ declared payload + 64).
pub fn decode_frame(frame: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let seq = u64::from_be_bytes(frame[4..HEADER_LEN].try_into().ok()?);
    let body = &frame[HEADER_LEN..];
    if body.len() != len + SIG_LEN {
        return None;
    }
    Some((seq, &body[..len], &body[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips() {
        let payload = b"(tell @room \"hi\")";
        let sig = [9u8; SIG_LEN];
        let frame = encode_frame(7, payload, &sig);
        let (seq, p, s) = decode_frame(&frame).expect("decodes");
        assert_eq!(seq, 7);
        assert_eq!(p, payload);
        assert_eq!(s, &sig);
    }

    #[test]
    fn decode_rejects_short_and_truncated() {
        assert!(decode_frame(b"only9byte").is_none());
        // header declares a 5-byte payload but the body is short
        let mut bad = Vec::new();
        bad.extend_from_slice(&5u32.to_be_bytes());
        bad.extend_from_slice(&1u64.to_be_bytes());
        bad.extend_from_slice(b"hi");
        assert!(decode_frame(&bad).is_none());
    }

    /// Byte-for-byte parity with the LFE `cbcl-signed-frame:envelope` (cbcl-bus).
    /// Vector: hub="cbcl-chat", audience="wsroom", seq=1, nonce=16×0x07,
    /// payload=`(tell @wsroom "hi" :from @wsuser)`. The expected hex was produced
    /// by the LFE codec; a mismatch means the wire would fail to verify.
    #[test]
    fn envelope_matches_lfe_bus() {
        let env = envelope(
            b"cbcl-chat",
            b"wsroom",
            1,
            &[7u8; 16],
            b"(tell @wsroom \"hi\" :from @wsuser)",
        );
        let expected = "000000156362636c2d7369676e65642d6d656d6265722f7631000000096362636c2d63686174000000067773726f6f6d00000000000000010000001007070707070707070707070707070707000000212874656c6c20407773726f6f6d2022686922203a66726f6d204077737573657229";
        assert_eq!(hex(&env), expected);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
