//! Per-connection signing for the SPEC-012 signed-member wire (slice-6 6b).
//!
//! The Rust peer of what the chat browser client does and what the LFE hub
//! verifies (`cbcl-frame-verify`): each outbound frame is Ed25519-signed over the
//! domain-separated envelope (`signed_frame::envelope`) and framed as
//! `len ‖ seq ‖ payload ‖ sig`. The hub issues a `conn_nonce` bootstrap on
//! connect; we capture it and fold it (plus a per-connection monotonic `seq`)
//! into every signature, so a frame can't be replayed across connections and
//! out-of-order/duplicate frames are dropped by the hub's strict seq check.
//!
//! This replaces hark's old transports: the router path's `Authorization: Bearer`
//! plus unsigned text hello, and the chat path's bare-payload codec. Identity is
//! per-frame by signature (REQ-009) — there is no bearer token.

use crate::chat_frame::FrameSigner;
use crate::signed_frame::{encode_frame, envelope};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

/// The router's substrate handle — the audience the router binds for frames an
/// agent sends to it (`@router`, sigil-stripped, matching `cbcl-frame-recipient`).
/// Every frame an agent sends to the router resolves to this: tells/asks to
/// `@router`, and recipient-less terminals (reply/error) which the hub correlates
/// by thread/receipt to the substrate.
pub const ROUTER_AUDIENCE: &[u8] = b"router";

/// Default router hub id folded into the envelope (overridden by the bootstrap).
pub const ROUTER_HUB_DEFAULT: &[u8] = b"cbcl-router";

/// The hub's connect bootstrap, parsed from
/// `(tell @agent "conn-nonce" :from @<hub> :nonce "<b64>" :hub "<hub>")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnBootstrap {
    /// The raw (base64-decoded) connection nonce.
    pub conn_nonce: Vec<u8>,
    /// The hub id, folded into every envelope as `hub_id`.
    pub hub_id: Vec<u8>,
}

/// Recognise + parse the hub's conn-nonce bootstrap frame payload. Returns `None`
/// for any other frame (so a normal message is not mistaken for the bootstrap).
pub fn parse_conn_bootstrap(payload: &str) -> Option<ConnBootstrap> {
    // Must be the transport bootstrap: a tell to @agent (router) or @client
    // (chat) whose content is "conn-nonce" and which carries :nonce. Anything
    // else is a real message.
    let to_transport =
        payload.starts_with("(tell @agent ") || payload.starts_with("(tell @client ");
    if !to_transport || !payload.contains("\"conn-nonce\"") {
        return None;
    }
    let nonce_b64 = quoted_kw(payload, ":nonce")?;
    let hub = quoted_kw(payload, ":hub")
        .unwrap_or_else(|| String::from_utf8_lossy(ROUTER_HUB_DEFAULT).into_owned());
    let conn_nonce = B64.decode(nonce_b64.as_bytes()).ok()?;
    Some(ConnBootstrap {
        conn_nonce,
        hub_id: hub.into_bytes(),
    })
}

/// Extract the double-quoted value immediately following a `:keyword`, e.g.
/// `:nonce "abc"` -> `Some("abc")`. Minimal: the bootstrap is a fixed shape.
fn quoted_kw(s: &str, kw: &str) -> Option<String> {
    let after = &s[s.find(kw)? + kw.len()..];
    let open = after.find('"')? + 1;
    let rest = &after[open..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

/// Per-connection signing state: the hub id + conn nonce captured at connect,
/// and the monotonic frame sequence.
pub struct SignedConn {
    hub_id: Vec<u8>,
    conn_nonce: Vec<u8>,
    seq: u64,
}

impl SignedConn {
    /// Build from a parsed bootstrap (the usual path).
    pub fn from_bootstrap(b: &ConnBootstrap) -> Self {
        Self {
            hub_id: b.hub_id.clone(),
            conn_nonce: b.conn_nonce.clone(),
            seq: 0,
        }
    }

    /// Build directly (tests / non-bootstrap callers).
    pub fn new(hub_id: impl Into<Vec<u8>>, conn_nonce: impl Into<Vec<u8>>) -> Self {
        Self {
            hub_id: hub_id.into(),
            conn_nonce: conn_nonce.into(),
            seq: 0,
        }
    }

    /// Sign `payload` for `audience` into a wire frame, advancing the connection
    /// seq. `signer` signs the domain-separated envelope (not the bare payload).
    pub fn sign_frame(
        &mut self,
        signer: &dyn FrameSigner,
        audience: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        self.seq += 1;
        let env = envelope(&self.hub_id, audience, self.seq, &self.conn_nonce, payload);
        let sig = signer.sign(&env);
        encode_frame(self.seq, payload, &sig)
    }

    /// Sign a frame addressed to the router (audience = the substrate handle).
    pub fn sign_router_frame(&mut self, signer: &dyn FrameSigner, payload: &[u8]) -> Vec<u8> {
        self.sign_frame(signer, ROUTER_AUDIENCE, payload)
    }

    /// Sign a frame for the chat hub. Unlike the router (which strips the sigil
    /// and folds recipient-less terminals to the substrate), the chat hub binds
    /// `audience` = the message's recipient WITH its `@` sigil (matching
    /// `cbcl-core-msg:room`), so derive it from the payload.
    pub fn sign_chat_frame(&mut self, signer: &dyn FrameSigner, payload: &[u8]) -> Vec<u8> {
        let audience = chat_audience(payload).unwrap_or_default();
        self.sign_frame(signer, &audience, payload)
    }
}

/// The chat audience: the recipient handle (kept `@`-prefixed) — the first
/// `@`-token in the canonical payload, i.e. the recipient immediately after the
/// performative (a `(lang …)` wrapper's inner recipient is also the first `@`).
pub fn chat_audience(payload: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(payload).ok()?;
    let at = s.find('@')?;
    let rest = &s[at..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ')' || c == '(')
        .unwrap_or(rest.len());
    Some(rest.as_bytes()[..end].to_vec())
}

/// The signed-member router hello payload (replaces the old unsigned
/// `(lang cbcl-router (tell @router "hello" ...))`):
/// `(hello @router :from @<agent-id> :key "<pubkey-b64>" :dialects (...))`.
/// `cbcl-hello:fields` reads `:from` as the agent-id, `:key` as the advertised
/// Ed25519 key, and `:dialects` as the advertised set.
pub fn build_router_hello(agent_id: &str, pubkey_b64: &str, dialects: &[String]) -> String {
    let dl = dialects
        .iter()
        .map(|d| format!("\"{}\"", d.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "(hello @router :from @{} :key \"{}\" :dialects ({}))",
        agent_id, pubkey_b64, dl
    )
}

/// CON-012 read-frame allocator (ADR-036): assigns each read request a `(session_id, frame_id)`
/// BEFORE inner read-signing, so the `READ-CONTEXT` the request signs binds to a frame the
/// transport retains and can match against the response. `session_id` is the connection nonce
/// (base64); `frame_id` is a per-connection monotonic counter. The duplicate-frame classifier,
/// exact-response cache, and consumed-frame watermark stay server-side (ADR-036) — this is only
/// the client-side allocation.
pub struct ReadFrameAllocator {
    session_id: String,
    next_frame: i64,
}

impl ReadFrameAllocator {
    /// Bind a session id to the connection nonce captured at bootstrap.
    pub fn for_connection(conn_nonce: &[u8]) -> Self {
        Self {
            session_id: B64.encode(conn_nonce),
            next_frame: 0,
        }
    }

    /// Allocate the next `(session_id, frame_id)` for a read request (monotonic).
    pub fn allocate_read_frame(&mut self) -> (String, i64) {
        let frame_id = self.next_frame;
        self.next_frame += 1;
        (self.session_id.clone(), frame_id)
    }

    /// The bound session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_frame_allocation_is_monotonic_and_session_bound() {
        let mut a = ReadFrameAllocator::for_connection(b"conn-nonce-bytes");
        let (s0, f0) = a.allocate_read_frame();
        let (s1, f1) = a.allocate_read_frame();
        assert_eq!(s0, s1, "same session id across the connection");
        assert_eq!((f0, f1), (0, 1), "frame ids are monotonic");
        assert_eq!(a.session_id(), s0);
    }
    use crate::signed_frame::decode_frame;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    struct DalekSigner(SigningKey);
    impl FrameSigner for DalekSigner {
        fn sign(&self, payload: &[u8]) -> [u8; 64] {
            self.0.sign(payload).to_bytes()
        }
    }

    #[test]
    fn parses_conn_bootstrap() {
        let p = "(tell @agent \"conn-nonce\" :from @cbcl-router :nonce \"BwcHBwcHBwcHBwcHBwcHBw==\" :hub \"cbcl-router\")";
        let b = parse_conn_bootstrap(p).expect("bootstrap");
        assert_eq!(b.conn_nonce, vec![7u8; 16]);
        assert_eq!(b.hub_id, b"cbcl-router");
    }

    #[test]
    fn ignores_non_bootstrap_frames() {
        assert!(parse_conn_bootstrap("(reply @router \"done\" :thread \"r1\")").is_none());
        assert!(parse_conn_bootstrap("(tell @room \"conn-nonce\")").is_none()); // not @agent
    }

    /// A frame signed by SignedConn verifies against the agent's key over the
    /// envelope the hub reconstructs — i.e. the hub (`cbcl-frame-verify`) accepts
    /// it. seq advances per frame.
    #[test]
    fn signed_frame_verifies_as_the_hub_would() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let vk: VerifyingKey = sk.verifying_key();
        let signer = DalekSigner(sk);
        let mut conn = SignedConn::new(b"cbcl-router".to_vec(), vec![7u8; 16]);

        let payload = b"(hello @router :from @agent-x :key \"k\" :dialects (demo))";
        let wire = conn.sign_router_frame(&signer, payload);

        let (seq, p, sig) = decode_frame(&wire).expect("decodes");
        assert_eq!(seq, 1);
        assert_eq!(p, payload);
        // the hub rebuilds the envelope from (hub_id, audience=recipient, seq,
        // conn_nonce, payload) and verifies the sig against the advertised key
        let env = envelope(b"cbcl-router", ROUTER_AUDIENCE, seq, &[7u8; 16], payload);
        let sig = Signature::from_bytes(sig.try_into().expect("64"));
        assert!(
            vk.verify(&env, &sig).is_ok(),
            "hub must accept the signed frame"
        );

        // next frame advances seq
        let wire2 = conn.sign_router_frame(&signer, b"(tell @router \"progress\")");
        let (seq2, _, _) = decode_frame(&wire2).unwrap();
        assert_eq!(seq2, 2);
    }

    #[test]
    fn hello_has_signed_member_shape() {
        let h = build_router_hello("agent-x", "PUBKEYB64", &["demo".into(), "echo".into()]);
        assert_eq!(
            h,
            "(hello @router :from @agent-x :key \"PUBKEYB64\" :dialects (\"demo\" \"echo\"))"
        );
    }

    #[test]
    fn parses_chat_client_bootstrap() {
        let p = "(tell @client \"conn-nonce\" :from @cbcl-chat :nonce \"BwcHBwcHBwcHBwcHBwcHBw==\" :hub \"cbcl-chat\")";
        let b = parse_conn_bootstrap(p).expect("chat bootstrap");
        assert_eq!(b.conn_nonce, vec![7u8; 16]);
        assert_eq!(b.hub_id, b"cbcl-chat");
    }

    #[test]
    fn chat_audience_keeps_the_sigil() {
        assert_eq!(
            chat_audience(b"(hello @general :from @h :key \"k\")").unwrap(),
            b"@general"
        );
        assert_eq!(
            chat_audience(b"(keypub @hub :last \"l\" :from @a)").unwrap(),
            b"@hub"
        );
        assert_eq!(
            chat_audience(b"(lang cbcl-chat (tell @room \"x\" :from @a))").unwrap(),
            b"@room"
        );
    }
}
