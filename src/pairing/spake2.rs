//! SPAKE2 initiator over Ristretto255 — the agent side of the SPEC-016
//! pairing handshake (REQ-007). Byte-for-byte compatible with the hub
//! responder (`cbcl-crypto-spake2` over libsodium ristretto255); pinned by
//! the shared known-answer vectors (`tests/pairing_vectors.rs`).
//!
//! Construction (must match `cbcl-crypto-spake2.lfe` exactly):
//!   M, N   = ristretto255 from_uniform_bytes(SHA-512(seed))   (nothing-up-sleeve)
//!   w_bytes = HKDF-SHA256(ikm=wib, salt=ctx.w_salt, info=ctx.w_info, len=64)
//!   w       = scalar_reduce_wide(w_bytes)
//!   x       = scalar_reduce_wide(ephemeral64)                 (initiator)
//!   msg_A   = x*B + w*M
//!   K_spake2 = x*(msg_B - w*N)
//!   transcript = SHA256( lv(idA) lv(idB) lv(msg_A) lv(msg_B) lv(K_spake2) lv(w_bytes) )
//!     where lv(x) = le64(len(x)) || x
//!   K       = HKDF-SHA256(ikm=transcript, salt="", info=ctx.sk_info, len=32)
//!   MAC_A   = HMAC-SHA256(K, ctx.mac_a_label || transcript)
//!   MAC_B   = HMAC-SHA256(K, ctx.mac_b_label || transcript)

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// The transcript-domain constants (R3-03). The pairing values are fixed in
/// [`Context::pairing`] and pinned by the vectors.
#[derive(Clone)]
pub struct Context {
    pub id_b_prefix: Vec<u8>,
    pub w_salt: Vec<u8>,
    pub w_info: Vec<u8>,
    pub sk_info: Vec<u8>,
    pub mac_a_label: Vec<u8>,
    pub mac_b_label: Vec<u8>,
}

impl Context {
    /// The SPEC-016 pairing domain (matches `cbcl-chat-pairing:pairing-context`).
    pub fn pairing() -> Self {
        Self {
            id_b_prefix: b"cbcl-chat-pair:".to_vec(),
            w_salt: b"cbcl-chat-pair-v1".to_vec(),
            w_info: b"cbcl-chat-pair-password-v1".to_vec(),
            sk_info: b"cbcl-chat-pair-session-key-v1".to_vec(),
            mac_a_label: b"cbcl-chat-pair-agent-confirm".to_vec(),
            mac_b_label: b"cbcl-chat-pair-hub-confirm".to_vec(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Spake2Error {
    #[error("peer message is not a valid ristretto255 point")]
    InvalidPeerPoint,
    #[error("hub MAC verification failed")]
    MacMismatch,
}

/// M / N nothing-up-my-sleeve generators (ristretto255 hash-to-group of the
/// SHA-512 of the CFRG reference strings).
fn m_point() -> RistrettoPoint {
    from_seed(b"SPAKE2 M Ristretto Curve25519 SHA-512 Hash v1")
}
fn n_point() -> RistrettoPoint {
    from_seed(b"SPAKE2 N Ristretto Curve25519 SHA-512 Hash v1")
}
fn from_seed(seed: &[u8]) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&Sha512::digest(seed));
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("hkdf len within bounds");
    out
}

/// `le64(len(x)) || x` — the RFC 9382 length-prefixed transcript framing.
fn lv(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u64).to_le_bytes());
    out.extend_from_slice(x);
}

/// The initiator (agent) state, carrying everything the later steps need.
pub struct Initiator {
    ctx: Context,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    w_scalar: Scalar,
    w_bytes: Vec<u8>,
    x_scalar: Scalar,
    msg_a: [u8; 32],
    // Filled after step1:
    transcript: Option<[u8; 32]>,
    session_key: Option<[u8; 32]>,
}

impl Initiator {
    /// Begin the handshake. `wib` is the word-index bytes derived from the
    /// phrase; `id_a` binds the transcript to this pairing (the pairing_id);
    /// `hub_id` feeds idB; `ephemeral64` is 64 CSPRNG bytes (the agent's x).
    pub fn start(ctx: Context, wib: &[u8], id_a: &[u8], hub_id: &[u8], ephemeral64: &[u8; 64]) -> Self {
        let w_bytes = hkdf_sha256(wib, &ctx.w_salt, &ctx.w_info, 64);
        let mut w_wide = [0u8; 64];
        w_wide.copy_from_slice(&w_bytes);
        let w_scalar = Scalar::from_bytes_mod_order_wide(&w_wide);
        let x_scalar = Scalar::from_bytes_mod_order_wide(ephemeral64);

        let mut id_b = ctx.id_b_prefix.clone();
        id_b.extend_from_slice(hub_id);

        // msg_A = x*B + w*M
        let msg_a_point = RISTRETTO_BASEPOINT_TABLE * &x_scalar + w_scalar * m_point();
        let msg_a = msg_a_point.compress().to_bytes();

        Self {
            ctx,
            id_a: id_a.to_vec(),
            id_b,
            w_scalar,
            w_bytes,
            x_scalar,
            msg_a,
            transcript: None,
            session_key: None,
        }
    }

    /// The first wire value the agent sends (pair_init.msg_a).
    pub fn msg_a(&self) -> [u8; 32] {
        self.msg_a
    }

    /// Step 1: consume the hub's msg_B, derive K, and produce MAC_A
    /// (pair_confirm.mac_a). Fails closed if msg_B is not a valid point.
    pub fn step1(&mut self, msg_b: &[u8]) -> Result<[u8; 32], Spake2Error> {
        let peer = CompressedRistretto::from_slice(msg_b)
            .map_err(|_| Spake2Error::InvalidPeerPoint)?
            .decompress()
            .ok_or(Spake2Error::InvalidPeerPoint)?;
        // K_spake2 = x * (msg_B - w*N)
        let k_spake2 = (self.x_scalar * (peer - self.w_scalar * n_point()))
            .compress()
            .to_bytes();

        let mut t = Vec::new();
        lv(&mut t, &self.id_a);
        lv(&mut t, &self.id_b);
        lv(&mut t, &self.msg_a);
        lv(&mut t, msg_b);
        lv(&mut t, &k_spake2);
        lv(&mut t, &self.w_bytes);
        let transcript: [u8; 32] = Sha256::digest(&t).into();

        let key = hkdf_sha256(&transcript, b"", &self.ctx.sk_info, 32);
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&key);

        let mac_a = mac(&session_key, &self.ctx.mac_a_label, &transcript);
        self.transcript = Some(transcript);
        self.session_key = Some(session_key);
        Ok(mac_a)
    }

    /// Step 2: verify the hub's MAC_B (pair_release.mac_b). On success the
    /// hub is authenticated and [`session_key`](Self::session_key) is the
    /// agreed K under which the record is encrypted.
    pub fn verify_hub(&self, mac_b: &[u8]) -> Result<(), Spake2Error> {
        let transcript = self.transcript.expect("step1 before verify_hub");
        let key = self.session_key.expect("step1 before verify_hub");
        let expected = mac(&key, &self.ctx.mac_b_label, &transcript);
        if expected.ct_eq(mac_b).into() {
            Ok(())
        } else {
            Err(Spake2Error::MacMismatch)
        }
    }

    /// The agreed session key K (only meaningful after a successful
    /// [`verify_hub`](Self::verify_hub)).
    pub fn session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }
}

fn mac(key: &[u8], label: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key any length");
    m.update(label);
    m.update(transcript);
    m.finalize().into_bytes().into()
}
