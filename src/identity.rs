//! The agent's cbcl-chat signing identity (IMPL-003 Phase 2; SPEC-001 CON-006).
//!
//! A persisted Ed25519 keypair — the agent's cryptographic identity on
//! `/chat/v1`. The hub enrols the public key against the agent's handle on the
//! first signed `hello` (TOFU) and thereafter requires the same key, so the
//! signer here is *who the agent is* on the wire.
//!
//! This is the one piece of cryptography V1 ships, and it is deliberately
//! standard: RFC 8032 Ed25519 via the audited `ed25519-dalek`, the same
//! primitive the cbcl-chat browser client uses (WebCrypto) and the hub verifies
//! (libsodium). It implements [`crate::chat_frame::FrameSigner`], so it plugs
//! into the frame codec at the single crypto seam and nothing else in the
//! transport touches keys.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};

use crate::chat_frame::{FrameSigner, SIG_LEN};

/// The agent's Ed25519 signing identity for cbcl-chat.
pub struct ChatIdentity {
    signing: SigningKey,
}

impl ChatIdentity {
    /// Load the signing key from `path`, generating and persisting a fresh one
    /// **only** when the file does not yet exist. The 32-byte seed is stored raw,
    /// `0600` on Unix. A new key means a new identity (the hub TOFU-enrols it on
    /// the next `hello`), so we must never create one to paper over a transient
    /// read failure: any error other than `NotFound` propagates unchanged, and a
    /// wrong-sized file is a hard error rather than a silent overwrite.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "identity file {} is not a 32-byte Ed25519 seed",
                            path.display()
                        ),
                    )
                })?;
                Ok(Self::from_seed(seed))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::create(path),
            // EACCES, EIO, a directory in the way, etc. — surface it. Treating
            // these as "missing" would rotate the agent's identity on a blip.
            Err(error) => Err(error),
        }
    }

    /// Generate a fresh seed and persist it atomically with `0600` on Unix.
    /// `create_new` fails (rather than truncating) if the file appeared between
    /// the read and now, so a concurrent creator can't have its key clobbered.
    fn create(path: &Path) -> std::io::Result<Self> {
        let seed: [u8; 32] = rand::random();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&seed)?;
        file.sync_all()?;
        Ok(Self::from_seed(seed))
    }

    /// Build an identity directly from a 32-byte seed (tests, or a key supplied
    /// out of band).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The raw 32-byte Ed25519 public key, base64 (standard) — the value for a
    /// `hello`'s `:key`, matching the browser's `pubB64`.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }
}

impl FrameSigner for ChatIdentity {
    fn sign(&self, payload: &[u8]) -> [u8; SIG_LEN] {
        self.signing.sign(payload).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::ChatIdentity;
    use crate::chat_frame::FrameSigner;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn verifying_key(id: &ChatIdentity) -> VerifyingKey {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let bytes = B64.decode(id.public_key_b64()).expect("valid base64");
        VerifyingKey::from_bytes(&bytes.try_into().expect("32 bytes")).expect("valid key")
    }

    #[test]
    fn signs_verifiably() {
        let id = ChatIdentity::from_seed([7u8; 32]);
        let payload = b"(hello @research :from @aria :key \"...\")";
        let sig = id.sign(payload);
        let vk = verifying_key(&id);
        assert!(vk.verify(payload, &Signature::from_bytes(&sig)).is_ok());
        // A tampered payload must fail.
        assert!(
            vk.verify(b"tampered", &Signature::from_bytes(&sig))
                .is_err()
        );
    }

    #[test]
    fn pubkey_is_32_bytes_base64() {
        let id = ChatIdentity::from_seed([1u8; 32]);
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        assert_eq!(B64.decode(id.public_key_b64()).unwrap().len(), 32);
    }

    #[test]
    fn persists_and_reloads_same_identity() {
        let dir = std::env::temp_dir().join(format!("hark-id-test-{}", std::process::id()));
        let path = dir.join("chat-identity.key");
        let _ = std::fs::remove_dir_all(&dir);
        let a = ChatIdentity::load_or_create(&path).expect("create");
        let b = ChatIdentity::load_or_create(&path).expect("reload");
        assert_eq!(a.public_key_b64(), b.public_key_b64());
        assert_eq!(a.sign(b"x"), b.sign(b"x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn created_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hark-id-perm-{}", std::process::id()));
        let path = dir.join("chat-identity.key");
        let _ = std::fs::remove_dir_all(&dir);
        ChatIdentity::load_or_create(&path).expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "seed must be created owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_sized_file_is_an_error_not_a_rotation() {
        let dir = std::env::temp_dir().join(format!("hark-id-bad-{}", std::process::id()));
        let path = dir.join("chat-identity.key");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(&path, b"too short").expect("write");
        match ChatIdentity::load_or_create(&path) {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidData),
            Ok(_) => panic!("a wrong-sized key file must be an error, not a silent rotation"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
