//! Handle→wire-key pinning (REQ-011) and the domain-separated app-signed
//! assertion contexts (REQ-019, OQ-001).
//!
//! Pins anchor MLS membership to the authenticated wire identity: a handle's
//! Ed25519 key is pinned from that handle's **own verified signatures** —
//! a per-frame wire signature the transport verified, or a verified self-signed
//! `idkey` assertion — never from hub-asserted sources (`keypkg`/`keyget`
//! responses, presence). First observation is TOFU; a conflicting later
//! observation **flags** the pin and never silently rotates it. Rotation is
//! an authenticated ceremony: a `rekey` assertion cross-signed by both the
//! old and new key under its own domain-separation label.
//!
//! Every app-signed context here carries its own label, length-prefixed
//! exactly like the wire envelope's `DS_TAG` — so the signed-byte domains of
//! the wire envelope, `idkey`, `rekey`, removal evidence, and MLS
//! `SignWithLabel` are pairwise disjoint (OQ-001; the property test below is
//! IMPL condition A-t).

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::{DS_IDKEY_ASSERT, DS_IDKEY_ROTATE, MlsError};

const PINS_VERSION: u32 = 1;

/// A pinned handle→key binding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Pin {
    /// 32-byte Ed25519 verification key, base64 in the file.
    #[serde(with = "key32")]
    pub key: [u8; 32],
    /// Monotonic pin epoch: bumped by each verified rotation. An `idkey`
    /// assertion's nonce binds to this, so a stale assertion cannot re-pin
    /// an old key after a rotation (REQ-019's defined nonce purpose).
    pub pin_epoch: u64,
    /// A later verified observation conflicted with this pin. The key is NOT
    /// rotated; the conflict is surfaced (REQ-011).
    pub flagged: bool,
}

mod key32 {
    use super::B64;
    use base64::Engine as _;
    pub fn serialize<S: serde::Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(key))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        let bytes = B64.decode(s).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("key is not 32 bytes"))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PinsFile {
    version: u32,
    pins: HashMap<String, Pin>,
}

/// Outcome of feeding a verified observation into the store.
#[derive(Debug, PartialEq)]
pub enum Observation {
    /// First contact: pinned TOFU.
    Pinned,
    /// Matches the existing pin.
    Consistent,
    /// Conflicts with the existing pin — flagged, NOT rotated (REQ-011).
    Conflict,
}

/// Durable handle→wire-key pin store, one file per agent identity.
pub struct PinStore {
    path: PathBuf,
    pins: HashMap<String, Pin>,
}

impl PinStore {
    /// Open (or initialise) the pin file. Pins are trust state: an unreadable
    /// file is an error, not a silent reset — resetting pins reopens TOFU.
    pub fn open(path: &Path) -> Result<Self, MlsError> {
        let pins = match fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(MlsError::Storage(e)),
            Ok(bytes) => {
                let file: PinsFile = serde_json::from_slice(&bytes).map_err(|e| {
                    MlsError::Rejected(format!(
                        "pin store {} unreadable ({e}); refusing to silently reset trust state",
                        path.display()
                    ))
                })?;
                if file.version != PINS_VERSION {
                    return Err(MlsError::Rejected(format!(
                        "pin store version {} != supported {PINS_VERSION}",
                        file.version
                    )));
                }
                file.pins
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            pins,
        })
    }

    /// The pinned key for `handle`, if any. Flagged pins still return their
    /// original key — the flag means "surface a conflict", not "unpin".
    pub fn pinned(&self, handle: &str) -> Option<&Pin> {
        self.pins.get(handle)
    }

    /// Record a key observed from `handle`'s **own verified signature** (the
    /// transport verified a per-frame signature, or a verified `idkey`
    /// assertion). TOFU on first contact; conflict flags and keeps the pin.
    pub fn observe_verified(
        &mut self,
        handle: &str,
        key: &[u8; 32],
    ) -> Result<Observation, MlsError> {
        match self.pins.get_mut(handle) {
            None => {
                self.pins.insert(
                    handle.to_string(),
                    Pin {
                        key: *key,
                        pin_epoch: 0,
                        flagged: false,
                    },
                );
                self.persist()?;
                Ok(Observation::Pinned)
            }
            Some(pin) if &pin.key == key => Ok(Observation::Consistent),
            Some(pin) => {
                pin.flagged = true;
                self.persist()?;
                Ok(Observation::Conflict)
            }
        }
    }

    /// Verify a self-signed `idkey` assertion (REQ-019) and feed it into the
    /// store. The signature must verify under the asserted key itself, over
    /// the `cbcl-idkey-assert/v1` context bound to **this room**; the nonce
    /// must not predate the handle's current pin epoch (a stale assertion
    /// cannot re-pin an old key after a rotation).
    pub fn apply_idkey(
        &mut self,
        handle: &str,
        key: &[u8; 32],
        room: &str,
        nonce: u64,
        signature: &[u8],
        expected_room: &str,
    ) -> Result<Observation, MlsError> {
        if room != expected_room {
            return Err(MlsError::Rejected(format!(
                "idkey assertion bound to {room}, not this room {expected_room}"
            )));
        }
        let signed = idkey_signing_bytes(handle, key, room, nonce);
        verify_sig(key, &signed, signature)
            .map_err(|_| MlsError::Rejected("idkey assertion signature invalid".into()))?;
        if let Some(pin) = self.pins.get(handle) {
            if nonce < pin.pin_epoch {
                return Err(MlsError::Rejected(format!(
                    "idkey assertion nonce {nonce} predates pin epoch {} for {handle}",
                    pin.pin_epoch
                )));
            }
        }
        self.observe_verified(handle, key)
    }

    /// Apply a cross-signed rotation assertion (REQ-011): `rekey` re-pins
    /// `handle` from `old` to `new` only when BOTH keys signed the
    /// `cbcl-idkey-rotate/v1` context, `old` is the current pin, and the
    /// epoch advances the pin epoch. The re-pin is atomic and clears any
    /// flag; it is membership-visible via the safety number, not silent.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_rekey(
        &mut self,
        handle: &str,
        old: &[u8; 32],
        new: &[u8; 32],
        room: &str,
        epoch: u64,
        sig_old: &[u8],
        sig_new: &[u8],
        expected_room: &str,
    ) -> Result<(), MlsError> {
        if room != expected_room {
            return Err(MlsError::Rejected(format!(
                "rekey assertion bound to {room}, not this room {expected_room}"
            )));
        }
        let signed = rekey_signing_bytes(handle, old, new, room, epoch);
        verify_sig(old, &signed, sig_old)
            .map_err(|_| MlsError::Rejected("rekey: old-key signature invalid".into()))?;
        verify_sig(new, &signed, sig_new)
            .map_err(|_| MlsError::Rejected("rekey: new-key signature invalid".into()))?;
        let pin = self
            .pins
            .get_mut(handle)
            .ok_or_else(|| MlsError::Rejected(format!("rekey for unpinned handle {handle}")))?;
        if &pin.key != old {
            return Err(MlsError::Rejected(format!(
                "rekey old key does not match the current pin for {handle}"
            )));
        }
        if epoch <= pin.pin_epoch {
            return Err(MlsError::Rejected(format!(
                "rekey epoch {epoch} does not advance pin epoch {} (replay?)",
                pin.pin_epoch
            )));
        }
        pin.key = *new;
        pin.pin_epoch = epoch;
        pin.flagged = false;
        self.persist()?;
        Ok(())
    }

    fn persist(&self) -> Result<(), MlsError> {
        let file = PinsFile {
            version: PINS_VERSION,
            pins: self.pins.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn verify_sig(key: &[u8; 32], signed: &[u8], signature: &[u8]) -> Result<(), ()> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| ())?;
    let sig = Signature::from_slice(signature).map_err(|_| ())?;
    vk.verify(signed, &sig).map_err(|_| ())
}

/// Length-prefix a field: `u32-be ‖ bytes` — the same framing as the wire
/// envelope, so no two distinct field assignments produce identical bytes.
pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The `cbcl-idkey-assert/v1` signed context (REQ-019): label, handle, the
/// asserted key, the room binding (load-bearing: prevents cross-room
/// transplant), and the pin-epoch nonce.
pub fn idkey_signing_bytes(handle: &str, key: &[u8; 32], room: &str, nonce: u64) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, DS_IDKEY_ASSERT.as_bytes());
    lp(&mut out, handle.as_bytes());
    lp(&mut out, key);
    lp(&mut out, room.as_bytes());
    out.extend_from_slice(&nonce.to_be_bytes());
    out
}

/// The `cbcl-idkey-rotate/v1` signed context (REQ-011): both keys sign this
/// exact byte string.
pub fn rekey_signing_bytes(
    handle: &str,
    old: &[u8; 32],
    new: &[u8; 32],
    room: &str,
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, DS_IDKEY_ROTATE.as_bytes());
    lp(&mut out, handle.as_bytes());
    lp(&mut out, old);
    lp(&mut out, new);
    lp(&mut out, room.as_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_frame::FrameSigner as _;
    use crate::identity::ChatIdentity;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hark-pins-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("agent.pins")
    }

    fn key_of(seed: u8) -> ([u8; 32], ChatIdentity) {
        let id = ChatIdentity::from_seed([seed; 32]);
        (id.verifying_key_bytes(), id)
    }

    /// REQ-011 (TEST-011): TOFU pin on first contact; conflict flags, never
    /// rotates.
    #[test]
    fn tofu_then_conflict_flags_not_rotates() {
        let mut store = PinStore::open(&temp("tofu")).unwrap();
        let (alice_key, _) = key_of(1);
        let (evil_key, _) = key_of(2);

        assert_eq!(
            store.observe_verified("@alice", &alice_key).unwrap(),
            Observation::Pinned
        );
        assert_eq!(
            store.observe_verified("@alice", &alice_key).unwrap(),
            Observation::Consistent
        );
        assert_eq!(
            store.observe_verified("@alice", &evil_key).unwrap(),
            Observation::Conflict
        );
        let pin = store.pinned("@alice").unwrap();
        assert_eq!(pin.key, alice_key, "conflict must not rotate the pin");
        assert!(pin.flagged, "conflict must be surfaced");
    }

    /// Pins survive a restart (they are trust state).
    #[test]
    fn pins_persist() {
        let path = temp("persist");
        let (alice_key, _) = key_of(3);
        {
            let mut store = PinStore::open(&path).unwrap();
            store.observe_verified("@alice", &alice_key).unwrap();
        }
        let store = PinStore::open(&path).unwrap();
        assert_eq!(store.pinned("@alice").unwrap().key, alice_key);
    }

    /// REQ-019 (TEST-019): a valid self-signed idkey assertion pins; a
    /// tampered signature or a cross-room transplant is rejected.
    #[test]
    fn idkey_assertion_verifies_and_pins() {
        let mut store = PinStore::open(&temp("idkey")).unwrap();
        let (key, id) = key_of(4);
        let signed = idkey_signing_bytes("@alice", &key, "@research", 0);
        let sig = id.sign(&signed);

        assert_eq!(
            store
                .apply_idkey("@alice", &key, "@research", 0, &sig, "@research")
                .unwrap(),
            Observation::Pinned
        );

        // Cross-room transplant: same bytes presented for another room.
        let err = store
            .apply_idkey("@alice", &key, "@research", 0, &sig, "@other")
            .unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));

        // Tampered signature.
        let mut bad = sig.to_vec();
        bad[0] ^= 1;
        let err = store
            .apply_idkey("@alice", &key, "@research", 0, &bad, "@research")
            .unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));
    }

    /// REQ-019 nonce purpose: an assertion whose nonce predates the pin
    /// epoch cannot re-pin (stale assertion after a rotation).
    #[test]
    fn stale_idkey_nonce_rejected_after_rotation() {
        let mut store = PinStore::open(&temp("stale")).unwrap();
        let (old_key, old_id) = key_of(5);
        let (new_key, new_id) = key_of(6);
        store.observe_verified("@alice", &old_key).unwrap();

        // Rotate to the new key at epoch 5.
        let signed = rekey_signing_bytes("@alice", &old_key, &new_key, "@research", 5);
        store
            .apply_rekey(
                "@alice",
                &old_key,
                &new_key,
                "@research",
                5,
                &old_id.sign(&signed),
                &new_id.sign(&signed),
                "@research",
            )
            .unwrap();

        // A stale idkey assertion for the OLD key with nonce 0 must not re-pin.
        let stale = idkey_signing_bytes("@alice", &old_key, "@research", 0);
        let err = store
            .apply_idkey(
                "@alice",
                &old_key,
                "@research",
                0,
                &old_id.sign(&stale),
                "@research",
            )
            .unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));
        assert_eq!(store.pinned("@alice").unwrap().key, new_key);
    }

    /// REQ-011 rotation ceremony: both signatures required; old key must be
    /// the current pin; the epoch must advance (no replay).
    #[test]
    fn rekey_requires_both_signatures_and_fresh_epoch() {
        let mut store = PinStore::open(&temp("rekey")).unwrap();
        let (old_key, old_id) = key_of(7);
        let (new_key, new_id) = key_of(8);
        store.observe_verified("@alice", &old_key).unwrap();

        let signed = rekey_signing_bytes("@alice", &old_key, &new_key, "@research", 1);
        let sig_old = old_id.sign(&signed);
        let sig_new = new_id.sign(&signed);

        // Missing/wrong new-key signature → reject.
        assert!(
            store
                .apply_rekey(
                    "@alice",
                    &old_key,
                    &new_key,
                    "@research",
                    1,
                    &sig_old,
                    &sig_old,
                    "@research"
                )
                .is_err(),
            "new key must co-sign"
        );

        // Valid ceremony → re-pin.
        store
            .apply_rekey(
                "@alice",
                &old_key,
                &new_key,
                "@research",
                1,
                &sig_old,
                &sig_new,
                "@research",
            )
            .unwrap();
        let pin = store.pinned("@alice").unwrap();
        assert_eq!(pin.key, new_key);
        assert_eq!(pin.pin_epoch, 1);

        // Replaying the same ceremony → rejected (epoch does not advance).
        assert!(
            store
                .apply_rekey(
                    "@alice",
                    &old_key,
                    &new_key,
                    "@research",
                    1,
                    &sig_old,
                    &sig_new,
                    "@research"
                )
                .is_err(),
            "replay must not re-apply"
        );
    }

    /// IMPL condition A-t (OQ-001): the signed-byte domains — wire envelope,
    /// idkey, rekey, removal evidence, and MLS `SignWithLabel` — are pairwise
    /// disjoint under the pinned labels: no byte string is a valid member of
    /// two domains.
    #[test]
    fn no_cross_protocol_signature_collision() {
        use crate::signed_frame::envelope;
        for i in 0..256u32 {
            let blob = i.to_be_bytes();
            let key = [i as u8; 32];

            let wire = envelope(&blob, &blob, i as u64, &blob, &blob);
            let idkey = idkey_signing_bytes("@h", &key, "@r", i as u64);
            let rekey = rekey_signing_bytes("@h", &key, &key, "@r", i as u64);
            let remove =
                crate::mls::removal::evidence_signing_bytes("@r", &blob, i as u64, "@h", 0, &key);

            // MLS RFC 9420 SignWithLabel signs SignContent whose first byte
            // is the TLS varint length of "MLS 1.0 <label>" — ≥ 0x10 for
            // every RFC label, never 0x00. Every cbcl context starts with
            // the u32-be length of a short label: byte 0 is 0x00. The
            // domains are disjoint at byte 0.
            for mls_label in [
                "LeafNodeTBS",
                "KeyPackageTBS",
                "GroupInfoTBS",
                "FramedContentTBS",
            ] {
                assert!("MLS 1.0 ".len() + mls_label.len() >= 0x10);
            }
            for cbcl in [&wire, &idkey, &rekey, &remove] {
                assert_eq!(cbcl[0], 0x00, "cbcl contexts start with u32-be len");
            }

            // Pairwise within cbcl: each context embeds exactly its own
            // label at offset 4; the labels are pairwise distinct and none
            // is a prefix of another, so the signed bytes diverge inside
            // the first 4+min(len) bytes for ANY field values.
            let domains = [
                (&wire, "cbcl-signed-member/v1"),
                (&idkey, super::DS_IDKEY_ASSERT),
                (&rekey, super::DS_IDKEY_ROTATE),
                (&remove, crate::mls::DS_MLS_REMOVE),
            ];
            for (a, label_a) in &domains {
                assert_eq!(&a[4..4 + label_a.len()], label_a.as_bytes());
                for (b, label_b) in &domains {
                    if label_a == label_b {
                        continue;
                    }
                    let n = 4 + label_a.len().min(label_b.len());
                    assert_ne!(&a[..n], &b[..n], "{label_a} vs {label_b} must diverge");
                }
            }
        }
    }
}
