//! R5-03 wasm probe — `cbcl-mls-wasm`'s shapes + the capability/genesis surface
//! the shipped crate must gain (SPEC-013 REQ-016 affected-repo change).
//!
//! Mirrors `cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs` (Provider/Identity/Group,
//! same ciphersuite, same join/encrypt paths) and adds exactly:
//!   - `Identity::key_package_with_genesis_capability` — a KeyPackage whose leaf
//!     advertises `ExtensionType::Unknown(GENESIS_EXT_TYPE)`;
//!   - `Group::genesis` — read the `Unknown(GENESIS_EXT_TYPE)` GroupContext
//!     extension from the joined group.
//! GLUE ONLY — no cryptographic primitive implemented here.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use wasm_bindgen::prelude::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Must match the native spike's `GENESIS_EXT_TYPE` (the pinned application
/// extension type for the REQ-016 genesis assertion).
const GENESIS_EXT_TYPE: u16 = 0xF013;

fn err<E: core::fmt::Debug>(ctx: &str) -> impl Fn(E) -> String + '_ {
    move |e| format!("{ctx}: {e:?}")
}

#[wasm_bindgen]
pub struct Provider {
    inner: OpenMlsRustCrypto,
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Provider {
        Provider { inner: OpenMlsRustCrypto::default() }
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct Identity {
    signer: SignatureKeyPair,
    cwk: CredentialWithKey,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, handle: &str) -> Result<Identity, String> {
        let credential = BasicCredential::new(handle.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(err("signature keypair"))?;
        signer.store(provider.inner.storage()).map_err(err("store signer"))?;
        let cwk = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(Identity { signer, cwk })
    }

    /// A KeyPackage whose leaf capabilities advertise the genesis extension type —
    /// the shape REQ-016 obliges the web client to publish.
    pub fn key_package_with_genesis_capability(
        &self,
        provider: &Provider,
    ) -> Result<Vec<u8>, String> {
        let caps = Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(GENESIS_EXT_TYPE)]),
            None,
            None,
        );
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(caps)
            .build(CIPHERSUITE, &provider.inner, &self.signer, self.cwk.clone())
            .map_err(err("build key package"))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(err("serialize key package"))
    }
}

#[wasm_bindgen]
pub struct Group {
    inner: MlsGroup,
}

#[wasm_bindgen]
impl Group {
    /// Join from a Welcome — identical to the shipped glue's `Group::join`.
    pub fn join(provider: &Provider, welcome_bytes: &[u8]) -> Result<Group, String> {
        let msg_in =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(err("deserialize welcome"))?;
        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("expected a Welcome message".to_string()),
        };
        let cfg = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
        let inner = StagedWelcome::new_from_welcome(&provider.inner, &cfg, welcome, None)
            .map_err(err("staged welcome"))?
            .into_group(&provider.inner)
            .map_err(err("join group"))?;
        Ok(Group { inner })
    }

    /// Read the genesis bytes from the joined group's GroupContext, if present.
    pub fn genesis(&self) -> Option<Vec<u8>> {
        self.inner
            .extensions()
            .unknown(GENESIS_EXT_TYPE)
            .map(|u| u.0.clone())
    }

    /// Encrypt an application message — identical to the shipped glue.
    pub fn encrypt(
        &mut self,
        provider: &Provider,
        identity: &Identity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let out = self
            .inner
            .create_message(&provider.inner, &identity.signer, plaintext)
            .map_err(err("create message"))?;
        out.tls_serialize_detached().map_err(err("serialize message"))
    }

    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }
}
