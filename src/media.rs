//! cbcl-bus SPEC-101 attachment codec and socket-only control protocol.
//! Keys travel only in file objects (inside MLS in encrypted rooms). Storage
//! receives commitment || AES-128-GCM ciphertext || tag, never plaintext.
use crate::daemon::{AgentHandle, AgentStore, MetaReplyDelivery, MetaReplyExpectation};
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cbcl_core::sexpr::{Atom, SExpr};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, process::Stdio, time::Duration};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;

pub const MAX_STORED_BYTES: usize = 8_388_608;
pub const MAX_PLAINTEXT_BYTES: usize = MAX_STORED_BYTES - 48;
const TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "audio/wav",
    "audio/mpeg",
    "audio/ogg",
    "audio/webm",
    "audio/mp4",
];

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MediaError(pub String);
fn error(message: &str) -> MediaError {
    MediaError(message.into())
}
pub type Result<T> = std::result::Result<T, MediaError>;

// Field order is part of the browser's canonical descriptor serialization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub uri: String,
    pub size: usize,
    #[serde(rename = "type")]
    pub mime: String,
    pub encryption: Encryption,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    pub algorithm: String,
    pub key: String,
    pub iv: String,
}
// Deliberately no Debug: a descriptor contains decryption material.
impl Descriptor {
    pub fn parse(text: &str) -> Result<Self> {
        let descriptor = if text.starts_with('{') {
            let d: Self = serde_json::from_str(text).map_err(|_| error("invalid-media-ref"))?;
            if d.render()? != text {
                return Err(error("invalid-media-ref"));
            }
            d
        } else {
            // Legacy whole-field reference, still accepted by cbcl-bus.
            let fields: Vec<_> = text.split(';').collect();
            if fields.len() != 6 || fields[0] != "cbcl-media/1" {
                return Err(error("invalid-media-ref"));
            }
            let value = |i: usize, prefix: &str| {
                fields[i]
                    .strip_prefix(prefix)
                    .ok_or_else(|| error("invalid-media-ref"))
            };
            let hash = value(1, "h=")?;
            if !hex(hash, 64) {
                return Err(error("invalid-media-ref"));
            }
            let size_text = value(2, "n=")?;
            let size: usize = size_text.parse().map_err(|_| error("invalid-media-ref"))?;
            if size.to_string() != size_text {
                return Err(error("invalid-media-ref"));
            }
            Self {
                version: 2,
                uri: format!("ni:///sha-256;{}", URL_SAFE_NO_PAD.encode(unhex(hash)?)),
                size,
                mime: value(3, "t=")?.into(),
                encryption: Encryption {
                    algorithm: "AES-128-GCM".into(),
                    key: value(4, "k=")?.into(),
                    iv: value(5, "iv=")?.into(),
                },
            }
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 2
            || self.encryption.algorithm != "AES-128-GCM"
            || !TYPES.contains(&self.mime.as_str())
            || !(48..=MAX_STORED_BYTES).contains(&self.size)
        {
            return Err(error("invalid-media-ref"));
        }
        self.digest_bytes()?;
        decode_url(&self.encryption.key, 16)?;
        decode_url(&self.encryption.iv, 12)?;
        Ok(())
    }
    pub fn render(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| error("invalid-media-ref"))
    }
    fn digest_bytes(&self) -> Result<Vec<u8>> {
        decode_url(
            self.uri
                .strip_prefix("ni:///sha-256;")
                .ok_or_else(|| error("invalid-media-ref"))?,
            32,
        )
    }
    pub fn digest(&self) -> Result<String> {
        Ok(to_hex(&self.digest_bytes()?))
    }
    pub fn open(&self, stored: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        if stored.len() != self.size || Sha256::digest(stored).as_slice() != self.digest_bytes()? {
            return Err(error("media-integrity-failed: size or digest mismatch"));
        }
        let key = decode_url(&self.encryption.key, 16)?;
        if !bool::from(stored[..32].ct_eq(&commitment(&key))) {
            return Err(error("media-integrity-failed: commitment mismatch"));
        }
        let iv = decode_url(&self.encryption.iv, 12)?;
        Aes128Gcm::new_from_slice(&key)
            .map_err(|_| error("invalid-media-ref"))?
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &stored[32..],
                    aad: &aad(&self.mime, self.size),
                },
            )
            .map_err(|_| error("media-integrity-failed: authentication failed"))
    }
}
fn decode_url(text: &str, size: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| error("invalid-media-ref"))?;
    if bytes.len() != size || URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(error("invalid-media-ref"));
    }
    Ok(bytes)
}
fn commitment(key: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(b"cbcl-media/1 key-commitment");
    mac.finalize().into_bytes().to_vec()
}
fn aad(mime: &str, size: usize) -> Vec<u8> {
    format!("cbcl-media/1;t={mime};n={size}").into_bytes()
}
pub fn seal(bytes: &[u8], mime: &str) -> Result<(Descriptor, Vec<u8>)> {
    seal_with_key(bytes, mime, rand::random(), rand::random())
}
fn seal_with_key(
    bytes: &[u8],
    mime: &str,
    key: [u8; 16],
    iv: [u8; 12],
) -> Result<(Descriptor, Vec<u8>)> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(error(
            "media-too-large: encrypted files may not exceed 8 MiB",
        ));
    }
    if !TYPES.contains(&mime) {
        return Err(error("unsupported-media-type"));
    }
    let size = bytes.len() + 48;
    let mut stored = commitment(&key);
    stored.extend(
        Aes128Gcm::new_from_slice(&key)
            .expect("128-bit key")
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: bytes,
                    aad: &aad(mime, size),
                },
            )
            .map_err(|_| error("media encryption failed"))?,
    );
    Ok((
        Descriptor {
            version: 2,
            uri: format!(
                "ni:///sha-256;{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(&stored))
            ),
            size,
            mime: mime.into(),
            encryption: Encryption {
                algorithm: "AES-128-GCM".into(),
                key: URL_SAFE_NO_PAD.encode(key),
                iv: URL_SAFE_NO_PAD.encode(iv),
            },
        },
        stored,
    ))
}
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex(text: &str, n: usize) -> bool {
    text.len() == n
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| error("invalid-media-ref")))
        .collect()
}

/// Full CBCL parsing precedes field recognition; unknown/duplicate fields and
/// wrong value types are refused before a reply can complete a request.
#[derive(Debug)]
pub struct ControlReply {
    pub op: String,
    pub req: String,
    fields: BTreeMap<String, SExpr>,
}
fn string(value: &SExpr) -> Option<&str> {
    match value {
        SExpr::Atom(Atom::Str(s)) => Some(s),
        _ => None,
    }
}
fn symbol(value: &SExpr) -> Option<&str> {
    match value {
        SExpr::Atom(Atom::Symbol(s)) => Some(s),
        _ => None,
    }
}
impl ControlReply {
    pub fn parse(text: &str) -> Option<Self> {
        let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
            return None;
        };
        let op = symbol(items.first()?)?;
        if !["mediaput", "mediaurl", "mediaok", "mediano", "medianone"].contains(&op)
            || items.len() % 2 != 1
        {
            return None;
        }
        let mut fields = BTreeMap::new();
        for pair in items[1..].chunks_exact(2) {
            let SExpr::Atom(Atom::Keyword(k)) = &pair[0] else {
                return None;
            };
            if fields.insert(k.clone(), pair[1].clone()).is_some() {
                return None;
            }
        }
        let req = string(fields.get("req")?)?.to_owned();
        if !hex(&req, 16) {
            return None;
        }
        let expected: &[&str] = match op {
            "mediaput" => &["req", "upload", "url", "expires"],
            "mediaurl" => &["req", "url", "expires"],
            "mediaok" | "medianone" => &["req"],
            "mediano" => {
                let why = symbol(fields.get("why")?)?;
                if ![
                    "media-bad-request",
                    "media-off",
                    "media-forbidden",
                    "media-slow-down",
                    "media-not-joined",
                    "media-too-large",
                    "media-quota",
                    "media-room-full",
                    "media-hub-full",
                    "media-expired",
                    "media-unavailable",
                    "media-retry",
                ]
                .contains(&why)
                {
                    return None;
                }
                if why == "media-quota" {
                    &["req", "why", "retry"]
                } else {
                    &["req", "why"]
                }
            }
            _ => return None,
        };
        if fields.len() != expected.len() || !expected.iter().all(|k| fields.contains_key(*k)) {
            return None;
        }
        for key in ["expires", "retry"] {
            if let Some(v) = fields.get(key) {
                if !matches!(v,SExpr::Atom(Atom::Num(n)) if *n>=0) {
                    return None;
                }
            }
        }
        if op == "mediaput" && !hex(string(fields.get("upload")?)?, 32) {
            return None;
        }
        if let Some(v) = fields.get("url") {
            if !valid_link(string(v)?) {
                return None;
            }
        }
        Some(Self {
            op: op.into(),
            req,
            fields,
        })
    }
    pub fn text(&self, key: &str) -> Result<&str> {
        self.fields
            .get(key)
            .and_then(string)
            .ok_or_else(|| error("malformed media reply"))
    }
    fn check(&self, expected: &str) -> Result<()> {
        match self.op.as_str() {
            "mediano" => {
                let why = self
                    .fields
                    .get("why")
                    .and_then(symbol)
                    .unwrap_or("media-unavailable");
                let retry = self
                    .fields
                    .get("retry")
                    .map(|v| format!("; retry at {v}"))
                    .unwrap_or_default();
                Err(MediaError(format!("{why}{retry}")))
            }
            "medianone" => Err(error("media-unavailable")),
            op if op == expected => {
                if let Some(SExpr::Atom(Atom::Num(expires))) = self.fields.get("expires") {
                    if *expires as u64
                        <= std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    {
                        return Err(error("media link expired"));
                    }
                }
                Ok(())
            }
            _ => Err(error("unexpected media reply")),
        }
    }
}
pub fn is_control(text: &str) -> bool {
    matches!(cbcl_parser::parse(text),Ok(SExpr::List(items)) if items.first().and_then(symbol).is_some_and(|s|["mediaput","mediaurl","mediaok","mediano","medianone","mediastate"].contains(&s)))
}
fn valid_link(text: &str) -> bool {
    reqwest::Url::parse(text).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    })
}
pub async fn control(
    store: &AgentStore,
    handle: &AgentHandle,
    room: &str,
    from: &str,
    op: &str,
    fields: &str,
) -> Result<ControlReply> {
    crate::config::validate_chat_handle("room", room).map_err(|_| error("invalid media room"))?;
    crate::config::validate_chat_handle("from", from).map_err(|_| error("invalid media sender"))?;
    let req = to_hex(&rand::random::<[u8; 8]>());
    let (verb, expected) = match op {
        "upload" => ("mediaupload", "mediaput"),
        "commit" => ("mediacommit", "mediaok"),
        "get" => ("mediaget", "mediaurl"),
        _ => return Err(error("invalid media operation")),
    };
    let frame = format!("({verb} {room} :req \"{req}\" {fields} :from {from})");
    let reply = store
        .send_meta_and_await(
            handle,
            frame,
            MetaReplyExpectation::Media(req),
            Duration::from_secs(30),
        )
        .await
        .map_err(|e| MediaError(e.to_string()))?;
    let MetaReplyDelivery::Reply(text) = reply else {
        return Err(error("unexpected media reply"));
    };
    let reply = ControlReply::parse(&text).ok_or_else(|| error("malformed media reply"))?;
    reply.check(expected)?;
    Ok(reply)
}
pub(crate) fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|_| error("media HTTP unavailable"))
}
pub async fn put(client: &reqwest::Client, url: &str, stored: Vec<u8>) -> Result<()> {
    if !valid_link(url) {
        return Err(error("invalid storage link"));
    }
    let checksum = STANDARD.encode(Sha256::digest(&stored));
    let response = client
        .put(url)
        .header("content-type", "application/octet-stream")
        .header("x-amz-checksum-sha256", checksum)
        .body(stored)
        .send()
        .await
        .map_err(|_| error("media upload failed"))?;
    if !response.status().is_success() {
        return Err(error("media upload refused by storage"));
    }
    Ok(())
}
pub async fn get(client: &reqwest::Client, url: &str, size: usize) -> Result<Vec<u8>> {
    if !valid_link(url) || !(48..=MAX_STORED_BYTES).contains(&size) {
        return Err(error("invalid storage link or size"));
    }
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| error("media download failed"))?;
    if !response.status().is_success() {
        return Err(error("media download refused by storage"));
    }
    if response.content_length().is_some_and(|n| n != size as u64) {
        return Err(error("media-integrity-failed: size mismatch"));
    }
    let mut bytes = Vec::with_capacity(size);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| error("media download interrupted"))?
    {
        if chunk.len() > size - bytes.len() {
            return Err(error("media-integrity-failed: oversized body"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != size {
        return Err(error("media-integrity-failed: truncated body"));
    }
    Ok(bytes)
}

/// Browser-equivalent file contract. Presentation stays a browser concern.
pub fn file_definition() -> serde_json::Value {
    serde_json::json!({"name":"file","verbs":{"open":{"causedBy":"begin","fields":{"title":"string","ref":"string","caption":"string"}}},"project":{"title":["last","open","title"],"ref":["last","open","ref"],"caption":["last","open","caption"]}})
}

/// Inspect headers/stream metadata, without decoding or playing media. Only a
/// local private temporary file is readable by the probe; network protocols and
/// playlists are excluded by magic recognition and the protocol whitelist.
pub async fn inspect(bytes: &[u8], expected: Option<&str>) -> Result<String> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(error("media-too-large"));
    }
    let mime = sniff(bytes).ok_or_else(|| error("unsupported-media-type"))?;
    if expected.is_some_and(|t| t != mime) {
        return Err(error("media type does not match file bytes"));
    }
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|_| error("cannot create private media inspection file"))?;
    file.write_all(bytes)
        .map_err(|_| error("cannot inspect media file"))?;
    let mut child = tokio::process::Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-protocol_whitelist",
            "file",
            "-skip_frame",
            "all",
            "-max_alloc",
            "16777216",
            "-probesize",
            "8388608",
            "-analyzeduration",
            "5000000",
            "-show_entries",
            "format=format_name:stream=codec_type,codec_name,width,height:stream_disposition=attached_pic",
            "-of",
            "json",
        ])
        .arg(file.path())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| error("ffprobe is required on the daemon PATH to validate media files"))?;
    let mut stdout = child.stdout.take().expect("piped stdout").take(65_537);
    let work = async {
        let mut output = Vec::new();
        stdout
            .read_to_end(&mut output)
            .await
            .map_err(|_| error("media inspection failed"))?;
        if output.len() > 65_536 {
            return Err(error("media metadata too large"));
        }
        if !child
            .wait()
            .await
            .map_err(|_| error("media inspection failed"))?
            .success()
        {
            return Err(error("unrecognized media bytes"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output).map_err(|_| error("invalid media metadata"))?;
        let format = value["format"]["format_name"].as_str().unwrap_or_default();
        let allowed = match mime {
            "image/png" => format == "png_pipe",
            "image/jpeg" => format == "jpeg_pipe",
            "image/webp" => format == "webp_pipe",
            "image/gif" => format == "gif",
            "audio/wav" => format == "wav",
            "audio/mpeg" => format == "mp3",
            "audio/ogg" => format == "ogg",
            "audio/webm" => format.split(',').any(|name| name == "webm"),
            "audio/mp4" => format.split(',').any(|name| name == "mp4"),
            _ => false,
        };
        if !allowed {
            return Err(error("media container does not match file type"));
        }
        let streams = value["streams"]
            .as_array()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| error("no media streams"))?;
        if mime.starts_with("image/") {
            if streams.len() != 1 || streams[0]["codec_type"] != "video" {
                return Err(error("invalid image"));
            }
            let w = streams[0]["width"].as_u64().unwrap_or(0);
            let h = streams[0]["height"].as_u64().unwrap_or(0);
            if w == 0 || h == 0 || w.checked_mul(h).is_none_or(|pixels| pixels > 16_000_000) {
                return Err(error(
                    "image exceeds 16 million pixels or has invalid dimensions",
                ));
            }
        } else if !streams.iter().any(|s| s["codec_type"] == "audio")
            || streams
                .iter()
                .any(|s| s["codec_type"] != "audio" && s["disposition"]["attached_pic"] != 1)
        {
            return Err(error("audio file contains unsupported streams"));
        }
        Ok(mime.to_owned())
    };
    tokio::time::timeout(Duration::from_secs(15), work)
        .await
        .map_err(|_| error("media inspection timed out"))?
}
fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WAVE") {
        Some("audio/wav")
    } else if b.starts_with(b"ID3") || b.len() > 1 && b[0] == 255 && b[1] & 0xe0 == 0xe0 {
        Some("audio/mpeg")
    } else if b.starts_with(b"OggS") {
        Some("audio/ogg")
    } else if b.starts_with(b"\x1a\x45\xdf\xa3") && b.windows(4).take(4096).any(|w| w == b"webm") {
        Some("audio/webm")
    } else if b.get(4..8) == Some(b"ftyp") {
        Some("audio/mp4")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/vectors/media/browser.json")).unwrap()
    }
    #[test]
    fn media_browser_vector_matches_both_directions() {
        let v = vector();
        let bytes = unhex(v["plaintext"].as_str().unwrap()).unwrap();
        let key = unhex(v["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let iv = unhex(v["iv"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let (d, stored) = seal_with_key(&bytes, "image/png", key, iv).unwrap();
        assert_eq!(to_hex(&stored), v["stored"]);
        assert_eq!(d.render().unwrap(), v["reference"]);
        assert_eq!(d.open(&stored).unwrap(), bytes);
        let legacy = Descriptor::parse(v["legacyReference"].as_str().unwrap()).unwrap();
        assert_eq!(legacy.render().unwrap(), d.render().unwrap());
    }
    #[test]
    fn media_integrity_rejects_each_independent_tamper() {
        let (d, stored) = seal(b"test bytes", "audio/wav").unwrap();
        let mut changed = stored.clone();
        changed[40] ^= 1;
        assert!(d.open(&changed).is_err());
        let mut wrong = d.clone();
        wrong.size += 1;
        assert!(wrong.open(&stored).is_err());
        let mut wrong = d.clone();
        wrong.encryption.key = URL_SAFE_NO_PAD.encode([1; 16]);
        assert!(wrong.open(&stored).unwrap_err().0.contains("commitment"));
        let mut wrong = d.clone();
        wrong.encryption.iv = URL_SAFE_NO_PAD.encode([1; 12]);
        assert!(wrong.open(&stored).is_err());
        let mut wrong = d.clone();
        wrong.mime = "image/png".into();
        assert!(wrong.open(&stored).is_err());
        let mut wrong = d.clone();
        wrong.uri = format!(
            "ni:///sha-256;{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(&changed))
        );
        assert!(
            wrong
                .open(&changed)
                .unwrap_err()
                .0
                .contains("authentication")
        );
        assert_ne!(seal(b"test bytes", "audio/wav").unwrap().0.uri, d.uri);
    }
    #[test]
    fn media_reference_recognizer_is_whole_field_and_canonical() {
        let v = vector();
        let text = v["reference"].as_str().unwrap();
        for bad in [
            format!(" {text}"),
            format!("{text}\n"),
            text.replace("\"version\":2", "\"version\":2,\"version\":2"),
            text.replace("\"version\":2", "\"version\":2,\"extra\":1"),
            text.replace("image/png", "text/html"),
            text.replace("\"size\":68", "\"size\":8388609"),
            text.replace("\"size\":68", "\"size\":68.0"),
            text.replace("AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0ODx"),
        ] {
            assert!(Descriptor::parse(&bad).is_err(), "{bad}");
        }
        let legacy = v["legacyReference"].as_str().unwrap();
        assert!(Descriptor::parse(&format!("{legacy}\n")).is_err());
        assert!(seal(&vec![0; MAX_PLAINTEXT_BYTES + 1], "image/png").is_err());
        assert!(seal(&[], "application/pdf").is_err());
    }
    #[test]
    fn media_control_recognition_refuses_duplicates_and_unsafe_links() {
        let req = "0123456789abcdef";
        let good = format!(
            "(mediaurl :req \"{req}\" :url \"https://storage.example/a\" :expires 2000000000)"
        );
        assert!(ControlReply::parse(&good).is_some());
        for bad in [
            good.replace("https:", "http:"),
            good.replace("storage.example", "user:pass@storage.example"),
            good.replace("/a\"", "/a#fragment\""),
            good.replace("2000000000", "\"2000000000\""),
            good.replace(":url", ":req \"0123456789abcdef\" :url"),
            good.replace(":expires", ":extra 1 :expires"),
        ] {
            assert!(ControlReply::parse(&bad).is_none(), "{bad}")
        }
        assert!(
            ControlReply::parse("(mediano :req \"0123456789abcdef\" :why media-off)")
                .unwrap()
                .check("mediaurl")
                .unwrap_err()
                .0
                .contains("media-off")
        );
        assert!(
            ControlReply::parse("(medianone :req \"0123456789abcdef\")")
                .unwrap()
                .check("mediaurl")
                .is_err()
        );
        assert!(
            ControlReply::parse("(mediano :req \"0123456789abcdef\" :why media-quota)").is_none()
        );
        assert!(
            ControlReply::parse("(mediaok :req \"0123456789abcdef\")")
                .unwrap()
                .check("mediaput")
                .is_err()
        );
    }
    pub fn wav() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(b"RIFF");
        b.extend(196u32.to_le_bytes());
        b.extend(b"WAVEfmt ");
        b.extend(16u32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(8000u32.to_le_bytes());
        b.extend(16000u32.to_le_bytes());
        b.extend(2u16.to_le_bytes());
        b.extend(16u16.to_le_bytes());
        b.extend(b"data");
        b.extend(160u32.to_le_bytes());
        b.extend([0; 160]);
        b
    }
    #[tokio::test]
    async fn media_metadata_validates_bytes_without_decoding() {
        assert_eq!(inspect(&wav(), None).await.unwrap(), "audio/wav");
        for (bytes, mime) in [
            (
                include_bytes!("../tests/vectors/media/sample.png").as_slice(),
                "image/png",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.jpg").as_slice(),
                "image/jpeg",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.webp").as_slice(),
                "image/webp",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.gif").as_slice(),
                "image/gif",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.wav").as_slice(),
                "audio/wav",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.mp3").as_slice(),
                "audio/mpeg",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.ogg").as_slice(),
                "audio/ogg",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.webm").as_slice(),
                "audio/webm",
            ),
            (
                include_bytes!("../tests/vectors/media/sample.m4a").as_slice(),
                "audio/mp4",
            ),
        ] {
            assert_eq!(inspect(bytes, Some(mime)).await.unwrap(), mime);
        }

        assert!(inspect(&wav(), Some("image/png")).await.is_err());
        assert!(inspect(b"<svg></svg>", None).await.is_err());
        assert!(inspect(b"RIFF1234WAVEbad", None).await.is_err());
    }
    #[test]
    fn media_browser_webcrypto_opens_native_and_native_opens_browser() {
        // Pinned, unmodified cbcl-bus browser codec; no sibling checkout needed.
        let (d, stored) = seal(b"bidirectional media", "audio/ogg").unwrap();
        let script = r#"import {openMedia,sealMedia} from './tests/vectors/media/media-ref.mjs';
            const d=process.argv[1],s=Buffer.from(process.argv[2],'hex');
            const p=await openMedia(d,s);
            const sealed=await sealMedia(p,'audio/ogg');
            process.stdout.write(JSON.stringify({plaintext:Buffer.from(p).toString('hex'),reference:sealed.reference,stored:Buffer.from(sealed.stored).toString('hex')}));"#;
        let result = std::process::Command::new("node")
            .args([
                "--input-type=module",
                "-e",
                script,
                &d.render().unwrap(),
                &to_hex(&stored),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Node is required for the browser interoperability test");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(v["plaintext"], to_hex(b"bidirectional media"));
        let d = Descriptor::parse(v["reference"].as_str().unwrap()).unwrap();
        assert_eq!(
            d.open(&unhex(v["stored"].as_str().unwrap()).unwrap())
                .unwrap(),
            b"bidirectional media"
        );
    }
}
