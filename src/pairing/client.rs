//! The `hark pair` WebSocket transport: connect to the hub's `/pair/v1`,
//! run the 4-frame SPAKE2 handshake, and return the released record. The
//! crypto is in [`super::spake2`]; this module owns the wire (JSON frames,
//! base64 payloads) and the orchestration.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;

use super::record::PairingRecord;
use super::spake2::{Context, Initiator};
use super::{PairError, PairingCode, open_record};

/// The pairing WS path (sibling to `/chat/v1`).
pub const PAIR_WS_PATH: &str = "/pair/v1";

#[derive(Debug, thiserror::Error)]
pub enum PairClientError {
    #[error(transparent)]
    Pair(#[from] PairError),
    #[error("could not derive a /pair/v1 URL from {0}")]
    BadHubUrl(String),
    #[error("pairing connection failed: {0}")]
    ConnectionFailed(String),
    #[error("the hub closed the connection before completing the pairing")]
    ClosedEarly,
    #[error("unexpected pairing frame: expected {expected}, got {got}")]
    UnexpectedFrame { expected: String, got: String },
    #[error("the hub rejected the pairing: {code} ({message})")]
    HubError { code: String, message: String },
    #[error("malformed pairing frame: {0}")]
    MalformedFrame(String),
}

/// Derive the `/pair/v1` URL from a configured chat hub URL (e.g. `…/chat/v1`).
/// The pairing endpoint is a sibling of the chat endpoint on the same host, so
/// the path is replaced wholesale; a URL already pointing at `/pair/v1` is
/// returned unchanged.
pub fn pair_url_from(ws_url: &str) -> Result<Url, PairClientError> {
    let mut url = Url::parse(ws_url).map_err(|_| PairClientError::BadHubUrl(ws_url.to_owned()))?;
    url.set_path(PAIR_WS_PATH);
    Ok(url)
}

// ---- wire frames ----------------------------------------------------------

#[derive(Serialize)]
struct PairInit<'a> {
    r#type: &'a str,
    pairing_id: &'a str,
    msg_a: String,
}

#[derive(Serialize)]
struct PairConfirm<'a> {
    r#type: &'a str,
    mac_a: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ServerFrame {
    #[serde(rename = "pair_resp")]
    PairResp { msg_b: String },
    #[serde(rename = "pair_release")]
    PairRelease { mac_b: String, ciphertext: String },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

fn b64d(s: &str, field: &str) -> Result<Vec<u8>, PairClientError> {
    B64.decode(s)
        .map_err(|_| PairClientError::MalformedFrame(format!("{field} is not valid base64")))
}

/// Run the full pairing handshake against `pair_url` for `code`, returning the
/// hub-released record. The four BIP39 words are the PAKE secret and never
/// leave this process; only the public `pairing_id` is sent.
pub async fn run_pairing(
    pair_url: &Url,
    code: &PairingCode,
) -> Result<PairingRecord, PairClientError> {
    let mut ephemeral = [0u8; 64];
    rand::rng().fill_bytes(&mut ephemeral);
    run_pairing_with_ephemeral(pair_url, code, &ephemeral).await
}

/// As [`run_pairing`], but with a caller-supplied ephemeral — for deterministic
/// tests against the known-answer vectors. Production uses [`run_pairing`].
pub async fn run_pairing_with_ephemeral(
    pair_url: &Url,
    code: &PairingCode,
    ephemeral: &[u8; 64],
) -> Result<PairingRecord, PairClientError> {
    let wib = super::bip39::phrase_to_wib(&code.words).map_err(PairError::from)?;

    let (mut ws, _resp) = connect_async(pair_url.as_str())
        .await
        .map_err(|e| PairClientError::ConnectionFailed(e.to_string()))?;

    // idA = pairing_id binds the transcript to this record; hub_id is the
    // canonical chat hub id the responder uses.
    let mut agent = Initiator::start(
        Context::pairing(),
        &wib,
        code.pairing_id.as_bytes(),
        b"cbcl-chat",
        ephemeral,
    );

    // Frame 1 → pair_init
    send_json(
        &mut ws,
        &PairInit {
            r#type: "pair_init",
            pairing_id: &code.pairing_id,
            msg_a: B64.encode(agent.msg_a()),
        },
    )
    .await?;

    // Frame 2 ← pair_resp
    let msg_b = match recv_frame(&mut ws).await? {
        ServerFrame::PairResp { msg_b } => b64d(&msg_b, "msg_b")?,
        ServerFrame::Error { code, message } => {
            return Err(PairClientError::HubError { code, message });
        }
        ServerFrame::PairRelease { .. } => {
            return Err(PairClientError::UnexpectedFrame {
                expected: "pair_resp".into(),
                got: "pair_release".into(),
            });
        }
    };
    let mac_a = agent.step1(&msg_b).map_err(PairError::from)?;

    // Frame 3 → pair_confirm
    send_json(
        &mut ws,
        &PairConfirm {
            r#type: "pair_confirm",
            mac_a: B64.encode(mac_a),
        },
    )
    .await?;

    // Frame 4 ← pair_release
    let (mac_b, ciphertext) = match recv_frame(&mut ws).await? {
        ServerFrame::PairRelease { mac_b, ciphertext } => {
            (b64d(&mac_b, "mac_b")?, b64d(&ciphertext, "ciphertext")?)
        }
        ServerFrame::Error { code, message } => {
            return Err(PairClientError::HubError { code, message });
        }
        ServerFrame::PairResp { .. } => {
            return Err(PairClientError::UnexpectedFrame {
                expected: "pair_release".into(),
                got: "pair_resp".into(),
            });
        }
    };

    // Authenticate the hub, then decrypt the record bound to K.
    agent.verify_hub(&mac_b).map_err(PairError::from)?;
    let key = agent.session_key().expect("session key after verify_hub");
    let record = open_record(&key, &ciphertext)?;
    let _ = ws.close(None).await;
    Ok(record)
}

async fn send_json<T: Serialize>(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    frame: &T,
) -> Result<(), PairClientError> {
    let text = serde_json::to_string(frame).expect("frame serializes");
    ws.send(WsMessage::Text(text.into()))
        .await
        .map_err(|e| PairClientError::ConnectionFailed(e.to_string()))
}

async fn recv_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<ServerFrame, PairClientError> {
    loop {
        match ws.next().await {
            None => return Err(PairClientError::ClosedEarly),
            Some(Err(e)) => return Err(PairClientError::ConnectionFailed(e.to_string())),
            Some(Ok(WsMessage::Text(text))) => {
                return serde_json::from_str(&text)
                    .map_err(|e| PairClientError::MalformedFrame(e.to_string()));
            }
            Some(Ok(WsMessage::Binary(bytes))) => {
                return serde_json::from_slice(&bytes)
                    .map_err(|e| PairClientError::MalformedFrame(e.to_string()));
            }
            Some(Ok(WsMessage::Close(_))) => return Err(PairClientError::ClosedEarly),
            Some(Ok(_)) => continue, // ping/pong/etc.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_pair_url_from_chat_url() {
        let u = pair_url_from("wss://cbcl-bus.fly.dev/chat/v1").unwrap();
        assert_eq!(u.as_str(), "wss://cbcl-bus.fly.dev/pair/v1");

        // already a pair url
        let u = pair_url_from("ws://127.0.0.1:9/pair/v1").unwrap();
        assert_eq!(u.path(), "/pair/v1");
    }
}
