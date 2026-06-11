//! Native cbcl-chat transport (SPEC-003 CON-001, IMPL-003 Phase 1/2).
//!
//! A sibling to [`crate::router`] that connects an agent to cbcl-chat's
//! `/chat/v1` WebSocket as an ordinary signed member: it sends an
//! Ed25519-signed `hello` to join a channel, then bridges the socket to the
//! daemon's inbound queue and outbound send channel, exactly as the router
//! transport does. Outbound frames are signed + length-framed (validated CBCL text)
//! (the cbcl-chat frame format); inbound frames have their payload extracted
//! and enqueued (the hub already verified the signer, so we trust delivered
//! frames, like the browser does).
//!
//! V1 scope: membership + recv/reply. The capability filter (answer only
//! learned dialects) and the claim round + RendezvousHash selection
//! (`crate::selector`) layer on top of this loop (IMPL-003 §3); they are
//! additive and do not change the connect/frame path proven here.

use std::sync::Arc;
use std::time::Duration;

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::sexpr::{Atom, SExpr};
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;

use crate::chat_frame::decode_payload;
use crate::chat_responder::{Action, Responder, WindowOutcome};
use crate::daemon::{AgentHandle, AgentSendChannel, AgentStore};
use crate::identity::ChatIdentity;
use crate::signed_transport::{SignedConn, parse_conn_bootstrap};

pub const CHAT_WS_PATH: &str = "/chat/v1";

/// How long to wait for the hub's join acknowledgement (`roomcfg`/`presence`)
/// or rejection (`error`) after sending the signed `hello`, before giving up.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The negotiated WebSocket stream type for a `/chat/v1` connection.
type ChatSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("chat connection failed: {0}")]
    ConnectionFailed(String),
    #[error("failed to build hello: {0}")]
    Hello(String),
    #[error("failed to send hello: {0}")]
    HelloSendFailed(String),
    #[error("hub rejected the join: {0}")]
    JoinRejected(String),
    #[error("hub did not acknowledge the join within {0:?}")]
    JoinTimeout(Duration),
    #[error("agent store rejected the connection: {0}")]
    Store(String),
    /// REQ-008 (SPEC-016): the operator chose a dialect the channel does not
    /// declare. Carries the declared names so the error can show the menu.
    #[error("dialect {dialect} is not declared by the channel")]
    UndeclaredDialect {
        dialect: String,
        declared: Vec<String>,
    },
}

/// One entry of a channel's declared-dialect menu (SPEC-015 CON-001):
/// a `(name, digest-hex)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDialect {
    pub name: String,
    pub digest: String,
}

/// The hub's join acknowledgement (`roomcfg`), parsed. `declared: None` means
/// the hub conveyed no `:dialects` menu (a legacy hub) — distinct from
/// `Some([])`, a channel that declares an empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomCfg {
    pub enc: bool,
    pub declared: Option<Vec<DeclaredDialect>>,
}

impl RoomCfg {
    fn absent() -> Self {
        Self {
            enc: false,
            declared: None,
        }
    }
}

/// Parse a `roomcfg` frame per SPEC-015 CON-001:
/// `(roomcfg @room :enc true|false :dialects ((<name> <digest-hex>) …))`.
/// Returns `None` for any other frame.
fn parse_roomcfg(text: &str) -> Option<RoomCfg> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(symbol)) if symbol == "roomcfg" => {}
        _ => return None,
    }

    let mut cfg = RoomCfg::absent();
    let mut index = 1;
    while index < items.len() {
        let SExpr::Atom(Atom::Keyword(keyword)) = &items[index] else {
            index += 1;
            continue;
        };
        let value = items.get(index + 1);
        match (keyword.as_str(), value) {
            ("enc", Some(SExpr::Atom(Atom::Bool(enc)))) => cfg.enc = *enc,
            ("enc", Some(SExpr::Atom(Atom::Symbol(word)))) => cfg.enc = word == "true",
            ("dialects", Some(SExpr::List(entries))) => {
                let mut declared = Vec::new();
                for entry in entries {
                    let SExpr::List(pair) = entry else { continue };
                    let (Some(name), Some(digest)) =
                        (atom_text(pair.first()), atom_text(pair.get(1)))
                    else {
                        continue;
                    };
                    declared.push(DeclaredDialect { name, digest });
                }
                cfg.declared = Some(declared);
            }
            _ => {}
        }
        index += 2;
    }
    Some(cfg)
}

/// The textual value of a string or symbol atom, if `expr` is one.
fn atom_text(expr: Option<&SExpr>) -> Option<String> {
    match expr {
        Some(SExpr::Atom(Atom::Str(text))) | Some(SExpr::Atom(Atom::Symbol(text))) => {
            Some(text.clone())
        }
        _ => None,
    }
}

/// The exact payload bytes to sign and transmit. We validate that `text`
/// parses as CBCL, then sign and send it **verbatim**: the hub verifies the
/// signature over the bytes as received (SPEC-001 CON-006) and parses them, so
/// the bytes signed MUST equal the bytes sent. We do not pre-canonicalise —
/// the hub accepts any well-formed CBCL and canonicalises server-side. (Note:
/// `cbcl_core::canonical_encode` is a binary *content-addressing* form, not the
/// wire text, so it must not be used here.)
fn payload_bytes(text: &str) -> Result<Vec<u8>, String> {
    cbcl_parser::parse(text).map_err(|error| error.to_string())?;
    Ok(text.as_bytes().to_vec())
}

/// The ` :cap "<token>"` clause for a private-channel join, or empty for a
/// public channel. A blank/whitespace cap is treated as absent. Embedded quotes
/// are stripped (caps are opaque tokens, not free text) so the hello stays
/// well-formed CBCL — mirrors the browser client's `cap.replace(/"/g, '')`.
fn cap_part(cap: Option<&str>) -> String {
    match cap.map(str::trim).filter(|token| !token.is_empty()) {
        Some(token) => format!(" :cap \"{}\"", token.replace('"', "")),
        None => String::new(),
    }
}

/// Connect to `/chat/v1`, join `channel` as `agent_handle` with a signed
/// `hello`, and spawn the receive loop. Returns the store handle for the
/// connection (used by `recv`/`reply`).
///
/// `cap` is the capability presented for a *private* channel: the channel's
/// standing cap or a bounded invite token (the hub's `allow-join?` /
/// `join-allowed?`, SPEC-001). Public channels ignore it; pass `None` to enter
/// a public channel.
#[allow(clippy::too_many_arguments)]
pub async fn create_chat_agent(
    store: AgentStore,
    ws_url: &Url,
    channel: &str,
    agent_handle: &str,
    dialects: Vec<String>,
    cap: Option<String>,
    added_by: Option<String>,
    claim_window: Duration,
    liveness_timeout: Duration,
    identity: Arc<ChatIdentity>,
) -> Result<(AgentHandle, Vec<String>), ChatError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| ChatError::Store(error.to_string()))?;
    let (mut websocket, _response) = connect_async(ws_url.as_str())
        .await
        .map_err(|error| ChatError::ConnectionFailed(error.to_string()))?;

    // SPEC-012 signed-member connect: capture the hub's conn-nonce bootstrap into
    // a per-connection signer, then sign the hello (and every later frame) over
    // the domain-separated envelope. The chat audience is the recipient handle
    // (@-kept), derived per frame by sign_chat_frame.
    let mut conn = recv_bootstrap(&mut websocket).await?;
    let hello = format!(
        "(hello {channel} :from {agent_handle} :key \"{}\"{})",
        identity.public_key_b64(),
        cap_part(cap.as_deref()),
    );
    let payload = payload_bytes(&hello).map_err(ChatError::Hello)?;
    let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
    websocket
        .send(WsMessage::Binary(frame.into()))
        .await
        .map_err(|error| ChatError::HelloSendFailed(error.to_string()))?;

    // Block until the hub acknowledges the join (`roomcfg`) or rejects it
    // (`error @room "slug"`). The hub keeps the socket open on rejection
    // (bad-signature / no-such-channel / forbidden-room), so returning Ok before
    // this would hand back a "joined" handle the agent is not actually a member
    // of. On rejection or timeout the websocket drops here, before any store
    // entry exists — nothing to mark unhealthy or clean up.
    let (roomcfg, learned_hub) = await_join_ack(&mut websocket).await?;

    // REQ-008 (SPEC-016): the advertised set must be a subset of the channel's
    // declared menu when one is conveyed. A hub that conveys no menu (today's
    // cbcl-bus) soft-passes with an explicit warning — never silently.
    let mut warnings = Vec::new();
    match &roomcfg.declared {
        None => warnings.push(format!(
            "channel {channel} declares no dialect menu (legacy hub); --speak validation skipped"
        )),
        Some(menu) => {
            for dialect in &dialects {
                if !menu.iter().any(|entry| entry.name == *dialect) {
                    return Err(ChatError::UndeclaredDialect {
                        dialect: dialect.clone(),
                        declared: menu.iter().map(|entry| entry.name.clone()).collect(),
                    });
                }
            }
            // REQ-005 acquisition-by-digest: blocked on the hub's
            // fetch-by-digest endpoint (SPEC-015 REQ-005, not yet served by
            // cbcl-bus). Until it lands, chosen dialects are advertised with
            // base-level validation and the gap is surfaced, not hidden.
            if !dialects.is_empty() {
                warnings.push(format!(
                    "definitions for {} cannot be acquired by digest yet (hub fetch pending); \
                     advertising with base validation",
                    dialects.join(", ")
                ));
            }
        }
    }

    // REQ-006 (SPEC-016): announce ourselves so chat clients render this
    // member as an agent (the agent treatment is *earned* by the announce
    // performative, not inferable from the handle). Sent once, right after
    // the join ack — a failure here is a failed join, not a silent
    // plain-member fallback.
    let announce = build_announce_frame(channel, agent_handle, &dialects, added_by.as_deref());
    // Enforce the announce is valid CBCL against the hub dialect the hub *taught*
    // us via its `(meta (define hub …))` advertisement — a real conformance check
    // against the grammar the peer actually declared, catching a malformed
    // announce locally before it reaches the wire. A legacy hub that teaches no
    // dialect degrades to a surfaced warning rather than a faked pass.
    match &learned_hub {
        HubTeaching::Learned(registry) => {
            let mut store = cbcl_core::store::ThreadedMessageStore::new();
            crate::cbcl_validation::validate_for_emit(&announce, registry, &mut store).map_err(
                |error| ChatError::Hello(format!("announce is not valid CBCL: {error}")),
            )?;
        }
        HubTeaching::None => warnings.push(format!(
            "hub {channel} taught no control dialect (legacy hub); \
             announce emitted without local CBCL self-validation"
        )),
        HubTeaching::Malformed(error) => warnings.push(format!(
            "hub {channel} taught a control dialect hark could not learn ({error}); \
             announce emitted without local CBCL self-validation"
        )),
    }
    let announce_payload = payload_bytes(&announce).map_err(ChatError::Hello)?;
    let announce_frame = conn.sign_chat_frame(identity.as_ref(), &announce_payload);
    websocket
        .send(WsMessage::Binary(announce_frame.into()))
        .await
        .map_err(|error| ChatError::ConnectionFailed(error.to_string()))?;

    let handle = AgentHandle::generate();
    let (close_tx, close_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    // The advertised dialects are both the store's record and the responder's
    // capability set (SPEC-003 REQ-002).
    let capability = dialects.clone();
    store
        .insert_connected_with_router_channels(
            handle.clone(),
            dialects,
            Some(close_tx),
            Some(AgentSendChannel::new(send_tx)),
            Some(agent_handle.to_owned()), // the chat wire identity (@handle)
            Some(channel.to_owned()),
        )
        .await
        .map_err(|error| ChatError::Store(error.to_string()))?;

    let responder = Responder::new(
        agent_handle.to_owned(),
        channel.to_owned(),
        capability,
        roomcfg
            .declared
            .as_ref()
            .map(|menu| menu.iter().map(|entry| entry.name.clone()).collect()),
    );
    spawn_receive_loop(ReceiveLoopArgs {
        store,
        handle: handle.clone(),
        websocket,
        close_rx,
        send_rx,
        identity,
        responder,
        claim_window,
        liveness_timeout,
        conn,
    });

    Ok((handle, warnings))
}

/// The agent's `announce` frame (SPEC-016 REQ-006): addressed to the channel
/// (the first `@`-token is the signing audience), carrying the agent handle
/// and its advertised dialects. When the agent was paired in, it also carries
/// `:added-by` so every client can show the provenance (REQ-010). Chat clients
/// key the agent rendering off this performative.
fn build_announce_frame(
    channel: &str,
    agent_handle: &str,
    dialects: &[String],
    added_by: Option<&str>,
) -> String {
    let list = dialects
        .iter()
        .map(|dialect| format!("\"{}\"", dialect.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    let added = added_by
        .map(|adder| format!(" :added-by {adder}"))
        .unwrap_or_default();
    // `:from` identifies the signed-member sender — the hub's dispatch requires
    // it (and verifies the frame signature against it) or the frame is rejected
    // as `missing-from` and never fanned. `:agent` is what chat clients key the
    // agent rendering off; both are the agent's own handle.
    format!(
        "(announce {channel} :from {agent_handle} :agent {agent_handle} :dialects ({list}){added})"
    )
}

/// Receive + parse the chat hub's conn-nonce bootstrap (its first frame:
/// `(tell @client "conn-nonce" …)`), yielding a `SignedConn`.
async fn recv_bootstrap(ws: &mut ChatSocket) -> Result<SignedConn, ChatError> {
    // A hub that accepts the upgrade then stalls must not hang create_chat_agent.
    let msg = match tokio::time::timeout(JOIN_TIMEOUT, ws.next()).await {
        Err(_) => {
            return Err(ChatError::ConnectionFailed(
                "timed out waiting for the conn-nonce bootstrap".into(),
            ));
        }
        Ok(None) => {
            return Err(ChatError::ConnectionFailed(
                "closed before conn-nonce bootstrap".into(),
            ));
        }
        Ok(Some(Err(error))) => return Err(ChatError::ConnectionFailed(error.to_string())),
        Ok(Some(Ok(msg))) => msg,
    };
    // The chat hub bare-frames its hub->client frames (len ‖ payload ‖ sig), so
    // strip the framing before reading the payload text (unlike the router, whose
    // hub->agent frames are raw payload bytes).
    let payload = match &msg {
        WsMessage::Binary(bytes) => decode_payload(bytes).ok_or_else(|| {
            ChatError::ConnectionFailed("malformed conn-nonce bootstrap frame".into())
        })?,
        WsMessage::Text(text) => text.as_bytes(),
        other => {
            return Err(ChatError::ConnectionFailed(format!(
                "unexpected first frame (expected conn-nonce bootstrap): {other:?}"
            )));
        }
    };
    let text = String::from_utf8_lossy(payload).into_owned();
    parse_conn_bootstrap(&text)
        .map(|boot| SignedConn::from_bootstrap(&boot))
        .ok_or_else(|| {
            ChatError::ConnectionFailed(format!(
                "first frame was not a conn-nonce bootstrap: {text}"
            ))
        })
}

struct ReceiveLoopArgs {
    store: AgentStore,
    handle: AgentHandle,
    websocket: ChatSocket,
    close_rx: oneshot::Receiver<()>,
    send_rx: mpsc::Receiver<crate::daemon::OutboundFrame>,
    identity: Arc<ChatIdentity>,
    responder: Responder,
    claim_window: Duration,
    liveness_timeout: Duration,
    /// Per-connection signer (conn_nonce + hub_id + seq) for every outbound frame.
    conn: SignedConn,
}

/// A scheduled responder timer fired by the receive loop (SPEC-003 REQ-005/007).
enum ClaimTimer {
    /// The Δ claim window for `ask_id` has closed — elect a winner.
    Window(String),
    /// The liveness fallback for `ask_id` is due — take over if still unanswered.
    Fallback(String),
}

/// What the hub taught about its control dialect during the join handshake.
enum HubTeaching {
    /// No `(meta …)` advertisement arrived before the verdict.
    None,
    /// The advertisement parsed and installed.
    Learned(DialectRegistry),
    /// An advertisement arrived but could not be learned (why, for the operator).
    Malformed(String),
}

/// Wait for the hub's verdict on a freshly sent `hello`. A successful join leads
/// with a `roomcfg` frame (then backfill + a `presence` broadcast); a rejected
/// one is a single `(error @room "slug")` with the socket left open. We consume
/// only the acknowledging frame and leave any backfill/presence for the receive
/// loop to enqueue.
///
/// Ordering contract: the hub teaches its control dialect BEFORE the verdict —
/// `cbcl-chat-room:join` builds the reply as `[meta, roomcfg | backfill]`, and
/// cbcl-bus pins that order in `join-leads-with-the-hub-dialect-meta`. A hub
/// that only teaches after its verdict is indistinguishable from one that
/// teaches nothing: we return on the verdict, and the agent degrades to the
/// "taught no control dialect" warning rather than waiting on a frame that may
/// never come.
async fn await_join_ack(websocket: &mut ChatSocket) -> Result<(RoomCfg, HubTeaching), ChatError> {
    let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
    // The hub leads the join with a `(meta (define hub …))` advertising its
    // control dialect (SPEC-016): we learn it here, before the verdict, so the
    // agent can validate its own control-plane frames against the grammar the
    // hub actually declared — no baked copy.
    let mut learned_hub = HubTeaching::None;
    loop {
        let message = match tokio::time::timeout_at(deadline, websocket.next()).await {
            Err(_elapsed) => return Err(ChatError::JoinTimeout(JOIN_TIMEOUT)),
            Ok(None) => {
                return Err(ChatError::ConnectionFailed(
                    "hub closed the connection before acknowledging the join".to_owned(),
                ));
            }
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(error))) => {
                return Err(ChatError::ConnectionFailed(sanitize(&error.to_string())));
            }
        };
        let text = match message {
            WsMessage::Binary(bytes) => match decode_payload(&bytes) {
                Some(payload) => String::from_utf8_lossy(payload).into_owned(),
                None => continue, // malformed frame: ignore, keep waiting for the verdict
            },
            WsMessage::Text(text) => text.to_string(),
            WsMessage::Close(frame) => {
                let detail = frame
                    .map(|f| format!("code={:?} reason=\"{}\"", f.code, f.reason))
                    .unwrap_or_else(|| "no close frame".to_owned());
                return Err(ChatError::ConnectionFailed(format!(
                    "hub closed during join: {}",
                    sanitize(&detail)
                )));
            }
            _ => continue, // ping/pong/etc.
        };
        match frame_performative(&text).as_deref() {
            // A roomcfg carries the channel's config (enc + declared dialect
            // menu, SPEC-015 CON-001); a presence-first ack conveys neither.
            Some("roomcfg") => {
                let roomcfg = parse_roomcfg(&text).unwrap_or_else(RoomCfg::absent);
                return Ok((roomcfg, learned_hub));
            }
            Some("presence") => return Ok((RoomCfg::absent(), learned_hub)),
            Some("error") => {
                return Err(ChatError::JoinRejected(
                    error_slug(&text).unwrap_or_else(|| "unknown".to_owned()),
                ));
            }
            // The hub's control-dialect advertisement: learn it (the language's
            // native `(meta (define …))` path) and keep waiting for the verdict.
            // A malformed advertisement is non-fatal — the join still proceeds;
            // the announce self-check degrades to a surfaced warning carrying
            // the learn error, so a teaching-but-broken hub is distinguishable
            // from a legacy hub that teaches nothing.
            Some("meta") => {
                match crate::hub_dialect::learn_hub_dialect(&text) {
                    Ok(registry) => learned_hub = HubTeaching::Learned(registry),
                    Err(error) => {
                        tracing::warn!("could not learn the hub dialect: {error}");
                        learned_hub = HubTeaching::Malformed(error.to_string());
                    }
                }
                continue;
            }
            // Any other frame (e.g. backfill arriving before the leading roomcfg
            // on some hub ordering) is not a verdict — keep waiting.
            _ => continue,
        }
    }
}

/// The performative (head symbol) of a CBCL frame, if it parses as a list led by
/// a symbol. Classifies hub control frames without fragile substring matching:
/// `(error @x "...")` → `error`, never a `(tell @x "error")` body.
fn frame_performative(text: &str) -> Option<String> {
    match cbcl_parser::parse(text).ok()? {
        SExpr::List(items) => match items.first()? {
            SExpr::Atom(Atom::Symbol(symbol)) => Some(symbol.clone()),
            _ => None,
        },
        SExpr::Atom(_) => None,
    }
}

/// The slug from an `(error @room "slug")` frame. Returns `None` if `text` is not
/// an error frame; the slug is the frame's string atom.
fn error_slug(text: &str) -> Option<String> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(symbol)) if symbol == "error" => {}
        _ => return None,
    }
    items.iter().find_map(|item| match item {
        SExpr::Atom(Atom::Str(slug)) => Some(slug.clone()),
        _ => None,
    })
}

fn spawn_receive_loop(args: ReceiveLoopArgs) {
    let ReceiveLoopArgs {
        store,
        handle,
        mut websocket,
        mut close_rx,
        mut send_rx,
        identity,
        mut responder,
        claim_window,
        liveness_timeout,
        mut conn,
    } = args;
    tokio::spawn(async move {
        // Pending Δ-window and liveness-fallback timers, fired into the select.
        let mut timers: FuturesUnordered<BoxFuture<'static, ClaimTimer>> = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = &mut close_rx => {
                    let _ = websocket.close(None).await;
                    break;
                }
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        let _ = store.mark_unhealthy(&handle, "local_send_failed", Some("chat send channel closed".to_owned())).await;
                        break;
                    };
                    // Validate + sign + frame on the way out.
                    let payload = match payload_bytes(&outbound.message) {
                        Ok(payload) => payload,
                        Err(error) => {
                            let _ = outbound.result_tx.send(Err(format!("outbound not valid CBCL: {error}")));
                            continue;
                        }
                    };
                    let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
                    match websocket.send(WsMessage::Binary(frame.into())).await {
                        Ok(()) => { let _ = outbound.result_tx.send(Ok(())); }
                        Err(error) => {
                            let detail = sanitize(&error.to_string());
                            let _ = outbound.result_tx.send(Err(detail.clone()));
                            let _ = store.mark_unhealthy(&handle, "local_send_failed", Some(detail)).await;
                            break;
                        }
                    }
                }
                // A responder timer fired (guarded so an empty set does not busy-loop).
                maybe_timer = timers.next(), if !timers.is_empty() => {
                    let Some(timer) = maybe_timer else { continue };
                    match timer {
                        ClaimTimer::Window(ask_id) => match responder.on_window_closed(&ask_id) {
                            WindowOutcome::Win(payload) => {
                                if store.enqueue_inbound(&handle, payload).await.is_err() { break; }
                            }
                            WindowOutcome::Hold { rank } => {
                                // Rank-k waits k liveness periods; if no reply is seen
                                // it takes over (REQ-007).
                                let delay = liveness_timeout.saturating_mul(rank as u32);
                                timers.push(async move {
                                    tokio::time::sleep(delay).await;
                                    ClaimTimer::Fallback(ask_id)
                                }.boxed());
                            }
                            WindowOutcome::Idle => {}
                        },
                        ClaimTimer::Fallback(ask_id) => {
                            if let Some(payload) = responder.on_fallback(&ask_id) {
                                if store.enqueue_inbound(&handle, payload).await.is_err() { break; }
                            }
                        }
                    }
                }
                message = websocket.next() => {
                    let payload_text = match message {
                        Some(Ok(WsMessage::Binary(bytes))) => {
                            match decode_payload(&bytes) {
                                Some(payload) => String::from_utf8_lossy(payload).into_owned(),
                                None => continue, // malformed frame: drop, keep the connection
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => text.to_string(),
                        Some(Ok(WsMessage::Close(frame))) => {
                            let detail = frame.map(|f| format!("code={:?} reason=\"{}\"", f.code, f.reason))
                                .unwrap_or_else(|| "no close frame".to_owned());
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some(sanitize(&detail))).await;
                            break;
                        }
                        None => {
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some("hub WebSocket stream ended".to_owned())).await;
                            break;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some(sanitize(&error.to_string()))).await;
                            break;
                        }
                    };
                    // The responder decides: claim for answerable asks, deliver to
                    // `recv` only when elected, drop everything else (REQ-002).
                    let mut send_failed = false;
                    for action in responder.on_inbound(&payload_text) {
                        let Action::Claim { ask_id, frame_text } = action;
                        match payload_bytes(&frame_text) {
                            Ok(payload) => {
                                let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
                                if let Err(error) = websocket.send(WsMessage::Binary(frame.into())).await {
                                    let _ = store.mark_unhealthy(&handle, "local_send_failed", Some(sanitize(&error.to_string()))).await;
                                    send_failed = true;
                                }
                            }
                            // Our own claim should always be valid CBCL; skip if not.
                            Err(_) => continue,
                        }
                        let delay = claim_window;
                        timers.push(async move {
                            tokio::time::sleep(delay).await;
                            ClaimTimer::Window(ask_id)
                        }.boxed());
                    }
                    if send_failed { break; }
                }
            }
        }
    });
}

fn sanitize(text: &str) -> String {
    text.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::{build_announce_frame, cap_part, error_slug, frame_performative, payload_bytes};

    #[test]
    fn parses_roomcfg_with_and_without_declared_dialects() {
        // Legacy hub: no :dialects key → the menu is absent (None), which is
        // different from a declared-empty menu (Some([])).
        let cfg = super::parse_roomcfg("(roomcfg @demo :enc false)")
            .expect("legacy roomcfg should parse");
        assert!(!cfg.enc);
        assert_eq!(cfg.declared, None);

        let cfg = super::parse_roomcfg("(roomcfg @demo :enc true :dialects ())")
            .expect("empty menu should parse");
        assert!(cfg.enc);
        assert_eq!(cfg.declared, Some(vec![]));

        let cfg = super::parse_roomcfg(
            r#"(roomcfg @demo :enc false :dialects (("cite" "abc123") ("vote" "def456")))"#,
        )
        .expect("menu should parse");
        let declared = cfg.declared.expect("menu is present");
        assert_eq!(declared.len(), 2);
        assert_eq!(declared[0].name, "cite");
        assert_eq!(declared[0].digest, "abc123");
        assert_eq!(declared[1].name, "vote");
        assert_eq!(declared[1].digest, "def456");

        // Not a roomcfg → None.
        assert!(super::parse_roomcfg("(presence @demo :members ())").is_none());
    }

    #[test]
    fn builds_announce_frame_with_channel_audience_and_dialects() {
        assert_eq!(
            build_announce_frame(
                "@demo",
                "@aria",
                &["cite".to_owned(), "vote".to_owned()],
                None
            ),
            r#"(announce @demo :from @aria :agent @aria :dialects ("cite" "vote"))"#
        );
        // Advertising nothing is still a legible agent (HP-2 + REQ-006).
        assert_eq!(
            build_announce_frame("@demo", "@aria", &[], None),
            "(announce @demo :from @aria :agent @aria :dialects ())"
        );
        // A paired agent carries its adder (REQ-010).
        assert_eq!(
            build_announce_frame("@demo", "@aria", &["cite".to_owned()], Some("@mira")),
            r#"(announce @demo :from @aria :agent @aria :dialects ("cite") :added-by @mira)"#
        );
    }

    /// Every chat-wire frame must be a well-formed CBCL *s-expression* — that
    /// is the bar the chat send path enforces (`payload_bytes` runs
    /// `cbcl_parser::parse`), and the hub's lenient parser likewise accepts it.
    ///
    /// NOTE: this is R1 (s-expression well-formedness), NOT full CBCL *message*
    /// validity. `addagent`/`paircode`/`removeagent`/`agent-removed`/`announce`
    /// are bare *custom* performatives, so the strict CBCL evaluator rejects
    /// them as `UnknownPerformative` (only the 8 core performatives or a
    /// dialect performative inside `(lang …)` resolve). They are cbcl-chat
    /// *protocol* verbs — recognized by name by the hub, like the pre-existing
    /// `presence`/`roomcfg`/`invite`/`channels` — not strict CBCL messages.
    /// This test pins their syntax + the shared grammar (the hyphenated
    /// `agent-removed` performative and `:added-by` keyword) across the stack.
    #[test]
    fn pairing_chat_frames_parse_as_wellformed_sexprs() {
        let announce = build_announce_frame("@demo", "@aria", &["cite".to_owned()], Some("@mira"));
        let frames = [
            announce.as_str(),
            r#"(addagent @general :name @aria :dialects ("cite") :from @mira)"#,
            r#"(paircode @general :name @aria :id "1" :code "1-rocket-anchor-velvet")"#,
            r#"(removeagent @general :name @aria :from @mira)"#,
            "(agent-removed @general :name @aria)",
        ];
        for frame in frames {
            assert!(
                cbcl_parser::parse(frame).is_ok(),
                "not a well-formed CBCL s-expression: {frame}"
            );
        }
    }

    #[test]
    fn cap_part_is_empty_when_absent_or_blank() {
        assert_eq!(cap_part(None), "");
        assert_eq!(cap_part(Some("")), "");
        assert_eq!(cap_part(Some("   ")), "");
    }

    #[test]
    fn cap_part_emits_clause_and_strips_quotes() {
        assert_eq!(cap_part(Some("s3cret")), " :cap \"s3cret\"");
        assert_eq!(cap_part(Some(" tok ")), " :cap \"tok\"");
        assert_eq!(cap_part(Some("a\"b")), " :cap \"ab\"");
        // The resulting hello must still parse as CBCL.
        let hello = format!("(hello @r :from @a :key \"k\"{})", cap_part(Some("a\"b")));
        assert!(cbcl_parser::parse(&hello).is_ok());
    }

    #[test]
    fn classifies_join_ack_frames() {
        assert_eq!(
            frame_performative("(roomcfg @general :enc false)").as_deref(),
            Some("roomcfg")
        );
        assert_eq!(
            frame_performative("(presence @general :members (@aria @bo))").as_deref(),
            Some("presence")
        );
        assert_eq!(
            frame_performative("(error @general \"no-such-channel\")").as_deref(),
            Some("error")
        );
    }

    #[test]
    fn performative_is_the_head_not_a_body_substring() {
        // A message whose *content* mentions "error" must not be read as an error frame.
        assert_eq!(
            frame_performative("(tell @x \"an error occurred\")").as_deref(),
            Some("tell")
        );
        assert_eq!(
            frame_performative("(tell @x \"an error occurred\")"),
            Some("tell".to_owned())
        );
        assert!(error_slug("(tell @x \"an error occurred\")").is_none());
    }

    #[test]
    fn extracts_error_slug() {
        assert_eq!(
            error_slug("(error @general \"bad-signature\")").as_deref(),
            Some("bad-signature")
        );
        assert_eq!(
            error_slug("(error @ \"forbidden-room\")").as_deref(),
            Some("forbidden-room")
        );
        // Not an error frame -> no slug.
        assert!(error_slug("(roomcfg @general :enc true)").is_none());
    }

    #[test]
    fn non_cbcl_has_no_performative() {
        assert!(frame_performative("not (((valid").is_none());
        assert!(error_slug("not (((valid").is_none());
    }

    #[test]
    fn payload_bytes_validates_and_passes_through() {
        // Parses and re-encodes; the output is valid canonical CBCL bytes.
        let payload = payload_bytes("(hello @general :from @aria :key \"abc\")")
            .expect("hello should canonicalise");
        assert!(!payload.is_empty());
        // Round-trips back through the parser.
        let text = String::from_utf8(payload).unwrap();
        assert!(cbcl_parser::parse(&text).is_ok());
    }

    #[test]
    fn rejects_non_cbcl() {
        assert!(payload_bytes("not (((valid").is_err());
    }
}
