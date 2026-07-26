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

use crate::chat_frame::{decode_frame, decode_payload};
use crate::chat_responder::{Action, Responder, WindowOutcome};
use crate::daemon::{AgentHandle, AgentSendChannel, AgentStore, OutboundReject};
use crate::identity::ChatIdentity;
use crate::mls::session::{MlsSession, SessionEvent};
use crate::reconnect::ReconnectSchedule;
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
    #[error("encryption downgrade refused (REQ-023): {0}")]
    DowngradeRefused(String),
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
    /// SPEC-024 (ADR-034): the room speaks `mls-ds/v1` — the hub either conveys
    /// `:protocol mls-ds/v1` or declares the `mls-ds/v1` dialect in its menu.
    pub mls_ds: bool,
}

impl RoomCfg {
    fn absent() -> Self {
        Self {
            enc: false,
            declared: None,
            mls_ds: false,
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
            ("protocol", Some(SExpr::Atom(Atom::Symbol(word))))
            | ("protocol", Some(SExpr::Atom(Atom::Str(word)))) => {
                cfg.mls_ds = word == "mls-ds/v1";
            }
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
    // Declaring the mls-ds/v1 dialect in the menu also marks the room v1.
    if let Some(menu) = &cfg.declared {
        if menu.iter().any(|entry| entry.name == "mls-ds/v1") {
            cfg.mls_ds = true;
        }
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

/// Everything needed to (re-)establish one agent's signed-member join
/// ([[SPEC-026 CON-001]]).
///
/// It exists because a reconnect is not a *new* join: it must reproduce the
/// original one exactly — same channel, same wire handle, same advertised
/// dialects, same capability, same provenance — or the agent comes back as
/// somebody else, or as a member of nothing. Grouping the parameters is what
/// makes "replay the join" a single call rather than six arguments threaded
/// through the transport loop.
#[derive(Debug, Clone)]
pub(crate) struct JoinParams {
    ws_url: Url,
    channel: String,
    wire_handle: String,
    dialects: Vec<String>,
    cap: Option<String>,
    added_by: Option<String>,
}

/// A joined member socket and the per-connection state that belongs to it
/// ([[SPEC-026 CON-001]] post-conditions).
struct Joined {
    websocket: ChatSocket,
    /// Primed from *this* connection's nonce: a `SignedConn` is not portable
    /// across sockets, so a reconnect always brings a new one.
    conn: SignedConn,
    roomcfg: RoomCfg,
    warnings: Vec<String>,
}

/// Run the signed-member join handshake for `params` ([[SPEC-026 CON-001]]).
///
/// This is the *single* implementation of the join: called once by
/// [`create_chat_agent`] at first join, and once per attempt by the reconnect
/// arm of the receive loop. Two clients of one handshake, not two handshakes —
/// a reconnect that drifted from the original join path is a reconnect that
/// eventually stops being accepted.
///
/// `mls_create` MUST be true at most once per agent, at first join only. A
/// second `create_group_as_creator` would fork the group, so the reconnect path
/// always passes `false`.
///
/// The error partition is load-bearing for the caller (REQ-005):
/// [`ChatError::JoinRejected`] and [`ChatError::DowngradeRefused`] are terminal
/// — the hub said no, or the encryption pin was violated. Everything else is a
/// transport-level failure and is retryable.
async fn join_hub(
    params: &JoinParams,
    identity: &ChatIdentity,
    mut mls: Option<&mut MlsSession>,
    mls_create: bool,
) -> Result<Joined, ChatError> {
    let JoinParams {
        ws_url,
        channel,
        wire_handle: agent_handle,
        dialects,
        cap,
        added_by,
    } = params;
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
    let frame = conn.sign_chat_frame(identity, &payload);
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
    let (ack, roomcfg, learned_hub) = await_join_ack(&mut websocket).await?;

    // SPEC-013: judge the ack against the encryption-mode pin (REQ-023) —
    // a `roomcfg :enc false` on a pinned-encrypted channel is a refused
    // downgrade and the join fails closed — then publish KeyPackages and
    // the self-signed idkey assertion (REQ-002, REQ-019).
    if let Some(session) = mls.as_mut() {
        session
            .on_roomcfg(&ack)
            .map_err(|e| ChatError::DowngradeRefused(e.to_string()))?;
        if session.encrypted() {
            // REQ-016 operator intent: bootstrap the MLS group as the room
            // creator before publishing, so this agent is the sole member /
            // elected owner and will add present members on presence.
            if mls_create {
                session
                    .create_group_as_creator()
                    .map_err(|e| ChatError::Hello(format!("mls create group: {e}")))?;
            }
            let frames = session
                .join_frames()
                .map_err(|e| ChatError::Hello(format!("mls join frames: {e}")))?;
            for text in frames {
                let payload = payload_bytes(&text).map_err(ChatError::Hello)?;
                let frame = conn.sign_chat_frame(identity, &payload);
                websocket
                    .send(WsMessage::Binary(frame.into()))
                    .await
                    .map_err(|e| ChatError::HelloSendFailed(e.to_string()))?;
            }
        }
    }

    // REQ-008 (SPEC-016): the advertised set must be a subset of the channel's
    // declared menu when one is conveyed. A hub that conveys no menu (today's
    // cbcl-bus) soft-passes with an explicit warning — never silently.
    let mut warnings = Vec::new();
    match &roomcfg.declared {
        None => warnings.push(format!(
            "channel {channel} declares no dialect menu (legacy hub); --speak validation skipped"
        )),
        Some(menu) => {
            for dialect in dialects {
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
    let announce = build_announce_frame(channel, agent_handle, dialects, added_by.as_deref());
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
    let announce_frame = conn.sign_chat_frame(identity, &announce_payload);
    websocket
        .send(WsMessage::Binary(announce_frame.into()))
        .await
        .map_err(|error| ChatError::ConnectionFailed(error.to_string()))?;

    Ok(Joined {
        websocket,
        conn,
        roomcfg,
        warnings,
    })
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
    mut mls: Option<MlsSession>,
    mls_create: bool,
    receive_all: bool,
    resume: Option<AgentHandle>,
) -> Result<(AgentHandle, Vec<String>), ChatError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| ChatError::Store(error.to_string()))?;

    let join = JoinParams {
        ws_url: ws_url.clone(),
        channel: channel.to_owned(),
        wire_handle: agent_handle.to_owned(),
        dialects: dialects.clone(),
        cap,
        added_by,
    };
    let Joined {
        websocket,
        conn,
        roomcfg,
        warnings,
    } = join_hub(&join, identity.as_ref(), mls.as_mut(), mls_create).await?;

    // SPEC-024 (ADR-034/ADR-035): a room the hub marks `mls-ds/v1` activates the
    // v1 posture on the session (H7 owner-removal rejection + CON-013 atomic
    // persist) and runs the DS pull loop instead of relying on SPEC-013 push for
    // the record log. The pull task feeds admitted records into the receive loop
    // below, which owns the MlsSession for the apply + atomic commit.
    //
    // Deliberately outside `join_hub`: the pull task is per *agent*, not per
    // *connection*. It owns its own socket and its own bounded backoff, so it
    // rides a hub restart on its own and must not be respawned by a chat
    // reconnect (SPEC-026 REQ-003 — the re-join replays the chat handshake, not
    // the whole agent).
    let mut ds_pull: Option<crate::mls_ds::task::DsPullConfig> = None;
    if roomcfg.mls_ds {
        if let Some(session) = mls.as_mut() {
            session
                .mark_v1()
                .map_err(|e| ChatError::Hello(format!("mls-ds/v1 activation: {e}")))?;
            let initial_log = session
                .load_v1_state()
                .map(|(_, _, log)| log)
                .unwrap_or_else(|| crate::mls_ds::ClientLog {
                    cursor: 0,
                    cursor_hash: crate::mls_ds::task::GENESIS_CURSOR_HASH.into(),
                });
            // The DS endpoint lives on the same hub as /chat/v1.
            let ds_url = ws_url.as_str().replace("/chat/v1", "/mls-ds/v1");
            ds_pull = Some(crate::mls_ds::task::DsPullConfig {
                ds_url,
                room: channel.to_owned(),
                state_dir: session.v1_pins_dir(),
                poll: Duration::from_secs(2),
                initial_log,
            });
        }
    }

    // SPEC-026 ADR-006: a resumed agent keeps the handle it had before the
    // daemon restarted, so an operator's exported `CBCL_AGENT_HANDLE` and any
    // script holding it keep working. The handle is an opaque local identifier
    // with no hub-side meaning, so reuse costs nothing.
    //
    // SIMPLIFY: the insert below REPLACES any placeholder entry registered for
    // this handle while the agent was still coming up, rather than updating it
    // in place. Ceiling: a `recv` issued against an agent that has not yet
    // joined blocks until its own timeout instead of being woken by the join,
    // because the entry's `Notify` is replaced with it. Upgrade path: an
    // `AgentStore::attach_connection` that mutates the existing entry. Not done
    // now because the placeholder's queue and waiter are empty by construction
    // (trace: SPEC-026 REQ-008, ADR-006).
    let handle = resume.unwrap_or_else(AgentHandle::generate);
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
    // v1 rooms: start the DS pull loop; its admitted records flow into the
    // receive loop through ds_rx for the MLS apply + CON-013 atomic commit.
    let (ds_tx, ds_rx) = mpsc::channel(8);
    if let Some(cfg) = ds_pull {
        crate::mls_ds::task::spawn_ds_pull_loop(cfg, ds_tx);
    }

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
        mls,
        receive_all,
        wire_handle: agent_handle.to_owned(),
        ds_rx,
        join,
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
    /// SPEC-013 MLS session (Some when the channel is pinned encrypted, or
    /// when prior MLS state exists for it).
    mls: Option<MlsSession>,
    /// Receive-all (`*`): deliver every channel content message to `recv`,
    /// not just answerable asks this agent is elected to answer. The agent's
    /// own fanned-back messages are skipped. The responder still runs for any
    /// concrete dialects also advertised.
    receive_all: bool,
    /// This agent's wire handle (`@name`) — used only by receive-all to skip
    /// its own messages.
    wire_handle: String,
    /// SPEC-024 (ADR-035): admitted DS records from the per-room pull task.
    /// The receive loop owns the MlsSession, so the CON-006 apply and the
    /// CON-013 atomic commit happen here. Idle (sender dropped immediately)
    /// on non-v1 rooms.
    ds_rx: mpsc::Receiver<crate::mls_ds::task::DsApply>,
    /// SPEC-026 REQ-003: the parameters of the original join, kept so the loop
    /// can replay it after the socket ends. Without this the loop could
    /// reconnect a *socket* but not rejoin a *channel*.
    join: JoinParams,
}

/// A replacement connection produced by [`reconnect`].
struct Reconnected {
    websocket: ChatSocket,
    conn: SignedConn,
}

/// How a reconnect attempt schedule ended ([[SPEC-026 REQ-001]], [[SPEC-026 REQ-005]]).
enum Recovery {
    /// The re-join succeeded: here is the replacement socket and its signer.
    /// Boxed because a `ChatSocket` carries the TLS buffers — inlining it would
    /// make every `Recovery` value, including the two small terminal ones, pay
    /// for the successful case.
    Reconnected(Box<Reconnected>),
    /// The agent was closed while the schedule was waiting. A `hark close`
    /// during an outage must not have to wait out the backoff.
    Closed,
    /// A terminal condition — the hub actively rejected the re-join, or it
    /// would have violated the encryption pin (REQ-005). The schedule stops.
    Terminal {
        reason: &'static str,
        detail: String,
    },
}

/// Re-establish the agent's hub connection ([[SPEC-026 REQ-001]]).
///
/// Loops on the [`ReconnectSchedule`] until the re-join succeeds, the agent is
/// closed, or a terminal condition is reached. There is no attempt ceiling: a
/// bound would reintroduce the failure this exists to fix, only later
/// (SPEC-026 ADR-004). What an operator gets instead is visibility — the handle
/// reports `reconnecting` with its attempt count throughout.
///
/// While waiting it keeps servicing two things, and both are load-bearing:
/// `close_rx`, so a close during an outage is immediate rather than delayed by
/// up to the ceiling; and `send_rx`, so an `emit` is answered with a *retryable*
/// refusal instead of blocking on a loop that is not reading its channel.
/// Outbound frames are deliberately refused rather than queued (SPEC-026
/// ADR-003): in an encrypted channel a frame sealed before the gap may be
/// sealed against an epoch the group has left by the time it flushes.
#[allow(clippy::too_many_arguments)]
async fn reconnect(
    join: &JoinParams,
    identity: &ChatIdentity,
    mls: &mut Option<MlsSession>,
    schedule: &mut ReconnectSchedule,
    close_rx: &mut oneshot::Receiver<()>,
    send_rx: &mut mpsc::Receiver<crate::daemon::OutboundFrame>,
    store: &AgentStore,
    handle: &AgentHandle,
    cause: String,
) -> Recovery {
    let started = tokio::time::Instant::now();
    // OBS-001: once per outage, not once per attempt.
    tracing::warn!(
        agent = handle.as_str(),
        channel = join.channel,
        cause = cause,
        "hub connection lost; reconnecting"
    );
    let mut announced_ceiling = false;
    let mut last_error = cause.clone();
    let _ = store
        .mark_reconnecting(handle, 0, Some(cause.clone()))
        .await;

    loop {
        let delay = schedule.next_delay(rand::random::<f64>());
        let _ = store
            .mark_reconnecting(handle, schedule.attempts(), Some(last_error.clone()))
            .await;

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut *close_rx => return Recovery::Closed,
                () = &mut sleep => break,
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        return Recovery::Terminal {
                            reason: "local_send_failed",
                            detail: "chat send channel closed".to_owned(),
                        };
                    };
                    let _ = outbound.result_tx.send(Err(OutboundReject::retryable(format!(
                        "hub connection is down; reconnecting (attempt {}): {last_error}",
                        schedule.attempts()
                    ))));
                }
            }
        }

        // The re-join NEVER creates the MLS group: `create_group_as_creator` a
        // second time would fork the group into two ciphertext worlds.
        match join_hub(join, identity, mls.as_mut(), false).await {
            Ok(joined) => {
                tracing::info!(
                    agent = handle.as_str(),
                    channel = join.channel,
                    attempts = schedule.attempts(),
                    outage_ms = started.elapsed().as_millis() as u64,
                    "hub connection re-established"
                );
                for warning in &joined.warnings {
                    tracing::debug!(agent = handle.as_str(), warning, "re-join warning");
                }
                return Recovery::Reconnected(Box::new(Reconnected {
                    websocket: joined.websocket,
                    conn: joined.conn,
                }));
            }
            // REQ-005(a): the hub gave a verdict. Retrying is a loop against a
            // settled answer — the channel is gone, or this agent is not
            // welcome in it.
            Err(ChatError::JoinRejected(slug)) => {
                return Recovery::Terminal {
                    reason: "hub_rejected",
                    detail: format!("hub rejected the re-join: {slug}"),
                };
            }
            // REQ-005(b): SPEC-013 REQ-023. A hub offering plaintext for a
            // channel pinned encrypted is misconfigured or hostile; either way
            // the agent must not resume in the clear.
            Err(ChatError::DowngradeRefused(detail)) => {
                return Recovery::Terminal {
                    reason: "downgrade_refused",
                    detail: sanitize(&detail),
                };
            }
            Err(error) => {
                last_error = sanitize(&error.to_string());
                tracing::debug!(
                    agent = handle.as_str(),
                    channel = join.channel,
                    attempt = schedule.attempts(),
                    error = last_error,
                    "reconnect attempt failed"
                );
                if schedule.at_ceiling() && !announced_ceiling {
                    announced_ceiling = true;
                    // "This is an outage, not a blip" — said exactly once.
                    tracing::warn!(
                        agent = handle.as_str(),
                        channel = join.channel,
                        attempts = schedule.attempts(),
                        error = last_error,
                        "hub still unreachable at the backoff ceiling; still retrying"
                    );
                }
            }
        }
    }
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
/// only the acknowledging frame (returned raw for the SPEC-013 REQ-023
/// mode-pin check, and parsed for the SPEC-016 REQ-008 menu check) and leave
/// any backfill/presence for the receive loop to enqueue.
///
/// Ordering contract: the hub teaches its control dialect BEFORE the verdict —
/// `cbcl-chat-room:join` builds the reply as `[meta, roomcfg | backfill]`, and
/// cbcl-bus pins that order in `join-leads-with-the-hub-dialect-meta`. A hub
/// that only teaches after its verdict is indistinguishable from one that
/// teaches nothing: we return on the verdict, and the agent degrades to the
/// "taught no control dialect" warning rather than waiting on a frame that may
/// never come.
async fn await_join_ack(
    websocket: &mut ChatSocket,
) -> Result<(String, RoomCfg, HubTeaching), ChatError> {
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
                return Ok((text, roomcfg, learned_hub));
            }
            Some("presence") => return Ok((text, RoomCfg::absent(), learned_hub)),
            Some("error") => {
                return Err(ChatError::JoinRejected(
                    error_slug(&text).unwrap_or_else(|| "unknown".to_owned()),
                ));
            }
            // The hub's control-dialect advertisement: learn it (the language's
            // native `(meta (define …))` path) and keep waiting for the verdict.
            // Only the dialect actually named `hub` counts — the same meta path
            // can carry other dialect distributions (cite, poll, …), which are
            // not the control grammar and must not be installed as it (R7-001).
            // A malformed advertisement is non-fatal — the join still proceeds;
            // the announce self-check degrades to a surfaced warning carrying
            // the learn error, so a teaching-but-broken hub is distinguishable
            // from a legacy hub that teaches nothing. A hub dialect already
            // learned is never clobbered by a later bad frame.
            Some("meta") => {
                use crate::hub_dialect::HubDialectError;
                match crate::hub_dialect::learn_hub_dialect(&text) {
                    Ok(registry) => learned_hub = HubTeaching::Learned(registry),
                    Err(HubDialectError::NotHub(name)) => {
                        tracing::debug!("ignoring a non-hub dialect meta ({name})");
                    }
                    Err(error) => {
                        tracing::warn!("could not learn the hub dialect: {error}");
                        if !matches!(learned_hub, HubTeaching::Learned(_)) {
                            learned_hub = HubTeaching::Malformed(error.to_string());
                        }
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
        mut mls,
        receive_all,
        wire_handle,
        mut ds_rx,
        join,
    } = args;
    tokio::spawn(async move {
        // Pending Δ-window and liveness-fallback timers, fired into the select.
        let mut timers: FuturesUnordered<BoxFuture<'static, ClaimTimer>> = FuturesUnordered::new();
        // SPEC-026 REQ-001. Every transport-level end of the socket — read side
        // or write side — parks its cause here and loops; the top of the loop
        // owns the single reconnect call site. One place to reason about, and
        // no way for a new failure path to quietly reintroduce the `break` that
        // was issue #25.
        let mut schedule = ReconnectSchedule::default();
        let mut pending_reconnect: Option<String> = None;
        loop {
            if let Some(cause) = pending_reconnect.take() {
                match reconnect(
                    &join,
                    identity.as_ref(),
                    &mut mls,
                    &mut schedule,
                    &mut close_rx,
                    &mut send_rx,
                    &store,
                    &handle,
                    cause,
                )
                .await
                {
                    Recovery::Reconnected(replacement) => {
                        websocket = replacement.websocket;
                        conn = replacement.conn;
                        schedule.reset();
                        let _ = store.mark_connected(&handle).await;
                    }
                    Recovery::Closed => {
                        let _ = websocket.close(None).await;
                        break;
                    }
                    Recovery::Terminal { reason, detail } => {
                        let _ = store.mark_unhealthy(&handle, reason, Some(detail)).await;
                        break;
                    }
                }
            }
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
                    // SPEC-013 REQ-005/REQ-023: in a pinned-encrypted channel
                    // every outbound payload is wrapped as an MLS deliver
                    // frame; there is no plaintext fallback (fail closed).
                    let message_text = match mls.as_mut() {
                        Some(session) if session.encrypted() => {
                            match session.encrypt_outbound(&outbound.message) {
                                Ok(wrapped) => wrapped,
                                // A NotReady refusal is transient (no Welcome yet):
                                // report it retryable so the handle stays healthy.
                                // Any other refusal (e.g. a refused downgrade) is a
                                // fail-closed security decision — fatal.
                                Err(error @ crate::mls::MlsError::NotReady(_)) => {
                                    let _ = outbound.result_tx.send(Err(OutboundReject::retryable(format!("mls encrypt refused: {error}"))));
                                    continue;
                                }
                                Err(error) => {
                                    let _ = outbound.result_tx.send(Err(OutboundReject::fatal(format!("mls encrypt refused: {error}"))));
                                    continue;
                                }
                            }
                        }
                        _ => outbound.message.clone(),
                    };
                    // Validate + sign + frame on the way out.
                    let payload = match payload_bytes(&message_text) {
                        Ok(payload) => payload,
                        Err(error) => {
                            let _ = outbound.result_tx.send(Err(OutboundReject::fatal(format!("outbound not valid CBCL: {error}"))));
                            continue;
                        }
                    };
                    let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
                    match websocket.send(WsMessage::Binary(frame.into())).await {
                        Ok(()) => { let _ = outbound.result_tx.send(Ok(())); }
                        // SPEC-026 REQ-001/REQ-004: a failed write is the same
                        // event as a failed read — the socket died — so it
                        // schedules a reconnect rather than killing the handle.
                        // The frame that lost the race is refused *retryably*
                        // so the caller re-offers it, which re-seals it against
                        // the epoch the group is actually in (ADR-003).
                        Err(error) => {
                            let detail = sanitize(&error.to_string());
                            let _ = outbound.result_tx.send(Err(OutboundReject::retryable(detail.clone())));
                            pending_reconnect = Some(detail);
                            continue;
                        }
                    }
                }
                // SPEC-024 (ADR-035): an ADMITTED DS record from the pull task. The
                // record already passed CON-011 recognition, CON-012 binding, and
                // CON-005 admission (anchor + hash + DS-sig + exact-next). Here the
                // session applies the embedded frame (CON-006 — decrypt/merge through
                // the same engine as any inbound, H7 active via is_v1) and then
                // commits provider snapshot + cursor in ONE manifest flip (CON-013).
                // An apply failure holds the durable cursor: on restart the same
                // record is re-pulled (immutable log, idempotent).
                maybe_apply = ds_rx.recv() => {
                    let Some(apply) = maybe_apply else { continue };
                    let Some(session) = mls.as_mut() else { continue };
                    let applied_text = match session.handle_frame(&apply.payload) {
                        SessionEvent::Plaintext { text, .. } => Some(text),
                        SessionEvent::NotMls => None,   // marker/control payload — nothing to render
                        SessionEvent::Handled { .. } => None,
                        SessionEvent::Dropped { reason, .. } => {
                            tracing::warn!(reason, "ds-admitted record failed MLS apply; cursor NOT committed");
                            continue;
                        }
                    };
                    if let Err(error) = session.persist_v1_state(apply.generation, &apply.log) {
                        tracing::warn!(%error, "CON-013 persist failed; durable cursor holds");
                        continue;
                    }
                    // Decrypted DS-delivered content reaches recv exactly like live
                    // content (receive-all path; own messages skipped).
                    if let Some(text) = applied_text {
                        if receive_all {
                            let own = crate::chat_responder::message_sender(&text).as_deref()
                                == Some(wire_handle.as_str());
                            if !own && store.enqueue_inbound(&handle, text).await.is_err() {
                                break;
                            }
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
                            // CON-012 (IMPL-025): decode with the receive-frame that RETAINS the
                            // outer signature. `frame.signature` is available for mls-ds/v1
                            // DS-response verification under the pinned DS key; SPEC-013 frames
                            // continue unchanged through the session path below.
                            match decode_frame(&bytes) {
                                Some(frame) => String::from_utf8_lossy(frame.payload).into_owned(),
                                None => continue, // malformed frame: drop, keep the connection
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => text.to_string(),
                        // SPEC-026 REQ-001: all three transport-level ends —
                        // a close frame, an exhausted stream, an IO error —
                        // schedule a reconnect. Marking the handle unhealthy
                        // here is what made an ordinary hub redeploy fatal
                        // (issue #25); the hub's durable state survives the
                        // redeploy, so the membership is still ours.
                        Some(Ok(WsMessage::Close(frame))) => {
                            let detail = frame.map(|f| format!("code={:?} reason=\"{}\"", f.code, f.reason))
                                .unwrap_or_else(|| "no close frame".to_owned());
                            pending_reconnect = Some(sanitize(&detail));
                            continue;
                        }
                        None => {
                            pending_reconnect = Some("hub WebSocket stream ended".to_owned());
                            continue;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            pending_reconnect = Some(sanitize(&error.to_string()));
                            continue;
                        }
                    };
                    // SPEC-013: the MLS session consumes its frames first —
                    // welcome/deliver/keypkg/idkey/presence — decrypting
                    // content and emitting any protocol frames to send. In a
                    // pinned-encrypted channel ONLY decrypted content reaches
                    // the responder (REQ-005/REQ-006/REQ-017/REQ-018).
                    let responder_text: Option<String> = match mls.as_mut() {
                        None => Some(payload_text),
                        Some(session) => match session.handle_frame(&payload_text) {
                            SessionEvent::NotMls => {
                                if session.encrypted() {
                                    // Plaintext content does not enter an
                                    // encrypted channel's responder; control
                                    // frames carry no content to answer.
                                    None
                                } else {
                                    Some(payload_text)
                                }
                            }
                            SessionEvent::Plaintext { text, .. } => Some(text),
                            SessionEvent::Handled { outbound } => {
                                // SPEC-026 REQ-001: a write failure here is the
                                // socket dying mid-MLS-exchange. Reconnect; the
                                // re-join republishes the key material and the
                                // peers re-drive the exchange, which is what
                                // the browser client does on reopen.
                                let mut dropped: Option<String> = None;
                                for text in outbound {
                                    let Ok(payload) = payload_bytes(&text) else { continue };
                                    let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
                                    if let Err(error) = websocket.send(WsMessage::Binary(frame.into())).await {
                                        dropped = Some(sanitize(&error.to_string()));
                                        break;
                                    }
                                }
                                if let Some(detail) = dropped {
                                    pending_reconnect = Some(detail);
                                    continue;
                                }
                                None
                            }
                            SessionEvent::Dropped { reason, probable_fork } => {
                                if probable_fork {
                                    tracing::warn!(reason, "mls probable fork/equivocation signal (REQ-006); compare safety numbers");
                                } else {
                                    tracing::debug!(reason, "mls frame dropped");
                                }
                                None
                            }
                        },
                    };
                    let Some(responder_text) = responder_text else { continue };
                    // Receive-all (`*`): deliver EVERY channel content message to
                    // `recv`, not just answerable asks — the firehose a paired
                    // observer asked for. Skip our own messages the hub fans back
                    // so the agent doesn't receive its own emits. The responder
                    // still runs below for any concrete dialects also advertised.
                    if receive_all {
                        let own = crate::chat_responder::message_sender(&responder_text)
                            .as_deref()
                            == Some(wire_handle.as_str());
                        if !own
                            && store
                                .enqueue_inbound(&handle, responder_text.clone())
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    // The responder decides: claim for answerable asks, deliver to
                    // `recv` only when elected, drop everything else (REQ-002).
                    // SPEC-026 REQ-001: a claim that cannot be written means the
                    // socket died. Reconnect rather than die — the claim itself
                    // is forfeited (another agent answers, or the liveness
                    // fallback fires), which is the correct outcome for a claim
                    // the hub never saw.
                    let mut send_failed: Option<String> = None;
                    for action in responder.on_inbound(&responder_text) {
                        let Action::Claim { ask_id, frame_text } = action;
                        match payload_bytes(&frame_text) {
                            Ok(payload) => {
                                let frame = conn.sign_chat_frame(identity.as_ref(), &payload);
                                if let Err(error) = websocket.send(WsMessage::Binary(frame.into())).await {
                                    send_failed = Some(sanitize(&error.to_string()));
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
                    if let Some(detail) = send_failed {
                        pending_reconnect = Some(detail);
                        continue;
                    }
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
        assert!(!cfg.mls_ds, "no v1 marker → legacy room");

        // SPEC-024 (ADR-034): the v1 marker — :protocol keyword or the dialect menu.
        let cfg = super::parse_roomcfg("(roomcfg @demo :enc true :protocol mls-ds/v1)")
            .expect("protocol roomcfg should parse");
        assert!(cfg.mls_ds, ":protocol mls-ds/v1 marks the room v1");
        let cfg = super::parse_roomcfg(
            r#"(roomcfg @demo :enc true :dialects (("mls-ds/v1" "922ba8")))"#,
        )
        .expect("v1-menu roomcfg should parse");
        assert!(cfg.mls_ds, "declaring the mls-ds/v1 dialect marks the room v1");

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
            r#"(paircode @general :name @aria :id "1" :code "1-rocket-anchor")"#,
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
