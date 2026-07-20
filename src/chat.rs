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
use crate::signed_transport::{SignedConn, parse_conn_bootstrap};

pub const CHAT_WS_PATH: &str = "/chat/v1";

/// How long to wait for the hub's join acknowledgement (`roomcfg`/`presence`)
/// or rejection (`error`) after sending the signed `hello`, before giving up.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Auto-reconnect backoff (the hub is a single immediate-deploy instance, so a
/// redeploy drops every socket at once). The first retry waits `BASE`; each
/// failed attempt doubles up to `MAX`; the delay resets to `BASE` after any
/// successful reconnect + rejoin. Reconnection retries indefinitely.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

// INVARIANT (reconnect credentials): every reconnect presents the SAME cap
// the agent originally joined with. A spent single-use pairing invite is
// harmless to replay — the hub's identity-bound resume admission
// (cbcl-chat-resume, granted atomically with every successful private-room
// admission) re-admits the verified identity without any token, and a
// standing cap simply matches again. There is deliberately NO client-side
// renewal machinery: a credential minted after the connection is ready can
// never close the disconnect-during-mint race, so resumption is the hub's
// job, issued with admission itself.

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

impl ChatError {
    /// Whether a failed reconnect attempt is worth retrying: retry TRANSPORT,
    /// terminate on PERMANENT.
    ///
    /// RETRYABLE (transient hub-down / transport): the hub is a single
    /// immediate-deploy instance, so a redeploy tears down the socket and the
    /// TCP/upgrade/hello handshake fails until it is back — backing off and
    /// retrying is correct.
    ///
    /// PERMANENT (fail-closed, terminate the reconnect loop): a verdict that a
    /// retry cannot change —
    /// * `JoinRejected` (forbidden-room / no-such-channel / bad-signature):
    ///   the membership decision is final. With the hub's identity-bound
    ///   resume admission, a legitimately re-admissible agent is never
    ///   rejected, so a rejection is authoritative — EXCEPT the hub's
    ///   `admission-store-unavailable` slug, which it emits when the
    ///   admission transaction aborted (e.g. its resume store is down
    ///   mid-restart): that is a storage fault, not a verdict, and the hub
    ///   keeps it distinct from `forbidden-room` precisely so reconnecting
    ///   clients retry instead of terminating.
    /// * `DowngradeRefused` (REQ-023): the `MlsSession` is now permanently
    ///   downgrade-refused; a later `:enc true` must NOT be read as recovery.
    /// * `UndeclaredDialect` / `Hello` (announce-invalid / MLS build): a local
    ///   configuration/build fault a reconnect cannot fix.
    /// * `Store`: the agent-store rejected the connection.
    fn is_retryable(&self) -> bool {
        match self {
            ChatError::ConnectionFailed(_)
            | ChatError::HelloSendFailed(_)
            | ChatError::JoinTimeout(_) => true,
            ChatError::JoinRejected(slug) => slug == "admission-store-unavailable",
            ChatError::DowngradeRefused(_)
            | ChatError::UndeclaredDialect { .. }
            | ChatError::Hello(_)
            | ChatError::Store(_) => false,
        }
    }
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
    mut mls: Option<MlsSession>,
    mls_create: bool,
    receive_all: bool,
) -> Result<(AgentHandle, Vec<String>), ChatError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| ChatError::Store(error.to_string()))?;

    // The full connect → bootstrap → hello → join-ack → MLS publish → announce
    // sequence is factored into `connect_and_join` so the receive loop can
    // re-run it verbatim on every reconnect (see `spawn_receive_loop`).
    let JoinOutcome {
        websocket,
        conn,
        roomcfg,
        warnings,
    } = connect_and_join(
        ws_url,
        channel,
        agent_handle,
        &dialects,
        cap.as_deref(),
        added_by.as_deref(),
        identity.as_ref(),
        mls.as_mut(),
        mls_create,
    )
    .await?;

    let handle = AgentHandle::generate();
    let (close_tx, close_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    // The advertised dialects are both the store's record and the responder's
    // capability set (SPEC-003 REQ-002).
    let capability = dialects.clone();
    store
        .insert_connected_with_router_channels(
            handle.clone(),
            dialects.clone(),
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
    let task = ChatAgentTask {
        ws_url: ws_url.clone(),
        channel: channel.to_owned(),
        wire_handle: agent_handle.to_owned(),
        dialects,
        cap,
        added_by,
        claim_window,
        liveness_timeout,
        receive_all,
        store,
        handle: handle.clone(),
        identity,
        responder,
        mls,
        close_rx,
        send_rx,
    };
    tokio::spawn(task.run(LiveConnection { websocket, conn }));

    Ok((handle, warnings))
}

/// Everything a successful `/chat/v1` connect + join yields that the receive
/// loop (and the initial caller) needs: the live socket, its per-connection
/// signer, the parsed room config, and any soft-pass warnings surfaced during
/// the join. Returned by [`connect_and_join`] for both the first connect and
/// every reconnect.
struct JoinOutcome {
    websocket: ChatSocket,
    conn: SignedConn,
    roomcfg: RoomCfg,
    warnings: Vec<String>,
}

/// Connect to `/chat/v1`, complete the signed-member join, and (in a pinned
/// encrypted channel) publish KeyPackages + the idkey assertion and announce
/// the agent — the exact frame sequence, in order, that a fresh membership
/// requires. Factored out of [`create_chat_agent`] so it is re-runnable on
/// every reconnect against a (possibly restarted) hub with the SAME identity
/// and MLS session.
///
/// MLS re-join semantics (IMPORTANT):
/// * `mls_create` must be true AT MOST ONCE — only on the very first connect.
///   Every reconnect passes `false`: re-creating the group would mint a new
///   `group_id` and fork every peer (`WrongGroupId`).
/// * `on_roomcfg` (a pure downgrade judge) and `join_frames` (a memoized
///   KeyPackage set + idkey + keyready) are safe to call again on an existing
///   session, so a reconnect re-publishes membership to the restarted hub
///   without minting fresh bundles on every attempt.
#[allow(clippy::too_many_arguments)]
async fn connect_and_join(
    ws_url: &Url,
    channel: &str,
    agent_handle: &str,
    dialects: &[String],
    cap: Option<&str>,
    added_by: Option<&str>,
    identity: &ChatIdentity,
    mut mls: Option<&mut MlsSession>,
    mls_create: bool,
) -> Result<JoinOutcome, ChatError> {
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
        cap_part(cap),
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
    // downgrade and the join fails closed.
    if let Some(session) = mls.as_deref_mut() {
        session
            .on_roomcfg(&ack)
            .map_err(|e| ChatError::DowngradeRefused(e.to_string()))?;
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
    let announce = build_announce_frame(channel, agent_handle, dialects, added_by);
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

    // Publish KeyPackages and the self-signed idkey assertion (REQ-002,
    // REQ-019) only now — AFTER every local validation above (dialect menu,
    // announce conformance). A rejoin that would fail those permanent checks
    // must not first durably mint KeyPackage bundles or emit control frames;
    // the memoized publication set inside `join_frames` bounds what a
    // *transport* failure below can cost across retries.
    if let Some(session) = mls {
        if session.encrypted() {
            // REQ-016 operator intent: bootstrap the MLS group as the room
            // creator before publishing, so this agent is the sole member /
            // elected owner and will add present members on presence. Only on
            // the first connect (`mls_create`); reconnects pass false so the
            // group is never re-created (would fork every peer).
            if mls_create {
                session
                    .create_group_as_creator()
                    .map_err(|e| ChatError::Hello(format!("mls create group: {e}")))?;
            }
            let frames = session
                .join_frames()
                .map_err(|e| ChatError::Hello(format!("mls join frames: {e}")))?;
            // Every (re)join replays the memoized publication verbatim: the
            // hub's keypub upsert is idempotent, so this heals a lost write
            // without any delivered heuristic or duplicate-queue risk.
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

    let announce_frame = conn.sign_chat_frame(identity, &announce_payload);
    websocket
        .send(WsMessage::Binary(announce_frame.into()))
        .await
        .map_err(|error| ChatError::ConnectionFailed(error.to_string()))?;

    Ok(JoinOutcome {
        websocket,
        conn,
        roomcfg,
        warnings,
    })
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

/// One chat agent's long-lived owner: the immutable join configuration and
/// every piece of state that must survive reconnects — created once by
/// [`create_chat_agent`], then driven to completion by [`Self::run`] on a
/// spawned task. The lifecycle invariant: exactly one [`LiveConnection`] is
/// active at a time and it is the ONLY thing replaced across reconnects;
/// identity, responder, MLS session, store handle, and both control channels
/// are never rebuilt.
struct ChatAgentTask {
    // --- immutable join configuration -----------------------------------
    /// The hub URL, re-dialed on every reconnect.
    ws_url: Url,
    /// The channel (`@name`) this agent joined — re-sent in every hello.
    channel: String,
    /// This agent's wire handle (`@name`) — used by receive-all to skip its
    /// own messages, and as the `:from`/`:agent` identity on every (re)join.
    wire_handle: String,
    /// The advertised dialect set — re-validated + re-announced on reconnect.
    dialects: Vec<String>,
    /// The capability presented in EVERY hello (if any). A spent single-use
    /// pairing invite is fine to replay: the hub's identity-bound resume
    /// admission re-admits the verified identity without it.
    cap: Option<String>,
    /// The `:added-by` provenance carried in the announce (if paired in).
    added_by: Option<String>,
    claim_window: Duration,
    liveness_timeout: Duration,
    /// Receive-all (`*`): deliver every channel content message to `recv`,
    /// not just answerable asks this agent is elected to answer. The agent's
    /// own fanned-back messages are skipped. The responder still runs for any
    /// concrete dialects also advertised.
    receive_all: bool,
    // --- state that survives reconnects ----------------------------------
    store: AgentStore,
    handle: AgentHandle,
    identity: Arc<ChatIdentity>,
    responder: Responder,
    /// SPEC-013 MLS session (Some when the channel is pinned encrypted, or
    /// when prior MLS state exists for it).
    mls: Option<MlsSession>,
    close_rx: oneshot::Receiver<()>,
    send_rx: mpsc::Receiver<crate::daemon::OutboundFrame>,
}

/// One connection's ephemera — replaced whole on every reconnect: the
/// WebSocket stream and the per-connection signer (conn_nonce + hub_id +
/// seq) bound to it.
struct LiveConnection {
    websocket: ChatSocket,
    conn: SignedConn,
}

/// Why the single-connection receive loop returned. The outer loop reconnects
/// only for [`LoopExit::HubClosed`]; the other two are terminal.
enum LoopExit {
    /// `close_rx` fired — an explicit `daemon stop`. The socket is closed; do
    /// NOT reconnect.
    Stopped,
    /// The daemon dropped this agent (send channel closed) or a local outbound
    /// send failed. Terminal: the handle is already poisoned, do NOT reconnect.
    LocalClosed,
    /// The hub closed the socket / the stream ended / a transport error — the
    /// single-instance hub was (re)deployed. Reconnect with backoff.
    HubClosed(String),
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

impl ChatAgentTask {
    /// Drive the agent to completion: run one connection until it exits,
    /// then — only when the HUB dropped the socket (a single-instance
    /// redeploy) — reconnect with backoff and continue. An explicit stop or
    /// a local drop is terminal.
    async fn run(mut self, mut live: LiveConnection) {
        loop {
            match self.run_connection(&mut live).await {
                LoopExit::Stopped => {
                    tracing::info!(agent = %self.wire_handle, "chat receive loop stopped (explicit)");
                    break;
                }
                LoopExit::LocalClosed => {
                    tracing::info!(agent = %self.wire_handle, "chat receive loop ended (agent dropped locally)");
                    break;
                }
                LoopExit::HubClosed(detail) => match self.reconnect(detail).await {
                    Some(fresh) => {
                        let _ = self.store.mark_connected(&self.handle).await;
                        tracing::info!(agent = %self.wire_handle, "chat reconnected");
                        live = fresh;
                    }
                    None => {
                        // Terminal (explicit stop or permanent rejection) —
                        // the store state is already marked by `reconnect`;
                        // just close the dead socket.
                        let _ = live.websocket.close(None).await;
                        break;
                    }
                },
            }
        }
    }

    /// The backoff/rejoin loop. Invariants:
    ///
    /// * The close signal is raced against BOTH the backoff wait and the
    ///   in-flight `connect_and_join`, so an explicit stop can never be
    ///   outrun by a rejoin that would emit frames for a removed handle
    ///   (dropping the join future closes any partial socket it opened).
    /// * `mls_create` is false on every reconnect — the group is created at
    ///   most once; re-creating it would fork every peer (WrongGroupId).
    /// * The SAME original cap is presented every time (see the credential
    ///   invariant at the top of this file): the hub's identity-bound
    ///   resume admission is what re-admits a paired agent whose single-use
    ///   invite is long spent.
    /// * Transport errors retry indefinitely with capped backoff; a
    ///   permanent verdict (rejection, refused downgrade, local build
    ///   fault) fails the handle closed rather than masquerade as
    ///   "reconnecting" forever.
    ///
    /// Returns the fresh connection, or `None` when terminal (store state
    /// already marked either way).
    async fn reconnect(&mut self, detail: String) -> Option<LiveConnection> {
        tracing::warn!(agent = %self.wire_handle, detail = %detail, "hub closed the chat connection; reconnecting");
        // The explicit Reconnecting state: sends fail fast with the
        // retryable transport error, and the close signal is NOT fired
        // (that would masquerade as an explicit stop and abort us).
        let _ = self
            .store
            .mark_reconnecting(&self.handle, Some(detail))
            .await;
        let mut backoff = RECONNECT_BACKOFF_BASE;
        loop {
            tokio::select! {
                _ = &mut self.close_rx => {
                    tracing::info!(agent = %self.wire_handle, "chat reconnect aborted by explicit stop");
                    return None;
                }
                _ = tokio::time::sleep(backoff) => {}
            }
            tracing::info!(agent = %self.wire_handle, "attempting chat reconnect");
            let attempt = tokio::select! {
                _ = &mut self.close_rx => {
                    tracing::info!(agent = %self.wire_handle, "chat reconnect aborted by explicit stop");
                    return None;
                }
                result = connect_and_join(
                    &self.ws_url,
                    &self.channel,
                    &self.wire_handle,
                    &self.dialects,
                    self.cap.as_deref(),
                    self.added_by.as_deref(),
                    self.identity.as_ref(),
                    self.mls.as_mut(),
                    false,
                ) => result,
            };
            match attempt {
                Ok(joined) => {
                    return Some(LiveConnection {
                        websocket: joined.websocket,
                        conn: joined.conn,
                    });
                }
                Err(error) if error.is_retryable() => {
                    tracing::warn!(agent = %self.wire_handle, error = %error, "chat reconnect attempt failed (transient); backing off");
                    backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                }
                Err(error) => {
                    let reason = error.to_string();
                    tracing::warn!(agent = %self.wire_handle, error = %reason, "chat reconnect rejected permanently; failing closed");
                    // Terminal fail-closed: mark_unhealthy fires `close_tx`,
                    // which is correct — we are terminating, not retrying.
                    let _ = self
                        .store
                        .mark_unhealthy(&self.handle, "reconnect_rejected", Some(reason))
                        .await;
                    return None;
                }
            }
        }
    }

    /// Run one connection's `tokio::select!` receive loop until it exits,
    /// returning the typed reason; [`Self::run`] decides whether to
    /// reconnect. Invariants:
    ///
    /// * A hub-side transport loss — read OR write, on any arm — exits via
    ///   `HubClosed` and fails only the in-flight operation; it never marks
    ///   the handle unhealthy (that would fire `close_tx` and turn the
    ///   reconnect into a phantom stop).
    /// * Dropped MLS protocol batches are safe: transition frames are
    ///   retained durably inside the `MlsSession` and re-driven on rejoin
    ///   and peer presence; everything else is regenerated by its trigger.
    async fn run_connection(&mut self, live: &mut LiveConnection) -> LoopExit {
        let Self {
            store,
            handle,
            identity,
            responder,
            mls,
            close_rx,
            send_rx,
            wire_handle,
            claim_window,
            liveness_timeout,
            receive_all,
            ..
        } = self;
        let identity: &ChatIdentity = identity.as_ref();
        let wire_handle = wire_handle.as_str();
        let claim_window = *claim_window;
        let liveness_timeout = *liveness_timeout;
        let receive_all = *receive_all;
        let LiveConnection { websocket, conn } = live;
        // Pending Δ-window and liveness-fallback timers, fired into the select.
        // Fresh per connection: any in-flight claims are moot once the hub
        // restarts — so the reused Responder's ask coordination is reset in
        // lockstep (an AskState with no backing timer would swallow a
        // replayed ask as a duplicate forever).
        let mut timers: FuturesUnordered<BoxFuture<'static, ClaimTimer>> = FuturesUnordered::new();
        responder.reset_pending();
        loop {
            tokio::select! {
                _ = &mut *close_rx => {
                    let _ = websocket.close(None).await;
                    return LoopExit::Stopped;
                }
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        let _ = store.mark_unhealthy(handle, "local_send_failed", Some("chat send channel closed".to_owned())).await;
                        return LoopExit::LocalClosed;
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
                                    let _ = outbound.result_tx.send(Err(OutboundReject::not_ready(format!("mls encrypt refused: {error}"))));
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
                    let frame = conn.sign_chat_frame(identity, &payload);
                    match websocket.send(WsMessage::Binary(frame.into())).await {
                        Ok(()) => { let _ = outbound.result_tx.send(Ok(())); }
                        Err(error) => {
                            // A WS write failure is a transport loss the read
                            // arm hasn't observed yet: fail ONLY this
                            // in-flight send with the Reconnecting reject
                            // (non-poisoning, and the API reports a transport
                            // outage rather than a spurious MLS wait), then
                            // exit via HubClosed. Never mark_unhealthy here —
                            // it fires `close_tx`, turning the reconnect into
                            // a phantom stop.
                            let detail = sanitize(&error.to_string());
                            let _ = outbound.result_tx.send(Err(OutboundReject::reconnecting(format!(
                                "connection to the hub lost; reconnecting: {detail}"
                            ))));
                            return LoopExit::HubClosed(detail);
                        }
                    }
                }
                // A responder timer fired (guarded so an empty set does not busy-loop).
                maybe_timer = timers.next(), if !timers.is_empty() => {
                    let Some(timer) = maybe_timer else { continue };
                    match timer {
                        ClaimTimer::Window(ask_id) => match responder.on_window_closed(&ask_id) {
                            WindowOutcome::Win(payload) => {
                                if store.enqueue_inbound(handle, payload).await.is_err() { return LoopExit::LocalClosed; }
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
                                if store.enqueue_inbound(handle, payload).await.is_err() { return LoopExit::LocalClosed; }
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
                        // The hub dropped us: return HubClosed so the outer loop
                        // reconnects. Do NOT mark_unhealthy here — that fires the
                        // close signal (see mark_reconnecting) and would abort the
                        // reconnect; the outer loop marks `reconnecting` instead.
                        Some(Ok(WsMessage::Close(frame))) => {
                            let detail = frame.map(|f| format!("code={:?} reason=\"{}\"", f.code, f.reason))
                                .unwrap_or_else(|| "no close frame".to_owned());
                            return LoopExit::HubClosed(sanitize(&detail));
                        }
                        None => {
                            return LoopExit::HubClosed("hub WebSocket stream ended".to_owned());
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            return LoopExit::HubClosed(sanitize(&error.to_string()));
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
                                // An MLS protocol-frame write failure is a
                                // transport loss — exit via HubClosed (never
                                // mark_unhealthy; see the write-failure
                                // invariant above). Dropping the rest of the
                                // batch is safe: transition frames are
                                // retained durably in the MlsSession and
                                // re-driven on rejoin and peer presence; the
                                // rest (keyget/idkey/keyready) regenerate
                                // from their own triggers.
                                let mut write_failure = None;
                                for text in outbound {
                                    let Ok(payload) = payload_bytes(&text) else { continue };
                                    let frame = conn.sign_chat_frame(identity, &payload);
                                    if let Err(error) = websocket.send(WsMessage::Binary(frame.into())).await {
                                        write_failure = Some(sanitize(&error.to_string()));
                                        break;
                                    }
                                }
                                if let Some(detail) = write_failure {
                                    return LoopExit::HubClosed(detail);
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
                            == Some(wire_handle);
                        if !own
                            && store
                                .enqueue_inbound(handle, responder_text.clone())
                                .await
                                .is_err()
                        {
                            return LoopExit::LocalClosed;
                        }
                    }
                    // The responder decides: claim for answerable asks, deliver to
                    // `recv` only when elected, drop everything else (REQ-002).
                    let mut write_failure = None;
                    for action in responder.on_inbound(&responder_text) {
                        let Action::Claim { ask_id, frame_text } = action;
                        match payload_bytes(&frame_text) {
                            Ok(payload) => {
                                let frame = conn.sign_chat_frame(identity, &payload);
                                if let Err(error) = websocket.send(WsMessage::Binary(frame.into())).await {
                                    // A claim-frame write failure is a transport
                                    // loss — exit via HubClosed (never
                                    // mark_unhealthy; see the invariant above).
                                    write_failure = Some(sanitize(&error.to_string()));
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
                    if let Some(detail) = write_failure {
                        return LoopExit::HubClosed(detail);
                    }
                }
            }
        }
    }
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

    // (The renewal-invite machinery and its tests are gone: reconnect
    // credentials are the hub's identity-bound resume admission, granted
    // atomically with every private-room admission — see cbcl-chat-resume
    // and the credential invariant at the top of this file.)

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

    /// The reconnect classifier retries only transient transport
    /// failures and terminates (fail-closed) on every permanent verdict.
    /// In particular `DowngradeRefused` MUST be permanent: the reused
    /// `MlsSession` is now permanently downgrade-refused, so a retry that later
    /// saw `:enc true` would falsely "recover" a session whose `encrypt_outbound`
    /// rejects forever — and the rejoin would already have emitted control frames.
    #[test]
    fn reconnect_error_classification_retries_transport_terminates_permanent() {
        use super::ChatError;
        use std::time::Duration;

        // RETRYABLE: transient hub-down / transport.
        assert!(ChatError::ConnectionFailed("reset".into()).is_retryable());
        assert!(ChatError::HelloSendFailed("broken pipe".into()).is_retryable());
        assert!(ChatError::JoinTimeout(Duration::from_secs(10)).is_retryable());
        // The hub's admission-store fault slug is a storage outage, not a
        // membership verdict — the hub emits it distinctly from
        // forbidden-room so the reconnect loop retries once storage recovers.
        assert!(ChatError::JoinRejected("admission-store-unavailable".into()).is_retryable());

        // PERMANENT: fail-closed, terminate the reconnect loop.
        assert!(!ChatError::JoinRejected("forbidden-room".into()).is_retryable());
        assert!(!ChatError::JoinRejected("no-such-channel".into()).is_retryable());
        assert!(!ChatError::DowngradeRefused("enc pin".into()).is_retryable());
        assert!(
            !ChatError::UndeclaredDialect {
                dialect: "cite".into(),
                declared: vec![],
            }
            .is_retryable()
        );
        assert!(!ChatError::Hello("announce invalid".into()).is_retryable());
        assert!(!ChatError::Store("rejected".into()).is_retryable());
    }
}
