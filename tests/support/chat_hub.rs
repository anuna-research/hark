//! A scriptable fake `/chat/v1` hub for the [[SPEC-026]] transport-resilience tests.
//!
//! It is a *real* `tokio-tungstenite` server on `127.0.0.1:0` speaking the genuine
//! wire formats — hub→client frames are `len(4) ‖ payload ‖ sig(64)`
//! (`hark::chat_frame::decode_payload`), client→hub frames are
//! `len(4) ‖ seq(8) ‖ payload ‖ sig(64)` (`hark::signed_frame::decode_frame`) —
//! so nothing about hark is mocked. Only the *peer* is fake, which is the point:
//! the behaviour under test is what hark does when a real socket to a real peer
//! ends (Constitutional Principle 5, integration-first testing).
//!
//! The hub is scripted per connection. A test says "accept, then drop, then
//! accept" and the harness plays exactly that, recording every payload it
//! received on each connection so the test can assert the re-join replayed the
//! `hello` and the `announce`.
//!
//! The hub does **not** verify signatures. hark's signing path is covered by
//! `tests/signed_handshake_live.rs` and by the live-hub tests; re-implementing
//! `verify-sender` here would be a second recogniser for the same language and
//! would test the fake rather than hark.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// What the hub does on one connection, after it has sent the conn-nonce
/// bootstrap and read the client's `hello`.
#[derive(Debug, Clone)]
pub enum Act {
    /// Acknowledge the join with `(roomcfg <channel> :enc <enc>)`, then stay open
    /// until the client goes away or the script says otherwise.
    Accept { enc: bool },
    /// Acknowledge as `Accept`, then close the socket after `after_frames` further
    /// client frames have been read (0 = close immediately after the ack). This is
    /// the hub redeploy: an ordinary member socket that simply ends.
    AcceptThenDrop { enc: bool, after_frames: usize },
    /// Acknowledge as `Accept`, then push `send` at the client — the hub's
    /// backfill-on-join, which a real hub replays after every successful
    /// `hello` (`backfill_n`, 50 by default).
    AcceptAndSend { enc: bool, send: Vec<String> },
    /// `AcceptAndSend`, then drop the socket. The redeploy that happens after
    /// the client has already seen some history.
    AcceptThenDropAfterSending { enc: bool, send: Vec<String> },
    /// Reject the join outright: `(error <channel> "<slug>")`, socket left open,
    /// exactly as cbcl-bus does.
    Reject { slug: String },
    /// Accept the TCP/WebSocket upgrade and then say nothing at all — not even the
    /// bootstrap. Models a hub that is up but not serving.
    Stall,
}

/// The transcript of one connection: every CBCL payload the hub read from the
/// client, in order.
pub type Transcript = Vec<String>;

/// A running fake hub.
pub struct FakeHub {
    addr: SocketAddr,
    transcripts: Arc<Mutex<Vec<Transcript>>>,
    /// How many connections the hub has seen END — the client went away or the
    /// socket was dropped. This is the only way a test can observe that hark
    /// let go of a socket, which is what distinguishes "the loop noticed" from
    /// "the loop is still sitting in a handshake timeout".
    ended: Arc<Mutex<usize>>,
}

impl FakeHub {
    /// Start a hub that plays `script` — one entry per accepted connection. When
    /// the script runs out, further connections are refused by simply not being
    /// accepted (the listener is dropped), which is what a down hub looks like.
    pub async fn start(script: Vec<Act>) -> Self {
        Self::start_inner(script, "@general").await
    }

    /// As [`FakeHub::start`], for a channel other than `@general`.
    pub async fn start_for(script: Vec<Act>, channel: &str) -> Self {
        Self::start_inner(script, channel).await
    }

    async fn start_inner(script: Vec<Act>, channel: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake hub should bind a loopback port");
        let addr = listener
            .local_addr()
            .expect("fake hub should report its address");
        let transcripts = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&transcripts);
        let ended = Arc::new(Mutex::new(0usize));
        let ended_writer = Arc::clone(&ended);
        let channel = channel.to_owned();

        tokio::spawn(async move {
            for act in script {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let index = {
                    let mut all = recorded.lock().expect("transcript lock");
                    all.push(Vec::new());
                    all.len() - 1
                };
                let recorded = Arc::clone(&recorded);
                let ended_writer = Arc::clone(&ended_writer);
                let channel = channel.clone();
                // Each connection is served concurrently, but the transcript
                // slot is claimed at *accept* time above, so slot order is
                // still connection order. Concurrency matters for the daemon
                // restart tests, where the old connection is still draining
                // while the replacement daemon dials in.
                tokio::spawn(async move {
                    serve(stream, act, channel, recorded, index).await;
                    *ended_writer.lock().expect("ended lock") += 1;
                });
            }
            // Script exhausted: drop the listener so later attempts get a refusal
            // rather than an accepted-but-silent socket.
            drop(listener);
        });

        Self {
            addr,
            transcripts,
            ended,
        }
    }

    /// How many connections have ended (client gone / socket dropped).
    pub fn ended(&self) -> usize {
        *self.ended.lock().expect("ended lock")
    }

    /// Wait until at least `n` connections have ended, or `timeout` elapses.
    pub async fn wait_for_ended(&self, n: usize, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.ended() >= n {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.ended() >= n
    }

    /// The `ws://…/chat/v1` URL to point an agent at.
    pub fn ws_url(&self) -> String {
        format!("ws://{}/chat/v1", self.addr)
    }

    /// How many connections have been accepted so far.
    pub fn connections(&self) -> usize {
        self.transcripts.lock().expect("transcript lock").len()
    }

    /// The payloads read on connection `index` (0-based), in order.
    pub fn transcript(&self, index: usize) -> Transcript {
        self.transcripts
            .lock()
            .expect("transcript lock")
            .get(index)
            .cloned()
            .unwrap_or_default()
    }

    /// Wait until at least `n` connections have been accepted, or `timeout`
    /// elapses. Returns whether the count was reached.
    pub async fn wait_for_connections(&self, n: usize, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.connections() >= n {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.connections() >= n
    }

    /// Wait until connection `index`'s transcript holds a payload whose text
    /// contains `needle`, or `timeout` elapses.
    pub async fn wait_for_frame(
        &self,
        index: usize,
        needle: &str,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self
                .transcript(index)
                .iter()
                .any(|frame| frame.contains(needle))
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }
}

/// Frame a hub→client payload: `len(4, big-endian) ‖ payload ‖ sig(64)`. The
/// signature region is filler — hark does not verify inbound signatures (the real
/// hub verifies every signer before fan-out, so a delivered frame's payload is
/// already custody-checked; see `src/chat_frame.rs`).
pub fn hub_frame(payload: &str) -> Vec<u8> {
    let bytes = payload.as_bytes();
    let mut frame = Vec::with_capacity(4 + bytes.len() + 64);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame.extend_from_slice(&[0u8; 64]);
    frame
}

/// The bootstrap every real connection leads with.
fn bootstrap() -> String {
    // The nonce is base64 of 16 fixed bytes: the client only needs *a* nonce to
    // prime its per-connection signer.
    "(tell @client \"conn-nonce\" :from @cbcl-chat \
     :nonce \"BwcHBwcHBwcHBwcHBwcHBw==\" :hub \"cbcl-chat\")"
        .to_owned()
}

async fn serve(
    stream: tokio::net::TcpStream,
    act: Act,
    channel: String,
    recorded: Arc<Mutex<Vec<Transcript>>>,
    index: usize,
) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    if matches!(act, Act::Stall) {
        // Up, but serving nothing. The client's join timeout must fire.
        let _ = ws.next().await;
        return;
    }
    if ws
        .send(Message::Binary(hub_frame(&bootstrap()).into()))
        .await
        .is_err()
    {
        return;
    }

    let mut frames_after_ack = 0usize;
    let mut acked = false;
    while let Some(Ok(message)) = ws.next().await {
        let Message::Binary(bytes) = message else {
            continue;
        };
        let Some((_seq, payload, _sig)) = hark::signed_frame::decode_frame(&bytes) else {
            continue;
        };
        let text = String::from_utf8_lossy(payload).into_owned();
        let is_hello = text.starts_with("(hello ");
        recorded
            .lock()
            .expect("transcript lock")
            .get_mut(index)
            .expect("transcript slot exists")
            .push(text);

        if is_hello && !acked {
            acked = true;
            let reply = match &act {
                Act::Reject { slug } => format!("(error {channel} \"{slug}\")"),
                Act::Accept { enc }
                | Act::AcceptThenDrop { enc, .. }
                | Act::AcceptAndSend { enc, .. }
                | Act::AcceptThenDropAfterSending { enc, .. } => {
                    format!("(roomcfg {channel} :enc {enc})")
                }
                Act::Stall => unreachable!("handled above"),
            };
            if ws
                .send(Message::Binary(hub_frame(&reply).into()))
                .await
                .is_err()
            {
                return;
            }
            // Backfill-on-join: a real hub replays the room's recent history
            // straight after the ack, on EVERY successful hello — including a
            // reconnect's.
            if let Act::AcceptAndSend { send, .. } | Act::AcceptThenDropAfterSending { send, .. } =
                &act
            {
                for frame in send {
                    if ws
                        .send(Message::Binary(hub_frame(frame).into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                if matches!(act, Act::AcceptThenDropAfterSending { .. }) {
                    // Give the client a beat to read the backfill before the
                    // socket disappears under it.
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    return;
                }
            }
            if let Act::AcceptThenDrop {
                after_frames: 0, ..
            } = act
            {
                // Drop without a close frame — the TLS-less analogue of the
                // "peer closed connection without sending close_notify" the
                // incident report shows.
                return;
            }
            continue;
        }

        if acked {
            frames_after_ack += 1;
            if let Act::AcceptThenDrop { after_frames, .. } = act {
                if frames_after_ack >= after_frames {
                    return;
                }
            }
        }
    }
}
