//! The DAEMON pull task (ADR-035 effectful shell). One task per `mls-ds/v1` room: it owns
//! the DS WebSocket + [`DsWire`] + [`PullDriver`], runs the pull loop, and hands each
//! ADMITTED record's embedded frame to the receive loop (which owns the `MlsSession`) for
//! the CON-006 MLS apply + the CON-013 atomic commit (`persist_v1_state`).
//!
//! Division of durable responsibility: the SESSION commits `(provider snapshot, ClientLog)`
//! in one manifest-flip after a successful apply — this task never writes the cursor. On
//! restart the caller reloads the durable `ClientLog` (`load_v1_state`) and hands it back
//! here as `initial_log`, so a crash between admit and apply simply re-pulls the record
//! (idempotent: DS records are immutable and exact-next).
//!
//! Pins owned HERE (in `state_dir`): the immutable genesis `anchor` and the DS
//! verification key `ds.pk` — TOFU-pinned from the first `genesis-anchor` response
//! (interim until CON-009 attestation rides pairing) and never overwritten; a later
//! response disagreeing with a saved pin is ds-key-substitution / anchor conflict and
//! stops the loop with evidence logged.
//!
//! Reconnect: the DS socket rides hub restarts with the same bounded backoff the chat
//! socket uses — the durable cursor makes resume trivial (re-pull from where we were).
//!
//! NOT here yet (documented gaps, closed with the hub's real record schema): Add-auth
//! evidence (`boundary::validate_v1_commit`) — the interim `log-v1` record carries no
//! AddAuth tuple; H7 owner-removal rejection IS active via `mark_v1` in the session's
//! own `process_inbound` gate.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use super::pull::{PullAction, PullDriver};
use super::wire::{pk32, DsInbound, DsWire};
use super::{ClientLog, Verdict};
use cbcl_core::sexpr::{Atom, SExpr};

/// The all-zero genesis cursor hash (cursor 0, before any record).
pub const GENESIS_CURSOR_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Configuration for one room's pull task.
pub struct DsPullConfig {
    /// The DS endpoint (`ws(s)://hub/mls-ds/v1`), derived from the chat hub URL.
    pub ds_url: String,
    pub room: String,
    /// Pin directory (genesis anchor + TOFU DS key).
    pub state_dir: PathBuf,
    /// How long to sleep when the log is at head before re-pulling.
    pub poll: Duration,
    /// The durable cursor reloaded by the session (CON-013), or genesis-zero.
    pub initial_log: ClientLog,
}

/// One admitted record, handed to the receive loop for MLS apply + atomic commit.
#[derive(Debug)]
pub struct DsApply {
    /// The embedded wire frame the record carries (the MLS/CBCL frame to apply).
    pub payload: String,
    /// The admitted record's seq — used as the CON-013 store generation.
    pub generation: u64,
    /// The post-admission durable tuple the session must commit with the snapshot.
    pub log: ClientLog,
}

fn read_pin(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name)).ok().map(|s| s.trim().to_string())
}
fn write_pin(dir: &Path, name: &str, value: &str) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(name), value);
}

/// Extract the embedded payload frame from an interim `log-v1` record:
/// `(log-v1 "<room>" <seq> "<prev>" "<payload-text>")`. Records without a
/// payload (e.g. bootstrap markers) apply as no-ops.
pub fn record_payload(log_record: &SExpr) -> Option<String> {
    let SExpr::List(items) = log_record else { return None };
    match items.first() {
        Some(SExpr::Atom(Atom::Symbol(s))) if s == "log-v1" => {}
        _ => return None,
    }
    match items.get(4) {
        Some(SExpr::Atom(Atom::Str(payload))) => Some(payload.clone()),
        _ => None,
    }
}

/// Spawn the per-room DS pull loop. Ends only on room closure, an equivocation
/// violation (evidence logged, cursor held), or the apply channel closing (the
/// receive loop went away).
pub fn spawn_ds_pull_loop(cfg: DsPullConfig, apply_tx: mpsc::Sender<DsApply>) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            match run_connection(&cfg, &apply_tx).await {
                LoopEnd::Terminal(reason) => {
                    tracing::info!(room = %cfg.room, reason, "ds pull loop ended");
                    return;
                }
                LoopEnd::Reconnect(reason) => {
                    tracing::debug!(room = %cfg.room, reason, backoff = ?backoff, "ds socket dropped; reconnecting");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

enum LoopEnd {
    /// Stop for good (closure, violation, apply channel gone).
    Terminal(&'static str),
    /// Transport drop — reconnect with backoff, cursor intact.
    Reconnect(&'static str),
}

async fn run_connection(cfg: &DsPullConfig, apply_tx: &mpsc::Sender<DsApply>) -> LoopEnd {
    let (mut ws, _) = match connect_async(&cfg.ds_url).await {
        Ok(pair) => pair,
        Err(_) => return LoopEnd::Reconnect("connect failed"),
    };

    let mut anchor = read_pin(&cfg.state_dir, "anchor");
    let mut ds_vk: Option<[u8; 32]> =
        read_pin(&cfg.state_dir, "ds.pk").and_then(|h| pk32(&h).ok());
    let mut wire = DsWire::new(&cfg.room);
    let mut driver = PullDriver::new(cfg.initial_log.clone(), anchor.clone());

    loop {
        // Choose the next request: genesis first when unpinned, else pull.
        let request = if anchor.is_none() || ds_vk.is_none() {
            wire.genesis_get_request()
        } else {
            match driver.next_pull() {
                PullAction::Pull { after_seq } => wire.next_record_request(after_seq),
                PullAction::Waiting => {
                    // Should not happen (one request per response below), but never busy-loop.
                    tokio::time::sleep(cfg.poll).await;
                    continue;
                }
            }
        };
        let request = match request {
            Ok(text) => text,
            Err(reason) => {
                tracing::warn!(room = %cfg.room, reason, "ds request refused by own recogniser");
                return LoopEnd::Terminal("request build failed");
            }
        };
        if ws.send(WsMessage::text(request)).await.is_err() {
            return LoopEnd::Reconnect("send failed");
        }
        let Some(Ok(message)) = ws.next().await else {
            return LoopEnd::Reconnect("stream ended");
        };
        let text = match message {
            WsMessage::Text(text) => text.to_string(),
            WsMessage::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            WsMessage::Close(_) => return LoopEnd::Reconnect("hub closed"),
            _ => continue,
        };
        match wire.inbound(&text) {
            Err(reason) => {
                // CON-011/CON-012 fail-closed: drop the frame, hold the cursor. The
                // outstanding slot stays consumed; re-pull on the next iteration.
                tracing::warn!(room = %cfg.room, reason, "ds frame rejected (fail-closed)");
                tokio::time::sleep(cfg.poll).await;
            }
            Ok(DsInbound::GenesisAnchor { anchor: got_anchor, ds_vk: got_vk }) => {
                // TOFU: pin on first contact; afterwards any disagreement is terminal.
                match (&anchor, &ds_vk) {
                    (None, _) | (_, None) => {
                        write_pin(&cfg.state_dir, "anchor", &got_anchor);
                        let hex: String = got_vk.iter().map(|b| format!("{b:02x}")).collect();
                        write_pin(&cfg.state_dir, "ds.pk", &hex);
                        anchor = Some(got_anchor.clone());
                        ds_vk = Some(got_vk);
                        // The driver binds records to the saved anchor from here on.
                        driver = PullDriver::new(driver.cursor().clone(), anchor.clone());
                    }
                    (Some(saved_anchor), Some(saved_vk)) => {
                        if *saved_anchor != got_anchor || *saved_vk != got_vk {
                            tracing::error!(room = %cfg.room, "genesis-anchor/ds-key pin conflict — ds-equivocation, stopping with evidence");
                            return LoopEnd::Terminal("pin conflict");
                        }
                    }
                }
            }
            Ok(DsInbound::Record(resp)) => {
                let Some(vk) = ds_vk else {
                    // No key pinned yet — cannot verify; re-enter the genesis path.
                    continue;
                };
                match driver.on_record(&vk, &resp) {
                    Verdict::Applied { cursor, cursor_hash } => {
                        let log = ClientLog { cursor, cursor_hash };
                        if let Some(payload) = record_payload(&resp.log_record) {
                            let apply = DsApply {
                                payload,
                                generation: cursor as u64,
                                log,
                            };
                            if apply_tx.send(apply).await.is_err() {
                                return LoopEnd::Terminal("apply channel closed");
                            }
                        }
                        // No payload = a marker record; the cursor still advanced in
                        // memory and will be committed with the next payload apply.
                    }
                    Verdict::AwaitingGenesis => {
                        // Pins missing — loop re-enters the genesis path above.
                        anchor = None;
                    }
                    Verdict::NotNext => {
                        // The DS answered off-position (e.g. a raced head) — hold and re-pull.
                        tokio::time::sleep(cfg.poll).await;
                    }
                    Verdict::Violation(code) => {
                        tracing::error!(room = %cfg.room, code, "ds-equivocation — cursor held, evidence retained, stopping");
                        return LoopEnd::Terminal("equivocation");
                    }
                }
            }
            Ok(DsInbound::AtHead { .. }) => {
                tokio::time::sleep(cfg.poll).await;
            }
            Ok(DsInbound::Rejected(reason)) => {
                tracing::warn!(room = %cfg.room, reason, "ds rejected the request");
                tokio::time::sleep(cfg.poll).await;
            }
            Ok(DsInbound::RoomClosed) => {
                tracing::info!(room = %cfg.room, "room closed at the DS (H10) — pull loop ends");
                return LoopEnd::Terminal("room closed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(s: &str) -> SExpr {
        SExpr::Atom(Atom::Str(s.into()))
    }
    fn sym(s: &str) -> SExpr {
        SExpr::Atom(Atom::Symbol(s.into()))
    }
    fn num(n: i64) -> SExpr {
        SExpr::Atom(Atom::Num(n))
    }

    #[test]
    fn record_payload_extracts_only_wellformed_log_v1() {
        let with = SExpr::List(vec![
            sym("log-v1"), st("r"), num(1), st("sha256:x"), st("(say @r :from @a)"),
        ]);
        assert_eq!(record_payload(&with).as_deref(), Some("(say @r :from @a)"));
        let marker = SExpr::List(vec![sym("log-v1"), st("r"), num(1), st("sha256:x")]);
        assert_eq!(record_payload(&marker), None);
        let alien = SExpr::List(vec![sym("other"), st("r")]);
        assert_eq!(record_payload(&alien), None);
    }

    #[test]
    fn pins_roundtrip_via_files() {
        let dir = std::env::temp_dir().join(format!("hark-ds-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read_pin(&dir, "anchor").is_none());
        write_pin(&dir, "anchor", "sha256:abc");
        assert_eq!(read_pin(&dir, "anchor").as_deref(), Some("sha256:abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
