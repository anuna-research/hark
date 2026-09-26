//! SPEC-086 — object transport for SDK agents.
//!
//! Hark carries hypermedia-object messages (`(lang object-<64hex> …)`) and
//! attests their authorship; it never interprets them (SPEC-086 ADR-001,
//! REQ-007). This module holds the pure parts of that contract:
//!
//! - the object-dialect recogniser, identical to the browser's
//!   `isSDKDialect` (`/^object-[0-9a-f]{64}$/`), so hark and the SDK agree on
//!   which frames are object messages;
//! - the [`ObjectRecord`] the `recv` response carries beside the message bytes
//!   (SPEC-086 CON-001), and the rule that derives it from how the receive
//!   loop authenticated the frame (REQ-006);
//! - the `(history …)` request frame (CON-002) and the hub's `backfilltimes`
//!   announcement (cbcl-bus SPEC-070), which together let the loop mark a
//!   frame `replayed`.
//!
//! Nothing here touches a socket or a store; the receive loop in
//! [`crate::chat`] drives it.

use std::time::{Duration, Instant};

use cbcl_core::sexpr::{Atom, SExpr};
use serde::{Deserialize, Serialize};

/// Who established the signer of an object message (SPEC-086 REQ-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestedBy {
    /// The MLS group authenticated the sender; the record's signer is the
    /// MLS sender handle, not the inner `:from`.
    Mls,
    /// The hub accepted the frame under its signed-member check; the signer is
    /// the frame's inner `:from`.
    Hub,
}

/// The attestation record delivered beside an object message (SPEC-086
/// CON-001). It carries no cid: only the SDK computes cids (ADR-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    /// The room handle the frame arrived on.
    pub room: String,
    /// The handle established by REQ-006.
    pub signer: String,
    pub attested_by: AttestedBy,
    /// `signer` is this agent's own wire handle.
    pub own: bool,
    /// The frame arrived in join/reconnect backfill or in a history reply.
    pub replayed: bool,
}

/// How the receive loop authenticated a content frame before offering it for
/// object delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// A cleartext frame the hub delivered; authorship is its inner `:from`.
    Hub,
    /// A frame decrypted by the MLS session; `sender` is the MLS-authenticated
    /// member handle (the session has already dropped any `:from` mismatch —
    /// SPEC-013 REQ-018, SPEC-086 REQ-006).
    Mls { sender: String },
}

/// The hub clamps `(history …)` replies to this many frames (cbcl-bus
/// `cbcl-store-core:clamp-limit`). SPEC-086 CON-002 admits up to 1000; the
/// difference is documented, not enforced here.
pub const HISTORY_LIMIT_MAX: usize = 1000;

/// How long after a `(history …)` request the first reply frame may take
/// before the phase lapses and later frames count as live traffic.
const HISTORY_FIRST_REPLY: Duration = Duration::from_secs(5);

/// The hub emits a history reply contiguously on one socket. A gap this long
/// between two frames means the reply has ended and live traffic resumed.
const HISTORY_SETTLE: Duration = Duration::from_millis(1500);

/// The object dialect named by `text`'s outer `(lang …)` wrapper, when it is an
/// SDK object dialect: `object-` followed by exactly 64 lowercase hex digits.
///
/// Textual on purpose: it must agree with the browser's regex recogniser and
/// must not depend on the message parsing under any stricter grammar — an
/// object message hark cannot fully parse is still an object message hark must
/// not drop (REQ-007). Leading whitespace is tolerated; the name must be
/// followed by whitespace, so `object-<hex>x` is not a match.
pub fn object_dialect(text: &str) -> Option<&str> {
    let rest = text.trim_start().strip_prefix("(lang")?;
    // `(lang` must be followed by at least one whitespace character.
    let rest = rest.strip_prefix(|c: char| c.is_whitespace())?;
    let rest = rest.trim_start();
    let name = rest.strip_prefix("object-")?;
    let hex: &str = name.get(..64)?;
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    match name[64..].chars().next() {
        Some(c) if c.is_whitespace() => Some(&rest[..7 + 64]),
        _ => None,
    }
}

/// Whether `text` is an object content message (REQ-001).
pub fn is_object_message(text: &str) -> bool {
    object_dialect(text).is_some()
}

/// The `:from` of the message inside the `(lang …)` wrapper — the inner
/// Simple's sender, the cbcl-chat convention. Parsed structurally; a message
/// the parser rejects falls back to a textual scan so an unusual but well-
/// formed object message still yields its signer.
pub fn inner_from(text: &str) -> Option<String> {
    if let Ok(SExpr::List(items)) = cbcl_parser::parse(text) {
        let inner = match items.first() {
            Some(SExpr::Atom(Atom::Symbol(head))) if head == "lang" => items.get(2),
            _ => Some(&SExpr::List(items.clone())),
        };
        if let Some(SExpr::List(inner)) = inner {
            let mut iter = inner.iter();
            while let Some(item) = iter.next() {
                if let SExpr::Atom(Atom::Keyword(key)) = item {
                    if key == "from" {
                        return match iter.next() {
                            Some(SExpr::Atom(Atom::Symbol(value)))
                            | Some(SExpr::Atom(Atom::Str(value))) => Some(value.clone()),
                            _ => None,
                        };
                    }
                }
            }
            return None;
        }
    }
    textual_from(text)
}

/// Fallback `:from` extraction: the token after the last ` :from `.
fn textual_from(text: &str) -> Option<String> {
    let index = text.rfind(":from ")?;
    let rest = text[index + ":from ".len()..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ')' && *c != '"')
        .collect();
    (!token.is_empty()).then_some(token)
}

/// Build the record for an object message, or `None` when no signer can be
/// established (REQ-006: hark MUST NOT deliver an object record without one).
///
/// - MLS: the signer is the MLS sender, whatever the inner `:from` says (the
///   session already refused a mismatch).
/// - Hub: the signer is the inner `:from`; a frame without one is not
///   delivered as an object record.
pub fn object_record(
    text: &str,
    attestation: &Attestation,
    wire_handle: &str,
    room: &str,
    replayed: bool,
) -> Option<ObjectRecord> {
    if !is_object_message(text) {
        return None;
    }
    let (signer, attested_by) = match attestation {
        Attestation::Mls { sender } => (sender.clone(), AttestedBy::Mls),
        Attestation::Hub => (inner_from(text)?, AttestedBy::Hub),
    };
    Some(ObjectRecord {
        room: room.to_owned(),
        own: signer == wire_handle,
        signer,
        attested_by,
        replayed,
    })
}

/// The number of frames a hub `(backfilltimes @room :times (…))` announcement
/// says are about to be replayed (cbcl-bus SPEC-070 CON-001), or `None` for
/// any other frame. The times themselves are not needed: the count is the
/// end-of-backfill marker.
pub fn parse_backfilltimes(text: &str) -> Option<usize> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(symbol)) if symbol == "backfilltimes" => {}
        _ => return None,
    }
    let mut iter = items.iter();
    while let Some(item) = iter.next() {
        if let SExpr::Atom(Atom::Keyword(key)) = item {
            if key == "times" {
                return match iter.next() {
                    Some(SExpr::List(times)) => Some(times.len()),
                    _ => Some(0),
                };
            }
        }
    }
    Some(0)
}

/// The `(history <room> :limit <n> :from <handle>)` request (SPEC-086 CON-002).
pub fn history_request_frame(room: &str, limit: usize, from: &str) -> String {
    format!("(history {room} :limit {limit} :from {from})")
}

/// The `:limit` of a `(history …)` frame, or `None` for any other frame. The
/// receive loop reads its own outbound request this way to arm the replay
/// accounting, so no second channel has to carry the limit.
pub fn history_request_limit(text: &str) -> Option<usize> {
    let SExpr::List(items) = cbcl_parser::parse(text).ok()? else {
        return None;
    };
    match items.first()? {
        SExpr::Atom(Atom::Symbol(symbol)) if symbol == "history" => {}
        _ => return None,
    }
    let mut iter = items.iter();
    while let Some(item) = iter.next() {
        if let SExpr::Atom(Atom::Keyword(key)) = item {
            if key == "limit" {
                return match iter.next() {
                    Some(SExpr::Atom(Atom::Num(n))) if *n > 0 => Some(*n as usize),
                    Some(SExpr::Atom(Atom::Symbol(n))) => n.parse().ok(),
                    _ => None,
                };
            }
        }
    }
    None
}

/// Tracks which inbound frames are replays — hub backfill after a hello, or
/// the reply to a `(history …)` request — so the [`ObjectRecord::replayed`]
/// flag can be set (SPEC-086 CON-001).
///
/// Backfill is exact: the hub announces the count ahead of the run
/// (SPEC-070), and the run is contiguous on the socket. A history reply has no
/// marker, so it is bounded positionally by the requested limit and
/// temporally by a settle gap; a live frame that lands inside the reply is
/// mislabelled, which the SDK tolerates (it deduplicates by cid and treats
/// `replayed` as advisory).
#[derive(Debug, Default)]
pub struct ReplayAccounting {
    backfill_remaining: usize,
    history: Option<HistoryPhase>,
}

#[derive(Debug)]
struct HistoryPhase {
    remaining: usize,
    deadline: Instant,
}

impl ReplayAccounting {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new socket: whatever the old one was replaying is over. The new
    /// hello brings its own `backfilltimes`.
    pub fn on_join(&mut self) {
        self.backfill_remaining = 0;
        self.history = None;
    }

    /// The hub announced `count` replayed frames.
    pub fn note_backfilltimes(&mut self, count: usize) {
        self.backfill_remaining = count;
    }

    /// A `(history …)` request with `limit` went out at `now`.
    pub fn note_history_request(&mut self, limit: usize, now: Instant) {
        self.history = Some(HistoryPhase {
            remaining: limit,
            deadline: now + HISTORY_FIRST_REPLY,
        });
    }

    /// Whether a history request is still being answered at `now`.
    pub fn history_in_flight(&self, now: Instant) -> bool {
        self.history
            .as_ref()
            .is_some_and(|phase| now <= phase.deadline)
    }

    /// Account for one inbound frame read at `now` and report whether it is a
    /// replay. Called for every frame after the `backfilltimes` announcement
    /// itself, including frames later suppressed or consumed as control —
    /// the hub's count is positional over the whole run.
    pub fn classify(&mut self, now: Instant) -> bool {
        if self.backfill_remaining > 0 {
            self.backfill_remaining -= 1;
            return true;
        }
        let Some(phase) = self.history.as_mut() else {
            return false;
        };
        if now > phase.deadline {
            self.history = None;
            return false;
        }
        phase.remaining -= 1;
        phase.deadline = now + HISTORY_SETTLE;
        if phase.remaining == 0 {
            self.history = None;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn object(from: &str) -> String {
        format!(
            "(lang object-{HEX} (check @room :item \"milk\" :caused-by sha256-{HEX} \
             :thread \"list-1\" :from {from}))"
        )
    }

    #[test]
    fn recogniser_matches_the_browsers_sdk_dialect_regex() {
        assert_eq!(
            object_dialect(&object("@alice")),
            Some(format!("object-{HEX}").as_str())
        );
        assert!(is_object_message(&format!(
            "  (lang   object-{HEX}\n (open @r))"
        )));
        // Not object messages: a built-in dialect, wrong hex length, uppercase
        // hex, a trailing character, a bare message, or an unwrapped verb.
        assert!(!is_object_message(
            "(lang poll (vote @trip :date \"sat\" :from @hugo))"
        ));
        assert!(!is_object_message(&format!(
            "(lang object-{} (x @r))",
            &HEX[..63]
        )));
        assert!(!is_object_message(&format!(
            "(lang object-{} (x @r))",
            HEX.to_uppercase()
        )));
        assert!(!is_object_message(&format!("(lang object-{HEX}x (x @r))")));
        assert!(!is_object_message(&format!("(lang object-{HEX})")));
        assert!(!is_object_message("(tell @general \"hi\" :from @bob)"));
        assert!(!is_object_message("(langobject-abc (x @r))"));
    }

    #[test]
    fn inner_from_reads_the_wrapped_messages_sender() {
        assert_eq!(inner_from(&object("@alice")).as_deref(), Some("@alice"));
        // A string-valued :from and an object-spec with escaped quotes parse too.
        let opener = format!(
            "(lang object-{HEX} (open @room :title \"Launch\" :object-spec \"{{\\\"version\\\":2}}\" \
             :caused-by begin :thread \"t\" :from \"@bo\"))"
        );
        assert_eq!(inner_from(&opener).as_deref(), Some("@bo"));
        // No :from → no signer.
        assert_eq!(
            inner_from(&format!("(lang object-{HEX} (check @room :thread \"t\"))")),
            None
        );
        // Unparseable text falls back to the textual scan.
        assert_eq!(
            inner_from("(lang object-x (check @room :from @cy").as_deref(),
            Some("@cy")
        );
    }

    #[test]
    fn hub_attested_record_uses_the_inner_from_and_requires_one() {
        let record = object_record(
            &object("@alice"),
            &Attestation::Hub,
            "@aria",
            "@room",
            false,
        )
        .expect("a signer is established");
        assert_eq!(
            record,
            ObjectRecord {
                room: "@room".into(),
                signer: "@alice".into(),
                attested_by: AttestedBy::Hub,
                own: false,
                replayed: false,
            }
        );
        let own = object_record(&object("@aria"), &Attestation::Hub, "@aria", "@room", true)
            .expect("own message");
        assert!(own.own && own.replayed);
        // TEST-003 negative input: no :from in a cleartext room → no record.
        let anonymous = format!("(lang object-{HEX} (check @room :thread \"t\"))");
        assert_eq!(
            object_record(&anonymous, &Attestation::Hub, "@aria", "@room", false),
            None
        );
        // A non-object message never yields a record.
        assert_eq!(
            object_record(
                "(tell @room \"hi\" :from @alice)",
                &Attestation::Hub,
                "@aria",
                "@room",
                false
            ),
            None
        );
    }

    #[test]
    fn mls_attested_record_uses_the_mls_sender() {
        let attestation = Attestation::Mls {
            sender: "@alice".into(),
        };
        let record = object_record(&object("@alice"), &attestation, "@aria", "@room", false)
            .expect("record");
        assert_eq!(record.attested_by, AttestedBy::Mls);
        assert_eq!(record.signer, "@alice");
        // The MLS sender is authoritative even when the inner :from is absent.
        let anonymous = format!("(lang object-{HEX} (check @room :thread \"t\"))");
        let record =
            object_record(&anonymous, &attestation, "@alice", "@room", false).expect("record");
        assert!(record.own);
    }

    #[test]
    fn record_serialises_to_the_con_001_shape() {
        let record = ObjectRecord {
            room: "@room".into(),
            signer: "@alice".into(),
            attested_by: AttestedBy::Mls,
            own: false,
            replayed: true,
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "room": "@room",
                "signer": "@alice",
                "attested_by": "mls",
                "own": false,
                "replayed": true
            })
        );
        assert_eq!(
            serde_json::to_value(AttestedBy::Hub).unwrap(),
            serde_json::json!("hub")
        );
    }

    #[test]
    fn backfilltimes_count_is_the_end_of_backfill_marker() {
        assert_eq!(
            parse_backfilltimes("(backfilltimes @room :times (1786007287642 1786007287643 0))"),
            Some(3)
        );
        assert_eq!(
            parse_backfilltimes("(backfilltimes @room :times ())"),
            Some(0)
        );
        assert_eq!(parse_backfilltimes("(backfilltimes @room)"), Some(0));
        assert_eq!(parse_backfilltimes("(roomcfg @room :enc false)"), None);
        assert_eq!(parse_backfilltimes("(tell @room \"backfilltimes\")"), None);
    }

    #[test]
    fn history_request_round_trips_its_limit() {
        let frame = history_request_frame("@room", 250, "@aria");
        assert_eq!(frame, "(history @room :limit 250 :from @aria)");
        assert_eq!(history_request_limit(&frame), Some(250));
        assert_eq!(history_request_limit("(history @room :from @aria)"), None);
        assert_eq!(
            history_request_limit("(tell @room \"history\" :limit 3)"),
            None
        );
    }

    #[test]
    fn replay_accounting_marks_backfill_exactly_and_history_by_bound() {
        let mut accounting = ReplayAccounting::new();
        let now = Instant::now();
        assert!(!accounting.classify(now), "nothing announced: live");

        accounting.note_backfilltimes(2);
        assert!(accounting.classify(now));
        assert!(accounting.classify(now));
        assert!(
            !accounting.classify(now),
            "the third frame after two announced is live"
        );

        accounting.note_history_request(2, now);
        assert!(accounting.history_in_flight(now));
        assert!(accounting.classify(now + Duration::from_millis(100)));
        assert!(accounting.classify(now + Duration::from_millis(200)));
        assert!(!accounting.history_in_flight(now + Duration::from_millis(300)));
        assert!(
            !accounting.classify(now + Duration::from_millis(300)),
            "the limit was reached: the next frame is live"
        );

        // A reply that never comes lapses after the first-reply window.
        accounting.note_history_request(10, now);
        assert!(!accounting.classify(now + HISTORY_FIRST_REPLY + Duration::from_secs(1)));
        assert!(!accounting.history_in_flight(now + HISTORY_FIRST_REPLY + Duration::from_secs(1)));

        // A settle gap inside a reply ends it.
        accounting.note_history_request(10, now);
        assert!(accounting.classify(now + Duration::from_millis(10)));
        assert!(
            !accounting.classify(
                now + Duration::from_millis(10) + HISTORY_SETTLE + Duration::from_millis(1)
            )
        );

        // A re-join discards any phase in progress.
        accounting.note_backfilltimes(5);
        accounting.on_join();
        assert!(!accounting.classify(now));
    }
}
