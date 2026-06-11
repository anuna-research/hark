//! SPEC-003 responder coordination (REQ-002/005/006/007) for the chat transport.
//!
//! This is the decision core of "when a capable agent should answer an ask".
//! It is driven by the transport's receive loop but holds no I/O and no clock:
//! the loop feeds it inbound messages and fires its timers, and it returns the
//! actions to take (broadcast a claim, deliver an ask to `recv`). That keeps the
//! coordination logic deterministic and unit-testable in isolation.
//!
//! Only **`(lang <dialect> <inner>)`-wrapped** messages are answerable asks: the
//! `lang` wrapper is the explicit "this is a dialect-scoped message" signal
//! (SPEC-005). Bare built-in performatives (cite, tell, propose, vote) are the
//! hub's human chat verbs, not agent capabilities, and are ignored — as are the
//! bare hub control frames (presence/roomcfg/…). `claim` and `reply` are bare
//! coordination/liveness signals handled explicitly.
//!
//! V1 flow for an answerable ask (one whose lang dialect is in the agent's
//! advertised capability set, REQ-002):
//!  1. broadcast `(claim @channel :on "<ask_id>" :from @handle)` (REQ-005); the
//!     claim is VRF-less — the V1 selector is [`RendezvousHash`], not VRF.
//!  2. collect claims for `ask_id` over the window Δ (the transport's timer).
//!  3. when Δ closes, rank the contenders. If we are rank 0, deliver the ask to
//!     `recv` (the agent answers via the unchanged `reply` CLI). Otherwise hold.
//!  4. liveness fallback (REQ-007): a rank-k agent that has seen no `reply` on
//!     the ask's thread within k·T takes over and answers.
//!
//! A `reply` observed on the ask's thread cancels our pending work for it.
//!
//! `ask_id` is the ask's `:thread` (content-addressed, cbcl-chat ADR-004) when
//! present, else the SHA-256 of the payload. The thread form is what lets the
//! winner's `reply` (which echoes `:thread`) cancel the others' fallback; a
//! thread-less ask degrades to winner-only (no fallback correlation).

use std::collections::{BTreeSet, HashMap, HashSet};

use cbcl_core::message::Message;
use cbcl_core::sexpr::{Atom, SExpr};
use sha2::{Digest, Sha256};

use crate::selector::{RendezvousHash, Selector};

/// An action the transport must perform after feeding the coordinator an inbound
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Broadcast this (validated, to-be-signed) claim frame and open the Δ
    /// window for `ask_id`.
    Claim { ask_id: String, frame_text: String },
}

/// What the transport should do when an ask's Δ window closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowOutcome {
    /// We are the elected answerer — deliver this payload to `recv` now.
    Win(String),
    /// We are rank `rank` (≥ 1): schedule a liveness fallback after `rank`
    /// liveness periods, then re-check via [`Responder::on_fallback`].
    Hold { rank: usize },
    /// Nothing to do (already answered, or the ask is no longer tracked).
    Idle,
}

/// Per-ask coordination state.
struct AskState {
    /// The ask payload, delivered to `recv` if we win or take over.
    payload: String,
    /// Handles that have claimed for this ask (including ours).
    contenders: BTreeSet<String>,
    /// A `reply` on this ask's thread has been observed.
    answered: bool,
}

/// The responder decision core. One per chat connection.
pub struct Responder {
    my_handle: String,
    channel: String,
    capability: HashSet<String>,
    /// The channel's declared dialect names (SPEC-016 REQ-009): `None` when
    /// the hub conveyed no menu (legacy — scope is the repertoire alone);
    /// `Some` scopes responses to declared ∩ repertoire, so `Some([])` is an
    /// empty response scope.
    declared: Option<HashSet<String>>,
    selector: RendezvousHash,
    asks: HashMap<String, AskState>,
}

impl Responder {
    /// `capability` is the agent's advertised dialect set (REQ-002): it answers
    /// `(lang <dialect> …)`-wrapped asks whose dialect is in this set —
    /// intersected with the channel's `declared` menu when one was conveyed
    /// (SPEC-016 REQ-009).
    pub fn new(
        my_handle: String,
        channel: String,
        capability: Vec<String>,
        declared: Option<Vec<String>>,
    ) -> Self {
        Self {
            my_handle,
            channel,
            capability: capability.into_iter().collect(),
            declared: declared.map(|names| names.into_iter().collect()),
            selector: RendezvousHash,
            asks: HashMap::new(),
        }
    }

    /// Feed one inbound message. Returns the actions the transport must perform
    /// (at most one claim broadcast). Non-answerable traffic returns `[]` and is
    /// thereby dropped before `recv` (REQ-002).
    ///
    /// Parsing and field access go through the canonical `cbcl_core::Message`
    /// API (the same model the hub uses): `dialect_name`/`innermost_simple`/
    /// `sender`/`thread`, so hark interprets messages exactly as cbcl-rs does.
    pub fn on_inbound(&mut self, text: &str) -> Vec<Action> {
        let Some(message) = parse_message(text) else {
            return vec![]; // unparseable: drop, keep the connection
        };
        match message.performative().map(|p| p.name()) {
            Some("claim") => {
                self.on_claim(&message);
                vec![]
            }
            Some("reply") => {
                self.on_reply(&message);
                vec![]
            }
            _ => self.on_possible_ask(text, &message),
        }
    }

    fn on_claim(&mut self, message: &Message) {
        // A claim is a bare Simple message carrying `:on` (the ask id) and the
        // cbcl-chat `:from` convention (a param in cbcl-rs, not the `sender` field).
        let (Some(ask_id), Some(from)) = (param_str(message, "on"), param_str(message, "from"))
        else {
            return;
        };
        if let Some(state) = self.asks.get_mut(ask_id) {
            state.contenders.insert(from.to_owned());
        }
    }

    fn on_reply(&mut self, message: &Message) {
        // A reply on an ask's thread is the liveness signal: someone answered.
        if let Some(thread) = message.thread() {
            if let Some(state) = self.asks.get_mut(thread) {
                state.answered = true;
            }
        }
    }

    fn on_possible_ask(&mut self, text: &str, message: &Message) -> Vec<Action> {
        // Only `(lang <dialect> <inner>)` messages are answerable asks (SPEC-005):
        // `dialect_name` is `Some` only for a Dialect message. Bare built-ins
        // (cite/tell/propose/vote) and bare hub control frames are dropped here
        // (REQ-002).
        let Some(dialect) = message.dialect_name() else {
            return vec![];
        };
        if !self.capability.contains(dialect) {
            return vec![]; // a dialect we have not learned: drop (REQ-002)
        }
        // SPEC-016 REQ-009: in a channel with a declared menu, respond only
        // within declared ∩ repertoire; an empty declared set answers nothing.
        if let Some(declared) = &self.declared {
            if !declared.contains(dialect) {
                return vec![];
            }
        }
        // Addressing lives on the innermost Simple message (cbcl-rs model). The
        // sender is the cbcl-chat `:from` convention (a param, not `sender`).
        let inner = message.innermost_simple();
        let from = inner.and_then(|m| param_str(m, "from"));
        if from == Some(self.my_handle.as_str()) {
            return vec![]; // our own message, fanned back: never contend with ourselves
        }
        let ask_id = inner
            .and_then(Message::thread)
            .map(str::to_owned)
            .unwrap_or_else(|| content_hash(text));
        if self.asks.contains_key(&ask_id) {
            return vec![]; // already contending for this ask
        }
        let mut contenders = BTreeSet::new();
        contenders.insert(self.my_handle.clone());
        self.asks.insert(
            ask_id.clone(),
            AskState {
                payload: text.to_owned(),
                contenders,
                answered: false,
            },
        );
        let frame_text = format!(
            "(claim {} :on \"{}\" :from {})",
            self.channel, ask_id, self.my_handle
        );
        vec![Action::Claim { ask_id, frame_text }]
    }

    /// Called when the Δ window for `ask_id` closes.
    pub fn on_window_closed(&mut self, ask_id: &str) -> WindowOutcome {
        let Some(state) = self.asks.get(ask_id) else {
            return WindowOutcome::Idle;
        };
        if state.answered {
            self.asks.remove(ask_id);
            return WindowOutcome::Idle;
        }
        let contenders: Vec<String> = state.contenders.iter().cloned().collect();
        let ranking = self.selector.rank(ask_id, &contenders);
        match ranking.iter().position(|h| h == &self.my_handle) {
            Some(0) => {
                let payload = state.payload.clone();
                self.asks.remove(ask_id);
                WindowOutcome::Win(payload)
            }
            Some(rank) => WindowOutcome::Hold { rank },
            // We always insert ourselves as a contender, so we are always ranked;
            // this arm is unreachable in practice but is handled defensively.
            None => {
                self.asks.remove(ask_id);
                WindowOutcome::Idle
            }
        }
    }

    /// Called when a rank-k agent's liveness fallback fires for `ask_id`.
    /// Returns the payload to deliver if the ask is still unanswered.
    pub fn on_fallback(&mut self, ask_id: &str) -> Option<String> {
        let answered = self.asks.get(ask_id)?.answered;
        let state = self.asks.remove(ask_id)?;
        if answered { None } else { Some(state.payload) }
    }

    /// Whether any asks are still being coordinated (for tests/diagnostics).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.asks.len()
    }
}

/// Parse wire text into a canonical `cbcl_core::Message` (R1–R4), or `None` if
/// it is not well-formed. The same parser the hub uses, so field semantics match.
fn parse_message(text: &str) -> Option<Message> {
    let sexpr = cbcl_parser::parse(text).ok()?;
    cbcl_parser::parse_message(&sexpr).ok()
}

/// The string value of a `:key` keyword param on a Simple message — used for
/// `claim`'s `:on` (the ask id), which is a param rather than a core field. The
/// value may be a string or a symbol. cbcl-rs maps `:from` to `sender` and
/// `:thread` to `thread` directly, so those use the typed accessors instead.
fn param_str<'a>(message: &'a Message, key: &str) -> Option<&'a str> {
    let Message::Simple { params, .. } = message else {
        return None;
    };
    let mut iter = params.iter();
    while let Some(item) = iter.next() {
        if let SExpr::Atom(Atom::Keyword(found)) = item {
            if found == key {
                return match iter.next() {
                    Some(SExpr::Atom(Atom::Str(value))) => Some(value),
                    Some(SExpr::Atom(Atom::Symbol(value))) => Some(value),
                    _ => None,
                };
            }
        }
    }
    None
}

/// Content-addressed fallback id: lowercase hex of `SHA-256(payload)`.
fn content_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A learned dialect the agent can answer (SPEC-005); always lang-wrapped.
    fn responder() -> Responder {
        Responder::new(
            "@me".to_owned(),
            "@general".to_owned(),
            vec!["summarize".to_owned()],
            None,
        )
    }

    #[test]
    fn response_scope_is_declared_intersect_repertoire() {
        // REQ-009 (SPEC-016, TEST-009): with a declared menu, the agent
        // answers only asks in declared ∩ repertoire.
        let mut r = Responder::new(
            "@me".to_owned(),
            "@general".to_owned(),
            vec!["summarize".to_owned(), "cite-check".to_owned()],
            Some(vec!["summarize".to_owned(), "translate".to_owned()]),
        );
        // declared ∩ repertoire → claim.
        assert_eq!(r.on_inbound(&ask("t1", "@asker")).len(), 1);
        // in repertoire but NOT declared → dropped.
        assert!(
            r.on_inbound("(lang cite-check (ask @general \"q\" :from @x :thread \"t2\"))")
                .is_empty()
        );
        // declared but NOT in repertoire → dropped (unchanged REQ-002).
        assert!(
            r.on_inbound("(lang translate (ask @general \"q\" :from @x :thread \"t3\"))")
                .is_empty()
        );
    }

    #[test]
    fn empty_declared_set_means_empty_response_scope() {
        let mut r = Responder::new(
            "@me".to_owned(),
            "@general".to_owned(),
            vec!["summarize".to_owned()],
            Some(vec![]),
        );
        assert!(r.on_inbound(&ask("t1", "@asker")).is_empty());
        assert_eq!(r.tracked(), 0);
    }

    fn ask(thread: &str, from: &str) -> String {
        format!("(lang summarize (ask @general \"q\" :from {from} :thread \"{thread}\"))")
    }

    #[test]
    fn lang_wrapped_ask_in_capability_emits_a_claim() {
        let mut r = responder();
        let actions = r.on_inbound(&ask("t1", "@asker"));
        assert_eq!(
            actions,
            vec![Action::Claim {
                ask_id: "t1".to_owned(),
                frame_text: "(claim @general :on \"t1\" :from @me)".to_owned(),
            }]
        );
    }

    #[test]
    fn bare_performatives_are_ignored() {
        let mut r = responder();
        // Bare built-ins and hub control frames have no lang wrapper → dropped,
        // even when the verb name coincides with chat dialects.
        for bare in [
            "(cite @general :doi \"10.1/x\" :from @human)",
            "(tell @general \"hi\" :from @human)",
            "(propose @general \"q?\" :options (yes no) :from @human)",
            "(presence @general :members (@a @b))",
            "(roomcfg @general :enc false)",
        ] {
            assert!(
                r.on_inbound(bare).is_empty(),
                "bare message must be ignored: {bare}"
            );
        }
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn non_capable_lang_dialect_is_dropped() {
        let mut r = responder();
        // A lang-wrapped ask in a dialect we have NOT learned: dropped (REQ-002).
        assert!(
            r.on_inbound("(lang translate (ask @general \"q\" :from @x :thread \"t\"))")
                .is_empty()
        );
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn own_messages_are_ignored() {
        let mut r = responder();
        assert!(r.on_inbound(&ask("t", "@me")).is_empty());
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn sole_contender_wins_the_window() {
        let mut r = responder();
        let payload = ask("t1", "@asker");
        r.on_inbound(&payload);
        assert_eq!(r.on_window_closed("t1"), WindowOutcome::Win(payload));
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn contended_window_ranks_deterministically() {
        // Two agents see the same ask and claim; both must agree on the winner.
        let payload = "(lang summarize (ask @g \"q\" :from @asker :thread \"t1\"))";
        let mut a = Responder::new(
            "@a".to_owned(),
            "@g".to_owned(),
            vec!["summarize".to_owned()],
            None,
        );
        let mut b = Responder::new(
            "@b".to_owned(),
            "@g".to_owned(),
            vec!["summarize".to_owned()],
            None,
        );
        a.on_inbound(payload);
        b.on_inbound(payload);
        // Exchange claims (the hub fans each agent's claim to the other).
        a.on_inbound("(claim @g :on \"t1\" :from @b)");
        b.on_inbound("(claim @g :on \"t1\" :from @a)");

        let oa = a.on_window_closed("t1");
        let ob = b.on_window_closed("t1");
        let a_won = matches!(oa, WindowOutcome::Win(_));
        let b_won = matches!(ob, WindowOutcome::Win(_));
        assert!(a_won ^ b_won, "exactly one of the two agents must win");
        if a_won {
            assert_eq!(ob, WindowOutcome::Hold { rank: 1 });
        } else {
            assert_eq!(oa, WindowOutcome::Hold { rank: 1 });
        }
    }

    #[test]
    fn reply_cancels_fallback() {
        let mut r = responder();
        r.on_inbound(&ask("t1", "@asker"));
        // Another agent claimed and outranks us → we hold.
        r.on_inbound("(claim @general :on \"t1\" :from @aaa)");
        // Someone answered on the thread (a bare reply) before our fallback fires.
        r.on_inbound("(reply @general \"a\" :thread \"t1\" :from @aaa)");
        assert_eq!(r.on_fallback("t1"), None);
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn fallback_takes_over_when_unanswered() {
        let mut r = responder();
        let payload = ask("t1", "@asker");
        r.on_inbound(&payload);
        r.on_inbound("(claim @general :on \"t1\" :from @aaa)");
        // No reply seen: the held agent takes over and delivers the ask.
        assert_eq!(r.on_fallback("t1"), Some(payload));
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn duplicate_ask_does_not_double_claim() {
        let mut r = responder();
        let payload = ask("t1", "@asker");
        assert_eq!(r.on_inbound(&payload).len(), 1);
        assert!(r.on_inbound(&payload).is_empty()); // already contending
    }

    #[test]
    fn thread_less_ask_uses_content_hash() {
        let mut r = responder();
        let actions = r.on_inbound("(lang summarize (ask @general \"q\" :from @asker))");
        let Action::Claim { ask_id, .. } = &actions[0];
        assert_eq!(ask_id.len(), 64); // hex SHA-256
        assert!(ask_id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
