//! The cbcl-chat **hub dialect** — the control-plane performatives the chat
//! protocol uses (agent pairing + legibility), as a real CBCL dialect.
//!
//! These performatives (`announce`, `addagent`, `paircode`, `removeagent`,
//! `agent-removed`) are bare *custom* performatives on the wire — the hub
//! routes them by their head symbol, with no `(lang …)` wrapper. Without a
//! defining dialect they parse as well-formed s-expressions but are NOT valid
//! CBCL *messages* (the evaluator rejects an unscoped custom performative as
//! `UnknownPerformative`). Registering this dialect makes them resolve — a bare
//! `(announce …)` becomes valid CBCL while dispatch stays by-name.
//!
//! The control plane is implicit in every channel. Rather than bake a copy of
//! the grammar (which drifts against the hub's canonical
//! `apps/cbcl_chat/priv/dialects/hub.cbcl`), the agent **learns** it from the
//! hub: the hub leads each join with a `(meta (define hub …))` advertisement,
//! and [`learn_hub_dialect`] installs it — CBCL's native dialect-distribution
//! path. The grammar is single-sourced at the hub; hark holds no *runtime*
//! copy. (The tests DO carry a fixture copy — `src/dialects/hub.cbcl` — to
//! synthesize the hub's advertisement; it is held byte-identical to the
//! canonical file by `hub_dialect_fixture_matches_the_canonical_cbcl_bus_grammar`
//! in `tests/join_cli.rs`.)

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::message::Message;

/// Why hark could not learn the hub dialect from a frame.
#[derive(Debug, thiserror::Error)]
pub enum HubDialectError {
    #[error("frame is not well-formed CBCL: {0}")]
    Parse(String),
    #[error("frame is not a (meta …) dialect-definition message")]
    NotMeta,
    #[error("the meta message does not carry a valid dialect: {0}")]
    Dialect(String),
    /// A valid meta, but defining some other dialect — the hub distributing
    /// e.g. `cite` over the same path, NOT its control grammar. Callers should
    /// ignore these for hub-learning rather than treat them as malformed.
    #[error("the meta defines dialect \"{0}\", not the hub control dialect")]
    NotHub(String),
    /// Named `hub` but missing the performative this agent actually emits and
    /// self-validates (`announce`) — accepting it would make every join fail
    /// its own announce check against a grammar that cannot express it.
    #[error("the taught hub dialect does not define `{0}`")]
    MissingControlPerformative(&'static str),
    #[error("the learned dialect does not install (R1–R3/R5): {0}")]
    Install(String),
}

/// Learn the hub control dialect from the `(meta (define hub …))` message the
/// hub sends over the wire — CBCL's native dialect-distribution path (a Meta
/// message carries a dialect definition; the evaluator turns it into an
/// `InstallDialect` effect). Returns a registry carrying the base dialect plus
/// the learned hub dialect, so the agent validates its control-plane frames
/// against the grammar the hub *actually* declared — no baked copy to drift.
///
/// Accepts only the dialect actually *named* `hub`, and only if it defines
/// `announce` (the performative this agent emits and self-validates against
/// it). Any other valid meta is [`HubDialectError::NotHub`] — a different
/// dialect being distributed over the same path, not the control grammar
/// (R7-001).
pub fn learn_hub_dialect(meta_frame: &str) -> Result<DialectRegistry, HubDialectError> {
    let sexpr =
        cbcl_parser::parse(meta_frame).map_err(|e| HubDialectError::Parse(e.to_string()))?;
    let message = cbcl_parser::parse_message(&sexpr).map_err(HubDialectError::Parse)?;
    let Message::Meta { dialect_def } = message else {
        return Err(HubDialectError::NotMeta);
    };
    let dialect = cbcl_parser::dialect_parser::parse_dialect(&dialect_def)
        .map_err(HubDialectError::Dialect)?;
    // Only the dialect actually named `hub` is the control grammar — a hub may
    // legitimately distribute other dialects (cite, poll, …) over the same
    // meta path, and installing one of those as "the hub dialect" would make
    // the agent validate its announce against a grammar that never defines it.
    if dialect.name != "hub" {
        return Err(HubDialectError::NotHub(dialect.name));
    }
    if !dialect.defines_performative("announce") {
        return Err(HubDialectError::MissingControlPerformative("announce"));
    }
    let mut registry = DialectRegistry::new();
    registry
        .install(dialect)
        .map_err(|e| HubDialectError::Install(format!("{e:?}")))?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbcl_validation::validate_for_emit;
    use cbcl_core::store::ThreadedMessageStore;

    /// The canonical hub dialect, as a *test fixture* only — the runtime no
    /// longer carries it; it learns the grammar from the hub's meta frame. Used
    /// here to synthesise a representative `(meta (define hub …))` the way the
    /// hub sends it.
    const HUB_DIALECT_FIXTURE: &str = include_str!("dialects/hub.cbcl");

    /// The registry the agent ends up with after learning from the hub's
    /// advertisement — synthesised the way the hub sends it: the fixture grammar
    /// wrapped in a `(meta …)` and run through the real [`learn_hub_dialect`].
    fn learned_registry() -> DialectRegistry {
        let meta_frame = format!("(meta {})", HUB_DIALECT_FIXTURE.trim());
        learn_hub_dialect(&meta_frame).expect("hark learns the hub dialect from the meta frame")
    }

    /// hark learns the hub control dialect from the CBCL Meta message the hub
    /// sends (`(meta (define hub …))`) — the language-native dialect-distribution
    /// path — and a control-plane frame then validates against that *learned*
    /// grammar, with no baked copy.
    #[test]
    fn learns_the_hub_dialect_from_a_meta_define_frame() {
        let registry = learned_registry();
        let mut store = ThreadedMessageStore::new();
        assert!(
            validate_for_emit(
                r#"(announce @general :from @aria :agent @aria :dialects ("cite") :added-by @mira)"#,
                &registry,
                &mut store,
            )
            .is_ok(),
            "the announce should validate against the learned hub grammar"
        );
    }

    /// A frame that is not a `(meta …)` dialect-definition is rejected — hark
    /// only learns from an actual Meta message, never from arbitrary traffic.
    #[test]
    fn rejects_a_frame_that_is_not_a_meta_define() {
        assert!(learn_hub_dialect(r#"(tell @aria "hi" :from @mira)"#).is_err());
        assert!(learn_hub_dialect("not cbcl at all (((").is_err());
    }

    /// R7-001: a perfectly valid meta defining some OTHER dialect (the hub
    /// distributing e.g. `cite` over the same path) is not the control grammar
    /// and must not be installed as it — the error is the distinguishable
    /// `NotHub`, which callers ignore for hub-learning.
    #[test]
    fn rejects_a_valid_meta_defining_a_non_hub_dialect() {
        let cite_meta = r#"(meta (define cite (cbcl) @anuna-chat
          (:resource-requirements ((max-depth 8) (max-expansion-size 512) (verification-time 10)))
          (extend cite (doi url note)
            (tell @room (citation :doi doi :url url :note note)))))"#;
        match learn_hub_dialect(cite_meta) {
            Err(HubDialectError::NotHub(name)) => assert_eq!(name, "cite"),
            other => panic!("expected NotHub(cite), got {other:?}"),
        }
    }

    /// R7-001: a dialect *named* `hub` that cannot express `announce` — the
    /// frame this agent emits and self-validates — is rejected outright;
    /// installing it would fail every join at its own announce check.
    #[test]
    fn rejects_a_hub_dialect_that_does_not_define_announce() {
        let truncated_hub_meta = r#"(meta (define hub (cbcl) @cbcl-chat
          (:resource-requirements ((max-depth 8) (max-expansion-size 512) (verification-time 10)))
          (extend paircode (name id code)
            (tell @room (pair-code :name name :id id :code code)))))"#;
        match learn_hub_dialect(truncated_hub_meta) {
            Err(HubDialectError::MissingControlPerformative(p)) => assert_eq!(p, "announce"),
            other => panic!("expected MissingControlPerformative(announce), got {other:?}"),
        }
    }

    /// With the *learned* hub dialect, every control-plane frame is valid CBCL
    /// (resolves + passes the pipeline) — not merely a well-formed s-expression.
    #[test]
    fn hub_dialect_makes_control_frames_valid_cbcl() {
        let registry = learned_registry();
        let frames = [
            // SPEC-016 pairing + legibility
            r#"(announce @general :from @aria :agent @aria :dialects ("cite") :added-by @mira)"#,
            r#"(announce @general :from @bot :agent @bot :dialects ())"#, // no adder
            r#"(addagent @general :name @aria :dialects ("cite") :from @mira)"#,
            r#"(paircode @general :name @aria :id "1" :code "1-rocket-anchor-velvet")"#,
            r#"(removeagent @general :name @aria :from @mira)"#,
            "(agent-removed @general :name @aria)",
            // SPEC-001 rooms (folded-in pre-existing control plane)
            "(presence @general :members (@a @b))",
            "(roomcfg @general :enc false)",
            r#"(invite @general :ttl 86400000 :uses 5 :from @mira)"#,
            r#"(invited @general :token "deadbeef" :ttl 86400000 :uses 5)"#,
            r#"(channels @hub :public (@general @research) :from @mira :key "k")"#,
            r#"(history @general :before "rcp-1" :limit 50 :from @mira)"#,
            // SPEC-002 MLS
            r#"(keypub @hub :last "b64" :onetime ("a" "b") :from @mira)"#,
            "(keyget @hub :for @bob :from @mira)",
            r#"(keypkg @hub :for @bob :kp "b64")"#,
            r#"(welcome @general :for @bob :ct "b64" :from @mira)"#,
            r#"(deliver @general :enc mls :epoch 3 :ct "b64" :from @mira)"#,
        ];
        for frame in frames {
            let mut store = ThreadedMessageStore::new();
            assert!(
                validate_for_emit(frame, &registry, &mut store).is_ok(),
                "not valid CBCL against the hub dialect: {frame}"
            );
        }
    }

    /// Without the hub dialect, the same frames are rejected — proving the
    /// dialect is what confers validity (they were never strict-valid bare).
    #[test]
    fn control_frames_are_invalid_without_the_hub_dialect() {
        let base = DialectRegistry::new();
        for frame in [
            r#"(addagent @general :name @aria :from @mira)"#,
            r#"(announce @general :from @aria :agent @aria :dialects ("cite"))"#,
        ] {
            let mut store = ThreadedMessageStore::new();
            assert!(
                validate_for_emit(frame, &base, &mut store).is_err(),
                "should be invalid without the hub dialect: {frame}"
            );
        }
    }
}
