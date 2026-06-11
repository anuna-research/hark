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
//! The control plane is implicit in every channel, so this is a built-in the
//! agent always carries (like the base dialect), not a channel-declared one.
//! The definition mirrors the hub's canonical
//! `apps/cbcl_chat/priv/dialects/hub.cbcl`.

use cbcl_core::dialect::DialectRegistry;
use std::sync::OnceLock;

/// The canonical hub-dialect definition (mirrors the hub's `hub.cbcl`).
pub const HUB_DIALECT_SRC: &str = include_str!("dialects/hub.cbcl");

/// The process-wide hub-dialect registry (parsed once). Use this to validate
/// control-plane frames as valid CBCL.
pub fn hub_registry_cached() -> &'static DialectRegistry {
    static REGISTRY: OnceLock<DialectRegistry> = OnceLock::new();
    REGISTRY.get_or_init(hub_registry)
}

/// A registry carrying the base dialect plus the hub control-plane dialect, so
/// the chat control performatives resolve as valid CBCL.
pub fn hub_registry() -> DialectRegistry {
    let mut registry = DialectRegistry::new();
    let sexpr = cbcl_parser::parser::parse(HUB_DIALECT_SRC).expect("hub.cbcl is well-formed");
    let dialect =
        cbcl_parser::dialect_parser::parse_dialect(&sexpr).expect("hub.cbcl is a valid dialect");
    registry
        .install(dialect)
        .expect("the hub dialect installs (R1–R3/R5)");
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbcl_validation::validate_for_emit;
    use cbcl_core::store::ThreadedMessageStore;

    /// With the hub dialect registered, every control-plane frame is valid CBCL
    /// (resolves + passes the pipeline) — not merely a well-formed s-expression.
    #[test]
    fn hub_dialect_makes_control_frames_valid_cbcl() {
        let registry = hub_registry();
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
