//! IMPL-025 H6 (partial) — pull-loop C-REBASE decision core.
//!
//! Models the distinctive [[IMPL-025-hark-mls-ds-client#H6 — Pull loop, rebase, and Welcome/ack handshake]]
//! property that [[IMPL-025-hark-mls-ds-client#ADR-035]] calls out: **transport retry** (resend
//! the SAME unexpired portable root — a socket-level failure) is NOT **semantic C-REBASE**
//! (rebuild a FRESH source/root from the semantic intent, bound to the RE-VERIFIED head — never
//! rewrap stale bytes), and a mutation whose portable-root window expired must **resume to head
//! before rebuilding** (REQ-039 resume-before-submit).
//!
//! This is the pure decision. DEFERRED to the hark-integration H6: the actual socket, the single
//! outstanding `next-record` pull, the separate `welcome-get` lane, join-before-ack, and feeding
//! verified responses to `transition_client`. No recogniser needed. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h6_pull_loop -- --nocapture

/// A portable submission root: a base position + the MLS ciphertext identity built over it.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Root {
    base_seq: i64,
    base_hash: String,
    cipher_id: u64, // models the MLS ciphertext/source identity
}

/// Build a FRESH root from the semantic intent, bound to the CURRENT verified head. `gen`
/// bumps the ciphertext identity so a rebuild never reuses the stale bytes.
fn build_root(intent: u64, head_seq: i64, head_hash: &str, gen: u64) -> Root {
    Root {
        base_seq: head_seq,
        base_hash: head_hash.into(),
        cipher_id: (intent.wrapping_shl(16)) ^ gen.wrapping_add(0x9e37),
    }
}

#[derive(Debug)]
enum Event {
    /// A socket-level failure — the root is still valid and unexpired.
    TransportError,
    /// The DS reports our base moved; we learn the new verified head.
    StaleBase { head_seq: i64, head_hash: String },
    /// Our portable-root time window expired.
    MutationExpired,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Resend the SAME bytes (transport-level; NOT a rebase).
    RetrySameRoot,
    /// C-REBASE: a fresh root bound to the new head.
    Rebase(Root),
    /// Resume-before-submit: re-verify head first, THEN rebuild.
    PullToHeadThenRebase,
}

struct Outstanding {
    root: Root,
    intent: u64,
    gen: u64,
}

/// The H6 decision on an outstanding submission.
fn decide(o: &Outstanding, e: Event) -> Action {
    match e {
        // Transport failure, the portable root is still valid → resend the SAME root.
        Event::TransportError => Action::RetrySameRoot,
        // The DS gave us the new head → C-REBASE onto it now (fresh bytes, new base).
        Event::StaleBase { head_seq, head_hash } => {
            Action::Rebase(build_root(o.intent, head_seq, &head_hash, o.gen + 1))
        }
        // The root window expired → we must re-verify head before rebuilding (resume-before-submit).
        Event::MutationExpired => Action::PullToHeadThenRebase,
    }
}

fn outstanding() -> Outstanding {
    Outstanding {
        root: Root { base_seq: 5, base_hash: "h5".into(), cipher_id: 0xABCD },
        intent: 42,
        gen: 1,
    }
}

/// A transport error resends the SAME root — no rebuild, bytes unchanged.
#[test]
fn transport_error_retries_the_same_root() {
    let o = outstanding();
    let a = decide(&o, Event::TransportError);
    println!("[H6 pull] transport error -> {a:?}");
    assert_eq!(a, Action::RetrySameRoot);
}

/// A stale base triggers C-REBASE: the fresh root is bound to the NEW head (never the stale
/// base) and carries FRESH ciphertext — the "never rewrap stale bytes" property.
#[test]
fn stale_base_rebases_onto_the_new_head_with_fresh_bytes() {
    let o = outstanding();
    let a = decide(&o, Event::StaleBase { head_seq: 8, head_hash: "h8".into() });
    println!("[H6 pull] stale base -> {a:?}");
    match a {
        Action::Rebase(new_root) => {
            assert_eq!(new_root.base_seq, 8, "rebased onto the NEW head seq");
            assert_eq!(new_root.base_hash, "h8", "rebased onto the NEW head hash, not the stale base");
            assert_ne!(new_root.cipher_id, o.root.cipher_id, "fresh ciphertext — the stale bytes are NOT rewrapped");
        }
        other => panic!("expected Rebase, got {other:?}"),
    }
}

/// An expired mutation window must re-verify head before rebuilding (resume-before-submit).
#[test]
fn expired_window_pulls_to_head_before_rebuilding() {
    let o = outstanding();
    let a = decide(&o, Event::MutationExpired);
    println!("[H6 pull] mutation expired -> {a:?}");
    assert_eq!(a, Action::PullToHeadThenRebase);
}

/// Transport retry and semantic rebase are genuinely distinct outcomes for the same outstanding
/// root — the H6/ADR-035 distinction.
#[test]
fn transport_retry_and_semantic_rebase_are_distinct() {
    let o = outstanding();
    let retry = decide(&o, Event::TransportError);
    let rebase = decide(&o, Event::StaleBase { head_seq: 8, head_hash: "h8".into() });
    assert_ne!(retry, rebase, "a transport retry must NOT be treated as a semantic rebase");
    // and the rebase must differ from the original root
    if let Action::Rebase(r) = rebase {
        assert_ne!(r, o.root, "the rebased root differs from the original");
    }
    println!("[H6 pull] transport-retry != semantic-rebase (ADR-035) confirmed");
}
