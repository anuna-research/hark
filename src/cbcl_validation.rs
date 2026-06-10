use cbcl_core::{
    dialect::DialectRegistry,
    message::{CorePerformative, Message, Performative},
    sexpr::{Atom, SExpr},
    store::ThreadedMessageStore,
};
use cbcl_parser::{
    ParseError, PipelineContext, PipelineResult, ValidationError, run_pipeline, run_pipeline_full,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MessageKind {
    Reply,
    Error,
    Progress,
}

impl MessageKind {
    fn expected_performative(self) -> CorePerformative {
        match self {
            MessageKind::Reply => CorePerformative::Reply,
            MessageKind::Error => CorePerformative::Error,
            MessageKind::Progress => CorePerformative::Tell,
        }
    }

    fn command_name(self) -> &'static str {
        match self {
            MessageKind::Reply => "reply",
            MessageKind::Error => "error",
            MessageKind::Progress => "progress",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidatedMessage {
    pub kind: MessageKind,
    pub thread: String,
    /// Parsed message returned by the pipeline. R5 Phase B: callers
    /// append this into the per-handle causal store on successful send.
    pub message: Message,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CbclValidationError {
    #[error("malformed CBCL: {0}")]
    Malformed(String),
    #[error("unsupported CBCL wrapper: only a single (lang ...) wrapper is supported")]
    UnsupportedWrapper,
    #[error("{expected} command requires a {expected_performative} message, got {actual}")]
    KindMismatch {
        expected: &'static str,
        expected_performative: &'static str,
        actual: String,
    },
    #[error("CBCL message must include exactly one :thread parameter")]
    MissingThread,
    #[error("CBCL message must not include duplicate :thread parameters")]
    DuplicateThread,
    #[error("CBCL :thread value must be a non-empty string")]
    EmptyThread,
    #[error("CBCL :thread value must be a string")]
    NonStringThread,
    #[error("progress messages must be sent to @router")]
    InvalidProgressRecipient,
    #[error("progress messages must have string content \"progress\"")]
    InvalidProgressContent,
    /// R5 shape constraint violation surfaced from `run_pipeline_full`
    /// (REQ-220, REQ-231 step 6b). Phase A plumbing: variant added so
    /// outbound/inbound paths can carry the structured error once they
    /// switch from `run_pipeline` to `run_pipeline_full` in B/C.
    #[error("CBCL shape violation: {detail}")]
    ShapeViolation {
        detail: String,
        performative: Option<String>,
        thread: Option<String>,
    },
    /// Causal protocol violation surfaced from `run_pipeline_full`
    /// (REQ-200, REQ-231 step 6a). Same plumbing rationale as above.
    #[error("CBCL causal violation: {detail}")]
    CausalViolation {
        detail: String,
        performative: Option<String>,
        thread: Option<String>,
    },
}

impl CbclValidationError {
    pub fn code(&self) -> &'static str {
        match self {
            CbclValidationError::Malformed(_) => "cbcl_malformed",
            CbclValidationError::UnsupportedWrapper => "cbcl_unsupported_wrapper",
            CbclValidationError::KindMismatch { .. } => "cbcl_kind_mismatch",
            CbclValidationError::MissingThread => "cbcl_thread_missing",
            CbclValidationError::DuplicateThread => "cbcl_thread_duplicate",
            CbclValidationError::EmptyThread => "cbcl_thread_empty",
            CbclValidationError::NonStringThread => "cbcl_thread_non_string",
            CbclValidationError::InvalidProgressRecipient => "cbcl_progress_recipient",
            CbclValidationError::InvalidProgressContent => "cbcl_progress_content",
            CbclValidationError::ShapeViolation { .. } => "shape_violation",
            CbclValidationError::CausalViolation { .. } => "causal_violation",
        }
    }

    /// Build a hark `CbclValidationError` from a cbcl-parser
    /// `ValidationError::ShapeViolation` / `CausalViolation`. Returns
    /// `None` for variants that don't map to a shape/causal error —
    /// callers should fall back to `Malformed` for those.
    ///
    /// Phase A: factory only; no caller yet (outbound/inbound paths
    /// keep using `run_pipeline`, which never returns these two
    /// variants). Wired in Phase B/C alongside the switch to
    /// `run_pipeline_full`.
    pub fn from_pipeline_validation(
        error: &ValidationError,
        performative: Option<String>,
        thread: Option<String>,
    ) -> Option<Self> {
        match error {
            ValidationError::ShapeViolation { .. } => Some(Self::ShapeViolation {
                detail: error.to_string(),
                performative,
                thread,
            }),
            ValidationError::CausalViolation { .. } => Some(Self::CausalViolation {
                detail: error.to_string(),
                performative,
                thread,
            }),
            _ => None,
        }
    }
}

pub fn validate_for_send(
    input: &str,
    expected_kind: MessageKind,
) -> Result<ValidatedMessage, CbclValidationError> {
    validate_for_send_inner(input, expected_kind, None)
}

/// R5 Phase B variant: drive [`run_pipeline_full`] with a runtime context so
/// outbound shape (REQ-220, REQ-231 step 6b) and causal (REQ-200, REQ-231
/// step 6a) violations surface as `ShapeViolation` / `CausalViolation` codes
/// instead of being lumped under `cbcl_malformed`.
///
/// Falls back to the lightweight pipeline when the message's `lang <name>`
/// wrapper references a dialect that isn't installed in `registry`: the
/// agent advertises a dialect name but we may not yet have the define
/// pushed from the router, in which case there's no protocol/shape to
/// verify against. Bare (un-`lang`-wrapped) messages always go through
/// the full pipeline using base-dialect rules.
pub fn validate_for_send_with_context(
    input: &str,
    expected_kind: MessageKind,
    registry: &DialectRegistry,
    store: &mut ThreadedMessageStore,
) -> Result<ValidatedMessage, CbclValidationError> {
    validate_for_send_inner(input, expected_kind, Some((registry, store)))
}

/// Validate a message an agent wants to **emit**: a proactive, agent-initiated
/// outbound that is *not* a reply/error/progress — typically a
/// `(lang <dialect> (<perf> …))` ask the agent originates on its own (SPEC-003
/// REQ-011, ADR-007: the concierge compiling an intent into a channel dialect).
///
/// Unlike [`validate_for_send_with_context`] this does **not** force a
/// reply/error/progress performative or require a `:thread`, and it accepts a
/// `Dialect`/`Wrapped` envelope (which `validate_for_send` rejects). It still
/// runs the full R1–R5 pipeline, so a malformed, shape-violating, or causally
/// dangling message is refused before it leaves the agent. A `(meta …)` form is
/// refused — an emit is a message, not dialect teaching.
pub fn validate_for_emit(
    input: &str,
    registry: &DialectRegistry,
    store: &mut ThreadedMessageStore,
) -> Result<(), CbclValidationError> {
    match run_validation_pipeline(input, Some((registry, store))) {
        PipelineResult::Success(message) => {
            if matches!(message, Message::Meta { .. }) {
                return Err(CbclValidationError::Malformed(
                    "an emit must be a message, not a (meta …) form".to_owned(),
                ));
            }
            Ok(())
        }
        PipelineResult::ParseError(error) => Err(malformed_parse(error)),
        PipelineResult::ValidationError(error) => Err(
            CbclValidationError::from_pipeline_validation(
                &error,
                violation_performative(&error),
                violation_thread(&error),
            )
            .unwrap_or_else(|| CbclValidationError::Malformed(error.to_string())),
        ),
        PipelineResult::Pending { message, reason } => Err(CbclValidationError::CausalViolation {
            detail: format!("causal predecessor unknown: {reason:?}"),
            performative: message
                .innermost_simple()
                .and_then(|m| m.performative())
                .map(|p| p.name().to_owned()),
            thread: message
                .innermost_simple()
                .and_then(|m| m.thread())
                .map(String::from),
        }),
        PipelineResult::Buffered { .. } => Err(CbclValidationError::Malformed(
            "unexpected buffered pipeline state during emit validation".to_owned(),
        )),
    }
}

fn validate_for_send_inner(
    input: &str,
    expected_kind: MessageKind,
    ctx: Option<(&DialectRegistry, &mut ThreadedMessageStore)>,
) -> Result<ValidatedMessage, CbclValidationError> {
    let message = match run_validation_pipeline(input, ctx) {
        PipelineResult::Success(message) => message,
        PipelineResult::ParseError(error) => return Err(malformed_parse(error)),
        PipelineResult::ValidationError(error) => {
            return Err(match CbclValidationError::from_pipeline_validation(
                &error,
                violation_performative(&error),
                violation_thread(&error),
            ) {
                Some(err) => err,
                None => CbclValidationError::Malformed(error.to_string()),
            });
        }
        PipelineResult::Pending { message, reason } => {
            // Under the default `Reject` policy this means a `:caused-by`
            // hash isn't in the per-handle store yet — surface as a causal
            // violation so the CLI gets the new exit code instead of a
            // generic malformed error.
            return Err(CbclValidationError::CausalViolation {
                detail: format!("causal predecessor unknown: {reason:?}"),
                performative: message
                    .innermost_simple()
                    .and_then(|m| m.performative())
                    .map(|p| p.name().to_owned()),
                thread: message
                    .innermost_simple()
                    .and_then(|m| m.thread())
                    .map(String::from),
            });
        }
        PipelineResult::Buffered { .. } => {
            // We never opt into Buffer policy; treat as internal mismatch.
            return Err(CbclValidationError::Malformed(
                "unexpected buffered pipeline state during local validation".to_owned(),
            ));
        }
    };

    let (inner_expr, inner_message) = unwrap_supported_message(input, &message)?;
    let simple = match inner_message {
        Message::Simple { .. } => inner_message,
        Message::Dialect { .. } | Message::Wrapped { .. } => {
            return Err(CbclValidationError::UnsupportedWrapper);
        }
        Message::Meta { .. } => {
            return Err(kind_mismatch(
                expected_kind,
                String::from("meta"),
                expected_kind.expected_performative(),
            ));
        }
    };

    let thread = validate_thread(&inner_expr)?;
    validate_kind(simple, expected_kind)?;
    let simple_owned = simple.clone();

    Ok(ValidatedMessage {
        kind: expected_kind,
        thread,
        message: simple_owned,
    })
}

fn malformed_parse(error: ParseError) -> CbclValidationError {
    CbclValidationError::Malformed(error.to_string())
}

/// Run the appropriate pipeline for outbound validation.
///
/// Uses [`run_pipeline_full`] when a runtime context is supplied AND the
/// message can be verified against the local registry. Falls back to
/// [`run_pipeline`] when the outer `lang <name>` wrapper names a dialect
/// the daemon has not yet been taught — fail-closed verification against
/// an unknown dialect would reject otherwise-valid traffic on agents that
/// advertised a name but haven't received the corresponding `(define ...)`
/// push.
fn run_validation_pipeline(
    input: &str,
    ctx: Option<(&DialectRegistry, &mut ThreadedMessageStore)>,
) -> PipelineResult {
    let Some((registry, store)) = ctx else {
        return run_pipeline(input);
    };
    if !can_verify_against_registry(input, registry) {
        return run_pipeline(input);
    }
    let pipeline_ctx = PipelineContext::new(registry, store);
    run_pipeline_full(input, &pipeline_ctx)
}

/// Best-effort: parse the outer wrapper to decide whether `run_pipeline_full`
/// can complete without tripping over an unknown dialect. Returns `false`
/// only when the outer form is `(lang <name> ...)` and `<name>` is missing
/// from the registry; everything else delegates to the full pipeline (which
/// applies the appropriate fail-closed checks itself).
fn can_verify_against_registry(input: &str, registry: &DialectRegistry) -> bool {
    let Ok(sexpr) = cbcl_parser::parse(input) else {
        // Parse will fail again inside the pipeline; let it produce the
        // structured `ParseError` rather than short-circuiting here.
        return true;
    };
    let SExpr::List(items) = &sexpr else {
        return true;
    };
    if symbol_name(items.first()) != Some("lang") {
        return true;
    }
    let Some(dialect_name) = items.get(1).and_then(|e| symbol_name(Some(e))) else {
        return true;
    };
    registry.find_by_name(dialect_name).is_some()
}

fn violation_performative(error: &ValidationError) -> Option<String> {
    match error {
        ValidationError::ShapeViolation { blame, .. }
        | ValidationError::CausalViolation { blame, .. } => {
            blame.performative.as_ref().map(String::from)
        }
        _ => None,
    }
}

fn violation_thread(error: &ValidationError) -> Option<String> {
    match error {
        ValidationError::ShapeViolation { blame, .. }
        | ValidationError::CausalViolation { blame, .. } => blame.thread_id.clone(),
        _ => None,
    }
}

fn unwrap_supported_message<'a>(
    input: &str,
    message: &'a Message,
) -> Result<(SExpr, &'a Message), CbclValidationError> {
    let sexpr = cbcl_parser::parse(input).map_err(malformed_parse)?;
    let inner_expr = unwrap_supported_expr(&sexpr)?.clone();

    let inner_message = match message {
        Message::Dialect { inner, .. } => inner.as_ref(),
        Message::Wrapped { .. } => return Err(CbclValidationError::UnsupportedWrapper),
        other => other,
    };

    Ok((inner_expr, inner_message))
}

fn unwrap_supported_expr(expr: &SExpr) -> Result<&SExpr, CbclValidationError> {
    let SExpr::List(items) = expr else {
        return Err(CbclValidationError::Malformed(
            "message must be a list".to_owned(),
        ));
    };

    let Some(head) = symbol_name(items.first()) else {
        return Err(CbclValidationError::Malformed(
            "message head must be a symbol".to_owned(),
        ));
    };

    match head {
        "lang" => {
            if items.len() != 3 {
                return Err(CbclValidationError::Malformed(
                    "lang wrapper requires dialect name and one inner message".to_owned(),
                ));
            }
            if !matches!(items.get(1), Some(SExpr::Atom(Atom::Symbol(_)))) {
                return Err(CbclValidationError::Malformed(
                    "lang wrapper dialect name must be a symbol".to_owned(),
                ));
            }
            let inner = &items[2];
            if is_wrapper_expr(inner) {
                return Err(CbclValidationError::UnsupportedWrapper);
            }
            Ok(inner)
        }
        "envelope" | "signed" | "with-limits" => Err(CbclValidationError::UnsupportedWrapper),
        _ => Ok(expr),
    }
}

fn is_wrapper_expr(expr: &SExpr) -> bool {
    match expr {
        SExpr::List(items) => matches!(
            symbol_name(items.first()),
            Some("lang" | "envelope" | "signed" | "with-limits")
        ),
        SExpr::Atom(_) => false,
    }
}

fn validate_thread(expr: &SExpr) -> Result<String, CbclValidationError> {
    let SExpr::List(items) = expr else {
        return Err(CbclValidationError::Malformed(
            "message must be a list".to_owned(),
        ));
    };

    let mut thread_values = items.windows(2).filter_map(|window| match &window[0] {
        SExpr::Atom(Atom::Keyword(keyword)) if keyword == "thread" => Some(&window[1]),
        _ => None,
    });

    let Some(value) = thread_values.next() else {
        return Err(CbclValidationError::MissingThread);
    };
    if thread_values.next().is_some() {
        return Err(CbclValidationError::DuplicateThread);
    }

    match value {
        SExpr::Atom(Atom::Str(thread)) if thread.is_empty() => {
            Err(CbclValidationError::EmptyThread)
        }
        SExpr::Atom(Atom::Str(thread)) => Ok(thread.clone()),
        _ => Err(CbclValidationError::NonStringThread),
    }
}

fn validate_kind(message: &Message, expected_kind: MessageKind) -> Result<(), CbclValidationError> {
    let Message::Simple {
        performative,
        recipient,
        content,
        ..
    } = message
    else {
        unreachable!("caller only passes simple messages");
    };

    let expected_performative = expected_kind.expected_performative();
    if performative != &Performative::Core(expected_performative) {
        return Err(kind_mismatch(
            expected_kind,
            performative.name().to_owned(),
            expected_performative,
        ));
    }

    if expected_kind == MessageKind::Progress {
        if recipient.as_deref() != Some("@router") {
            return Err(CbclValidationError::InvalidProgressRecipient);
        }
        if !matches!(content, SExpr::Atom(Atom::Str(text)) if text == "progress") {
            return Err(CbclValidationError::InvalidProgressContent);
        }
    }

    Ok(())
}

fn kind_mismatch(
    expected: MessageKind,
    actual: String,
    expected_performative: CorePerformative,
) -> CbclValidationError {
    CbclValidationError::KindMismatch {
        expected: expected.command_name(),
        expected_performative: expected_performative.as_str(),
        actual,
    }
}

fn symbol_name(expr: Option<&SExpr>) -> Option<&str> {
    match expr {
        Some(SExpr::Atom(Atom::Symbol(symbol))) => Some(symbol.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SPEC-009 inbound classification.
//
// validate_for_send/2 above is the outbound path — it rejects meta because
// the only kinds clients send through that surface (reply/error/progress)
// can't be meta. INCOMING frames are a separate concern: the router can push
// `(meta (teach @<self> (define ...)))` announcements to subscribers, and
// hark must surface those distinctly from ordinary work so the daemon can
// install + cache the dialect before forwarding to the consumer.
// ---------------------------------------------------------------------------

/// What an inbound WS frame looks like once classified.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InboundClass {
    /// A SPEC-009 dialect push: `(meta (teach @<recipient> (define <name> ...)))`.
    /// `define_form` holds the inner `(define ...)` form as raw bytes so the
    /// daemon can re-canonicalise + hash without re-walking the SExpr.
    DialectPush {
        recipient: String,
        name: String,
        define_form: String,
    },
    /// A bare `(reply ...)` frame from the router — typically the response
    /// to an agent-initiated `(meta (teach ...))` or `(meta (query (list)))`.
    /// Used by the daemon to route the next meta-reply to a pending
    /// `send_meta_and_await` waiter. Normal asks arrive wrapped in
    /// `(lang <dialect> (ask ...))` and stay as `Ordinary`.
    MetaReply,
    /// Anything else — pass through to the agent's inbound queue verbatim.
    Ordinary,
    /// Couldn't even parse the frame. Caller decides whether to log/drop.
    Malformed(String),
}

/// Best-effort classification of an inbound CBCL frame. Never panics; on
/// parse failure returns `Malformed` so the caller can choose policy.
pub fn classify_inbound(text: &str) -> InboundClass {
    let sexpr = match cbcl_parser::parse(text) {
        Ok(sexpr) => sexpr,
        Err(error) => return InboundClass::Malformed(error.to_string()),
    };
    let Some(items) = list_items(&sexpr) else {
        return InboundClass::Ordinary;
    };
    if symbol_name(items.first()) == Some("reply") {
        return InboundClass::MetaReply;
    }
    if symbol_name(items.first()) != Some("meta") {
        return InboundClass::Ordinary;
    }
    // (meta <op-form>) — op-form's head decides the operation.
    let Some(op_form) = items.get(1) else {
        return InboundClass::Ordinary;
    };
    let Some(op_items) = list_items(op_form) else {
        return InboundClass::Ordinary;
    };
    if symbol_name(op_items.first()) != Some("teach") {
        return InboundClass::Ordinary;
    }
    // (teach @<recipient> (define <name> ...))
    let Some(recipient_expr) = op_items.get(1) else {
        return InboundClass::Ordinary;
    };
    let Some(recipient_sym) = symbol_name(Some(recipient_expr)) else {
        return InboundClass::Ordinary;
    };
    let recipient = recipient_sym.trim_start_matches('@').to_owned();
    let Some(define_expr) = op_items.get(2) else {
        return InboundClass::Ordinary;
    };
    let Some(define_items) = list_items(define_expr) else {
        return InboundClass::Ordinary;
    };
    if symbol_name(define_items.first()) != Some("define") {
        return InboundClass::Ordinary;
    }
    let Some(name) = define_items.get(1).and_then(|e| symbol_name(Some(e))) else {
        return InboundClass::Ordinary;
    };
    InboundClass::DialectPush {
        recipient,
        name: name.to_owned(),
        define_form: define_expr.to_string(),
    }
}

fn list_items(expr: &SExpr) -> Option<&Vec<SExpr>> {
    match expr {
        SExpr::List(items) => Some(items),
        SExpr::Atom(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(input: &str, kind: MessageKind) -> Result<ValidatedMessage, CbclValidationError> {
        validate_for_send(input, kind)
    }

    fn assert_error_code(input: &str, kind: MessageKind, expected_code: &str) {
        let error = validate(input, kind).expect_err("validation should fail");
        assert_eq!(error.code(), expected_code, "{error}");
    }

    #[test]
    fn cbcl_validation_accepts_bare_reply_with_thread() {
        let validated = validate(r#"(reply "done" :thread "rcp-1")"#, MessageKind::Reply).unwrap();

        assert_eq!(validated.kind, MessageKind::Reply);
        assert_eq!(validated.thread, "rcp-1");
    }

    #[test]
    fn cbcl_validation_accepts_wrapped_error_with_thread() {
        let validated = validate(
            r#"(lang elf (error "failed" :thread "rcp-2"))"#,
            MessageKind::Error,
        )
        .unwrap();

        assert_eq!(validated.kind, MessageKind::Error);
        assert_eq!(validated.thread, "rcp-2");
    }

    #[test]
    fn cbcl_validation_rejects_malformed_cbcl() {
        assert_error_code(
            "(reply \"done\" :thread",
            MessageKind::Reply,
            "cbcl_malformed",
        );
    }

    #[test]
    fn cbcl_validation_rejects_kind_mismatch() {
        assert_error_code(
            r#"(error "failed" :thread "rcp-1")"#,
            MessageKind::Reply,
            "cbcl_kind_mismatch",
        );
    }

    #[test]
    fn cbcl_validation_rejects_missing_thread() {
        assert_error_code(
            r#"(reply "done")"#,
            MessageKind::Reply,
            "cbcl_thread_missing",
        );
    }

    #[test]
    fn cbcl_validation_rejects_duplicate_thread() {
        assert_error_code(
            r#"(reply "done" :thread "rcp-1" :thread "rcp-2")"#,
            MessageKind::Reply,
            "cbcl_thread_duplicate",
        );
    }

    #[test]
    fn cbcl_validation_rejects_empty_thread() {
        assert_error_code(
            r#"(reply "done" :thread "")"#,
            MessageKind::Reply,
            "cbcl_thread_empty",
        );
    }

    #[test]
    fn cbcl_validation_rejects_non_string_thread() {
        assert_error_code(
            r#"(reply "done" :thread rcp-1)"#,
            MessageKind::Reply,
            "cbcl_thread_non_string",
        );
    }

    #[test]
    fn cbcl_validation_accepts_valid_progress() {
        let validated = validate(
            r#"(lang elf (tell @router "progress" :thread "rcp-3"))"#,
            MessageKind::Progress,
        )
        .unwrap();

        assert_eq!(validated.kind, MessageKind::Progress);
        assert_eq!(validated.thread, "rcp-3");
    }

    #[test]
    fn cbcl_validation_rejects_progress_with_invalid_recipient() {
        assert_error_code(
            r#"(tell @worker "progress" :thread "rcp-3")"#,
            MessageKind::Progress,
            "cbcl_progress_recipient",
        );
    }

    #[test]
    fn cbcl_validation_rejects_progress_with_invalid_content() {
        assert_error_code(
            r#"(tell @router "working" :thread "rcp-3")"#,
            MessageKind::Progress,
            "cbcl_progress_content",
        );
    }

    #[test]
    fn cbcl_validation_rejects_unsupported_wrappers() {
        assert_error_code(
            r#"(signed "sig" (reply "done" :thread "rcp-1"))"#,
            MessageKind::Reply,
            "cbcl_unsupported_wrapper",
        );
        assert_error_code(
            r#"(lang elf (lang inner (reply "done" :thread "rcp-1")))"#,
            MessageKind::Reply,
            "cbcl_unsupported_wrapper",
        );
    }

    // ----- SPEC-009 inbound classification -----

    #[test]
    fn classify_inbound_recognises_dialect_push() {
        let frame = "(meta (teach @local-agent (define arena-v1 (cbcl) @author)))";
        match classify_inbound(frame) {
            InboundClass::DialectPush {
                recipient,
                name,
                define_form,
            } => {
                assert_eq!(recipient, "local-agent");
                assert_eq!(name, "arena-v1");
                assert!(define_form.contains("define"));
                assert!(define_form.contains("arena-v1"));
            }
            other => panic!("expected DialectPush, got {other:?}"),
        }
    }

    #[test]
    fn classify_inbound_passes_through_ordinary_frames() {
        let dispatched_ask =
            r#"(lang arena-v1 (ask @worker "psi-commit" :n 7 :thread "rcp-1"))"#;
        assert!(matches!(
            classify_inbound(dispatched_ask),
            InboundClass::Ordinary
        ));
    }

    #[test]
    fn classify_inbound_passes_through_meta_query_reply() {
        // A teach-back from `(meta (query (speak? X)))` also matches the
        // DialectPush shape — by design, since both deliver a define the
        // client should install. The receive loop's behaviour for both is
        // identical: install + forward.
        let teach_back = "(meta (teach @asker (define answer (cbcl) @author)))";
        assert!(matches!(
            classify_inbound(teach_back),
            InboundClass::DialectPush { .. }
        ));
    }

    #[test]
    fn classify_inbound_marks_malformed() {
        assert!(matches!(
            classify_inbound("(unclosed"),
            InboundClass::Malformed(_)
        ));
    }

    // ----- R5 Phase B: shape + causal verification on outbound -----
    //
    // These exercise `validate_for_send_with_context` directly so the
    // assertions are independent of the HTTP plumbing. They install a
    // synthetic dialect into a `DialectRegistry`, then send a message
    // that triggers the protocol/shape rule and check the error code
    // maps to the new `shape_violation` / `causal_violation` variants.

    use cbcl_core::dialect::{Dialect, DialectRegistry, PerformativeDef, ResourceBounds};
    use cbcl_core::protocol::{CausalProtocol, NodeRef, StepDecl};
    use cbcl_core::shape::{ShapeConstraint, ShapeRule, TypeConstraint};
    use cbcl_core::store::ThreadedMessageStore;
    use std::collections::BTreeMap;

    fn effect_template(action: &str) -> SExpr {
        SExpr::List(vec![
            SExpr::Atom(Atom::Symbol(String::from("effect"))),
            SExpr::Atom(Atom::Symbol(String::from(action))),
        ])
    }

    /// Registry with a `shape-dialect` whose `reply` shape requires a
    /// `:package` string keyword on its `track` performative. A
    /// `(track @router :thread ...)` send with no `:package` must fail
    /// with `shape_violation`.
    ///
    /// Shape constraints can target inherited core performatives in
    /// principle, but cbcl-rs's R5 validator requires shape rules to
    /// reference a performative that *is* defined by the dialect (or
    /// inherited), so we pin the rule to the dialect-local `track`
    /// performative to keep the fixture self-contained.
    fn shape_constraint_registry() -> DialectRegistry {
        let mut registry = DialectRegistry::new();
        registry
            .install(Dialect {
                name: String::from("shape-dialect"),
                extends: vec![String::from("cbcl")],
                author: None,
                performatives: vec![PerformativeDef {
                    name: String::from("track"),
                    params: vec![],
                    template: effect_template("track-action"),
                }],
                resources: ResourceBounds {
                    max_depth: 8,
                    max_expansion_size: 512,
                    verification_time_ms: 10,
                },
                examples: vec![],
                signature: None,
                hash: None,
                protocol: None,
                causal_protocol: None,
                shapes: vec![ShapeConstraint {
                    performative: String::from("track"),
                    rules: vec![ShapeRule::Require {
                        keyword: String::from("package"),
                        type_constraint: Some(TypeConstraint::String),
                        children: vec![],
                    }],
                }],
            })
            .expect("shape-dialect installs cleanly");
        registry
    }

    /// Registry with a `causal-dialect` whose protocol declares
    /// `begin → notify`. A `notify` with `:caused-by` referencing a
    /// hash that isn't in the per-handle store must fail with
    /// `causal_violation` under the default Reject policy.
    ///
    /// Uses a non-core performative `notify` because core performatives
    /// (R3) cannot be redefined by a child dialect, and the protocol
    /// step decl only matches performative names that resolve through
    /// the registry.
    fn causal_protocol_registry() -> DialectRegistry {
        let mut steps = BTreeMap::new();
        steps.insert(
            "begin".into(),
            StepDecl {
                performative: "begin".into(),
                predecessors: vec![],
                successors: vec![NodeRef::Single("notify".into())],
            },
        );
        steps.insert(
            "notify".into(),
            StepDecl {
                performative: "notify".into(),
                predecessors: vec![NodeRef::Single("begin".into())],
                successors: vec![],
            },
        );
        let mut registry = DialectRegistry::new();
        registry
            .install(Dialect {
                name: String::from("causal-dialect"),
                extends: vec![String::from("cbcl")],
                author: None,
                performatives: vec![
                    PerformativeDef {
                        name: String::from("begin"),
                        params: vec![],
                        template: effect_template("begin-action"),
                    },
                    PerformativeDef {
                        name: String::from("notify"),
                        params: vec![],
                        template: effect_template("notify-action"),
                    },
                ],
                resources: ResourceBounds {
                    max_depth: 8,
                    max_expansion_size: 512,
                    verification_time_ms: 10,
                },
                examples: vec![],
                signature: None,
                hash: None,
                protocol: None,
                causal_protocol: Some(CausalProtocol { steps }),
                shapes: vec![],
            })
            .expect("causal-dialect installs cleanly");
        registry
    }

    #[test]
    fn validate_for_send_surfaces_shape_violation() {
        // The outbound surface only emits reply/error/progress, but
        // `validate_for_send_with_context` rejects on shape before the
        // kind check — we want to confirm the violation code surfaces
        // through `from_pipeline_validation`. Use `MessageKind::Reply`
        // and a `track` message; the shape check fires first because
        // its dialect rule matches the `track` performative.
        let registry = shape_constraint_registry();
        let mut store = ThreadedMessageStore::new();
        let error = validate_for_send_with_context(
            r#"(lang shape-dialect (track @worker :thread "rcp-1"))"#,
            MessageKind::Reply,
            &registry,
            &mut store,
        )
        .expect_err("missing :package must violate shape constraint");
        assert_eq!(
            error.code(),
            "shape_violation",
            "expected shape_violation, got: {error}"
        );
    }

    #[test]
    fn emit_accepts_lang_and_bare_messages() {
        let registry = DialectRegistry::new();
        let mut store = ThreadedMessageStore::new();
        // A proactive (lang …) ask — which validate_for_send rejects as an
        // unsupported wrapper — is accepted for emit (unknown dialect →
        // lightweight R1–R4 pipeline).
        validate_for_emit(
            r#"(lang cbcl-cli (ls @host "/etc" :from @aria :thread "t1"))"#,
            &registry,
            &mut store,
        )
        .expect("a well-formed lang emit is accepted");
        // A bare message needs no reply shape and no :thread.
        validate_for_emit(r#"(tell @general "hi" :from @aria)"#, &registry, &mut store)
            .expect("a bare message emits");
    }

    #[test]
    fn emit_rejects_meta_and_malformed() {
        let registry = DialectRegistry::new();
        let mut store = ThreadedMessageStore::new();
        assert!(
            validate_for_emit("not (((valid", &registry, &mut store).is_err(),
            "malformed input must be refused"
        );
        assert!(
            validate_for_emit("(meta (query (list)))", &registry, &mut store).is_err(),
            "a (meta …) form is not an emittable message"
        );
    }

    #[test]
    fn emit_still_enforces_r5_shape() {
        // An emit is not an R5 bypass: a known-dialect message that violates
        // its shape is refused just as on the send path.
        let registry = shape_constraint_registry();
        let mut store = ThreadedMessageStore::new();
        let error = validate_for_emit(
            r#"(lang shape-dialect (track @worker :thread "rcp-1"))"#,
            &registry,
            &mut store,
        )
        .expect_err("missing :package must violate shape even on emit");
        assert_eq!(error.code(), "shape_violation", "got: {error}");
    }

    #[test]
    fn validate_for_send_surfaces_causal_violation_for_unknown_predecessor() {
        let registry = causal_protocol_registry();
        let mut store = ThreadedMessageStore::new();
        // `notify` declares `begin` as its only predecessor; with
        // `:caused-by` referencing a hash that isn't in the store, the
        // default Reject policy returns `Pending`, which the outbound
        // validator maps to `causal_violation` (the predecessor is
        // unknown, so we can't accept the message in order).
        let error = validate_for_send_with_context(
            r#"(lang causal-dialect (notify @worker :thread "rcp-1" :caused-by "sha256:unknown"))"#,
            MessageKind::Reply,
            &registry,
            &mut store,
        )
        .expect_err("unknown causal predecessor must be rejected");
        assert_eq!(
            error.code(),
            "causal_violation",
            "expected causal_violation, got: {error}"
        );
    }

    #[test]
    fn validate_for_send_passes_through_when_lang_dialect_unknown() {
        // The agent advertises `elf` but the daemon hasn't received
        // its `(define ...)` push yet. Fall back to the lightweight
        // pipeline rather than fail-closed on `UnknownDialect`, so
        // existing happy-path tests in `tests/router_integration.rs`
        // (which use `lang elf` with an empty registry) continue to
        // pass. R5 enforcement kicks in once the dialect is installed.
        let registry = DialectRegistry::new(); // base only
        let mut store = ThreadedMessageStore::new();
        let validated = validate_for_send_with_context(
            r#"(lang elf (reply "done" :thread "rcp-1"))"#,
            MessageKind::Reply,
            &registry,
            &mut store,
        )
        .expect("unknown lang dialect must fall back to the lightweight pipeline");
        assert_eq!(validated.kind, MessageKind::Reply);
        assert_eq!(validated.thread, "rcp-1");
    }
}
