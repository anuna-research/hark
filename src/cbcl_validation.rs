use cbcl_core::{
    message::{CorePerformative, Message, Performative},
    sexpr::{Atom, SExpr},
};
use cbcl_parser::{ParseError, PipelineResult, run_pipeline};
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
        }
    }
}

pub fn validate_for_send(
    input: &str,
    expected_kind: MessageKind,
) -> Result<ValidatedMessage, CbclValidationError> {
    let message = match run_pipeline(input) {
        PipelineResult::Success(message) => message,
        PipelineResult::ParseError(error) => return Err(malformed_parse(error)),
        PipelineResult::ValidationError(error) => {
            return Err(CbclValidationError::Malformed(error.to_string()));
        }
        PipelineResult::Pending { .. } | PipelineResult::Buffered { .. } => {
            return Err(CbclValidationError::Malformed(
                "unexpected pipeline state during local validation".to_owned(),
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

    Ok(ValidatedMessage {
        kind: expected_kind,
        thread,
    })
}

fn malformed_parse(error: ParseError) -> CbclValidationError {
    CbclValidationError::Malformed(error.to_string())
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
}
