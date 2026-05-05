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
}
