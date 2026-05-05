#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MessageKind {
    Reply,
    Error,
    Progress,
}
