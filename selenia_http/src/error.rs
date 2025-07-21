//! HTTP error mapping utilities.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    MalformedHeader,
    NoMatch,
    WafBlock,
    UpstreamTimeout,
    Internal,
}

impl ErrorKind {
    /// Map error kind to HTTP status code as per DESIGN.md §15.
    pub fn status_code(self) -> u16 {
        match self {
            ErrorKind::MalformedHeader => 400,
            ErrorKind::NoMatch => 404,
            ErrorKind::WafBlock => 403,
            ErrorKind::UpstreamTimeout => 504,
            ErrorKind::Internal => 500,
        }
    }

    /// Map error kind to log level string.
    pub fn log_level(self) -> &'static str {
        match self {
            ErrorKind::MalformedHeader => "WARN",
            ErrorKind::NoMatch => "INFO",
            ErrorKind::WafBlock => "INFO",
            ErrorKind::UpstreamTimeout => "WARN",
            ErrorKind::Internal => "ERROR",
        }
    }
} 