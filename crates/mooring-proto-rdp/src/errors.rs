//! `IronRDP` / I/O errors → `(CloseCode, reason)`. Reasons are fixed English strings or
//! `IronRDP`'s static negotiation texts: never server-controlled bytes, never secrets. The
//! original error goes to `tracing::debug!` only.

use std::io;

use ironrdp_connector::{ConnectorError, ConnectorErrorKind};
use ironrdp_session::{SessionError, SessionErrorKind};
use mooring_core::session::CloseCode;

/// A session-ending cause.
pub(crate) type End = (CloseCode, String);

pub(crate) fn end(code: CloseCode, reason: &str) -> End {
    (code, reason.to_owned())
}

fn has_io_source(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if err.is::<io::Error>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Connection-sequence errors.
pub(crate) fn connector(e: &ConnectorError) -> End {
    tracing::debug!(error = %e, "rdp connection sequence failed");
    match e.kind() {
        ConnectorErrorKind::Credssp(_) | ConnectorErrorKind::AccessDenied => {
            end(CloseCode::AuthFailed, "authentication failed (NLA)")
        }
        ConnectorErrorKind::Negotiation(failure) => {
            (CloseCode::ProtocolError, format!("security negotiation failed: {failure}"))
        }
        _ if std::error::Error::source(e).is_some_and(has_io_source) => {
            end(CloseCode::Network, "connection lost during the handshake")
        }
        _ => end(CloseCode::ProtocolError, "protocol error during the connection sequence"),
    }
}

/// Active-stage errors.
pub(crate) fn session(e: &SessionError) -> End {
    tracing::debug!(error = %e, "rdp active stage failed");
    match e.kind() {
        SessionErrorKind::Custom if std::error::Error::source(e).is_some_and(has_io_source) => {
            end(CloseCode::Network, "connection lost")
        }
        _ => end(CloseCode::ProtocolError, "the server sent data Mooring could not process"),
    }
}

/// Transport errors.
pub(crate) fn io(e: &io::Error) -> End {
    tracing::debug!(error = %e, "rdp transport error");
    match e.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => {
            end(CloseCode::ServerEnded, "the server closed the connection")
        }
        io::ErrorKind::InvalidData => {
            end(CloseCode::ProtocolError, "the server sent malformed data")
        }
        _ => end(CloseCode::Network, "connection lost"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_connector::ConnectorErrorExt as _;

    #[test]
    fn maps_without_leaking_detail() {
        let e = ConnectorError::new("CredSSP", ConnectorErrorKind::AccessDenied);
        assert_eq!(connector(&e).0, CloseCode::AuthFailed);
        let e = ConnectorError::custom("read frame", io::Error::other("secret-ish detail"));
        let (code, reason) = connector(&e);
        assert_eq!(code, CloseCode::Network);
        assert!(!reason.contains("secret"));
        let e = ConnectorError::reason("x", "server text");
        let (code, reason) = connector(&e);
        assert_eq!(code, CloseCode::ProtocolError);
        assert!(!reason.contains("server text"));
        assert_eq!(io(&io::Error::from(io::ErrorKind::UnexpectedEof)).0, CloseCode::ServerEnded);
        assert_eq!(io(&io::Error::from(io::ErrorKind::TimedOut)).0, CloseCode::Network);
    }
}
