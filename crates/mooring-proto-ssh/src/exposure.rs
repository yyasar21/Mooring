//! Forward exposure policy (ADR-0007, security review 2 M-2): loopback by default,
//! anything else only on explicit, audited opt-in.

use mooring_core::MooringError;

/// Who may reach a forward's listener (ADR-0007, security review 2 M-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Exposure {
    /// Loopback only (OpenSSH's client default). A non-loopback bind is refused.
    #[default]
    Loopback,
    /// Any address, on explicit opt-in; audited as `exposure: external`.
    External,
}

impl Exposure {
    /// Stable name for audit and UI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::External => "external",
        }
    }
}

/// Refuse a bind outside loopback unless the caller opted into [`Exposure::External`].
pub(crate) fn check_exposure(loopback: bool, exposure: Exposure) -> Result<(), MooringError> {
    if loopback || exposure == Exposure::External {
        return Ok(());
    }
    Err(MooringError::Invalid {
        field: "bind",
        reason: "forwards bind to loopback unless external exposure is chosen".into(),
    })
}

/// Remote bind hosts that `Exposure::Loopback` accepts (the server resolves the name).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_policy() {
        assert!(check_exposure(true, Exposure::Loopback).is_ok());
        assert!(matches!(
            check_exposure(false, Exposure::Loopback),
            Err(MooringError::Invalid { field: "bind", .. })
        ));
        assert!(check_exposure(false, Exposure::External).is_ok());
        for h in ["localhost", "LOCALHOST", "127.0.0.1", "::1"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["0.0.0.0", "*", "::", "", "192.0.2.1", "localhost.evil", "127.0.0.2"] {
            assert!(!is_loopback_host(h), "{h}");
        }
        assert_eq!(Exposure::default(), Exposure::Loopback);
        assert_eq!(Exposure::External.as_str(), "external");
    }
}
