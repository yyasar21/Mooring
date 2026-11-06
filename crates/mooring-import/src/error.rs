//! Errors of an import parse. Messages carry a code, an offset or line and a fixed reason:
//! never a byte of the input (ADR-0019 §3).

/// Why a file could not be turned into a plan. Items that are merely unusable become
/// `skipped` entries of the plan, not errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// The input (or a member of a directory source) exceeds the input cap.
    #[error("import file is larger than the {max} byte limit")]
    TooLarge {
        /// The cap that was hit.
        max: usize,
    },
    /// Not a document of the named format. `at` is a byte offset or a line number, `what` a
    /// fixed description.
    #[error("not a valid {format} file ({what} at {at})")]
    Format {
        /// Format label.
        format: &'static str,
        /// Fixed reason.
        what: &'static str,
        /// Byte offset or line.
        at: u64,
    },
    /// The document is password protected or encrypted; nothing is decrypted.
    #[error("the document is encrypted; export it without a password first")]
    Encrypted,
    /// `<!DOCTYPE` is refused in every XML input.
    #[error("XML with a DOCTYPE is refused at offset {at}")]
    Doctype {
        /// Byte offset of the declaration.
        at: u64,
    },
    /// A structural cap (depth, element count, text length, decompressed size, item counts).
    #[error("the file exceeds the import limit: {what}")]
    Limits {
        /// Which cap.
        what: &'static str,
    },
    /// A container the importer does not open (ZIP `.rtsz`, owner decision).
    #[error("the file is a {what} container, which is not supported; export the plain document")]
    UnsupportedContainer {
        /// Container kind.
        what: &'static str,
    },
}

impl ImportError {
    /// Stable `import.*` code for IPC.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "import.too_large",
            Self::Format { .. } => "import.format",
            Self::Encrypted => "import.encrypted",
            Self::Doctype { .. } => "import.doctype",
            Self::Limits { .. } => "import.limits",
            Self::UnsupportedContainer { .. } => "import.unsupported_container",
        }
    }

    pub(crate) const fn format(format: &'static str, what: &'static str, at: u64) -> Self {
        Self::Format { format, what, at }
    }

    pub(crate) const fn limits(what: &'static str) -> Self {
        Self::Limits { what }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, ImportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_messages_carry_no_input() {
        let e = ImportError::format("royal_ts", "missing root element", 12);
        assert_eq!(e.code(), "import.format");
        assert_eq!(e.to_string(), "not a valid royal_ts file (missing root element at 12)");
        assert_eq!(ImportError::Doctype { at: 3 }.code(), "import.doctype");
        assert_eq!(ImportError::limits("depth").code(), "import.limits");
        assert_eq!(ImportError::Encrypted.code(), "import.encrypted");
        assert_eq!(ImportError::TooLarge { max: 1 }.code(), "import.too_large");
        assert_eq!(
            ImportError::UnsupportedContainer { what: "zip" }.code(),
            "import.unsupported_container"
        );
    }
}
