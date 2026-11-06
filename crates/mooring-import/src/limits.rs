//! Size and structure caps (ADR-0019 §3). Every cap is checked before the matching
//! allocation; exceeding one is `import.limits` (`import.too_large` for the raw input).

/// Caps applied to one import. The defaults are the ADR values; tests lower them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Raw input bytes (one file, or each file of a directory source).
    pub max_input: usize,
    /// Decompressed size of a compressed container.
    pub max_decompressed: usize,
    /// Decompressed / compressed ratio.
    pub max_ratio: usize,
    /// XML nesting depth.
    pub max_xml_depth: usize,
    /// XML elements per document.
    pub max_xml_elements: usize,
    /// Longest attribute value, text node, CSV field, JSON string or config line (bytes).
    pub max_text: usize,
    /// Plan connections.
    pub max_connections: usize,
    /// Plan folders.
    pub max_folders: usize,
    /// Plan credentials.
    pub max_credentials: usize,
    /// Rows of the `skipped` and `warnings` lists; further entries are counted only.
    pub max_notes: usize,
}

impl Limits {
    /// ADR-0019 §3 values.
    pub const DEFAULT: Self = Self {
        max_input: 16 * 1024 * 1024,
        max_decompressed: 64 * 1024 * 1024,
        max_ratio: 20,
        max_xml_depth: 64,
        max_xml_elements: 200_000,
        max_text: 4096,
        max_connections: 20_000,
        max_folders: 5_000,
        max_credentials: 2_000,
        max_notes: 20_000,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
