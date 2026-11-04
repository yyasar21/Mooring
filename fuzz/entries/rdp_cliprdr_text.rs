//! Fuzz entry `rdp_cliprdr_text`: hostile cliprdr format data → text ≤ 1 MiB (ADR-0011 `cliprdr_text`); byte 0 picks `CF_UNICODETEXT` (even) or `CF_TEXT` (odd).

/// Never panics.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::cliprdr_text(data);
}
