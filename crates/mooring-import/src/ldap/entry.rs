//! Safe extraction of a `SearchResultEntry` from a parsed BER structure (`ldap3`'s own
//! `SearchEntry::construct` panics on a malformed entry). This walk returns an error
//! instead, caps every value and keeps only the attributes the importer asked for. Fuzzed
//! through `ldap_ber_response` (raw BER → scan → parse → [`extract`] → plan).

use lber::common::TagClass;
use lber::structure::{StructureTag, PL};

/// Attributes the importer requests (case-insensitive on the wire).
pub const ATTRIBUTES: [&str; 6] =
    ["cn", "dNSHostName", "operatingSystem", "description", "distinguishedName", "ipHostNumber"];

/// Caps on one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryLimits {
    /// Longest DN (bytes).
    pub max_dn: usize,
    /// Longest attribute value kept (bytes); longer ones are dropped.
    pub max_value: usize,
    /// Most values kept per attribute.
    pub max_values: usize,
    /// Most attributes looked at per entry (the rest are ignored).
    pub max_attrs: usize,
}

impl Default for EntryLimits {
    fn default() -> Self {
        Self { max_dn: 1024, max_value: 1024, max_values: 16, max_attrs: 64 }
    }
}

/// One entry: its DN and the requested attributes (type lower-cased).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEntry {
    /// `objectName`.
    pub dn: String,
    /// Kept attributes with their text values.
    pub attrs: Vec<(String, Vec<String>)>,
    /// Values dropped for being binary or over the cap.
    pub dropped_values: usize,
}

impl RawEntry {
    /// First value of `attr` (case-insensitive).
    #[must_use]
    pub fn first(&self, attr: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attr))
            .and_then(|(_, v)| v.first())
            .map(String::as_str)
    }
}

const APPLICATION_SEARCH_ENTRY: u64 = 4;
const UNIVERSAL_OCTET_STRING: u64 = 4;
const UNIVERSAL_SEQUENCE: u64 = 16;
const UNIVERSAL_SET: u64 = 17;

fn primitive(t: &StructureTag, id: u64) -> Option<&[u8]> {
    match (&t.class, t.id, &t.payload) {
        (TagClass::Universal, i, PL::P(bytes)) if i == id => Some(bytes.as_slice()),
        _ => None,
    }
}

fn constructed(t: &StructureTag, class: TagClass, id: u64) -> Option<&[StructureTag]> {
    match (&t.class, t.id, &t.payload) {
        (c, i, PL::C(items)) if *c == class && i == id => Some(items.as_slice()),
        _ => None,
    }
}

/// Walk `tag` as `[APPLICATION 4] { objectName, attributes }`. `keep` names the attributes to
/// retain (case-insensitive); others are skipped without decoding their values.
pub fn extract(
    tag: &StructureTag,
    keep: &[&str],
    limits: &EntryLimits,
) -> Result<RawEntry, &'static str> {
    let parts = constructed(tag, TagClass::Application, APPLICATION_SEARCH_ENTRY)
        .ok_or("not a search result entry")?;
    let [dn_tag, attrs_tag] = parts else { return Err("entry is not {dn, attributes}") };
    let dn_bytes = primitive(dn_tag, UNIVERSAL_OCTET_STRING).ok_or("dn is not an octet string")?;
    if dn_bytes.len() > limits.max_dn {
        return Err("dn exceeds the cap");
    }
    let dn = std::str::from_utf8(dn_bytes).map_err(|_| "dn is not UTF-8")?;
    if dn.chars().any(char::is_control) {
        return Err("dn has control characters");
    }
    let attrs_list = constructed(attrs_tag, TagClass::Universal, UNIVERSAL_SEQUENCE)
        .ok_or("attributes is not a sequence")?;
    let mut entry = RawEntry { dn: dn.to_owned(), ..RawEntry::default() };
    for attr in attrs_list.iter().take(limits.max_attrs) {
        let pair = constructed(attr, TagClass::Universal, UNIVERSAL_SEQUENCE)
            .ok_or("attribute is not a sequence")?;
        let [type_tag, vals_tag] = pair else { return Err("attribute is not {type, vals}") };
        let name =
            primitive(type_tag, UNIVERSAL_OCTET_STRING).ok_or("type is not an octet string")?;
        let Ok(name) = std::str::from_utf8(name) else { return Err("type is not UTF-8") };
        if name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b';')
        {
            return Err("type is not an attribute description");
        }
        let vals =
            constructed(vals_tag, TagClass::Universal, UNIVERSAL_SET).ok_or("vals is not a set")?;
        if !keep.iter().any(|k| k.eq_ignore_ascii_case(name)) {
            continue;
        }
        let mut values = Vec::new();
        for v in vals {
            let bytes =
                primitive(v, UNIVERSAL_OCTET_STRING).ok_or("value is not an octet string")?;
            if values.len() >= limits.max_values || bytes.len() > limits.max_value {
                entry.dropped_values += 1;
                continue;
            }
            match std::str::from_utf8(bytes) {
                Ok(s) if !s.chars().any(char::is_control) => values.push(s.to_owned()),
                _ => entry.dropped_values += 1,
            }
        }
        entry.attrs.push((name.to_ascii_lowercase(), values));
    }
    Ok(entry)
}
