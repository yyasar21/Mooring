//! Search-filter evaluation and rendering for the LDAP mock: `and`, `or`, `not`, equality,
//! substrings and presence (what the importer sends). Rendering re-escapes assertion values
//! per RFC 4515, so a test can assert that an injected `)(` reached the server as a literal.

use std::fmt::Write as _;

use lber::common::TagClass;
use lber::structure::StructureTag;

use super::ber::{constructed, primitive, text};
use super::LdapEntry;

const AND: u64 = 0;
const OR: u64 = 1;
const NOT: u64 = 2;
const EQ: u64 = 3;
const SUBSTR: u64 = 4;
const PRESENT: u64 = 7;

fn values<'a>(e: &'a LdapEntry, attr: &str) -> Vec<&'a str> {
    e.attrs
        .iter()
        .filter(|(a, _)| a.eq_ignore_ascii_case(attr))
        .flat_map(|(_, v)| v.iter().map(String::as_str))
        .collect()
}

/// Whether `entry` matches `filter`. Unknown shapes match nothing.
pub fn matches(filter: &StructureTag, entry: &LdapEntry) -> bool {
    if filter.class != TagClass::Context {
        return false;
    }
    match filter.id {
        AND => constructed(filter).is_some_and(|f| f.iter().all(|x| matches(x, entry))),
        OR => constructed(filter).is_some_and(|f| f.iter().any(|x| matches(x, entry))),
        NOT => constructed(filter).and_then(|f| f.first()).is_some_and(|x| !matches(x, entry)),
        EQ => {
            let Some([attr, value]) = constructed(filter) else { return false };
            let (Some(attr), Some(value)) = (text(attr), text(value)) else { return false };
            values(entry, &attr).iter().any(|v| v.eq_ignore_ascii_case(&value))
        }
        SUBSTR => {
            let Some([attr, parts]) = constructed(filter) else { return false };
            let (Some(attr), Some(parts)) = (text(attr), constructed(parts)) else { return false };
            values(entry, &attr).iter().any(|v| substr_matches(parts, &v.to_lowercase()))
        }
        PRESENT => primitive(filter)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .is_some_and(|attr| !values(entry, &attr).is_empty()),
        _ => false,
    }
}

fn substr_matches(parts: &[StructureTag], value: &str) -> bool {
    let mut rest = value;
    for p in parts {
        let Some(piece) = text(p) else { return false };
        let piece = piece.to_lowercase();
        match p.id {
            0 => match rest.strip_prefix(piece.as_str()) {
                Some(r) => rest = r,
                None => return false,
            },
            1 => match rest.find(piece.as_str()) {
                Some(i) => rest = &rest[i + piece.len()..],
                None => return false,
            },
            2 => return rest.ends_with(piece.as_str()),
            _ => return false,
        }
    }
    true
}

fn escape(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars() {
        match c {
            '*' | '(' | ')' | '\\' | '\x00'..='\x1f' | '\x7f' => {
                let _ = write!(out, "\\{:02x}", c as u8);
            }
            _ => out.push(c),
        }
    }
    out
}

/// RFC 4515 text of `filter` (`?` for shapes the mock does not know).
pub fn render(filter: &StructureTag) -> String {
    if filter.class != TagClass::Context {
        return "?".to_owned();
    }
    let join = |op: &str| {
        let inner: String =
            constructed(filter).map(|f| f.iter().map(render).collect()).unwrap_or_default();
        format!("({op}{inner})")
    };
    match filter.id {
        AND => join("&"),
        OR => join("|"),
        NOT => join("!"),
        EQ => match constructed(filter) {
            Some([a, v]) => format!(
                "({}={})",
                text(a).unwrap_or_default(),
                escape(&text(v).unwrap_or_default())
            ),
            _ => "?".to_owned(),
        },
        SUBSTR => match constructed(filter) {
            Some([a, parts]) => {
                let mut s = format!("({}=", text(a).unwrap_or_default());
                let parts = constructed(parts).unwrap_or_default();
                for (i, p) in parts.iter().enumerate() {
                    let piece = escape(&text(p).unwrap_or_default());
                    match p.id {
                        0 => {
                            let _ = write!(s, "{piece}*");
                        }
                        1 => {
                            if i == 0 {
                                s.push('*');
                            }
                            let _ = write!(s, "{piece}*");
                        }
                        _ => {
                            if i == 0 {
                                s.push('*');
                            }
                            s.push_str(&piece);
                        }
                    }
                }
                s.push(')');
                s
            }
            _ => "?".to_owned(),
        },
        PRESENT => format!(
            "({}=*)",
            primitive(filter).map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default()
        ),
        _ => "?".to_owned(),
    }
}
