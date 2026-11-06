//! The untrusted strings of a directory query: RFC 4515 filter escaping of every user value,
//! the fixed filter shapes, RFC 4514 distinguished names (parsed, never interpolated) and the
//! `ldaps://` URL. Nothing here does I/O; the `ldap_filter_escape` fuzz entry covers
//! [`escape_value`] with the oracle "re-parses to one literal".

use std::fmt::Write as _;

use super::{DirectoryKind, LdapError};

/// Longest base DN accepted (bytes).
pub const MAX_DN: usize = 1024;
/// Most RDNs of a DN.
pub const MAX_RDNS: usize = 64;
/// Longest `nameContains` value (bytes).
pub const MAX_NAME_FILTER: usize = 256;
/// Default LDAPS port.
pub const LDAPS_PORT: u16 = 636;

/// RFC 4515 §3 escaping of one assertion value: `*`, `(`, `)`, `\`, NUL and every other
/// control character become `\XX`; everything else (UTF-8 included) is passed through, so
/// the value can never close, open or widen the filter it is placed in.
#[must_use]
pub fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '*' | '(' | ')' | '\\' | '\x00'..='\x1f' | '\x7f' => {
                let _ = write!(out, "\\{:02x}", c as u8);
            }
            _ => out.push(c),
        }
    }
    out
}

/// The object-class filter of a directory kind: AD computers, or `OpenLDAP` hosts
/// (`ipHost`) and devices.
#[must_use]
pub const fn class_filter(kind: DirectoryKind) -> &'static str {
    match kind {
        DirectoryKind::Ad => "(objectClass=computer)",
        DirectoryKind::OpenLdap => "(|(objectClass=ipHost)(objectClass=device))",
    }
}

/// The search filter: the class filter, optionally AND-ed with a substring match of the
/// escaped `name_contains` on `cn` and `dNSHostName`.
pub fn search_filter(
    kind: DirectoryKind,
    name_contains: Option<&str>,
) -> Result<String, LdapError> {
    let class = class_filter(kind);
    let Some(name) = name_contains.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(class.to_owned());
    };
    if name.len() > MAX_NAME_FILTER || name.chars().any(char::is_control) {
        return Err(LdapError::Invalid("name filter is too long or has control characters"));
    }
    let v = escape_value(name);
    Ok(format!("(&{class}(|(cn=*{v}*)(dNSHostName=*{v}*)))"))
}

/// One attribute-value assertion of an RDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ava {
    /// Attribute type, lower-cased (`ou`, `dc`, `cn`, or a numeric OID).
    pub attr: String,
    /// Unescaped value.
    pub value: String,
}

/// One relative distinguished name (usually a single AVA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    /// AVAs, in order.
    pub avas: Vec<Ava>,
}

impl Rdn {
    /// The display value: the `ou` AVA when present, else the first one.
    #[must_use]
    pub fn display(&self) -> &str {
        self.avas
            .iter()
            .find(|a| a.attr == "ou")
            .or_else(|| self.avas.first())
            .map_or("", |a| a.value.as_str())
    }

    /// Case-folded form for suffix comparison (types and values).
    fn folded(&self) -> Vec<(String, String)> {
        self.avas.iter().map(|a| (a.attr.clone(), a.value.to_lowercase())).collect()
    }
}

/// A parsed DN: RDNs leftmost (most specific) first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn {
    /// RDNs.
    pub rdns: Vec<Rdn>,
}

impl Dn {
    /// Parse per RFC 4514 (string form): RDNs split on unescaped `,`, AVAs on unescaped `+`,
    /// `\XX` and `\<special>` escapes decoded, `#hex` values kept opaque. Bounded by
    /// [`MAX_DN`] and [`MAX_RDNS`]. An empty DN (the root DSE) is refused.
    pub fn parse(text: &str) -> Result<Self, LdapError> {
        let bad = LdapError::DnInvalid;
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_DN {
            return Err(bad("empty or longer than 1024 bytes"));
        }
        if text.chars().any(char::is_control) {
            return Err(bad("control characters"));
        }
        let mut rdns = Vec::new();
        for rdn_text in split_unescaped(text, ',') {
            if rdns.len() >= MAX_RDNS {
                return Err(bad("more than 64 RDNs"));
            }
            let mut avas = Vec::new();
            for ava_text in split_unescaped(&rdn_text, '+') {
                let Some((attr, value)) = ava_text.split_once('=') else {
                    return Err(bad("an RDN is not type=value"));
                };
                let attr = attr.trim().to_ascii_lowercase();
                if !valid_attr_type(&attr) {
                    return Err(bad("invalid attribute type"));
                }
                let value = unescape_value(value.trim_start())?;
                if value.is_empty() {
                    return Err(bad("empty RDN value"));
                }
                avas.push(Ava { attr, value });
            }
            if avas.is_empty() {
                return Err(bad("empty RDN"));
            }
            rdns.push(Rdn { avas });
        }
        if rdns.is_empty() {
            return Err(bad("empty"));
        }
        Ok(Self { rdns })
    }

    /// The RDNs of `self` below `base` (entry RDN first), or `None` when `self` is not under
    /// `base` (compared case-insensitively on types and values).
    #[must_use]
    pub fn relative_to(&self, base: &Self) -> Option<&[Rdn]> {
        let n = self.rdns.len().checked_sub(base.rdns.len())?;
        let tail = &self.rdns[n..];
        let same = tail.iter().zip(&base.rdns).all(|(a, b)| a.folded() == b.folded());
        same.then_some(&self.rdns[..n])
    }

    /// `dc` components joined with `.` (`DC=corp,DC=example,DC=test` → `corp.example.test`),
    /// `None` without any.
    #[must_use]
    pub fn domain(&self) -> Option<String> {
        let parts: Vec<&str> = self
            .rdns
            .iter()
            .flat_map(|r| r.avas.iter())
            .filter(|a| a.attr == "dc")
            .map(|a| a.value.as_str())
            .collect();
        (!parts.is_empty()).then(|| parts.join("."))
    }

    /// RFC 4514 string form (values re-escaped), what goes on the wire as `baseObject`.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let rdn = |r: &Rdn| {
            r.avas
                .iter()
                .map(|a| format!("{}={}", a.attr, escape_dn_value(&a.value)))
                .collect::<Vec<_>>()
                .join("+")
        };
        self.rdns.iter().map(rdn).collect::<Vec<_>>().join(",")
    }
}

fn valid_attr_type(attr: &str) -> bool {
    if attr.is_empty() || attr.len() > 64 {
        return false;
    }
    let descr = attr.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let oid = attr.chars().all(|c| c.is_ascii_digit() || c == '.')
        && !attr.starts_with('.')
        && !attr.ends_with('.')
        && !attr.contains("..");
    descr || oid
}

/// Split on `sep` outside `\` escapes.
fn split_unescaped(text: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            cur.push(c);
            escaped = true;
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// Decode an RFC 4514 value: `\XX` hex pairs (UTF-8 reassembled), `\<special>` pass-through;
/// `#hex` is kept verbatim.
fn unescape_value(raw: &str) -> Result<String, LdapError> {
    let bad = LdapError::DnInvalid;
    if raw.starts_with('#') {
        return Ok(raw.to_owned());
    }
    let mut bytes = Vec::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let Some(n) = chars.next() else { return Err(bad("dangling escape")) };
        if n.is_ascii_hexdigit() {
            let Some(m) = chars.next().filter(char::is_ascii_hexdigit) else {
                return Err(bad("bad hex escape"));
            };
            let hex = [n as u8, m as u8];
            let v = u8::from_str_radix(std::str::from_utf8(&hex).unwrap_or("zz"), 16)
                .map_err(|_| bad("bad hex escape"))?;
            bytes.push(v);
        } else if " \"#+,;<=>\\".contains(n) {
            bytes.push(n as u8);
        } else {
            return Err(bad("unknown escape"));
        }
    }
    let s = String::from_utf8(bytes).map_err(|_| bad("value is not UTF-8"))?;
    if s.chars().any(char::is_control) {
        return Err(bad("control characters"));
    }
    Ok(s.trim_end().to_owned())
}

/// RFC 4514 §2.4 escaping for the wire form.
fn escape_dn_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 4);
    for (i, c) in v.chars().enumerate() {
        let special = matches!(c, '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=')
            || (i == 0 && (c == '#' || c == ' '));
        if special {
            out.push('\\');
        }
        out.push(c);
    }
    if out.ends_with(' ') {
        out.insert(out.len() - 1, '\\');
    }
    out
}

/// The server named by an `ldaps://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapTarget {
    /// Host (lower-case; IPv6 without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
}

impl LdapTarget {
    /// Parse `ldaps://host[:port][/]`. `ldap://` (plaintext or `StartTLS`) → `ldap.insecure`;
    /// anything else, user info, a path or a query → `ldap.invalid`.
    pub fn parse(url: &str) -> Result<Self, LdapError> {
        let bad = LdapError::Invalid;
        let url = url.trim();
        if url.len() > 512 {
            return Err(bad("URL is too long"));
        }
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("ldap://") || lower.starts_with("ldapi://") {
            return Err(LdapError::Insecure);
        }
        let rest = lower.strip_prefix("ldaps://").ok_or(bad("URL must start with ldaps://"))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@', ' ']) || rest.is_empty() {
            return Err(bad("URL must be ldaps://host[:port]"));
        }
        let (host, port) = if let Some(after) = rest.strip_prefix('[') {
            let (h, p) = after.split_once(']').ok_or(bad("unterminated IPv6 literal"))?;
            let port = match p.strip_prefix(':') {
                Some(p) => p.parse::<u16>().map_err(|_| bad("port must be 1..=65535"))?,
                None if p.is_empty() => LDAPS_PORT,
                None => return Err(bad("junk after the IPv6 literal")),
            };
            if h.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(bad("not an IPv6 literal"));
            }
            (h.to_owned(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) => {
                    (h.to_owned(), p.parse::<u16>().map_err(|_| bad("port must be 1..=65535"))?)
                }
                None => (rest.to_owned(), LDAPS_PORT),
            }
        };
        if port == 0 {
            return Err(bad("port must be 1..=65535"));
        }
        let name_ok = host.len() <= 253
            && host
                .split('.')
                .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if !(name_ok || host.parse::<std::net::IpAddr>().is_ok()) {
            return Err(bad("host is not a DNS name or IP address"));
        }
        Ok(Self { host, port })
    }

    /// The canonical URL handed to the client (IPv6 bracketed).
    #[must_use]
    pub fn url(&self) -> String {
        if self.host.contains(':') {
            format!("ldaps://[{}]:{}", self.host, self.port)
        } else {
            format!("ldaps://{}:{}", self.host, self.port)
        }
    }
}
