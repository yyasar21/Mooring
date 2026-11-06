//! BER helpers of the LDAP mock: building LDAPMessages with `lber` and decoding the few
//! request shapes the mock understands (bind, search, abandon, unbind). Hostile raw frames
//! are produced here too.

use bytes::BytesMut;
use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::{ASNTag, Boolean, Enumerated, Integer, OctetString, Sequence, Tag};

use super::Hostile;

pub const APP_BIND_REQUEST: u64 = 0;
pub const APP_BIND_RESPONSE: u64 = 1;
pub const APP_UNBIND: u64 = 2;
pub const APP_SEARCH_REQUEST: u64 = 3;
pub const APP_SEARCH_ENTRY: u64 = 4;
pub const APP_SEARCH_DONE: u64 = 5;
pub const APP_ABANDON: u64 = 16;
pub const APP_SEARCH_REF: u64 = 19;
pub const PAGED_OID: &str = "1.2.840.113556.1.4.319";

pub fn octet(b: &[u8]) -> Tag {
    Tag::OctetString(OctetString { inner: b.to_vec(), ..Default::default() })
}

pub fn int(i: i64) -> Tag {
    Tag::Integer(Integer { inner: i, ..Default::default() })
}

pub fn enumerated(i: i64) -> Tag {
    Tag::Enumerated(Enumerated { inner: i, ..Default::default() })
}

pub fn boolean(b: bool) -> Tag {
    Tag::Boolean(Boolean { inner: b, ..Default::default() })
}

pub fn seq(inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { inner, ..Default::default() })
}

pub fn set(inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { id: 17, inner, ..Default::default() })
}

pub fn app(id: u64, inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { id, class: TagClass::Application, inner })
}

pub fn ctx(id: u64, inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { id, class: TagClass::Context, inner })
}

/// Encode one tag to bytes.
pub fn encode(tag: Tag) -> Vec<u8> {
    let mut buf = BytesMut::new();
    lber::write::encode_into(&mut buf, tag.into_structure()).expect("encode");
    buf.to_vec()
}

/// `LDAPMessage { messageID, protocolOp, controls? }`.
pub fn message(msgid: i64, op: Tag, controls: Option<Tag>) -> Vec<u8> {
    let mut inner = vec![int(msgid), op];
    if let Some(c) = controls {
        inner.push(c);
    }
    encode(seq(inner))
}

/// `LDAPResult { resultCode, matchedDN, diagnosticMessage }` plus optional referral URIs.
pub fn result(app_id: u64, rc: i64, text: &str, refs: &[&str]) -> Tag {
    let mut inner = vec![enumerated(rc), octet(b""), octet(text.as_bytes())];
    if !refs.is_empty() {
        inner.push(ctx(3, refs.iter().map(|r| octet(r.as_bytes())).collect()));
    }
    app(app_id, inner)
}

/// The paged-results response control (`[0] { Control { oid, value } }`).
pub fn paged_control(size: i64, cookie: &[u8]) -> Tag {
    let value = encode(seq(vec![int(size), octet(cookie)]));
    ctx(0, vec![seq(vec![octet(PAGED_OID.as_bytes()), octet(&value)])])
}

/// A `SearchResultEntry`.
pub fn entry(dn: &str, attrs: &[(String, Vec<String>)]) -> Tag {
    let attrs = attrs
        .iter()
        .map(|(name, vals)| {
            seq(vec![
                octet(name.as_bytes()),
                set(vals.iter().map(|v| octet(v.as_bytes())).collect()),
            ])
        })
        .collect();
    app(APP_SEARCH_ENTRY, vec![octet(dn.as_bytes()), seq(attrs)])
}

/// `len` BER length octets (short or long form).
fn length(len: usize) -> Vec<u8> {
    if let Ok(short) = u8::try_from(len) {
        if short < 128 {
            return vec![short];
        }
    }
    let be = len.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let mut out = vec![0x80 | u8::try_from(be.len() - first).unwrap_or(8)];
    out.extend_from_slice(&be[first..]);
    out
}

/// `depth` nested universal SEQUENCEs around an empty one (stack-depth probe).
pub fn deep_nesting(depth: usize) -> Vec<u8> {
    let mut inner = vec![0x30, 0x00];
    for _ in 0..depth {
        let mut next = vec![0x30];
        next.extend(length(inner.len()));
        next.extend_from_slice(&inner);
        inner = next;
    }
    inner
}

/// A SEQUENCE header claiming `claimed` bytes followed by `present` bytes of zeros.
pub fn huge_length(claimed: u32, present: usize) -> Vec<u8> {
    let mut out = vec![0x30, 0x84];
    out.extend_from_slice(&claimed.to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, present));
    out
}

/// The bytes of a [`Hostile`] reply to a search with message id `msgid`.
pub fn hostile_bytes(h: Hostile, msgid: i64) -> Vec<u8> {
    match h {
        Hostile::EmptyMessage => vec![0x30, 0x00],
        Hostile::DeepNesting(n) => deep_nesting(n),
        Hostile::HugeLength => huge_length(0xffff_ffff, 16),
        Hostile::Garbage => (0..64u8).map(|i| 0xff - i).collect(),
        Hostile::OversizedValue(n) => {
            let attrs = vec![
                ("cn".to_owned(), vec!["BIG".to_owned()]),
                ("dNSHostName".to_owned(), vec!["big.corp.example.test".to_owned()]),
                ("description".to_owned(), vec!["x".repeat(n)]),
            ];
            let mut out = message(msgid, entry("CN=BIG,DC=corp,DC=example,DC=test", &attrs), None);
            out.extend(message(msgid, result(APP_SEARCH_DONE, 0, "", &[]), None));
            out
        }
        Hostile::ExtraElement => {
            let e = app(
                APP_SEARCH_ENTRY,
                vec![octet(b"CN=X,DC=corp,DC=example,DC=test"), seq(vec![]), octet(b"extra")],
            );
            let mut out = message(msgid, e, None);
            out.extend(message(msgid, result(APP_SEARCH_DONE, 0, "", &[]), None));
            out
        }
    }
}

// ---- request decoding -------------------------------------------------------------------

pub fn constructed(t: &StructureTag) -> Option<&[StructureTag]> {
    match &t.payload {
        PL::C(items) => Some(items.as_slice()),
        PL::P(_) => None,
    }
}

pub fn primitive(t: &StructureTag) -> Option<&[u8]> {
    match &t.payload {
        PL::P(b) => Some(b.as_slice()),
        PL::C(_) => None,
    }
}

pub fn text(t: &StructureTag) -> Option<String> {
    primitive(t).map(|b| String::from_utf8_lossy(b).into_owned())
}

pub fn integer(t: &StructureTag) -> Option<i64> {
    let b = primitive(t)?;
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in b {
        v = (v << 8) | i64::from(*byte);
    }
    Some(v)
}

/// A decoded LDAPMessage.
#[derive(Debug, Clone)]
pub struct Request {
    pub msgid: i64,
    /// Application tag of the protocol op.
    pub op: u64,
    pub op_tag: StructureTag,
    /// Paged-results request control: `(size, cookie)`.
    pub paged: Option<(i64, Vec<u8>)>,
    /// Every control OID sent.
    pub controls: Vec<String>,
}

/// Split an LDAPMessage; `None` when it is not one.
pub fn decode_request(tag: &StructureTag) -> Option<Request> {
    let items = constructed(tag)?;
    if tag.class != TagClass::Universal || tag.id != 16 || items.len() < 2 || items.len() > 3 {
        return None;
    }
    let msgid = integer(&items[0])?;
    let op_tag = items[1].clone();
    if op_tag.class != TagClass::Application {
        return None;
    }
    let (mut paged, mut controls) = (None, Vec::new());
    if let Some(ctrls) = items.get(2).and_then(constructed) {
        for c in ctrls {
            let parts = constructed(c)?;
            let oid = text(parts.first()?)?;
            if oid == PAGED_OID {
                let value =
                    parts.iter().skip(1).find(|p| p.id == 4 && p.class == TagClass::Universal);
                let (_, v) = lber::parse::parse_tag(primitive(value?)?).ok()?;
                let pv = constructed(&v)?;
                paged = Some((integer(pv.first()?)?, primitive(pv.get(1)?)?.to_vec()));
            }
            controls.push(oid);
        }
    }
    Some(Request { msgid, op: op_tag.id, op_tag, paged, controls })
}

/// `BindRequest { version, name, simple password }`: `(name, password)`; `None` for SASL or
/// a malformed shape.
pub fn decode_bind(op: &StructureTag) -> Option<(String, Vec<u8>)> {
    let items = constructed(op)?;
    let [_version, name, auth] = items else { return None };
    if auth.class != TagClass::Context || auth.id != 0 {
        return None;
    }
    Some((text(name)?, primitive(auth)?.to_vec()))
}

/// The fields of a `SearchRequest`.
#[derive(Debug, Clone)]
pub struct Search {
    pub base: String,
    pub scope: i64,
    pub size_limit: i64,
    pub time_limit: i64,
    pub filter: StructureTag,
    pub attrs: Vec<String>,
}

pub fn decode_search(op: &StructureTag) -> Option<Search> {
    let items = constructed(op)?;
    let [base, scope, _deref, size, time, _types_only, filter, attrs] = items else { return None };
    Some(Search {
        base: text(base)?,
        scope: integer(scope)?,
        size_limit: integer(size)?,
        time_limit: integer(time)?,
        filter: filter.clone(),
        attrs: constructed(attrs)?.iter().filter_map(text).collect(),
    })
}
