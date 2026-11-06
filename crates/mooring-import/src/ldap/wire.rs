//! LDAP v3 messages of the reader (RFC 4511): the four requests it may send (bind, search,
//! abandon, unbind — nothing else exists here) and the responses it understands. Encoding
//! uses `lber`'s structures; decoding walks `lber::StructureTag`s without panicking.

use bytes::BytesMut;
use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::{ASNTag, Boolean, Enumerated, Integer, Null, OctetString, Sequence, Tag};

use super::{DirectoryKind, SearchScope};

pub const APP_BIND_REQUEST: u64 = 0;
pub const APP_BIND_RESPONSE: u64 = 1;
pub const APP_UNBIND: u64 = 2;
pub const APP_SEARCH_REQUEST: u64 = 3;
pub const APP_SEARCH_ENTRY: u64 = 4;
pub const APP_SEARCH_DONE: u64 = 5;
pub const APP_ABANDON: u64 = 16;
pub const APP_SEARCH_REF: u64 = 19;
pub const APP_EXTENDED_RESPONSE: u64 = 24;
pub const APP_INTERMEDIATE: u64 = 25;
/// RFC 2696 paged results control.
pub const PAGED_OID: &str = "1.2.840.113556.1.4.319";

fn octet(b: &[u8]) -> Tag {
    Tag::OctetString(OctetString { inner: b.to_vec(), ..Default::default() })
}

fn int(i: i64) -> Tag {
    Tag::Integer(Integer { inner: i, ..Default::default() })
}

fn enumerated(i: i64) -> Tag {
    Tag::Enumerated(Enumerated { inner: i, ..Default::default() })
}

fn seq(inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { inner, ..Default::default() })
}

fn app(id: u64, inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { id, class: TagClass::Application, inner })
}

fn ctx(id: u64, inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence { id, class: TagClass::Context, inner })
}

fn encode(tag: Tag) -> Vec<u8> {
    let mut buf = BytesMut::new();
    // `encode_into` only fails on an unwritable buffer; a `BytesMut` grows.
    let _ = lber::write::encode_into(&mut buf, tag.into_structure());
    buf.to_vec()
}

fn message(msgid: i32, op: Tag, controls: Option<Tag>) -> Vec<u8> {
    let mut inner = vec![int(i64::from(msgid)), op];
    inner.extend(controls);
    encode(seq(inner))
}

/// `BindRequest { version 3, name, simple password }`.
pub fn bind_request(msgid: i32, name: &str, password: &str) -> Vec<u8> {
    let simple = Tag::OctetString(OctetString {
        id: 0,
        class: TagClass::Context,
        inner: password.as_bytes().to_vec(),
    });
    message(msgid, app(APP_BIND_REQUEST, vec![int(3), octet(name.as_bytes()), simple]), None)
}

/// What one `SearchRequest` carries.
#[derive(Debug, Clone)]
pub struct SearchParams<'a> {
    pub base: &'a str,
    pub scope: SearchScope,
    pub size_limit: i32,
    pub time_limit: i32,
    pub filter: &'a StructureTag,
    pub attrs: &'a [&'a str],
    /// Paged-results page size.
    pub page: i32,
    /// Paged-results cookie (empty on the first page).
    pub cookie: &'a [u8],
}

/// `SearchRequest` with the paged-results control, `derefAliases = neverDerefAliases`,
/// `typesOnly = false`.
pub fn search_request(msgid: i32, p: &SearchParams<'_>) -> Vec<u8> {
    let SearchParams { base, scope, size_limit, time_limit, filter, attrs, page, cookie } = *p;
    let scope = match scope {
        SearchScope::Base => 0,
        SearchScope::One => 1,
        SearchScope::Sub => 2,
    };
    let op = app(
        APP_SEARCH_REQUEST,
        vec![
            octet(base.as_bytes()),
            enumerated(scope),
            enumerated(0),
            int(i64::from(size_limit)),
            int(i64::from(time_limit)),
            Tag::Boolean(Boolean { inner: false, ..Default::default() }),
            Tag::StructureTag(filter.clone()),
            seq(attrs.iter().map(|a| octet(a.as_bytes())).collect()),
        ],
    );
    let value = encode(seq(vec![int(i64::from(page)), octet(cookie)]));
    let controls = ctx(0, vec![seq(vec![octet(PAGED_OID.as_bytes()), octet(&value)])]);
    message(msgid, op, Some(controls))
}

fn eq(attr: &str, value: &str) -> Tag {
    Tag::Sequence(Sequence {
        id: 3,
        class: TagClass::Context,
        inner: vec![octet(attr.as_bytes()), octet(value.as_bytes())],
    })
}

/// `(attr=*value*)`: a substrings filter with one `any` component.
fn contains(attr: &str, value: &str) -> Tag {
    let any = Tag::OctetString(OctetString {
        id: 1,
        class: TagClass::Context,
        inner: value.as_bytes().to_vec(),
    });
    Tag::Sequence(Sequence {
        id: 4,
        class: TagClass::Context,
        inner: vec![octet(attr.as_bytes()), seq(vec![any])],
    })
}

/// The search filter as BER (RFC 4511 §4.5.1): the class filter of `kind`, AND-ed with a
/// `cn` / `dNSHostName` substring match when `name_contains` is set. Values travel as octet
/// strings, so no escaping is involved on the wire; [`super::filter::search_filter`] is the
/// same filter in text form (display, audit, recorder).
pub fn filter_tag(kind: DirectoryKind, name_contains: Option<&str>) -> StructureTag {
    let class = match kind {
        DirectoryKind::Ad => eq("objectClass", "computer"),
        DirectoryKind::OpenLdap => {
            ctx(1, vec![eq("objectClass", "ipHost"), eq("objectClass", "device")])
        }
    };
    let tag = match name_contains {
        Some(v) => ctx(0, vec![class, ctx(1, vec![contains("cn", v), contains("dNSHostName", v)])]),
        None => class,
    };
    tag.into_structure()
}

/// `AbandonRequest`.
pub fn abandon_request(msgid: i32, target: i32) -> Vec<u8> {
    let op = Tag::Integer(Integer {
        id: APP_ABANDON,
        class: TagClass::Application,
        inner: i64::from(target),
    });
    message(msgid, op, None)
}

/// `UnbindRequest`.
pub fn unbind_request(msgid: i32) -> Vec<u8> {
    message(
        msgid,
        Tag::Null(Null { id: APP_UNBIND, class: TagClass::Application, inner: () }),
        None,
    )
}

/// A decoded `LDAPMessage` from the server.
#[derive(Debug, Clone)]
pub struct Message {
    pub msgid: i32,
    /// Application tag of the protocol op.
    pub op: u64,
    pub op_tag: StructureTag,
    /// Response controls (`[0] Controls`), when present.
    pub controls: Option<StructureTag>,
}

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

fn integer(t: &StructureTag) -> Option<i64> {
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

/// Split an `LDAPMessage`: `{ messageID, protocolOp [APPLICATION n], controls [0] OPTIONAL }`.
pub fn decode_message(tag: &StructureTag) -> Result<Message, &'static str> {
    if tag.class != TagClass::Universal || tag.id != 16 {
        return Err("not an LDAPMessage");
    }
    let items = constructed(tag).ok_or("not an LDAPMessage")?;
    let (id_tag, op_tag, rest) = match items {
        [id, op, rest @ ..] if rest.len() <= 1 => (id, op, rest),
        _ => return Err("LDAPMessage has the wrong number of elements"),
    };
    if id_tag.class != TagClass::Universal || id_tag.id != 2 {
        return Err("messageID is not an integer");
    }
    let msgid =
        integer(id_tag).and_then(|i| i32::try_from(i).ok()).ok_or("messageID out of range")?;
    if op_tag.class != TagClass::Application {
        return Err("protocolOp is not an application tag");
    }
    let controls = match rest.first() {
        Some(c) if c.class == TagClass::Context && c.id == 0 && matches!(c.payload, PL::C(_)) => {
            Some(c.clone())
        }
        Some(_) => return Err("trailing element is not controls"),
        None => None,
    };
    Ok(Message { msgid, op: op_tag.id, op_tag: op_tag.clone(), controls })
}

/// `LDAPResult.resultCode` of a bind response or search result done.
pub fn result_code(op_tag: &StructureTag) -> Result<u32, &'static str> {
    let items = constructed(op_tag).ok_or("result is not a sequence")?;
    let rc = items.first().ok_or("result has no resultCode")?;
    if rc.class != TagClass::Universal || rc.id != 10 {
        return Err("resultCode is not an enumerated");
    }
    integer(rc).and_then(|i| u32::try_from(i).ok()).ok_or("resultCode out of range")
}

/// The paged-results cookie of a response's controls: `Some(empty)` when the control is
/// absent (the server did not page), `None` for a malformed control value.
pub fn paging_cookie(controls: Option<&StructureTag>) -> Option<Vec<u8>> {
    let Some(ctrls) = controls.and_then(constructed) else { return Some(Vec::new()) };
    for c in ctrls {
        let parts = constructed(c)?;
        let oid = primitive(parts.first()?)?;
        if oid != PAGED_OID.as_bytes() {
            continue;
        }
        let value = parts.iter().skip(1).find(|p| {
            p.class == TagClass::Universal && p.id == 4 && matches!(p.payload, PL::P(_))
        })?;
        let bytes = primitive(value)?;
        if bytes.len() > 4096
            || !matches!(super::frame::scan(bytes), super::frame::Scan::Complete(n) if n == bytes.len())
        {
            return None;
        }
        let (_, inner) = lber::parse::parse_tag(bytes).ok()?;
        let [size, cookie] = constructed(&inner)? else { return None };
        if size.id != 2 || cookie.id != 4 || cookie.class != TagClass::Universal {
            return None;
        }
        return primitive(cookie).map(<[u8]>::to_vec);
    }
    Some(Vec::new())
}
