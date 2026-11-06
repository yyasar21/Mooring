//! Panic-free entry points of the directory importer's fuzz targets (feature `directory`):
//!
//! | target | entry | oracle |
//! | --- | --- | --- |
//! | `ldap_filter_escape` | [`fuzz_filter_escape`] | the escaped value holds no raw `( ) * \` or control byte, unescapes back to the input, and the built filter is one balanced expression; DN and URL parsers never panic, a parsed DN round-trips through its wire form |
//! | `ldap_ber_response` | [`fuzz_ber_response`] | `scan` → `parse_tag` → message / result / control / entry decoders → plan: no panic, scan-accepted frames parse, the plan passes the importer oracle |

use lber::structure::StructureTag;

use super::entry::{extract, EntryLimits, ATTRIBUTES};
use super::filter::{escape_value, search_filter, Dn, LdapTarget};
use super::frame::{scan, Scan};
use super::plan::{build_plan, PlanOptions};
use super::wire::{decode_message, paging_cookie, result_code};
use super::DirectoryKind;
use crate::fuzz::check_plan;
use crate::{ImportOptions, Limits};

/// Inverse of [`escape_value`] for the oracle: `\XX` pairs back to bytes.
fn unescape(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// `ldap_filter_escape`.
pub fn fuzz_filter_escape(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let escaped = escape_value(&text);
    assert!(!escaped.bytes().any(|b| matches!(b, b'(' | b')' | b'*' | 0x00..=0x1f | 0x7f)));
    assert_eq!(unescape(&escaped).as_deref(), Some(text.as_bytes()), "escape round trip");
    for kind in [DirectoryKind::Ad, DirectoryKind::OpenLdap] {
        if let Ok(f) = search_filter(kind, Some(&text)) {
            let (mut depth, mut max) = (0i32, 0i32);
            for c in f.chars() {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "unbalanced filter");
                max = max.max(depth);
            }
            assert_eq!(depth, 0, "unbalanced filter");
            assert!(max <= 4, "a user value widened the filter");
        }
    }
    if let Ok(dn) = Dn::parse(&text) {
        let wire = dn.to_wire();
        assert_eq!(Dn::parse(&wire).ok().as_ref(), Some(&dn), "DN round trip");
        let _ = dn.domain();
        let _ = dn.relative_to(&dn);
    }
    let _ = LdapTarget::parse(&text).map(|t| t.url());
}

fn walk_message(tag: &StructureTag, limits: &EntryLimits) {
    let _ = extract(tag, &ATTRIBUTES, limits);
    let Ok(m) = decode_message(tag) else { return };
    let _ = result_code(&m.op_tag);
    let _ = paging_cookie(m.controls.as_ref());
    if let Ok(entry) = extract(&m.op_tag, &ATTRIBUTES, limits) {
        let Ok(base) = Dn::parse("dc=corp,dc=example,dc=test") else { return };
        let entries = vec![entry.clone(), entry];
        for kind in [DirectoryKind::Ad, DirectoryKind::OpenLdap] {
            let opts =
                PlanOptions { kind, base: base.clone(), max_depth: 8, limits: Limits::DEFAULT };
            if let Ok(plan) = build_plan(&entries, &opts) {
                let import_opts =
                    ImportOptions { include_plaintext_secrets: false, limits: Limits::DEFAULT };
                check_plan(&plan, &import_opts, false);
                assert!(plan.connections.len() <= 2 && plan.credentials.len() <= 1);
            }
        }
    }
}

/// `ldap_ber_response`.
pub fn fuzz_ber_response(data: &[u8]) {
    let limits = EntryLimits::default();
    match scan(data) {
        Scan::Complete(n) => {
            assert!(n <= data.len());
            let parsed = lber::parse::parse_tag(&data[..n]);
            let Ok((rest, tag)) = parsed else { panic!("scan accepted a frame lber refuses") };
            assert!(rest.is_empty(), "scan length disagrees with lber");
            walk_message(&tag, &limits);
        }
        Scan::Incomplete | Scan::Invalid(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_run_on_seeds_and_garbage() {
        for s in [
            "",
            "web01",
            "*)(objectClass=*",
            "cn=a\\,b,dc=x",
            "ldaps://h:636",
            "\u{fffd}\0\\",
            "cn=x,",
        ] {
            fuzz_filter_escape(s.as_bytes());
        }
        fuzz_filter_escape(b"\xff\xfe\\");
        let entry = crate::ldap::tests::entry_tag(
            "CN=web01,OU=Servers,DC=corp,DC=example,DC=test",
            &[
                ("cn", &["web01"]),
                ("dNSHostName", &["web01.corp.example.test"]),
                ("operatingSystem", &["Windows"]),
            ],
        );
        let msg = lber::structures::Tag::Sequence(lber::structures::Sequence {
            inner: vec![
                lber::structures::Tag::Integer(lber::structures::Integer {
                    inner: 2,
                    ..Default::default()
                }),
                lber::structures::Tag::StructureTag(entry),
            ],
            ..Default::default()
        });
        let mut buf = bytes::BytesMut::new();
        lber::write::encode_into(&mut buf, lber::structures::ASNTag::into_structure(msg))
            .expect("encode");
        fuzz_ber_response(&buf);
        fuzz_ber_response(&buf[..buf.len() - 3]);
        fuzz_ber_response(b"\x30\x00");
        fuzz_ber_response(b"\x30\x84\xff\xff\xff\xff");
        fuzz_ber_response(b"\xff\xff");
        fuzz_ber_response(b"");
    }
}
