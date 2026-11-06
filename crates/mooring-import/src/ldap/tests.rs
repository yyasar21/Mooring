//! Pure tests of the directory importer: escaping, DN parsing, URL parsing, entry extraction
//! and the plan mapping. The network path is covered by `tests/ldap_mock.rs` against the
//! `mooring-testsrv` LDAP mock.

use ldap3::asn1::{StructureTag, TagClass, PL};
use mooring_core::{CredentialKind, Protocol};

use super::entry::{extract, EntryLimits};
use super::filter::Rdn;
use super::*;
use crate::{SkipReason, WarningCode};

fn prim(id: u64, v: &[u8]) -> StructureTag {
    StructureTag { class: TagClass::Universal, id, payload: PL::P(v.to_vec()) }
}

fn cons(class: TagClass, id: u64, items: Vec<StructureTag>) -> StructureTag {
    StructureTag { class, id, payload: PL::C(items) }
}

/// A well-formed `SearchResultEntry`.
pub(crate) fn entry_tag(dn: &str, attrs: &[(&str, &[&str])]) -> StructureTag {
    let attrs = attrs
        .iter()
        .map(|(name, vals)| {
            let set =
                cons(TagClass::Universal, 17, vals.iter().map(|v| prim(4, v.as_bytes())).collect());
            cons(TagClass::Universal, 16, vec![prim(4, name.as_bytes()), set])
        })
        .collect();
    cons(
        TagClass::Application,
        4,
        vec![prim(4, dn.as_bytes()), cons(TagClass::Universal, 16, attrs)],
    )
}

fn raw(dn: &str, attrs: &[(&str, &[&str])]) -> RawEntry {
    extract(&entry_tag(dn, attrs), &ATTRIBUTES, &EntryLimits::default()).expect("entry")
}

const BASE: &str = "DC=corp,DC=example,DC=test";

#[test]
fn escape_covers_the_rfc_4515_set_and_control_bytes() {
    assert_eq!(escape_value("plain-01"), "plain-01");
    assert_eq!(escape_value("a*b(c)d\\e"), "a\\2ab\\28c\\29d\\5ce");
    assert_eq!(escape_value("x\0y\x1fz\x7f"), "x\\00y\\1fz\\7f");
    assert_eq!(escape_value("héllo wörld"), "héllo wörld");
    // An injected clause stays a literal.
    let f = search_filter(DirectoryKind::Ad, Some("*)(objectClass=*")).expect("filter");
    assert_eq!(f, "(&(objectClass=computer)(|(cn=*\\2a\\29\\28objectClass=\\2a*)(dNSHostName=*\\2a\\29\\28objectClass=\\2a*)))");
    assert_eq!(
        search_filter(DirectoryKind::OpenLdap, Some("  ")).expect("f"),
        "(|(objectClass=ipHost)(objectClass=device))"
    );
    assert_eq!(
        search_filter(DirectoryKind::Ad, Some("a\nb")).expect_err("ctl").code(),
        "ldap.invalid"
    );
    assert_eq!(
        search_filter(DirectoryKind::Ad, Some(&"a".repeat(257))).expect_err("long").code(),
        "ldap.invalid"
    );
}

#[test]
fn escaped_values_re_parse_as_one_literal() {
    for v in ["web01", "a*b", ")(", "\\", "(cn=x)", "ünï", "\0\x01", "*"] {
        let f = format!("(cn={})", escape_value(v));
        let tag = ldap3::parse_filter(&f).expect("parses");
        let st = ldap3::asn1::ASNTag::into_structure(tag);
        assert_eq!((st.class, st.id), (TagClass::Context, 3), "{v:?} is an equality match");
        let PL::C(items) = st.payload else { panic!("constructed") };
        let PL::P(val) = &items[1].payload else { panic!("value") };
        assert_eq!(val.as_slice(), v.as_bytes(), "{v:?} round-trips");
    }
}

#[test]
fn dn_parse_relative_and_domain() {
    let base = Dn::parse(BASE).expect("base");
    assert_eq!(base.rdns.len(), 3);
    assert_eq!(base.domain().as_deref(), Some("corp.example.test"));
    assert_eq!(base.to_wire(), "dc=corp,dc=example,dc=test");
    let e = Dn::parse("CN=web01,OU=Servers,OU=Prod,dc=CORP,DC=Example,DC=test").expect("dn");
    let rel = e.relative_to(&base).expect("under base");
    assert_eq!(rel.iter().map(Rdn::display).collect::<Vec<_>>(), ["web01", "Servers", "Prod"]);
    assert!(Dn::parse("CN=x,DC=other,DC=test").expect("dn").relative_to(&base).is_none());
    assert!(Dn::parse("DC=example,DC=test").expect("short").relative_to(&base).is_none());
    assert!(base.relative_to(&base).expect("itself").is_empty());
    // Escapes: `\,` and `\2C` are a literal comma; multi-valued RDN keeps `ou` for display.
    let d = Dn::parse(r"CN=Smith\, John,OU=A\2Cb+cn=zz,DC=x").expect("escapes");
    assert_eq!(d.rdns[0].avas[0].value, "Smith, John");
    assert_eq!(d.rdns[1].display(), "A,b");
    assert_eq!(d.to_wire(), r"cn=Smith\, John,ou=A\,b+cn=zz,dc=x");
    // `#hex` values are opaque, OIDs are types.
    assert!(Dn::parse("1.2.3=#0401ff,dc=x").is_ok());
    for bad in ["", "nodots", "cn=,dc=x", "=x", "cn=a\\", "cn=a\\zz", "cn=a\nb", "-x=1", "1..2=v"] {
        assert_eq!(Dn::parse(bad).expect_err(bad).code(), "ldap.dn_invalid", "{bad}");
    }
    assert!(Dn::parse(&"cn=a,".repeat(65)).is_err());
    assert!(Dn::parse(&format!("cn={}", "a".repeat(1100))).is_err());
}

#[test]
fn url_parse_is_ldaps_only() {
    assert_eq!(
        LdapTarget::parse("ldaps://dc.example.test").expect("u"),
        LdapTarget { host: "dc.example.test".into(), port: 636 }
    );
    assert_eq!(LdapTarget::parse("LDAPS://DC.Example.test:3269/").expect("u").port, 3269);
    assert_eq!(
        LdapTarget::parse("ldaps://[2001:db8::1]:636").expect("v6").url(),
        "ldaps://[2001:db8::1]:636"
    );
    assert_eq!(
        LdapTarget::parse("ldaps://192.0.2.10").expect("v4").url(),
        "ldaps://192.0.2.10:636"
    );
    assert_eq!(
        LdapTarget::parse("ldap://dc.example.test").expect_err("plain").code(),
        "ldap.insecure"
    );
    assert_eq!(
        LdapTarget::parse("ldapi:///var/run/ldapi").expect_err("unix").code(),
        "ldap.insecure"
    );
    for bad in [
        "https://dc.example.test",
        "ldaps://",
        "ldaps://user@dc.example.test",
        "ldaps://dc.example.test/dc=x",
        "ldaps://dc.example.test?x",
        "ldaps://dc.example.test:0",
        "ldaps://dc.example.test:99999",
        "ldaps://bad host",
        "ldaps://[::1",
        "ldaps://[zz]:636",
        "ldaps://a..b",
    ] {
        assert_eq!(LdapTarget::parse(bad).expect_err(bad).code(), "ldap.invalid", "{bad}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn extract_walks_a_valid_entry_and_refuses_malformed_ones() {
    let e = raw(
        "CN=web01,OU=Srv,DC=x",
        &[
            ("dNSHostName", &["web01.example.test"]),
            ("operatingSystem", &["Windows Server 2022"]),
            ("memberOf", &["cn=g"]),
        ],
    );
    assert_eq!(e.first("dnshostname"), Some("web01.example.test"));
    assert_eq!(e.first("DNSHOSTNAME"), Some("web01.example.test"));
    assert_eq!(e.first("memberof"), None, "unrequested attributes are not kept");
    assert_eq!(e.attrs.len(), 2);
    let lim = EntryLimits { max_dn: 8, ..EntryLimits::default() };
    assert_eq!(
        extract(&entry_tag("CN=toolong,DC=x", &[]), &ATTRIBUTES, &lim),
        Err("dn exceeds the cap")
    );
    let lim = EntryLimits { max_value: 4, max_values: 1, ..EntryLimits::default() };
    let e = extract(&entry_tag("CN=a", &[("cn", &["abcde", "ab", "cd"])]), &ATTRIBUTES, &lim)
        .expect("ok");
    assert_eq!((e.first("cn"), e.dropped_values), (Some("ab"), 2));
    let bad = [
        cons(TagClass::Application, 5, vec![]),
        cons(TagClass::Application, 4, vec![prim(4, b"dn")]),
        cons(
            TagClass::Application,
            4,
            vec![prim(2, b"\x01"), cons(TagClass::Universal, 16, vec![])],
        ),
        cons(
            TagClass::Application,
            4,
            vec![prim(4, b"\xff"), cons(TagClass::Universal, 16, vec![])],
        ),
        cons(
            TagClass::Application,
            4,
            vec![prim(4, b"d\x00n"), cons(TagClass::Universal, 16, vec![])],
        ),
        cons(TagClass::Application, 4, vec![prim(4, b"dn"), prim(4, b"x")]),
        cons(
            TagClass::Application,
            4,
            vec![prim(4, b"dn"), cons(TagClass::Universal, 16, vec![prim(4, b"x")])],
        ),
        cons(
            TagClass::Application,
            4,
            vec![
                prim(4, b"dn"),
                cons(
                    TagClass::Universal,
                    16,
                    vec![cons(TagClass::Universal, 16, vec![prim(4, b"cn"), prim(4, b"v")])],
                ),
            ],
        ),
        cons(
            TagClass::Application,
            4,
            vec![
                prim(4, b"dn"),
                cons(
                    TagClass::Universal,
                    16,
                    vec![cons(
                        TagClass::Universal,
                        16,
                        vec![prim(4, b"c n"), cons(TagClass::Universal, 17, vec![])],
                    )],
                ),
            ],
        ),
        cons(
            TagClass::Application,
            4,
            vec![
                prim(4, b"dn"),
                cons(
                    TagClass::Universal,
                    16,
                    vec![cons(
                        TagClass::Universal,
                        16,
                        vec![
                            prim(4, b"cn"),
                            cons(
                                TagClass::Universal,
                                17,
                                vec![cons(TagClass::Universal, 16, vec![])],
                            ),
                        ],
                    )],
                ),
            ],
        ),
    ];
    for b in &bad {
        assert!(extract(b, &ATTRIBUTES, &EntryLimits::default()).is_err(), "{b:?}");
    }
    // Binary values are dropped, not errors.
    let e = raw("CN=a", &[("description", &["\u{fffd}ok"])]);
    assert_eq!(e.first("description"), Some("\u{fffd}ok"));
    let st = cons(
        TagClass::Application,
        4,
        vec![
            prim(4, b"cn=a"),
            cons(
                TagClass::Universal,
                16,
                vec![cons(
                    TagClass::Universal,
                    16,
                    vec![prim(4, b"cn"), cons(TagClass::Universal, 17, vec![prim(4, b"\xff\xfe")])],
                )],
            ),
        ],
    );
    let e = extract(&st, &ATTRIBUTES, &EntryLimits::default()).expect("binary dropped");
    assert_eq!((e.first("cn"), e.dropped_values), (None, 1));
}

#[test]
fn plan_mirrors_ou_path_and_picks_protocol_by_os() {
    let base = Dn::parse(BASE).expect("base");
    let entries = vec![
        raw(
            "CN=web01,OU=Web,OU=Servers,DC=corp,DC=example,DC=test",
            &[
                ("cn", &["web01"]),
                ("dNSHostName", &["web01.corp.example.test"]),
                ("operatingSystem", &["Windows Server 2022 Standard"]),
            ],
        ),
        raw(
            "CN=db01,OU=Servers,DC=corp,DC=example,DC=test",
            &[
                ("cn", &["db01"]),
                ("dNSHostName", &["db01.corp.example.test"]),
                ("operatingSystem", &["Red Hat Enterprise Linux"]),
            ],
        ),
        raw("CN=nohost,OU=Servers,DC=corp,DC=example,DC=test", &[("cn", &["nohost"])]),
        raw("CN=elsewhere,DC=other,DC=test", &[("cn", &["x"]), ("dNSHostName", &["x.other.test"])]),
        raw("not a dn", &[("cn", &["x"])]),
        raw(
            "CN=noos,OU=Servers,DC=corp,DC=example,DC=test",
            &[("dNSHostName", &["noos.corp.example.test"])],
        ),
        raw(
            "CN=bad host,OU=Servers,DC=corp,DC=example,DC=test",
            &[("cn", &["bad"]), ("dNSHostName", &["has space"])],
        ),
    ];
    let plan = build_plan(&entries, &PlanOptions::new(DirectoryKind::Ad, base)).expect("plan");
    let c = plan.counts();
    assert_eq!(
        (c.folders, c.connections, c.credentials, c.secrets, c.skipped, c.warnings),
        (2, 3, 1, 0, 4, 0)
    );
    let servers = plan.folders.iter().find(|f| f.name == "Servers").expect("Servers");
    let web = plan.folders.iter().find(|f| f.name == "Web").expect("Web");
    assert_eq!(
        (servers.parent.as_deref(), web.parent.as_deref()),
        (None, Some(servers.key.as_str()))
    );
    let web01 = plan.connections.iter().find(|c| c.name == "web01").expect("web01");
    assert_eq!(
        (web01.protocol, web01.host.as_str(), web01.folder.as_deref()),
        (Protocol::Rdp, "web01.corp.example.test", Some(web.key.as_str()))
    );
    let db01 = plan.connections.iter().find(|c| c.name == "db01").expect("db01");
    assert_eq!(
        (db01.protocol, db01.folder.as_deref()),
        (Protocol::Ssh, Some(servers.key.as_str()))
    );
    let noos = plan.connections.iter().find(|c| c.name == "noos").expect("rdn name");
    assert_eq!(noos.protocol, Protocol::Ssh);
    let cred = &plan.credentials[0];
    assert_eq!(
        (cred.kind, cred.name.as_str(), cred.has_secret()),
        (CredentialKind::Prompt, "Directory account (corp.example.test)", false)
    );
    assert_eq!(cred.fields["domain"], "corp.example.test");
    assert!(plan.connections.iter().all(|c| c.credential.as_deref() == Some(cred.key.as_str())));
    assert!(plan
        .skipped
        .iter()
        .all(|s| s.reason == SkipReason::Invalid && s.source_ref.starts_with("entry ")));
    assert!(plan.is_consistent());
}

#[test]
fn plan_caps_depth_and_openldap_falls_back_to_cn() {
    let base = Dn::parse("dc=example,dc=test").expect("base");
    let deep = format!(
        "cn=h,{}dc=example,dc=test",
        "ou=l,".repeat(10)
    );
    let entries = vec![
        raw(&deep, &[("cn", &["h"]), ("ipHostNumber", &["192.0.2.7"])]),
        raw("cn=sw1,ou=net,dc=example,dc=test", &[("cn", &["sw1"])]),
        raw("dc=example,dc=test", &[("cn", &["root"]), ("dNSHostName", &["example.test"])]),
    ];
    let plan =
        build_plan(&entries, &PlanOptions::new(DirectoryKind::OpenLdap, base)).expect("plan");
    assert_eq!(plan.counts().folders, MAX_DEPTH + 1);
    assert_eq!(plan.warnings.len(), 1);
    assert_eq!(plan.warnings[0].code, WarningCode::PathTruncated);
    let h = plan.connections.iter().find(|c| c.name == "h").expect("h");
    assert_eq!(h.host, "192.0.2.7");
    let (mut depth, mut key) = (0, h.folder.as_deref());
    while let Some(k) = key {
        depth += 1;
        key = plan.folders.iter().find(|f| f.key == k).and_then(|f| f.parent.as_deref());
    }
    assert_eq!(depth, MAX_DEPTH);
    let sw = plan.connections.iter().find(|c| c.name == "sw1").expect("sw1");
    assert_eq!((sw.host.as_str(), sw.protocol), ("sw1", Protocol::Ssh));
    let root = plan.connections.iter().find(|c| c.name == "root").expect("base itself");
    assert!(root.folder.is_none());
    assert_eq!(plan.credentials[0].name, "Directory account");
    assert!(plan.credentials[0].fields.get("domain").is_none());
}

#[test]
fn query_prepare_validates_and_clamps() {
    let q = LdapQuery {
        url: "ldaps://dc.example.test".into(),
        base_dn: BASE.into(),
        scope: SearchScope::Sub,
        kind: DirectoryKind::Ad,
        name_contains: Some("web(".into()),
        size_limit: Some(99_999),
    };
    let p = q.prepare(&LdapLimits::DEFAULT).expect("prepared");
    assert_eq!(p.size_limit, LdapLimits::DEFAULT.max_entries);
    assert!(p.filter.contains("web\\28"));
    assert_eq!(p.target.url(), "ldaps://dc.example.test:636");
    let bad = LdapQuery { size_limit: Some(0), ..q.clone() };
    assert_eq!(bad.prepare(&LdapLimits::DEFAULT).expect_err("zero").code(), "ldap.invalid");
    let plain = LdapQuery { url: "ldap://dc.example.test".into(), ..q.clone() };
    assert_eq!(plain.prepare(&LdapLimits::DEFAULT).expect_err("plain").code(), "ldap.insecure");
    let small = LdapQuery { size_limit: Some(10), ..q };
    assert_eq!(small.prepare(&LdapLimits::DEFAULT).expect("p").size_limit, 10);
    assert_eq!(serde_json::to_value(DirectoryKind::OpenLdap).expect("j"), "openldap");
    assert_eq!(
        serde_json::from_value::<SearchScope>(serde_json::json!("one")).expect("j"),
        SearchScope::One
    );
}

#[test]
fn write_ops_are_absent_from_the_reader() {
    let src = include_str!("client.rs");
    for op in [
        ".add(",
        ".modify(",
        ".delete(",
        ".modifydn(",
        ".extended(",
        ".compare(",
        "sasl_",
        "set_no_tls_verify",
        "set_starttls",
    ] {
        assert!(!src.contains(op), "{op} must not appear in the directory reader");
    }
    assert!(
        src.contains(".simple_bind(")
            && src.contains(".streaming_search(")
            && src.contains(".abandon(")
            && src.contains(".unbind(")
    );
}

#[test]
fn error_codes_and_debug_hide_secrets() {
    let c = BindCredential {
        name: "CORP\\svc".into(),
        password: zeroize::Zeroizing::new("hunter2".into()),
    };
    assert!(!format!("{c:?}").contains("hunter2"));
    assert_eq!(LdapError::Bind(49).code(), "ldap.bind");
    assert_eq!(LdapError::SizeLimit.code(), "ldap.size_limit");
    assert_eq!(LdapError::Timeout.code(), "ldap.timeout");
    assert_eq!(LdapError::Response("x").code(), "ldap.response");
    assert_eq!(LdapError::Unavailable("y".into()).code(), "ldap.unavailable");
    assert_eq!(LdapError::Tls(mooring_http::HttpError::TrustStore).code(), "http.trust_store");
}
