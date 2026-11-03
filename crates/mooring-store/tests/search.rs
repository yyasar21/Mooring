//! FTS5 search: name / host / tag prefix matching, trigger sync, injection resistance,
//! limit cap.

mod common;

use common::{conn, lab};
use mooring_core::Protocol;
use mooring_store::MAX_SEARCH_LIMIT;

fn names(hits: &[mooring_store::ConnectionHit]) -> Vec<String> {
    let mut v: Vec<_> = hits.iter().map(|h| h.name.clone()).collect();
    v.sort();
    v
}

#[test]
fn matches_name_host_and_tag_prefixes() {
    let l = lab();
    let s = &l.store;
    conn(s, &l.servers, "xinfra01", "10.10.20.5", &["infra"]);
    conn(s, &l.servers, "xmon01", "10.10.20.30", &["observability", "grafana"]);
    conn(s, &l.okd, "okd-master", "api.okd.homelab.xyz", &["k8s"]);

    assert_eq!(names(&s.search("xinf", 10).expect("name")), vec!["xinfra01"]);
    assert_eq!(names(&s.search("XMON", 10).expect("case")), vec!["xmon01"]);
    assert_eq!(names(&s.search("10.10.20", 10).expect("host")).len(), 2);
    assert_eq!(names(&s.search("homelab", 10).expect("host token")), vec!["okd-master"]);
    assert_eq!(names(&s.search("observ", 10).expect("tag")), vec!["xmon01"]);
    assert_eq!(names(&s.search("graf xmon", 10).expect("AND")), vec!["xmon01"]);
    assert!(s.search("graf xinfra", 10).expect("AND miss").is_empty());
    assert!(s.search("   ", 10).expect("blank").is_empty());

    let hit = &s.search("okd-master", 10).expect("hyphen")[0];
    assert_eq!(hit.folder, l.okd.id);
    assert_eq!(hit.protocol, Protocol::Ssh);
}

#[test]
fn index_follows_updates_tags_and_deletes() {
    let l = lab();
    let s = &l.store;
    let c = conn(s, &l.servers, "xinfra01", "10.10.20.5", &["infra"]);

    s.set_tags(c.id, &["dns".into()]).expect("tags");
    assert!(s.search("infra", 10).expect("old tag").is_empty());
    assert_eq!(s.search("dns", 10).expect("new tag").len(), 1);

    let mut renamed = s.get_connection(c.id).expect("get");
    renamed.name = "resolver".into();
    renamed.host = "10.10.20.53".into();
    s.update_connection(&renamed).expect("update");
    assert!(s.search("xinfra", 10).expect("old name").is_empty());
    assert_eq!(names(&s.search("resolv", 10).expect("new name")), vec!["resolver"]);
    assert_eq!(names(&s.search("dns", 10).expect("tag kept")), vec!["resolver"]);

    s.delete_connection(c.id).expect("delete");
    assert!(s.search("resolv", 10).expect("deleted").is_empty());
}

#[test]
fn fts_operators_and_quotes_are_literal() {
    let l = lab();
    let s = &l.store;
    conn(s, &l.servers, "xinfra01", "10.10.20.5", &["infra"]);
    conn(s, &l.servers, "weird \"quoted\" name", "10.10.20.6", &[]);

    // Each of these would be a syntax error or a broadened query if passed raw to MATCH.
    for q in [
        "\"",
        "\"\"\"",
        "xinfra OR 1",
        "NEAR(xinfra 10)",
        "name:xinfra",
        "^xinfra",
        "-xinfra",
        "xinfra*\"",
        "') OR 1=1 --",
        "{name host}: x",
        "xinfra AND NOT",
    ] {
        let r = s.search(q, 10);
        assert!(r.is_ok(), "query {q:?} must not error: {r:?}");
    }
    // "OR" is a literal token; nothing has it, so AND semantics give no rows.
    assert!(s.search("xinfra OR 1", 10).expect("or").is_empty());
    // Quote inside a token is matched as text, not as FTS syntax.
    assert_eq!(names(&s.search("\"quoted\"", 10).expect("quotes")), vec!["weird \"quoted\" name"]);
    assert_eq!(
        names(&s.search("weird \"quo", 10).expect("partial")),
        vec!["weird \"quoted\" name"]
    );
}

#[test]
fn limit_is_clamped() {
    let l = lab();
    let s = &l.store;
    for i in 0..(MAX_SEARCH_LIMIT + 5) {
        conn(s, &l.servers, &format!("node{i:03}"), &format!("10.10.40.{}", i % 250), &[]);
    }
    assert_eq!(s.search("node", usize::MAX).expect("cap").len(), MAX_SEARCH_LIMIT);
    assert_eq!(s.search("node", 0).expect("min").len(), 1);
    assert_eq!(s.search("node", 7).expect("seven").len(), 7);
}
