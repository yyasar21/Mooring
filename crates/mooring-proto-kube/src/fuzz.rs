//! Fuzz entry points for the hostile-input parsers of this crate (cargo-fuzz targets live in
//! `fuzz/`, owned by QA). Each must never panic; the oracles are asserted inline.

use http::Method;

use crate::browse::{List, PodIn, MAX_CONTAINERS, MAX_PORTS};
use crate::client::MAX_JSON_BODY;
use crate::frame::{decode_exec, ExecFrame, PfDecoder, PfEvent};
use crate::guard::{check, GuardPolicy, RequestShape, Route};
use crate::logs::{sanitize_line, Sanitizer};

fn clean_text(s: &str) -> bool {
    s.chars().all(|c| (!c.is_control() || c == '\n' || c == '\t') && !crate::browse::is_bidi(c))
}

/// One server → client exec message (channel byte + payload).
pub fn fuzz_exec_frame(data: &[u8]) {
    if let Ok(ExecFrame::Status(crate::frame::ExecStatus::Failure(r))) = decode_exec(data) {
        assert!(clean_text(&r) && r.chars().count() <= 256);
    }
}

/// A sequence of port-forward messages: `[port lo, port hi, (len, bytes)*]`.
pub fn fuzz_portforward_frame(data: &[u8]) {
    let [lo, hi, rest @ ..] = data else { return };
    let mut rest: &[u8] = rest;
    let mut dec = PfDecoder::new(u16::from_le_bytes([*lo, *hi]));
    while let [len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (msg, next) = tail.split_at(n);
        match dec.feed(msg) {
            Ok(PfEvent::Data(d)) => assert!(d.len() < msg.len()),
            Ok(PfEvent::Error(e)) => assert!(clean_text(&e)),
            Ok(PfEvent::Header) | Err(_) => {}
        }
        rest = next;
    }
}

/// Log bytes, fed whole and in two pieces: the output never carries a control character
/// other than `\t` / `\n`, a bidi control or an ESC.
pub fn fuzz_log_line(data: &[u8]) {
    assert!(clean_text(&sanitize_line(data)));
    let mid = data.len() / 2;
    let mut s = Sanitizer::default();
    let mut out = s.push(&data[..mid]);
    out.extend(s.push(&data[mid..]));
    out.extend(s.finish());
    let text = String::from_utf8(out).expect("sanitizer output is UTF-8");
    assert!(clean_text(&text));
}

/// `[method selector, websocket flag, path+query bytes…]` through the guard. Oracle: an
/// accepted request has a plain path (no `%`, `..`, `;`, `//`) and a method its route allows.
pub fn fuzz_guard_path(data: &[u8]) {
    let [m, flags, rest @ ..] = data else { return };
    let methods =
        [Method::GET, Method::HEAD, Method::POST, Method::PUT, Method::PATCH, Method::DELETE];
    let method = &methods[usize::from(*m) % methods.len()];
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let Ok(uri) = text.parse::<http::Uri>() else { return };
    let shape =
        RequestShape { method, uri: &uri, websocket: flags & 1 == 1, impersonates: flags & 2 == 2 };
    if let Ok(route) = check(shape, GuardPolicy::default()) {
        let path = uri.path();
        assert!(
            !path.contains('%')
                && !path.contains("..")
                && !path.contains(';')
                && !path.contains("//")
        );
        assert_eq!(flags & 2, 0);
        let q = uri.query().unwrap_or("");
        assert!(!q.contains("dryRun") && !q.contains("fieldManager"));
        match route {
            Route::AccessReview | Route::RulesReview | Route::SelfReview => {
                assert_eq!(*method, Method::POST);
            }
            Route::PodExec | Route::PodPortForward => {
                assert!(*method == Method::GET && flags & 1 == 1);
            }
            _ => assert!(*method == Method::GET || *method == Method::HEAD),
        }
    }
}

/// An API server `PodList` body: the 16 MiB cap is checked before `serde_json` runs, and
/// every summary has bounded, clean strings (name ≤ 253 chars, image ≤ 512, ≤ 64
/// containers, ≤ 32 ports).
pub fn fuzz_pod_list_json(data: &[u8]) {
    if data.len() > MAX_JSON_BODY {
        return;
    }
    let Ok(list) = serde_json::from_slice::<List<PodIn>>(data) else { return };
    let bounded = |s: &str, max: usize| s.chars().count() <= max && clean_text(s);
    for pod in list.items {
        let p = pod.summary();
        assert!(bounded(&p.name, 253) && bounded(&p.phase, 32));
        assert!(p.node.as_deref().is_none_or(|n| bounded(n, 253)));
        assert!(p.created_at.as_deref().is_none_or(|c| bounded(c, 40)));
        assert!(p.containers.len() <= MAX_CONTAINERS);
        for c in &p.containers {
            assert!(bounded(&c.name, 63) && bounded(&c.image, 512));
            assert!(c.ports.len() <= MAX_PORTS && c.ports.iter().all(|p| *p != 0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_list_entry_accepts_a_list_and_survives_hostile_bodies() {
        let list = br#"{"kind":"PodList","metadata":{"continue":"c2"},"items":[{"metadata":
            {"name":"web-0\u202e","creationTimestamp":"2026-11-01T00:00:00Z"},"spec":{"nodeName":
            "node-1.example.test","containers":[{"name":"app","image":"registry.example.test/web:1",
            "ports":[{"containerPort":8080},{"containerPort":0},{"containerPort":70000}]}]},
            "status":{"phase":"Running\u001b[31m","containerStatuses":[{"name":"app","ready":true,
            "restartCount":-5}]}}]}"#;
        fuzz_pod_list_json(list);
        let long = format!(
            r#"{{"items":[{{"metadata":{{"name":"{}"}},"spec":{{"containers":[{}]}}}}]}}"#,
            "n".repeat(1000),
            std::iter::repeat_n(r#"{"name":"c","image":"i"}"#, 100).collect::<Vec<_>>().join(",")
        );
        fuzz_pod_list_json(long.as_bytes());
        for hostile in [&b""[..], b"[", b"{\"items\":5}", b"\xff\xfe", b"{\"items\":[null]}"] {
            fuzz_pod_list_json(hostile);
        }
        fuzz_pod_list_json(&vec![b'['; MAX_JSON_BODY + 1]);
    }
}
