//! Fuzz entry points for the hostile-input parsers of this crate (cargo-fuzz targets live in
//! `fuzz/`, owned by QA). Each must never panic; the oracles are asserted inline.

use http::Method;

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
