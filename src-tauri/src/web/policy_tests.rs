//! Navigation guard table (ADR-0013 test plan).

use super::*;

fn opts(url: &str, allowed: &[&str], allow_http: bool) -> WebConnOptions {
    WebConnOptions {
        url: url.into(),
        allowed_origins: allowed.iter().map(|s| (*s).to_owned()).collect(),
        persistent: false,
        allow_http,
    }
}

fn policy() -> NavPolicy {
    let o = opts("https://console.example.test/ui/", &["https://sso.example.test"], false);
    NavPolicy::from_options(&o, None).expect("policy").0
}

fn u(s: &str) -> Url {
    Url::parse(s).expect(s)
}

#[test]
fn start_origin_and_allow_list_are_allowed() {
    let p = policy();
    assert_eq!(p.allowed(), ["https://console.example.test", "https://sso.example.test"]);
    for ok in [
        "https://console.example.test/",
        "https://console.example.test/ui/#/vm/42?x=1",
        "https://CONSOLE.Example.TEST/ui",
        "https://console.example.test:443/ui",
        "https://sso.example.test/login?next=%2F",
    ] {
        assert_eq!(p.decide(&u(ok)), Nav::Allow, "{ok}");
    }
}

#[test]
fn everything_else_is_blocked_with_origin_only() {
    let p = policy();
    let cases = [
        ("https://evil.example.test/steal?token=abc", "https://evil.example.test"),
        ("http://console.example.test/", "http://console.example.test"),
        ("https://console.example.test:8443/", "https://console.example.test:8443"),
        ("https://console.example.test:444/", "https://console.example.test:444"),
        ("https://sub.console.example.test/", "https://sub.console.example.test"),
        ("https://console.example.test.evil.test/", "https://console.example.test.evil.test"),
        ("https://example.test/", "https://example.test"),
        ("https://console.example.test./ui", "https://console.example.test."),
        // userinfo tricks: the host is what follows the `@`.
        ("https://console.example.test@evil.test/", "https://evil.test"),
        ("https://console.example.test:443@evil.test/", "https://evil.test"),
        // credentials towards an allowed origin are refused too.
        ("https://user:pw@console.example.test/", "https://console.example.test"),
        ("https://user@console.example.test/", "https://console.example.test"),
        // IDN look-alikes (Cyrillic а, Greek ο) normalise to punycode, not the ASCII host.
        ("https://\u{0441}onsole.example.test/", "https://xn--onsole-hrf.example.test"),
        ("https://c\u{03bf}nsole.example.test/", "https://xn--cnsole-i0e.example.test"),
        ("https://xn--onsole-hrf.example.test/", "https://xn--onsole-hrf.example.test"),
        // app origin.
        ("tauri://localhost/index.html", "tauri:"),
        ("http://tauri.localhost/", "http://tauri.localhost"),
        ("https://tauri.localhost/index.html", "https://tauri.localhost"),
        ("ipc://localhost/vault_unlock", "ipc:"),
        // N-31: the whole RFC 6761 localhost zone is app surface on Windows.
        ("https://ipc.localhost/vault_unlock", "https://ipc.localhost"),
        ("http://ipc.localhost:8080/", "http://ipc.localhost:8080"),
        ("https://a.b.localhost/", "https://a.b.localhost"),
        // non-http schemes.
        ("file:///etc/passwd", "file:"),
        ("javascript:alert(document.cookie)", "javascript:"),
        ("data:text/html,<script>1</script>", "data:"),
        ("blob:https://console.example.test/0b3c", "blob:"),
        ("about:blank", "about:"),
        ("ftp://console.example.test/", "ftp://console.example.test"),
        ("ws://console.example.test/", "ws://console.example.test"),
    ];
    for (url, origin) in cases {
        let got = p.decide(&u(url));
        let shown = match &got {
            Nav::Block { origin } => origin.clone(),
            Nav::Allow => panic!("{url} must be blocked"),
        };
        // blob: URLs have the origin of their inner URL; the guard still refuses the scheme.
        if url.starts_with("blob:") {
            assert!(shown.starts_with("https://") || shown == "blob:", "{url}: {shown}");
            continue;
        }
        assert_eq!(shown, origin, "{url}");
        assert!(!shown.contains("token") && !shown.contains("pw"), "no path or secret: {shown}");
    }
}

#[test]
fn dev_url_counts_as_app_origin() {
    let dev = u("http://localhost:1420");
    let o = opts("http://localhost:1420/", &[], true);
    let e = NavPolicy::from_options(&o, Some(dev.clone())).expect_err("dev server");
    assert_eq!(e.code, "web.origin_refused");
    let o = opts("http://192.0.2.10:8080/", &["http://localhost:1420"], true);
    let (p, _) = NavPolicy::from_options(&o, Some(dev)).expect("listed dev origin is ignored");
    assert!(matches!(p.decide(&u("http://localhost:1420/")), Nav::Block { .. }));
    assert_eq!(p.decide(&u("http://192.0.2.10:8080/x")), Nav::Allow);
}

#[test]
fn app_origin_start_url_is_refused() {
    // N-31: `*.localhost` fails validation, before the policy is even built.
    for url in ["https://tauri.localhost/", "http://tauri.localhost/", "https://ipc.localhost/"] {
        let e = NavPolicy::from_options(&opts(url, &[], true), None).expect_err(url);
        assert_eq!(e.code, "input.invalid", "{url}");
    }
    for allowed in ["https://ipc.localhost", "https://tauri.localhost"] {
        let o = opts("https://console.example.test/", &[allowed], false);
        assert_eq!(NavPolicy::from_options(&o, None).expect_err(allowed).code, "input.invalid");
    }
    // Plain `localhost` is an ordinary host (a local console over http with allowHttp).
    let o = opts("http://localhost:8006/", &["http://localhost:8007"], true);
    let (p, _) = NavPolicy::from_options(&o, None).expect("localhost");
    assert_eq!(p.decide(&u("http://localhost:8007/x")), Nav::Allow);
    assert!(matches!(p.decide(&u("http://ipc.localhost:8007/")), Nav::Block { .. }));
    assert!(matches!(p.decide(&u("http://console.localhost:8006/")), Nav::Block { .. }));
}

#[test]
fn options_validation() {
    let ok = |o: WebConnOptions| NavPolicy::from_options(&o, None);
    assert!(ok(opts("https://192.0.2.1/", &[], false)).is_ok(), "IP literal");
    assert!(ok(opts("https://[2001:db8::1]:8443/", &[], false)).is_ok(), "IPv6 literal");
    assert!(ok(opts("http://192.0.2.1/", &[], true)).is_ok(), "http with allowHttp");
    for (url, allowed, http) in [
        ("", &[][..], false),
        ("http://console.example.test/", &[][..], false),
        ("ftp://console.example.test/", &[][..], true),
        ("file:///etc/passwd", &[][..], true),
        ("javascript:alert(1)", &[][..], true),
        ("data:text/html,x", &[][..], true),
        ("console.example.test", &[][..], false),
        ("https://user:pw@console.example.test/", &[][..], false),
        ("https://console.example.test/", &["https://*.example.test"][..], false),
        ("https://console.example.test/", &["https://sso.example.test/path"][..], false),
        ("https://console.example.test/", &["http://sso.example.test"][..], false),
        ("https://console.example.test/", &["file:///"][..], true),
        ("https://console.example.test:0/", &[][..], false),
        ("https://console.example.test /", &[][..], false),
    ] {
        let e = ok(opts(url, allowed, http)).expect_err(url);
        assert_eq!(e.code, "input.invalid", "{url} {allowed:?}");
    }
}

#[test]
fn allow_list_is_normalised_and_deduplicated() {
    let o = opts(
        "https://Console.Example.test:443/",
        &["https://console.example.test", "https://SSO.example.test:443", "https://b\u{fc}ro.example.test"],
        false,
    );
    let (p, start) = NavPolicy::from_options(&o, None).expect("policy");
    assert_eq!(start.host_str(), Some("console.example.test"));
    assert_eq!(p.allowed(), [
        "https://console.example.test",
        "https://sso.example.test",
        "https://xn--bro-hoa.example.test"
    ]);
    assert_eq!(p.decide(&u("https://b\u{fc}ro.example.test/")), Nav::Allow);
}
