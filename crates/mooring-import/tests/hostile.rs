//! A4 Q1 hostile fixtures through the public `parse` / `detect` API (ADR-0019 §3 test plan):
//! the input cap at max + 1, a gzip bomb over the 20:1 ratio, DOCTYPE and entity XML, deep
//! nesting, UTF-16 without a BOM, CSV with embedded quotes and newlines, a `PuTTY` `.reg`
//! with odd escapes, and an mRemoteNG file whose passwords must never reach a plan. Every
//! error is checked for its code and for carrying nothing of the input (no host, no secret).

use std::io::Write as _;

use flate2::write::GzEncoder;
use flate2::Compression;
use mooring_core::CredentialKind;
use mooring_import::{detect, parse, ImportError, ImportFormat, ImportOptions, ImportSource};

const MREMOTENG: &[u8] = include_bytes!("fixtures/confCons.xml");
const ROYAL: &[u8] = include_bytes!("fixtures/royal.rtsx");
const RDM: &[u8] = include_bytes!("fixtures/export.rdm");

/// Markers that must never appear in an error message or a plan's debug form.
const LEAKS: &[&str] = &["example.test", "192.0.2.", "bm90LWltcG9ydGVk", "not-imported", "hunter2"];

fn parse_file(
    format: ImportFormat,
    name: &str,
    bytes: &[u8],
    secrets: bool,
) -> Result<mooring_import::ImportPlan, ImportError> {
    let opts = ImportOptions { include_plaintext_secrets: secrets, ..ImportOptions::default() };
    parse(format, ImportSource::File { name, bytes }, &opts)
}

fn assert_clean(text: &str, what: &str) {
    for leak in LEAKS {
        assert!(!text.contains(leak), "{what} carries `{leak}`: {text}");
    }
}

fn err_code(r: Result<mooring_import::ImportPlan, ImportError>, what: &str) -> &'static str {
    let e = r.expect_err(what);
    assert_clean(&e.to_string(), what);
    assert_clean(&format!("{e:?}"), what);
    e.code()
}

#[test]
fn input_cap_plus_one_is_too_large_for_every_format() {
    let max = ImportOptions::default().limits.max_input;
    let mut big = vec![b'\n'; max + 1];
    big[..4].copy_from_slice(b"Host");
    for f in ImportFormat::FILES {
        assert_eq!(err_code(parse_file(f, "x", &big, false), f.name()), "import.too_large");
    }
    // Exactly the cap is read (and refused for its content, not its size).
    big.truncate(max);
    let e = parse_file(ImportFormat::Openssh, "config", &big, false).expect("at the cap");
    assert_eq!(e.counts().connections, 0);
    // A directory source is capped on the sum too.
    let files = vec![
        ("a".to_owned(), vec![b'\n'; max / 2 + 1]),
        ("b".to_owned(), vec![b'\n'; max / 2 + 1]),
    ];
    let r = parse(ImportFormat::Putty, ImportSource::Dir(&files), &ImportOptions::default());
    assert_eq!(err_code(r, "dir"), "import.too_large");
}

#[test]
fn gzip_bomb_over_the_ratio_is_refused_before_inflating_it_all() {
    // 8 MiB of zeros compress to ~8 KiB: well under the 64 MiB decompressed cap, far over 20:1.
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(&vec![0u8; 8 * 1024 * 1024]).expect("write");
    let bomb = e.finish().expect("finish");
    assert!(bomb.len() < 64 * 1024, "bomb is {} bytes", bomb.len());
    assert_eq!(detect(&bomb, "ops.rtsz"), Some(ImportFormat::RoyalTs));
    assert_eq!(
        err_code(parse_file(ImportFormat::RoyalTs, "ops.rtsz", &bomb, false), "bomb"),
        "import.limits"
    );
    // A ZIP-wrapped .rtsz is a container we do not open, not a format error.
    let zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00rest of a zip".to_vec();
    assert_eq!(
        err_code(parse_file(ImportFormat::RoyalTs, "ops.rtsz", &zip, false), "zip"),
        "import.unsupported_container"
    );
    // A gzip whose plain content is fine still works (the ratio of real XML is low).
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(ROYAL).expect("write");
    let ok = e.finish().expect("finish");
    let plan = parse_file(ImportFormat::RoyalTs, "ops.rtsz", &ok, false).expect("gzip royal");
    assert!(plan.counts().connections >= 2);
}

#[test]
fn doctype_and_entities_are_refused_in_every_xml_format() {
    let xml = [
        (ImportFormat::RoyalTs, "x.rtsx", ROYAL),
        (ImportFormat::Rdm, "x.rdm", RDM),
        (ImportFormat::Mremoteng, "confCons.xml", MREMOTENG),
    ];
    for (format, name, body) in xml {
        let text = std::str::from_utf8(body).expect("utf-8 fixture");
        let (head, rest) = text.split_once("?>").expect("xml declaration");
        // DOCTYPE with an external entity (XXE) and with a billion-laughs entity.
        for doctype in [
            "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<!DOCTYPE x [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]>",
            "<!DOCTYPE x>",
        ] {
            let doc = format!("{head}?>\n{doctype}{rest}");
            assert_eq!(err_code(parse_file(format, name, doc.as_bytes(), false), name), "import.doctype", "{format:?} {doctype}");
            // Also after the root element opens (quick-xml would still see it).
            let (open, tail) = rest.split_once('>').expect("root");
            let doc = format!("{head}?>{open}>{doctype}{tail}");
            assert_eq!(err_code(parse_file(format, name, doc.as_bytes(), false), name), "import.doctype", "{format:?} late");
        }
        // An undeclared entity is a format error (never expanded, never passed through).
        let doc = rest.replacen('>', ">&xxe;", 1);
        let doc = format!("{head}?>{doc}");
        assert_eq!(
            err_code(parse_file(format, name, doc.as_bytes(), false), name),
            "import.format",
            "{format:?} entity"
        );
    }
}

#[test]
fn deep_nesting_is_a_limit_not_a_stack_overflow() {
    let cap = ImportOptions::default().limits.max_xml_depth;
    let nested = |root: &str, depth: usize| {
        let mut doc = format!("<{root}>");
        for _ in 0..depth {
            doc.push_str("<Node Type=\"Container\" Name=\"n\">");
        }
        for _ in 0..depth {
            doc.push_str("</Node>");
        }
        let name = root.split(' ').next().expect("root name");
        doc.push_str("</");
        doc.push_str(name);
        doc.push('>');
        doc
    };
    for (format, name, root) in [
        (
            ImportFormat::Mremoteng,
            "confCons.xml",
            "mrng:Connections xmlns:mrng=\"http://mremoteng.org\"",
        ),
        (ImportFormat::Rdm, "x.rdm", "ArrayOfConnection"),
        (ImportFormat::RoyalTs, "x.rtsx", "RTSDocument"),
    ] {
        let doc = nested(root, cap + 1);
        assert_eq!(
            err_code(parse_file(format, name, doc.as_bytes(), false), name),
            "import.limits",
            "{format:?}"
        );
        // 100 000 levels: still the same limit, in bounded time, with no stack growth.
        let doc = nested(root, 100_000);
        assert_eq!(
            err_code(parse_file(format, name, doc.as_bytes(), false), name),
            "import.limits",
            "{format:?} deep"
        );
        // Below the cap parses (the cap is the only reason to refuse).
        let ok = nested(root, cap - 2);
        assert!(parse_file(format, name, ok.as_bytes(), false).is_ok(), "{format:?} below the cap");
    }
    // Deeply nested JSON for Termius must not recurse without bound either.
    let json = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let r = parse_file(ImportFormat::Termius, "x.json", json.as_bytes(), false);
    assert!(
        matches!(r, Err(ImportError::Format { .. } | ImportError::Limits { .. }) | Ok(_)),
        "{r:?}"
    );
}

#[test]
fn utf16_without_a_bom_is_a_format_error_not_garbage() {
    let text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\web]\r\n\"HostName\"=\"ops@web01.example.test\"\r\n\"Protocol\"=\"ssh\"\r\n";
    let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    assert_eq!(
        err_code(parse_file(ImportFormat::Putty, "x.reg", &le, false), "utf16le"),
        "import.format"
    );
    assert_eq!(
        err_code(parse_file(ImportFormat::Putty, "x.reg", &be, false), "utf16be"),
        "import.format"
    );
    // With the BOM the same bytes are the real export.
    let mut with_bom = vec![0xFF, 0xFE];
    with_bom.extend_from_slice(&le);
    let plan = parse_file(ImportFormat::Putty, "x.reg", &with_bom, false).expect("bom");
    assert_eq!(plan.connections.len(), 1);
    assert_eq!(plan.connections[0].host, "web01.example.test");
    // A lone surrogate inside UTF-16 is refused, not replaced.
    let mut broken = with_bom.clone();
    broken.extend_from_slice(&[0x00, 0xD8, b'\n', 0]);
    assert_eq!(
        err_code(parse_file(ImportFormat::Putty, "x.reg", &broken, false), "surrogate"),
        "import.format"
    );
}

#[test]
fn csv_with_embedded_quotes_and_newlines_keeps_fields_whole() {
    let csv = "Groups,Label,Hostname/IP,Protocol,Port,Username,Password\r\n\
               \"Prod/Web\",\"web \"\"quoted\"\" 01\",web01.example.test,ssh,22,deploy,hunter2\r\n\
               Prod,\"multi\nline\nname\",192.0.2.31,ssh,2201,dba,\r\n\
               \"a,b\",\"comma, label\",198.51.100.5,ssh,,,\r\n\
               ,\"unterminated,198.51.100.6,ssh,,,\r\n";
    // The unterminated quote makes the last record malformed: a format error naming the record.
    let r = parse_file(ImportFormat::Termius, "hosts.csv", csv.as_bytes(), false);
    let e = r.expect_err("malformed quoting");
    assert_eq!(e.code(), "import.format");
    assert_clean(&e.to_string(), "csv error");
    let good = csv
        .rsplit_once('\n')
        .and_then(|(h, _)| h.rsplit_once('\n'))
        .map(|(h, _)| format!("{h}\n"))
        .expect("rows");
    let plan = parse_file(ImportFormat::Termius, "hosts.csv", good.as_bytes(), false).expect("csv");
    let names: Vec<&str> = plan.connections.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["web \"quoted\" 01", "comma, label"]);
    // A multi-line name is not a valid connection name: skipped as one record, never split
    // into two rows.
    assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
    assert_eq!(plan.skipped[0].reason, mooring_import::SkipReason::Invalid);
    let folders: Vec<&str> = plan.folders.iter().map(|f| f.name.as_str()).collect();
    assert!(folders.contains(&"a,b"), "{folders:?}");
    // Without the opt-in the password is dropped from the plan entirely.
    assert_eq!(plan.counts().secrets, 0);
    assert!(!format!("{plan:?}").contains("hunter2"), "dropped password in Debug");
    let with =
        parse_file(ImportFormat::Termius, "hosts.csv", good.as_bytes(), true).expect("csv opt-in");
    assert_eq!(with.counts().secrets, 1);
    // Even with the secret in the plan its debug form names no secret value.
    assert!(!format!("{with:?}").contains("hunter2"), "secret in Debug");
}

#[test]
fn putty_reg_with_odd_escapes_decodes_without_leaking() {
    let reg = "Windows Registry Editor Version 5.00\r\n\
               \r\n\
               [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\lab%20%22box%22%5c]\r\n\
               \"Present\"=dword:00000001\r\n\
               \"HostName\"=\"ops@192.0.2.9\"\r\n\
               \"Protocol\"=\"ssh\"\r\n\
               \"PortNumber\"=dword:00000016\r\n\
               \"PublicKeyFile\"=\"C:\\\\keys\\\\\\\"odd\\\" name.ppk\"\r\n\
               \"ProxyPassword\"=\"hunter2\"\r\n\
               \r\n\
               [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\%zz%4]\r\n\
               \"Present\"=dword:00000001\r\n\
               \"HostName\"=\"\\\\\\\\unc\\\\share\"\r\n\
               \"Protocol\"=\"ssh\"\r\n\
               \r\n\
               [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\bidi]\r\n\
               \"Present\"=dword:00000001\r\n\
               \"HostName\"=\"\u{202e}evil.example.test\"\r\n\
               \"Protocol\"=\"ssh\"\r\n";
    let plan = parse_file(ImportFormat::Putty, "x.reg", reg.as_bytes(), false).expect("reg");
    let lab = plan.connections.iter().find(|c| c.host == "192.0.2.9").expect("lab box");
    assert_eq!(lab.name, "lab \"box\"\\");
    assert_eq!(lab.port, Some(22));
    assert_eq!(lab.user.as_deref(), Some("ops"), "user@host split before the UserName field");
    assert!(
        plan.warnings.iter().any(|w| w.code == mooring_import::WarningCode::PpkKey),
        "{:?}",
        plan.warnings
    );
    // A `%`-sequence that is not an escape stays literal; the unescaped UNC host passes the
    // core host validator (no whitespace or control characters: the same rule as a typed
    // host, ADR-0004) and is a connection the user sees in the preview.
    let unc = plan.connections.iter().find(|c| c.name == "%zz%4").expect("unc session");
    assert_eq!(unc.host, "\\\\unc\\share");
    // The bidi-override host is refused by the validator: skipped, never a connection.
    assert_eq!(plan.connections.len(), 2, "{:?}", plan.connections);
    assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
    for s in &plan.skipped {
        assert_clean(&s.source_ref, "skipped source_ref");
        assert!(!s.source_ref.contains('\u{202e}'), "bidi in source_ref");
    }
    // A PuTTY proxy password is never a secret of the plan, opt-in or not.
    for secrets in [false, true] {
        let p = parse_file(ImportFormat::Putty, "x.reg", reg.as_bytes(), secrets).expect("reg");
        assert_eq!(p.counts().secrets, 0);
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}

#[test]
fn mremoteng_passwords_never_reach_the_plan_whatever_the_opt_in() {
    for secrets in [false, true] {
        let plan = parse_file(ImportFormat::Mremoteng, "confCons.xml", MREMOTENG, secrets)
            .expect("mremoteng");
        assert!(plan.counts().connections >= 3);
        assert_eq!(plan.counts().secrets, 0, "opt-in {secrets}");
        for c in &plan.credentials {
            assert_eq!(c.kind, CredentialKind::Prompt, "{}", c.name);
            assert!(!c.has_secret());
            assert!(c.secrets.is_none());
            assert!(!c.fields.to_string().contains("bm90LWltcG9ydGVk"), "password in fields");
        }
        assert!(plan
            .warnings
            .iter()
            .any(|w| w.code == mooring_import::WarningCode::PasswordDropped));
        assert!(!format!("{plan:?}").contains("bm90LWltcG9ydGVk"), "password in Debug");
    }
    // A plaintext-looking password attribute is dropped the same way.
    let plaintext = std::str::from_utf8(MREMOTENG)
        .expect("utf-8")
        .replace("Password=\"bm90LWltcG9ydGVk\"", "Password=\"hunter2\"");
    let plan = parse_file(ImportFormat::Mremoteng, "confCons.xml", plaintext.as_bytes(), true)
        .expect("plain");
    assert_eq!(plan.counts().secrets, 0);
    assert!(!format!("{plan:?}").contains("hunter2"));
    // Full-file encryption is refused as encrypted, with nothing of the file in the error.
    let enc = std::str::from_utf8(MREMOTENG)
        .expect("utf-8")
        .replace("FullFileEncryption=\"false\"", "FullFileEncryption=\"true\"");
    assert_eq!(
        err_code(
            parse_file(ImportFormat::Mremoteng, "confCons.xml", enc.as_bytes(), true),
            "encrypted"
        ),
        "import.encrypted"
    );
}

#[test]
fn bidi_and_control_characters_in_names_and_hosts_are_not_imported() {
    let config = "Host \u{202e}prod\n  HostName 192.0.2.5\nHost ok\n  HostName 192.0.2.6\n  User a\u{0}b\nHost tab\tname\n  HostName 192.0.2.7\n";
    let plan =
        parse_file(ImportFormat::Openssh, "config", config.as_bytes(), false).expect("config");
    for c in &plan.connections {
        assert!(c.name.chars().all(|ch| !ch.is_control() && ch != '\u{202e}'), "{:?}", c.name);
        assert!(c.host.chars().all(|ch| ch.is_ascii_graphic()), "{:?}", c.host);
        if let Some(u) = &c.user {
            assert!(u.chars().all(|ch| !ch.is_control()), "{u:?}");
        }
    }
    for s in &plan.skipped {
        assert!(s.source_ref.chars().all(|ch| !ch.is_control()), "{:?}", s.source_ref);
    }
    for cred in &plan.credentials {
        assert!(!cred.fields.to_string().contains('\u{0}'), "NUL in credential fields");
    }
}
