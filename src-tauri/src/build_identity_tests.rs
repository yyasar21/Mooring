use super::*;
use crate::build_channel::{self as bc, BuildChannel, BuildChannelError};
use crate::dirs::Dirs;
use crate::test_config;

const BASE: &str = r#"{ "identifier": "io.github.yyasar21.mooring.dev", "productName": "Mooring Dev" }"#;
const OVERLAY: &str = r#"{ "identifier": "io.github.yyasar21.mooring", "productName": "Mooring" }"#;

#[test]
fn build_script_decision_table() {
    let rel = Ok(("io.github.yyasar21.mooring".to_owned(), BuildChannel::Release));
    let dev = Ok(("io.github.yyasar21.mooring.dev".to_owned(), BuildChannel::Dev));
    assert_eq!(bc::channel_of(BASE, None, None, None), dev, "plain build");
    assert_eq!(bc::channel_of(BASE, None, Some(""), Some("")), dev, "empty values are unset");
    assert_eq!(bc::channel_of(BASE, None, None, Some("0")), dev);
    assert_eq!(bc::channel_of(BASE, None, Some(OVERLAY), Some("1")), rel, "release.yml");
    assert_eq!(bc::channel_of(BASE, None, Some(OVERLAY), Some(" 1 ")), rel);
    // Exactly one half says release: a build error, never a silent channel.
    assert!(matches!(
        bc::channel_of(BASE, None, Some(OVERLAY), None),
        Err(BuildChannelError::Mismatch { flag: false, .. })
    ));
    assert!(matches!(
        bc::channel_of(BASE, None, None, Some("1")),
        Err(BuildChannelError::Mismatch { flag: true, .. })
    ));
    // A CI overlay that sets other keys only keeps the base identifier.
    let ci = r#"{ "bundle": { "createUpdaterArtifacts": false } }"#;
    assert_eq!(bc::channel_of(BASE, None, Some(ci), None), dev);
    // The platform file is merged before TAURI_CONFIG.
    assert_eq!(bc::channel_of(BASE, Some(OVERLAY), None, Some("1")), rel);
    let back = r#"{ "identifier": "io.github.yyasar21.mooring.dev" }"#;
    assert_eq!(bc::channel_of(BASE, Some(OVERLAY), Some(back), None), dev, "TAURI_CONFIG wins");
    // Junk is refused loudly.
    assert!(matches!(bc::channel_of(BASE, None, None, Some("yes")), Err(BuildChannelError::Flag(_))));
    assert!(matches!(bc::channel_of(BASE, None, Some("src-tauri/x.json"), None), Err(BuildChannelError::Config(_))));
    assert!(matches!(bc::channel_of("{}", None, None, None), Err(BuildChannelError::Config(_))));
    assert!(matches!(bc::channel_of(r#"{"identifier": 1}"#, None, None, None), Err(BuildChannelError::Config(_))));
    // Messages name the fix.
    let e = bc::decide("io.github.yyasar21.mooring.dev", true).expect_err("mismatch");
    assert!(e.to_string().contains("tauri.release.conf.json"), "{e}");
    let e = bc::decide("io.github.yyasar21.mooring", false).expect_err("mismatch");
    assert!(e.to_string().contains("MOORING_RELEASE_BUILD=1"), "{e}");
    assert_eq!(bc::platform_file("macos"), Some("tauri.macos.conf.json"));
    assert_eq!(bc::platform_file("freebsd"), None);
}

/// RFC 7396 Appendix A, the cases tauri-build relies on.
#[test]
fn merge_patch_follows_rfc_7396() {
    use serde_json::json;
    for (target, patch, want) in [
        (json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"})),
        (json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"})),
        (json!({"a":"b"}), json!({"a":null}), json!({})),
        (json!({"a":"b","b":"c"}), json!({"a":null}), json!({"b":"c"})),
        (json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"})),
        (json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]})),
        (json!({"a":{"b":"c"}}), json!({"a":{"b":"d","c":null}}), json!({"a":{"b":"d"}})),
        (json!({"a":[{"b":"c"}]}), json!({"a":[1]}), json!({"a":[1]})),
        (json!(["a","b"]), json!(["c","d"]), json!(["c","d"])),
        (json!({"a":"b"}), json!(["c"]), json!(["c"])),
        (json!({"a":"foo"}), json!(null), json!(null)),
        (json!({"a":"foo"}), json!("bar"), json!("bar")),
        (json!({"e":null}), json!({"a":1}), json!({"e":null,"a":1})),
        (json!([1,2]), json!({"a":"b","c":null}), json!({"a":"b"})),
        (json!({}), json!({"a":{"bb":{"ccc":null}}}), json!({"a":{"bb":{}}})),
    ] {
        let mut t = target.clone();
        bc::merge_patch(&mut t, &patch);
        assert_eq!(t, want, "{target} + {patch}");
    }
}

#[test]
fn channel_and_identifier_must_agree() {
    assert_eq!(check(Channel::Release, RELEASE_IDENTIFIER), Ok(()));
    assert_eq!(check(Channel::Dev, "io.github.yyasar21.mooring.dev"), Ok(()));
    assert_eq!(check(Channel::Dev, "org.example.fork"), Ok(()), "a fork's own id is dev");
    let r = check(Channel::Dev, RELEASE_IDENTIFIER).expect_err("dev binary, release id");
    assert_eq!(r.code, "app.build_identity");
    assert!(r.message.contains("development build") && r.message.contains(RELEASE_IDENTIFIER), "{}", r.message);
    let r = check(Channel::Release, "io.github.yyasar21.mooring.dev").expect_err("release binary, dev id");
    assert_eq!(r.code, "app.build_identity");
    assert!(r.message.contains("release build"), "{}", r.message);
    assert_eq!(serde_json::to_value(Channel::Release).expect("json"), "release");
    assert_eq!(Channel::Dev.wire(), "dev");
    assert!(Channel::Dev.is_dev() && !Channel::Release.is_dev());
}

/// The compiled channel and the identifier `build.rs` derived agree (the same check setup
/// runs against `app.config().identifier`), in both the plain and the release build.
#[test]
fn this_build_is_consistent() {
    assert_eq!(check(Channel::CURRENT, EFFECTIVE_IDENTIFIER), Ok(()));
    assert_eq!(Channel::CURRENT == Channel::Release, cfg!(mooring_release));
    assert_eq!(RELEASE_IDENTIFIER, bc::RELEASE_IDENTIFIER, "one release id");
}

/// ADR-0028 test plan, config half: base = dev (no pubkey, own upgradeCode), merged = release.
#[test]
fn checked_in_configs_carry_both_identities() {
    let base = test_config::base();
    let release = test_config::release();
    let id = |v: &serde_json::Value| bc::identifier(v).expect("identifier");
    assert_eq!(id(&base), "io.github.yyasar21.mooring.dev");
    assert_eq!(Channel::of_identifier(&id(&base)), Channel::Dev);
    assert_eq!(id(&release), RELEASE_IDENTIFIER);
    assert_eq!(base["productName"], "Mooring Dev");
    assert_eq!(release["productName"], "Mooring");
    assert!(base.pointer("/plugins/updater").is_none(), "no updater block in the dev config");
    assert!(release.pointer("/plugins/updater/pubkey").and_then(serde_json::Value::as_str).is_some_and(|k| !k.is_empty()));
    let code = |v: &serde_json::Value| v.pointer("/bundle/windows/wix/upgradeCode").cloned();
    assert_eq!(code(&release), Some(serde_json::json!("1f940c60-f3be-5e3f-81de-92ee690e0b6d")), "byte-identical");
    assert!(code(&base).is_some() && code(&base) != code(&release));
    // Window title stays the config's: "Mooring Dev" / "Mooring".
    assert_eq!(base.pointer("/app/windows/0/title"), Some(&serde_json::json!("Mooring Dev")));
    assert_eq!(release.pointer("/app/windows/0/title"), Some(&serde_json::json!("Mooring")));
}

/// Data and cache directories follow the identifier: Tauri resolves `app_data_dir` /
/// `app_cache_dir` as `<os dir>/<identifier>`, so the two channels never share a directory
/// (neither identifier is a path component of the other's directory), and the portable root
/// differs by name.
#[test]
fn channels_never_share_a_directory() {
    let os = std::path::Path::new("/Users/u/Library/Application Support");
    let dev = os.join("io.github.yyasar21.mooring.dev");
    let rel = os.join(RELEASE_IDENTIFIER);
    assert_ne!(dev, rel);
    assert!(!dev.starts_with(&rel) && !rel.starts_with(&dev));
    assert_eq!(Dirs::root_name(Channel::Release), "Mooring Data");
    assert_eq!(Dirs::root_name(Channel::Dev), "Mooring Dev Data");
    assert_eq!(Dirs::ROOT, Dirs::root_name(Channel::CURRENT));
    assert_eq!(Dirs::MARKER, "portable", "the marker name is shared");
}
