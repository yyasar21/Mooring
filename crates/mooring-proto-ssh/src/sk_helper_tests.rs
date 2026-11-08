//! `ssh-sk-helper` framing and reply parsing; a scripted fake helper on Unix.

use proptest::prelude::*;

use super::*;

fn reply(version: u8, kind: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![version];
    body.extend_from_slice(&kind.to_be_bytes());
    body.extend_from_slice(payload);
    let mut out = u32::try_from(body.len()).expect("len").to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

#[test]
fn request_framing() {
    let f = sign_request(b"KEY", b"DATA");
    let len = u32::from_be_bytes([f[0], f[1], f[2], f[3]]) as usize;
    assert_eq!(len, f.len() - 4);
    assert_eq!(f[4], SK_HELPER_VERSION);
    assert_eq!(&f[5..9], &SK_HELPER_SIGN.to_be_bytes());
    assert_eq!(&f[9..14], &[0, 0, 0, 0, 0], "log off, quiet");
    assert_eq!(&f[14..21], &[0, 0, 0, 3, b'K', b'E', b'Y']);
    assert!(f.windows(8).any(|w| w == b"internal"), "built-in provider only");
}

#[test]
fn replies() {
    let mut sig = Vec::new();
    put_string(&mut sig, b"SIG");
    assert_eq!(parse_reply(&reply(5, SK_HELPER_SIGN, &sig)).expect("sig"), b"SIG");
    assert_eq!(parse_reply(&reply(4, SK_HELPER_SIGN, &sig)), Err(SkFailure::HelperVersion));
    assert_eq!(parse_reply(&reply(6, SK_HELPER_SIGN, &sig)), Err(SkFailure::HelperVersion));
    let err = 3u32.to_be_bytes();
    assert_eq!(parse_reply(&reply(5, SK_HELPER_ERROR, &err)), Err(SkFailure::HelperFailed));
    assert_eq!(parse_reply(&reply(5, 9, &sig)), Err(SkFailure::HelperFailed));
    let mut trailing = sig.clone();
    trailing.push(0);
    assert_eq!(parse_reply(&reply(5, SK_HELPER_SIGN, &trailing)), Err(SkFailure::HelperFailed));
    let good = reply(5, SK_HELPER_SIGN, &sig);
    for n in 0..good.len() {
        assert!(parse_reply(&good[..n]).is_err(), "truncated at {n}");
    }
    assert_eq!(parse_reply(b""), Err(SkFailure::HelperFailed), "helper died (version refusal)");
}

#[test]
fn fixed_paths_are_absolute_templates() {
    for t in SK_HELPER_PATHS {
        assert!(t.starts_with('/') || t.starts_with("%SystemRoot%"), "{t}");
    }
    if cfg!(target_os = "macos") {
        assert!(SK_HELPER_PATHS.is_empty(), "Apple's OpenSSH has no helper");
    }
}

#[test]
fn signer_preconditions_fail_closed() {
    use mooring_core::credential::sk_key::parse_sk_public_line;
    use mooring_core::credential::testdata::{public_line, sk_ed25519_public, sk_key_handle_pem};
    use mooring_core::credential::SkBackend;
    use secrecy::SecretString;
    let key = sk_ed25519_public([7; 32], "ssh:");
    let public = parse_sk_public_line(&public_line(&key)).expect("pk");
    let handle = sk_key_handle_pem(&key, 0x01, b"h");
    let login = |h: Option<&str>| SkLogin {
        public_key: public_line(&key),
        fingerprint: public.fingerprint.clone(),
        certificate: None,
        backend: SkBackend::Helper,
        key_handle: h.map(|s| SecretString::from(s.to_owned())),
        passphrase: None,
    };
    let mut o = SkOptions { agent_path: None, touch_timeout: DEADLINE, helper: None };
    let err = |l: &SkLogin, o: &SkOptions| HelperSigner::new(l, &public, o).err();
    assert_eq!(err(&login(Some(&handle)), &o), Some(SkFailure::HelperDisabled));
    o.helper = Some(PathBuf::from("relative/ssh-sk-helper"));
    assert_eq!(err(&login(Some(&handle)), &o), Some(SkFailure::HelperMissing));
    // Test-only: any existing absolute file stands in for the helper binary.
    let exe = std::env::current_exe().expect("exe"); // nosemgrep
    o.helper = Some(exe);
    assert_eq!(err(&login(None), &o), Some(SkFailure::BadKey), "helper needs the handle");
    let other = sk_key_handle_pem(&sk_ed25519_public([8; 32], "ssh:"), 0x01, b"h");
    assert_eq!(err(&login(Some(&other)), &o), Some(SkFailure::BadKey), "handle of another key");
    assert!(HelperSigner::new(&login(Some(&handle)), &public, &o).is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn scripted_helper_round_trip_and_cleared_environment() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("dir");
    let mut sig = Vec::new();
    put_string(&mut sig, b"SIG");
    let canned = dir.path().join("reply.bin");
    std::fs::write(&canned, reply(5, SK_HELPER_SIGN, &sig)).expect("reply");
    let env_out = dir.path().join("env.txt");
    let script = dir.path().join("ssh-sk-helper");
    let body = format!(
        "#!/bin/sh\n/bin/cat > /dev/null\n/usr/bin/env > '{}'\n/bin/cat '{}'\n",
        env_out.display(),
        canned.display()
    );
    std::fs::write(&script, body).expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let out = run(&script, &sign_request(b"K", b"D")).await.expect("ran");
    assert_eq!(parse_reply(&out).expect("sig"), b"SIG");
    let env = std::fs::read_to_string(&env_out).expect("env");
    assert!(!env.contains("SSH_SK_PROVIDER") && !env.contains("SSH_AUTH_SOCK"), "{env}");
    assert!(!env.contains("HOME="), "cleared: {env}");
}

proptest! {
    #[test]
    fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..300)) {
        fuzz_sk_helper_reply(&data);
    }
}
