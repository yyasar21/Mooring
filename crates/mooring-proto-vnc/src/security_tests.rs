use super::*;

fn pol(security: VncSecurity, pinned: bool) -> SecPolicy {
    SecPolicy { security, pinned, allow_no_auth: false, skip_vencrypt: false }
}

#[test]
fn selection_matrix() {
    use CredKind as C;
    use VncSecurity::{AllowPlaintext as A, PreferTls as P, RequireTls as R};
    let ok = |offered: &[u8], cred, policy| select_security(offered, cred, policy).expect("ok");
    let err = |offered: &[u8], cred, policy| select_security(offered, cred, policy).expect_err("e");

    // VeNCrypt wins whenever it is offered.
    for s in [A, P, R] {
        for c in [C::None, C::Password, C::UserPassword] {
            for pinned in [false, true] {
                assert_eq!(ok(&[1, 2, 19], c, pol(s, pinned)), SecChoice::VeNCrypt);
            }
        }
    }
    // Plaintext fallbacks.
    for s in [A, P] {
        assert_eq!(ok(&[1, 2], C::Password, pol(s, false)), SecChoice::VncAuth);
        assert_eq!(ok(&[2, 1], C::None, pol(s, false)), SecChoice::None);
        // L-27: a password with only None offered is refused unless allowNoAuth.
        let e = err(&[1], C::Password, pol(s, false));
        assert!(matches!(e, VncError::Unsupported(_)), "{e:?}");
        let allow = SecPolicy { allow_no_auth: true, ..pol(s, false) };
        assert_eq!(ok(&[1], C::Password, allow), SecChoice::None);
        assert_eq!(ok(&[1, 2], C::Password, allow), SecChoice::VncAuth, "auth still preferred");
        assert!(matches!(err(&[1], C::UserPassword, allow), VncError::Unsupported(_)));
        assert!(matches!(err(&[2], C::None, pol(s, false)), VncError::AuthFailed(_)));
        assert!(matches!(err(&[1, 2], C::UserPassword, pol(s, false)), VncError::Unsupported(_)));
        assert!(matches!(err(&[16, 30], C::Password, pol(s, false)), VncError::Unsupported(_)));
    }
    // require_tls without VeNCrypt.
    assert!(matches!(err(&[1, 2], C::Password, pol(R, false)), VncError::Unsupported(_)));
    // Downgrade guard: a pin turns a stripped list into a hard stop, whatever the policy.
    for s in [A, P, R] {
        let e = err(&[1, 2], C::Password, pol(s, true));
        assert!(matches!(e, VncError::TrustMismatch(_)), "{e:?}");
        assert_eq!(e.code(), mooring_core::CloseCode::TrustMismatch);
    }
    // Fallback attempt after an anonymous-TLS-only VeNCrypt: skip it, unless TLS is required.
    let skip = SecPolicy { skip_vencrypt: true, ..pol(P, false) };
    assert_eq!(ok(&[19, 2], C::Password, skip), SecChoice::VncAuth);
    let skip_req = SecPolicy { skip_vencrypt: true, ..pol(R, false) };
    assert_eq!(ok(&[19, 2], C::Password, skip_req), SecChoice::VeNCrypt);
    assert_eq!(SecChoice::VeNCrypt.byte(), 19);
}

#[test]
fn des_known_answer() {
    // FIPS 46 / Stallings classic vector, run through the RFB path by pre-reversing the key.
    let key = [0x13u8, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
    let password: Vec<u8> = key.iter().map(|b| b.reverse_bits()).collect();
    assert_eq!(*vnc_des_key(&password), key);
    let mut challenge = [0u8; 16];
    challenge[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    challenge[8..].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    let r = vnc_auth_response(&password, &challenge);
    assert_eq!(r[..8], [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05]);
    assert_eq!(r[..8], r[8..], "ECB: equal blocks, equal output");
}

#[test]
fn vnc_auth_vectors() {
    // Cross-checked with `openssl enc -des-ecb -nopad` on the bit-reversed keys
    // (password -> 0e86ceceeef64e26, abc -> 8646c60000000000).
    let challenge: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).expect("i"));
    assert_eq!(
        *vnc_auth_response(b"password", &challenge),
        [
            0xb8, 0x66, 0x92, 0x41, 0x25, 0xc8, 0xee, 0xbb, 0x9d, 0xeb, 0xc1, 0xdb, 0x61, 0xc5,
            0x38, 0xe2
        ]
    );
    let challenge: [u8; 16] = std::array::from_fn(|i| u8::try_from(i + 16).expect("i"));
    assert_eq!(
        *vnc_auth_response(b"abc", &challenge),
        [
            0x5d, 0x30, 0xc0, 0x9d, 0x60, 0x06, 0x99, 0xfa, 0x6c, 0x8f, 0x4e, 0xe5, 0xf8, 0xfb,
            0xf5, 0x0b
        ]
    );
    // An empty password is a zero key (some servers accept it); it must not panic.
    let _ = vnc_auth_response(b"", &challenge);
}

#[test]
fn password_rules_and_redaction() {
    let s = |v: &str| SecretString::from(v.to_owned());
    assert_eq!(vnc_password_bytes(&s("12345678")).expect("8").len(), 8);
    assert!(vnc_password_bytes(&s("123456789")).is_err());
    let m = plain_auth_message("u", &s("pw")).expect("plain");
    assert_eq!(&m[..], &[0, 0, 0, 1, 0, 0, 0, 2, b'u', b'p', b'w']);
    assert!(plain_auth_message(&"u".repeat(1025), &s("pw")).is_err());
    let c = Credential::UserPassword { user: "alice".into(), password: s("hunter2") };
    let shown = format!("{c:?}");
    assert!(!shown.contains("hunter2") && !shown.contains("alice"), "{shown}");
    assert_eq!(c.kind(), CredKind::UserPassword);
}
