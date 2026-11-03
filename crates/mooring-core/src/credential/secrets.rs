//! Secret validation before sealing (ADR-0009 §5): the name must belong to the kind, the size
//! cap holds (VNC passwords are rejected above 8 bytes, never truncated), text secrets are
//! UTF-8 without control characters, PEM/YAML allow `\n`/`\r`/`\t`, TOTP seeds decode.

use super::{otp, CredentialError, CredentialKind, FieldFormat, SecretName};

/// Largest secret of any kind (kubeconfig, bytes).
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;

fn name_static(n: SecretName) -> &'static str {
    n.as_str()
}

/// Validate one secret value for `kind`. Errors name the secret, never its value.
pub fn validate_secret(
    kind: CredentialKind,
    name: SecretName,
    plain: &[u8],
) -> Result<(), CredentialError> {
    let field = name_static(name);
    let schema = kind
        .schema()
        .secret(name)
        .ok_or_else(|| CredentialError::invalid(field, "is not a secret of this kind"))?;
    if plain.is_empty() {
        return Err(CredentialError::invalid(field, "cannot be empty; clear it instead"));
    }
    let max = schema.validation.max_bytes;
    if plain.len() > max {
        let reason = if max <= 16 {
            format!("is limited to {max} bytes; longer input is rejected, not truncated")
        } else {
            format!("is larger than {max} bytes")
        };
        return Err(CredentialError::invalid(field, reason));
    }
    let text =
        std::str::from_utf8(plain).map_err(|_| CredentialError::invalid(field, "must be text"))?;
    let multiline = matches!(schema.validation.format, FieldFormat::Pem | FieldFormat::Yaml);
    let bad = text.chars().any(|c| {
        let allowed_ws = multiline && matches!(c, '\n' | '\r' | '\t');
        !allowed_ws && super::is_forbidden(c)
    });
    if bad {
        return Err(CredentialError::invalid(field, "contains a control or invisible character"));
    }
    match schema.validation.format {
        FieldFormat::Pem if !text.contains("-----BEGIN ") => {
            Err(CredentialError::invalid(field, "must be PEM (-----BEGIN …)"))
        }
        FieldFormat::Base32 => otp::decode_seed(plain).map(drop),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CredentialKind as K;
    use SecretName as S;

    #[test]
    fn names_must_belong_to_the_kind() {
        assert!(validate_secret(K::UserPassword, S::Password, b"pw").is_ok());
        assert!(validate_secret(K::UserPassword, S::PrivateKey, b"x").is_err());
        assert!(validate_secret(K::SshAgent, S::Password, b"x").is_err());
        assert!(
            validate_secret(K::KubeToken, S::OtpSeed, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").is_err()
        );
        assert!(validate_secret(K::SshKey, S::OtpSeed, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").is_ok());
    }

    #[test]
    fn caps_at_max_and_max_plus_one() {
        for (kind, name, max) in [
            (K::UserPassword, S::Password, 4096),
            (K::VncPassword, S::Password, 8),
            (K::ApiToken, S::Token, 16 * 1024),
            (K::OauthClient, S::RefreshToken, 16 * 1024),
            (K::SudoBecome, S::Password, 4096),
            (K::SshKey, S::Passphrase, 4096),
        ] {
            assert!(validate_secret(kind, name, &vec![b'x'; max]).is_ok(), "{kind:?} {name}");
            let e = validate_secret(kind, name, &vec![b'x'; max + 1]).expect_err("cap");
            assert!(!e.to_string().contains("xxxx"), "no echo");
        }
        let e = validate_secret(K::VncPassword, S::Password, b"123456789").expect_err("vnc");
        assert!(e.to_string().contains("not truncated"), "{e}");
        let pem = format!("-----BEGIN X-----\n{}", "A".repeat(64 * 1024));
        assert!(validate_secret(K::SshKey, S::PrivateKey, pem.as_bytes()).is_err());
    }

    #[test]
    fn character_and_format_rules() {
        assert!(validate_secret(K::UserPassword, S::Password, b"").is_err());
        assert!(validate_secret(K::UserPassword, S::Password, b"a\nb").is_err());
        assert!(validate_secret(K::UserPassword, S::Password, "a\u{202e}b".as_bytes()).is_err());
        assert!(validate_secret(K::UserPassword, S::Password, &[0xff, 0xfe]).is_err());
        assert!(validate_secret(K::UserPassword, S::Password, "pässwörd İ".as_bytes()).is_ok());
        assert!(validate_secret(K::SshKey, S::PrivateKey, b"no pem here").is_err());
        let pem = crate::credential::testdata::placeholder_key_pem();
        assert!(validate_secret(K::SshKey, S::PrivateKey, pem.as_bytes()).is_ok());
        assert!(validate_secret(K::UserPassword, S::OtpSeed, b"short").is_err());
    }
}
