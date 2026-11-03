//! Best-effort scrubbing of secrets from free text. Defence in depth: the real rule is that
//! secrets never reach a log call in the first place (CLAUDE.md); this catches mistakes.
//!
//! No regex crate: a small hand-rolled scanner keeps the dependency tree short and avoids
//! pathological regex inputs on attacker-controlled text (remote banners, error bodies).

const REDACTED: &str = "[REDACTED]";

/// Keys whose value is scrubbed when written as `key=value`, `key: value` or `"key":"value"`.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

fn is_value_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, ',' | ';' | '&' | '"' | '\'' | '}' | ']' | ')')
}

/// Scrub secret-looking values from `input`.
///
/// Handles `key=value`, `key: value`, JSON `"key":"value"`, `Bearer <token>`, `Basic <b64>` and
/// whole PEM private-key blocks. Keys are matched case-insensitively.
#[must_use]
pub fn redact(input: &str) -> String {
    let mut out = redact_pem(input);
    out = redact_auth_schemes(&out);
    for key in SECRET_KEYS {
        out = redact_key(&out, key);
    }
    out
}

/// Replace every `-----BEGIN ... PRIVATE KEY-----` … `-----END ...-----` block.
fn redact_pem(s: &str) -> String {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    const DASHES: &str = "-----";
    let upper = s.to_ascii_uppercase();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(i) = upper[pos..].find(BEGIN) {
        let b = pos + i;
        let label_start = b + BEGIN.len();
        let Some(label_len) = upper[label_start..].find(DASHES) else {
            break;
        };
        let label = &upper[label_start..label_start + label_len];
        if !label.contains("PRIVATE KEY") {
            out.push_str(&s[pos..label_start]);
            pos = label_start;
            continue;
        }
        out.push_str(&s[pos..b]);
        out.push_str("-----BEGIN PRIVATE KEY [REDACTED]-----");
        let block_end = upper[label_start..]
            .find(END)
            .and_then(|e| {
                let after_end = label_start + e + END.len();
                upper[after_end..].find(DASHES).map(|d| after_end + d + DASHES.len())
            })
            .unwrap_or(s.len());
        pos = block_end;
    }
    out.push_str(&s[pos..]);
    out
}

fn redact_auth_schemes(s: &str) -> String {
    let mut out = s.to_owned();
    for scheme in ["Bearer ", "Basic ", "bearer ", "basic "] {
        let mut cursor = 0;
        while let Some(i) = out[cursor..].find(scheme) {
            let start = cursor + i + scheme.len();
            let end = out[start..].find(is_value_end).map_or(out.len(), |e| start + e);
            if end > start {
                out.replace_range(start..end, REDACTED);
            }
            cursor = start + REDACTED.len();
        }
    }
    out
}

fn redact_key(s: &str, key: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut cursor = 0;
    while let Some(i) = lower[cursor..].find(key) {
        let k_start = cursor + i;
        let k_end = k_start + key.len();
        // the key must be a whole word
        let before_ok = k_start == 0 || !lower.as_bytes()[k_start - 1].is_ascii_alphanumeric();
        let after = &s[k_end..];
        let after_trim = after.trim_start_matches(['"', '\'']);
        let sep_pos = after.len() - after_trim.len();
        let value_start = match after_trim.chars().next() {
            Some('=' | ':') => {
                let v = &after_trim[1..];
                let v2 = v.trim_start();
                let v3 = v2.trim_start_matches(['"', '\'']);
                Some(k_end + sep_pos + 1 + (v.len() - v2.len()) + (v2.len() - v3.len()))
            }
            _ => None,
        };
        match (before_ok, value_start) {
            (true, Some(vs)) if vs < s.len() => {
                let ve = s[vs..].find(is_value_end).map_or(s.len(), |e| vs + e);
                out.push_str(&s[last..vs]);
                out.push_str(REDACTED);
                last = ve;
                cursor = ve;
            }
            _ => cursor = k_end,
        }
        if cursor >= s.len() {
            break;
        }
    }
    out.push_str(&s[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_common_shapes() {
        let s = "user=yunus password=hunter2 token: abc.def Authorization: Bearer eyJ.x.y";
        let r = redact(s);
        assert!(!r.contains("hunter2"));
        assert!(!r.contains("abc.def"));
        assert!(!r.contains("eyJ.x.y"));
        assert!(r.contains("user=yunus"));
    }

    #[test]
    fn scrubs_json_and_quotes() {
        let r = redact(r#"{"host":"a","password":"p@ss, word","api_key":"K1"}"#);
        assert!(!r.contains("p@ss"));
        assert!(!r.contains("K1"));
        assert!(r.contains(r#""host":"a""#));
    }

    #[test]
    fn scrubs_pem_private_keys_but_not_certificates() {
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n";
        let r = redact(pem);
        assert!(!r.contains("AAAA"));
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(redact(cert), cert);
    }

    #[test]
    fn leaves_unrelated_text_alone() {
        let s = "passwordless login for user tokenizer=on";
        assert_eq!(redact(s), s);
    }
}
