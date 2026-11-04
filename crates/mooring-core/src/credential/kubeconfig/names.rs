//! Kubernetes name and API-server URL rules shared by [`super::resolve`], the connection
//! options (ADR-0014 §3) and the read-only guard (K3: `{ns}` / `{pod}` path segments).

/// Longest API server URL accepted, in bytes.
pub const MAX_SERVER_URL: usize = 2048;

/// RFC 1123 label: `1..=63` of `[a-z0-9-]`, starting and ending alphanumeric (namespaces).
#[must_use]
pub fn is_dns_label(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.last().is_some_and(u8::is_ascii_alphanumeric)
}

/// RFC 1123 subdomain: `1..=253` bytes of dot-separated [`is_dns_label`]s (pod names, TLS
/// server names).
#[must_use]
pub fn is_dns_subdomain(s: &str) -> bool {
    (1..=253).contains(&s.len()) && s.split('.').all(is_dns_label)
}

/// A validated Kubernetes API server URL: `https://host[:port][/path]`, ASCII only, no
/// credentials, query, fragment, wildcard or `..` segment. The host is lower-cased; IPv6
/// literals keep their brackets in [`Self::as_str`] and lose them in [`Self::host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeServer {
    url: String,
    host: String,
    port: u16,
    path: String,
}

impl KubeServer {
    /// Parse and validate. The error is a static reason; it never echoes the input.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.len() > MAX_SERVER_URL {
            return Err("server URL is too long");
        }
        if !s.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("server URL must be ASCII without spaces or control characters");
        }
        let Some(after) =
            s.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).map(|_| &s[8..])
        else {
            return Err("server URL must use https://");
        };
        if after.contains(['?', '#', '\\', '*']) {
            return Err("server URL may not carry a query, fragment, backslash or wildcard");
        }
        let end = after.find('/').unwrap_or(after.len());
        let (authority, path) = after.split_at(end);
        if authority.contains('@') {
            return Err("server URL must not carry credentials");
        }
        let (host, port, bracketed) = split_host_port(authority)?;
        let host = host.to_ascii_lowercase();
        let host_ok = if bracketed {
            host.contains(':')
                && host.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        } else {
            !host.is_empty()
                && host.len() <= 253
                && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                && !host.starts_with(['.', '-'])
        };
        if !host_ok {
            return Err("server URL has an invalid host");
        }
        if path.split('/').any(|seg| seg == ".." || seg == ".") {
            return Err("server URL path may not contain dot segments");
        }
        let path = path.trim_end_matches('/').to_owned();
        let shown = if bracketed { format!("[{host}]") } else { host.clone() };
        let url = match port {
            Some(p) => format!("https://{shown}:{p}{path}"),
            None => format!("https://{shown}{path}"),
        };
        Ok(Self { url, host, port: port.unwrap_or(443), path })
    }

    /// Normalised URL (lower-case scheme and host, no trailing `/`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Host name or IP literal (no brackets), lower-case.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Port (443 when not given).
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Path prefix of the API (empty, or `/…` without a trailing slash).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Display for KubeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url)
    }
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>, bool), &'static str> {
    const BAD: &str = "server URL has an invalid host or port";
    let (host, port, bracketed) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']').ok_or(BAD)?;
        let port = if tail.is_empty() { None } else { Some(tail.strip_prefix(':').ok_or(BAD)?) };
        (host, port, true)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port), false),
            None => (authority, None, false),
        }
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().ok().filter(|p| *p != 0).ok_or(BAD)?)
        }
        Some(_) => return Err(BAD),
    };
    Ok((host, port, bracketed))
}
