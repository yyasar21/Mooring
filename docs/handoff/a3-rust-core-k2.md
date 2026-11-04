# A3 rust-core — K2: `kubeconfig::resolve`, `KubeConnOptions`, `ConnectSecret::Kube`

Branch: worktree of `a3` @ `aa629eb`; commits `22461ca`, `e14b6a1` (+ this note). Not merged.

## Done

### API for K3 (`mooring_core::credential::kubeconfig`)
```rust
pub fn resolve(yaml: &[u8], context: Option<&str>) -> Result<Resolved, KubeResolveError>;

pub struct Resolved {               // Debug is redacted (auth) / size-only (CA)
    pub context_name: String,       // named context, or current-context when None
    pub server: KubeServer,         // https only
    pub ca: CaSource,
    pub tls_server_name: Option<String>, // lower-case DNS name
    pub auth: KubeAuth,
    pub namespace: Option<String>,  // RFC 1123 label
    pub insecure_skip: bool,        // caller MUST treat as CaSource::None -> TOFU (ADR-0014 §3)
}
pub enum CaSource { Pem(Vec<u8>) /* cert-only PEM, <= 64 KiB; chain must validate, no TOFU */, None }
pub enum KubeAuth {                 // Clone, redacted Debug, SecretString = zeroized on drop
    Token(SecretString),            // visible ASCII only, <= MAX_TOKEN (16 KiB)
    ClientCert { cert_pem: String, key_pem: SecretString }, // unencrypted PKCS#8/RSA/EC PEM
}
pub enum KubeResolveError {         // static Display, never a value; .code() for IPC
    Rejected(CredentialError),      // parse() refusal       -> credential.kubeconfig_rejected
    NoContext, NotFound(&str), Duplicate(&str), Invalid(&str), // -> credential.kubeconfig_rejected
    UnsupportedAuth(&str),          // basic, impersonation, unknown user key, none, both -> kube.unsupported_auth
}
impl From<KubeResolveError> for MooringError;   // Invalid { field: "kubeconfig", .. }

pub struct KubeServer;  // parse(&str) -> Result<_, &'static str>; as_str(), host() (no brackets),
                        // port() (443 default), path() (API prefix, no trailing '/'), Display
pub fn is_dns_label(&str) -> bool;      // namespaces; reuse for the guard's {ns}
pub fn is_dns_subdomain(&str) -> bool;  // pod names / SNI; reuse for {pod}
pub const MAX_CA_PEM: usize = 64 * 1024; pub const MAX_TOKEN: usize = 16 * 1024;
```
`mooring_core::connect::ConnectSecret::Kube(KubeAuth)` (kind `"kube"`). The `kubeconfig`
credential still arrives as `ConnectSecret::Kubeconfig { yaml, context }`; K3/K4 call
`resolve(yaml.expose_secret().as_bytes(), context)` and continue with `ConnectSecret::Kube`. For
`kube_token`, build `KubeAuth::Token` and take server / CA from the options.

Resolve rules: only the selected context / cluster / user are read, each by an exact-key
allow-list (context: `cluster user namespace extensions`; cluster: `server
certificate-authority-data insecure-skip-tls-verify tls-server-name disable-compression
extensions`; user: `token client-certificate-data client-key-data extensions`). Anything else
there is refused (so case variants can never be silently ignored). `proxy-url` refused; CA data +
`insecure-skip-tls-verify: true` together refused (kubectl does too). Duplicate names in a
section are refused. Base64 is capped before decoding, decoded into `Zeroizing`; whitespace is
allowed. The whole `parse()` hardening (non-ASCII keys, case variants, merge keys, exec /
auth-provider / tokenFile / path fields anywhere) runs first and is unchanged.

### Options (`mooring_core::options`, `ProtocolOptions::Kube`) — UI fields
| Field (camelCase) | Type | Default | Rule |
| --- | --- | --- | --- |
| `context` | string \| null | null | ≤ 253 B, no control/bidi; refused for `kube_token` |
| `server` | string \| null | null | `https://host[:port][/path]`, no userinfo/query/`..`; **required for `kube_token`, refused for `kubeconfig`** |
| `caPem` | string \| null | null | certificate PEM only, ≤ 64 KiB; same credential rule as `server` |
| `tlsServerName` | string \| null | null | lower-case DNS name |
| `namespace` | string \| null | null | RFC 1123 label |
| `allowedNamespaces` | string[] | [] | ≤ 64 unique labels |
| `execCommand` | `"/bin/sh" \| "/bin/bash" \| "/bin/ash" \| "sh" \| "bash"` | `"/bin/sh"` | closed list, no argv |
| `logTailLines` | number | 1000 | 1..=100 000 |
| `maxLogBytes` | number | 8 388 608 | 1..=64 MiB |
| `portForwardEnabled` | bool | true | |

`deny_unknown_fields`; `KubeConnOptions::validate()` (shape) runs in `ProtocolOptions::from_value`;
`check_credential(kind)` (server/caPem/context vs credential kind) must be called by K4 in
`connection_create/update` and `connect_plan` once the credential is known — the options layer
does not see it. `server_url()` returns the parsed `KubeServer`. Existing Kubernetes rows hold
`{}` and read as defaults: **no migration** (no protocol CHECK exists; `Protocol::Kubernetes`
already present). Matrix: `kubeconfig` / `kube_token` valid for Kubernetes `primary` only
(already in the schema table; test added).

## Left open
- Fuzz (QA, Q2): `resolve` is a new accept path → needs a `kubeconfig_resolve` target; oracle:
  any `Ok` has `server` starting `https://`, `ca` either None or PEM passing `x509_pem`, token
  visible ASCII, and the input passed `parse`. I did not touch `fuzz/`.
- `src-tauri` not built here (scope); its `ProtocolOptions` / `ConnectSecret` matches all have
  wildcard arms, so it should compile unchanged. K4 wires `check_credential`.
- JWT `exp` peek (ADR §3) is not in K2; K3 or K4.

## Decision needed
- Names: the brief said `logMaxBytes`; ADR-0014 says `maxLogBytes` — I kept the ADR name.
- `logTailLines` range 1..=100 000 (brief) vs ADR §5 "`tailLines ≤ 10 000`" per request: K3
  should clamp the request to 10 000 or the ADR should be amended.
- `portForwardEnabled` defaults to `true` (forwards are loopback, confirmed when external).

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-core -p mooring-store -p mooring-proto-ssh
--all-targets -- -D warnings && cargo test -p mooring-core -p mooring-store -p mooring-proto-ssh`:
green. New: `credential::kubeconfig::resolve_tests` (token, client cert, three contexts,
current-context default/dangling, parser refusals incl. M-12, typed unsupported auth, 21 field
refusals, CA/token caps, folded base64, 3 proptests), `options::kube_tests` (defaults, wire,
validation table, credential rules, matrix, 2 proptests), store
`kubernetes_rows_use_kube_options_without_a_migration`.
