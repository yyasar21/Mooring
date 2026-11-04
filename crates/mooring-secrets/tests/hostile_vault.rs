//! The Vault client against QA's `mooring-testsrv::vault` mock (ADR-0016 §Test plan): raw
//! KV bodies the real server would never send (duplicate keys, non-string values, nested
//! objects, control characters, 65 fields, a 129-byte key), bodies padded past the 1 MiB
//! response cap, sealed / standby / 403 knobs and the root-token refusal. Every test ends
//! with `assert_no_violations()`: the client never writes, lists or touches `sys/` beyond
//! what the ADR allows, and no secret value ever appears in an error.

use std::time::Duration;

use mooring_core::credential::parse_vault_reference;
use mooring_core::model::SecretSourceId;
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind, SourceOptions};
use mooring_core::CredentialId;
use mooring_secrets::{Category, ClientConfig, SecretsError, VaultClient};
use mooring_testsrv::tls::TestCert;
use mooring_testsrv::vault::{self, VaultConfig, VaultKnobs, VaultServer};

const TOKEN: &str = "hvs.test-token";

struct Mock {
    srv: VaultServer,
    dir: tempfile::TempDir,
    ca: String,
}

async fn start(knobs: VaultKnobs) -> Mock {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let config = VaultConfig { knobs, cert: Some(cert), ..VaultConfig::default() };
    let srv = vault::start(config, 0).await.expect("vault mock");
    Mock { srv, dir: tempfile::tempdir().expect("tempdir"), ca }
}

impl Mock {
    fn client(&self) -> VaultClient {
        let source = SecretSource {
            id: SecretSourceId::new(),
            name: "qa mock".into(),
            kind: SourceKind::Vault,
            address: self.srv.base_url(),
            namespace: None,
            auth: SecretSourceAuth::Token { credential_id: CredentialId::new() },
            options: SourceOptions { ca_pem: Some(self.ca.clone()), ..SourceOptions::default() },
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let mut cfg = ClientConfig::new(self.dir.path().join("known_vault_certs"));
        cfg.retry.base_delay = Duration::from_millis(1);
        cfg.retry.max_delay = Duration::from_millis(5);
        VaultClient::new(&source, &cfg).expect("client")
    }

    async fn read(&self, reference: &str) -> Result<usize, SecretsError> {
        let at = parse_vault_reference(reference).expect("reference");
        self.client().read_kv2(TOKEN, &at, None).await.map(|s| s.data.len())
    }

    fn read_only(&self) {
        self.srv.recorder().assert_no_violations();
        for line in self.srv.recorder().lines() {
            assert!(!line.contains("testpass") && !line.contains("old-testpass"), "{line}");
        }
    }
}

fn shape(e: &SecretsError) -> bool {
    matches!(
        e,
        SecretsError::Unavailable { category: Category::Shape, .. } | SecretsError::Shape { .. }
    )
}

#[test]
fn the_token_never_appears_in_an_error() {
    for e in [SecretsError::NotFound, SecretsError::RootToken, SecretsError::Invalid("token")] {
        assert!(!e.to_string().contains("hvs."), "{e}");
    }
}

/// The baseline reads `secret/servers/web` v2 and the deleted / destroyed versions are
/// `not_found`, with GETs only.
#[tokio::test]
async fn baseline_reads_and_not_found() {
    let m = start(VaultKnobs::default()).await;
    assert_eq!(m.read("secret/servers/web").await.expect("v2"), 3);
    let e = m.read("secret/servers/deleted").await.expect_err("deleted");
    assert_eq!(e.code(), "credential.external_not_found");
    let e = m.read("secret/servers/destroyed").await.expect_err("destroyed");
    assert_eq!(e.code(), "credential.external_not_found");
    let e = m.read("secret/servers/nope").await.expect_err("missing");
    assert_eq!(e.code(), "credential.external_not_found");
    assert_eq!(m.srv.recorder().count("GET", "/v1/secret/data/"), 4);
    m.read_only();
}

/// Raw bodies: every hostile shape is a `shape` unavailability (never a panic, never a
/// partial secret), and the error text carries key names at most, never a value.
#[tokio::test]
async fn raw_kv_bodies_are_refused_as_shape() {
    let m = start(VaultKnobs::default()).await;
    let sixty_five = (0..65).map(|i| format!("\"k{i}\":\"v\"")).collect::<Vec<_>>().join(",");
    let long_key = "k".repeat(129);
    let cases = [
        r#"{"data":{"data":{"password":"a","password":"b"},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"password":42},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"password":{"nested":"x"}},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"password":["a"]},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"password":null},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"pass\u0000word":"x"},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"":"x"},"metadata":{"version":1}}}"#,
        r#"{"data":{"data":"not an object","metadata":{"version":1}}}"#,
        r#"{"data":{"data":{"password":"x"},"metadata":{"version":"two"}}}"#,
        r#"{"data":[]}"#,
        r#"["data"]"#,
        "{",
        "",
        "\u{feff}{}",
        r#"{"errors":["permission denied"]}"#,
    ];
    for body in cases {
        m.srv.set_knobs(VaultKnobs { raw_kv_body: Some(body.to_owned()), ..VaultKnobs::default() });
        let e = m.read("secret/servers/web").await.expect_err(body);
        assert!(shape(&e) || matches!(e, SecretsError::NotFound), "{body}: {e}");
        assert!(!e.to_string().contains("nested") && !e.to_string().contains('"'), "{e}");
    }
    let too_many = format!(r#"{{"data":{{"data":{{{sixty_five}}},"metadata":{{"version":1}}}}}}"#);
    m.srv.set_knobs(VaultKnobs { raw_kv_body: Some(too_many), ..VaultKnobs::default() });
    assert!(shape(&m.read("secret/servers/web").await.expect_err("65 fields")));
    let long = format!(r#"{{"data":{{"data":{{"{long_key}":"v"}},"metadata":{{"version":1}}}}}}"#);
    m.srv.set_knobs(VaultKnobs { raw_kv_body: Some(long), ..VaultKnobs::default() });
    assert!(shape(&m.read("secret/servers/web").await.expect_err("129-byte key")));
    // deep nesting inside a value is a decode error, never a stack overflow
    let deep = format!(
        r#"{{"data":{{"data":{{"password":{}{}}}}}}}"#,
        "[".repeat(50_000),
        "]".repeat(50_000)
    );
    m.srv.set_knobs(VaultKnobs { raw_kv_body: Some(deep), ..VaultKnobs::default() });
    assert!(shape(&m.read("secret/servers/web").await.expect_err("deep")));
    // exactly 64 fields of 128-byte keys still read
    let max_key = "k".repeat(126);
    let fields = (0..64).map(|i| format!("\"{max_key}{i:02}\":\"v\"")).collect::<Vec<_>>();
    let ok =
        format!(r#"{{"data":{{"data":{{{}}},"metadata":{{"version":1}}}}}}"#, fields.join(","));
    m.srv.set_knobs(VaultKnobs { raw_kv_body: Some(ok), ..VaultKnobs::default() });
    assert_eq!(m.read("secret/servers/web").await.expect("64 fields"), 64);
    m.read_only();
}

/// A body padded past the 1 MiB cap is refused before it is parsed (the padding is valid
/// JSON, so only the cap can be the reason); one just under it is read.
#[tokio::test]
async fn oversized_kv_bodies_are_capped() {
    let m = start(VaultKnobs::default()).await;
    m.srv.set_knobs(VaultKnobs { oversized_body: Some(1024 * 1024 + 1), ..VaultKnobs::default() });
    let e = m.read("secret/servers/web").await.expect_err("1 MiB + 1");
    assert!(shape(&e) && e.to_string().contains("too large"), "{e}");
    m.srv.set_knobs(VaultKnobs { oversized_body: Some(8 * 1024 * 1024), ..VaultKnobs::default() });
    let e = m.read("secret/servers/web").await.expect_err("8 MiB");
    assert!(shape(&e) && e.to_string().contains("too large"), "{e}");
    m.srv.set_knobs(VaultKnobs { oversized_body: Some(900 * 1024), ..VaultKnobs::default() });
    assert_eq!(m.read("secret/servers/web").await.expect("900 KiB"), 3);
    m.read_only();
}

/// Sealed (503) is `network`; a standby 307 is refused rather than followed; a 403 is
/// `forbidden`; the root token is refused at lookup.
#[tokio::test]
async fn server_state_knobs_fail_closed() {
    let m = start(VaultKnobs { sealed: true, ..VaultKnobs::default() }).await;
    let e = m.read("secret/servers/web").await.expect_err("sealed");
    assert_eq!(e.category(), Category::Network, "{e}");
    m.read_only();

    let m = start(VaultKnobs { standby: true, ..VaultKnobs::default() }).await;
    let e = m.read("secret/servers/web").await.expect_err("standby");
    assert!(matches!(e.category(), Category::Network | Category::Shape), "{e}");
    assert_eq!(m.srv.recorder().count("GET", "/v1/secret/data/"), 1, "redirect not followed");
    m.read_only();

    let m = start(VaultKnobs { force_403: true, ..VaultKnobs::default() }).await;
    let e = m.read("secret/servers/web").await.expect_err("403");
    assert_eq!(e.category(), Category::Forbidden, "{e}");
    m.read_only();

    let m = start(VaultKnobs { root_token: true, ..VaultKnobs::default() }).await;
    let e = m.client().lookup_self(TOKEN).await.expect_err("root");
    assert_eq!(e.code(), "credential.external_root_token");
    let e = m.client().lookup_self("hvs.root-token").await.expect_err("root");
    assert_eq!(e.code(), "credential.external_root_token");
    m.read_only();
}

/// The reference grammar keeps hostile paths off the wire: nothing is sent for any of them.
#[tokio::test]
async fn hostile_references_never_reach_the_server() {
    let m = start(VaultKnobs::default()).await;
    for bad in [
        "secret/../sys/raw",
        "secret/x?list=true",
        "secret/x#frag",
        "secret/%2e%2e/x",
        "secret/\u{202e}x",
        "secret/x\u{0}",
        "/secret/x",
        "secret//x",
    ] {
        assert!(parse_vault_reference(bad).is_err(), "{bad}");
    }
    assert!(m.srv.recorder().is_empty());
    m.read_only();
}
