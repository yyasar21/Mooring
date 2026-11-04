//! Fixtures for the ADR-0016 E2 tests: QA's `mooring-testsrv::vault` behind a private test
//! CA, sources and credentials created through the command layer, and a recording OIDC
//! window backend.

use std::sync::{Arc, Mutex};

use mooring_testsrv::tls::TestCert;
use mooring_testsrv::vault::{self, VaultConfig, VaultServer};
use serde_json::{json, Value};

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::secret_sources::{self, SecretSourceDto};
use crate::oidc_window::OidcWindows;
use crate::state::AppState;

/// A running Vault mock and the CA that issued its certificate.
pub struct Vault {
    pub srv: VaultServer,
    pub ca: String,
}

pub async fn start(cfg: VaultConfig) -> Vault {
    let (cert, ca) = TestCert::generate_ca_issued(&["localhost", "127.0.0.1"]).expect("cert");
    let srv = vault::start(VaultConfig { cert: Some(cert), ..cfg }, 0).await.expect("vault mock");
    Vault { srv, ca }
}

pub async fn start_default() -> Vault {
    start(VaultConfig::default()).await
}

fn credential(st: &AppState, name: &str, kind: &str, secrets: &[(&str, &str)]) -> String {
    let c = NewCredential {
        name: name.to_owned(),
        kind: kind.to_owned(),
        fields: json!({}),
        secrets: WireSecrets::of(secrets),
    };
    credentials::create(st, c).expect("credential").id
}

/// An `api_token` credential holding `token`.
pub fn token_credential(st: &AppState, token: &str) -> String {
    credential(st, "vault token", "api_token", &[("token", token)])
}

/// A `vault_approle` credential with the mock's role.
pub fn approle_credential(st: &AppState, role_id: &str, secret_id: &str) -> String {
    credential(
        st,
        "vault approle",
        "vault_approle",
        &[("role_id", role_id), ("secret_id", secret_id)],
    )
}

pub fn source_json(v: &Vault, method: &str, credential: Option<&str>, role: Option<&str>) -> Value {
    json!({
        "name": format!("lab {method}"),
        "address": v.srv.base_url(),
        "authMethod": method,
        "credentialId": credential,
        "oidcRole": role,
        "options": { "caPem": v.ca, "allowHttp": false, "allowedOrigins": [] },
    })
}

pub fn token_source(st: &AppState, v: &Vault, token: &str) -> SecretSourceDto {
    let cred = token_credential(st, token);
    secret_sources::create(st, &source_json(v, "token", Some(&cred), None)).expect("source")
}

pub fn approle_source(st: &AppState, v: &Vault) -> SecretSourceDto {
    let cred = approle_credential(st, "test-role-id", "test-secret-id");
    secret_sources::create(st, &source_json(v, "approle", Some(&cred), None)).expect("source")
}

pub fn oidc_source(st: &AppState, v: &Vault) -> SecretSourceDto {
    secret_sources::create(st, &source_json(v, "oidc", None, Some("mooring"))).expect("source")
}

/// An `external_ref` credential resolving `reference` from `source` into `target`.
pub fn external_ref(st: &AppState, source: &str, reference: &str, target: &str) -> String {
    let c = NewCredential {
        name: "from vault".to_owned(),
        kind: "external_ref".to_owned(),
        fields: json!({ "provider": "vault", "source": source, "reference": reference,
                        "target_kind": target }),
        secrets: WireSecrets::default(),
    };
    credentials::create(st, c).expect("external_ref").id
}

/// Records what the OIDC code would do with a real window.
#[derive(Default)]
pub struct Windows {
    pub opened: Mutex<Vec<(String, String, String)>>,
    pub closed: Mutex<Vec<String>>,
}

impl OidcWindows for Windows {
    fn open(&self, label: &str, url: &str, session: &str) -> Result<(), String> {
        self.opened.lock().expect("m").push((label.into(), url.into(), session.into()));
        Ok(())
    }
    fn close(&self, label: &str) {
        self.closed.lock().expect("m").push(label.into());
    }
    fn focus(&self, _label: &str) {}
}

pub fn windows(st: &AppState) -> Arc<Windows> {
    let w = Arc::new(Windows::default());
    st.secrets.oidc.set_windows(Arc::clone(&w) as Arc<dyn OidcWindows>);
    w
}

/// Audit rows of `event` as JSON.
pub fn audit_rows(st: &AppState, event: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).unwrap_or_default();
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["event"] == event)
        .collect()
}
