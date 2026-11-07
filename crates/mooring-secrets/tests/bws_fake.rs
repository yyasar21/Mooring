//! ADR-0026 §4 with a scripted fake `bws` (the test-only path override, like the network-tools
//! shims): cleared environment with only the token and server URL, pinned argv, version
//! check, exit codes, garbage / oversized output, the deadline, stderr noise that is never
//! echoed, a missing binary and a changed binary (`secret.tool_changed`). Unix only: the fake
//! is a `/bin/sh` script.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mooring_core::credential::{ExternalRefFields, RefProvider};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind, SourceOptions};
use mooring_core::{CredentialId, CredentialKind, SecretName, SecretSourceId};
use mooring_secrets::{
    BwsConfig, ClientConfig, FakeClock, LoginMaterial, LoginProvider, MemoryAudit, SecretEvent,
    SecretsEngine, SecretsError, TokenCache,
};
use zeroize::Zeroizing;

const ID: &str = "3b5c1e02-1d2a-4c8e-9f00-0123456789ab";
const PROJECT: &str = "0b5c1e02-1d2a-4c8e-9f00-0123456789ab";
const TOKEN: &str = "0.test-only.machine-token";

/// One fake at a time: writing an executable while another test forks can fail with
/// `ETXTBSY` (the net-tools shim tests are serialized for the same reason).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().expect("tempdir") }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("bws")
    }

    /// Write the fake: `version` for `--version`, `body` for `secret …` / `project list`.
    fn write(&self, version: &str, body: &str) {
        let d = self.dir.path().display();
        let script = format!(
            "#!/bin/sh\n/usr/bin/env > '{d}/env.txt'\nprintf '%s\\n' \"$*\" >> '{d}/argv.txt'\n\
             case \"$1\" in\n  --version) {version} ;;\n  *) {body} ;;\nesac\n"
        );
        let p = self.path();
        std::fs::write(&p, script).expect("write fake");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
    }
}

fn engine(path: &Path, deadline: Duration) -> (SecretsEngine, Arc<MemoryAudit>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = Arc::new(MemoryAudit::default());
    let cache = Arc::new(TokenCache::new(Arc::new(FakeClock::default()), audit.clone()));
    let mut cfg = ClientConfig::new(dir.path().join("known_vault_certs"));
    cfg.bws = BwsConfig::custom(path.to_owned());
    cfg.bws.deadline = deadline;
    (SecretsEngine::new(cache, audit.clone(), cfg), audit, dir)
}

fn source() -> SecretSource {
    SecretSource {
        id: SecretSourceId::new(),
        name: "sm".into(),
        kind: SourceKind::Bitwarden,
        address: "https://bitwarden.example.test".into(),
        namespace: None,
        auth: SecretSourceAuth::Token { credential_id: CredentialId::new() },
        options: SourceOptions::default(),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

fn login() -> impl LoginProvider {
    |_: &SecretSource| Ok(LoginMaterial::Token(Zeroizing::new(TOKEN.to_owned())))
}

fn bw(src: &SecretSource, reference: &str, kind: CredentialKind) -> ExternalRefFields {
    let mut f = ExternalRefFields::new(RefProvider::Bitwarden, reference.into(), kind);
    f.source = Some(src.id);
    f
}

fn print(json: &str) -> String {
    format!("printf '%s' '{json}'")
}

async fn resolve(
    e: &SecretsEngine,
    src: &SecretSource,
    f: &ExternalRefFields,
) -> Result<mooring_secrets::ResolvedSecrets, SecretsError> {
    e.resolve(src, CredentialId::new(), f, &login()).await
}

#[tokio::test]
async fn secret_get_with_a_cleared_environment() {
    let _serial = SERIAL.lock().await;
    let fake = Fake::new();
    let body =
        format!(r#"{{"object":"secret","id":"{ID}","key":"api","value":"bw-token-1","note":""}}"#);
    fake.write("echo 'bws 1.0.1'", &format!("echo 'bw-token-1 noise' >&2; {}", print(&body)));
    let (e, audit, _d) = engine(&fake.path(), Duration::from_secs(10));
    let src = source();
    let r = resolve(&e, &src, &bw(&src, ID, CredentialKind::ApiToken)).await.expect("resolved");
    assert_eq!(r.secret(SecretName::Token), Some(&b"bw-token-1"[..]));
    let env = fake.read("env.txt");
    let keys: Vec<&str> = env.lines().filter_map(|l| l.split_once('=').map(|k| k.0)).collect();
    assert!(keys.contains(&"BWS_ACCESS_TOKEN") && keys.contains(&"BWS_SERVER_URL"), "{keys:?}");
    for k in &keys {
        assert!(
            matches!(*k, "BWS_ACCESS_TOKEN" | "BWS_SERVER_URL" | "PWD" | "SHLVL" | "_" | "OLDPWD"),
            "leaked {k}"
        );
    }
    assert!(env.contains("BWS_SERVER_URL=https://bitwarden.example.test"));
    let argv = fake.read("argv.txt");
    assert_eq!(
        argv.lines().collect::<Vec<_>>(),
        ["--version", &format!("secret get {ID} --output json")]
    );
    let again = resolve(&e, &src, &bw(&src, ID, CredentialKind::ApiToken)).await;
    assert!(again.is_ok());
    assert_eq!(fake.read("argv.txt").matches("--version").count(), 1, "version checked once");
    let ev = audit.take();
    assert!(ev.iter().any(|x| matches!(
        x,
        SecretEvent::ToolSpawned { action: "secret_get", exit: Some(0), .. }
    )));
    assert!(!format!("{ev:?}").contains("bw-token-1"));
}

#[tokio::test]
async fn project_key_and_json_values() {
    let _serial = SERIAL.lock().await;
    let fake = Fake::new();
    let list = format!(
        r#"[{{"id":"{ID}","key":"db","value":"{{\"username\":\"app\",\"password\":\"bw-pass\"}}"}},{{"id":"x","key":"other","value":"v"}}]"#
    );
    fake.write("echo 'bws 1.2.0'", &print(&list));
    let (e, _a, _d) = engine(&fake.path(), Duration::from_secs(10));
    let src = source();
    let r = resolve(&e, &src, &bw(&src, &format!("{PROJECT}/db"), CredentialKind::UserPassword))
        .await
        .expect("by key");
    assert_eq!(r.secret(SecretName::Password), Some(&b"bw-pass"[..]));
    assert!(fake.read("argv.txt").contains(&format!("secret list {PROJECT} --output json")));
    let err =
        resolve(&e, &src, &bw(&src, &format!("{PROJECT}/nope"), CredentialKind::ApiToken)).await;
    assert_eq!(err.expect_err("missing").code(), "credential.external_not_found");
    let err =
        resolve(&e, &src, &bw(&src, &format!("{PROJECT}/other"), CredentialKind::UserPassword))
            .await;
    assert_eq!(err.expect_err("not an object").code(), "credential.external_shape");
}

#[tokio::test]
async fn exit_codes_garbage_and_caps() {
    let _serial = SERIAL.lock().await;
    let src = source();
    let f = bw(&src, ID, CredentialKind::ApiToken);
    for (body, code) in [
        ("echo 'bw-secret-value on stderr' >&2; exit 3", "secret.tool_failed"),
        ("printf 'not json at all'", "credential.external_shape"),
        ("printf '{\"id\":\"x\"'", "credential.external_shape"),
        (&*format!("printf '%s' '{{\"id\":\"{ID}\",\"key\":\"k\",\"value\":5}}'"), "credential.external_shape"),
        ("printf '%s' '{\"id\":\"00000000-0000-0000-0000-000000000000\",\"key\":\"k\",\"value\":\"v\"}'", "credential.external_shape"),
        ("/usr/bin/yes bw-flood", "secret.tool_failed"),
        ("kill -9 $$", "secret.tool_failed"),
    ] {
        let fake = Fake::new();
        fake.write("echo 'bws 1.0.0'", body);
        let (e, _a, _d) = engine(&fake.path(), Duration::from_secs(10));
        let err = resolve(&e, &src, &f).await.expect_err(body);
        assert_eq!(err.code(), code, "{body}");
        assert!(!err.to_string().contains("bw-secret-value") && !err.to_string().contains(TOKEN), "{err}");
    }
}

#[tokio::test]
async fn deadline_version_missing_and_changed() {
    let _serial = SERIAL.lock().await;
    let src = source();
    let f = bw(&src, ID, CredentialKind::ApiToken);
    let slow = Fake::new();
    slow.write("echo 'bws 1.0.0'", "/bin/sleep 5");
    let (e, _a, _d) = engine(&slow.path(), Duration::from_millis(300));
    let t = std::time::Instant::now();
    let err = resolve(&e, &src, &f).await.expect_err("deadline");
    assert!(matches!(err, SecretsError::ToolFailed { exit: None, .. }), "{err:?}");
    assert!(t.elapsed() < Duration::from_secs(4), "killed at the deadline");
    for v in ["echo 'bws 0.9.3'", "echo 'garbage'", "exit 1"] {
        let old = Fake::new();
        old.write(v, "exit 0");
        let (e, _a, _d) = engine(&old.path(), Duration::from_secs(10));
        let err = resolve(&e, &src, &f).await.expect_err(v);
        assert!(matches!(err.code(), "secret.tool_version" | "secret.tool_failed"), "{v}: {err}");
    }
    let none = Fake::new();
    let (e, _a, _d) = engine(&none.path(), Duration::from_secs(10));
    assert_eq!(resolve(&e, &src, &f).await.expect_err("missing").code(), "secret.tool_missing");
    let fake = Fake::new();
    let body = format!(r#"{{"id":"{ID}","key":"api","value":"t"}}"#);
    fake.write("echo 'bws 1.0.0'", &print(&body));
    let (e, audit, _d) = engine(&fake.path(), Duration::from_secs(10));
    resolve(&e, &src, &f).await.expect("first");
    fake.write("echo 'bws 1.0.1'", &format!("true; {}", print(&body)));
    resolve(&e, &src, &f).await.expect("changed binary still runs");
    assert!(audit.take().iter().any(|x| matches!(x, SecretEvent::ToolChanged { .. })));
    assert_eq!(fake.read("argv.txt").matches("--version").count(), 2, "re-checked after a change");
    let t = e.test_source(&src, &login()).await;
    assert!(t.is_err(), "the fake prints a secret, not a project list");
}
