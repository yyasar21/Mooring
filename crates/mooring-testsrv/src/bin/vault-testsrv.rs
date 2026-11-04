//! `cargo run -p mooring-testsrv --bin vault-testsrv -- --port 0` — loopback mock Vault / `OpenBao`
//! (KV v2, token, `AppRole`, OIDC) for manual testing with the app. Flags: docs/qa/test-servers.md.

use mooring_testsrv::cli::{self, Args};
use mooring_testsrv::vault::{self, VaultConfig, VaultKnobs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a =
        Args::parse(&["sealed", "standby", "root-token"], &cli::with_http_flags(&["namespace"]))?;
    let cfg = VaultConfig {
        namespace: a.str("namespace").map(str::to_owned),
        knobs: VaultKnobs {
            sealed: a.has("sealed"),
            standby: a.has("standby"),
            root_token: a.has("root-token"),
            ..VaultKnobs::default()
        },
        http: a.http_knobs()?,
        ..VaultConfig::default()
    };
    let mut lines: Vec<String> = cfg
        .tokens
        .iter()
        .map(|t| {
            format!("token (test value): {} policies={:?} ttl={}s", t.token, t.policies, t.ttl)
        })
        .collect();
    let r = &cfg.approle;
    lines.push(format!(
        "approle (test values): mount={} role_id={} secret_id={}",
        r.mount, r.role_id, r.secret_id
    ));
    let o = &cfg.oidc;
    lines.push(format!(
        "oidc: mount={} role={} redirect={:?}",
        o.mount, o.role, o.allowed_redirect_uris
    ));
    lines.push(
        "kv v2: secret/servers/web (v1, v2), secret/servers/deleted, secret/servers/destroyed"
            .to_owned(),
    );
    let srv = vault::start(cfg, a.get_or("port", 8200)?).await.map_err(|e| e.to_string())?;
    cli::announce("vault-testsrv", srv.addr(), srv.cert(), &lines);
    std::future::pending::<()>().await;
    Ok(())
}
