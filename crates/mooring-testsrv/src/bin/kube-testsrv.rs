//! `cargo run -p mooring-testsrv --bin kube-testsrv -- --port 0` — loopback mock Kubernetes API
//! for manual testing with the app. Flags: docs/qa/test-servers.md.

use base64::Engine as _;
use mooring_testsrv::cli::{self, Args};
use mooring_testsrv::kube::{self, many_pods, KubeConfig, KubeKnobs};

fn config(a: &Args) -> Result<KubeConfig, String> {
    let mut c = KubeConfig {
        token: Some(a.str("token").unwrap_or("test-token").to_owned()),
        client_cert_auth: !a.has("no-client-cert"),
        http: a.http_knobs()?,
        ..KubeConfig::default()
    };
    if let Some(n) = a.get::<usize>("pods")? {
        c.pods.extend(many_pods("default", n));
    }
    let d = KubeKnobs::default();
    let protocols = a
        .str("ws-protocols")
        .map_or_else(|| d.ws_protocols.clone(), |p| p.split(',').map(str::to_owned).collect());
    c.knobs = KubeKnobs {
        force_401: a.has("force-401"),
        force_403: a.has("force-403"),
        oversized_body: a.get("oversized-body")?,
        huge_log: a.get("huge-log")?,
        log_lines: a.get_or("log-lines", d.log_lines)?,
        ws_protocols: protocols,
        portforward_error: a.str("portforward-error").map(str::to_owned),
        ..d
    };
    Ok(c)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a = Args::parse(
        &["no-client-cert", "force-401", "force-403"],
        &cli::with_http_flags(&[
            "token",
            "pods",
            "oversized-body",
            "huge-log",
            "log-lines",
            "ws-protocols",
            "portforward-error",
        ]),
    )?;
    let cfg = config(&a)?;
    let token = cfg.token.clone().unwrap_or_default();
    let srv = kube::start(cfg, a.get_or("port", 6443)?).await.map_err(|e| e.to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64.encode(srv.cert().cert_der().as_ref())
    );
    let kubeconfig = format!(
        "# kubeconfig for this server (fake test token):\napiVersion: v1\nkind: Config\n\
         current-context: mooring-test\nclusters:\n- name: mooring-test\n  cluster:\n    \
         server: {}\n    certificate-authority-data: {}\nusers:\n- name: alice\n  user:\n    \
         token: {token}\ncontexts:\n- name: mooring-test\n  context:\n    cluster: mooring-test\n    \
         user: alice\n    namespace: default",
        srv.base_url(),
        b64.encode(pem)
    );
    cli::announce("kube-testsrv", srv.addr(), srv.cert(), &[kubeconfig]);
    std::future::pending::<()>().await;
    Ok(())
}
