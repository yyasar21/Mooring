//! `cargo run -p mooring-testsrv --bin ldap-testsrv -- --port 0` — loopback mock LDAPS directory
//! (AD-style computers under OUs) for manual testing of the directory importer.
//! Flags: `--port`, `--referral`, `--ignore-paging`, `--size-limit-after N`.

use mooring_testsrv::cli::{self, Args};
use mooring_testsrv::ldap::{self, LdapConfig, LdapKnobs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a = Args::parse(&["referral", "ignore-paging"], &["port", "size-limit-after"])?;
    let cfg = LdapConfig {
        knobs: LdapKnobs {
            referral: a.has("referral"),
            ignore_paging: a.has("ignore-paging"),
            size_limit_after: a
                .str("size-limit-after")
                .map(|v| v.parse().map_err(|_| "--size-limit-after needs a number".to_owned()))
                .transpose()?,
            ..LdapKnobs::default()
        },
        ..LdapConfig::default()
    };
    let lines = vec![
        format!("bind (test values): name={} password={}", cfg.bind_name, cfg.bind_password),
        "base DN: DC=corp,DC=example,DC=test (OU=Servers, OU=Web, OU=Workstations, OU=People)"
            .to_owned(),
        format!("entries: {}", cfg.entries.len()),
    ];
    let srv = ldap::start(cfg, a.get_or("port", 6636)?).await.map_err(|e| e.to_string())?;
    cli::announce("ldap-testsrv", srv.addr(), srv.cert(), &lines);
    std::future::pending::<()>().await;
    Ok(())
}
