//! `cargo run -p mooring-testsrv --bin vcenter-testsrv -- --port 0` — loopback mock vCenter REST
//! API for manual testing with the app. Flags: docs/qa/test-servers.md.

use mooring_testsrv::cli::{self, Args};
use mooring_testsrv::vcenter::{self, InventorySpec, VcenterConfig, VcenterKnobs};

fn config(a: &Args) -> Result<VcenterConfig, String> {
    let d = VcenterConfig::default();
    let i = InventorySpec::default();
    Ok(VcenterConfig {
        username: a.str("user").map_or_else(|| d.username.clone(), str::to_owned),
        password: a.str("password").map_or_else(|| d.password.clone(), str::to_owned),
        inventory: InventorySpec {
            datacenters: a.get_or("datacenters", i.datacenters)?,
            clusters_per_dc: a.get_or("clusters", i.clusters_per_dc)?,
            hosts_per_cluster: a.get_or("hosts", i.hosts_per_cluster)?,
            standalone_hosts_per_dc: a.get_or("standalone", i.standalone_hosts_per_dc)?,
            vms_per_host: a.get_or("vms-per-host", i.vms_per_host)?,
        },
        knobs: VcenterKnobs {
            rate_limit_per_sec: a.get("rate-limit")?,
            result_limit: a.get_or("result-limit", 4000)?,
            tools_missing: a.has("tools-missing"),
            tickets_unavailable: a.has("no-tickets"),
        },
        http: a.http_knobs()?,
        ..d
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a = Args::parse(
        &["tools-missing", "no-tickets"],
        &cli::with_http_flags(&[
            "user",
            "password",
            "datacenters",
            "clusters",
            "hosts",
            "standalone",
            "vms-per-host",
            "rate-limit",
            "result-limit",
        ]),
    )?;
    let cfg = config(&a)?;
    let login = format!("login (test values): {} / {}", cfg.username, cfg.password);
    let srv = vcenter::start(cfg, a.get_or("port", 8443)?).await.map_err(|e| e.to_string())?;
    let vms = format!("inventory: {} VMs", srv.inventory().vms.len());
    cli::announce("vcenter-testsrv", srv.addr(), srv.cert(), &[login, vms]);
    std::future::pending::<()>().await;
    Ok(())
}
