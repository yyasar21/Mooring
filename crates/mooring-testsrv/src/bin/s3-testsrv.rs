//! `cargo run -p mooring-testsrv --bin s3-testsrv -- --port 0` — loopback mock S3 bucket (`SigV4`,
//! conditional writes) for manual testing of vault sync. Flags: docs/qa/test-servers.md.

use mooring_testsrv::cli::{self, Args};
use mooring_testsrv::s3::{self, S3Config, S3Knobs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a = Args::parse(
        &["fork", "no-conditional"],
        &cli::with_http_flags(&[
            "access-key",
            "secret-key",
            "region",
            "bucket",
            "max-object",
            "rollback",
        ]),
    )?;
    let mut cfg = S3Config::default();
    let c = &mut cfg.credentials;
    for (flag, field) in [
        ("access-key", &mut c.access_key),
        ("secret-key", &mut c.secret_key),
        ("region", &mut c.region),
    ] {
        if let Some(v) = a.str(flag) {
            v.clone_into(field);
        }
    }
    if let Some(b) = a.str("bucket") {
        b.clone_into(&mut cfg.bucket);
    }
    cfg.conditional_writes = !a.has("no-conditional");
    cfg.max_object_size = a.get_or("max-object", cfg.max_object_size)?;
    cfg.knobs = S3Knobs { rollback: a.get_or("rollback", 0)?, fork: a.has("fork") };
    let mut http = a.http_knobs()?;
    if a.str("max-body").is_none() {
        http.max_request_body = cfg.http.max_request_body;
    }
    cfg.http = http;
    let info = vec![
        format!("bucket: {} region: {} (path-style endpoint)", cfg.bucket, cfg.credentials.region),
        format!(
            "access key (test values): {} / {}",
            cfg.credentials.access_key, cfg.credentials.secret_key
        ),
    ];
    let srv = s3::start(cfg, a.get_or("port", 9000)?).await.map_err(|e| e.to_string())?;
    cli::announce("s3-testsrv", srv.addr(), srv.cert(), &info);
    std::future::pending::<()>().await;
    Ok(())
}
