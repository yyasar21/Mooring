//! `cargo run -p mooring-testsrv --bin rdp-testsrv -- --port 0` — loopback RDP test server
//! for manual testing with the app. Flags: docs/qa/test-servers.md.

use std::io::Write as _;
use std::time::Duration;

use mooring_testsrv::cli::Args;
use mooring_testsrv::rdp::{self, BitmapMode, RdpConfig, RdpKnobs, RdpSecurity, Rect};

fn config(a: &Args) -> Result<RdpConfig, String> {
    let security = match a.str("security").unwrap_or("nla") {
        "nla" => RdpSecurity::Nla,
        "tls" => RdpSecurity::Tls,
        s => return Err(format!("unknown --security {s:?} (nla | tls)")),
    };
    let bitmap = match a.str("bitmap").unwrap_or("raw") {
        "raw" => BitmapMode::Raw,
        "planar" => BitmapMode::Planar,
        b => return Err(format!("unknown --bitmap {b:?} (raw | planar)")),
    };
    Ok(RdpConfig {
        width: a.get_or("width", 1024)?,
        height: a.get_or("height", 768)?,
        security,
        username: a.str("user").unwrap_or("alice").to_owned(),
        password: a.str("password").unwrap_or("testpass").to_owned(),
        domain: a.str("domain").map(str::to_owned),
        bitmap,
        clipboard: !a.has("no-clipboard"),
        display_control: !a.has("no-display-control"),
        knobs: RdpKnobs {
            out_of_bounds_bitmap: a.get("out-of-bounds")?,
            drop_after_accept: a.has("drop-after-accept"),
            advertised_desktop: a.str("desktop").map(parse_size).transpose()?,
        },
        ..RdpConfig::default()
    })
}

/// `--desktop WxH`: the size advertised to the client (hostile sizes allowed).
fn parse_size(v: &str) -> Result<(u16, u16), String> {
    let (w, h) = v.split_once('x').ok_or_else(|| format!("bad --desktop {v:?} (WxH)"))?;
    let n = |s: &str| s.parse::<u16>().map_err(|_| format!("bad --desktop {v:?} (WxH)"));
    Ok((n(w)?, n(h)?))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let a = Args::parse(
        &["animate", "no-clipboard", "no-display-control", "drop-after-accept"],
        &[
            "port",
            "width",
            "height",
            "security",
            "bitmap",
            "user",
            "password",
            "domain",
            "out-of-bounds",
            "clipboard-text",
            "desktop",
        ],
    )?;
    let srv = rdp::start(config(&a)?, a.get_or("port", 3389)?).map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "rdp-testsrv listening on {}", srv.addr());
    let _ = writeln!(out, "certificate SHA256:{}", srv.cert().sha256_hex());
    let _ = out.flush();
    if let Some(text) = a.str("clipboard-text") {
        tokio::time::sleep(Duration::from_secs(1)).await;
        srv.set_clipboard(text);
    }
    let mut tick: u16 = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if a.has("animate") {
            let fb = srv.framebuffer();
            let x = tick.wrapping_mul(8) % fb.width.saturating_sub(64).max(1);
            srv.fill(
                Rect::new(x, 40, 64, 64),
                [0, 160, u8::try_from(tick % 256).unwrap_or(0), 255],
            );
            tick = tick.wrapping_add(1);
        }
    }
}
