//! `cargo run -p mooring-testsrv --bin rfb-testsrv -- --port 0` — loopback RFB 3.8 test server
//! for manual testing with the app. Flags: docs/qa/test-servers.md.

use std::io::Write as _;
use std::time::Duration;

use mooring_testsrv::cli::Args;
use mooring_testsrv::rfb::{
    self, Knobs, Rect, RfbConfig, SecurityOffer, TightMode, VeNCryptSub, ZrleMode,
};

fn security(list: &str) -> Result<Vec<SecurityOffer>, String> {
    let mut subs = Vec::new();
    let mut out = Vec::new();
    for item in list.split(',') {
        match item {
            "none" => out.push(SecurityOffer::None),
            "vnc" => out.push(SecurityOffer::VncAuth),
            "x509none" => subs.push(VeNCryptSub::X509None),
            "x509vnc" => subs.push(VeNCryptSub::X509Vnc),
            "x509plain" => subs.push(VeNCryptSub::X509Plain),
            "tlsnone" => subs.push(VeNCryptSub::TlsNone),
            "tlsvnc" => subs.push(VeNCryptSub::TlsVnc),
            "tlsplain" => subs.push(VeNCryptSub::TlsPlain),
            "plain" => subs.push(VeNCryptSub::Plain),
            other => return Err(format!("unknown security {other:?}")),
        }
    }
    if !subs.is_empty() {
        out.insert(0, SecurityOffer::VeNCrypt(subs));
    }
    Ok(out)
}

fn config(a: &Args) -> Result<RfbConfig, String> {
    let zrle_mode = match a.str("zrle").unwrap_or("auto") {
        "auto" => ZrleMode::Auto,
        "raw" => ZrleMode::Raw,
        "plain-rle" => ZrleMode::PlainRle,
        m => return Err(format!("unknown --zrle {m:?}")),
    };
    let tight_mode = match a.str("tight").unwrap_or("auto") {
        "auto" => TightMode::Auto,
        "copy" => TightMode::Copy,
        "palette" => TightMode::Palette,
        "gradient" => TightMode::Gradient,
        m => return Err(format!("unknown --tight {m:?}")),
    };
    let version = match a.str("version") {
        Some(v) if v.len() == 11 => {
            let mut b = [b'\n'; 12];
            b[..11].copy_from_slice(v.as_bytes());
            Some(b)
        }
        Some(v) => {
            return Err(format!("--version must be 11 bytes like \"RFB 003.003\", got {v:?}"))
        }
        None => None,
    };
    let knobs = Knobs {
        version,
        strip_tls_after: a.get("strip-tls-after")?,
        slow_loris: a.get::<u64>("slow-loris-ms")?.map(Duration::from_millis),
        oversized_rect: a.get("oversized-rect")?,
        lie_zlib_length: a.get("lie-zlib-length")?,
        lie_cut_text_length: a.get("lie-cut-text-length")?,
        missing_rects: a.get("missing-rects")?,
        use_last_rect: a.has("last-rect"),
        force_encoding: a.get("force-encoding")?,
        tight_jpeg: a.has("tight-jpeg"),
        fail_auth_reason: a.str("fail-auth").map(str::to_owned),
        huge_name: a.get("huge-name")?,
    };
    let user = a.str("user").unwrap_or("alice").to_owned();
    let password = a.str("password").unwrap_or("testpass").to_owned();
    Ok(RfbConfig {
        width: a.get_or("width", 1024)?,
        height: a.get_or("height", 768)?,
        name: a.str("name").unwrap_or("mooring-testsrv").to_owned(),
        security: security(a.str("security").unwrap_or("x509vnc,x509none,vnc,none"))?,
        plain_user: Some((user, password.clone())),
        password: Some(password),
        zrle_mode,
        tight_mode,
        allow_client_resize: !a.has("no-client-resize"),
        knobs,
        ..RfbConfig::default()
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let a = Args::parse(
        &["animate", "last-rect", "tight-jpeg", "no-client-resize"],
        &[
            "port",
            "width",
            "height",
            "name",
            "security",
            "user",
            "password",
            "zrle",
            "tight",
            "version",
            "strip-tls-after",
            "slow-loris-ms",
            "oversized-rect",
            "lie-zlib-length",
            "lie-cut-text-length",
            "missing-rects",
            "force-encoding",
            "fail-auth",
            "huge-name",
        ],
    )?;
    let cfg = config(&a)?;
    let srv = rfb::start(cfg, a.get_or("port", 5900)?).await.map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "rfb-testsrv listening on {}", srv.addr());
    if let Some(c) = srv.cert() {
        let _ = writeln!(out, "VeNCrypt certificate SHA256:{}", c.sha256_hex());
    }
    let _ = out.flush();
    let mut tick: u16 = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if a.has("animate") {
            let fb = srv.framebuffer();
            let x = tick.wrapping_mul(8) % fb.width.saturating_sub(48).max(1);
            srv.fill(
                Rect::new(x, 40, 48, 48),
                [255, u8::try_from(tick % 256).unwrap_or(0), 0, 255],
            );
            tick = tick.wrapping_add(1);
        }
    }
}
