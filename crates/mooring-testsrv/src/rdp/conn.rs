//! Accept loop and the acceptor-driven connection sequence (X.224 → TLS → CredSSP → finalize).

use std::sync::Arc;

use ironrdp_acceptor::{
    accept_begin, accept_credssp, accept_finalize, Acceptor, BeginResult, DesktopSize,
};
use ironrdp_async::NetworkClient;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{general_err, ConnectorResult};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::{self as caps, CapabilitySet, GeneralExtraFlags};
use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_tokio::TokioFramed;
use tokio::sync::watch;

use super::{active, channels, lock, RdpSecurity, Shared};

/// Refuses every network request: no KDC / Kerberos traffic leaves a test (NTLM only).
struct NoNetwork;

impl NetworkClient for NoNetwork {
    #[allow(clippy::manual_async_fn)] // the trait is declared with `impl Future`
    fn send(
        &mut self,
        _req: &NetworkRequest,
    ) -> impl std::future::Future<Output = ConnectorResult<Vec<u8>>> {
        async { Err(general_err!("network requests are disabled in the RDP test server")) }
    }
}

pub(crate) async fn accept_loop(
    shared: Arc<Shared>,
    listener: std::net::TcpListener,
    mut stopped: watch::Receiver<()>,
) {
    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else { return };
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else { break };
                let _ = tcp.set_nodelay(true);
                lock(&shared.stats).connections += 1;
                let shared = Arc::clone(&shared);
                tokio::task::spawn_local(async move {
                    if let Err(e) = serve(&shared, tcp).await {
                        lock(&shared.stats).errors.push(e);
                    }
                });
            }
        }
    }
}

/// Server capability sets, modelled on `ironrdp-server` 0.13 (fast-path output, 32 bpp,
/// fast-path input). No bitmap codecs (RemoteFX / NSCodec are not served).
fn capabilities(size: DesktopSize) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(caps::General {
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
            refresh_rect_support: true,
            suppress_output_support: true,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(caps::Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: size.width,
            desktop_height: size.height,
            desktop_resize_flag: true,
            drawing_flags: caps::BitmapDrawingFlags::empty(),
        }),
        CapabilitySet::Order(caps::Order::new(
            caps::OrderFlags::empty(),
            caps::OrderSupportExFlags::empty(),
            2048,
            224,
        )),
        CapabilitySet::Pointer(caps::Pointer {
            color_pointer_cache_size: 2048,
            pointer_cache_size: 2048,
        }),
        CapabilitySet::Input(caps::Input {
            input_flags: caps::InputFlags::SCANCODES
                | caps::InputFlags::MOUSEX
                | caps::InputFlags::FASTPATH_INPUT
                | caps::InputFlags::UNICODE
                | caps::InputFlags::FASTPATH_INPUT_2,
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 128,
            keyboard_ime_filename: String::new(),
        }),
        CapabilitySet::VirtualChannel(caps::VirtualChannel {
            flags: caps::VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: None,
        }),
        CapabilitySet::MultiFragmentUpdate(caps::MultifragmentUpdate {
            max_request_size: 8 * 1024 * 1024,
        }),
    ]
}

fn e<E: std::fmt::Display>(stage: &'static str) -> impl FnOnce(E) -> String {
    move |err| format!("{stage}: {err}")
}

async fn serve(shared: &Arc<Shared>, tcp: tokio::net::TcpStream) -> Result<(), String> {
    let cfg = &shared.config;
    let size = DesktopSize { width: cfg.width, height: cfg.height };
    let protocol = match cfg.security {
        RdpSecurity::Tls => SecurityProtocol::SSL,
        RdpSecurity::Nla => SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX,
    };
    let creds = Credentials {
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        domain: cfg.domain.clone(),
    };
    let mut acceptor = Acceptor::new(protocol, size, capabilities(size), Some(creds));
    let clip = channels::attach(shared, &mut acceptor);

    let begin =
        accept_begin(TokioFramed::new(tcp), &mut acceptor).await.map_err(e("negotiation"))?;
    let BeginResult::ShouldUpgrade(tcp) = begin else {
        return Err(
            "negotiation: no security upgrade (standard RDP security is never served)".to_owned()
        );
    };
    let tls = tokio_rustls::TlsAcceptor::from(Arc::clone(&shared.tls))
        .accept(tcp)
        .await
        .map_err(e("tls"))?;
    acceptor.mark_security_upgrade_as_done();
    let mut framed = TokioFramed::new(tls);
    if cfg.security == RdpSecurity::Nla {
        let public_key = cfg.cert.as_ref().map(|c| c.public_key_raw().to_vec()).unwrap_or_default();
        accept_credssp(
            &mut framed,
            &mut acceptor,
            &mut NoNetwork,
            "mooring-client".to_owned().into(),
            public_key,
            None,
        )
        .await
        .map_err(e("credssp"))?;
    }
    let (framed, result) = accept_finalize(framed, &mut acceptor).await.map_err(e("finalize"))?;
    {
        let mut stats = lock(&shared.stats);
        stats.accepted += 1;
        stats.security.push(match cfg.security {
            RdpSecurity::Tls => "ssl".to_owned(),
            RdpSecurity::Nla => "hybrid".to_owned(),
        });
        stats.keyboard_layout = Some(result.keyboard_layout);
    }
    if cfg.knobs.drop_after_accept {
        return Ok(());
    }
    active::run(shared, framed, result, clip).await
}
