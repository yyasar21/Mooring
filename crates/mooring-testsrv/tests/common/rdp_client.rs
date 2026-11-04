//! RDP verification client for the test server's self-tests, built from `ironrdp-connector`,
//! `ironrdp-async` and `ironrdp-session` (dev-dependencies of this crate only). NOT the product
//! client (`mooring-proto-rdp`, ADR-0011): it trusts any certificate and takes the CredSSP
//! public key from the test instead of the peer certificate.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ironrdp_async::NetworkClient;
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    general_err, BitmapConfig, ClientConnector, Config, ConnectionOutcome, ConnectorResult,
    Credentials, DesktopSize,
};
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::rdp::capability_sets::{client_codecs_capabilities, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::TokioFramed;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::tls::client_config;

pub type Res<T> = Result<T, String>;

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

struct NoNetwork;

impl NetworkClient for NoNetwork {
    #[allow(clippy::manual_async_fn)]
    fn send(
        &mut self,
        _req: &NetworkRequest,
    ) -> impl std::future::Future<Output = ConnectorResult<Vec<u8>>> {
        async { Err(general_err!("no network in tests")) }
    }
}

/// Clipboard events seen by the client backend.
#[derive(Debug, Default)]
pub struct ClipLog {
    pub request_format_list: bool,
    pub remote_offers_text: bool,
    pub data_requested: bool,
    pub received: Vec<String>,
}

#[derive(Debug)]
struct Backend(Arc<Mutex<ClipLog>>);

impl ironrdp_core::AsAny for Backend {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl CliprdrBackend for Backend {
    fn temporary_directory(&self) -> &'static str {
        ".cliprdr"
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }
    fn on_ready(&mut self) {}
    fn on_request_format_list(&mut self) {
        self.0.lock().expect("log").request_format_list = true;
    }
    fn on_process_negotiated_capabilities(&mut self, _c: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        if formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT) {
            self.0.lock().expect("log").remote_offers_text = true;
        }
    }
    fn on_format_data_request(&mut self, _r: FormatDataRequest) {
        self.0.lock().expect("log").data_requested = true;
    }
    fn on_format_data_response(&mut self, r: FormatDataResponse<'_>) {
        if let Ok(t) = r.to_unicode_string() {
            self.0.lock().expect("log").received.push(t);
        }
    }
    fn on_file_contents_request(&mut self, _r: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _r: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _id: LockDataId) {}
    fn on_unlock(&mut self, _id: LockDataId) {}
}

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub nla: bool,
    pub tls: bool,
    pub width: u16,
    pub height: u16,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            username: "alice".to_owned(),
            password: "correct horse".to_owned(),
            domain: None,
            nla: true,
            tls: false,
            width: 640,
            height: 480,
        }
    }
}

fn config(o: &ClientOptions) -> Res<Config> {
    Ok(Config {
        desktop_size: DesktopSize { width: o.width, height: o.height },
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls: o.tls,
        enable_credssp: o.nla,
        enable_standard_rdp_security: false,
        support_dyn_vc_gfx_protocol: false,
        credentials: Credentials::UsernamePassword {
            username: o.username.clone(),
            password: o.password.clone(),
        },
        domain: o.domain.clone(),
        client_build: 0,
        client_name: "mooring-qa".to_owned(),
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x041F,
        connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: Some(BitmapConfig {
            lossy_compression: false,
            color_depth: 32,
            codecs: client_codecs_capabilities(&[]).map_err(s)?,
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
    })
}

pub struct RdpClient {
    framed: TokioFramed<TlsStream<TcpStream>>,
    pub stage: ActiveStage,
    pub image: DecodedImage,
    pub leaf: Option<Vec<u8>>,
    pub clip: Arc<Mutex<ClipLog>>,
    pub graphics_updates: u32,
    pub terminated: bool,
    local_text: Option<String>,
}

impl RdpClient {
    pub async fn connect(
        addr: SocketAddr,
        o: ClientOptions,
        server_public_key: Vec<u8>,
    ) -> Res<Self> {
        let clip = Arc::new(Mutex::new(ClipLog::default()));
        let dvc = DrdynvcClient::new()
            .with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
        let mut connector = ClientConnector::new(config(&o)?, addr)
            .with_static_channel(dvc)
            .with_static_channel(CliprdrClient::new(Box::new(Backend(Arc::clone(&clip)))));
        let mut framed = TokioFramed::new(TcpStream::connect(addr).await.map_err(s)?);
        let should_upgrade =
            ironrdp_async::connect_begin(&mut framed, &mut connector).await.map_err(s)?;
        let tcp = framed.into_inner_no_leftover();
        let (tls_config, verifier) = client_config();
        let name = rustls::pki_types::ServerName::try_from("example.test").map_err(s)?;
        let tls =
            tokio_rustls::TlsConnector::from(tls_config).connect(name, tcp).await.map_err(s)?;
        let leaf = verifier.leaf.lock().expect("leaf").clone();
        let upgraded = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
        let mut framed = TokioFramed::new(tls);
        let outcome = ironrdp_async::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut NoNetwork,
            "example.test".to_owned().into(),
            server_public_key,
            None,
        )
        .await
        .map_err(s)?;
        let ConnectionOutcome::Connected(r) = outcome else {
            return Err("unexpected redirection".to_owned());
        };
        let image = DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::RgbA32,
            r.desktop_size.width,
            r.desktop_size.height,
        );
        let stage = ActiveStageBuilder {
            static_channels: r.static_channels,
            user_channel_id: r.user_channel_id,
            io_channel_id: r.io_channel_id,
            message_channel_id: r.message_channel_id,
            share_id: r.share_id,
            compression_type: r.compression_type,
            enable_server_pointer: false,
            pointer_software_rendering: false,
        }
        .build();
        Ok(Self {
            framed,
            stage,
            image,
            leaf,
            clip,
            graphics_updates: 0,
            terminated: false,
            local_text: None,
        })
    }

    async fn write(&mut self, bytes: &[u8]) -> Res<()> {
        use ironrdp_async::FramedWrite as _;
        self.framed.write_all(bytes).await.map_err(s)
    }

    async fn handle(&mut self, outputs: Vec<ActiveStageOutput>) -> Res<()> {
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(b) => self.write(&b).await?,
                ActiveStageOutput::GraphicsUpdate(_) => self.graphics_updates += 1,
                ActiveStageOutput::Terminate(_) => self.terminated = true,
                _ => {}
            }
        }
        Ok(())
    }

    /// Reads and processes one PDU from the server.
    pub async fn step(&mut self) -> Res<()> {
        let (action, frame) = self.framed.read_pdu().await.map_err(s)?;
        let outputs = self.stage.process(&mut self.image, action, &frame, None).map_err(s)?;
        self.handle(outputs).await?;
        self.clipboard_reactions().await
    }

    /// Processes PDUs for at most `ms` milliseconds (returns early on none). Use this, not
    /// `step`, when waiting for server-side state: the server may have nothing more to send.
    pub async fn pump(&mut self, ms: u64) -> Res<()> {
        match tokio::time::timeout(std::time::Duration::from_millis(ms), self.step()).await {
            Ok(r) => r,
            Err(_) => Ok(()),
        }
    }

    /// Steps until `cond` holds.
    pub async fn until(&mut self, mut cond: impl FnMut(&Self) -> bool) -> Res<()> {
        while !cond(self) {
            self.step().await?;
        }
        Ok(())
    }

    /// Sends the client Shutdown Request (graceful disconnect).
    pub async fn shutdown(&mut self) -> Res<()> {
        let outputs = self.stage.graceful_shutdown().map_err(s)?;
        self.handle(outputs).await
    }

    pub async fn input(&mut self, events: &[FastPathInputEvent]) -> Res<()> {
        let outputs = self.stage.process_fastpath_input(&mut self.image, events).map_err(s)?;
        self.handle(outputs).await
    }

    pub async fn resize(&mut self, w: u32, h: u32) -> Res<bool> {
        match self.stage.encode_resize(w, h, None, None) {
            Some(frame) => {
                let frame = frame.map_err(s)?;
                self.write(&frame).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Runs `f` on the cliprdr client and sends what it produced.
    async fn cliprdr<F>(&mut self, f: F) -> Res<()>
    where
        F: FnOnce(
            &mut CliprdrClient,
        ) -> ironrdp_pdu::PduResult<
            ironrdp_cliprdr::CliprdrSvcMessages<ironrdp_cliprdr::Client>,
        >,
    {
        let c = self.stage.get_svc_processor_mut::<CliprdrClient>().ok_or("no cliprdr")?;
        let msgs = f(c).map_err(s)?;
        let frame = self.stage.process_svc_processor_messages(msgs).map_err(s)?;
        self.write(&frame).await
    }

    /// Announces CF_UNICODETEXT (Format List); the server then requests the text set with
    /// [`Self::set_local_text`].
    pub async fn copy_text(&mut self) -> Res<()> {
        let formats = [ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
        self.cliprdr(|c| c.initiate_copy(&formats)).await
    }

    pub fn clipboard_ready(&mut self) -> bool {
        self.stage.get_svc_processor_mut::<CliprdrClient>().is_some_and(|c| c.is_ready())
    }

    /// Text the client would serve when asked (set by the test).
    pub fn set_local_text(&mut self, text: &str) {
        self.local_text = Some(text.to_owned());
    }

    async fn clipboard_reactions(&mut self) -> Res<()> {
        let (init, offer, asked) = {
            let mut log = self.clip.lock().expect("log");
            let r = (log.request_format_list, log.remote_offers_text, log.data_requested);
            log.request_format_list = false;
            log.remote_offers_text = false;
            log.data_requested = false;
            r
        };
        if init {
            self.cliprdr(|c| c.initiate_copy(&[])).await?;
        }
        if offer {
            self.cliprdr(|c| c.initiate_paste(ClipboardFormatId::CF_UNICODETEXT)).await?;
        }
        if asked {
            let text = self.local_text.clone().unwrap_or_default();
            let resp = FormatDataResponse::new_unicode_string(&text);
            self.cliprdr(|c| c.submit_format_data(resp)).await?;
        }
        Ok(())
    }

    /// RGBA of the decoded image.
    pub fn rgba(&self) -> &[u8] {
        self.image.data()
    }
}
