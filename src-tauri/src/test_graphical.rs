//! A scripted graphical session and factory for the R2 tests: each connect hands the test a
//! [`FakeConn`] to push events and frames and to read the inputs the session received.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mooring_core::frame::{decode_mfr1, FrameSink, Mfr1Frame};
use mooring_core::session::{CloseCode, Session, SessionEvent, SessionInput, Size};
use mooring_core::{MooringError, Protocol, ProtocolOptions, SessionAudit};
use tokio::sync::mpsc;

use crate::commands::sessions as sess;
use crate::commands::tree::{self, ConnectionFields};
use crate::error::IpcError;
use crate::frame_pump::FrameOut;
use crate::session_factory::{ConnectFuture, GraphicalConnect, SessionFactory};
use crate::sessions::EventSink;
use crate::state::testing::{unlocked, Fixture};

type Res<T> = Result<T, MooringError>;
type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The test's end of one connection.
#[derive(Debug)]
pub struct FakeConn {
    pub events: mpsc::UnboundedSender<SessionEvent>,
    pub inputs: mpsc::UnboundedReceiver<SessionInput>,
    pub frames: FrameSink,
    pub audits: Arc<Mutex<Vec<SessionAudit>>>,
    pub trusted_once: Option<[u8; 32]>,
    pub options: ProtocolOptions,
    pub size: Size,
}

impl FakeConn {
    pub fn send(&self, e: SessionEvent) {
        self.events.send(e).expect("session alive");
    }

    pub fn connected(&self) {
        self.send(SessionEvent::Connected {
            protocol: Protocol::Rdp,
            peer_identity: Some("x509 SHA256:00".into()),
            security: Some("nla".into()),
        });
    }

    pub fn closed(&self, code: CloseCode) {
        self.send(SessionEvent::Closed { reason: format!("{code:?}"), code });
    }

    pub async fn input(&mut self) -> SessionInput {
        tokio::time::timeout(Duration::from_secs(5), self.inputs.recv())
            .await
            .expect("input within 5 s")
            .expect("open")
    }
}

#[derive(Debug)]
struct FakeSession {
    events: mpsc::UnboundedReceiver<SessionEvent>,
    inputs: mpsc::UnboundedSender<SessionInput>,
    audits: Arc<Mutex<Vec<SessionAudit>>>,
    closed: Option<bool>,
}

impl Session for FakeSession {
    fn protocol(&self) -> Protocol {
        Protocol::Rdp
    }

    fn send<'a, 'b>(&'a mut self, input: SessionInput) -> Fut<'b, Res<()>>
    where
        'a: 'b,
        Self: 'b,
    {
        let r = self.inputs.send(input).map_err(|_| MooringError::Closed);
        Box::pin(async move { r })
    }

    fn next_event<'a, 'b>(&'a mut self) -> Fut<'b, Res<Option<SessionEvent>>>
    where
        'a: 'b,
        Self: 'b,
    {
        Box::pin(async move {
            if self.closed == Some(false) {
                self.closed = Some(true);
                let reason = "closed".to_owned();
                return Ok(Some(SessionEvent::Closed { reason, code: CloseCode::User }));
            }
            if self.closed.is_some() {
                return Ok(None);
            }
            Ok(self.events.recv().await)
        })
    }

    fn close<'a, 'b>(&'a mut self) -> Fut<'b, Res<()>>
    where
        'a: 'b,
        Self: 'b,
    {
        self.closed.get_or_insert(false);
        Box::pin(async { Ok(()) })
    }

    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        std::mem::take(&mut *self.audits.lock().expect("audits"))
    }
}

/// Factory handing out fake sessions; queued errors fail the next connects.
#[derive(Debug)]
pub struct FakeFactory {
    conns: mpsc::UnboundedSender<FakeConn>,
    pub fail: Mutex<VecDeque<IpcError>>,
}

impl SessionFactory for FakeFactory {
    fn connect(&self, req: GraphicalConnect) -> ConnectFuture {
        let failed = self.fail.lock().expect("fail").pop_front();
        let conns = self.conns.clone();
        Box::pin(async move {
            if let Some(e) = failed {
                return Err(e);
            }
            let (etx, erx) = mpsc::unbounded_channel();
            let (itx, irx) = mpsc::unbounded_channel();
            let audits = Arc::new(Mutex::new(Vec::new()));
            let conn = FakeConn {
                events: etx,
                inputs: irx,
                frames: req.frames,
                audits: Arc::clone(&audits),
                trusted_once: req.trusted_once,
                options: req.options,
                size: req.params.size,
            };
            conns.send(conn).map_err(|_| IpcError::session_failed("test gone"))?;
            let s = FakeSession { events: erx, inputs: itx, audits, closed: None };
            Ok(Box::new(s) as Box<dyn Session>)
        })
    }
}

/// A test bench: unlocked state with the fake factory and one connection of `protocol`.
#[derive(Debug)]
pub struct Bench {
    pub f: Fixture,
    pub conn: String,
    pub conns: mpsc::UnboundedReceiver<FakeConn>,
    pub factory: Arc<FakeFactory>,
}

pub fn bench(protocol: &str) -> Bench {
    let mut f = unlocked();
    let (tx, conns) = mpsc::unbounded_channel();
    let factory = Arc::new(FakeFactory { conns: tx, fail: Mutex::new(VecDeque::new()) });
    f.state.settings.graphical = Arc::clone(&factory) as Arc<dyn SessionFactory>;
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let fields = ConnectionFields::basic(&root, "desk", protocol, "rdp.example.test");
    let conn = tree::create_connection(&f.state, fields).expect("connection").id;
    Bench { f, conn, conns, factory }
}

/// UI side of an open session: JSON events and decoded frames.
#[derive(Debug)]
pub struct Ui {
    pub session_id: String,
    pub events: mpsc::UnboundedReceiver<serde_json::Value>,
    pub frames: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Ui {
    pub async fn event(&mut self) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(5), self.events.recv())
            .await
            .expect("event within 5 s")
            .expect("open")
    }

    pub async fn frame(&mut self) -> Mfr1Frame {
        let m = tokio::time::timeout(Duration::from_secs(5), self.frames.recv())
            .await
            .expect("frame within 5 s")
            .expect("open");
        decode_mfr1(&m).expect("valid MFR1")
    }
}

pub const DESKTOP: Size = Size { width: 1280, height: 800 };

/// Open a graphical session on `b` and take its first fake connection.
pub async fn open(b: &mut Bench) -> (Ui, FakeConn) {
    let (etx, events) = mpsc::unbounded_channel();
    let (ftx, frames) = mpsc::unbounded_channel();
    let sink: EventSink =
        Arc::new(move |e| etx.send(serde_json::to_value(&e).expect("json")).is_ok());
    let out: FrameOut = Arc::new(move |m| ftx.send(m).is_ok());
    let opened =
        sess::open_with(&b.f.state, &b.conn, DESKTOP, sink, Some(out)).await.expect("open");
    let conn = next_conn(b).await;
    (Ui { session_id: opened.session_id, events, frames }, conn)
}

pub async fn next_conn(b: &mut Bench) -> FakeConn {
    tokio::time::timeout(Duration::from_secs(5), b.conns.recv())
        .await
        .expect("connect within 5 s")
        .expect("factory alive")
}

/// Wait until the session left the registry.
pub async fn gone(b: &Bench) {
    for _ in 0..250 {
        if sess::list(&b.f.state).expect("list").is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session did not leave the registry");
}

/// Raw audit log text.
pub fn audit(b: &Bench) -> String {
    std::fs::read_to_string(b.f.dir.path().join(crate::state::AppState::AUDIT_FILE))
        .unwrap_or_default()
}
