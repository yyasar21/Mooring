//! In-process mock LDAPS directory (ADR-0019 §4 test plan) on loopback TLS: simple bind
//! against one fixture account, subtree / one-level / base search over fixture entries with
//! filter evaluation, RFC 2696 paging, `sizeLimit`, referrals, and hostile response knobs
//! (empty message, deep nesting, huge length, garbage, oversized values). Every request is
//! recorded; any operation other than bind / search / abandon / unbind, a search before a
//! bind, or a malformed frame is a **violation** (`assert_no_violations`). The bind
//! password never reaches the record.

pub mod ber;
mod filter;
mod recorder;

pub use recorder::{LdapRecorder, LdapRequest};

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lber::structure::StructureTag;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::tls::TestCert;

/// Largest request frame accepted before the connection is dropped.
pub const MAX_REQUEST: usize = 64 * 1024;

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<String>)>,
}

impl LdapEntry {
    pub fn new(dn: &str, attrs: &[(&str, &[&str])]) -> Self {
        Self {
            dn: dn.to_owned(),
            attrs: attrs
                .iter()
                .map(|(a, v)| ((*a).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
                .collect(),
        }
    }
}

/// A hostile reply sent instead of the search result (then the connection closes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hostile {
    /// `30 00`: an LDAPMessage with no elements.
    EmptyMessage,
    /// `n` nested SEQUENCEs.
    DeepNesting(usize),
    /// A header claiming 4 GiB followed by a few bytes, then silence.
    HugeLength,
    /// Random non-BER bytes.
    Garbage,
    /// A valid entry whose `description` value is this many bytes.
    OversizedValue(usize),
    /// A search result entry with three elements.
    ExtraElement,
}

/// Failure behaviour of the mock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapKnobs {
    /// Stop after this many entries with `sizeLimitExceeded` (4), like a server-side limit.
    pub size_limit_after: Option<usize>,
    /// Send a `SearchResultReference` before the entries (never to be followed).
    pub referral: bool,
    /// Instead of the search result.
    pub hostile: Option<Hostile>,
    /// Return everything in one go without a paged-results control.
    pub ignore_paging: bool,
    /// Ignore the request's `sizeLimit` (a server that keeps sending).
    pub ignore_size_limit: bool,
    /// Never answer a search (client deadline test).
    pub never_answer_search: bool,
    /// Delay every bind response.
    pub bind_delay: Option<Duration>,
}

/// Configuration of one mock.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// The one account that binds (any name form the client uses verbatim).
    pub bind_name: String,
    pub bind_password: String,
    pub entries: Vec<LdapEntry>,
    pub knobs: LdapKnobs,
    pub cert: Option<TestCert>,
}

/// The default fixture: four AD computers under two OUs of `DC=corp,DC=example,DC=test`.
pub fn default_entries() -> Vec<LdapEntry> {
    let base = "DC=corp,DC=example,DC=test";
    vec![
        LdapEntry::new(
            &format!("CN=WEB01,OU=Web,OU=Servers,{base}"),
            &[
                ("objectClass", &["top", "computer"]),
                ("cn", &["WEB01"]),
                ("dNSHostName", &["web01.corp.example.test"]),
                ("operatingSystem", &["Windows Server 2022 Standard"]),
            ],
        ),
        LdapEntry::new(
            &format!("CN=DB01,OU=Servers,{base}"),
            &[
                ("objectClass", &["top", "computer"]),
                ("cn", &["DB01"]),
                ("dNSHostName", &["db01.corp.example.test"]),
                ("operatingSystem", &["Red Hat Enterprise Linux 9"]),
                ("description", &["primary database"]),
            ],
        ),
        LdapEntry::new(
            &format!("CN=LAPTOP07,OU=Workstations,{base}"),
            &[
                ("objectClass", &["top", "computer"]),
                ("cn", &["LAPTOP07"]),
                ("dNSHostName", &["laptop07.corp.example.test"]),
                ("operatingSystem", &["Windows 11 Enterprise"]),
            ],
        ),
        LdapEntry::new(
            &format!("CN=STALE,OU=Servers,{base}"),
            &[("objectClass", &["top", "computer"]), ("cn", &["STALE"])],
        ),
        LdapEntry::new(
            &format!("CN=Alice,OU=People,{base}"),
            &[("objectClass", &["top", "person", "user"]), ("cn", &["Alice"])],
        ),
    ]
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            bind_name: "svc-mooring@corp.example.test".to_owned(),
            bind_password: "test-bind-pw".to_owned(),
            entries: default_entries(),
            knobs: LdapKnobs::default(),
            cert: None,
        }
    }
}

#[derive(Debug)]
struct State {
    config: Mutex<LdapConfig>,
}

impl State {
    fn config(&self) -> LdapConfig {
        self.config.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

/// A running mock; dropping it stops the listener.
#[derive(Debug)]
pub struct LdapServer {
    addr: SocketAddr,
    cert: TestCert,
    state: Arc<State>,
    recorder: LdapRecorder,
    task: JoinHandle<()>,
}

impl Drop for LdapServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral).
pub async fn start(mut config: LdapConfig, port: u16) -> io::Result<LdapServer> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let tls = cert.server_config().map_err(io::Error::other)?;
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let state = Arc::new(State { config: Mutex::new(config) });
    let recorder = LdapRecorder::default();
    let (st, rec) = (Arc::clone(&state), recorder.clone());
    let acceptor = TlsAcceptor::from(tls);
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, st, rec) = (acceptor.clone(), Arc::clone(&st), rec.clone());
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp).await {
                    let _ = Connection { st, rec, bound: false }.run(stream).await;
                }
            });
        }
    });
    Ok(LdapServer { addr, cert, state, recorder, task })
}

impl LdapServer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `ldaps://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("ldaps://{}", self.addr)
    }

    pub fn cert(&self) -> &TestCert {
        &self.cert
    }

    pub fn recorder(&self) -> &LdapRecorder {
        &self.recorder
    }

    pub fn set_knobs(&self, knobs: LdapKnobs) {
        self.state.config.lock().unwrap_or_else(std::sync::PoisonError::into_inner).knobs = knobs;
    }

    pub fn set_entries(&self, entries: Vec<LdapEntry>) {
        self.state.config.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries =
            entries;
    }
}

struct Connection {
    st: Arc<State>,
    rec: LdapRecorder,
    bound: bool,
}

type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

impl Connection {
    async fn run(mut self, mut stream: Stream) -> io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let (consumed, tag) = match lber::parse::parse_tag(&buf) {
                Ok((rest, tag)) => (buf.len() - rest.len(), Some(tag)),
                Err(e) if e.is_incomplete() => (0, None),
                Err(_) => {
                    self.rec.push(LdapRequest {
                        violation: Some("malformed BER request".into()),
                        ..LdapRequest::default()
                    });
                    return Ok(());
                }
            };
            if let Some(tag) = tag {
                buf.drain(..consumed);
                if !self.handle(&tag, &mut stream).await? {
                    return Ok(());
                }
                continue;
            }
            if buf.len() > MAX_REQUEST {
                self.rec.push(LdapRequest {
                    violation: Some("request frame over 64 KiB".into()),
                    ..LdapRequest::default()
                });
                return Ok(());
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Handle one LDAPMessage; `Ok(false)` closes the connection.
    async fn handle(&mut self, tag: &StructureTag, stream: &mut Stream) -> io::Result<bool> {
        let Some(req) = ber::decode_request(tag) else {
            self.rec.push(LdapRequest {
                violation: Some("not an LDAPMessage".into()),
                ..LdapRequest::default()
            });
            return Ok(false);
        };
        let cfg = self.st.config();
        let mut record = LdapRequest {
            msgid: req.msgid,
            paged: req.paged.clone(),
            controls: req.controls.clone(),
            ..LdapRequest::default()
        };
        match req.op {
            ber::APP_BIND_REQUEST => {
                record.op = "bind".into();
                let Some((name, password)) = ber::decode_bind(&req.op_tag) else {
                    record.violation = Some("bind is not a simple bind".into());
                    self.rec.push(record);
                    return Ok(false);
                };
                record.bind_name = Some(name.clone());
                self.rec.push(record);
                if let Some(d) = cfg.knobs.bind_delay {
                    tokio::time::sleep(d).await;
                }
                let ok = name == cfg.bind_name && password == cfg.bind_password.as_bytes();
                self.bound = ok;
                let rc = if ok { 0 } else { 49 };
                let text = if ok {
                    ""
                } else {
                    "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error"
                };
                stream
                    .write_all(&ber::message(
                        req.msgid,
                        ber::result(ber::APP_BIND_RESPONSE, rc, text, &[]),
                        None,
                    ))
                    .await?;
                Ok(true)
            }
            ber::APP_SEARCH_REQUEST => {
                record.op = "search".into();
                let Some(search) = ber::decode_search(&req.op_tag) else {
                    record.violation = Some("malformed search request".into());
                    self.rec.push(record);
                    return Ok(false);
                };
                record.base = Some(search.base.clone());
                record.filter = Some(filter::render(&search.filter));
                record.attrs.clone_from(&search.attrs);
                record.scope = Some(search.scope);
                record.size_limit = Some(search.size_limit);
                record.time_limit = Some(search.time_limit);
                if !self.bound {
                    record.violation = Some("search before a successful bind".into());
                    self.rec.push(record);
                    stream
                        .write_all(&ber::message(
                            req.msgid,
                            ber::result(ber::APP_SEARCH_DONE, 1, "bind first", &[]),
                            None,
                        ))
                        .await?;
                    return Ok(false);
                }
                self.rec.push(record);
                self.answer_search(req.msgid, &search, req.paged.as_ref(), &cfg, stream).await
            }
            ber::APP_ABANDON => {
                record.op = "abandon".into();
                self.rec.push(record);
                Ok(true)
            }
            ber::APP_UNBIND => {
                record.op = "unbind".into();
                self.rec.push(record);
                Ok(false)
            }
            other => {
                record.op = format!("op:{other}");
                record.violation =
                    Some(format!("operation {other} is not bind/search/abandon/unbind"));
                self.rec.push(record);
                Ok(false)
            }
        }
    }

    async fn answer_search(
        &self,
        msgid: i64,
        search: &ber::Search,
        paged: Option<&(i64, Vec<u8>)>,
        cfg: &LdapConfig,
        stream: &mut Stream,
    ) -> io::Result<bool> {
        if cfg.knobs.never_answer_search {
            std::future::pending::<()>().await;
        }
        if let Some(h) = cfg.knobs.hostile {
            stream.write_all(&ber::hostile_bytes(h, msgid)).await?;
            stream.flush().await?;
            if h == Hostile::HugeLength {
                std::future::pending::<()>().await;
            }
            return Ok(false);
        }
        let base = search.base.to_lowercase();
        let in_scope = |dn: &str| {
            let dn = dn.to_lowercase();
            match search.scope {
                0 => dn == base,
                1 => dn.strip_suffix(&format!(",{base}")).is_some_and(|p| !p.contains(',')),
                _ => dn == base || dn.ends_with(&format!(",{base}")),
            }
        };
        let matching: Vec<&LdapEntry> = cfg
            .entries
            .iter()
            .filter(|e| in_scope(&e.dn) && filter::matches(&search.filter, e))
            .collect();
        let mut limit = usize::MAX;
        if search.size_limit > 0 && !cfg.knobs.ignore_size_limit {
            limit = limit.min(usize::try_from(search.size_limit).unwrap_or(usize::MAX));
        }
        if let Some(n) = cfg.knobs.size_limit_after {
            limit = limit.min(n);
        }
        let (offset, page) = match paged {
            Some((size, cookie)) if !cfg.knobs.ignore_paging => {
                let offset = std::str::from_utf8(cookie)
                    .ok()
                    .and_then(|c| c.parse::<usize>().ok())
                    .unwrap_or(0);
                (offset, usize::try_from(*size).unwrap_or(0).max(1))
            }
            _ => (0, usize::MAX),
        };
        if cfg.knobs.referral && offset == 0 {
            let r = ber::app(
                ber::APP_SEARCH_REF,
                vec![ber::octet(b"ldaps://other.example.test/DC=other,DC=test")],
            );
            stream.write_all(&ber::message(msgid, r, None)).await?;
        }
        let end = matching.len().min(offset.saturating_add(page));
        for (sent_total, e) in (offset..).zip(&matching[offset.min(matching.len())..end]) {
            if sent_total >= limit {
                stream
                    .write_all(&ber::message(
                        msgid,
                        ber::result(ber::APP_SEARCH_DONE, 4, "size limit exceeded", &[]),
                        None,
                    ))
                    .await?;
                return Ok(true);
            }
            let attrs: Vec<(String, Vec<String>)> = e
                .attrs
                .iter()
                .filter(|(a, _)| {
                    search.attrs.is_empty()
                        || search.attrs.iter().any(|w| w.eq_ignore_ascii_case(a))
                })
                .cloned()
                .collect();
            stream.write_all(&ber::message(msgid, ber::entry(&e.dn, &attrs), None)).await?;
        }
        let control = match paged {
            Some(_) if !cfg.knobs.ignore_paging => {
                let cookie = if end < matching.len() { end.to_string() } else { String::new() };
                Some(ber::paged_control(0, cookie.as_bytes()))
            }
            _ => None,
        };
        stream
            .write_all(&ber::message(msgid, ber::result(ber::APP_SEARCH_DONE, 0, "", &[]), control))
            .await?;
        stream.flush().await?;
        Ok(true)
    }
}
