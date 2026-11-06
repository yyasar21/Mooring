//! The read-only directory reader (ADR-0019 §4): one TLS connection (our verifier through
//! `mooring-http`), simple bind, paged search (RFC 2696), abandon, unbind — the only four
//! requests that exist in [`super::wire`] (`write_ops_are_absent` greps this file). Every
//! frame from the server passes the iterative [`super::frame::scan`] (size and depth caps)
//! before the recursive BER parser sees it; every message is decoded without panics. The
//! whole run is one task under a deadline.

use std::sync::Arc;
use std::time::Duration;

use mooring_http::{HttpError, TlsClient};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::entry::{extract, RawEntry, ATTRIBUTES};
use super::frame::{scan, Scan, MAX_FRAME};
use super::wire::{self, Message};
use super::{BindCredential, BindPhase, BindSignal, LdapError, LdapLimits, Prepared};

const RC_SUCCESS: u32 = 0;
const RC_TIME_LIMIT: u32 = 3;
const RC_SIZE_LIMIT: u32 = 4;
const RC_NO_SUCH_OBJECT: u32 = 32;
/// Most malformed entries tolerated in one search before the run is refused.
const MAX_MALFORMED: usize = 64;
/// Most frames read for one search page beyond its entries (notices, refs, intermediates).
const MAX_NOISE: usize = 1024;
/// How long to wait for the server to close after the unbind.
const UNBIND_GRACE: Duration = Duration::from_millis(500);

/// A bound connection that can only search, abandon and unbind.
pub struct DirectoryReader {
    stream: TlsStream<TcpStream>,
    buf: Vec<u8>,
    /// Read chunk (heap: keeps the futures small).
    chunk: Box<[u8]>,
    next_id: i32,
}

impl std::fmt::Debug for DirectoryReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryReader").field("next_id", &self.next_id).finish_non_exhaustive()
    }
}

fn result_error(rc: u32) -> LdapError {
    match rc {
        RC_TIME_LIMIT => LdapError::Timeout,
        RC_SIZE_LIMIT => LdapError::SizeLimit,
        RC_NO_SUCH_OBJECT => LdapError::DnInvalid("the server has no such base object"),
        rc => LdapError::Unavailable(format!("result code {rc}")),
    }
}

fn io_error(e: &std::io::Error) -> LdapError {
    LdapError::Unavailable(format!("io {:?}", e.kind()))
}

/// TCP connect plus TLS handshake with `tls` (our verifier: a trust decision surfaces as
/// `LdapError::Tls(HttpError::Trust*)`), under `limits.connect_timeout`. No LDAP frame.
async fn handshake(
    query: &Prepared,
    tls: TlsClient,
    limits: &LdapLimits,
) -> Result<TlsStream<TcpStream>, LdapError> {
    let host = query.target.host.clone();
    let sni = ServerName::try_from(host.clone())
        .map_err(|_| LdapError::Invalid("host is not a valid TLS server name"))?;
    let connect = async {
        let tcp = TcpStream::connect((host.as_str(), query.target.port))
            .await
            .map_err(|e| io_error(&e))?;
        let _ = tcp.set_nodelay(true);
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&tls.config));
        connector.connect(sni, tcp).await.map_err(|e| match tls.trust_error() {
            Some(t) => LdapError::Tls(t),
            None => match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                Some(r) => LdapError::Tls(HttpError::Tls(r.to_string())),
                None => io_error(&e),
            },
        })
    };
    tokio::time::timeout(limits.connect_timeout, connect).await.map_err(|_| LdapError::Timeout)?
}

/// Settle transport trust without sending a byte of LDAP (review 7 L-43): connect, complete
/// the TLS handshake with `tls` and close. The caller learns the trust verdict for the
/// target (`Ok`, or `LdapError::Tls(HttpError::TrustPrompt(_))` and friends) before it
/// decides whether a password may be sent there.
pub async fn probe_tls(
    query: &Prepared,
    tls: TlsClient,
    limits: &LdapLimits,
) -> Result<(), LdapError> {
    let mut stream = handshake(query, tls, limits).await?;
    let _ = tokio::time::timeout(UNBIND_GRACE, stream.shutdown()).await;
    Ok(())
}

impl DirectoryReader {
    /// Connect over LDAPS with `tls` and bind as `cred`. A bind result other than success
    /// is `ldap.bind` with the result code (the diagnostic text is dropped).
    pub async fn connect(
        query: &Prepared,
        cred: &BindCredential,
        tls: TlsClient,
        limits: &LdapLimits,
        bind: &BindSignal,
    ) -> Result<Self, LdapError> {
        let stream = handshake(query, tls, limits).await?;
        let mut reader = Self {
            stream,
            buf: Vec::new(),
            chunk: vec![0u8; 16 * 1024].into_boxed_slice(),
            next_id: 1,
        };
        let id = reader.id();
        bind.set(BindPhase::Attempted);
        reader.send(&wire::bind_request(id, &cred.name, &cred.password)).await?;
        let reply = reader.recv_for(id).await?;
        if reply.op != wire::APP_BIND_RESPONSE {
            return Err(LdapError::Response("bind answered with another operation"));
        }
        let rc = wire::result_code(&reply.op_tag).map_err(LdapError::Response)?;
        if rc != RC_SUCCESS {
            tracing::info!(rc, "ldap bind refused (49 = invalid credentials)");
            let _ = reader.unbind().await;
            return Err(LdapError::Bind(rc));
        }
        bind.set(BindPhase::Bound);
        Ok(reader)
    }

    fn id(&mut self) -> i32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), LdapError> {
        self.stream.write_all(frame).await.map_err(|e| io_error(&e))?;
        self.stream.flush().await.map_err(|e| io_error(&e))
    }

    /// The next complete frame, scanned and decoded.
    async fn recv(&mut self) -> Result<Message, LdapError> {
        loop {
            match scan(&self.buf) {
                Scan::Complete(n) => {
                    let frame: Vec<u8> = self.buf.drain(..n).collect();
                    let (_, tag) = lber::parse::parse_tag(&frame)
                        .map_err(|_| LdapError::Response("BER did not parse"))?;
                    return wire::decode_message(&tag).map_err(LdapError::Response);
                }
                Scan::Invalid(what) => return Err(LdapError::Response(what)),
                Scan::Incomplete => {}
            }
            if self.buf.len() >= MAX_FRAME {
                return Err(LdapError::Response("frame too large"));
            }
            let n = self.stream.read(&mut self.chunk).await.map_err(|e| io_error(&e))?;
            if n == 0 {
                return Err(LdapError::Response("connection closed"));
            }
            self.buf.extend_from_slice(&self.chunk[..n]);
        }
    }

    /// The next message for `msgid`; unsolicited notices (id 0) and other ids are skipped,
    /// a Notice of Disconnection ends the run.
    async fn recv_for(&mut self, msgid: i32) -> Result<Message, LdapError> {
        for _ in 0..MAX_NOISE {
            let m = self.recv().await?;
            if m.msgid == msgid {
                return Ok(m);
            }
            if m.msgid == 0 && m.op == wire::APP_EXTENDED_RESPONSE {
                return Err(LdapError::Response("the server disconnected"));
            }
        }
        Err(LdapError::Response("too many unrelated messages"))
    }

    /// Paged search under the query's base: at most `query.size_limit` entries over at most
    /// `limits.max_pages` pages; one more entry or page is `ldap.size_limit` (the running
    /// search is abandoned). Referrals and intermediates are ignored, never followed.
    pub async fn search(
        &mut self,
        query: &Prepared,
        limits: &LdapLimits,
    ) -> Result<Vec<RawEntry>, LdapError> {
        let cap = query.size_limit.min(limits.max_entries);
        let size_limit = i32::try_from(cap).unwrap_or(i32::MAX);
        let time_limit = i32::try_from(limits.deadline.as_secs()).unwrap_or(i32::MAX);
        let page = i32::try_from(limits.page_size).unwrap_or(i32::MAX);
        let base = query.base.to_wire();
        let filter = wire::filter_tag(query.kind, query.name_contains.as_deref());
        let mut entries = Vec::new();
        let mut cookie: Vec<u8> = Vec::new();
        let mut malformed = 0usize;
        for _ in 0..limits.max_pages {
            let id = self.id();
            let params = wire::SearchParams {
                base: &base,
                scope: query.scope,
                size_limit,
                time_limit,
                filter: &filter,
                attrs: &ATTRIBUTES,
                page,
                cookie: &cookie,
            };
            let req = wire::search_request(id, &params);
            self.send(&req).await?;
            let mut noise = 0usize;
            let done = loop {
                let m = self.recv_for(id).await?;
                match m.op {
                    wire::APP_SEARCH_ENTRY => {
                        if entries.len() >= cap {
                            let abandon = self.id();
                            let _ = self.send(&wire::abandon_request(abandon, id)).await;
                            return Err(LdapError::SizeLimit);
                        }
                        match extract(&m.op_tag, &ATTRIBUTES, &limits.entry) {
                            Ok(e) => entries.push(e),
                            Err(what) => {
                                malformed += 1;
                                if malformed > MAX_MALFORMED {
                                    return Err(LdapError::Response(what));
                                }
                            }
                        }
                    }
                    wire::APP_SEARCH_DONE => break m,
                    wire::APP_SEARCH_REF | wire::APP_INTERMEDIATE => {
                        noise += 1;
                        if noise > MAX_NOISE {
                            return Err(LdapError::Response("too many references"));
                        }
                    }
                    _ => return Err(LdapError::Response("unexpected operation in a search")),
                }
            };
            let rc = wire::result_code(&done.op_tag).map_err(LdapError::Response)?;
            if rc != RC_SUCCESS {
                return Err(result_error(rc));
            }
            cookie = wire::paging_cookie(done.controls.as_ref())
                .ok_or(LdapError::Response("bad paged-results control"))?;
            if cookie.is_empty() {
                return Ok(entries);
            }
        }
        Err(LdapError::SizeLimit)
    }

    /// Send the unbind, then wait (briefly) for the server to close: LDAP servers end the
    /// connection on unbind, and reading to EOF keeps the close orderly.
    async fn unbind(&mut self) -> Result<(), LdapError> {
        let id = self.id();
        self.send(&wire::unbind_request(id)).await?;
        let drain =
            async { while matches!(self.stream.read(&mut self.chunk).await, Ok(n) if n > 0) {} };
        let _ = tokio::time::timeout(UNBIND_GRACE, drain).await;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    /// Unbind and close.
    pub async fn close(mut self) {
        let _ = self.unbind().await;
    }
}

/// One run under the deadline, in its own task (a panic anywhere below ends the task and
/// surfaces as `ldap.response`, never the process).
async fn run<T: Send + 'static>(
    deadline: Duration,
    fut: impl std::future::Future<Output = Result<T, LdapError>> + Send + 'static,
) -> Result<T, LdapError> {
    match tokio::spawn(tokio::time::timeout(deadline, fut)).await {
        Ok(Ok(r)) => r,
        Ok(Err(_elapsed)) => Err(LdapError::Timeout),
        Err(join) => {
            tracing::warn!(panicked = join.is_panic(), "ldap task ended abnormally");
            Err(LdapError::Response("the response could not be decoded"))
        }
    }
}

/// Bind and search; the entries, or the first error.
pub async fn fetch(
    query: &Prepared,
    cred: &BindCredential,
    tls: TlsClient,
    limits: &LdapLimits,
    bind: &BindSignal,
) -> Result<Vec<RawEntry>, LdapError> {
    let (query, limits, bind) = (query.clone(), *limits, bind.clone());
    let cred = BindCredential { name: cred.name.clone(), password: cred.password.clone() };
    run(limits.deadline, async move {
        let mut reader = DirectoryReader::connect(&query, &cred, tls, &limits, &bind).await?;
        let result = reader.search(&query, &limits).await;
        reader.close().await;
        result
    })
    .await
}

/// Bind only (`ldap_import_test`): connect, bind, unbind.
pub async fn bind_only(
    query: &Prepared,
    cred: &BindCredential,
    tls: TlsClient,
    limits: &LdapLimits,
    bind: &BindSignal,
) -> Result<(), LdapError> {
    let (query, limits, bind) = (query.clone(), *limits, bind.clone());
    let cred = BindCredential { name: cred.name.clone(), password: cred.password.clone() };
    run(limits.deadline, async move {
        let reader = DirectoryReader::connect(&query, &cred, tls, &limits, &bind).await?;
        reader.close().await;
        Ok(())
    })
    .await
}
