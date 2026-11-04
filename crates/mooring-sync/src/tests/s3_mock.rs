//! A loopback S3 mock for the `S3Backend` tests: path-style objects, `ETag`s, `If-None-Match`
//! / `If-Match`, a mode that ignores them, and a presign check (algorithm, credential scope,
//! signature shape, and that every conditional / metadata header is in `X-Amz-SignedHeaders`).
//!
//! TODO(merge): replace with `mooring-testsrv::s3` (full `SigV4` verification, rollback / fork
//! knobs) once QA lands it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

pub(crate) const ACCESS_KEY: &str = "AKIDEXAMPLETEST";
pub(crate) const BUCKET: &str = "mooring-test";

#[derive(Default)]
struct State {
    objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    etag: AtomicU64,
    ignore_conditionals: AtomicBool,
    log: Mutex<Vec<String>>,
}

/// Running mock; dropped with the test runtime.
pub(crate) struct S3Mock {
    pub addr: SocketAddr,
    state: Arc<State>,
}

struct Req {
    method: String,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl S3Mock {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(State::default());
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let st = st.clone();
                tokio::spawn(async move {
                    let _ = serve(sock, &st).await;
                });
            }
        });
        Self { addr, state }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_ignore_conditionals(&self, on: bool) {
        self.state.ignore_conditionals.store(on, Ordering::SeqCst);
    }

    pub fn put_raw(&self, key: &str, bytes: Vec<u8>) {
        let etag = format!("\"s{}\"", self.state.etag.fetch_add(1, Ordering::SeqCst) + 1);
        lock(&self.state.objects).insert(key.to_owned(), (bytes, etag));
    }

    /// `METHOD status` lines of every request.
    pub fn log(&self) -> Vec<String> {
        lock(&self.state.log).clone()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn read_req(sock: &mut TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    Some(Req { method, path: path.to_owned(), query: query.to_owned(), headers, body })
}

fn presign_ok(r: &Req) -> bool {
    let q: BTreeMap<&str, &str> = r.query.split('&').filter_map(|p| p.split_once('=')).collect();
    let signed = q.get("X-Amz-SignedHeaders").copied().unwrap_or_default().replace("%3B", ";");
    let signed: Vec<&str> = signed.split(';').collect();
    let sig_ok = q
        .get("X-Amz-Signature")
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let cred_ok = q.get("X-Amz-Credential").is_some_and(|c| {
        c.starts_with(&format!("{ACCESS_KEY}%2F")) && c.ends_with("%2Fs3%2Faws4_request")
    });
    let must_sign = r
        .headers
        .keys()
        .filter(|k| k.starts_with("if-") || k.starts_with("x-amz-"))
        .all(|k| signed.contains(&k.as_str()));
    // Review 6 N-44: a presign that outlives one minute is refused like a bad signature.
    let short_lived =
        q.get("X-Amz-Expires").and_then(|e| e.parse::<u64>().ok()).is_some_and(|e| e <= 60);
    q.get("X-Amz-Algorithm") == Some(&"AWS4-HMAC-SHA256")
        && sig_ok
        && cred_ok
        && must_sign
        && short_lived
}

fn handle(r: &Req, st: &State) -> (u16, Vec<(String, String)>, Vec<u8>) {
    if !presign_ok(r) {
        return (403, vec![], b"<Error><Code>SignatureDoesNotMatch</Code></Error>".to_vec());
    }
    let Some(key) = r.path.strip_prefix(&format!("/{BUCKET}/")) else {
        return (404, vec![], vec![]);
    };
    let mut objects = lock(&st.objects);
    let etag_h = |e: &str| vec![("ETag".to_owned(), e.to_owned())];
    match r.method.as_str() {
        "GET" | "HEAD" => match objects.get(key) {
            Some((b, e)) if r.method == "GET" => (200, etag_h(e), b.clone()),
            Some((_, e)) => (200, etag_h(e), vec![]),
            None => (404, vec![], vec![]),
        },
        "PUT" => {
            let have = objects.get(key).map(|(_, e)| e.clone());
            let ignore = st.ignore_conditionals.load(Ordering::SeqCst);
            let inm = r.headers.get("if-none-match").is_some_and(|v| v == "*");
            let im = r.headers.get("if-match");
            let refused = !ignore
                && ((inm && have.is_some()) || im.is_some_and(|want| have.as_ref() != Some(want)));
            if refused {
                return (412, vec![], b"<Error><Code>PreconditionFailed</Code></Error>".to_vec());
            }
            let etag = format!("\"s{}\"", st.etag.fetch_add(1, Ordering::SeqCst) + 1);
            objects.insert(key.to_owned(), (r.body.clone(), etag.clone()));
            (200, etag_h(&etag), vec![])
        }
        "DELETE" => {
            objects.remove(key);
            (204, vec![], vec![])
        }
        _ => (405, vec![], vec![]),
    }
}

async fn serve(mut sock: TcpStream, st: &State) -> std::io::Result<()> {
    let Some(req) = read_req(&mut sock).await else { return Ok(()) };
    let (status, headers, body) = handle(&req, st);
    lock(&st.log).push(format!("{} {status}", req.method));
    let mut out = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    let len = if req.method == "HEAD" {
        lock(&st.objects)
            .get(req.path.trim_start_matches(&format!("/{BUCKET}/")))
            .map_or(0, |(b, _)| b.len())
    } else {
        body.len()
    };
    let _ = write!(out, "Content-Length: {len}\r\n");
    for (k, v) in headers {
        let _ = write!(out, "{k}: {v}\r\n");
    }
    out.push_str("\r\n");
    sock.write_all(out.as_bytes()).await?;
    if req.method != "HEAD" {
        sock.write_all(&body).await?;
    }
    sock.shutdown().await
}
