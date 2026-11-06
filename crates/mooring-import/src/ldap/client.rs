//! The read-only directory reader (ADR-0019 §4): simple bind, paged search (RFC 2696),
//! abandon, unbind — nothing else of `ldap3` is reachable from here (`write_ops_are_absent`
//! greps this file). The whole run is one task under a deadline, so a codec panic on a
//! hostile response ends the task, not the process, and surfaces as `ldap.response`.

use std::time::Duration;

use ldap3::asn1::{parse_tag, StructureTag, TagClass, PL};
use ldap3::controls::{Control, ControlType, PagedResults, RawControl};
use ldap3::{LdapConnAsync, LdapConnSettings, LdapError as Lib, LdapResult, Scope, SearchOptions};
use mooring_http::{HttpError, TlsClient};
use tokio::task::JoinHandle;

use super::entry::{extract, RawEntry, ATTRIBUTES};
use super::{BindCredential, LdapError, LdapLimits, Prepared, SearchScope};

const RC_TIME_LIMIT: u32 = 3;
const RC_SIZE_LIMIT: u32 = 4;
const RC_NO_SUCH_OBJECT: u32 = 32;

/// Aborts the `ldap3` driver task when the reader is dropped (deadline, error or success).
struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A bound connection that can only search, abandon and unbind.
pub struct DirectoryReader {
    ldap: ldap3::Ldap,
    _driver: Driver,
}

impl std::fmt::Debug for DirectoryReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryReader").finish_non_exhaustive()
    }
}

fn connect_error(e: Lib, tls: &TlsClient) -> LdapError {
    if let Some(t) = tls.trust_error() {
        return LdapError::Tls(t);
    }
    match e {
        Lib::Timeout { .. } => LdapError::Timeout,
        Lib::Io { source } => {
            match source.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                Some(r) => LdapError::Tls(HttpError::Tls(r.to_string())),
                None => LdapError::Unavailable(format!("{:?}", source.kind())),
            }
        }
        other => LdapError::Unavailable(kind_of(&other)),
    }
}

/// A fixed description of a library error (never its payload).
fn kind_of(e: &Lib) -> String {
    match e {
        Lib::Io { source } => format!("io {:?}", source.kind()),
        Lib::Timeout { .. } => "timeout".to_owned(),
        Lib::LdapResult { result } => format!("result code {}", result.rc),
        Lib::EndOfStream => "connection closed".to_owned(),
        Lib::ResultRecv { .. } | Lib::OpSend { .. } => "connection lost".to_owned(),
        _ => "protocol error".to_owned(),
    }
}

fn op_error(e: Lib) -> LdapError {
    match e {
        Lib::Timeout { .. } => LdapError::Timeout,
        Lib::LdapResult { result } => result_error(&result),
        Lib::ResultRecv { .. } | Lib::OpSend { .. } | Lib::EndOfStream => {
            LdapError::Response("connection lost")
        }
        other => LdapError::Unavailable(kind_of(&other)),
    }
}

fn result_error(r: &LdapResult) -> LdapError {
    match r.rc {
        RC_TIME_LIMIT => LdapError::Timeout,
        RC_SIZE_LIMIT => LdapError::SizeLimit,
        RC_NO_SUCH_OBJECT => LdapError::DnInvalid("the server has no such base object"),
        rc => LdapError::Unavailable(format!("result code {rc}")),
    }
}

impl DirectoryReader {
    /// Connect over LDAPS with `tls` and bind as `cred`. A bind result other than success
    /// is `ldap.bind` (the code is kept, the diagnostic text is not).
    pub async fn connect(
        query: &Prepared,
        cred: &BindCredential,
        tls: TlsClient,
        limits: &LdapLimits,
    ) -> Result<Self, LdapError> {
        let settings = LdapConnSettings::new()
            .set_config(tls.config.clone())
            .set_conn_timeout(limits.connect_timeout);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &query.target.url())
            .await
            .map_err(|e| connect_error(e, &tls))?;
        let driver = Driver(tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::debug!(error = %kind_of(&e), "ldap connection ended");
            }
        }));
        let bind = ldap
            .with_timeout(limits.deadline)
            .simple_bind(&cred.name, &cred.password)
            .await
            .map_err(op_error)?;
        if bind.rc != 0 {
            let rc = bind.rc;
            tracing::info!(rc, "ldap bind refused (49 = invalid credentials)");
            let _ = ldap.unbind().await;
            return Err(LdapError::Bind(rc));
        }
        Ok(Self { ldap, _driver: driver })
    }

    /// Paged search under the query's base: at most `limits.max_entries` entries over at most
    /// `limits.max_pages` pages; one more entry or page is `ldap.size_limit` (the running
    /// search is abandoned). Referrals are ignored, never followed.
    pub async fn search(
        &mut self,
        query: &Prepared,
        limits: &LdapLimits,
    ) -> Result<Vec<RawEntry>, LdapError> {
        let scope = match query.scope {
            SearchScope::Base => Scope::Base,
            SearchScope::One => Scope::OneLevel,
            SearchScope::Sub => Scope::Subtree,
        };
        let size_limit =
            i32::try_from(query.size_limit.min(limits.max_entries)).unwrap_or(i32::MAX);
        let time_limit = i32::try_from(limits.deadline.as_secs()).unwrap_or(i32::MAX);
        let page = i32::try_from(limits.page_size).unwrap_or(i32::MAX);
        let base = query.base.to_wire();
        let mut entries = Vec::new();
        let mut cookie: Vec<u8> = Vec::new();
        let mut malformed = 0usize;
        for _ in 0..limits.max_pages {
            let control: RawControl = PagedResults { size: page, cookie: cookie.clone() }.into();
            let mut stream = self
                .ldap
                .with_controls(vec![control])
                .with_search_options(
                    SearchOptions::new().sizelimit(size_limit).timelimit(time_limit),
                )
                .with_timeout(limits.deadline)
                .streaming_search(&base, scope, &query.filter, ATTRIBUTES)
                .await
                .map_err(op_error)?;
            while let Some(item) = stream.next().await.map_err(op_error)? {
                if item.is_ref() || item.is_intermediate() {
                    continue;
                }
                if entries.len() >= query.size_limit {
                    let id = stream.ldap_handle().last_id();
                    let _ = self.ldap.abandon(id).await;
                    return Err(LdapError::SizeLimit);
                }
                match extract(&item.0, &ATTRIBUTES, &limits.entry) {
                    Ok(e) => entries.push(e),
                    Err(what) => {
                        malformed += 1;
                        if malformed > 64 {
                            return Err(LdapError::Response(what));
                        }
                    }
                }
            }
            let done = stream.finish().await;
            if done.rc != 0 {
                return Err(result_error(&done));
            }
            cookie = paging_cookie(&done.ctrls)
                .ok_or(LdapError::Response("bad paged-results control"))?;
            if cookie.is_empty() {
                return Ok(entries);
            }
        }
        Err(LdapError::SizeLimit)
    }

    /// Unbind and close.
    pub async fn close(mut self) {
        let _ = self.ldap.unbind().await;
    }
}

/// The cookie of the paged-results response control (`Some(empty)` when absent: the server
/// did not page, the result is complete); `None` for a malformed control value.
fn paging_cookie(ctrls: &[Control]) -> Option<Vec<u8>> {
    let Some(Control(_, raw)) =
        ctrls.iter().find(|c| matches!(c.0, Some(ControlType::PagedResults)))
    else {
        return Some(Vec::new());
    };
    let val = raw.val.as_deref()?;
    if val.len() > 4096 {
        return None;
    }
    let (_, tag) = parse_tag(val).ok()?;
    cookie_of(&tag)
}

fn cookie_of(tag: &StructureTag) -> Option<Vec<u8>> {
    let PL::C(items) = &tag.payload else { return None };
    if tag.class != TagClass::Universal || tag.id != 16 {
        return None;
    }
    let [size, cookie] = items.as_slice() else { return None };
    match (&size.payload, &cookie.payload) {
        (PL::P(_), PL::P(c)) if size.id == 2 && cookie.id == 4 => Some(c.clone()),
        _ => None,
    }
}

/// One run under the deadline, in its own task: a panic inside the `ldap3` codec (hostile
/// BER) ends the task and becomes `ldap.response`.
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
) -> Result<Vec<RawEntry>, LdapError> {
    let (query, limits) = (query.clone(), *limits);
    let cred = BindCredential { name: cred.name.clone(), password: cred.password.clone() };
    run(limits.deadline, async move {
        let mut reader = DirectoryReader::connect(&query, &cred, tls, &limits).await?;
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
) -> Result<(), LdapError> {
    let (query, limits) = (query.clone(), *limits);
    let cred = BindCredential { name: cred.name.clone(), password: cred.password.clone() };
    run(limits.deadline, async move {
        let reader = DirectoryReader::connect(&query, &cred, tls, &limits).await?;
        reader.close().await;
        Ok(())
    })
    .await
}
