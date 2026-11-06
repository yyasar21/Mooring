//! Request log of the LDAP mock: one [`LdapRequest`] per decoded message (names only; the
//! bind password is never kept) and the "only bind / search / abandon / unbind" trap.

use std::sync::{Arc, Mutex, MutexGuard};

/// One recorded request (names only; the bind password is never kept).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapRequest {
    /// `bind` | `search` | `abandon` | `unbind` | `op:<tag>`.
    pub op: String,
    pub msgid: i64,
    pub bind_name: Option<String>,
    pub base: Option<String>,
    /// RFC 4515 text of the filter as the server decoded it.
    pub filter: Option<String>,
    pub attrs: Vec<String>,
    pub scope: Option<i64>,
    pub size_limit: Option<i64>,
    pub time_limit: Option<i64>,
    /// Paged-results request control `(size, cookie)`.
    pub paged: Option<(i64, Vec<u8>)>,
    pub controls: Vec<String>,
    pub violation: Option<String>,
}

/// Shared request log.
#[derive(Debug, Clone, Default)]
pub struct LdapRecorder(Arc<Mutex<Vec<LdapRequest>>>);

impl LdapRecorder {
    fn lock(&self) -> MutexGuard<'_, Vec<LdapRequest>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn push(&self, r: LdapRequest) {
        let mut g = self.lock();
        if g.len() < 100_000 {
            g.push(r);
        }
    }

    pub fn requests(&self) -> Vec<LdapRequest> {
        self.lock().clone()
    }

    /// `op` of every request, oldest first.
    pub fn ops(&self) -> Vec<String> {
        self.lock().iter().map(|r| r.op.clone()).collect()
    }

    pub fn searches(&self) -> Vec<LdapRequest> {
        self.lock().iter().filter(|r| r.op == "search").cloned().collect()
    }

    pub fn violations(&self) -> Vec<LdapRequest> {
        self.lock().iter().filter(|r| r.violation.is_some()).cloned().collect()
    }

    /// Panics with the offending requests if any request hit the trap.
    pub fn assert_no_violations(&self) {
        let v = self.violations();
        assert!(v.is_empty(), "forbidden requests reached the LDAP mock: {v:#?}");
    }
}
