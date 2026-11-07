//! The dynamic-engine endpoints of ADR-0026 §1–§2 on [`VaultClient`]: database creds, SSH
//! sign / OTP, PKI issue / revoke and the lease API. Paths come from validated segments and
//! are percent-encoded; request bodies are built with `serde_json` (nothing user-typed is
//! concatenated into JSON).

use std::net::IpAddr;
use std::time::Duration;

use mooring_core::credential::VaultPath;
use mooring_http::Method;
use serde::Serialize;

use crate::client::{mount_path, pct_encode, VaultClient};
use crate::error::{Ctx, SecretsError};
use crate::wire_dynamic::{DbCreds, Envelope, LeaseInfo, PkiIssued, Renewed, SshOtp, SshSigned};

/// `ssh/sign` request parameters.
#[derive(Debug, Clone, Default)]
pub struct SignRequest<'a> {
    /// The OpenSSH public key line (never the private key).
    pub public_key: &'a str,
    /// `valid_principals`.
    pub principals: &'a [String],
    /// Requested TTL.
    pub ttl: Option<u64>,
}

/// `pki/issue` request parameters.
#[derive(Debug, Clone, Default)]
pub struct IssueRequest<'a> {
    /// `common_name`.
    pub common_name: &'a str,
    /// `alt_names`.
    pub alt_names: &'a [String],
    /// Requested TTL.
    pub ttl: Option<u64>,
}

#[derive(Serialize)]
struct SignBody<'a> {
    public_key: &'a str,
    cert_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_principals: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
}

#[derive(Serialize)]
struct OtpBody<'a> {
    ip: String,
    username: &'a str,
}

#[derive(Serialize)]
struct IssueBody<'a> {
    common_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    alt_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
}

#[derive(Serialize)]
struct LeaseBody<'a> {
    lease_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    increment: Option<u64>,
}

#[derive(Serialize)]
struct RevokeCert<'a> {
    serial_number: &'a str,
}

fn engine_path(at: &VaultPath, verb: &str) -> String {
    let (mount, role) = at.mount_role();
    format!("/v1/{}/{verb}/{}", mount_path(&mount), pct_encode(role))
}

fn joined(v: &[String]) -> Option<String> {
    (!v.is_empty()).then(|| v.join(","))
}

impl VaultClient {
    /// `GET /v1/<mount>/creds/<role>` (database).
    pub(crate) async fn db_creds(
        &self,
        token: &str,
        at: &VaultPath,
    ) -> Result<(LeaseInfo, DbCreds), SecretsError> {
        let path = engine_path(at, "creds");
        let r = self.call(Method::GET, &path, Some(token), None, Ctx::Read).await?;
        Self::json::<Envelope<DbCreds>>(&r)?.split()
    }

    /// `POST /v1/<mount>/sign/<role> { public_key, cert_type: user, valid_principals?, ttl? }`.
    pub(crate) async fn ssh_sign(
        &self,
        token: &str,
        at: &VaultPath,
        req: &SignRequest<'_>,
    ) -> Result<(LeaseInfo, SshSigned), SecretsError> {
        let body = Self::body(&SignBody {
            public_key: req.public_key,
            cert_type: "user",
            valid_principals: joined(req.principals),
            ttl: req.ttl.map(|t| format!("{t}s")),
        })?;
        let path = engine_path(at, "sign");
        let r = self.call(Method::POST, &path, Some(token), Some(body), Ctx::Read).await?;
        Self::json::<Envelope<SshSigned>>(&r)?.split()
    }

    /// `POST /v1/<mount>/creds/<role> { ip, username }` (SSH one-time password).
    pub(crate) async fn ssh_otp(
        &self,
        token: &str,
        at: &VaultPath,
        ip: IpAddr,
        username: &str,
    ) -> Result<(LeaseInfo, SshOtp), SecretsError> {
        let body = Self::body(&OtpBody { ip: ip.to_string(), username })?;
        let path = engine_path(at, "creds");
        let r = self.call(Method::POST, &path, Some(token), Some(body), Ctx::Read).await?;
        Self::json::<Envelope<SshOtp>>(&r)?.split()
    }

    /// `POST /v1/<mount>/issue/<role> { common_name, alt_names?, ttl? }`.
    pub(crate) async fn pki_issue(
        &self,
        token: &str,
        at: &VaultPath,
        req: &IssueRequest<'_>,
    ) -> Result<(LeaseInfo, PkiIssued), SecretsError> {
        let body = Self::body(&IssueBody {
            common_name: req.common_name,
            alt_names: joined(req.alt_names),
            ttl: req.ttl.map(|t| format!("{t}s")),
        })?;
        let path = engine_path(at, "issue");
        let r = self.call(Method::POST, &path, Some(token), Some(body), Ctx::Read).await?;
        Self::json::<Envelope<PkiIssued>>(&r)?.split()
    }

    /// `POST /v1/<mount>/revoke { serial_number }` (`revokeCertOnDisconnect`).
    pub async fn pki_revoke(
        &self,
        token: &str,
        mount: &str,
        serial: &str,
    ) -> Result<(), SecretsError> {
        let body = Self::body(&RevokeCert { serial_number: serial })?;
        let path = format!("/v1/{}/revoke", mount_path(mount));
        self.call(Method::POST, &path, Some(token), Some(body), Ctx::Read).await.map(drop)
    }

    /// `PUT /v1/sys/leases/renew { lease_id, increment }`: the new duration and whether the
    /// lease may be renewed again. A response for another lease is refused.
    pub async fn lease_renew(
        &self,
        token: &str,
        lease_id: &str,
        increment: Duration,
    ) -> Result<(Duration, bool), SecretsError> {
        let body = Self::body(&LeaseBody { lease_id, increment: Some(increment.as_secs()) })?;
        let r = self
            .call(Method::PUT, "/v1/sys/leases/renew", Some(token), Some(body), Ctx::Read)
            .await?;
        let r: Renewed = Self::json(&r)?;
        if r.lease_id.as_ref().is_some_and(|id| id.expose() != lease_id) {
            return Err(SecretsError::Lease("the server renewed another lease"));
        }
        Ok((Duration::from_secs(r.lease_duration).min(crate::wire_dynamic::MAX_LEASE), r.renewable))
    }

    /// `PUT /v1/sys/leases/revoke { lease_id }`.
    pub async fn lease_revoke(&self, token: &str, lease_id: &str) -> Result<(), SecretsError> {
        let body = Self::body(&LeaseBody { lease_id, increment: None })?;
        self.call(Method::PUT, "/v1/sys/leases/revoke", Some(token), Some(body), Ctx::Read)
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::credential::parse_vault_reference;

    #[test]
    fn paths_and_bodies() {
        let at = parse_vault_reference("team/db/app-ro").expect("ref");
        assert_eq!(engine_path(&at, "creds"), "/v1/team/db/creds/app-ro");
        let body = serde_json::to_string(&SignBody {
            public_key: "ssh-ed25519 AAAA",
            cert_type: "user",
            valid_principals: joined(&["a".into(), "b".into()]),
            ttl: Some("60s".into()),
        })
        .expect("json");
        assert_eq!(
            body,
            r#"{"public_key":"ssh-ed25519 AAAA","cert_type":"user","valid_principals":"a,b","ttl":"60s"}"#
        );
        assert_eq!(joined(&[]), None);
        let b = serde_json::to_string(&LeaseBody { lease_id: "x/1", increment: None }).expect("j");
        assert_eq!(b, r#"{"lease_id":"x/1"}"#);
    }
}
