//! The Vault dynamic engines on [`SecretsEngine`] (ADR-0026 §1–§2): issue, check the lease,
//! build the target credential through its own validators, then register the lease for its
//! owner (or revoke it at once). A credential whose lease cannot be kept is never used, and a
//! lease whose credential is refused is revoked before the error returns.

use std::time::{SystemTime, UNIX_EPOCH};

use mooring_core::credential::{
    check_signed_certificate, parse_vault_reference, ExternalRefFields, SignedCertificate,
    VaultEngine, VaultPath,
};
use mooring_core::secret_source::SecretSource;
use mooring_core::CredentialId;
use zeroize::Zeroizing;

use crate::audit::SecretEvent;
use crate::client::VaultClient;
use crate::client_dynamic::{IssueRequest, SignRequest};
use crate::engine::{check_source, LoginProvider, ResolveCtx, SecretsEngine};
use crate::error::{Category, SecretsError};
use crate::leases::{retire_one, CertRevoke, Lease};
use crate::resolve::{build, shape, ResolvedSecrets};
use crate::wire::{SecretMap, SecretValue};
use crate::wire_dynamic::{serial_ok, LeaseInfo, MAX_PKI_PEM};

/// What one issue returned: the lease, the names for the target kind, a PKI serial.
struct Issued {
    lease: LeaseInfo,
    map: SecretMap,
    serial: Option<String>,
}

fn sv(s: String) -> SecretValue {
    SecretValue(Zeroizing::new(s))
}

fn locked() -> SecretsError {
    SecretsError::unavailable(Category::Locked, "the Mooring vault locked during the resolve")
}

impl SecretsEngine {
    async fn issue(
        client: &VaultClient,
        token: &str,
        at: &VaultPath,
        f: &ExternalRefFields,
        ctx: &ResolveCtx<'_>,
    ) -> Result<Issued, SecretsError> {
        match f.engine {
            VaultEngine::Database => {
                let (lease, d) = client.db_creds(token, at).await?;
                if lease.id.is_none() {
                    return Err(SecretsError::Lease(
                        "database credentials came without a lease id",
                    ));
                }
                let map = SecretMap::from_values(vec![
                    ("username".to_owned(), d.username),
                    ("password".to_owned(), d.password),
                ]);
                Ok(Issued { lease, map, serial: None })
            }
            VaultEngine::SshOtp => {
                let ip =
                    ctx.ip.ok_or(SecretsError::Engine("ssh_otp needs the target's IP address"))?;
                let user = f.username.as_deref().ok_or(SecretsError::Invalid("username"))?;
                let (mut lease, d) = client.ssh_otp(token, at, ip, user).await?;
                if !d.key_type.is_empty() && d.key_type != "otp" {
                    return Err(SecretsError::shape("ssh role is not an OTP role"));
                }
                if !d.username.is_empty() && d.username != user {
                    return Err(SecretsError::shape("OTP issued for another user"));
                }
                // The first use consumes the OTP lease (ADR-0026 §1): nothing to keep.
                lease.id = None;
                let map = SecretMap::from_values(vec![
                    ("username".to_owned(), sv(user.to_owned())),
                    ("password".to_owned(), d.key),
                ]);
                Ok(Issued { lease, map, serial: None })
            }
            VaultEngine::Pki => {
                let req = IssueRequest {
                    common_name: f
                        .common_name
                        .as_deref()
                        .ok_or(SecretsError::Invalid("common_name"))?,
                    alt_names: f.alt_names.as_deref().unwrap_or_default(),
                    ttl: f.ttl,
                };
                let (lease, d) = client.pki_issue(token, at, &req).await?;
                if d.certificate.len() > MAX_PKI_PEM || d.private_key.expose().len() > MAX_PKI_PEM {
                    return Err(SecretsError::shape("PKI response too large"));
                }
                let serial = (!d.serial_number.is_empty()).then_some(d.serial_number);
                if serial.as_deref().is_some_and(|s| !serial_ok(s)) {
                    return Err(SecretsError::shape("PKI serial is malformed"));
                }
                let mut cert = d.certificate;
                for c in d.ca_chain {
                    cert.push('\n');
                    cert.push_str(c.trim_end());
                }
                cert.push('\n');
                let map = SecretMap::from_values(vec![
                    ("cert_pem".to_owned(), sv(cert)),
                    ("key_pem".to_owned(), d.private_key),
                ]);
                Ok(Issued { lease, map, serial })
            }
            VaultEngine::Kv2 | VaultEngine::SshSign => {
                Err(SecretsError::Engine("not a dynamic engine"))
            }
        }
    }

    /// A dynamic engine for one connect.
    pub(crate) async fn dynamic(
        &self,
        source: &SecretSource,
        f: &ExternalRefFields,
        provider: &dyn LoginProvider,
        ctx: &ResolveCtx<'_>,
    ) -> Result<ResolvedSecrets, SecretsError> {
        let at =
            parse_vault_reference(&f.reference).map_err(|_| SecretsError::Invalid("reference"))?;
        let epoch = self.leases.epoch();
        let (client, token, cached) = self.token(source, provider).await?;
        let first = Self::issue(&client, &token, &at, f, ctx).await;
        let (client, token, issued) = match first {
            Err(e) if cached && e.token_refused() => {
                drop(token);
                self.cache.forget(source.id).await;
                let (client, token, _) = self.token(source, provider).await?;
                let issued = Self::issue(&client, &token, &at, f, ctx).await?;
                (client, token, issued)
            }
            other => (client, token, other?),
        };
        let Issued { lease, map, serial } = issued;
        let cert = match (ctx.revoke_cert, serial) {
            (true, Some(serial)) => Some(CertRevoke { mount: at.mount_role().0, serial }),
            _ => None,
        };
        let lease = (lease.id.is_some() || cert.is_some()).then(|| Lease {
            id: lease.id.map(SecretValue::into_inner),
            source: source.id,
            owner: ctx.owner.map(str::to_owned),
            engine: f.engine,
            client: client.clone(),
            token: token.clone(),
            issued: self.leases.now(),
            ttl: lease.ttl,
            renewable: lease.renewable,
            failed: false,
            cert,
        });
        let built = build(f.target_kind, None, &map, 0);
        let Some(lease) = lease else { return built };
        self.audit.record(SecretEvent::LeaseIssued {
            owner: lease.owner.clone(),
            source: source.id,
            engine: f.engine,
            ttl: lease.ttl.as_secs(),
            renewable: lease.renewable,
        });
        match (&built, ctx.owner) {
            (Ok(_), Some(_)) => {
                if let Err(refused) = self.leases.register(lease, epoch) {
                    retire_one(refused, "locked", self.audit.as_ref()).await;
                    return Err(locked());
                }
            }
            (Ok(_), None) => retire_one(lease, "test", self.audit.as_ref()).await,
            (Err(_), _) => retire_one(lease, "refused", self.audit.as_ref()).await,
        }
        built
    }

    /// `ssh_sign` (role `certificate`): Vault signs `public_key_line` (never the private key);
    /// the certificate must certify exactly that key, be a user certificate and be valid now.
    pub async fn sign_ssh_key(
        &self,
        source: &SecretSource,
        credential: CredentialId,
        f: &ExternalRefFields,
        provider: &dyn LoginProvider,
        public_key_line: &str,
    ) -> Result<SignedCertificate, SecretsError> {
        let r = async {
            check_source(source, f)?;
            if f.engine != VaultEngine::SshSign {
                return Err(SecretsError::Engine(
                    "the certificate role needs an ssh_sign reference",
                ));
            }
            let at = parse_vault_reference(&f.reference)
                .map_err(|_| SecretsError::Invalid("reference"))?;
            let req = SignRequest {
                public_key: public_key_line,
                principals: f.principals.as_deref().unwrap_or_default(),
                ttl: f.ttl,
            };
            let (client, token, cached) = self.token(source, provider).await?;
            let signed = match client.ssh_sign(&token, &at, &req).await {
                Err(e) if cached && e.token_refused() => {
                    drop(token);
                    self.cache.forget(source.id).await;
                    let (client, token, _) = self.token(source, provider).await?;
                    client.ssh_sign(&token, &at, &req).await?
                }
                other => other?,
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            check_signed_certificate(&signed.1.signed_key, public_key_line, now)
                .map_err(|e| shape(&e))
        };
        match r.await {
            Ok(c) => {
                self.audit.record(SecretEvent::Resolved {
                    credential,
                    source: source.id,
                    reference: f.reference.clone(),
                    version: 0,
                    target_kind: f.target_kind,
                    fields: vec!["certificate"],
                    provider: f.provider.name(),
                    engine: f.engine,
                });
                Ok(c)
            }
            Err(e) => self.failed(source.id, e),
        }
    }
}
