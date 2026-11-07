//! 1Password Connect and Bitwarden (`bws`) on [`SecretsEngine`] (ADR-0026 §3–§5). Both log
//! in with a stored token opened per resolve (nothing cached, nothing to revoke: the token is
//! the user's), map onto the target kind and run its validators, exactly like KV v2.

use mooring_core::credential::{
    parse_bws_reference, parse_op_reference, BwsReference, ExternalRefFields,
};
use mooring_core::secret_source::SecretSource;
use mooring_http::decode_json;
use zeroize::Zeroizing;

use crate::bws_wire::{by_key, one_secret, resolve_value, BwsProjects};
use crate::engine::{LoginMaterial, LoginProvider, SecretsEngine, SourceTest};
use crate::error::SecretsError;
use crate::op_client::ConnectClient;
use crate::op_wire::item_values;
use crate::resolve::{build, ResolvedSecrets};

fn token_of(
    provider: &dyn LoginProvider,
    source: &SecretSource,
) -> Result<Zeroizing<String>, SecretsError> {
    match provider.login_material(source)? {
        LoginMaterial::Token(t) if !t.is_empty() => Ok(t),
        _ => Err(SecretsError::Invalid("login material does not match the method")),
    }
}

impl SecretsEngine {
    /// `op://` → Connect item → target kind.
    pub(crate) async fn onepassword(
        &self,
        source: &SecretSource,
        f: &ExternalRefFields,
        provider: &dyn LoginProvider,
    ) -> Result<ResolvedSecrets, SecretsError> {
        let r = parse_op_reference(&f.reference).map_err(|_| SecretsError::Invalid("reference"))?;
        let client = ConnectClient::new(source, &self.cfg)?;
        let token = token_of(provider, source)?;
        let item = client.item(&token, &r).await?;
        drop(token);
        let map = item_values(&item, &r, f.target_kind, f.field_map.as_ref())?;
        build(f.target_kind, None, &map, 0)
    }

    /// `bws secret get <uuid>` (or `secret list <project>` + key) → target kind.
    pub(crate) async fn bitwarden(
        &self,
        source: &SecretSource,
        f: &ExternalRefFields,
        provider: &dyn LoginProvider,
    ) -> Result<ResolvedSecrets, SecretsError> {
        let r =
            parse_bws_reference(&f.reference).map_err(|_| SecretsError::Invalid("reference"))?;
        let path = self.bws.config().locate(source.options.bws_path.as_deref())?;
        self.bws.ensure_checked(&path, &source.address).await?;
        let token = token_of(provider, source)?;
        let secret = match &r {
            BwsReference::Id(id) => {
                let args = ["secret", "get", id.as_str(), "--output", "json"];
                let out = self.bws.run(&path, "secret_get", &args, &token, &source.address).await?;
                one_secret(&out.stdout, id)?
            }
            BwsReference::ProjectKey { project, key } => {
                let args = ["secret", "list", project.as_str(), "--output", "json"];
                let out =
                    self.bws.run(&path, "secret_list", &args, &token, &source.address).await?;
                by_key(&out.stdout, key)?
            }
        };
        drop(token);
        resolve_value(&secret.value, f.target_kind, f.field_map.as_ref())
    }

    /// `secret_source_test` of a Connect (`/heartbeat` + `/v1/vaults`) or `bws` source
    /// (`--version` + `project list`): `policies_count` is the number of vaults / projects.
    pub(crate) async fn test_token_source(
        &self,
        source: &SecretSource,
        provider: &dyn LoginProvider,
    ) -> Result<SourceTest, SecretsError> {
        use mooring_core::secret_source::SourceKind;
        let count = match source.kind {
            SourceKind::Onepassword => {
                let client = ConnectClient::new(source, &self.cfg)?;
                client.heartbeat().await?;
                let token = token_of(provider, source)?;
                client.vault_count(&token).await?
            }
            SourceKind::Bitwarden => {
                let path = self.bws.config().locate(source.options.bws_path.as_deref())?;
                self.bws.ensure_checked(&path, &source.address).await?;
                let token = token_of(provider, source)?;
                let args = ["project", "list", "--output", "json"];
                let out =
                    self.bws.run(&path, "project_list", &args, &token, &source.address).await?;
                decode_json::<BwsProjects>(&out.stdout)?.0.len()
            }
            SourceKind::Vault => return Err(SecretsError::Invalid("source kind")),
        };
        Ok(SourceTest {
            method: "token",
            ttl_seconds: None,
            renewable: false,
            policies_count: count,
        })
    }
}
