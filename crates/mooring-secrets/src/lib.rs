//! Mooring external secrets (ADR-0016): `external_ref` credentials resolved at connect time
//! from `HashiCorp` Vault or `OpenBao` KV v2.
//!
//! * [`VaultClient`] — the seven endpoints over `mooring-http` (`CertProtocol::Vault`, our
//!   verifier and pins, 1 MiB cap, `X-Vault-Token` redacted, `X-Vault-Namespace`).
//! * [`TokenCache`] — tokens in memory only (`Zeroizing`), refresh at < 10 % / < 30 s,
//!   [`TokenCache::revoke_all`] on lock and exit. Root tokens are refused.
//! * [`SecretsEngine`] — source → token → KV read → the target kind's own validators
//!   ([`ResolvedSecrets`]); audit hooks ([`SecretsAudit`]); OIDC flow ([`OidcFlow`]).
//!
//! Rules: nothing is written to disk, no secret value is cached between connects, every
//! failure closes (no fallback), and no value appears in an error, a log line or an event.

#![forbid(unsafe_code)]

mod audit;
mod cache;
mod client;
mod engine;
mod error;
pub mod fuzz;
mod oidc;
mod resolve;
mod wire;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_kv;

pub use audit::{MemoryAudit, NoAudit, SecretEvent, SecretsAudit};
pub use cache::{
    refresh_due, Clock, Drained, FakeClock, Maintenance, Rejected, SystemClock, TokenCache,
    MAX_CACHE, REFRESH_FLOOR, REVOKE_TIMEOUT,
};
pub use client::{pct_encode, ClientConfig, KvSecret, VaultClient, VaultToken, MAX_RESPONSE};
pub use engine::{LoginMaterial, LoginProvider, RefTest, SecretsEngine, SourceTest};
pub use error::{Category, SecretsError};
pub use oidc::{parse_callback, Navigation, OidcFlow, OIDC_TIMEOUT};
pub use resolve::{build, presence, ResolvedSecrets};
pub use wire::{KvMetadata, Policies, SecretMap, SecretValue, MAX_KV_FIELDS, MAX_KV_KEY};
