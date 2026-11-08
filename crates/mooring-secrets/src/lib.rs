//! Mooring external secrets (ADR-0016, ADR-0026): `external_ref` credentials resolved at
//! connect time from `HashiCorp` Vault or `OpenBao` (KV v2 and the dynamic engines
//! `database`, `ssh_sign`, `ssh_otp`, `pki` with leases), a 1Password Connect server or
//! Bitwarden Secrets Manager through the `bws` CLI.
//!
//! * [`VaultClient`] — the seven endpoints over `mooring-http` (`CertProtocol::Vault`, our
//!   verifier and pins, 1 MiB cap, `X-Vault-Token` redacted, `X-Vault-Namespace`).
//! * [`TokenCache`] — tokens in memory only (`Zeroizing`), refresh at < 10 % / < 30 s,
//!   [`TokenCache::revoke_all`] on lock and exit. Root tokens are refused.
//! * [`SecretsEngine`] — source → token → KV read → the target kind's own validators
//!   ([`ResolvedSecrets`]); audit hooks ([`SecretsAudit`]); OIDC flow ([`OidcFlow`]).
//! * [`LeaseRegistry`] — dynamic leases in memory, renewed at 2/3 TTL, revoked on session
//!   close, lock and exit; [`ConnectClient`]; [`BwsRunner`] (fixed path, cleared env).
//!
//! Rules: nothing is written to disk, no secret value is cached between connects, every
//! failure closes (no fallback), and no value appears in an error, a log line or an event.

#![forbid(unsafe_code)]

mod audit;
mod bws;
mod bws_pins;
mod bws_wire;
mod cache;
mod client;
mod client_dynamic;
mod engine;
mod engine_dynamic;
mod engine_providers;
mod error;
pub mod fuzz;
mod leases;
mod oidc;
mod op_client;
mod op_wire;
mod resolve;
mod wire;
mod wire_dynamic;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_kv;

pub use audit::{MemoryAudit, NoAudit, SecretEvent, SecretsAudit};
pub use bws::{expand as expand_bws_path, BwsConfig, BwsRunner, BWS_DEADLINE};
pub use cache::{
    refresh_due, Clock, Drained, FakeClock, Maintenance, Rejected, SystemClock, TokenCache,
    MAX_CACHE, REFRESH_FLOOR, REVOKE_TIMEOUT,
};
pub use client::{pct_encode, ClientConfig, KvSecret, VaultClient, VaultToken, MAX_RESPONSE};
pub use client_dynamic::{IssueRequest, SignRequest};
pub use engine::{LoginMaterial, LoginProvider, RefTest, ResolveCtx, SecretsEngine, SourceTest};
pub use error::{Category, SecretsError};
pub use leases::{renew_due, CertRevoke, Lease, LeaseRegistry, LeaseStatus, Released, LEASE_TICK};
pub use oidc::{parse_callback, Navigation, OidcFlow, OIDC_TIMEOUT};
pub use op_client::{is_op_id, ConnectClient};
pub use resolve::{build, presence, ResolvedSecrets};
pub use wire::{KvMetadata, Policies, SecretMap, SecretValue, MAX_KV_FIELDS, MAX_KV_KEY};
pub use wire_dynamic::LeaseInfo;
