//! `RdpConnOptions.gateway` (ADR-0027 §1): the RD Gateway in front of an RDP target. The
//! gateway credential is the connection's `gateway` role credential, or the sign-in
//! credential when that role is empty ("same as sign-in", ADR-0009 §3).

use serde::{Deserialize, Serialize};

use super::{check_ca_pem, invalid};
use crate::credential::is_forbidden;
use crate::error::Result;

/// Longest gateway host name.
pub const MAX_GATEWAY_HOST: usize = 253;

/// When the gateway is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayUsage {
    /// Every connect goes through the gateway (default).
    #[default]
    Always,
    /// Try the target directly for 3 s first; the gateway only when that fails (audited).
    IfUnreachable,
}

const fn https() -> u16 {
    443
}

/// `{ host, port: 443, usage, allowBasicGateway, caPem|null }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RdGatewayOptions {
    /// Gateway DNS name or IP (the TLS name and the `known_rdg_certs` key).
    pub host: String,
    /// HTTPS port (default 443).
    #[serde(default = "https")]
    pub port: u16,
    /// Default `always`.
    #[serde(default)]
    pub usage: GatewayUsage,
    /// Allow HTTP Basic when the gateway refuses NTLM (only ever inside TLS; audited as a
    /// warning). Default `false`.
    #[serde(default)]
    pub allow_basic_gateway: bool,
    /// Extra CA certificates for the gateway (PEM, certificates only, ≤ 64 KiB).
    #[serde(default)]
    pub ca_pem: Option<String>,
}

impl RdGatewayOptions {
    /// Host shape, port and CA rules.
    pub fn validate(&self) -> Result<()> {
        let h = &self.host;
        let ok = !h.is_empty()
            && h.len() <= MAX_GATEWAY_HOST
            && !h.chars().any(|c| c.is_whitespace() || is_forbidden(c) || "/?#@\\".contains(c));
        if !ok {
            return Err(invalid("gateway.host must be a host name or an IP address"));
        }
        if self.port == 0 {
            return Err(invalid("gateway.port must be 1..=65535"));
        }
        check_ca_pem(self.ca_pem.as_ref())
    }

    /// `host:port` (the pin key and the audit / UI label).
    #[must_use]
    pub fn label(&self) -> String {
        crate::known_certs::host_key(&self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_validation() {
        let g: RdGatewayOptions =
            serde_json::from_value(serde_json::json!({ "host": "gw01.example.test" })).expect("ok");
        assert_eq!((g.port, g.usage, g.allow_basic_gateway), (443, GatewayUsage::Always, false));
        assert!(g.validate().is_ok());
        assert_eq!(g.label(), "gw01.example.test:443");
        for bad in ["", "gw01 .example.test", "https://gw", "user@gw", "gw/x"] {
            let g = RdGatewayOptions { host: bad.into(), ..g.clone() };
            assert!(g.validate().is_err(), "{bad:?}");
        }
        assert!(RdGatewayOptions { port: 0, ..g.clone() }.validate().is_err());
        let unknown = serde_json::json!({ "host": "gw", "rpcFallback": true });
        assert!(serde_json::from_value::<RdGatewayOptions>(unknown).is_err());
        let usage = serde_json::json!({ "host": "gw", "usage": "if_unreachable", "port": 8443 });
        let g: RdGatewayOptions = serde_json::from_value(usage).expect("ok");
        assert_eq!((g.usage, g.port), (GatewayUsage::IfUnreachable, 8443));
    }
}
