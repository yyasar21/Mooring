//! Browsing (ADR-0014 §5/§6): namespaces, pods, one pod, as trimmed DTOs. Lists page with
//! `limit=500` + `continue`, at most 10 pages; bodies are capped at 16 MiB each. Only the
//! fields below are deserialised (no env values, no annotations); every string that reaches
//! the UI is sanitised (no controls, no bidi overrides) and length-capped.

use mooring_core::credential::kubeconfig::{is_dns_label, is_dns_subdomain};
use serde::{Deserialize, Serialize};

use crate::client::KubeClient;
use crate::error::KubeError;
use crate::guard::MAX_LIST_LIMIT;
use crate::query::{encode, MAX_CONTINUE, MAX_SELECTOR};

/// Most list pages fetched per call.
pub const MAX_PAGES: usize = 10;
/// Containers kept per pod (init containers are not listed).
pub const MAX_CONTAINERS: usize = 64;
/// Ports kept per container.
pub const MAX_PORTS: usize = 32;

/// Strip C0/C1 controls, DEL and bidi controls, clip to `max` characters.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control() && !is_bidi(*c)).take(max).collect()
}

pub(crate) fn is_bidi(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// A list result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listing<T> {
    /// Items in server order.
    pub items: Vec<T>,
    /// More items exist than were fetched (page cap, or a malformed continue token).
    pub truncated: bool,
}

/// One container of a pod.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerSummary {
    /// Name.
    pub name: String,
    /// Image reference.
    pub image: String,
    /// `ready` from the status.
    pub ready: bool,
    /// `restartCount`.
    pub restarts: u32,
    /// Declared container ports.
    pub ports: Vec<u16>,
}

/// `PodSummary` (ADR-0014 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSummary {
    /// Name.
    pub name: String,
    /// `Pending` / `Running` / `Succeeded` / `Failed` / `Unknown` (as sent, sanitised).
    pub phase: String,
    /// Node name.
    pub node: Option<String>,
    /// `creationTimestamp` (RFC 3339).
    pub created_at: Option<String>,
    /// Seconds since `creationTimestamp`, when it parses.
    pub age_seconds: Option<u64>,
    /// Sum of container restarts.
    pub restarts: u32,
    /// Containers.
    pub containers: Vec<ContainerSummary>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListMeta {
    #[serde(rename = "continue")]
    cont: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct List<T> {
    metadata: ListMeta,
    items: Vec<T>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Meta {
    name: String,
    creation_timestamp: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Named {
    metadata: Meta,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PortIn {
    container_port: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContainerIn {
    name: String,
    image: String,
    ports: Vec<PortIn>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SpecIn {
    node_name: Option<String>,
    containers: Vec<ContainerIn>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct StatusIn {
    name: String,
    ready: bool,
    restart_count: i64,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PodStatusIn {
    phase: Option<String>,
    container_statuses: Vec<StatusIn>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct PodIn {
    metadata: Meta,
    spec: SpecIn,
    status: PodStatusIn,
}

fn age(created: Option<&str>) -> Option<u64> {
    let t = time::OffsetDateTime::parse(created?, &time::format_description::well_known::Rfc3339)
        .ok()?;
    u64::try_from((time::OffsetDateTime::now_utc() - t).whole_seconds()).ok()
}

fn clamp_u32(n: i64) -> u32 {
    u32::try_from(n.max(0)).unwrap_or(u32::MAX)
}

impl PodIn {
    pub(crate) fn summary(self) -> PodSummary {
        let statuses = self.status.container_statuses;
        let containers: Vec<ContainerSummary> = self
            .spec
            .containers
            .into_iter()
            .take(MAX_CONTAINERS)
            .map(|c| {
                let st = statuses.iter().find(|s| s.name == c.name);
                ContainerSummary {
                    name: clean(&c.name, 63),
                    image: clean(&c.image, 512),
                    ready: st.is_some_and(|s| s.ready),
                    restarts: st.map_or(0, |s| clamp_u32(s.restart_count)),
                    ports: c
                        .ports
                        .iter()
                        .filter_map(|p| u16::try_from(p.container_port).ok())
                        .filter(|p| *p != 0)
                        .take(MAX_PORTS)
                        .collect(),
                }
            })
            .collect();
        let created = self.metadata.creation_timestamp.as_deref().map(|t| clean(t, 40));
        PodSummary {
            name: clean(&self.metadata.name, 253),
            phase: clean(self.status.phase.as_deref().unwrap_or("Unknown"), 32),
            node: self.spec.node_name.as_deref().map(|n| clean(n, 253)),
            age_seconds: age(created.as_deref()),
            created_at: created,
            restarts: containers.iter().fold(0u32, |a, c| a.saturating_add(c.restarts)),
            containers,
        }
    }
}

fn valid_continue(t: &str) -> bool {
    (1..=MAX_CONTINUE).contains(&t.len())
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_=+/.".contains(&b))
}

impl KubeClient {
    async fn paged<T: serde::de::DeserializeOwned + Default>(
        &self,
        base: &str,
        extra: &str,
    ) -> Result<Listing<T>, KubeError> {
        let mut items = Vec::new();
        let mut cont: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut path = format!("{base}?limit={MAX_LIST_LIMIT}{extra}");
            if let Some(c) = &cont {
                path.push_str("&continue=");
                path.push_str(&encode(c));
            }
            let page: List<T> = self.get_json(&path).await?;
            items.extend(page.items);
            match page.metadata.cont.filter(|c| !c.is_empty()) {
                None => return Ok(Listing { items, truncated: false }),
                Some(c) if valid_continue(&c) => cont = Some(c),
                Some(_) => return Ok(Listing { items, truncated: true }),
            }
        }
        Ok(Listing { items, truncated: true })
    }

    /// Namespace names (`list namespaces`).
    pub async fn namespaces(&self) -> Result<Listing<String>, KubeError> {
        let l: Listing<Named> = self.paged("/api/v1/namespaces", "").await?;
        Ok(Listing {
            items: l
                .items
                .into_iter()
                .map(|n| n.metadata.name)
                .filter(|n| is_dns_label(n))
                .collect(),
            truncated: l.truncated,
        })
    }

    /// Pods of `namespace`, optionally filtered by a label selector.
    pub async fn pods(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> Result<Listing<PodSummary>, KubeError> {
        check_ns(namespace)?;
        let extra = match label_selector {
            None => String::new(),
            Some(s)
                if (1..=MAX_SELECTOR).contains(&s.len())
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_./=!,() ".contains(&b)) =>
            {
                format!("&labelSelector={}", encode(s))
            }
            Some(_) => return Err(KubeError::Invalid("labelSelector")),
        };
        let l: Listing<PodIn> =
            self.paged(&format!("/api/v1/namespaces/{namespace}/pods"), &extra).await?;
        Ok(Listing {
            items: l.items.into_iter().map(PodIn::summary).collect(),
            truncated: l.truncated,
        })
    }

    /// One pod.
    pub async fn pod(&self, namespace: &str, name: &str) -> Result<PodSummary, KubeError> {
        check_ns(namespace)?;
        check_pod(name)?;
        let p: PodIn =
            self.get_json(&format!("/api/v1/namespaces/{namespace}/pods/{name}")).await?;
        Ok(p.summary())
    }
}

pub(crate) fn check_ns(ns: &str) -> Result<(), KubeError> {
    if is_dns_label(ns) {
        Ok(())
    } else {
        Err(KubeError::Invalid("namespace must be an RFC 1123 label"))
    }
}

pub(crate) fn check_pod(pod: &str) -> Result<(), KubeError> {
    if is_dns_subdomain(pod) {
        Ok(())
    } else {
        Err(KubeError::Invalid("pod name must be an RFC 1123 subdomain"))
    }
}

pub(crate) fn check_container(c: Option<&str>) -> Result<(), KubeError> {
    if c.is_none_or(is_dns_label) {
        Ok(())
    } else {
        Err(KubeError::Invalid("container name must be an RFC 1123 label"))
    }
}
