//! RBAC pre-flight (ADR-0014 §5): `SelfSubjectReview` for "who am I" and one
//! `SelfSubjectAccessReview` per (verb, resource) the UI needs, plus a trimmed
//! `SelfSubjectRulesReview` for display. The UI greys out what the identity cannot do; the
//! guard and the server's RBAC still decide.

use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use mooring_core::credential::kubeconfig::is_dns_label;
use serde::Serialize;

use crate::browse::clean;
use crate::client::KubeClient;
use crate::error::KubeError;
use crate::guard::Route;

/// Rules kept from a `SelfSubjectRulesReview`.
pub const MAX_RULES: usize = 256;
/// Groups kept from a `SelfSubjectReview`.
pub const MAX_GROUPS: usize = 64;
/// Entries kept per rule list (verbs, resources, groups).
const MAX_RULE_ITEMS: usize = 32;

/// The authenticated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// User name (sanitised, ≤ 256 chars).
    pub user: String,
    /// Groups (sanitised, ≤ 64).
    pub groups: Vec<String>,
}

/// One trimmed resource rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSummary {
    /// Verbs (`get`, `list`, `*`, …).
    pub verbs: Vec<String>,
    /// API groups (`""` = core).
    pub api_groups: Vec<String>,
    /// Resources (`pods`, `pods/log`, …).
    pub resources: Vec<String>,
}

/// What the identity may do in one namespace (IPC `kube_access`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // the IPC shape is five flags (ADR-0014 §6)
pub struct RbacSummary {
    /// `list pods`.
    pub can_list_pods: bool,
    /// `get pods/log`.
    pub can_get_logs: bool,
    /// `create pods/exec`.
    pub can_exec: bool,
    /// `create pods/portforward`.
    pub can_port_forward: bool,
    /// `list namespaces` (cluster scope).
    pub can_list_namespaces: bool,
    /// `SelfSubjectReview`, when allowed.
    pub identity: Option<Identity>,
    /// Trimmed `SelfSubjectRulesReview` rules (empty when the review was denied).
    pub rules: Vec<RuleSummary>,
    /// The server said the rule list is incomplete, or we trimmed it.
    pub rules_incomplete: bool,
}

/// The five access checks: (verb, resource, subresource, namespaced).
const CHECKS: [(&str, &str, Option<&str>, bool); 5] = [
    ("list", "pods", None, true),
    ("get", "pods", Some("log"), true),
    ("create", "pods", Some("exec"), true),
    ("create", "pods", Some("portforward"), true),
    ("list", "namespaces", None, false),
];

fn items(v: Option<Vec<String>>, trimmed: &mut bool) -> Vec<String> {
    let v = v.unwrap_or_default();
    *trimmed |= v.len() > MAX_RULE_ITEMS;
    v.iter().take(MAX_RULE_ITEMS).map(|s| clean(s, 128)).collect()
}

impl KubeClient {
    /// `SelfSubjectReview`.
    pub async fn whoami(&self) -> Result<Identity, KubeError> {
        let review = SelfSubjectReview::default();
        let r: SelfSubjectReview = self.post_json(Route::SelfReview.template(), &review).await?;
        let info = r.status.and_then(|s| s.user_info).unwrap_or_default();
        let groups = info.groups.unwrap_or_default();
        Ok(Identity {
            user: clean(info.username.as_deref().unwrap_or(""), 256),
            groups: groups.iter().take(MAX_GROUPS).map(|g| clean(g, 256)).collect(),
        })
    }

    /// One `SelfSubjectAccessReview`.
    pub async fn can(
        &self,
        verb: &str,
        resource: &str,
        subresource: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<bool, KubeError> {
        let review = SelfSubjectAccessReview {
            spec: SelfSubjectAccessReviewSpec {
                resource_attributes: Some(ResourceAttributes {
                    namespace: namespace.map(str::to_owned),
                    verb: Some(verb.to_owned()),
                    resource: Some(resource.to_owned()),
                    subresource: subresource.map(str::to_owned),
                    ..ResourceAttributes::default()
                }),
                ..SelfSubjectAccessReviewSpec::default()
            },
            ..SelfSubjectAccessReview::default()
        };
        let r: SelfSubjectAccessReview =
            self.post_json(Route::AccessReview.template(), &review).await?;
        Ok(r.status.is_some_and(|s| s.allowed && s.denied != Some(true)))
    }

    /// Trimmed `SelfSubjectRulesReview` for `namespace`: (rules, incomplete).
    pub async fn rules(&self, namespace: &str) -> Result<(Vec<RuleSummary>, bool), KubeError> {
        let review = SelfSubjectRulesReview {
            spec: SelfSubjectRulesReviewSpec { namespace: Some(namespace.to_owned()) },
            ..SelfSubjectRulesReview::default()
        };
        let r: SelfSubjectRulesReview =
            self.post_json(Route::RulesReview.template(), &review).await?;
        let status = r.status.unwrap_or_default();
        let mut incomplete = status.incomplete || status.resource_rules.len() > MAX_RULES;
        let rules = status
            .resource_rules
            .into_iter()
            .take(MAX_RULES)
            .map(|rule| RuleSummary {
                verbs: items(Some(rule.verbs), &mut incomplete),
                api_groups: items(rule.api_groups, &mut incomplete),
                resources: items(rule.resources, &mut incomplete),
            })
            .collect();
        Ok((rules, incomplete))
    }

    /// The pre-flight for `namespace`. A denied review counts as "not allowed"; transport and
    /// trust errors are returned.
    pub async fn preflight(&self, namespace: &str) -> Result<RbacSummary, KubeError> {
        if !is_dns_label(namespace) {
            return Err(KubeError::Invalid("namespace must be an RFC 1123 label"));
        }
        let mut allowed = [false; 5];
        for (slot, (verb, res, sub, namespaced)) in allowed.iter_mut().zip(CHECKS) {
            let ns = namespaced.then_some(namespace);
            *slot = soft(self.can(verb, res, sub, ns).await)?.unwrap_or(false);
        }
        let identity = soft(self.whoami().await)?;
        let (rules, rules_incomplete) =
            soft(self.rules(namespace).await)?.unwrap_or((Vec::new(), true));
        Ok(RbacSummary {
            can_list_pods: allowed[0],
            can_get_logs: allowed[1],
            can_exec: allowed[2],
            can_port_forward: allowed[3],
            can_list_namespaces: allowed[4],
            identity,
            rules,
            rules_incomplete,
        })
    }
}

/// RBAC / not-found / old-server refusals become `None`; everything else stays an error.
fn soft<T>(r: Result<T, KubeError>) -> Result<Option<T>, KubeError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(KubeError::RbacDenied | KubeError::NotFound | KubeError::Status(_)) => Ok(None),
        Err(e) => Err(e),
    }
}
