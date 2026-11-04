//! Fixture model of the kube mock: namespaces, pods, containers, RBAC rules, and their
//! Kubernetes JSON shapes (`core/v1` Pod, Namespace, `meta/v1` Status).

use serde_json::{json, Value};

/// A container of a fixture pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFixture {
    pub name: String,
    pub image: String,
    pub ports: Vec<u16>,
    pub ready: bool,
    pub restarts: u32,
    /// Log lines served by `pods/log`; `None` = synthetic `line N of <pod>/<container>`.
    pub log: Option<Vec<String>>,
}

impl ContainerFixture {
    pub fn new(name: &str, image: &str, ports: &[u16]) -> Self {
        Self {
            name: name.to_owned(),
            image: image.to_owned(),
            ports: ports.to_vec(),
            ready: true,
            restarts: 0,
            log: None,
        }
    }
}

/// A pod in a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodFixture {
    pub namespace: String,
    pub name: String,
    pub phase: String,
    pub node: Option<String>,
    pub labels: Vec<(String, String)>,
    pub containers: Vec<ContainerFixture>,
}

impl PodFixture {
    pub fn new(namespace: &str, name: &str, containers: Vec<ContainerFixture>) -> Self {
        Self {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            phase: "Running".to_owned(),
            node: Some("node-1.example.test".to_owned()),
            labels: vec![("app".to_owned(), name.split('-').next().unwrap_or(name).to_owned())],
            containers,
        }
    }

    pub fn to_json(&self) -> Value {
        let labels: serde_json::Map<String, Value> =
            self.labels.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
        let containers: Vec<Value> = self
            .containers
            .iter()
            .map(|c| {
                let ports: Vec<Value> = c
                    .ports
                    .iter()
                    .map(|p| json!({ "containerPort": p, "protocol": "TCP" }))
                    .collect();
                json!({ "name": c.name, "image": c.image, "ports": ports })
            })
            .collect();
        let statuses: Vec<Value> = self
            .containers
            .iter()
            .map(|c| {
                json!({ "name": c.name, "image": c.image, "ready": c.ready,
                        "restartCount": c.restarts, "state": { "running": {} } })
            })
            .collect();
        json!({
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "uid": format!("00000000-0000-4000-8000-{:012x}", fnv(&self.namespace, &self.name)),
                "resourceVersion": "1",
                "creationTimestamp": "2026-11-01T00:00:00Z",
                "labels": labels,
            },
            "spec": { "nodeName": self.node, "containers": containers },
            "status": { "phase": self.phase, "containerStatuses": statuses },
        })
    }

    /// `labelSelector` with equality terms only (`a=b,c==d,e!=f`); anything else matches none.
    pub fn matches_selector(&self, selector: &str) -> bool {
        selector.split(',').filter(|t| !t.is_empty()).all(|term| {
            let get = |k: &str| self.labels.iter().find(|(lk, _)| lk == k).map(|(_, v)| v.as_str());
            if let Some((k, v)) = term.split_once("!=") {
                get(k.trim()) != Some(v.trim())
            } else if let Some((k, v)) = term.split_once("==").or_else(|| term.split_once('=')) {
                get(k.trim()) == Some(v.trim())
            } else {
                false
            }
        })
    }
}

fn fnv(a: &str, b: &str) -> u64 {
    a.bytes().chain(*b"/").chain(b.bytes()).fold(0xcbf2_9ce4_8422_2325, |h, c| {
        (h ^ u64::from(c)).wrapping_mul(0x0100_0000_01b3) & 0xffff_ffff_ffff
    })
}

/// One RBAC rule the mock evaluates for every request and for the review APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRule {
    /// `get`, `list`, `watch`, `create`, or `*`.
    pub verbs: Vec<String>,
    /// `namespaces`, `pods`, `pods/log`, `pods/exec`, `pods/portforward`, or `*`.
    pub resources: Vec<String>,
    /// `None` = every namespace (and cluster-scoped resources).
    pub namespaces: Option<Vec<String>>,
}

impl AccessRule {
    pub fn new(verbs: &[&str], resources: &[&str]) -> Self {
        Self {
            verbs: verbs.iter().map(|s| (*s).to_owned()).collect(),
            resources: resources.iter().map(|s| (*s).to_owned()).collect(),
            namespaces: None,
        }
    }

    #[must_use]
    pub fn in_namespaces(mut self, ns: &[&str]) -> Self {
        self.namespaces = Some(ns.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    pub fn allows(&self, verb: &str, resource: &str, namespace: Option<&str>) -> bool {
        let any = |list: &[String], v: &str| list.iter().any(|x| x == "*" || x == v);
        let ns_ok = match (&self.namespaces, namespace) {
            (None, _) => true,
            (Some(list), Some(ns)) => list.iter().any(|x| x == ns),
            (Some(_), None) => false,
        };
        ns_ok && any(&self.verbs, verb) && any(&self.resources, resource)
    }

    /// The rule as a `SelfSubjectRulesReview` `resourceRules[]` entry.
    pub fn to_json(&self) -> Value {
        let (groups, resources): (Vec<&str>, Vec<&str>) =
            (vec![""], self.resources.iter().map(String::as_str).collect());
        json!({ "verbs": self.verbs, "apiGroups": groups, "resources": resources })
    }
}

/// The default rules: read namespaces / pods / logs, exec and port-forward everywhere.
pub fn default_rules() -> Vec<AccessRule> {
    vec![
        AccessRule::new(&["get", "list", "watch"], &["namespaces", "pods", "pods/log"]),
        AccessRule::new(&["create", "get"], &["pods/exec", "pods/portforward"]),
    ]
}

/// The default fixture set: three namespaces, three pods (one with two containers).
pub fn default_pods() -> Vec<PodFixture> {
    vec![
        PodFixture::new(
            "default",
            "web-0",
            vec![
                ContainerFixture::new("app", "registry.example.test/web:1.0", &[8080]),
                ContainerFixture::new("sidecar", "registry.example.test/proxy:2.1", &[9090]),
            ],
        ),
        PodFixture::new(
            "default",
            "db-0",
            vec![ContainerFixture::new("postgres", "registry.example.test/pg:16", &[5432])],
        ),
        PodFixture::new(
            "team-a",
            "worker-1",
            vec![ContainerFixture::new("worker", "registry.example.test/worker:3", &[])],
        ),
    ]
}

/// `n` synthetic single-container pods `pod-00000 …` in `namespace` (pagination / cap tests).
pub fn many_pods(namespace: &str, n: usize) -> Vec<PodFixture> {
    (0..n)
        .map(|i| {
            PodFixture::new(
                namespace,
                &format!("pod-{i:05}"),
                vec![ContainerFixture::new("c", "registry.example.test/busybox:1", &[80])],
            )
        })
        .collect()
}

/// A `meta/v1` Status error body.
pub fn status(code: u16, reason: &str, message: &str) -> Value {
    json!({ "kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
            "message": message, "reason": reason, "code": code })
}

pub fn namespace_json(name: &str) -> Value {
    json!({ "kind": "Namespace", "apiVersion": "v1",
            "metadata": { "name": name, "resourceVersion": "1",
                          "creationTimestamp": "2026-11-01T00:00:00Z" },
            "status": { "phase": "Active" } })
}
