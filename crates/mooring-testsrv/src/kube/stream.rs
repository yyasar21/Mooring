//! Streamed kube responses: pod watches and `pods/log`.

use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_TYPE};
use http::{Response, StatusCode};

use super::fixtures::status;
use super::routes::rbac;
use super::{KubeConfig, KubeState, PodFixture};
use crate::http::{json, Body, Ctx, Reply};

fn streamed(body: Body, content_type: &'static str) -> Reply {
    let mut r = Response::new(body);
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    r.into()
}

fn bad(msg: &str) -> Reply {
    json(StatusCode::BAD_REQUEST, &status(400, "BadRequest", msg)).into()
}

impl KubeState {
    /// `watch=1`: one `ADDED` per current pod, then events pushed by the test, until
    /// `timeoutSeconds` (default 300) passes.
    pub(super) fn watch(&self, ctx: &Ctx, ns: &str, pods: Vec<PodFixture>) -> Reply {
        let timeout =
            ctx.query_get("timeoutSeconds").and_then(|t| t.parse::<u64>().ok()).unwrap_or(300);
        let mut events = self.events.subscribe();
        let (tx, body) = Body::channel(64);
        let ns = ns.to_owned();
        tokio::spawn(async move {
            for p in pods {
                let line = serde_json::json!({ "type": "ADDED", "object": p.to_json() });
                if tx.send(Bytes::from(format!("{line}\n"))).await.is_err() {
                    return;
                }
            }
            let deadline = tokio::time::sleep(Duration::from_secs(timeout));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    () = &mut deadline => return,
                    ev = events.recv() => {
                        let Ok(ev) = ev else { return };
                        let Some((ev_ns, line)) = ev.split_once('\t') else { continue };
                        if ev_ns == ns && tx.send(Bytes::from(line.to_owned())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        streamed(body, "application/json")
    }

    /// `pods/log` with `container`, `tailLines`, `limitBytes`, `timestamps`, `follow`.
    pub(super) fn log(ctx: &Ctx, cfg: &KubeConfig, user: &str, ns: &str, pod: &str) -> Reply {
        if let Some(r) = rbac(cfg, user, "get", "pods/log", Some(ns)) {
            return r;
        }
        let Some(p) = cfg.pods.iter().find(|p| p.namespace == ns && p.name == pod) else {
            let msg = format!("pods \"{pod}\" not found");
            return json(StatusCode::NOT_FOUND, &status(404, "NotFound", &msg)).into();
        };
        let names: Vec<&str> = p.containers.iter().map(|c| c.name.as_str()).collect();
        let container = match (ctx.query_get("container"), p.containers.as_slice()) {
            (Some(c), _) => c,
            (None, [only]) => only.name.clone(),
            (None, _) => {
                let list = names.join(" ");
                return bad(&format!(
                    "a container name must be specified for pod {pod}, choose one of: [{list}]"
                ));
            }
        };
        let Some(c) = p.containers.iter().find(|c| c.name == container) else {
            return bad(&format!("container {container} is not valid for pod {pod}"));
        };
        if let Some(n) = cfg.knobs.huge_log {
            return streamed(huge(n), "text/plain");
        }
        let follow = ctx.query_get("follow").is_some_and(|f| f == "true" || f == "1");
        let timestamps = ctx.query_get("timestamps").is_some_and(|f| f == "true" || f == "1");
        let num = |k: &str| ctx.query_get(k).and_then(|v| v.parse::<usize>().ok());
        let stamp = move |i: usize, l: &str| {
            if timestamps {
                format!("2026-11-04T00:{:02}:{:02}.000000000Z {l}\n", (i / 60) % 60, i % 60)
            } else {
                format!("{l}\n")
            }
        };
        let lines: Vec<String> = c.log.clone().unwrap_or_else(|| {
            (0..cfg.knobs.log_lines).map(|i| format!("line {i} of {pod}/{container}")).collect()
        });
        let skip = num("tailLines").map_or(0, |t| lines.len().saturating_sub(t));
        let backlog: String =
            lines.iter().enumerate().skip(skip).map(|(i, l)| stamp(i, l)).collect();
        let mut budget = num("limitBytes").unwrap_or(usize::MAX);
        let take = |s: String, budget: &mut usize| -> Bytes {
            let mut b = s.into_bytes();
            b.truncate(*budget);
            *budget -= b.len();
            Bytes::from(b)
        };
        if !follow {
            return streamed(Body::full(take(backlog, &mut budget)), "text/plain");
        }
        let (extra, gap, base) = (cfg.knobs.follow_lines, cfg.knobs.follow_interval, lines.len());
        let (tx, body) = Body::channel(16);
        let label = format!("{pod}/{container}");
        tokio::spawn(async move {
            let first = take(backlog, &mut budget);
            if !first.is_empty() && tx.send(first).await.is_err() {
                return;
            }
            for i in 0..extra {
                if budget == 0 {
                    return;
                }
                tokio::time::sleep(gap).await;
                let line = stamp(base + i, &format!("follow {i} of {label}"));
                if tx.send(take(line, &mut budget)).await.is_err() {
                    return;
                }
            }
        });
        streamed(body, "text/plain")
    }
}

/// `n` bytes of log in 64 KiB chunks (the huge-log knob).
fn huge(n: usize) -> Body {
    let (tx, body) = Body::channel(4);
    tokio::spawn(async move {
        let chunk = Bytes::from([b"A".repeat(1023), b"\n".to_vec()].concat().repeat(64));
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len());
            if tx.send(chunk.slice(..k)).await.is_err() {
                return;
            }
            left -= k;
        }
    });
    body
}
