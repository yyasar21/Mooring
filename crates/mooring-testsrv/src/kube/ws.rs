//! `pods/exec` and `pods/portforward` over WebSocket.
//!
//! **Exec** speaks the Kubernetes channel protocol: every binary message starts with a channel
//! byte — 0 stdin, 1 stdout, 2 stderr, 3 status (`meta/v1` Status JSON, then close), 4 resize
//! (`{"Width":w,"Height":h}`); `v5.channel.k8s.io` adds 255 = close (`[255, 0]` closes stdin).
//! The backend is an echo shell: stdin is echoed to stdout; a line `exit [N]` ends with status N,
//! `stty size` prints `<rows> <cols>` from the last resize, `stderr <text>` writes to channel 2.
//!
//! **Port-forward** is the native WebSocket variant (subprotocol `v4.channel.k8s.io` or
//! `portforward.k8s.io`, as used by kube-rs's `Portforwarder` and the kubelet's websocket
//! handler), **not** KEP-4006's SPDY-over-WebSocket tunnel (`SPDY/3.1+portforward.k8s.io`,
//! refused with 400). For the i-th `ports=` entry, channel 2i carries data and 2i+1 errors;
//! the server first sends `[ch, port_lo, port_hi]` on both. The backend echoes data back on
//! its channel.

use std::sync::Arc;

use http::StatusCode;
use serde_json::{json, Value};

use super::fixtures::status;
use super::routes::rbac;
use super::{lock, ExecRecord, KubeConfig, KubeState, PortForwardRecord};
use crate::http::ws::{self, Message, WsStream};
use crate::http::{Ctx, Reply};

pub(super) const V5: &str = "v5.channel.k8s.io";
pub(super) const V4: &str = "v4.channel.k8s.io";
pub(super) const PORTFORWARD: &str = "portforward.k8s.io";

fn bad(code: StatusCode, msg: &str) -> Reply {
    crate::http::json(code, &status(code.as_u16(), "BadRequest", msg)).into()
}

fn flag(ctx: &Ctx, k: &str) -> bool {
    ctx.query_get(k).is_some_and(|v| v == "true" || v == "1")
}

impl KubeState {
    pub(super) fn exec(
        self: &Arc<Self>,
        ctx: Ctx,
        cfg: &KubeConfig,
        user: &str,
        ns: &str,
        pod: &str,
    ) -> Reply {
        if let Some(r) = rbac(cfg, user, "create", "pods/exec", Some(ns)) {
            return r;
        }
        let Some(p) = cfg.pods.iter().find(|p| p.namespace == ns && p.name == pod) else {
            return bad(StatusCode::NOT_FOUND, &format!("pods \"{pod}\" not found"));
        };
        let container = match (ctx.query_get("container"), p.containers.as_slice()) {
            (Some(c), _) if p.containers.iter().any(|x| x.name == c) => c,
            (None, [only]) => only.name.clone(),
            _ => return bad(StatusCode::BAD_REQUEST, "a valid container name must be specified"),
        };
        let command: Vec<String> =
            ctx.query().into_iter().filter(|(k, _)| k == "command").map(|(_, v)| v).collect();
        if command.is_empty() {
            return bad(StatusCode::BAD_REQUEST, "you must specify at least 1 command");
        }
        let (proto, accept) = match ws::negotiate(&ctx, &cfg.knobs.ws_protocols) {
            Ok(x) => x,
            Err(e) => return bad(StatusCode::BAD_REQUEST, &e),
        };
        let rec = ExecRecord {
            namespace: ns.to_owned(),
            pod: pod.to_owned(),
            container,
            command,
            tty: flag(&ctx, "tty"),
            stdin: flag(&ctx, "stdin"),
            protocol: proto.clone(),
            ..ExecRecord::default()
        };
        let stderr = flag(&ctx, "stderr");
        let Some(upgrade) = ctx.upgrade else {
            return bad(StatusCode::BAD_REQUEST, "Upgrade request required");
        };
        let (state, max) = (Arc::clone(self), cfg.knobs.max_ws_message);
        tokio::spawn(async move {
            if let Ok(up) = upgrade.await {
                run_exec(state, WsStream::new(up, max), rec, stderr).await;
            }
        });
        ws::switching(&accept, &proto).into()
    }

    pub(super) fn port_forward(
        self: &Arc<Self>,
        ctx: Ctx,
        cfg: &KubeConfig,
        user: &str,
        ns: &str,
        pod: &str,
    ) -> Reply {
        if let Some(r) = rbac(cfg, user, "create", "pods/portforward", Some(ns)) {
            return r;
        }
        if !cfg.pods.iter().any(|p| p.namespace == ns && p.name == pod) {
            return bad(StatusCode::NOT_FOUND, &format!("pods \"{pod}\" not found"));
        }
        let ports: Option<Vec<u16>> = ctx
            .query_all("ports")
            .iter()
            .map(|p| p.parse::<u16>().ok().filter(|p| *p > 0))
            .collect();
        let Some(ports) = ports.filter(|p| !p.is_empty() && p.len() <= 127) else {
            return bad(StatusCode::BAD_REQUEST, "query parameter \"ports\" is required (1-65535)");
        };
        let (proto, accept) = match ws::negotiate(&ctx, &[V4.to_owned(), PORTFORWARD.to_owned()]) {
            Ok(x) => x,
            Err(e) => return bad(StatusCode::BAD_REQUEST, &e),
        };
        let Some(upgrade) = ctx.upgrade else {
            return bad(StatusCode::BAD_REQUEST, "Upgrade request required");
        };
        let rec = PortForwardRecord {
            namespace: ns.to_owned(),
            pod: pod.to_owned(),
            ports,
            protocol: proto.clone(),
            bytes_echoed: 0,
        };
        let (state, max, error) =
            (Arc::clone(self), cfg.knobs.max_ws_message, cfg.knobs.portforward_error.clone());
        tokio::spawn(async move {
            if let Ok(up) = upgrade.await {
                run_port_forward(state, WsStream::new(up, max), rec, error).await;
            }
        });
        ws::switching(&accept, &proto).into()
    }
}

fn chan(ch: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.push(ch);
    v.extend_from_slice(data);
    v
}

fn exit_status(code: i32) -> Value {
    if code == 0 {
        return json!({ "metadata": {}, "status": "Success" });
    }
    json!({ "metadata": {}, "status": "Failure",
        "message": format!("command terminated with non-zero exit code: exit status {code}"),
        "reason": "NonZeroExitCode",
        "details": { "causes": [{ "reason": "ExitCode", "message": code.to_string() }] } })
}

async fn run_exec(state: Arc<KubeState>, mut ws: WsStream, rec: ExecRecord, stderr: bool) {
    let idx = {
        let mut g = lock(&state.exec);
        g.push(rec.clone());
        g.len() - 1
    };
    let update = |f: &dyn Fn(&mut ExecRecord)| {
        if let Some(r) = lock(&state.exec).get_mut(idx) {
            f(r);
        }
    };
    let (tty, v5) = (rec.tty, rec.protocol == V5);
    let (mut size, mut line, mut exit) = ((80u16, 24u16), Vec::<u8>::new(), None);
    if tty && ws.send_binary(&chan(1, b"$ ")).await.is_err() {
        return;
    }
    while exit.is_none() {
        let Ok(Some(Message::Binary(data) | Message::Text(data))) = ws.recv().await else { return };
        let Some((&ch, payload)) = data.split_first() else { continue };
        let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
        match ch {
            0 => {
                update(&|r| r.stdin_bytes += payload.len());
                out.push((1, payload.to_vec()));
                for &b in payload {
                    if b != b'\r' && b != b'\n' {
                        line.push(b);
                        continue;
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_owned();
                    line.clear();
                    if let Some(rest) = cmd.strip_prefix("exit") {
                        exit = Some(rest.trim().parse::<i32>().unwrap_or(0));
                        break;
                    } else if cmd == "stty size" {
                        out.push((1, format!("\r\n{} {}\r\n", size.1, size.0).into_bytes()));
                    } else if let Some(text) = cmd.strip_prefix("stderr ") {
                        let ch = if stderr && !tty { 2 } else { 1 };
                        out.push((ch, format!("{text}\r\n").into_bytes()));
                    }
                    if tty && !cmd.is_empty() {
                        out.push((1, b"$ ".to_vec()));
                    }
                }
            }
            4 => {
                let v: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
                let dim = |k| v[k].as_u64().and_then(|n| u16::try_from(n).ok());
                if let (Some(w), Some(h)) = (dim("Width"), dim("Height")) {
                    size = (w, h);
                    update(&|r| r.resizes.push((w, h)));
                }
            }
            255 if v5 && payload.first() == Some(&0) => exit = Some(0),
            _ => {}
        }
        for (ch, d) in out {
            if ws.send_binary(&chan(ch, &d)).await.is_err() {
                return;
            }
        }
    }
    let code = exit.unwrap_or(0);
    update(&|r| r.exit_code = Some(code));
    let st = serde_json::to_vec(&exit_status(code)).unwrap_or_default();
    let _ = ws.send_binary(&chan(3, &st)).await;
    let _ = ws.close(1000, "").await;
}

async fn run_port_forward(
    state: Arc<KubeState>,
    mut ws: WsStream,
    rec: PortForwardRecord,
    error: Option<String>,
) {
    let idx = {
        let mut g = lock(&state.forwards);
        g.push(rec.clone());
        g.len() - 1
    };
    for (i, port) in rec.ports.iter().enumerate() {
        let data = u8::try_from(2 * i).unwrap_or(u8::MAX - 1);
        for ch in [data, data + 1] {
            if ws.send_binary(&chan(ch, &port.to_le_bytes())).await.is_err() {
                return;
            }
        }
        if let Some(e) = &error {
            let _ = ws.send_binary(&chan(data + 1, e.as_bytes())).await;
        }
    }
    if error.is_some() {
        let _ = ws.close(1011, "port-forward error").await;
        return;
    }
    let channels = rec.ports.len() * 2;
    loop {
        let data = match ws.recv().await {
            Ok(Some(Message::Binary(d))) => d,
            Ok(Some(Message::Text(_))) => continue,
            _ => return,
        };
        let Some((&ch, payload)) = data.split_first() else { continue };
        if usize::from(ch) < channels && ch % 2 == 0 && !payload.is_empty() {
            if ws.send_binary(&data).await.is_err() {
                return;
            }
            if let Some(r) = lock(&state.forwards).get_mut(idx) {
                r.bytes_echoed += payload.len();
            }
        }
    }
}
