import { useEffect, useMemo, useState } from "react";
import type { ConnectionSummary, KubeExecCommand, PodTarget } from "../../lib/ipc";
import { useCredentials } from "../../stores/credentials";
import { openExec, openLogs, useKube } from "../../stores/kube";
import { useSessions, type Tab } from "../../stores/sessions";
import { ForwardsPanel } from "../forwards/ForwardsPanel";
import { PodDetail } from "./PodDetail";
import { RbacSummary } from "./RbacSummary";
import { age, matchesPod, podStatus, readyCount, restartCount } from "./podStatus";
import { useCluster, useKubeOptions } from "./useCluster";
import { CLOSE_TEXT } from "../remote/ConnectionBanner";

type View = "pods" | "forwards";

/**
 * The cluster tab of a Kubernetes connection (ADR-0014): contexts → namespaces → pods →
 * containers, the RBAC pre-flight, and the entry points for exec, logs and pod forwards.
 * Everything here is read-only; exec and port-forward run only what the token allows.
 */
export function ClusterBrowser({ tab, connection }: { tab: Tab; connection: ConnectionSummary | undefined }) {
  const meta = useKube((s) => s.clusters[tab.id]);
  const cred = useCredentials((s) => s.items.find((c) => c.id === connection?.effectiveCredentialId));
  const options = useKubeOptions(connection);
  const sessionId = tab.state === "connected" ? tab.sessionId : null;
  const cluster = useCluster(sessionId, options.namespace ?? meta?.contextNamespace ?? null, options.allowedNamespaces);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<View>("pods");
  const [preset, setPreset] = useState<PodTarget | null>(null);
  const [command, setCommand] = useState<KubeExecCommand>(options.execCommand);

  useEffect(() => { setCommand(options.execCommand); }, [options.execCommand]);

  const shown = useMemo(() => cluster.pods.filter((p) => matchesPod(p, query)), [cluster.pods, query]);
  const pod = cluster.pods.find((p) => p.name === selected) ?? null;
  const contexts = Array.isArray(cred?.fields.contexts) ? cred.fields.contexts : [];
  const active = options.context ?? (typeof cred?.fields.context === "string" ? cred.fields.context : null);
  const forwardWhy = !options.portForward ? "Port-forward is off for this connection." : cluster.access && !cluster.access.portForward ? "The token may not port-forward in this namespace." : null;
  const ns = cluster.namespace;

  if (!sessionId) {
    return (
      <div className="panel-note m-hud">
        <div className="max-w-sm">
          <p className="m-micro">Kubernetes</p>
          <p className="m-display mt-2 text-[length:var(--fs-xl)]">{connection?.name}</p>
          <p className="mt-3 text-text-muted" role="status">{tab.state === "closed" ? (tab.reason ?? "The cluster session ended.") : "Connecting to the API server…"}</p>
          {tab.state === "closed" && (tab.closeCode === "hop_failed" || tab.closeCode === "hop_lost") && (
            <p className="dropped-hint mt-2">{CLOSE_TEXT[tab.closeCode].hint}</p>
          )}
          {tab.state === "closed" && (
            <button type="button" className="btn mt-4" onClick={() => void useSessions.getState().reconnect(tab.id)}>Reconnect</button>
          )}
        </div>
      </div>
    );
  }

  const execInto = (container: string) => {
    if (!pod || !ns || !connection) return;
    void openExec(connection.id, { parentSessionId: sessionId, namespace: ns, pod: pod.name, container, command });
  };
  const logsOf = (container: string) => {
    if (!pod || !ns || !connection) return;
    void openLogs(connection.id, { parentSessionId: sessionId, namespace: ns, pod: pod.name, container });
  };

  return (
    <div className="kube-browser">
      <div role="toolbar" aria-label="Cluster" className="session-toolbar">
        <span className="m-micro">Kubernetes</span>
        <span className="mono truncate text-text-muted select-text" title={meta?.server}>{meta?.server ?? connection?.host}</span>
        <span className="flex-1" />
        <button type="button" className="btn btn-ghost" aria-pressed={view === "pods"} onClick={() => { setView("pods"); }}>Pods</button>
        <button type="button" className="btn btn-ghost" aria-pressed={view === "forwards"} onClick={() => { setView("forwards"); }}>Forwards</button>
        <button type="button" className="btn btn-ghost" onClick={() => void cluster.refresh()}>Refresh</button>
      </div>
      <p className="kube-banner" role="note">
        <span className="m-micro">Read-only</span>
        Mooring never mutates this cluster. Exec shells and port-forwards run only what your token allows, and each one is audited.
      </p>

      <div className="kube-grid">
        <aside className="kube-side" aria-label="Contexts and namespaces">
          <h3 className="m-micro">Context</h3>
          <ul className="kube-list" aria-label="Contexts">
            <li aria-current="true" className="mono">{active ?? "current-context"}</li>
            {contexts.filter((c) => c !== active).map((c) => (
              <li key={c} className="mono" aria-disabled="true" title="One connection per context: create a connection to browse this one">{c}</li>
            ))}
          </ul>
          <h3 className="m-micro mt-3">Namespaces</h3>
          {cluster.namespacesFallback && <p className="field-hint">The token may not list namespaces. Showing the context namespace and the connection's allowed list.</p>}
          <ul className="kube-list" aria-label="Namespaces">
            {cluster.namespaces.map((n) => (
              <li key={n}>
                <button type="button" className="kube-ns mono" aria-current={n === ns || undefined} onClick={() => { cluster.setNamespace(n); setSelected(null); setPreset(null); }}>{n}</button>
              </li>
            ))}
          </ul>
          {cluster.namespacesTruncated && <p className="field-hint">The namespace list is cut at 5 000.</p>}
          <RbacSummary identity={meta?.identity ?? null} namespace={ns} access={cluster.access} />
        </aside>

        {view === "forwards" ? (
          <div className="kube-main">
            <ForwardsPanel
              key={preset ? `${preset.namespace}/${preset.pod}:${preset.port}` : "list"}
              sessionId={sessionId}
              pods={cluster.pods.filter((p) => p.phase === "Running").map((p) => ({ namespace: ns ?? "", pod: p.name, ports: p.containers.flatMap((c) => c.ports) }))}
              preset={preset}
              disabledReason={forwardWhy}
            />
          </div>
        ) : (
          <div className="kube-main">
            <div className="kube-search">
              <input type="search" className="field" aria-label="Search pods" placeholder="Search pods, nodes, images" value={query} onChange={(e) => { setQuery(e.target.value); }} />
              <span className="chip tnum" title="Pods shown / in this namespace">{shown.length} / {cluster.pods.length}</span>
            </div>
            {cluster.error && <p role="alert" className="tool-error">{cluster.error}</p>}
            {cluster.access && !cluster.access.listPods && <p className="tool-empty">The token may not list pods in {ns}.</p>}
            <div role="table" aria-label="Pods" className="kube-table">
              <div role="row" className="kube-row kube-row-head">
                <span role="columnheader">Name</span><span role="columnheader">Status</span><span role="columnheader">Ready</span>
                <span role="columnheader">Restarts</span><span role="columnheader">Node</span><span role="columnheader">Age</span>
              </div>
              {shown.map((p) => {
                const st = podStatus(p);
                return (
                  <div key={p.name} role="row" className="kube-row" aria-selected={p.name === selected} tabIndex={0}
                    onClick={() => { setSelected(p.name); }} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelected(p.name); } }}>
                    <span role="cell" className="mono truncate">{p.name}</span>
                    <span role="cell"><span className="chip" data-tone={st.tone}>{st.label}</span></span>
                    <span role="cell" className="mono tnum">{readyCount(p)}</span>
                    <span role="cell" className="mono tnum" data-hot={restartCount(p) >= 3 || undefined}>{restartCount(p)}</span>
                    <span role="cell" className="mono truncate text-text-muted">{p.node ?? "—"}</span>
                    <span role="cell" className="mono tnum text-text-muted">{age(p.createdAt)}</span>
                  </div>
                );
              })}
              {shown.length === 0 && !cluster.loading && cluster.access?.listPods && (
                <div role="row" className="fw-row-empty"><span role="cell">{query ? "No pod matches the search." : "No pods in this namespace."}</span></div>
              )}
            </div>
            {cluster.podsTruncated && <p className="field-hint px-3">The pod list is cut at 5 000. Narrow it with the search.</p>}
          </div>
        )}

        <div className="kube-detail">
          {pod && view === "pods" ? (
            <PodDetail
              pod={pod}
              access={cluster.access}
              forwardOff={!options.portForward}
              command={command}
              onCommand={setCommand}
              actions={{
                exec: execInto,
                logs: logsOf,
                forward: (port) => { setPreset({ namespace: ns ?? "", pod: pod.name, port }); setView("forwards"); },
              }}
            />
          ) : (
            <p className="tool-empty">{view === "pods" ? "Select a pod to see its containers." : "Forwards close with the cluster tab, and external ones when the vault locks."}</p>
          )}
        </div>
      </div>
    </div>
  );
}
