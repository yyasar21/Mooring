import { useId } from "react";
import { KUBE_EXEC_COMMANDS, type KubeAccess, type KubeExecCommand, type PodSummary } from "../../lib/ipc";
import { age, podStatus, readyCount } from "./podStatus";

export interface PodActions {
  exec: (container: string) => void;
  logs: (container: string) => void;
  forward: (port: number) => void;
}

/** One pod: containers with their state and the three things Mooring may do with them. */
export function PodDetail({ pod, access, forwardOff, command, onCommand, actions }: {
  pod: PodSummary;
  access: KubeAccess | null;
  /** The connection turned pod port-forward off. */
  forwardOff: boolean;
  command: KubeExecCommand;
  onCommand: (c: KubeExecCommand) => void;
  actions: PodActions;
}) {
  const id = useId();
  const st = podStatus(pod);
  const running = pod.phase === "Running";
  const why = (allowed: boolean | undefined, verb: string) => (allowed ? null : `The token may not ${verb} in this namespace.`);
  const execWhy = why(access?.exec, "exec into pods") ?? (running ? null : "Exec needs a running pod.");
  const logsWhy = why(access?.getLogs, "read logs");
  const fwWhy = forwardOff ? "Port-forward is off for this connection." : (why(access?.portForward, "port-forward") ?? (running ? null : "Port-forward needs a running pod."));

  return (
    <section aria-label={`Pod ${pod.name}`} className="kube-card m-hud" data-active>
      <header className="flex items-center gap-2">
        <h3 className="m-display min-w-0 flex-1 truncate text-[length:var(--fs-16)] select-text" title={pod.name}>{pod.name}</h3>
        <span className="chip" data-tone={st.tone}>{st.label}</span>
      </header>
      <dl className="kube-ident">
        <dt>Node</dt>
        <dd className="mono">{pod.node ?? "not scheduled"}</dd>
        <dt>Ready</dt>
        <dd className="mono tnum">{readyCount(pod)}</dd>
        <dt>Age</dt>
        <dd className="mono tnum">{age(pod.createdAt) || "unknown"}</dd>
      </dl>

      <div className="kube-exec-cmd">
        <label className="field-label" htmlFor={`${id}-cmd`}>Exec command</label>
        <select id={`${id}-cmd`} className="field mono" value={command} onChange={(e) => { onCommand(e.target.value as KubeExecCommand); }}>
          {KUBE_EXEC_COMMANDS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      <ul className="kube-containers" aria-label="Containers">
        {pod.containers.map((c) => (
          <li key={c.name} className="kube-container">
            <div className="flex items-center gap-2">
              <span aria-hidden className="kube-dot" data-ready={c.ready || undefined} />
              <span className="mono min-w-0 flex-1 truncate">{c.name}</span>
              {c.restarts > 0 && <span className="chip tnum" data-tone={c.restarts >= 3 ? "warning" : undefined} title="Restarts">↻ {c.restarts}</span>}
            </div>
            <p className="kube-image mono truncate" title={c.image}>{c.image}</p>
            <div className="kube-actions">
              <button type="button" className="btn" disabled={execWhy !== null} title={execWhy ?? `Run ${command} in ${c.name}`}
                aria-label={`Exec into ${c.name}`} onClick={() => { actions.exec(c.name); }}>Exec</button>
              <button type="button" className="btn" disabled={logsWhy !== null} title={logsWhy ?? `Stream the logs of ${c.name}`}
                aria-label={`Logs of ${c.name}`} onClick={() => { actions.logs(c.name); }}>Logs</button>
              {c.ports.map((p) => (
                <button key={p} type="button" className="btn btn-ghost mono" disabled={fwWhy !== null} title={fwWhy ?? `Forward port ${p}`}
                  aria-label={`Forward port ${p} of ${c.name}`} onClick={() => { actions.forward(p); }}>:{p}</button>
              ))}
            </div>
          </li>
        ))}
      </ul>
      {(execWhy ?? logsWhy) && <p className="field-hint">{execWhy ?? logsWhy}</p>}
    </section>
  );
}
