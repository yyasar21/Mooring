import { useId, useState } from "react";
import type { Exposure, PodForwardOpen, PodTarget } from "../../lib/ipc";
import { isLoopbackHost } from "../../lib/validate.exit";
import { hasErrors, validatePodForward } from "../../lib/validate.kube";
import { ConfirmDialog } from "../dialogs/TrustDialog";
import { formatHostPort } from "./useForwards";

type Draft = Omit<PodForwardOpen, "sessionId">;

/** A pod a forward may target, with the container ports it declares (any port may still be typed). */
export interface PodChoice {
  namespace: string;
  pod: string;
  ports: number[];
}

/**
 * New pod forward (ADR-0014 §5, `kind: "pod"`). Same rules as SSH forwards: loopback by default,
 * external exposure only after an explicit confirmation (audited by Rust).
 */
export function PodForwardForm({ pods, preset, onSubmit, onCancel, busy }: {
  pods: PodChoice[];
  preset: PodTarget | null;
  onSubmit: (d: Draft) => Promise<boolean>;
  onCancel: () => void;
  busy: boolean;
}) {
  const id = useId();
  const first = preset ?? (pods[0] ? { namespace: pods[0].namespace, pod: pods[0].pod, port: pods[0].ports[0] ?? 0 } : null);
  const [podKey, setPodKey] = useState(first ? `${first.namespace}/${first.pod}` : "");
  const [port, setPort] = useState(first && first.port > 0 ? String(first.port) : "");
  const [bindHost, setBindHost] = useState("127.0.0.1");
  const [bindPort, setBindPort] = useState(first && first.port > 1024 ? String(first.port) : "");
  const [exposure, setExposure] = useState<Exposure>("loopback");
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState<Draft | null>(null);

  const choice = pods.find((p) => `${p.namespace}/${p.pod}` === podKey);
  const draft: Draft = {
    kind: "pod",
    bind: { host: bindHost.trim(), port: bindPort.trim() === "" ? 0 : Number(bindPort) },
    target: { namespace: choice?.namespace ?? "", pod: choice?.pod ?? "", port: Number(port) },
    exposure,
  };
  const errors = validatePodForward(draft);
  const show = (k: keyof typeof errors) => (touched ? errors[k] : undefined);

  const setExposed = (on: boolean) => {
    setExposure(on ? "external" : "loopback");
    if (on && isLoopbackHost(bindHost)) setBindHost("0.0.0.0");
    if (!on && bindHost.trim() === "0.0.0.0") setBindHost("127.0.0.1");
  };
  const submit = async (d: Draft) => {
    if (await onSubmit(d)) setConfirming(null);
  };

  return (
    <form
      className="fw-form m-hud"
      data-active
      aria-label="New pod forward"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (hasErrors(errors)) return;
        if (draft.exposure === "external") setConfirming(draft);
        else void submit(draft);
      }}
    >
      <p className="field-hint fw-kind-help">
        <span className="fw-kind-tag" aria-hidden>P</span> Listen on this computer; the cluster connects on to a port of the pod.
      </p>
      <div className="fw-grid">
        <Field id={`${id}-pod`} label="Pod" error={show("pod") ?? show("namespace")}>
          <select id={`${id}-pod`} className="field mono" value={podKey} onChange={(e) => {
            setPodKey(e.target.value);
            const next = pods.find((p) => `${p.namespace}/${p.pod}` === e.target.value);
            setPort(next?.ports[0] ? String(next.ports[0]) : "");
          }}>
            {pods.length === 0 && <option value="">No pods</option>}
            {pods.map((p) => <option key={`${p.namespace}/${p.pod}`} value={`${p.namespace}/${p.pod}`}>{p.namespace}/{p.pod}</option>)}
          </select>
        </Field>
        <Field id={`${id}-pp`} label="Pod port" error={show("port")}>
          <input id={`${id}-pp`} className="field mono" inputMode="numeric" list={`${id}-ports`} value={port}
            aria-invalid={show("port") ? true : undefined} onChange={(e) => { setPort(e.target.value); }} />
          <datalist id={`${id}-ports`}>{choice?.ports.map((p) => <option key={p} value={p} />)}</datalist>
        </Field>
        <Field id={`${id}-bh`} label="Bind host" error={show("bindHost")}>
          <input id={`${id}-bh`} className="field mono" value={bindHost} spellCheck={false}
            aria-invalid={show("bindHost") ? true : undefined} onChange={(e) => { setBindHost(e.target.value); }} />
        </Field>
        <Field id={`${id}-bp`} label="Bind port" error={show("bindPort")}>
          <input id={`${id}-bp`} className="field mono" inputMode="numeric" placeholder="0 = any free" value={bindPort}
            aria-invalid={show("bindPort") ? true : undefined} onChange={(e) => { setBindPort(e.target.value); }} />
        </Field>
      </div>

      <label className="fw-expose" data-on={exposure === "external" || undefined}>
        <input type="checkbox" role="switch" checked={exposure === "external"} onChange={(e) => { setExposed(e.target.checked); }} />
        <span className="fw-expose-track" aria-hidden />
        <span>
          <span className="fw-expose-title">Allow other machines to connect</span>
          <span className="field-hint block">
            {exposure === "external" ? "External: anyone who can reach the bind address can reach the pod." : "Loopback only: only this machine can use the forward."}
          </span>
        </span>
      </label>
      {show("exposure") && <p className="fw-err" role="alert">{show("exposure")}</p>}

      <div className="fw-actions">
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="submit" className={exposure === "external" ? "btn btn-danger" : "btn btn-primary"} disabled={busy || pods.length === 0}>
          {exposure === "external" ? "Open external forward" : "Open forward"}
        </button>
      </div>

      {confirming && (
        <ConfirmDialog
          title="Expose this forward?"
          tone="danger"
          well={{ label: "Listening on", value: confirming.bind.port === 0 ? `${confirming.bind.host}, any free port` : formatHostPort(confirming.bind) }}
          confirmLabel="Expose to network"
          danger
          busy={busy}
          onConfirm={() => void submit(confirming)}
          onCancel={() => { setConfirming(null); }}
        >
          <p className="m-0">
            Any machine that can reach this address can use the forward to reach {confirming.target.namespace}/{confirming.target.pod} port {confirming.target.port}. Mooring records this in the audit log.
          </p>
        </ConfirmDialog>
      )}
    </form>
  );
}

function Field({ id, label, error, children }: { id: string; label: string; error: string | undefined; children: React.ReactNode }) {
  return (
    <div>
      <label className="field-label" htmlFor={id}>{label}</label>
      {children}
      {error && <p className="fw-err" role="alert">{error}</p>}
    </div>
  );
}
