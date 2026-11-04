import { useId, useState } from "react";
import type { Exposure, ForwardKind, ForwardOpen } from "../../lib/ipc";
import { hasErrors, isLoopbackHost, validateForward } from "../../lib/validate.exit";
import { Modal } from "../dialogs/Modal";
import { formatHostPort } from "./useForwards";

type Draft = Omit<ForwardOpen, "sessionId">;

export const KIND_META: Record<ForwardKind, { label: string; short: string; help: string }> = {
  local: { label: "Local", short: "L", help: "Listen on this computer; the server connects on to the target." },
  remote: { label: "Remote", short: "R", help: "Listen on the server; this computer connects on to the target." },
  dynamic: { label: "Dynamic", short: "D", help: "A SOCKS5 proxy on this computer that routes through the server." },
};

const KINDS: ForwardKind[] = ["local", "remote", "dynamic"];

/** Inline form for a new forward. External exposure always passes an explicit confirmation. */
export function ForwardForm({ onSubmit, onCancel, busy }: {
  onSubmit: (d: Draft) => Promise<boolean>;
  onCancel: () => void;
  busy: boolean;
}) {
  const id = useId();
  const [kind, setKind] = useState<ForwardKind>("local");
  const [bindHost, setBindHost] = useState("127.0.0.1");
  const [bindPort, setBindPort] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [exposure, setExposure] = useState<Exposure>("loopback");
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState<Draft | null>(null);

  const draft: Draft = {
    kind,
    bind: { host: bindHost.trim(), port: bindPort.trim() === "" ? 0 : Number(bindPort) },
    target: kind === "dynamic" ? null : { host: targetHost.trim(), port: Number(targetPort) },
    exposure,
  };
  const errors = validateForward(draft);
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
      aria-label="New forward"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (hasErrors(errors)) return;
        if (draft.exposure === "external") setConfirming(draft);
        else void submit(draft);
      }}
    >
      <fieldset className="fw-kinds">
        <legend className="field-label">Kind</legend>
        {KINDS.map((k) => (
          <label key={k} className="fw-kind" data-checked={kind === k || undefined}>
            <input type="radio" name={`${id}-kind`} value={k} checked={kind === k} onChange={() => { setKind(k); }} />
            <span className="fw-kind-tag" aria-hidden>{KIND_META[k].short}</span>
            {KIND_META[k].label}
          </label>
        ))}
      </fieldset>
      <p className="field-hint fw-kind-help">{KIND_META[kind].help}</p>

      <div className="fw-grid">
        <Field id={`${id}-bh`} label={kind === "remote" ? "Bind host (server)" : "Bind host"} error={show("bindHost")}>
          <input id={`${id}-bh`} className="field mono" value={bindHost} spellCheck={false}
            aria-invalid={show("bindHost") ? true : undefined} onChange={(e) => { setBindHost(e.target.value); }} />
        </Field>
        <Field id={`${id}-bp`} label="Bind port" error={show("bindPort")}>
          <input id={`${id}-bp`} className="field mono" inputMode="numeric" placeholder="0 = any free" value={bindPort}
            aria-invalid={show("bindPort") ? true : undefined} onChange={(e) => { setBindPort(e.target.value); }} />
        </Field>
        {kind !== "dynamic" && (
          <>
            <Field id={`${id}-th`} label={kind === "remote" ? "Target host (this side)" : "Target host"} error={show("targetHost")}>
              <input id={`${id}-th`} className="field mono" value={targetHost} spellCheck={false} placeholder="db.example.test"
                aria-invalid={show("targetHost") ? true : undefined} onChange={(e) => { setTargetHost(e.target.value); }} />
            </Field>
            <Field id={`${id}-tp`} label="Target port" error={show("targetPort")}>
              <input id={`${id}-tp`} className="field mono" inputMode="numeric" value={targetPort}
                aria-invalid={show("targetPort") ? true : undefined} onChange={(e) => { setTargetPort(e.target.value); }} />
            </Field>
          </>
        )}
      </div>

      <label className="fw-expose" data-on={exposure === "external" || undefined}>
        <input type="checkbox" role="switch" checked={exposure === "external"} onChange={(e) => { setExposed(e.target.checked); }} />
        <span className="fw-expose-track" aria-hidden />
        <span>
          <span className="fw-expose-title">Allow other machines to connect</span>
          <span className="field-hint block">
            {exposure === "external" ? "External: anyone who can reach the bind address can use this forward." : "Loopback only: only this machine can use the forward."}
          </span>
        </span>
      </label>
      {show("exposure") && <p className="fw-err" role="alert">{show("exposure")}</p>}

      <div className="fw-actions">
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="submit" className={exposure === "external" ? "btn btn-danger" : "btn btn-primary"} disabled={busy}>
          {exposure === "external" ? "Open external forward" : "Open forward"}
        </button>
      </div>

      {confirming && (
        <Modal title="Expose this forward?" onClose={() => { setConfirming(null); }} width={460}>
          <div className="px-4 py-3.5">
            <p className="fw-confirm-addr mono">
              {confirming.bind.port === 0 ? `${confirming.bind.host}, any free port` : formatHostPort(confirming.bind)}
            </p>
            <p className="mt-3 text-text-muted">
              Any machine that can reach this address can use the forward
              {confirming.kind === "dynamic" ? " as a proxy into every network the server can reach" : ` to reach ${confirming.target ? formatHostPort(confirming.target) : "the target"}`}.
              Mooring records this in the audit log.
            </p>
          </div>
          <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
            <button type="button" className="btn btn-ghost" onClick={() => { setConfirming(null); }}>Cancel</button>
            <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void submit(confirming)}>
              Expose to network
            </button>
          </div>
        </Modal>
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
