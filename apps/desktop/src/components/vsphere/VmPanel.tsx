import { useEffect, useState } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, type ConnectionSummary, type VmAction, type VsphereConnOptions } from "../../lib/ipc";
import { useConnOptions } from "../../stores/connOptions";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { PowerMenu } from "./PowerMenu";
import { useVmIdentity, useVmPower } from "./useVsphere";
import { ACTIONS, POWER_LABEL, powerBlocked, vmrcBlocked } from "./vsphere";

/**
 * Inspector sections of a synced VM row (ADR-0015 §3–4): live power state (polled while
 * visible), the power menu, the guest identity and the two console paths. A `missing` VM shows
 * only why it is greyed out: vCenter no longer reports it.
 */
export function VmPanel({ vm }: { vm: ConnectionSummary }) {
  const vcenter = useTree((s) => s.connections.find((c) => c.id === vm.syncSource));
  const options = useConnOptions((s) => (vm.syncSource ? (s.byId[vm.syncSource] as VsphereConnOptions | undefined) : undefined));
  const missing = vm.syncState === "missing";
  const power = useVmPower(vm.id, !missing);
  const identity = useVmIdentity(vm.id, !missing);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ text: string; tone: "ok" | "hot" | "muted" } | null>(null);

  useEffect(() => {
    if (vm.syncSource) void useConnOptions.getState().load(vm.syncSource);
  }, [vm.syncSource]);
  useEffect(() => { setNotice(null); }, [vm.id]);

  const vcName = vcenter?.name ?? "the vCenter";

  const act = async (action: VmAction) => {
    const meta = ACTIONS.find((a) => a.action === action);
    setBusy(true);
    setNotice({ text: `Waiting for your answer in the Mooring dialog: ${meta?.label.toLowerCase() ?? action} ${vm.name}…`, tone: "muted" });
    try {
      const { outcome } = await ipc.vsphereVmAction({ connectionId: vm.id, action });
      setNotice(outcome === "done" ? { text: `${meta?.label ?? action}: requested from ${vcName}.`, tone: "ok" } : { text: "Cancelled in the dialog. Nothing was done.", tone: "muted" });
    } catch (e: unknown) {
      setNotice({ text: describeError(e), tone: "hot" });
    } finally {
      setBusy(false);
      await power.reload();
    }
  };

  const console_ = async (kind: "client" | "vmrc") => {
    setBusy(true);
    setNotice(null);
    try {
      const { windowLabel } = await ipc.vsphereConsole({ connectionId: vm.id, kind });
      setNotice(
        kind === "client"
          ? { text: `Opened the vSphere Client window${windowLabel ? ` (${windowLabel})` : ""}. Sign in there; the copy buttons below give you the account.`, tone: "ok" }
          : { text: "Ticket handed to VMware Remote Console. It is valid once, for about a minute.", tone: "ok" },
      );
    } catch (e: unknown) {
      setNotice({ text: describeError(e), tone: "hot" });
    } finally {
      setBusy(false);
    }
  };

  if (missing) {
    return (
      <section className="readout-section" aria-label="Virtual machine">
        <HudLabel>Virtual machine</HudLabel>
        <p className="vs-line" data-tone="hot" role="status">
          {vcName} no longer reports this VM. It is removed from the tree if it is still missing at the next refresh; power actions and
          consoles are unavailable until then.
        </p>
      </section>
    );
  }

  const state = power.value;
  const vmrc = vmrcBlocked(options, vcName);
  return (
    <>
      <section className="readout-section" aria-label="Virtual machine">
        <HudLabel>Virtual machine</HudLabel>
        <div className="vs-power" data-state={state ?? undefined} role="status" aria-live="polite">
          <span className="vs-power-dot" aria-hidden />
          <span>{state ? POWER_LABEL[state] : power.error ? "Power state unknown" : "Reading power state…"}</span>
        </div>
        {power.error && <p className="field-hint field-problem">{power.error}</p>}
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void console_("client")}>
            Open in vSphere Client
          </button>
          <button type="button" className="btn" disabled={busy || vmrc !== null} title={vmrc ?? "Hands a one-time ticket to the VMRC app after a system dialog with three buttons (Cancel, Open, Not now); only a click confirms"} onClick={() => void console_("vmrc")}>
            VMRC
          </button>
          <PowerMenu state={state} blocked={powerBlocked(options, vcName)} busy={busy} onAction={(a) => void act(a)} />
        </div>
        {options && !options.allowPowerActions && (
          <p className="field-hint mt-2">Power actions are off for {vcName}. Turn them on in its connection options.</p>
        )}
        {notice && (
          <p role={notice.tone === "hot" ? "alert" : "status"} className="vs-line mt-2" data-tone={notice.tone === "muted" ? undefined : notice.tone}>
            {notice.text}
          </p>
        )}
      </section>

      <section className="readout-section" aria-label="Guest identity">
        <HudLabel>Guest identity</HudLabel>
        <dl className="prop-grid">
          <dt>Host name</dt><dd className="mono select-text">{identity.value?.hostName ?? <Faint>{identity.loading ? "…" : "unknown"}</Faint>}</dd>
          <dt>IP</dt><dd className="mono select-text">{identity.value?.ip ?? <Faint>{identity.loading ? "…" : "unknown"}</Faint>}</dd>
          <dt>Family</dt><dd>{identity.value?.family ?? <Faint>{identity.loading ? "…" : "unknown"}</Faint>}</dd>
          <dt>vCenter id</dt><dd className="mono select-text">{vm.externalId}</dd>
        </dl>
        {identity.error && <p className="field-hint">{identity.error}</p>}
        <button type="button" className="btn btn-ghost mt-2" disabled={identity.loading} onClick={() => void identity.reload()}>
          Reload identity
        </button>
      </section>
    </>
  );
}

function Faint({ children }: { children: string }) {
  return <span className="text-text-faint">{children}</span>;
}
