import type { VsphereConnOptions } from "../../../lib/ipc";
import { VSPHERE_LIMITS } from "../../../lib/ipc";
import type { OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { CaPemField, ReadOnly, Warn } from "./controls";

/**
 * `VsphereConnOptions` (ADR-0015). The sign-in is a `vsphere_user` credential (user@domain);
 * the synced folder is set by the import, not here. Power actions are off by default and every
 * one is confirmed in a dialog Mooring itself opens, outside this window.
 */
export function VsphereOptions({ value, errors, onChange }: { value: VsphereConnOptions; errors: OptionErrors; onChange: (v: VsphereConnOptions) => void }) {
  const set = (p: Partial<VsphereConnOptions>) => { onChange({ ...value, ...p }); };
  const manual = value.refreshMinutes === null;
  return (
    <div className="opt-grid">
      <div className="opt-readonly-row">
        <ReadOnly label="Inventory">{value.syncFolderId ? "Synced into a read-only folder." : "Not imported yet. Use Import inventory in the inspector."}</ReadOnly>
        <ReadOnly label="Console">Opens in the vSphere Client window by default.</ReadOnly>
      </div>
      <div>
        <Toggle
          checked={!manual}
          onChange={(on) => { set({ refreshMinutes: on ? VSPHERE_LIMITS.defaultRefresh : null }); }}
          label="Refresh the inventory on a schedule"
          hint="Only while Mooring is open and the vault is unlocked."
        />
        {!manual && (
          <>
            <label className="field-label mt-2" htmlFor="vs-refresh">Refresh every (minutes)</label>
            <input id="vs-refresh" className="field mono" inputMode="numeric" value={Number.isFinite(value.refreshMinutes) ? String(value.refreshMinutes) : ""}
              aria-invalid={errors.refreshMinutes ? true : undefined}
              onChange={(e) => { set({ refreshMinutes: e.target.value.trim() === "" ? NaN : Number(e.target.value) }); }} />
            <p className={errors.refreshMinutes ? "field-hint field-problem" : "field-hint"} role={errors.refreshMinutes ? "alert" : undefined}>
              {errors.refreshMinutes ?? "15 to 1440 minutes."}
            </p>
          </>
        )}
      </div>
      <div className="opt-danger" data-on={value.allowPowerActions || undefined}>
        <Toggle
          checked={value.allowPowerActions}
          onChange={(allowPowerActions) => { set({ allowPowerActions }); }}
          label="Allow power actions on VMs"
          hint="Power on, guest shutdown and reboot, power off, reset. Off by default."
        />
        {value.allowPowerActions && (
          <Warn>
            Each action asks for confirmation in a system dialog with three buttons (Cancel, the action, Not now) that names the VM and
            the vCenter; Return and Escape refuse, only a click on the action confirms, and every answer is recorded in the audit log.
            Power off and reset are like pulling the plug and may lose data. Enabling this is logged as a warning.
          </Warn>
        )}
      </div>
      <Toggle
        checked={value.allowVmrc}
        onChange={(allowVmrc) => { set({ allowVmrc }); }}
        label="Offer VMware Remote Console"
        hint="Hands a one-time ticket to the VMRC app installed on this computer."
      />
      <CaPemField id="vs-ca" value={value.caPem} error={errors.caPem} onChange={(caPem) => { set({ caPem }); }} />
    </div>
  );
}
