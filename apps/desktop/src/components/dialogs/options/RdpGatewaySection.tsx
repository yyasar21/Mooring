import { useRef } from "react";
import { DEFAULT_GATEWAY, type GatewayUsage, type RdGatewayOptions } from "../../../lib/ipc";
import type { OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { CaPemField, Seg, Warn } from "./controls";

const USAGE: { value: GatewayUsage; label: string }[] = [
  { value: "always", label: "Always" },
  { value: "if_unreachable", label: "Only when the computer is unreachable" },
];

/** The contract's copy for the Basic toggle (`a5-rust-core-r5.md`, UI contract). */
export const BASIC_WARNING = "Sends the password in an HTTP header (inside TLS). Audited.";

/**
 * ADR-0027: `RdpConnOptions.gateway`. Off stores `null` (a direct connection); the fields typed so
 * far come back when it is switched on again in the same form. The gateway credential is the
 * connection's existing `gateway` role (`gatewayCredentialId`), picked in the form's credential section.
 */
export function RdpGatewaySection({ value, errors, onChange }: {
  value: RdGatewayOptions | null;
  errors: OptionErrors;
  onChange: (v: RdGatewayOptions | null) => void;
}) {
  const last = useRef<RdGatewayOptions>(value ?? DEFAULT_GATEWAY);
  if (value) last.current = value;
  const set = (p: Partial<RdGatewayOptions>) => { if (value) onChange({ ...value, ...p }); };
  const on = value !== null;
  return (
    <fieldset className="rdg-section" aria-label="RD Gateway">
      <legend className="sk-heading">RD Gateway</legend>
      <Toggle
        checked={on}
        onChange={(v) => { onChange(v ? { ...last.current } : null); }}
        label="Connect through an RD Gateway"
        hint="For computers you reach only through a Remote Desktop Gateway (HTTPS, Windows Server 2016 or later)."
      />
      {value && (
        <>
          <div className="grid grid-cols-[1fr_96px] gap-3">
            <div>
              <label className="field-label" htmlFor="rdg-host">Gateway host</label>
              <input
                id="rdg-host"
                className="field mono"
                spellCheck={false}
                placeholder="gateway.example.test"
                aria-invalid={errors["gateway.host"] ? true : undefined}
                aria-describedby="rdg-host-hint"
                value={value.host}
                onChange={(e) => { set({ host: e.target.value.trim() }); }}
              />
              <p id="rdg-host-hint" className={errors["gateway.host"] ? "field-hint field-problem" : "field-hint"}>
                {errors["gateway.host"] ?? "Host name or IP address only. Its certificate is pinned on first use, like the computer's."}
              </p>
            </div>
            <div>
              <label className="field-label" htmlFor="rdg-port">Port</label>
              <input
                id="rdg-port"
                className="field mono"
                inputMode="numeric"
                aria-invalid={errors["gateway.port"] ? true : undefined}
                value={String(value.port)}
                onChange={(e) => { set({ port: /^\d{1,5}$/.test(e.target.value) ? Number(e.target.value) : 0 }); }}
              />
              {errors["gateway.port"] && <p className="field-hint field-problem">{errors["gateway.port"]}</p>}
            </div>
          </div>
          <Seg
            legend="Use the gateway"
            name="rdg-usage"
            value={value.usage}
            options={USAGE}
            onChange={(usage) => { set({ usage }); }}
            hint={value.usage === "if_unreachable" ? "Mooring tries the computer directly for 3 seconds first. Which way it went is audited." : undefined}
          />
          <p className="field-hint">
            The gateway signs in with the RD Gateway credential chosen above; Same as sign-in sends this connection's sign-in. Kerberos
            and smart-card gateway sign-in are not supported yet.
          </p>
          <div className="opt-danger" data-on={value.allowBasicGateway || undefined}>
            <Toggle
              checked={value.allowBasicGateway}
              onChange={(allowBasicGateway) => { set({ allowBasicGateway }); }}
              label="Allow Basic authentication"
              hint="Off by default. Only used when the gateway refuses NTLM."
            />
            {value.allowBasicGateway && <Warn>{BASIC_WARNING}</Warn>}
          </div>
          <CaPemField id="rdg-ca" value={value.caPem} error={errors["gateway.caPem"]} onChange={(caPem) => { set({ caPem }); }} />
        </>
      )}
    </fieldset>
  );
}
