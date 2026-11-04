import { KEYBOARD_LAYOUTS, type KeyboardLayout, type RdpConnOptions } from "../../../lib/ipc";
import { KEYBOARD_LAYOUT_NAMES, type OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { CaPemField, ClipboardSelect, FpsSeg, ReadOnly, Warn } from "./controls";

const klid = (k: number) => `0x${k.toString(16).padStart(4, "0").toUpperCase()}`;

/** `RdpConnOptions` (ADR-0011). Display, colour and audio are fixed in A2 and shown read-only. */
export function RdpOptions({ value, errors, onChange }: { value: RdpConnOptions; errors: OptionErrors; onChange: (v: RdpConnOptions) => void }) {
  const set = (p: Partial<RdpConnOptions>) => { onChange({ ...value, ...p }); };
  return (
    <div className="opt-grid">
      <div className="opt-readonly-row">
        <ReadOnly label="Resolution">Fits the tab; resized live when the server supports Display Control.</ReadOnly>
        <ReadOnly label="Colour">32-bit, lossless.</ReadOnly>
        <ReadOnly label="Audio">Off in this release.</ReadOnly>
      </div>
      <div>
        <label className="field-label" htmlFor="rdp-kbd">Keyboard layout</label>
        <select
          id="rdp-kbd"
          className="field"
          value={value.keyboardLayout}
          aria-invalid={errors.keyboardLayout ? true : undefined}
          onChange={(e) => { set({ keyboardLayout: Number(e.target.value) as KeyboardLayout }); }}
        >
          {KEYBOARD_LAYOUTS.map((k) => <option key={k} value={k}>{KEYBOARD_LAYOUT_NAMES[k]} · {klid(k)}</option>)}
        </select>
        <p className="field-hint">Keys are sent as scan codes; the server applies this layout.</p>
      </div>
      <ClipboardSelect id="rdp-clip" value={value.clipboard} onChange={(clipboard) => { set({ clipboard }); }} />
      <FpsSeg name="rdp-fps" value={value.maxFps} onChange={(maxFps) => { set({ maxFps }); }} />
      <div className="opt-danger" data-on={value.allowTlsWithoutNla || undefined}>
        <Toggle
          checked={value.allowTlsWithoutNla}
          onChange={(allowTlsWithoutNla) => { set({ allowTlsWithoutNla }); }}
          label="Allow TLS without NLA (legacy hosts)"
          hint="Off by default. Only for old servers that cannot do Network Level Authentication."
        />
        {value.allowTlsWithoutNla && (
          <Warn>
            Without NLA the server shows its sign-in screen before you are authenticated, which exposes it to anyone who can reach the
            port. Every such connection is recorded in the audit log and shows a “TLS without NLA” badge.
          </Warn>
        )}
      </div>
      <CaPemField id="rdp-ca" value={value.caPem} error={errors.caPem} onChange={(caPem) => { set({ caPem }); }} />
    </div>
  );
}
