import type { VncConnOptions, VncSecurity } from "../../../lib/ipc";
import type { OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { CaPemField, ClipboardSelect, FpsSeg, ReadOnly, Seg, Warn } from "./controls";

const SECURITY: { value: VncSecurity; label: string }[] = [
  { value: "require_tls", label: "Require TLS" },
  { value: "prefer_tls", label: "Prefer TLS" },
  { value: "allow_plaintext", label: "Allow plaintext" },
];

/** The ADR-0012 `SetEncodings` order; not configurable in A2. */
export const VNC_ENCODINGS = "CopyRect, ZRLE, Tight (no JPEG), Raw";

/** `VncConnOptions` (ADR-0012). */
export function VncOptions({ value, errors, onChange }: { value: VncConnOptions; errors: OptionErrors; onChange: (v: VncConnOptions) => void }) {
  const set = (p: Partial<VncConnOptions>) => { onChange({ ...value, ...p }); };
  return (
    <div className="opt-grid">
      <Seg
        legend="Security"
        name="vnc-sec"
        value={value.security}
        options={SECURITY}
        onChange={(security) => { set({ security }); }}
        hint="VeNCrypt X.509 is used whenever the server offers it. Once a certificate is stored for this host, Mooring always requires TLS."
      />
      {value.security !== "require_tls" && (
        <Warn>
          {value.security === "allow_plaintext"
            ? "Plaintext allowed: without TLS the screen, keystrokes and clipboard cross the network unencrypted."
            : "If the server offers no TLS, Mooring falls back to an unencrypted session: screen, keystrokes and clipboard cross the network in clear text."}{" "}
          Such sessions show an “Unencrypted” badge and are recorded in the audit log.
        </Warn>
      )}
      <Toggle
        checked={value.viewOnly}
        onChange={(viewOnly) => { set({ viewOnly }); }}
        label="Start in view-only mode"
        hint="Mooring drops your keyboard, mouse and clipboard input until you turn input on in the session toolbar."
      />
      <Toggle
        checked={value.shared}
        onChange={(shared) => { set({ shared }); }}
        label="Shared session"
        hint="Let other viewers stay connected (RFB shared flag)."
      />
      <ClipboardSelect id="vnc-clip" value={value.clipboard} onChange={(clipboard) => { set({ clipboard }); }} />
      <FpsSeg name="vnc-fps" value={value.maxFps} onChange={(maxFps) => { set({ maxFps }); }} />
      <div className="opt-danger" data-on={value.allowNoAuth || undefined}>
        <Toggle
          checked={value.allowNoAuth}
          onChange={(allowNoAuth) => { set({ allowNoAuth }); }}
          label="Allow servers without authentication"
          hint="Off by default. Only for servers that offer no VNC authentication at all although a password is stored for this connection."
        />
        {value.allowNoAuth && (
          <Warn>
            A server that offers no authentication is accepted although a password is set: your password proves nothing, and anyone who
            can reach the port gets the same desktop. Every such connection is recorded in the audit log as weak security.
          </Warn>
        )}
      </div>
      <ReadOnly label="Encodings">{VNC_ENCODINGS}</ReadOnly>
      <CaPemField id="vnc-ca" value={value.caPem} error={errors.caPem} onChange={(caPem) => { set({ caPem }); }} />
    </div>
  );
}
