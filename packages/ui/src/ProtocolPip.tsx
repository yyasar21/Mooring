export type ProtocolName = "ssh" | "rdp" | "vnc" | "web" | "kubernetes" | "vsphere-console";

/** Full protocol names (design review 2026-11: icons plus full names, no code book). */
export const PROTOCOL_LABEL: Record<ProtocolName, string> = {
  ssh: "SSH",
  rdp: "RDP",
  vnc: "VNC",
  web: "Web",
  kubernetes: "Kubernetes",
  "vsphere-console": "vSphere",
};

/**
 * Text badge with the protocol's full name, for details and tables. The tree and tabs use
 * `ProtocolIcon`. Lit (success tint) only when a session to that host is connected; the name is
 * the label, so colour never carries state alone.
 */
export function ProtocolPip({ protocol, live = false }: { protocol: ProtocolName; live?: boolean }) {
  return (
    <span aria-label={protocol} className="m-pip" data-live={live || undefined}>
      {PROTOCOL_LABEL[protocol]}
    </span>
  );
}
