export type ProtocolName = "ssh" | "rdp" | "vnc" | "web" | "kubernetes" | "vsphere-console";

const LABEL: Record<ProtocolName, string> = {
  ssh: "SSH",
  rdp: "RDP",
  vnc: "VNC",
  web: "WEB",
  kubernetes: "K8S",
  "vsphere-console": "VMK",
};

/**
 * Protocol marker for the tree, tabs and palette. Monochrome at rest; it lights up in the signal
 * colour only when `live` (a session to that host is connected), so colour still means state.
 */
export function ProtocolPip({ protocol, live = false }: { protocol: ProtocolName; live?: boolean }) {
  return (
    <span aria-label={protocol} className="m-pip" data-live={live || undefined}>
      {LABEL[protocol]}
    </span>
  );
}
