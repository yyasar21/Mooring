export type ProtocolName = "ssh" | "rdp" | "vnc" | "web" | "kubernetes" | "vsphere-console";

const LABEL: Record<ProtocolName, string> = {
  ssh: "SSH",
  rdp: "RDP",
  vnc: "VNC",
  web: "WEB",
  kubernetes: "K8S",
  "vsphere-console": "VMK",
};

/** Small protocol marker used in the tree and tabs. Monochrome on purpose: colour is reserved for state. */
export function ProtocolPip({ protocol }: { protocol: ProtocolName }) {
  return (
    <span
      aria-label={protocol}
      style={{
        font: `500 10px/1 var(--font-mono)`,
        letterSpacing: "0.02em",
        color: "var(--text-muted)",
        border: "1px solid var(--line-strong)",
        borderRadius: 3,
        padding: "2px 4px",
        minWidth: 30,
        textAlign: "center",
        display: "inline-block",
      }}
    >
      {LABEL[protocol]}
    </span>
  );
}
