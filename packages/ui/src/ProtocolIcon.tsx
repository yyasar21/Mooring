import { Icon, type IconName } from "./Icon";
import { StateDot, type DotTone } from "./MooringLine";
import { PROTOCOL_LABEL, type ProtocolName } from "./ProtocolPip";

const ICON: Record<ProtocolName, IconName> = {
  ssh: "ssh",
  rdp: "rdp",
  vnc: "vnc",
  web: "web",
  kubernetes: "kubernetes",
  "vsphere-console": "vsphere",
};

/**
 * 16 px protocol icon for the tree, tabs and palette (replaces the 3-letter pip). The glyph is an
 * image named after the protocol (the name the pip used to carry). An optional status dot sits on
 * its corner; `dotLabel` names that state, so colour is never the only signal.
 */
export function ProtocolIcon({ protocol, tone, dotLabel }: { protocol: ProtocolName; tone?: DotTone | null; dotLabel?: string }) {
  return (
    <span className="m-proto" data-protocol={protocol}>
      <span role="img" aria-label={protocol} title={PROTOCOL_LABEL[protocol]} className="m-proto-glyph">
        <Icon name={ICON[protocol]} />
      </span>
      {tone && (dotLabel ? <StateDot tone={tone} label={dotLabel} /> : <StateDot tone={tone} />)}
    </span>
  );
}
