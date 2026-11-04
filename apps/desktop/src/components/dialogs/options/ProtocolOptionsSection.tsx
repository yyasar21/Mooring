import { useEffect, useState } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, type Protocol, type ProtocolOptions, type RdpConnOptions, type VncConnOptions, type WebConnOptions } from "../../../lib/ipc";
import { defaultOptions, hasOptions, normalizeOptions, validateOptions, type OptionErrors } from "../../../lib/validate.options";
import { describeError } from "../../../stores/errors";
import { RdpOptions } from "./RdpOptions";
import { VncOptions } from "./VncOptions";
import { WebOptions } from "./WebOptions";

export interface OptionsDraft {
  protocol: Protocol;
  value: ProtocolOptions;
  set: (v: ProtocolOptions) => void;
  errors: OptionErrors;
  valid: boolean;
  loading: boolean;
  loadError: string | null;
  /** False for protocols without options, and when stored options failed to load and were not edited (never overwrite blind). */
  shouldSave: boolean;
}

/**
 * The options being edited in the connection form. Stored options are read with
 * `connection_options_get` (tree rows do not carry them); a protocol switch starts from that
 * protocol's defaults, as Rust drops `options_json` when the protocol changes.
 */
export function useOptionsDraft(connectionId: string | undefined, storedProtocol: Protocol | undefined, protocol: Protocol): OptionsDraft {
  const [stored, setStored] = useState<ProtocolOptions | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Partial<Record<Protocol, ProtocolOptions>>>({});
  const loadable = connectionId !== undefined && storedProtocol !== undefined && hasOptions(storedProtocol);

  useEffect(() => {
    if (!loadable) return;
    let live = true;
    ipc.connectionOptionsGet({ connectionId }).then(
      (o) => { if (live) setStored(normalizeOptions(storedProtocol, o)); },
      (e: unknown) => { if (live) setLoadError(describeError(e)); },
    );
    return () => { live = false; };
  }, [loadable, connectionId, storedProtocol]);

  const same = protocol === storedProtocol;
  const value = drafts[protocol] ?? (same && stored ? stored : defaultOptions(protocol));
  const errors = validateOptions(protocol, value);
  const loading = loadable && same && stored === null && loadError === null;
  const blind = same && loadable && stored === null && drafts[protocol] === undefined;
  return {
    protocol,
    value,
    set: (v) => { setDrafts((d) => ({ ...d, [protocol]: v })); },
    errors,
    valid: Object.keys(errors).length === 0,
    loading,
    loadError: same ? loadError : null,
    shouldSave: hasOptions(protocol) && !blind,
  };
}

const TITLE: Partial<Record<Protocol, string>> = { rdp: "RDP options", vnc: "VNC options", web: "Web options" };

/** The protocol-specific section of the connection form; nothing for protocols without options. */
export function ProtocolOptionsSection({ draft }: { draft: OptionsDraft }) {
  const title = TITLE[draft.protocol];
  if (!title) return null;
  return (
    <section aria-label={title} className="space-y-3 border-t border-line px-4 py-4">
      <HudLabel>{title}</HudLabel>
      {draft.loadError && (
        <p className="field-hint field-problem" role="alert">
          The stored options could not be loaded ({draft.loadError}). They stay unchanged unless you edit them here.
        </p>
      )}
      {draft.loading ? (
        <p className="field-hint" role="status">Loading options…</p>
      ) : (
        <Body draft={draft} />
      )}
    </section>
  );
}

function Body({ draft }: { draft: OptionsDraft }) {
  switch (draft.protocol) {
    case "rdp":
      return <RdpOptions value={draft.value as RdpConnOptions} errors={draft.errors} onChange={draft.set} />;
    case "vnc":
      return <VncOptions value={draft.value as VncConnOptions} errors={draft.errors} onChange={draft.set} />;
    case "web":
      return <WebOptions value={draft.value as WebConnOptions} errors={draft.errors} onChange={draft.set} />;
    default:
      return null;
  }
}
