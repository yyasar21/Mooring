import { useMemo, useState } from "react";
import { HudLabel } from "@mooring/ui";
import type { Protocol, VncConnOptions } from "../../lib/ipc";
import { MAX_VIA } from "../../lib/ipc.types.a5";
import { chainText, moveItem, supportsVia, viaCandidates } from "../../lib/via";
import { useTree } from "../../stores/tree";
import { isMac } from "../../lib/shortcuts";

/**
 * ADR-0025 "Connect via": an ordered list of up to three SSH jump hosts, first hop first. Only
 * connection ids go to Rust; each hop signs in with its own credential. Keyboard: every row has
 * Up / Down / Remove buttons, and the picker adds the chosen host at the end.
 */
export function ViaSection({ selfId, protocol, target, via, onChange, vnc }: {
  selfId: string | null;
  protocol: Protocol;
  /** The name (or host) typed so far, shown at the end of the chain. */
  target: string;
  via: string[];
  onChange: (via: string[]) => void;
  /** The VNC options draft: a VNC session that may run in plaintext across a hop gets a warning (ADR-0025 T8). */
  vnc?: Partial<VncConnOptions> | null;
}) {
  const connections = useTree((s) => s.connections);
  const candidates = useMemo(() => viaCandidates(connections, selfId, via), [connections, selfId, via]);
  const [pick, setPick] = useState("");
  const chosen = candidates.some((c) => c.id === pick) ? pick : "";

  if (!supportsVia(protocol)) return null;

  const nameOf = (id: string) => connections.find((c) => c.id === id);
  const full = via.length >= MAX_VIA;

  return (
    <div className="space-y-3 border-t border-line px-4 py-4" role="group" aria-labelledby="via-h">
      <HudLabel id="via-h">Connect via</HudLabel>
      {via.length === 0 ? (
        <p className="field-hint">Direct connection. Add SSH jump hosts to reach this host through them.</p>
      ) : (
        <ol className="via-list" aria-label="Jump hosts, first hop first">
          {via.map((id, i) => {
            const hop = nameOf(id);
            const name = hop?.name ?? "missing jump host";
            return (
              <li key={id} className="via-item">
                <span className="via-step">{i + 1}</span>
                <span className="via-name">
                  {name}
                  {hop && <span className="via-host">{hop.host}{hop.port ? `:${String(hop.port)}` : ""}</span>}
                </span>
                <span className="via-actions">
                  <button type="button" className="btn btn-ghost" aria-label={`Move ${name} up`} disabled={i === 0} onClick={() => { onChange(moveItem(via, i, -1)); }}>Up</button>
                  <button type="button" className="btn btn-ghost" aria-label={`Move ${name} down`} disabled={i === via.length - 1} onClick={() => { onChange(moveItem(via, i, 1)); }}>Down</button>
                  <button type="button" className="btn btn-ghost" aria-label={`Remove ${name}`} onClick={() => { onChange(via.filter((x) => x !== id)); }}>Remove</button>
                </span>
              </li>
            );
          })}
        </ol>
      )}
      <div className="via-add">
        <div>
          <label className="field-label" htmlFor="via-pick">Add jump host</label>
          <select id="via-pick" className="field" value={chosen} disabled={full || candidates.length === 0} onChange={(e) => { setPick(e.target.value); }}>
            <option value="">{full ? "At most 3 jump hosts" : candidates.length === 0 ? "No other SSH connection" : "Choose an SSH connection"}</option>
            {candidates.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.host})</option>)}
          </select>
        </div>
        <button
          type="button"
          className="btn"
          disabled={!chosen}
          onClick={() => {
            onChange([...via, chosen]);
            setPick("");
          }}
        >
          Add
        </button>
      </div>
      {via.length > 0 && <p className="via-chain" aria-label="Route">{chainText(connections, via, target)}</p>}
      {via.length > 0 && (
        <p className="field-hint">Each jump host signs in with its own credential and checks its own host key. Only SSH connections can be jump hosts.</p>
      )}
      {protocol === "web" && <WebViaNote chained={via.length > 0} />}
      {via.length > 0 && protocol === "vnc" && vnc?.security === "allow_plaintext" && (
        <p className="field-hint field-problem" role="note">
          This VNC connection allows plaintext. The jump hosts carry it inside SSH, but the last leg from the final jump host to the target can be unencrypted.
        </p>
      )}
    </div>
  );
}

/**
 * R6: a web window goes through a SOCKS proxy on the last jump host. The chain opens without a
 * human, and macOS refuses it in this build (`web.via_unsupported`).
 */
function WebViaNote({ chained }: { chained: boolean }) {
  return (
    <>
      {chained && (
        <p className="field-hint">
          The page goes through a SOCKS proxy on the last jump host. A web window cannot answer a jump host&apos;s questions: trust each jump host&apos;s key in an SSH session first, and give it a stored credential.
        </p>
      )}
      {isMac() && (
        <p className="field-hint field-problem" role="note">
          On macOS, this build cannot open web windows through jump hosts. Opening is refused; use an SSH session&apos;s dynamic forward instead.
        </p>
      )}
    </>
  );
}
