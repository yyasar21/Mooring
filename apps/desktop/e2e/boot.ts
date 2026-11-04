// E2E boot: swap in a MockTransport that starts with no vault, record what the mock "remote"
// sends back, then load the real app entry. Nothing here ships: `vite build` only bundles
// index.html. The probe holds mock data only (fake hosts, no secrets).
import { MockTransport } from "../src/lib/ipc.mock";
import { setIpc, type SessionEvent } from "../src/lib/ipc";

interface Probe {
  transport: MockTransport;
  /** Decoded text of every `bytes` event, in order, across sessions. */
  output: string;
  /** Kinds of every session event, in order. */
  events: string[];
}

declare global {
  interface Window {
    __mooringE2E?: Probe;
  }
}

const transport = new MockTransport({ vault: "missing", delayMs: 0 });
const probe: Probe = { transport, output: "", events: [] };
const dec = new TextDecoder();

const open = transport.sessionOpen;
transport.sessionOpen = (args) =>
  open({
    ...args,
    onEvent: (e: SessionEvent) => {
      probe.events.push(e.kind);
      if (e.kind === "bytes") probe.output += dec.decode(e.data);
      args.onEvent(e);
    },
  });

setIpc(transport);
window.__mooringE2E = probe;

await import("../src/main");
