// `vite dev` in a plain browser at `#/detached/<sessionId>` (screenshots, design work): there is
// no main window to detach from, so a fresh mock opens a demo session first and the page sees it
// through `viewOf`, which enforces the detached-window command list. `r-…` ids open the RDP seed
// (dc01, certificate pre-pinned), anything else the SSH seed (web01, host pre-trusted).
import type { Ipc } from "./ipc.types";
import { MockTransport } from "./ipc.mock";
import { bootRoute } from "./route";

export function detachedDemoTransport(sessionId: string): Ipc {
  const mock = new MockTransport({ webDemo: true });
  const ready = (async () => {
    if (sessionId.startsWith("r-")) {
      await mock.pin({ connectionId: "c-dc", protocol: "rdp", name: "dc01", host: "dc01.example.test", port: 3389, tags: [], options: undefined });
      await mock.sessionOpen({ connectionId: "c-dc", size: { width: 1280, height: 800 }, onEvent: () => undefined, onFrame: () => undefined });
    } else {
      mock.trustedHosts.add("web01.example.test");
      await mock.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined });
    }
    await new Promise((r) => setTimeout(r, 20));
  })();
  return mock.viewOf(sessionId, ready);
}

/**
 * The transport of a plain `vite dev` window (`bootTransport()` loads this file lazily): a demo
 * session behind the detached ACL for a detached-window URL, else the full mock. Transfers move
 * slowly enough to watch the progress bars; web windows show their notices.
 */
export function devTransport(): Ipc {
  const route = bootRoute();
  if (route.kind === "detached") return detachedDemoTransport(route.sessionId);
  return new MockTransport({ transferStepMs: 350, webDemo: true });
}
