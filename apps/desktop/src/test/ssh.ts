import { MockTransport } from "../lib/ipc.mock";

const tick = () => new Promise((r) => setTimeout(r, 0));

/** A mock with one connected SSH session to web01 (host already trusted). */
export async function connectedSsh(m = new MockTransport()): Promise<{ m: MockTransport; sessionId: string }> {
  m.trustedHosts.add("web01.example.test");
  const { sessionId } = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined });
  await tick();
  return { m, sessionId };
}

/** Wait (macrotask by macrotask) until `fn` holds or `max` ticks pass. */
export async function until(fn: () => boolean, max = 50): Promise<void> {
  for (let i = 0; i < max && !fn(); i++) await tick();
}
