import { freshBackend, settle } from "../test/harness";
import type { MockTransport } from "../lib/ipc.mock";
import { subscribeOutput, useSessions } from "./sessions";
import { useTree } from "./tree";

const text = (chunks: Uint8Array[]) => chunks.map((c) => new TextDecoder().decode(c)).join("");

describe("sessions store", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await useTree.getState().load();
  });

  it("opens a tab, shows the TOFU prompt, connects after the answer and echoes input", async () => {
    const tabId = await useSessions.getState().open("c-web01");
    await settle();
    let tab = useSessions.getState().tabs[0];
    expect(tab?.state).toBe("connecting");
    expect(tab?.prompt?.message).toMatch(/web01\.example\.test/);

    expect(await useSessions.getState().answer(tabId, "yes")).toBe(true);
    await settle();
    tab = useSessions.getState().tabs[0];
    expect(tab?.state).toBe("connected");
    expect(tab?.peerIdentity).toMatch(/SHA256/);

    const seen: Uint8Array[] = [];
    const off = subscribeOutput(tabId, (d) => seen.push(d));
    expect(text(seen)).toMatch(/Mock shell/); // buffered output replays on attach
    await useSessions.getState().send(tabId, new TextEncoder().encode("uptime"));
    await settle();
    expect(text(seen)).toMatch(/uptime$/);
    off();
  });

  it("reuses the tab for the same connection unless a new one is asked for", async () => {
    const a = await useSessions.getState().open("c-dc");
    const b = await useSessions.getState().open("c-dc");
    const c = await useSessions.getState().open("c-dc", { newTab: true });
    expect(a).toBe(b);
    expect(c).not.toBe(a);
    expect(useSessions.getState().tabs).toHaveLength(2);
  });

  it("reorders, closes and picks the neighbour as active", async () => {
    const a = await useSessions.getState().open("c-web01");
    const b = await useSessions.getState().open("c-web02");
    const c = await useSessions.getState().open("c-dc");
    useSessions.getState().move(c, 0);
    expect(useSessions.getState().tabs.map((t) => t.id)).toEqual([c, a, b]);
    useSessions.getState().activate(a);
    await useSessions.getState().close(a);
    expect(useSessions.getState().activeTab).toBe(b);
    expect(mock.sessions.size + mock.remote.size).toBe(2);
  });

  it("detach hands the session id to window_detach; the tab stays and turns into the placeholder", async () => {
    const id = await useSessions.getState().open("c-web01");
    const sid = useSessions.getState().tabs[0]?.sessionId;
    expect(await useSessions.getState().detach(id)).toBe(true);
    expect(mock.detached).toEqual([sid]);
    expect(useSessions.getState().tabs).toHaveLength(1);
    await settle();
    expect(useSessions.getState().tabs[0]?.state).toBe("detached");
  });

  it("rejecting the host key closes the tab state with a reason", async () => {
    const id = await useSessions.getState().open("c-web02");
    await settle();
    await useSessions.getState().answer(id, "no");
    await settle();
    expect(useSessions.getState().tabs[0]).toMatchObject({ state: "closed", reason: "host key rejected" });
  });
});
