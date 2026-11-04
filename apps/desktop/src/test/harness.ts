import { act } from "@testing-library/react";
import { setIpc } from "../lib/ipc";
import { MockTransport, type MockOptions } from "../lib/ipc.mock";
import { useApp } from "../stores/app";
import { useCredentials } from "../stores/credentials";
import { useSessions } from "../stores/sessions";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";
import { useTransfers } from "../stores/transfers";
import { useConnOptions } from "../stores/connOptions";

/** Fresh mock backend and empty stores for every test. */
export function freshBackend(opts: MockOptions = {}): MockTransport {
  const mock = new MockTransport(opts);
  setIpc(mock);
  useSessions.getState().reset();
  useTree.getState().reset();
  useCredentials.getState().reset();
  useUi.getState().reset();
  useTransfers.getState().reset();
  useConnOptions.getState().reset();
  useUi.setState({ theme: "dark", inspectorOpen: true });
  useApp.setState({ info: null, vault: "unknown", lastError: null, lockReason: null });
  return mock;
}

/** Let mock timers and promise chains settle inside act(). */
export async function settle(times = 3): Promise<void> {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
  }
}
