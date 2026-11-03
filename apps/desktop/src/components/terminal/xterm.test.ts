import { describe, expect, it, vi } from "vitest";

// test.setup.ts replaces this wrapper with a fake for component tests; test the real one here.
vi.unmock("./xterm");

// jsdom has no canvas/WebGL: capture the options passed to xterm instead of rendering.
const ctorOptions: unknown[] = [];
vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    options: Record<string, unknown> = {};
    constructor(opts: unknown) {
      ctorOptions.push(opts);
    }
    loadAddon() {}
    open() {}
    attachCustomKeyEventHandler() {}
    onData() {
      return { dispose() {} };
    }
    write() {}
    focus() {}
    dispose() {}
  },
}));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));
vi.mock("@xterm/addon-webgl", () => ({ WebglAddon: class { onContextLoss() {} dispose() {} } }));

import { createTerminal, inertLinkHandler } from "./xterm";

describe("createTerminal (security review 2, M-4)", () => {
  it("passes an inert linkHandler so OSC 8 links from remote output never navigate", () => {
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    const handle = createTerminal(document.createElement("div"), {
      onData: () => {},
      shouldPassKey: () => true,
      theme: {},
      fontFamily: "monospace",
    });
    const opts = ctorOptions.at(-1) as { linkHandler?: typeof inertLinkHandler };
    expect(opts.linkHandler).toBe(inertLinkHandler);
    expect(opts.linkHandler?.allowNonHttpProtocols).toBe(false);
    opts.linkHandler?.activate();
    expect(open).not.toHaveBeenCalled();
    handle.dispose();
    open.mockRestore();
  });
});
