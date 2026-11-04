import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { createFakeTerminal } from "./test/fakeTerm";

// jsdom has neither canvas nor WebGL: replace the xterm wrapper with a recording fake.
vi.mock("./components/terminal/xterm", () => ({
  createTerminal: createFakeTerminal,
  themeFromCss: () => ({}),
}));

// jsdom has no canvas: without a stub every RemoteCanvas logs "not implemented". Tests that draw
// install a recording context (test/fakeGl.ts).
Object.defineProperty(HTMLCanvasElement.prototype, "getContext", { configurable: true, value: () => null });

// jsdom has no layout: scrolling a row into view is a no-op there.
Element.prototype.scrollIntoView = function scrollIntoView() {
  /* no layout in jsdom */
};

afterEach(() => {
  cleanup();
});
