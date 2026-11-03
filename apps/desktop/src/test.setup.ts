import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { createFakeTerminal } from "./test/fakeTerm";

// jsdom has neither canvas nor WebGL: replace the xterm wrapper with a recording fake.
vi.mock("./components/terminal/xterm", () => ({
  createTerminal: createFakeTerminal,
  themeFromCss: () => ({}),
}));

afterEach(() => {
  cleanup();
});
