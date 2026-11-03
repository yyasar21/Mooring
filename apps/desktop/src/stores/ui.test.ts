import { freshBackend } from "../test/harness";
import { INSPECTOR, SIDEBAR, useUi } from "./ui";

describe("ui store", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("dark is the default and the toggle writes data-theme", () => {
    expect(useUi.getState().theme).toBe("dark");
    useUi.getState().toggleTheme();
    expect(useUi.getState().theme).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    useUi.getState().toggleTheme();
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("clamps pane widths", () => {
    useUi.getState().setSidebarWidth(10);
    expect(useUi.getState().sidebarWidth).toBe(SIDEBAR.min);
    useUi.getState().setInspectorWidth(9999);
    expect(useUi.getState().inspectorWidth).toBe(INSPECTOR.max);
  });

  it("opening a dialog closes the palette; switching view closes it too", () => {
    useUi.getState().setPalette(true);
    useUi.getState().openDialog({ kind: "credential" });
    expect(useUi.getState().paletteOpen).toBe(false);
    useUi.getState().setPalette(true);
    useUi.getState().setView("audit");
    expect(useUi.getState()).toMatchObject({ view: "audit", paletteOpen: false });
  });
});
