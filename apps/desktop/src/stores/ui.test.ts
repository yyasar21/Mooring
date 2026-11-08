import { freshBackend } from "../test/harness";
import { INSPECTOR, SIDEBAR, useUi } from "./ui";

describe("ui store", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("follows the system by default (dark where the platform cannot say); the toggle writes data-theme", () => {
    expect(useUi.getState()).toMatchObject({ themePref: "system", theme: "dark" });
    useUi.getState().toggleTheme();
    expect(useUi.getState()).toMatchObject({ themePref: "light", theme: "light" });
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("mooring.theme")).toBe("light");
    useUi.getState().toggleTheme();
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("Appearance is a three-state setting; System resolves from prefers-color-scheme and follows it live", () => {
    let light = true;
    // jsdom has no matchMedia: install a controllable one for this test only.
    Object.defineProperty(window, "matchMedia", { configurable: true, writable: true, value: (q: string) => ({ matches: q.includes("light") ? light : !light }) });
    try {
      useUi.getState().setThemePref("dark");
      expect(document.documentElement.dataset.theme).toBe("dark");
      useUi.getState().setThemePref("system");
      expect(useUi.getState()).toMatchObject({ themePref: "system", theme: "light" });
      expect(document.documentElement.dataset.theme).toBe("light");
      expect(localStorage.getItem("mooring.theme")).toBeNull();
      light = false;
      useUi.getState().syncSystemTheme();
      expect(useUi.getState().theme).toBe("dark");
      // An explicit choice ignores later OS changes.
      useUi.getState().setThemePref("light");
      useUi.getState().syncSystemTheme();
      expect(useUi.getState().theme).toBe("light");
    } finally {
      Reflect.deleteProperty(window, "matchMedia");
      useUi.getState().setThemePref("system");
    }
  });

  it("clamps pane widths", () => {
    useUi.getState().setSidebarWidth(10);
    expect(useUi.getState().sidebarWidth).toBe(SIDEBAR.min);
    useUi.getState().setInspectorWidth(9999);
    expect(useUi.getState().inspectorWidth).toBe(INSPECTOR.max);
  });

  it("opening a dialog closes the palette; switching view closes it too", () => {
    useUi.getState().setPalette(true);
    useUi.getState().openDialog({ kind: "folder", parentId: "f-root" });
    expect(useUi.getState().paletteOpen).toBe(false);
    useUi.getState().setPalette(true);
    useUi.getState().showCredentials({ mode: "new" });
    expect(useUi.getState()).toMatchObject({ view: "credentials", paletteOpen: false, dialog: null, credentialPane: { mode: "new" } });
    useUi.getState().setPalette(true);
    useUi.getState().setView("audit");
    expect(useUi.getState()).toMatchObject({ view: "audit", paletteOpen: false });
  });
});
