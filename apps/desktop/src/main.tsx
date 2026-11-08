import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";
import { Root } from "./Root";
import { bootTransport } from "./lib/ipc";
import { applyTheme, useUi } from "./stores/ui";

applyTheme(useUi.getState().theme);
// Appearance "System" follows the OS live (Settings → Appearance).
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { useUi.getState().syncSystemTheme(); });

// Outside Tauri the mock transport is a lazy chunk; inside, this resolves at once.
await bootTransport();

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <Root />
    </StrictMode>,
  );
}
