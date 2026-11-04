import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";
import { Root } from "./Root";
import { applyTheme, useUi } from "./stores/ui";

applyTheme(useUi.getState().theme);

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <Root />
    </StrictMode>,
  );
}
