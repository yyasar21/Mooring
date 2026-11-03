import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri dev server: fixed port, no HMR overlay noise in the WebView, env prefix for TAURI_* only.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: { target: ["es2022", "safari15"], sourcemap: false, minify: "esbuild" },
  test: { environment: "jsdom", setupFiles: ["./src/test.setup.ts"], globals: true },
});
