import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { frozenPrototypeCompat } from "./vite-plugins/frozenPrototype";

// Tauri dev server: fixed port, no HMR overlay noise in the WebView, env prefix for TAURI_* only.
export default defineConfig({
  plugins: [frozenPrototypeCompat(), react(), tailwindcss()],
  // xterm is not pre-bundled so the compat transform also runs under `make dev`, where Tauri
  // freezes Object.prototype exactly as in a release build.
  optimizeDeps: { exclude: ["@xterm/xterm", "@xterm/addon-webgl", "@xterm/addon-fit"] },
  clearScreen: false,
  server: { port: 1420, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    target: ["es2022", "safari15"],
    sourcemap: false,
    minify: "esbuild",
    rollupOptions: {
      output: {
        // React (+ scheduler) in its own long-lived chunk; the app chunk then stays under Vite's
        // 500 kB warning. The mock transport is a lazy chunk (`bootTransport`), xterm is lazy already.
        manualChunks(id: string) {
          return /\/node_modules\/(react|react-dom|scheduler)\//.test(id) ? "react" : undefined;
        },
      },
    },
  },
  test: { environment: "jsdom", setupFiles: ["./src/test.setup.ts"], globals: true },
});
