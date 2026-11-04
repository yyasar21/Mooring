import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri dev server: fixed port, no HMR overlay noise in the WebView, env prefix for TAURI_* only.
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
