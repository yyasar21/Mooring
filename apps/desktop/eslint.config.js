import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname }, globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-console": "error", // logs go through the Rust side with redaction
      // tauri-plugin-dialog replaces window.alert/confirm with async IPC calls the capability does
      // not grant: confirm() then returns a truthy Promise and asks nothing (review 4, N-11).
      // Use the shared Modal instead.
      "no-alert": "error",
      "no-restricted-globals": [
        "error",
        { name: "confirm", message: "Use the shared Modal: confirm() is replaced by the dialog plugin (N-11)." },
        { name: "alert", message: "Use the shared Modal: alert() is replaced by the dialog plugin (N-11)." },
        { name: "prompt", message: "Use the shared Modal: prompt() is not supported in the WebView (N-11)." },
      ],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
);
