// OS file pickers (tauri-plugin-dialog, ADR-0010). The only way a local path enters the UI: the
// user picks it in the native dialog and the string goes straight to the SFTP command, where Rust
// confines it with `LocalPath`. The UI never types, edits or stores a local path.
import { open } from "@tauri-apps/plugin-dialog";
import { inTauri } from "./ipc";

/** Plain `vite dev` has no native dialog: demo picks so the panel stays usable in a browser. */
const DEMO = { dir: "/home/demo/Downloads", file: "/home/demo/Documents/notes.txt" };

/** Folder to download into, or null when the user cancelled. */
export async function pickDownloadDir(): Promise<string | null> {
  if (!inTauri()) return DEMO.dir;
  const r = await open({ directory: true, multiple: false, title: "Download to folder" });
  return typeof r === "string" ? r : null;
}

/** File to upload, or null when the user cancelled. */
export async function pickUploadFile(): Promise<string | null> {
  if (!inTauri()) return DEMO.file;
  const r = await open({ directory: false, multiple: false, title: "Upload a file" });
  return typeof r === "string" ? r : null;
}

/** Last path component for display; works for `/` and `\` separators. */
export function localName(path: string): string {
  const parts = path.split(/[\\/]/).filter((p) => p !== "");
  return parts.at(-1) ?? path;
}
