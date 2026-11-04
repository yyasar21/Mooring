// POSIX path helpers for the remote (SFTP) side. Local paths never go through here: they come
// from the OS dialog and are passed to Rust untouched.
import { IpcError } from "./ipc.error";

export const MAX_REMOTE_PATH = 4096;

/** Normalise an absolute remote path: collapses `//`, `.` and `..` (never above `/`). */
export function normalizeRemote(path: string): string {
  if (path.length === 0 || path.length > MAX_REMOTE_PATH || path.includes("\0")) {
    throw new IpcError("input.invalid", "remote path must be 1 to 4096 bytes without NUL");
  }
  if (!path.startsWith("/")) throw new IpcError("input.invalid", "remote path must be absolute");
  const out: string[] = [];
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return `/${out.join("/")}`;
}

export function parentOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i <= 0 ? "/" : path.slice(0, i);
}

export function baseName(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

export function joinRemote(dir: string, name: string): string {
  return dir === "/" ? `/${name}` : `${dir}/${name}`;
}

/** Null when `name` is a valid single path component, else the reason. */
export function checkEntryName(name: string): string | null {
  if (name.trim() === "") return "Enter a name.";
  if (name === "." || name === "..") return "That name is reserved.";
  if (name.includes("/") || name.includes("\0")) return "A name cannot contain / .";
  if (new TextEncoder().encode(name).length > 255) return "Use at most 255 bytes.";
  return null;
}

/** Breadcrumb segments: [["/", "/"], ["home", "/home"], ...]. */
export function crumbs(path: string): [string, string][] {
  const out: [string, string][] = [["/", "/"]];
  let acc = "";
  for (const part of path.split("/").filter((p) => p !== "")) {
    acc += `/${part}`;
    out.push([part, acc]);
  }
  return out;
}
