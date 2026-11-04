// The mock SFTP server: an in-memory POSIX-ish tree per session, with the crate's error behaviour
// (rmdir refuses non-empty directories, never recursive; names with `/` or NUL are refused).
import { IpcError } from "./ipc.error";
import type { SftpEntry, SftpListing } from "./ipc.types";
import { baseName, joinRemote, normalizeRemote, parentOf } from "./remotePath";

export { normalizeRemote } from "./remotePath";

interface Node {
  kind: "file" | "dir" | "symlink";
  size: number;
  mtime: number;
  mode: number;
}

const BASE_MTIME = Date.parse("2026-11-01T08:00:00Z") / 1000;

export class MockRemoteFs {
  private nodes = new Map<string, Node>();

  constructor() {
    const dir = (p: string, age = 0) => { this.nodes.set(p, { kind: "dir", size: 4096, mtime: BASE_MTIME - age, mode: 0o755 }); };
    const file = (p: string, size: number, age = 0, mode = 0o644) => {
      this.nodes.set(p, { kind: "file", size, mtime: BASE_MTIME - age, mode });
    };
    dir("/");
    dir("/home");
    dir("/home/ops", 3600);
    dir("/home/ops/releases", 86_400);
    dir("/home/ops/logs", 7200);
    dir("/home/ops/empty");
    file("/home/ops/README.md", 1_284, 172_800);
    file("/home/ops/deploy.sh", 2_210, 90_000, 0o755);
    file("/home/ops/releases/app-2.4.1.tar.gz", 52_428_800, 86_400);
    file("/home/ops/releases/app-2.4.0.tar.gz", 51_904_512, 604_800);
    file("/home/ops/logs/app.log", 734_003, 60);
    file("/home/ops/logs/app.log.1", 10_485_760, 86_400);
    this.nodes.set("/home/ops/current", { kind: "symlink", size: 24, mtime: BASE_MTIME, mode: 0o777 });
    dir("/tmp");
  }

  private node(path: string): Node {
    const n = this.nodes.get(path);
    if (!n) throw new IpcError("sftp.not_found", "no such file or directory");
    return n;
  }

  private dirNode(path: string): void {
    if (this.node(path).kind !== "dir") throw new IpcError("sftp.not_a_directory", "not a directory");
  }

  private checkName(name: string): void {
    if (name === "" || name === "." || name === ".." || name.includes("/") || name.includes("\0") || name.length > 1024) {
      throw new IpcError("input.invalid", "invalid name");
    }
  }

  list(raw: string): SftpListing {
    const path = normalizeRemote(raw);
    this.dirNode(path);
    const prefix = path === "/" ? "/" : `${path}/`;
    const entries: SftpEntry[] = [];
    for (const [p, n] of this.nodes) {
      if (p === path || !p.startsWith(prefix) || p.slice(prefix.length).includes("/")) continue;
      entries.push({ name: p.slice(prefix.length), kind: n.kind, size: n.size, mtime: n.mtime, mode: n.mode });
    }
    return { entries, truncated: false };
  }

  stat(raw: string): SftpEntry {
    const path = normalizeRemote(raw);
    const n = this.node(path);
    return { name: baseName(path) || "/", kind: n.kind, size: n.size, mtime: n.mtime, mode: n.mode };
  }

  mkdir(raw: string): void {
    const path = normalizeRemote(raw);
    this.checkName(baseName(path));
    this.dirNode(parentOf(path));
    if (this.nodes.has(path)) throw new IpcError("sftp.exists", "already exists");
    this.nodes.set(path, { kind: "dir", size: 4096, mtime: BASE_MTIME, mode: 0o755 });
  }

  rename(rawFrom: string, rawTo: string): void {
    const from = normalizeRemote(rawFrom);
    const to = normalizeRemote(rawTo);
    this.node(from);
    this.checkName(baseName(to));
    this.dirNode(parentOf(to));
    if (this.nodes.has(to)) throw new IpcError("sftp.exists", "already exists");
    if (to.startsWith(`${from}/`)) throw new IpcError("input.invalid", "cannot move a directory into itself");
    for (const [p, n] of [...this.nodes]) {
      if (p === from || p.startsWith(`${from}/`)) {
        this.nodes.delete(p);
        this.nodes.set(to + p.slice(from.length), n);
      }
    }
  }

  remove(raw: string): void {
    const path = normalizeRemote(raw);
    if (path === "/") throw new IpcError("sftp.permission", "permission denied");
    const n = this.node(path);
    if (n.kind === "dir" && this.list(path).entries.length > 0) {
      throw new IpcError("sftp.not_empty", "directory not empty");
    }
    this.nodes.delete(path);
  }

  /** Size of a regular file to download; directories and links are refused like the crate does. */
  fileSize(raw: string): number {
    const n = this.node(normalizeRemote(raw));
    if (n.kind !== "file") throw new IpcError("sftp.not_a_file", "only regular files can be transferred");
    return n.size;
  }

  /** Land an upload once it completes. */
  put(dir: string, name: string, size: number): void {
    const d = normalizeRemote(dir);
    this.dirNode(d);
    this.nodes.set(joinRemote(d, name), { kind: "file", size, mtime: BASE_MTIME, mode: 0o644 });
  }
}
