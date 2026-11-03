/** Error shape produced by the Rust side (`IpcError` in src-tauri/src/commands.rs). */
export class IpcError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "IpcError";
    this.code = code;
  }
}
