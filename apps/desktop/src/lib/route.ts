// The one route the bundle knows besides the main window (ADR-0013): Rust loads
// `index.html#/detached/<sessionId>` into `detached-<sessionId>`. The route is read once at boot;
// a hash change later never turns a detached window into the main UI (whose boot calls commands
// that window may not call).

const DETACHED = /^#\/detached\/([0-9A-Za-z-]{1,64})$/;

/** The session id of a detached-window URL hash, or null for the main window. */
export function detachedSessionId(hash: string): string | null {
  return DETACHED.exec(hash)?.[1] ?? null;
}

/** The route of this window, fixed at the first call. */
let fixed: string | null | undefined;
export function bootRoute(): { kind: "main" } | { kind: "detached"; sessionId: string } {
  fixed ??= typeof window === "undefined" ? null : detachedSessionId(window.location.hash);
  return fixed === null ? { kind: "main" } : { kind: "detached", sessionId: fixed };
}

/** Tests only: read the hash again on the next `bootRoute()`. */
export function resetBootRoute(): void {
  fixed = undefined;
}
