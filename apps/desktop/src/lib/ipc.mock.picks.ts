// The mock side of `sftp_pick_local` (ADR-0010 as amended by review 4, B-4). Rust keeps the chosen
// path; here a pick only knows its display name. Same rules as Rust: a pick is single-use, bound
// to its session and mode, expires after 10 minutes and is cleared on every lock. A bad pick is
// refused with `input.invalid` naming "pick".
import { IpcError } from "./ipc.error";
import type { LocalPick, PickMode } from "./ipc.types";

/** ADR-0010: a pick lives at most this long. */
export const PICK_TTL_MS = 10 * 60_000;

/** What the browser "dialog" picks when a test does not queue anything. */
export const DEMO_PICKS: Record<PickMode, string> = { folder: "Downloads", file: "notes.txt" };

interface Pick {
  sessionId: string;
  mode: PickMode;
  name: string;
  at: number;
}

export class MockPicks {
  /** Names the next dialogs return, in order; `null` = the user cancels. Empty = demo picks. */
  queue: (string | null)[] = [];
  /** Local files that exist, as `folder/name` (downloads land here; `sftp.exists` checks it). */
  localFiles = new Set<string>();
  private picks = new Map<string, Pick>();
  private seq = 0;

  open(sessionId: string, mode: PickMode, now = Date.now()): LocalPick | null {
    const name = this.queue.length > 0 ? this.queue.shift() : DEMO_PICKS[mode];
    if (name === null || name === undefined) return null;
    this.seq += 1;
    // Opaque like Rust's random 128-bit id; tests only need it unique and unguessable-looking.
    const pickId = `pick-${this.seq.toString(16).padStart(4, "0")}-${Math.random().toString(16).slice(2, 10)}`;
    this.picks.set(pickId, { sessionId, mode, name, at: now });
    return { pickId, name };
  }

  /** Validate without consuming: an `sftp.exists` refusal keeps the pick for the overwrite retry. */
  peek(pickId: string, sessionId: string, mode: PickMode, now = Date.now()): string {
    const p = this.picks.get(pickId);
    if (!p || p.sessionId !== sessionId || p.mode !== mode || now - p.at > PICK_TTL_MS) {
      throw new IpcError("input.invalid", "invalid pick: unknown, used, expired or from another session");
    }
    return p.name;
  }

  consume(pickId: string): void {
    this.picks.delete(pickId);
  }

  /** Every lock forgets every pick. */
  clear(): void {
    this.picks.clear();
  }

  get size(): number {
    return this.picks.size;
  }
}
