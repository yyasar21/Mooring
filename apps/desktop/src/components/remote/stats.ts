// Frames drawn and bytes received per second, for the FPS/bandwidth overlay.

export interface StatsSample {
  fps: number;
  /** Received MFR1 payload in kilobytes per second. */
  kBps: number;
  /** Messages that failed to decode since the session tab opened. */
  errors: number;
}

export class FrameStats {
  private frames = 0;
  private bytes = 0;
  private since: number;
  errors = 0;

  constructor(now: number) {
    this.since = now;
  }

  frame(bytes: number): void {
    this.frames += 1;
    this.bytes += bytes;
  }

  /** Rates since the previous sample; resets the window. */
  sample(now: number): StatsSample {
    const secs = Math.max(0.001, (now - this.since) / 1000);
    const out = { fps: Math.round(this.frames / secs), kBps: Math.round(this.bytes / 1024 / secs), errors: this.errors };
    this.frames = 0;
    this.bytes = 0;
    this.since = now;
    return out;
  }
}
