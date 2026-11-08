import { create } from "zustand";

/** How long a toast stays before it leaves on its own. */
export const TOAST_MS = 4000;
/** A toast with a second line stays a little longer, so the detail can be read. */
export const TOAST_DETAIL_MS = 7000;

/** success = something was saved or done; info = a neutral notice; warning = something changed under you. */
export type ToastTone = "success" | "info" | "warning";

export interface Toast {
  id: number;
  /** The title: what happened, in a few words. */
  text: string;
  /** An optional second line: the object it happened to, or what to do next. */
  detail: string | null;
  tone: ToastTone;
}

interface ToastState {
  toasts: Toast[];
  /**
   * Show a short confirmation. Text only: never a secret, never an error (errors stay next to the
   * control that failed).
   */
  push: (text: string, opts?: { detail?: string | null; tone?: ToastTone }) => number;
  dismiss: (id: number) => void;
  reset: () => void;
}

let seq = 0;

export const useToasts = create<ToastState>((set, get) => ({
  toasts: [],
  push: (text, opts) => {
    seq += 1;
    const id = seq;
    const detail = opts?.detail ?? null;
    set({ toasts: [...get().toasts, { id, text, detail, tone: opts?.tone ?? "success" }].slice(-3) });
    setTimeout(() => { get().dismiss(id); }, detail ? TOAST_DETAIL_MS : TOAST_MS);
    return id;
  },
  dismiss: (id) => { set({ toasts: get().toasts.filter((t) => t.id !== id) }); },
  reset: () => { set({ toasts: [] }); },
}));
