import { create } from "zustand";

/** How long a toast stays before it leaves on its own. */
export const TOAST_MS = 4000;

export interface Toast {
  id: number;
  text: string;
}

interface ToastState {
  toasts: Toast[];
  /** Show a short confirmation. Text only: never a secret, never an error (errors stay in place). */
  push: (text: string) => number;
  dismiss: (id: number) => void;
  reset: () => void;
}

let seq = 0;

export const useToasts = create<ToastState>((set, get) => ({
  toasts: [],
  push: (text) => {
    seq += 1;
    const id = seq;
    set({ toasts: [...get().toasts, { id, text }].slice(-3) });
    setTimeout(() => { get().dismiss(id); }, TOAST_MS);
    return id;
  },
  dismiss: (id) => { set({ toasts: get().toasts.filter((t) => t.id !== id) }); },
  reset: () => { set({ toasts: [] }); },
}));
