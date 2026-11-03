import { useState } from "react";
import { useApp } from "../stores/app";

/** Onboarding (no vault yet) and unlock (vault locked). Both are one field: the master password. */
export function VaultGate({ mode }: { mode: "create" | "unlock" }) {
  const createVault = useApp((s) => s.createVault);
  const unlock = useApp((s) => s.unlock);
  const lastError = useApp((s) => s.lastError);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const mismatch = mode === "create" && confirm.length > 0 && confirm !== password;
  const tooShort = mode === "create" && password.length > 0 && password.length < 12;
  const canSubmit = password.length > 0 && !mismatch && !tooShort && !busy;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    await (mode === "create" ? createVault(password) : unlock(password));
    setPassword("");
    setConfirm("");
    setBusy(false);
  }

  return (
    <main className="h-full grid place-items-center bg-bg-sunken">
      <form onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }} className="w-[380px] rounded-[var(--radius-m)] border border-line bg-surface p-7">
        <h1 className="text-[length:var(--fs-xl)] font-semibold tracking-tight">
          {mode === "create" ? "Create your vault" : "Unlock Nexus"}
        </h1>
        <p className="mt-1 text-text-muted">
          {mode === "create"
            ? "Everything you save is encrypted with this password. It is never stored and cannot be recovered."
            : "Your connections and credentials stay encrypted until you unlock."}
        </p>

        <label className="block mt-6 text-[length:var(--fs-s)] text-text-muted" htmlFor="pw">
          Master password
        </label>
        <input
          id="pw"
          type="password"
          autoFocus
          autoComplete={mode === "create" ? "new-password" : "current-password"}
          value={password}
          onChange={(e) => { setPassword(e.target.value); }}
          className="mt-1 w-full rounded-[var(--radius-s)] border border-line-strong bg-bg px-3 py-2 font-mono text-text"
        />
        {mode === "create" && (
          <>
            <label className="block mt-4 text-[length:var(--fs-s)] text-text-muted" htmlFor="pw2">
              Repeat password
            </label>
            <input
              id="pw2"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => { setConfirm(e.target.value); }}
              className="mt-1 w-full rounded-[var(--radius-s)] border border-line-strong bg-bg px-3 py-2 font-mono text-text"
            />
          </>
        )}

        <p className="mt-3 min-h-5 text-[length:var(--fs-s)] text-danger" role="alert">
          {tooShort && "Use at least 12 characters. Length matters more than symbols."}
          {mismatch && "The two passwords differ."}
          {!tooShort && !mismatch && lastError}
        </p>

        <button
          type="submit"
          disabled={!canSubmit}
          className="mt-2 w-full rounded-[var(--radius-s)] bg-accent px-3 py-2 font-medium text-accent-ink disabled:opacity-40"
        >
          {busy ? "Deriving key…" : mode === "create" ? "Create vault" : "Unlock"}
        </button>
      </form>
    </main>
  );
}
