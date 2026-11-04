import { useRef, useState } from "react";
import { ipc, SYNC_INTERVAL, type SyncBackend } from "../lib/ipc";
import { isVaultId, normalizeBackend, validateBackend } from "../lib/validate.secrets";
import { useApp } from "../stores/app";
import { describeError } from "../stores/errors";
import { BackendFields, BLANK_BACKEND, IntervalField } from "./settings/SyncConfigDialog";

type Step = "bootstrap" | "key" | "join";
const STEPS: { id: Step; label: string }[] = [
  { id: "bootstrap", label: "1 · Bootstrap vault" },
  { id: "key", label: "2 · Store access key" },
  { id: "join", label: "3 · Pull the synced vault" },
];

/**
 * ADR-0017 join on a fresh device (S2): a bootstrap vault is created with the synced vault's
 * password, the S3 access key is sealed into it, then `vault_join` pulls the remote header and
 * blob and replaces the bootstrap header. The device unlocks with the synced password afterwards.
 * The access key secret and the password are read from their inputs once and never kept in state.
 */
export function VaultJoin({ onBack }: { onBack: () => void }) {
  const [backend, setBackend] = useState<SyncBackend>(BLANK_BACKEND);
  const [accessKeyId, setAccessKeyId] = useState("");
  const [vaultId, setVaultId] = useState("");
  const [interval, setInterval] = useState<number | null>(SYNC_INTERVAL.default);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState<Step | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Step[]>([]);
  const secret = useRef<HTMLInputElement>(null);
  const token = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  /** What a failed attempt leaves behind, so a retry does not repeat it. */
  const progress = useRef<{ bootstrapped: boolean; credentialId: string | null }>({ bootstrapped: false, credentialId: null });

  const errors: Record<string, string> = validateBackend(backend);
  if (!/^[\x21-\x7e]{1,128}$/.test(accessKeyId.trim())) errors.accessKeyId = "Access key id is required (visible ASCII).";
  if (!isVaultId(vaultId)) errors.vaultId = "The vault id is the UUID shown under Settings → Vault sync on a synced device.";
  if (interval !== null && !(Number.isInteger(interval) && interval >= SYNC_INTERVAL.min && interval <= SYNC_INTERVAL.max)) errors.intervalMinutes = `Interval is ${SYNC_INTERVAL.min} to ${SYNC_INTERVAL.max} minutes, or manual.`;
  const show = (k: string) => (tried ? errors[k] : undefined);

  async function submit() {
    setTried(true);
    const pw = password.current?.value ?? "";
    const sk = secret.current?.value ?? "";
    if (pw.length === 0) errors.password = "Enter the synced vault's master password.";
    if (sk.length === 0 && progress.current.credentialId === null) errors.secretAccessKey = "Enter the secret access key.";
    if (Object.keys(errors).length > 0 || busy) return;
    setError(null);
    const b = normalizeBackend(backend);
    try {
      if (!progress.current.bootstrapped) {
        setBusy("bootstrap");
        await ipc.vaultCreate(pw);
        progress.current.bootstrapped = true;
        setDone(["bootstrap"]);
      }
      if (progress.current.credentialId === null) {
        setBusy("key");
        const st = token.current?.value ?? "";
        const fields: Record<string, string> = { access_key_id: accessKeyId.trim(), ...(b.region ? { region: b.region } : {}) };
        const key = await ipc.credentialCreate({ name: "Sync access key", kind: "s3_access_key", fields, secrets: { secret_access_key: sk, ...(st ? { session_token: st } : {}) } });
        progress.current.credentialId = key.id;
        setDone(["bootstrap", "key"]);
      }
      setBusy("join");
      const vault = await ipc.vaultJoin({ backend: b, credentialId: progress.current.credentialId, vaultId: vaultId.trim().toLowerCase(), password: pw, intervalMinutes: interval });
      setDone(["bootstrap", "key", "join"]);
      if (vault === "unlocked") await useApp.getState().adoptJoined();
      else setError("The joined vault is not unlocked; restart Mooring and unlock with the synced password.");
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      if (secret.current) secret.current.value = "";
      if (token.current) token.current.value = "";
      if (password.current) password.current.value = "";
      setBusy(null);
    }
  }

  const state = (s: Step) => (busy === s ? "active" : done.includes(s) ? "done" : undefined);
  const leftover = progress.current.bootstrapped && busy === null && !done.includes("join");

  return (
    <main className="airlock">
      <form className="airlock-hatch airlock-join m-hud" data-active autoComplete="off" onSubmit={(e) => { e.preventDefault(); void submit(); }} aria-label="Join a synced vault">
        <div className="airlock-kicker">
          <span className="m-micro">Mooring vault</span>
          <span className="m-micro">Join</span>
        </div>
        <h1 className="airlock-title">Join a synced vault</h1>
        <p className="airlock-copy">
          Pull a vault that another device already syncs to an S3 bucket. This device then unlocks with that vault's master password; the
          password typed here is used once for the bootstrap and is never stored.
        </p>
        <ol className="airlock-steps mt-4" aria-label="Join steps">
          {STEPS.map((s) => <li key={s.id} data-state={state(s.id)}>{s.label}</li>)}
        </ol>

        <div className="settings-body" aria-busy={busy !== null || undefined}>
          <BackendFields b={backend} onChange={setBackend} show={show} idPrefix="jn" />
          <div className="settings-grid">
            <div>
              <label className="field-label" htmlFor="jn-akid">Access key ID</label>
              <input id="jn-akid" className="field mono" spellCheck={false} placeholder="AKIA…" value={accessKeyId} aria-invalid={show("accessKeyId") ? true : undefined}
                disabled={progress.current.credentialId !== null} onChange={(e) => { setAccessKeyId(e.target.value); }} />
              <p className={`field-hint${show("accessKeyId") ? " field-problem" : ""}`}>{show("accessKeyId") ?? "Stored as an S3 access key credential inside the vault."}</p>
            </div>
            <div>
              <label className="field-label" htmlFor="jn-sk">Secret access key</label>
              <input id="jn-sk" ref={secret} type="password" className="field mono" autoComplete="new-password" data-secret aria-invalid={show("secretAccessKey") ? true : undefined}
                disabled={progress.current.credentialId !== null} />
              <p className={`field-hint${show("secretAccessKey") ? " field-problem" : ""}`}>{show("secretAccessKey") ?? "Sent to the vault once; never shown again."}</p>
            </div>
          </div>
          <div>
            <label className="field-label" htmlFor="jn-st">Session token <span className="field-opt">optional</span></label>
            <input id="jn-st" ref={token} type="password" className="field mono" autoComplete="new-password" data-secret disabled={progress.current.credentialId !== null} />
          </div>
          <div className="settings-grid">
            <div>
              <label className="field-label" htmlFor="jn-vid">Vault id</label>
              <input id="jn-vid" className="field mono" spellCheck={false} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={vaultId} aria-invalid={show("vaultId") ? true : undefined} onChange={(e) => { setVaultId(e.target.value); }} />
              <p className={`field-hint${show("vaultId") ? " field-problem" : ""}`}>{show("vaultId") ?? "Shown under Settings → Vault sync on a device that already syncs."}</p>
            </div>
            <div>
              <label className="field-label" htmlFor="jn-pw">Synced vault password</label>
              <input id="jn-pw" ref={password} type="password" className="field mono" autoComplete="current-password" data-secret aria-invalid={show("password") ? true : undefined} />
              <p className={`field-hint${show("password") ? " field-problem" : ""}`}>{show("password") ?? "The master password of the synced vault, not a new one."}</p>
            </div>
          </div>
          <IntervalField value={interval} onChange={setInterval} problem={show("intervalMinutes")} />
          {leftover && (
            <p className="settings-warn" role="note">
              The bootstrap vault and the access key are already on this device (unlocked with the password you typed). Fix the problem and
              join again; nothing else is stored until the join succeeds.
            </p>
          )}
        </div>

        <p className="airlock-error" role="alert">{error ?? (tried && Object.keys(errors).length > 0 ? "Fix the highlighted fields." : "")}</p>
        <button type="submit" disabled={busy !== null} className="airlock-submit" data-busy={busy !== null || undefined}>
          {busy === "bootstrap" ? "Creating bootstrap vault…" : busy === "key" ? "Sealing access key…" : busy === "join" ? "Pulling synced vault…" : "Join vault"}
        </button>
        <div className="airlock-foot">
          <button type="button" className="airlock-link" onClick={onBack} disabled={progress.current.bootstrapped}>Create a local vault instead</button>
          <span className="m-micro">Encrypted end to end · the bucket sees ciphertext only</span>
        </div>
      </form>
    </main>
  );
}
