import { useCallback, useEffect, useRef, useState } from "react";
import {
  ipc, isIpcError, type ImportFormat, type ImportFormatInfo, type ImportPick, type ImportPreview, type ImportReport, type ImportSource, type KnownLocation,
  type LdapBindInfo,
} from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { sourceKind, type SourceId } from "./importText";
import { LDAP_FORM_DEFAULT, toPreviewArgs, toTestArgs, validateLdapForm, type LdapForm, type LdapFormErrors } from "./ldapForm";

export type WizardStep = "source" | "file" | "directory" | "preview" | "apply";

export interface ImportOptions {
  /** Owner decision 16: off until the user turns it on; every change re-runs the preview. */
  plaintextSecrets: boolean;
  /** ADR-0019 §3: OpenSSH `IdentityFile`s under `~/.ssh/`. */
  keyFiles: boolean;
}

const OPTIONS_OFF: ImportOptions = { plaintextSecrets: false, keyFiles: false };

/** Form fields whose change makes a bind result stale. */
const BIND_FIELDS: readonly (keyof LdapForm)[] = ["url", "baseDn", "kind", "credentialId", "caPem"];

const firstStep = (s: SourceId | null): WizardStep => sourceKind(s) ?? "source";

/**
 * State of the import wizard (ADR-0019 §6). The plan lives in Rust under `planId`; this hook only
 * holds its DTO, the exclusions and the opt-ins. A file source goes through the Rust pick dialog;
 * the directory source (I2) holds its form here and previews with `ldap_import_preview`. Both land
 * on the same preview step and apply with `import_apply`. Closing before the apply discards the plan.
 */
export function useImportWizard(initial: SourceId | null, initialKnown: KnownLocation | null = null, onApplied?: (report: ImportReport) => void) {
  const [formats, setFormats] = useState<ImportFormatInfo[]>([]);
  const [source, setSource] = useState<SourceId | null>(initial);
  const [step, setStep] = useState<WizardStep>(firstStep(initial));
  const [pick, setPick] = useState<ImportPick | null>(null);
  const [known, setKnown] = useState<KnownLocation | null>(initialKnown);
  const [options, setOptions] = useState<ImportOptions>(OPTIONS_OFF);
  const [ldap, setLdapForm] = useState<LdapForm>(LDAP_FORM_DEFAULT);
  const [ldapErrors, setLdapErrors] = useState<LdapFormErrors>({});
  const [bind, setBind] = useState<LdapBindInfo | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [excluded, setExcluded] = useState<ReadonlySet<string>>(new Set());
  const [skipDuplicates, setSkipDuplicates] = useState(true);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** The plan to discard on close; cleared by apply and by discard. */
  const livePlan = useRef<string | null>(null);

  useEffect(() => {
    let live = true;
    ipc.importFormats().then(
      (rows) => { if (live) setFormats(rows); },
      (e: unknown) => { if (live) setError(describeError(e)); },
    );
    return () => { live = false; };
  }, []);

  const format: ImportFormat | null = source === "ldaps" ? null : source;
  const info = format ? (formats.find((f) => f.format === format) ?? null) : null;

  /** Opened by the known-location shortcut: the preview starts at once. */
  useEffect(() => {
    if (initialKnown) void readKnownLocation(initialKnown);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- once per open

  const discard = useCallback(() => {
    const id = livePlan.current;
    livePlan.current = null;
    if (id) ipc.importDiscard({ planId: id }).catch(() => undefined); // best effort: the plan expires on its own
  }, []);

  /** Unmount with a live plan = the user left: drop it in Rust (also a plan that arrives after). */
  const gone = useRef(false);
  useEffect(() => {
    gone.current = false; // StrictMode runs the cleanup once on mount
    return () => { gone.current = true; discard(); };
  }, [discard]);

  /** Run a preview; on failure fall back to `failStep` (a consumed file pick is cleared). */
  const run = async (fetch: () => Promise<ImportPreview>, failStep: "file" | "directory", consumesPick: boolean) => {
    setBusy(true);
    setError(null);
    discard();
    try {
      const p = await fetch();
      livePlan.current = p.planId;
      if (gone.current) { discard(); return; }
      setPreview(p);
      setExcluded(new Set());
      setStep("preview");
    } catch (e: unknown) {
      setError(describeError(e));
      setPreview(null);
      setStep(failStep);
      if (consumesPick) setPick(null); // a pick is single use in Rust: the next try needs the dialog again
    } finally {
      setBusy(false);
    }
  };

  const runFile = (s: ImportSource, opts: ImportOptions) =>
    run(() => ipc.importPreview({ source: s, includePlaintextSecrets: opts.plaintextSecrets, importKeyFiles: opts.keyFiles }), "file", !("known" in s));

  const chooseSource = (s: SourceId) => {
    setSource(s);
    setPick(null);
    setKnown(null);
    setOptions(OPTIONS_OFF);
    setLdapForm(LDAP_FORM_DEFAULT);
    setLdapErrors({});
    setBind(null);
    setError(null);
    setStep(firstStep(s));
  };

  const pickFile = async () => {
    if (!format) return;
    setBusy(true);
    setError(null);
    try {
      const p = await ipc.importPick({ format });
      if (p) {
        setPick(p);
        setKnown(null);
      }
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  /** The known-location shortcut: no dialog, straight to the preview. */
  const readKnownLocation = async (k: KnownLocation) => {
    setSource(k);
    setPick(null);
    setKnown(k);
    setOptions(OPTIONS_OFF);
    setStep("file");
    await runFile({ known: k }, OPTIONS_OFF);
  };

  const fileSource = (): ImportSource | null => (known ? { known } : pick ? { pickId: pick.pickId } : null);

  // ---------- the directory step (I2) ----------

  const setLdap = (patch: Partial<LdapForm>) => {
    setLdapForm((cur) => ({ ...cur, ...patch }));
    setLdapErrors((cur) => Object.fromEntries(Object.entries(cur).filter(([k]) => !(k in patch))));
    if (BIND_FIELDS.some((k) => k in patch)) setBind(null);
    setError(null);
  };

  /** `ldap_import_test`: bind + unbind, no search; the result names the host, port and bind name. */
  const testBind = async () => {
    const errs = validateLdapForm(ldap, false);
    setLdapErrors(errs);
    setBind(null);
    setError(null);
    if (Object.keys(errs).length > 0) return;
    setBusy(true);
    try {
      setBind(await ipc.ldapImportTest(toTestArgs(ldap)));
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const runPreview = async () => {
    if (source === "ldaps") {
      const errs = validateLdapForm(ldap, true);
      setLdapErrors(errs);
      if (Object.keys(errs).length > 0) return;
      await run(() => ipc.ldapImportPreview(toPreviewArgs(ldap)), "directory", false);
      return;
    }
    const s = fileSource();
    if (s) await runFile(s, options);
  };

  /** An opt-in change re-runs the preview with the same source (a pick is single use, so the known location re-runs; a file needs a new pick). */
  const setOption = async (key: keyof ImportOptions, on: boolean) => {
    const next = { ...options, [key]: on };
    setOptions(next);
    if (known) await runFile({ known }, next);
    else if (format) {
      // The pick was consumed by the first preview: ask Rust for the file again.
      setBusy(true);
      try {
        const p = await ipc.importPick({ format });
        if (!p) { setBusy(false); return; }
        setPick(p);
        await runFile({ pickId: p.pickId }, next);
      } catch (e: unknown) {
        setError(describeError(e));
        setBusy(false);
      }
    }
  };

  const toggle = (key: string, on: boolean) => {
    setExcluded((cur) => {
      const next = new Set(cur);
      if (on) next.delete(key);
      else next.add(key);
      return next;
    });
  };
  const setAll = (on: boolean) => {
    setExcluded(on || !preview ? new Set() : new Set([...preview.items.map((i) => i.key), ...preview.credentials.map((c) => c.key)]));
  };

  const apply = async () => {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const r = await ipc.importApply({ planId: preview.planId, exclude: [...excluded], duplicates: skipDuplicates ? "skip" : "import" });
      livePlan.current = null;
      setReport(r);
      setStep("apply");
      const tree = useTree.getState();
      await tree.load();
      tree.toggle(r.rootFolderId, true);
      onApplied?.(r);
    } catch (e: unknown) {
      setError(describeError(e));
      if (isIpcError(e) && e.code === "import.plan_expired") { livePlan.current = null; setPreview(null); setStep(firstStep(source)); }
    } finally {
      setBusy(false);
    }
  };

  const back = () => {
    setError(null);
    if (step === "preview") { discard(); setPreview(null); setStep(firstStep(source)); }
    else if (step === "file" || step === "directory") { setSource(initial); setPick(null); setKnown(null); setStep("source"); }
  };

  return {
    formats, source, format, info, step, pick, known, options, ldap, ldapErrors, bind, preview, excluded, skipDuplicates, report, busy, error,
    chooseSource, pickFile, readKnownLocation, setLdap, testBind, runPreview, setOption, toggle, setAll, setSkipDuplicates, apply, back, discard,
  };
}

export type ImportWizardState = ReturnType<typeof useImportWizard>;
