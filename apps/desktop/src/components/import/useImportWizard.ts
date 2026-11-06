import { useCallback, useEffect, useRef, useState } from "react";
import {
  ipc, isIpcError, type ImportFormat, type ImportFormatInfo, type ImportPick, type ImportPreview, type ImportReport, type ImportSource, type KnownLocation,
} from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";

export type WizardStep = "source" | "file" | "preview" | "apply";

export interface ImportOptions {
  /** Owner decision 16: off until the user turns it on; every change re-runs the preview. */
  plaintextSecrets: boolean;
  /** ADR-0019 §3: OpenSSH `IdentityFile`s under `~/.ssh/`. */
  keyFiles: boolean;
}

const OPTIONS_OFF: ImportOptions = { plaintextSecrets: false, keyFiles: false };

/**
 * State of the import wizard (ADR-0019 §6). The plan lives in Rust under `planId`; this hook only
 * holds its DTO, the exclusions and the opt-ins. Closing before the apply discards the plan.
 */
export function useImportWizard(initial: ImportFormat | null, initialKnown: KnownLocation | null = null, onApplied?: (report: ImportReport) => void) {
  const [formats, setFormats] = useState<ImportFormatInfo[]>([]);
  const [format, setFormat] = useState<ImportFormat | null>(initial);
  const [step, setStep] = useState<WizardStep>(initial ? "file" : "source");
  const [pick, setPick] = useState<ImportPick | null>(null);
  const [known, setKnown] = useState<KnownLocation | null>(initialKnown);
  const [options, setOptions] = useState<ImportOptions>(OPTIONS_OFF);
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

  const run = async (source: ImportSource, opts: ImportOptions) => {
    setBusy(true);
    setError(null);
    discard();
    try {
      const p = await ipc.importPreview({ source, includePlaintextSecrets: opts.plaintextSecrets, importKeyFiles: opts.keyFiles });
      livePlan.current = p.planId;
      if (gone.current) { discard(); return; }
      setPreview(p);
      setExcluded(new Set());
      setStep("preview");
    } catch (e: unknown) {
      setError(describeError(e));
      setPreview(null);
      setStep("file");
      if (!("known" in source)) setPick(null); // a pick is single use in Rust: the next try needs the dialog again
    } finally {
      setBusy(false);
    }
  };

  const chooseSource = (f: ImportFormat) => {
    setFormat(f);
    setPick(null);
    setKnown(null);
    setOptions(OPTIONS_OFF);
    setError(null);
    setStep("file");
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
    setFormat(k);
    setPick(null);
    setKnown(k);
    setOptions(OPTIONS_OFF);
    setStep("file");
    await run({ known: k }, OPTIONS_OFF);
  };

  const source = (): ImportSource | null => (known ? { known } : pick ? { pickId: pick.pickId } : null);

  const runPreview = async () => {
    const s = source();
    if (s) await run(s, options);
  };

  /** An opt-in change re-runs the preview with the same source (a pick is single use, so the known location re-runs; a file needs a new pick). */
  const setOption = async (key: keyof ImportOptions, on: boolean) => {
    const next = { ...options, [key]: on };
    setOptions(next);
    if (known) await run({ known }, next);
    else if (format) {
      // The pick was consumed by the first preview: ask Rust for the file again.
      setBusy(true);
      try {
        const p = await ipc.importPick({ format });
        if (!p) { setBusy(false); return; }
        setPick(p);
        await run({ pickId: p.pickId }, next);
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
      if (isIpcError(e) && e.code === "import.plan_expired") { livePlan.current = null; setPreview(null); setStep("file"); }
    } finally {
      setBusy(false);
    }
  };

  const back = () => {
    setError(null);
    if (step === "preview") { discard(); setPreview(null); setStep("file"); }
    else if (step === "file") { setFormat(initial); setPick(null); setKnown(null); setStep("source"); }
  };

  return {
    formats, format, info, step, pick, known, options, preview, excluded, skipDuplicates, report, busy, error,
    chooseSource, pickFile, readKnownLocation, runPreview, setOption, toggle, setAll, setSkipDuplicates, apply, back, discard,
  };
}

export type ImportWizardState = ReturnType<typeof useImportWizard>;
