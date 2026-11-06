import { useEffect, useState } from "react";
import { useOnboarding } from "../../stores/onboarding";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { ABOUT_LINKS } from "../settings/AboutCard";

const GUIDE = ABOUT_LINKS.find((l) => l.label === "User guide")?.url ?? "";

/**
 * First-run card (ADR-0019 §6) on the empty tree after the first unlock: start from scratch (the
 * connection dialog), import from another tool (the wizard on its source grid), or copy the user
 * guide link (no opener capability in the main window, as in About). "Not now" remembers the
 * dismissal per vault; a tree with a connection never shows it again.
 */
export function OnboardingCard() {
  const load = useOnboarding((s) => s.load);
  const dismiss = useOnboarding((s) => s.dismiss);
  const folders = useTree((s) => s.folders);
  const setImporting = useOnboarding((s) => s.setImporting);
  const [copied, setCopied] = useState(false);

  useEffect(() => { void load(); }, [load]);

  const startEmpty = () => {
    const root = folders.find((f) => f.parentId === null);
    dismiss();
    if (root) useUi.getState().openDialog({ kind: "connection", folderId: root.id });
  };

  const copyGuide = async () => {
    try {
      await navigator.clipboard.writeText(GUIDE);
      setCopied(true);
      setTimeout(() => { setCopied(false); }, 1800);
    } catch {
      // clipboard refused: the button stays as it was
    }
  };

  return (
    <section className="onboard m-hud" aria-labelledby="onboard-title" data-active>
      <p className="onboard-kicker">First run</p>
      <h2 id="onboard-title" className="onboard-title">Nothing is moored here yet</h2>
      <p className="onboard-lead">
        This vault is empty. Add your first host by hand, bring the connections you already keep in another tool, or read how Mooring works first.
      </p>
      <ul className="onboard-paths">
        <li>
          <button type="button" className="onboard-path" onClick={startEmpty} autoFocus>
            <span className="onboard-path-name">Start from scratch</span>
            <span className="onboard-path-hint">Open the new-connection dialog and add a host.</span>
          </button>
        </li>
        <li>
          <button type="button" className="onboard-path" onClick={() => { setImporting(true); }}>
            <span className="onboard-path-name">Import from another tool</span>
            <span className="onboard-path-hint">Royal TS, Remote Desktop Manager, Termius, mRemoteNG, PuTTY or an ssh config.</span>
          </button>
        </li>
        <li>
          <button type="button" className="onboard-path" onClick={() => void copyGuide()} aria-label="Copy User guide link">
            <span className="onboard-path-name">{copied ? "Link copied" : "Read the user guide"}</span>
            <span className="onboard-path-hint">Copies the guide's address; open it in your browser.</span>
          </button>
        </li>
      </ul>
      <div className="onboard-foot">
        <p className="onboard-status" role="status">{copied ? "Link copied." : ""}</p>
        <button type="button" className="btn btn-ghost" onClick={dismiss}>Not now</button>
      </div>
    </section>
  );
}
