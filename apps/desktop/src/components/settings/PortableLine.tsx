import { useEffect, useState } from "react";

/** The Settings → Updates helper when the build is portable (ADR-0021 §2); the exact text Rust sends with `update.manual_only`. */
export const PORTABLE_UPDATE_TEXT = "portable build: download the new zip and replace the folder";

/**
 * "Portable build — data in <path>" (ADR-0021 §1), shown by About and Settings → Updates when
 * `app_info.portableDataDir` is set. The path is monospace, selectable and copyable like the
 * About links; nothing opens a file manager (no opener capability).
 */
export function PortableLine({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => { setCopied(false); }, 1800);
    return () => { clearTimeout(t); };
  }, [copied]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="portable-line" data-testid="portable-line">
      <span className="portable-line-label">Portable build — data in{" "}</span>
      <code className="about-link-url" title={path}>{path}</code>
      <button type="button" className="btn btn-ghost" onClick={() => void copy()} aria-label="Copy portable data folder path">
        {copied ? "Copied" : "Copy"}
      </button>
      <span role="status" className="sr-only">{copied ? "Path copied." : ""}</span>
    </div>
  );
}
