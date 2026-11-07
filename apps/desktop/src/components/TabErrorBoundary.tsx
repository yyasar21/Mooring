import { Component, type ReactNode } from "react";

interface Props {
  /** Shown in the fallback, e.g. "the terminal". */
  what: string;
  onClose?: () => void;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Keeps a failure inside one session tab. Without it, an error while rendering or loading a tab's
 * view (a lazy chunk that throws at import, a renderer bug) unmounts the whole React root and the
 * window goes blank — the SSH "Connect" report of 2026-11-07. The message is a code or library
 * error, never session data, so it is safe to show.
 */
export class TabErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" className="panel-note m-hud" data-testid="tab-error">
        <div className="max-w-md">
          <p className="m-micro" style={{ color: "var(--hot)" }}>View failed</p>
          <p className="mt-2 text-text-muted">Mooring could not display {this.props.what}. The rest of the app keeps working.</p>
          <p className="readout-host mt-2 select-text break-all">{error.message}</p>
          <div className="mt-4 flex gap-2">
            <button type="button" className="btn" onClick={() => { this.setState({ error: null }); }}>
              Try again
            </button>
            {this.props.onClose && (
              <button type="button" className="btn" onClick={this.props.onClose}>
                Close tab
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }
}
