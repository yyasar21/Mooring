// ADR-0016 §4 sign-in through the isolated OIDC window (E2): `secret_source_oidc_begin` opens
// `oidc-<id>`, the UI polls `secret_source_oidc_status` (passive) every second until the flow
// leaves `pending`, then runs `secret_source_test` once so the card shows the real outcome. The
// window never talks to this code; the token never reaches it.
import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, type SecretSourceTest } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

export const OIDC_POLL_MS = 1000;

export type OidcPhase =
  | { kind: "idle" }
  | { kind: "waiting"; sourceId: string; sessionId: string; since: number }
  | { kind: "testing"; sourceId: string }
  | { kind: "done"; sourceId: string; test: SecretSourceTest }
  | { kind: "failed"; sourceId: string; reason: string };

/** Plain text for the fixed OIDC failure reasons; anything else is an `external_unavailable` category. */
export function oidcFailureText(error: string | null): string {
  switch (error) {
    case "timeout":
      return "The sign-in window timed out after 5 minutes. Start again when you are ready.";
    case "closed":
      return "The sign-in window was closed before the identity provider answered.";
    case "locked":
      return "The vault was locked during the sign-in, so the flow was abandoned.";
    case "exit":
      return "Mooring was shutting down, so the sign-in was abandoned.";
    case "state_mismatch":
      return "The identity provider returned a response for a different sign-in (state mismatch). Nothing was accepted.";
    case "network":
      return "Vault did not answer the callback (network).";
    case "tls":
      return "The TLS connection to Vault was refused (certificate not trusted).";
    case "auth_failed":
      return "Vault rejected the sign-in (role, redirect URI or identity provider configuration).";
    case "forbidden":
      return "Vault refused the callback: the role denies this identity.";
    case null:
      return "The sign-in failed.";
    default:
      return `The sign-in failed (${error}).`;
  }
}

export function useOidcLogin() {
  const [phase, setPhase] = useState<OidcPhase>({ kind: "idle" });
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const stop = useCallback(() => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
  }, []);
  useEffect(() => stop, [stop]);

  // The poll only reads the passive status; the one-off test runs here, once the flow is done.
  useEffect(() => {
    if (phase.kind !== "testing") return;
    const { sourceId } = phase;
    let live = true;
    ipc.secretSourceTest({ id: sourceId }).then(
      (test) => { if (live) setPhase({ kind: "done", sourceId, test }); },
      (e: unknown) => { if (live) setPhase({ kind: "failed", sourceId, reason: describeError(e) }); },
    );
    return () => { live = false; };
  }, [phase]);

  const begin = useCallback(async (sourceId: string) => {
    stop();
    let sessionId: string;
    try {
      ({ sessionId } = await ipc.secretSourceOidcBegin({ id: sourceId }));
    } catch (e: unknown) {
      setPhase({ kind: "failed", sourceId, reason: describeError(e) });
      return;
    }
    setPhase({ kind: "waiting", sourceId, sessionId, since: Date.now() });
    let inFlight = false;
    timer.current = setInterval(() => {
      if (inFlight) return;
      inFlight = true;
      void ipc.secretSourceOidcStatus({ sessionId }).then(
        (s) => {
          inFlight = false;
          if (s.state === "pending") return;
          stop();
          setPhase(s.state === "failed" ? { kind: "failed", sourceId, reason: oidcFailureText(s.error) } : { kind: "testing", sourceId });
        },
        (e: unknown) => {
          inFlight = false;
          stop();
          setPhase({ kind: "failed", sourceId, reason: describeError(e) });
        },
      );
    }, OIDC_POLL_MS);
  }, [stop]);

  const clear = useCallback(() => { stop(); setPhase({ kind: "idle" }); }, [stop]);

  return { phase, begin, clear };
}
