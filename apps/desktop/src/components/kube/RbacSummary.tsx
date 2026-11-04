import type { KubeAccess, KubeIdentity } from "../../lib/ipc";
import { ACCESS_ROWS } from "./podStatus";

/** What the token may do (SelfSubjectReview + five SelfSubjectAccessReviews, ADR-0014 §5). */
export function RbacSummary({ identity, namespace, access }: { identity: KubeIdentity | null; namespace: string | null; access: KubeAccess | null }) {
  return (
    <section aria-label="Token permissions" className="kube-card m-hud">
      <h3 className="m-micro">Token permissions</h3>
      <dl className="kube-ident">
        <dt>Signed in as</dt>
        <dd className="mono select-text">{identity?.user ?? "unknown (reopen the cluster tab to refresh)"}</dd>
        {identity && identity.groups.length > 0 && (
          <>
            <dt>Groups</dt>
            <dd className="mono select-text">{identity.groups.join(", ")}</dd>
          </>
        )}
      </dl>
      <p className="field-hint">{namespace ? <>In <span className="mono">{namespace}</span>:</> : "Choose a namespace."}</p>
      <ul className="kube-rbac" aria-label={`Permissions in ${namespace ?? "no namespace"}`}>
        {ACCESS_ROWS.map((r) => {
          const ok = access?.[r.key];
          return (
            <li key={r.key} data-allowed={ok === true || undefined} title={r.verb}>
              <span aria-hidden className="kube-rbac-dot" />
              <span className="flex-1">{r.label}</span>
              <span className="kube-rbac-state">{access === null ? "…" : ok ? "Allowed" : "Denied"}</span>
            </li>
          );
        })}
      </ul>
      <p className="field-hint">RBAC is the cluster's policy. Mooring adds its own: no request that creates, changes or deletes an API object ever leaves this machine.</p>
    </section>
  );
}
