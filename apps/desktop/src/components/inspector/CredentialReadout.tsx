import type { ReactNode } from "react";
import type { ConnectionSummary, CredentialMeta, KindSchema } from "../../lib/ipc";
import { accountSummary, credentialValidFor, supportsOverride } from "../../lib/credentials";
import { kindLabel, useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { Fingerprint, KindBadge } from "../credentials/fields";
import { CopySecret } from "./CopySecret";

/**
 * Effective credential of a connection with one row per role (sign-in, RD Gateway, become) and the
 * account after overrides. References only: kind, account, fingerprint, which secrets exist.
 */
export function ConnectionCredentials({ c, inheritedFrom }: { c: ConnectionSummary; inheritedFrom: string | null }) {
  const items = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  const primary = items.find((x) => x.id === c.effectiveCredentialId);
  const gateway = items.find((x) => x.id === c.gatewayCredentialId);
  const become = items.find((x) => x.id === c.becomeCredentialId);
  const compat = primary ? credentialValidFor(kinds, primary, c.protocol, "primary") : null;

  return (
    <div className="space-y-2">
      <RoleCard role="Sign-in" cred={primary} kinds={kinds} from={inheritedFrom} c={c} problem={compat && !compat.ok ? compat.reason : null}>
        {!primary && <p className="text-text-faint">None. The session will ask when it connects.</p>}
      </RoleCard>
      {c.protocol === "rdp" && (
        <RoleCard role="RD Gateway" cred={gateway} kinds={kinds} from={null} c={null} problem={null}>
          {!gateway && <p className="text-text-faint">Same as the sign-in credential.</p>}
        </RoleCard>
      )}
      {c.protocol === "ssh" && (become || c.becomeCredentialId) && (
        <RoleCard role="Become" cred={become} kinds={kinds} from={null} c={null} problem={null} />
      )}
    </div>
  );
}

export function FolderCredential({ id }: { id: string | null }) {
  const cred = useCredentials((s) => s.items.find((x) => x.id === id));
  const kinds = useCredentials((s) => s.kinds);
  return (
    <RoleCard role="Default" cred={cred} kinds={kinds} from={null} c={null} problem={null}>
      {!cred && <p className="text-text-faint">None. Connections below inherit from further up, or ask.</p>}
    </RoleCard>
  );
}

function RoleCard({
  role,
  cred,
  kinds,
  from,
  c,
  problem,
  children,
}: {
  role: string;
  cred: CredentialMeta | undefined;
  kinds: KindSchema[];
  from: string | null;
  /** Set for the sign-in row: overrides apply to it. */
  c: ConnectionSummary | null;
  problem: string | null;
  children?: ReactNode;
}) {
  const show = useUi((s) => s.showCredentials);
  const userOv = c && cred && supportsOverride(cred.kind, "username") ? c.usernameOverride : null;
  const domainOv = c && cred && supportsOverride(cred.kind, "domain") ? c.domainOverride : null;
  return (
    <div className="cred-card m-hud" data-tone={problem ? "hot" : undefined} aria-label={`${role} credential`} role="group">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="role-tag">{role}</span>
        {cred && <KindBadge kind={cred.kind} kinds={kinds} />}
        {cred && (
          <button type="button" className="cred-link min-w-0 flex-1 truncate text-left" onClick={() => { show({ mode: "edit", id: cred.id }); }}>
            {cred.name}
          </button>
        )}
      </div>
      {children}
      {cred && (
        <>
          <dl className="prop-grid">
            <Prop k="Kind">{kindLabel(kinds, cred.kind)}</Prop>
            <Prop k="Account" mono>
              {userOv || domainOv ? (
                <span title="Overridden for this connection">
                  {accountSummary(withOverrides(cred, userOv, domainOv))}
                  <span className="ov-tag">override</span>
                </span>
              ) : (
                accountSummary(cred) || "none"
              )}
            </Prop>
            {cred.fingerprint && <Prop k="Key"><Fingerprint value={cred.fingerprint} /></Prop>}
            {from && <Prop k="From">folder {from}</Prop>}
            <Prop k="Secrets">
              {cred.secretNames.length ? <span className="mono text-text-muted">{cred.secretNames.join(", ")}</span> : <span className="text-text-faint">none stored</span>}
            </Prop>
          </dl>
          {problem && <p className="mt-1.5 text-[length:var(--fs-xs)] text-hot" role="note">{problem}</p>}
          <div className="pt-2.5">
            <CopySecret meta={cred} kinds={kinds} />
          </div>
        </>
      )}
    </div>
  );
}

/** The account as the resolver will use it: overrides replace username/user and domain (ADR-0009 §3). */
function withOverrides(cred: CredentialMeta, user: string | null, domain: string | null): CredentialMeta {
  const fields = { ...cred.fields };
  if (user) fields[cred.kind === "domain_user" ? "user" : "username"] = user;
  if (domain) fields.domain = domain;
  return { ...cred, fields };
}

function Prop({ k, mono, children }: { k: string; mono?: boolean; children: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd className={mono ? "mono select-text" : ""}>{children}</dd>
    </>
  );
}
