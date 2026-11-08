import { useMemo, useState } from "react";
import { DataTable, Icon, type DataColumn, type SortState } from "@mooring/ui";
import type { CredentialKind, CredentialMeta, KindSchema } from "../../lib/ipc";
import { accountSummary, usedByCount } from "../../lib/credentials";
import { kindLabel } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { KindBadge } from "./fields";

/** The filter chips over the list (design review §4, credential-detail mockup). */
export type KindGroup = "all" | "passwords" | "keys" | "domain" | "external";
export const GROUP_LABEL: Record<KindGroup, string> = { all: "All", passwords: "Passwords", keys: "Keys", domain: "Domain", external: "External" };
const GROUP_KINDS: Record<Exclude<KindGroup, "all">, readonly CredentialKind[]> = {
  passwords: ["user_password", "vnc_password", "vnc_user_password", "prompt", "sudo_become", "vsphere_user"],
  keys: ["ssh_key", "ssh_agent", "ssh_sk_key", "smart_card", "x509", "kubeconfig", "kube_token", "api_token", "oauth_client", "s3_access_key"],
  domain: ["domain_user"],
  external: ["external_ref", "vault_approle", "bitwarden_access_token"],
};
export const inGroup = (kind: CredentialKind, g: KindGroup): boolean => g === "all" || GROUP_KINDS[g].includes(kind);

const SORT_TEXT: Record<string, string> = { name: "name", kind: "type", account: "account", used: "use", updated: "last change" };

/** Row name: the text the old list button carried (kind, name, account, uses), so queries keep matching. */
export function credentialRowLabel(c: CredentialMeta, kinds: KindSchema[], used: number): string {
  return `${kindLabel(kinds, c.kind)} ${c.name} ${accountSummary(c) || "no account"}${c.fingerprint ? ` ${c.fingerprint}` : ""} ${String(used)} used`;
}

function shortDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

/**
 * L2 / M5: the stored credentials as a sortable grid with a filter field and kind chips. A row
 * selects its credential; each row keeps "Delete <name>" with the two-step confirm in place.
 */
export function CredentialsTable({ items, kinds, selected, onSelect, onDelete }: {
  items: CredentialMeta[];
  kinds: KindSchema[];
  selected: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => Promise<boolean>;
}) {
  const connections = useTree((s) => s.connections);
  const folders = useTree((s) => s.folders);
  const [filter, setFilter] = useState("");
  const [group, setGroup] = useState<KindGroup>("all");
  const [sort, setSort] = useState<SortState>({ column: "name", dir: "ascending" });
  const [confirm, setConfirm] = useState<string | null>(null);
  const defaults = useMemo(() => folders.map((f) => f.defaultCredentialId), [folders]);
  const used = (c: CredentialMeta) => usedByCount(c.id, connections, defaults);

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return items.filter((c) => inGroup(c.kind, group) && (!q || [c.name, c.kind, kindLabel(kinds, c.kind), accountSummary(c), c.fingerprint ?? ""].some((v) => v.toLowerCase().includes(q))));
  }, [items, kinds, filter, group]);

  const columns: DataColumn<CredentialMeta>[] = [
    {
      id: "name", header: "Name", width: "28%", sortValue: (c) => c.name,
      cell: (c) => (
        <span className="cred-name">
          <KindBadge kind={c.kind} kinds={kinds} decorative />
          <span className="truncate">{c.name}</span>
        </span>
      ),
    },
    { id: "kind", header: "Type", width: "22%", className: "text-text-muted", cell: (c) => kindLabel(kinds, c.kind), sortValue: (c) => kindLabel(kinds, c.kind) },
    { id: "account", header: "Account", className: "mono", cell: (c) => accountSummary(c) || <span className="text-text-faint">—</span>, sortValue: accountSummary },
    { id: "used", header: "Used by", width: "84px", numeric: true, cell: used, sortValue: used },
    { id: "updated", header: "Updated", width: "84px", className: "text-text-muted tnum", cell: (c) => shortDate(c.updatedAt), sortValue: (c) => c.updatedAt },
    {
      id: "actions", header: "Actions", hideHeader: true, width: "128px", className: "cred-actions",
      cell: (c) =>
        confirm === c.id ? (
          <button type="button" className="btn btn-sm btn-danger" onClick={(e) => { e.stopPropagation(); void onDelete(c.id).then(() => { setConfirm(null); }); }}>
            Confirm delete
          </button>
        ) : (
          <button type="button" className="icon-btn icon-btn-sm cred-del" aria-label={`Delete ${c.name}`} title="Delete" onClick={(e) => { e.stopPropagation(); setConfirm(c.id); }}>
            <Icon name="x" size={14} />
          </button>
        ),
    },
  ];

  return (
    <>
      <div className="cred-filters">
        <span className="cred-filter-field">
          <Icon name="search" size={14} />
          <input
            aria-label="Filter credentials"
            className="field"
            placeholder="Filter by name, kind, account or fingerprint"
            value={filter}
            onChange={(e) => { setFilter(e.target.value); }}
            onKeyDown={(e) => { if (e.key === "Escape" && filter) { e.stopPropagation(); setFilter(""); } }}
          />
        </span>
        <div role="radiogroup" aria-label="Kind" className="segmented">
          {(Object.keys(GROUP_LABEL) as KindGroup[]).map((g) => (
            <button key={g} type="button" role="radio" aria-checked={group === g} data-checked={group === g || undefined} onClick={() => { setGroup(g); }}>
              {GROUP_LABEL[g]}
            </button>
          ))}
        </div>
        <span className="cred-sorted" aria-live="polite">Sorted by {SORT_TEXT[sort.column] ?? sort.column}</span>
      </div>
      <DataTable
        label="Stored credentials"
        className="cred-table"
        columns={columns}
        rows={shown}
        rowKey={(c) => c.id}
        rowLabel={(c) => credentialRowLabel(c, kinds, used(c))}
        rowAttrs={() => ({ "data-row": "credential" })}
        selected={selected}
        onSelect={(id) => { setConfirm(null); onSelect(id); }}
        defaultSort={sort}
        onSortChange={setSort}
        empty={items.length === 0 ? "No credentials yet. Create one to attach it to folders and connections." : "No credential matches the filter."}
      />
    </>
  );
}
