import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "@mooring/ui";
import type { CredentialRole, KubeConnOptions, Protocol, VncConnOptions } from "../../lib/ipc";
import { supportsVia } from "../../lib/via";
import { kubeCredentialFit } from "../../lib/validate.kube";
import { credentialValidFor, isSshSignRef, supportsOverride } from "../../lib/credentials";
import { ipc } from "../../lib/ipc";
import { folderPath, hopUsers, useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { useSessions } from "../../stores/sessions";
import { useToasts } from "../../stores/toast";
import { useUi, type ConnectionDraft } from "../../stores/ui";
import { CredentialPicker, gatewayPickerOptions, pickerOptions } from "../credentials/CredentialPicker";
import { Modal } from "./Modal";
import { FieldError, FormSection, PROTOCOLS, ProtocolCards, SectionNav, sectionHeadingId } from "./ConnectionParts";
import { FIELD_INPUT, connErrors, optionsSection, sectionOf, sectionsFor, summaryText, type ConnField, type ConnSection } from "./connectionForm";
import { SignInFields } from "./SignInFields";
import { ProtocolOptionsSection, useOptionsDraft } from "./options/ProtocolOptionsSection";
import { useConnOptions } from "../../stores/connOptions";
import { describeError } from "../../stores/errors";
import { READONLY_REASON } from "../vsphere/vsphere";
import { ViaSection } from "./ViaSection";

/** Nearest folder default credential above `folderId` (the inheritance rule of ADR-0005). */
function inheritedId(folders: { id: string; parentId: string | null; defaultCredentialId: string | null }[], folderId: string): string | null {
  let cur = folders.find((f) => f.id === folderId);
  while (cur) {
    if (cur.defaultCredentialId) return cur.defaultCredentialId;
    const p = cur.parentId;
    cur = folders.find((f) => f.id === p);
  }
  return null;
}

/** Select a saved connection in the tree, open its ancestors and the DETAILS panel (U0). */
export function revealConnection(id: string, folderId: string): void {
  const t = useTree.getState();
  const open = new Set<string>();
  let cur = t.folders.find((f) => f.id === folderId);
  while (cur) {
    open.add(cur.id);
    const p = cur.parentId;
    cur = t.folders.find((f) => f.id === p);
  }
  useTree.setState({ collapsed: Object.fromEntries(Object.entries(t.collapsed).filter(([k]) => !open.has(k))) });
  t.select({ kind: "connection", id });
  useUi.setState({ inspectorOpen: true });
}

/**
 * Create or edit a connection (L1): a left section nav (General, Sign-in, Gateway, Display or
 * Advanced) over one scrolling form, the protocol as radio cards, inline validation with a
 * summary in the footer that takes focus to the first problem, and "Create and connect".
 * Credentials are chosen by reference; secrets never appear here.
 */
export function ConnectionDialog({ id, folderId, onClose }: { id?: string; folderId: string; onClose: () => void }) {
  // After a create whose options failed to save, further submits update that row (no duplicates).
  const [createdId, setCreatedId] = useState<string | undefined>(undefined);
  const existing = useTree((s) => s.connections.find((c) => c.id === (id ?? createdId)));
  const folders = useTree((s) => s.folders);
  const creds = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  // U0: back from a "New…" credential, the form reopens with its draft and the new credential picked.
  // Peeked here (StrictMode runs initializers twice) and cleared after mount.
  const [resume] = useState(() => useUi.getState().connectionResume);
  useEffect(() => { if (resume) useUi.getState().takeConnectionResume(); }, [resume]);
  const r: ConnectionDraft | undefined = resume?.draft;
  const picked = (role: CredentialRole) => (resume?.pick?.role === role ? resume.pick.id : undefined);
  const [name, setName] = useState(r?.name ?? existing?.name ?? "");
  const [protocol, setProtocol] = useState<Protocol>(r?.protocol ?? existing?.protocol ?? "ssh");
  const [host, setHost] = useState(r?.host ?? existing?.host ?? "");
  const [port, setPort] = useState(r?.port ?? existing?.port?.toString() ?? "");
  const [folder, setFolder] = useState(r?.folder ?? existing?.folderId ?? folderId);
  const [cred, setCred] = useState(picked("primary") ?? r?.cred ?? existing?.credentialId ?? "");
  const [userOv, setUserOv] = useState(r?.userOv ?? existing?.usernameOverride ?? "");
  const [domainOv, setDomainOv] = useState(r?.domainOv ?? existing?.domainOverride ?? "");
  const [gateway, setGateway] = useState(picked("gateway") ?? r?.gateway ?? existing?.gatewayCredentialId ?? "");
  const [become, setBecome] = useState(picked("become") ?? r?.become ?? existing?.becomeCredentialId ?? "");
  const [certificate, setCertificate] = useState(picked("certificate") ?? r?.certificate ?? existing?.certificateCredentialId ?? "");
  const [tags, setTags] = useState(r?.tags ?? existing?.tags.join(" ") ?? "");
  const [via, setVia] = useState<string[]>(r?.via ?? existing?.via ?? []);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState<ReadonlySet<ConnField>>(new Set());
  const [submitted, setSubmitted] = useState(false);
  const [active, setActive] = useState<ConnSection>("general");
  const bodyRef = useRef<HTMLDivElement>(null);
  const edited = useRef(new Set<ConnField>());
  const options = useOptionsDraft(id, existing?.protocol, protocol, r?.options);
  // ADR-0015: a synced VM row keeps name, host, port, protocol and folder from vCenter (`tree.synced_readonly`).
  const synced = !!existing?.syncSource;

  const portNum = port.trim() === "" ? null : Number(port);
  const defaultPort = PROTOCOLS.find((p) => p.value === protocol)?.port;

  const inherited = creds.find((c) => c.id === inheritedId(folders, folder));
  const effective = creds.find((c) => c.id === (cred || inherited?.id));
  const inheritedOk = inherited ? credentialValidFor(kinds, inherited, protocol, "primary") : null;

  const primaryOptions = useMemo(
    () =>
      pickerOptions(
        creds,
        kinds,
        protocol,
        "primary",
        "Inherit from folder",
        inherited ? `${inherited.name}${inheritedOk && !inheritedOk.ok ? " — not usable here" : ""}` : "none set: the session will ask",
      ),
    [creds, kinds, protocol, inherited, inheritedOk],
  );
  const gatewayOptions = useMemo(
    () => gatewayPickerOptions(pickerOptions(creds, kinds, protocol, "gateway", "Same as sign-in", "the RD Gateway gets the sign-in above")),
    [creds, kinds, protocol],
  );
  const becomeOptions = useMemo(
    () => pickerOptions(creds, kinds, protocol, "become", "None", "no privilege escalation after login"),
    [creds, kinds, protocol],
  );

  // ADR-0026: only Vault SSH sign references are offered; the role is saved on its own command.
  const certificateOptions = useMemo(
    () => pickerOptions(creds.filter(isSshSignRef), kinds, protocol, "certificate", "None", "the key signs in without a Vault certificate"),
    [creds, kinds, protocol],
  );

  const pick = (v: string, opts: { value: string; disabledReason: string | null }[]) =>
    opts.find((o) => o.value === v && !o.disabledReason) ? v : "";
  // Changing protocol drops choices that became incompatible instead of failing on save.
  const primary = pick(cred, primaryOptions);
  const gw = protocol === "rdp" ? pick(gateway, gatewayOptions) : "";
  const bc = protocol === "ssh" ? pick(become, becomeOptions) : "";
  const cert = protocol === "ssh" ? pick(certificate, certificateOptions) : "";
  const canUser = effective ? supportsOverride(effective.kind, "username") : true;
  const canDomain = effective ? supportsOverride(effective.kind, "domain") : true;
  const dropped = (cred && !primary) || (gateway && protocol === "rdp" && !gw) || (become && protocol === "ssh" && !bc);
  // ADR-0014 §3: server/CA are required with a token and refused with a kubeconfig.
  const fit = protocol === "kubernetes" ? kubeCredentialFit(options.value as KubeConnOptions, effective?.kind) : {};
  const fitOk = Object.keys(fit).length === 0;

  // ADR-0027: the existing gateway role. The RD Gateway options (host, port, Basic) are in the RDP options section.
  const gatewayPicker = (
    <div className="flex items-start gap-2">
      <div className="min-w-0 flex-1">
        <CredentialPicker label="RD Gateway credential" value={gw} options={gatewayOptions} kinds={kinds} onChange={setGateway}
          hint="Same as sign-in sends this connection's sign-in to the gateway too. Only a user and password or a Windows domain account can sign in to a gateway." />
      </div>
      <button type="button" className="btn mt-[26px]" aria-label="New RD Gateway credential…" onClick={() => { newCredential("gateway"); }}>
        New…
      </button>
    </div>
  );

  async function submit(connect: boolean) {
    setBusy(true);
    const fields = {
      folderId: folder,
      name: name.trim(),
      protocol,
      host: host.trim(),
      port: portNum,
      credentialId: primary || null,
      usernameOverride: canUser && userOv.trim() ? userOv.trim() : null,
      domainOverride: canDomain && domainOv.trim() ? domainOv.trim() : null,
      gatewayCredentialId: gw || null,
      becomeCredentialId: bc || null,
      tags: tags.split(/[\s,]+/).filter(Boolean),
      // ADR-0025: the form owns the chain, so it always sends it ([] clears it).
      via: supportsVia(protocol) ? via : [],
    };
    const t = useTree.getState();
    const saved = existing ? await t.updateConnection(existing.id, fields) : await t.createConnection(fields);
    if (!saved) {
      setBusy(false);
      setError(useTree.getState().error ?? "could not save the connection");
      return;
    }
    if (!existing) setCreatedId(saved.id);
    if (cert !== (saved.certificateCredentialId ?? "")) {
      try {
        await ipc.connectionSetRoleCredential({ id: saved.id, role: "certificate", credentialId: cert || null });
        await useTree.getState().load();
      } catch (e: unknown) {
        setBusy(false);
        setError(`The connection was saved, but its certificate was not: ${describeError(e)}`);
        return;
      }
    }
    // ADR-0011: options travel on their own command, after the row exists.
    if (options.shouldSave) {
      try {
        await useConnOptions.getState().save(saved.id, protocol, options.value);
      } catch (e: unknown) {
        setBusy(false);
        setError(`The connection was saved, but its ${protocol.toUpperCase()} options were not: ${describeError(e)}`);
        return;
      }
    }
    setBusy(false);
    revealConnection(saved.id, saved.folderId);
    useToasts.getState().push(existing ? "Connection saved" : "Connection created", { detail: saved.name });
    onClose();
    if (connect) {
      useUi.getState().setView("workspace");
      void useSessions.getState().open(saved.id);
    }
  }

  /** "New…" next to a picker: leave for the credentials view, keeping everything typed so far. */
  function newCredential(role: CredentialRole) {
    const draft: ConnectionDraft = { name, protocol, host, port, folder, cred, userOv, domainOv, gateway, become, certificate, tags, via, options: options.drafts };
    const conn = id ?? createdId;
    useUi.getState().showCredentials({
      mode: "new",
      protocol,
      returnTo: { dialog: { kind: "connection", ...(conn ? { id: conn } : {}), folderId }, role, draft },
    });
  }

  async function remove() {
    if (!existing) return;
    setBusy(true);
    for (const tab of useSessions.getState().tabs.filter((x) => x.connectionId === existing.id)) {
      await useSessions.getState().close(tab.id);
    }
    const users = hopUsers(useTree.getState().connections, existing.id).map((c) => c.name);
    const ok = await useTree.getState().deleteConnection(existing.id);
    setBusy(false);
    if (ok) onClose();
    else setError(`${useTree.getState().error ?? "could not delete the connection"}${users.length > 0 ? ` Used by: ${users.join(", ")}.` : ""}`);
  }

  const errors = connErrors({ name, host, port, optionsValid: options.valid, fitOk });
  const failing = (Object.keys(errors) as ConnField[]);
  const visible = (f: ConnField) => (submitted || touched.has(f) ? errors[f] : undefined);
  const sections = sectionsFor(protocol, synced);
  const invalid = new Set(failing.filter((f) => visible(f) !== undefined || (submitted && f === "options")).map((f) => sectionOf(f, protocol)));
  const touch = (f: ConnField) => { setTouched((t) => (t.has(f) ? t : new Set(t).add(f))); };
  // A field the user typed in is checked when they leave it; an untouched one waits for Create.
  const leave = (f: ConnField) => { if (edited.current.has(f)) touch(f); };
  const edit = (f: ConnField) => { edited.current.add(f); };
  const describedBy = (f: ConnField) => (visible(f) ? `${FIELD_INPUT[f]}-err` : undefined);
  const canConnect = !existing && protocol !== "vsphere-console";

  /** Focus the first field with an error (the footer summary does the same). */
  function focusFirstError(list: ConnField[] = failing) {
    const f = list[0];
    if (!f) return;
    const scope = bodyRef.current;
    const el = f === "options"
      ? scope?.querySelector<HTMLElement>(`[data-section="${sectionOf(f, protocol)}"] [aria-invalid="true"]`) ?? scope?.querySelector<HTMLElement>(`[data-section="${sectionOf(f, protocol)}"] input, [data-section="${sectionOf(f, protocol)}"] select`)
      : document.getElementById(FIELD_INPUT[f]);
    el?.focus();
    setActive(sectionOf(f, protocol));
  }

  /** Save, or show every error and go to the first one. */
  function attempt(connect: boolean) {
    if (busy || options.loading) return;
    if (failing.length > 0) {
      setSubmitted(true);
      focusFirstError();
      return;
    }
    void submit(connect);
  }

  /** The nav: scroll the section into view and focus its heading. */
  function go(s: ConnSection) {
    const h = document.getElementById(sectionHeadingId(s));
    h?.scrollIntoView({ block: "start", behavior: "smooth" });
    h?.focus({ preventScroll: true });
    setActive(s);
  }

  /** Scroll spy: the last section whose top has passed the top of the body. */
  function onScroll() {
    const body = bodyRef.current;
    if (!body) return;
    const top = body.getBoundingClientRect().top;
    let current: ConnSection = sections[0] ?? "general";
    for (const el of body.querySelectorAll<HTMLElement>("[data-section]")) {
      if (el.getBoundingClientRect().top - top <= 32) current = el.dataset.section as ConnSection;
    }
    setActive(current);
  }

  const optionsAt = optionsSection(protocol);
  const optionsBlock = !synced && <div id={FIELD_INPUT.options}><ProtocolOptionsSection draft={options} credential={effective} extraErrors={fit} /></div>;
  const footerText = submitted && failing.length > 0 ? null : error;

  return (
    <Modal title={synced ? "Edit VM overlays" : existing ? "Edit connection" : "New connection"} onClose={onClose} width={880}>
      <form
        className="conn-form"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          attempt(false);
        }}
      >
        <div className="conn-layout">
          <SectionNav sections={sections} active={sections.includes(active) ? active : "general"} invalid={invalid} onGo={go} />
          <div ref={bodyRef} className="conn-body" onScroll={onScroll}>
            <FormSection id="general">
              {synced && (
                <p className="field-hint" role="note">
                  {READONLY_REASON} Credential, overrides, tags and options are yours and survive refreshes.
                </p>
              )}
              <ProtocolCards value={protocol} disabled={synced} onChange={setProtocol} />
              <div>
                <label className="field-label" htmlFor="conn-name">Name</label>
                <input id="conn-name" data-autofocus className="field" value={name} maxLength={200} disabled={synced}
                  aria-invalid={visible("name") ? true : undefined} aria-describedby={describedBy("name")}
                  onBlur={() => { leave("name"); }} onChange={(e) => { edit("name"); setName(e.target.value); }} />
                <FieldError id="conn-name-err" text={visible("name")} />
              </div>
              <div className="grid grid-cols-[1fr_120px] gap-3">
                <div>
                  <label className="field-label" htmlFor="conn-host">Host</label>
                  <input id="conn-host" className="field mono" spellCheck={false} placeholder={protocol === "kubernetes" ? "https://k8s.example.test:6443" : "server.example.test"}
                    value={host} disabled={synced} aria-invalid={visible("host") ? true : undefined} aria-describedby={describedBy("host")}
                    onBlur={() => { leave("host"); }} onChange={(e) => { edit("host"); setHost(e.target.value); }} />
                  <FieldError id="conn-host-err" text={visible("host")} />
                </div>
                <div>
                  <label className="field-label" htmlFor="conn-port">Port</label>
                  <input id="conn-port" className="field mono" inputMode="numeric" placeholder={defaultPort?.toString() ?? "none"} disabled={synced}
                    aria-invalid={errors.port ? true : undefined} aria-describedby={errors.port ? "conn-port-err" : undefined}
                    value={port} onChange={(e) => { setPort(e.target.value); touch("port"); }} />
                  <FieldError id="conn-port-err" text={errors.port} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="field-label" htmlFor="conn-folder">Folder</label>
                  <select id="conn-folder" className="field" value={folder} disabled={synced} onChange={(e) => { setFolder(e.target.value); }}>
                    {folders.map((f) => (
                      <option key={f.id} value={f.id}>{folderPath(folders, f.id).join(" / ") || f.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="field-label" htmlFor="conn-tags">Tags</label>
                  <input id="conn-tags" className="field" placeholder="space or comma separated" value={tags} onChange={(e) => { setTags(e.target.value); }} />
                </div>
              </div>
            </FormSection>

            <FormSection id="signin">
              <SignInFields
                protocol={protocol} kinds={kinds} primary={primary} primaryOptions={primaryOptions} onPrimary={setCred}
                inherited={!primary ? inherited : undefined} inheritedProblem={inheritedOk && !inheritedOk.ok ? inheritedOk.reason : null}
                canUser={canUser} canDomain={canDomain} userOv={userOv} domainOv={domainOv} onUserOv={setUserOv} onDomainOv={setDomainOv}
                become={bc} becomeOptions={becomeOptions} onBecome={setBecome}
                certificate={cert} certificateOptions={certificateOptions} onCertificate={setCertificate}
                dropped={Boolean(dropped)} onNew={newCredential}
              />
            </FormSection>

            {sections.includes("gateway") && (
              <FormSection id="gateway">
                {protocol === "rdp" && gatewayPicker}
                <ViaSection
                  selfId={existing?.id ?? null}
                  protocol={protocol}
                  target={name.trim() || host.trim()}
                  via={via}
                  onChange={setVia}
                  vnc={protocol === "vnc" ? (options.value as Partial<VncConnOptions>) : null}
                />
              </FormSection>
            )}

            {/* ADR-0015: refresh, power and VMRC opt-ins belong to the vCenter connection, not to a VM row. */}
            {optionsAt && sections.includes(optionsAt) && <FormSection id={optionsAt}>{optionsBlock}</FormSection>}
          </div>
        </div>

        <div className="conn-footer">
          <p role="alert" className="conn-footer-msg">
            {submitted && failing.length > 0 ? (
              <button type="button" className="conn-summary" onClick={() => { focusFirstError(); }}>
                <Icon name="alert" size={14} />
                {summaryText(failing.length)}
              </button>
            ) : footerText}
          </p>
          {existing && !synced && (
            <button type="button" className="btn btn-ghost btn-danger" disabled={busy} onClick={() => void remove()}>
              Delete
            </button>
          )}
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          {canConnect && (
            <button type="button" className="btn" disabled={busy || options.loading} onClick={() => { attempt(true); }}>
              Create and connect
            </button>
          )}
          <button type="submit" className="btn btn-primary" disabled={busy || options.loading}>
            {synced ? "Save overlays" : existing ? "Save connection" : "Create connection"}
          </button>
        </div>
      </form>
    </Modal>
  );
}