// L1: the connection dialog's sections and its inline validation, kept free of React so the
// rules are tested on their own.
import type { Protocol } from "../../lib/ipc";
import { supportsVia } from "../../lib/via";

export type ConnSection = "general" | "signin" | "gateway" | "display" | "advanced";
export const SECTION_LABEL: Record<ConnSection, string> = {
  general: "General",
  signin: "Sign-in",
  gateway: "Gateway",
  display: "Display",
  advanced: "Advanced",
};

/** Which section holds a protocol's own options: what it shows (RDP, VNC, web) or how it is reached. */
export function optionsSection(protocol: Protocol): "display" | "advanced" | null {
  if (protocol === "rdp" || protocol === "vnc" || protocol === "web") return "display";
  if (protocol === "kubernetes" || protocol === "vsphere-console") return "advanced";
  return null;
}

/** The sections a protocol has, in nav order. Gateway = jump hosts and the RD Gateway credential. */
export function sectionsFor(protocol: Protocol, synced: boolean): ConnSection[] {
  const out: ConnSection[] = ["general", "signin"];
  if (supportsVia(protocol) || protocol === "rdp") out.push("gateway");
  const opts = synced ? null : optionsSection(protocol);
  if (opts === "display") out.push("display");
  if (opts === "advanced") out.push("advanced");
  return out;
}

export type ConnField = "name" | "host" | "port" | "options";

/** The input each field error points at (for focus and `aria-describedby`). */
export const FIELD_INPUT: Record<ConnField, string> = { name: "conn-name", host: "conn-host", port: "conn-port", options: "conn-options" };

export interface ConnFormState {
  name: string;
  host: string;
  port: string;
  optionsValid: boolean;
  /** Kubernetes: the credential fits the server / CA fields. */
  fitOk: boolean;
}

/** Field errors in form order, as one sentence each. Empty when the form can be saved. */
export function connErrors(s: ConnFormState): Partial<Record<ConnField, string>> {
  const out: Partial<Record<ConnField, string>> = {};
  if (s.name.trim() === "") out.name = "Enter a name for the connection.";
  if (s.host.trim() === "") out.host = "Enter a host name or IP address.";
  const port = s.port.trim() === "" ? null : Number(s.port);
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) out.port = "Port must be 1 to 65535.";
  if (!s.optionsValid || !s.fitOk) out.options = "Fix the highlighted options.";
  return out;
}

/** The section that shows a field. */
export function sectionOf(field: ConnField, protocol: Protocol): ConnSection {
  return field === "options" ? (optionsSection(protocol) ?? "general") : "general";
}

/** "Fix 1 field to continue" / "Fix 3 fields to continue". */
export function summaryText(count: number): string {
  return `Fix ${String(count)} field${count === 1 ? "" : "s"} to continue`;
}
