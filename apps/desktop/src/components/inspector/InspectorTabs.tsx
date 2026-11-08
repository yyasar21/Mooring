import { SectionTabs, sectionPanelId, sectionTabId } from "../SectionTabs";

export type InspectorTab = "properties" | "network" | "history";

const LABEL: Record<InspectorTab, string> = { properties: "Properties", network: "Network", history: "History" };

export const tabId = (base: string, t: InspectorTab) => sectionTabId(base, t);
export const panelId = (base: string, t: InspectorTab) => sectionPanelId(base, t);

/** The inspector's section tabs (M4), on the shared `SectionTabs`. */
export function InspectorTabs({ base, tabs, value, onChange }: { base: string; tabs: readonly InspectorTab[]; value: InspectorTab; onChange: (t: InspectorTab) => void }) {
  return <SectionTabs base={base} label="Details sections" tabs={tabs} labels={LABEL} value={value} onChange={onChange} />;
}
