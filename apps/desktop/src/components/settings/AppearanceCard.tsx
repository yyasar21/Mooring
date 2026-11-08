import { useUi, type ThemePref } from "../../stores/ui";
import { SettingsCard } from "./Toggle";

const OPTIONS: { id: ThemePref; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
];

/**
 * Settings → Appearance (design review 2026-11, Q9): the theme moved here from the title bar.
 * "System" follows the operating system and changes with it; the choice is stored on this device
 * only and applies at once, so there is no Save.
 */
export function AppearanceCard() {
  const pref = useUi((s) => s.themePref);
  const setPref = useUi((s) => s.setThemePref);
  return (
    <SettingsCard title="Appearance" labelledBy="appearance-title">
      <div className="settings-body">
        <fieldset className="settings-seg">
          <legend className="field-label">Theme</legend>
          {OPTIONS.map((o) => (
            <label key={o.id} className="seg-opt" data-checked={pref === o.id || undefined}>
              <input type="radio" name="appearance-theme" value={o.id} checked={pref === o.id} onChange={() => { setPref(o.id); }} />
              {o.label}
            </label>
          ))}
        </fieldset>
        <p className="field-hint">System follows your operating system. The choice is kept on this device.</p>
      </div>
    </SettingsCard>
  );
}
