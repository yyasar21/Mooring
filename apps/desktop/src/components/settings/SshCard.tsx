import { SettingsCard } from "./Toggle";

/**
 * Settings → SSH (ADR-0024). Security keys sign through the ssh-agent. The `ssh-sk-helper`
 * backend exists in Rust behind an off-by-default setting with no command to change it yet, so it
 * is shown as an informational, disabled row: no toggle.
 */
export function SshCard() {
  return (
    <SettingsCard title="SSH" labelledBy="ssh-title">
      <div className="settings-body">
        <div className="ssh-row">
          <div className="min-w-0 flex-1">
            <p className="ssh-row-title">Security keys (FIDO2) sign through your ssh-agent</p>
            <p className="field-hint">
              Mooring asks the agent at SSH_AUTH_SOCK (macOS, Linux) or the OpenSSH agent pipe (Windows); Pageant has no
              security-key support. Add a key with ssh-add -K (resident) or ssh-add with its key handle file. Mooring never falls
              back to a password after a security-key sign-in.
            </p>
          </div>
          <span className="ssh-state">On</span>
        </div>
        <div className="ssh-row" aria-disabled="true" data-disabled>
          <div className="min-w-0 flex-1">
            <p className="ssh-row-title">Direct security-key access (without ssh-agent) — coming later</p>
            <p className="field-hint">
              Signing with OpenSSH&apos;s ssh-sk-helper on Windows and Linux is turned off in this version. There is nothing to
              change here yet.
            </p>
          </div>
          <span className="ssh-state">Not available</span>
        </div>
      </div>
    </SettingsCard>
  );
}
