import { fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { freshBackend, settle } from "../../test/harness";
import { AutoLockCard } from "./AutoLockCard";
import { SyslogCard } from "./SyslogCard";

const card = (name: string) => screen.getByRole("region", { name });
const sw = (name: string) => screen.getByRole("switch", { name: new RegExp(`^${name}`) });

describe("AutoLockCard", () => {
  it("loads the policy, sets never and saves the toggles", async () => {
    const mock = freshBackend();
    render(<AutoLockCard />);
    await settle();
    const minutes = screen.getByLabelText("Minutes");
    expect(minutes).toHaveValue("15");
    const save = within(card("Auto-lock")).getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();

    fireEvent.click(sw("Lock when idle"));
    expect(minutes).toBeDisabled();
    expect(minutes).toHaveAttribute("placeholder", "never");
    fireEvent.click(sw("When the Mooring window is hidden"));
    fireEvent.click(save);
    await settle();
    expect(mock.policy).toEqual({ idleMinutes: null, onScreenLock: true, onSleep: true, onWindowHidden: false });
    expect(screen.getByRole("status")).toHaveTextContent("Saved.");
    expect(save).toBeDisabled();
  });

  it("validates the idle minutes like the backend", async () => {
    const mock = freshBackend();
    render(<AutoLockCard />);
    await settle();
    const minutes = screen.getByLabelText("Minutes");
    for (const bad of ["0", "1441", "2.5", "", "ten"]) {
      fireEvent.change(minutes, { target: { value: bad } });
      expect(screen.getByLabelText("Minutes")).toHaveAttribute("aria-invalid", "true");
      expect(within(card("Auto-lock")).getByRole("button", { name: "Save" })).toBeDisabled();
    }
    expect(screen.getByText("Use a whole number of minutes from 1 to 1440.")).toBeInTheDocument();
    fireEvent.change(minutes, { target: { value: "30" } });
    fireEvent.click(within(card("Auto-lock")).getByRole("button", { name: "Save" }));
    await settle();
    expect(mock.policy.idleMinutes).toBe(30);
  });

  it("warns when nothing would ever lock the vault", async () => {
    freshBackend();
    render(<AutoLockCard />);
    await settle();
    for (const n of ["Lock when idle", "When the screen locks", "When the computer sleeps", "When the Mooring window is hidden"]) fireEvent.click(sw(n));
    expect(screen.getByText(/the vault stays open until you lock it/)).toBeInTheDocument();
  });
});

describe("SyslogCard", () => {
  it("starts empty, validates, saves and sends a test entry", async () => {
    const mock = freshBackend();
    render(<SyslogCard />);
    await settle();
    const test = screen.getByRole("button", { name: "Send test entry" });
    expect(test).toBeDisabled();
    expect(screen.getByLabelText("Port")).toHaveValue("6514");

    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "https://logs.example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByText("Enter a host name or IP address, without scheme or port.")).toBeInTheDocument();
    expect(mock.syslog).toBeNull();

    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "logs.example.test" } });
    fireEvent.change(screen.getByLabelText("Facility"), { target: { value: "local4" } });
    fireEvent.click(sw("Mirror audit entries"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await settle();
    expect(mock.syslog).toEqual({ host: "logs.example.test", port: 6514, transport: "tls", facility: "local4", enabled: true });

    fireEvent.click(screen.getByRole("button", { name: "Send test entry" }));
    await settle();
    expect(screen.getByRole("status", { name: "Test result" })).toHaveTextContent("Test entry delivered.");
  });

  it("follows the default port, warns about plaintext and reports a failed test", async () => {
    const mock = freshBackend();
    await mock.syslogSet({ host: "down.invalid", port: 6514, transport: "tls", facility: "auth", enabled: true });
    render(<SyslogCard />);
    await settle();
    expect(screen.getByLabelText("Host")).toHaveValue("down.invalid");
    fireEvent.click(screen.getByRole("button", { name: "Send test entry" }));
    await settle();
    expect(screen.getByRole("status", { name: "Test result" })).toHaveTextContent("Test entry failed: connection refused.");

    fireEvent.click(screen.getByRole("radio", { name: "UDP" }));
    expect(screen.getByLabelText("Port")).toHaveValue("514");
    expect(screen.getByText(/Entries travel unencrypted over UDP/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send test entry" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "70000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByText("Use 1 to 65535.")).toBeInTheDocument();
  });
});

describe("Settings view", () => {
  it("opens from the navigation rail and shows both cards; Hosts leads back", async () => {
    freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    const rail = screen.getByRole("navigation", { name: "Views" });
    fireEvent.click(within(rail).getByRole("button", { name: "Settings" }));
    await settle();
    expect(screen.getByRole("region", { name: "Auto-lock" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Syslog mirror" })).toBeInTheDocument();
    fireEvent.click(within(rail).getByRole("button", { name: "Hosts" }));
    expect(screen.queryByRole("region", { name: "Auto-lock" })).toBeNull();
  });

  it("Appearance sets the theme: System, Light or Dark", async () => {
    freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    fireEvent.click(within(screen.getByRole("navigation", { name: "Views" })).getByRole("button", { name: "Settings" }));
    await settle();
    const card = screen.getByRole("region", { name: "Appearance" });
    expect(within(card).getByRole("radio", { name: "System" })).toBeChecked();
    fireEvent.click(within(card).getByRole("radio", { name: "Light" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(within(card).getByRole("radio", { name: "Light" })).toBeChecked();
    fireEvent.click(within(card).getByRole("radio", { name: "Dark" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    fireEvent.click(within(card).getByRole("radio", { name: "System" }));
    expect(localStorage.getItem("mooring.theme")).toBeNull();
  });
});
