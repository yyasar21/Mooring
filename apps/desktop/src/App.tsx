import { useEffect } from "react";
import { useApp } from "./stores/app";
import { VaultGate } from "./components/VaultGate";
import { Shell } from "./components/Shell";

export function App() {
  const vault = useApp((s) => s.vault);
  const boot = useApp((s) => s.boot);
  const lastError = useApp((s) => s.lastError);

  useEffect(() => {
    void boot();
  }, [boot]);

  switch (vault) {
    case "unknown":
      return (
        <main className="grid h-full place-items-center text-text-muted">
          {lastError ?? "Starting…"}
        </main>
      );
    case "missing":
      return <VaultGate mode="create" />;
    case "locked":
      return <VaultGate mode="unlock" />;
    case "unlocked":
      return <Shell />;
  }
}
