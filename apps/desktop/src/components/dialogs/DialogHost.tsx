import { useUi } from "../../stores/ui";
import { ConnectionDialog } from "./ConnectionDialog";
import { CredentialDialog } from "./CredentialDialog";
import { CredentialsDialog } from "./CredentialsDialog";
import { FolderDialog } from "./FolderDialog";

/** Renders whichever editor dialog the ui store says is open. */
export function DialogHost() {
  const dialog = useUi((s) => s.dialog);
  const close = useUi((s) => s.closeDialog);
  if (!dialog) return null;
  switch (dialog.kind) {
    case "folder":
      return <FolderDialog key={dialog.id ?? "new"} {...(dialog.id ? { id: dialog.id } : {})} parentId={dialog.parentId} onClose={close} />;
    case "connection":
      return <ConnectionDialog key={dialog.id ?? "new"} {...(dialog.id ? { id: dialog.id } : {})} folderId={dialog.folderId} onClose={close} />;
    case "credential":
      return (
        <CredentialDialog
          key={dialog.id ?? "new"}
          {...(dialog.id ? { id: dialog.id } : {})}
          onClose={() => { useUi.getState().openDialog({ kind: "credentials" }); }}
        />
      );
    case "credentials":
      return <CredentialsDialog onClose={close} />;
  }
}
