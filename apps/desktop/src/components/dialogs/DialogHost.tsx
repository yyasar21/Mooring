import { useUi } from "../../stores/ui";
import { ConnectionDialog } from "./ConnectionDialog";
import { FolderDialog } from "./FolderDialog";

/** Renders whichever editor dialog the ui store says is open. Credentials are a view, not a dialog. */
export function DialogHost() {
  const dialog = useUi((s) => s.dialog);
  const close = useUi((s) => s.closeDialog);
  if (!dialog) return null;
  switch (dialog.kind) {
    case "folder":
      return <FolderDialog key={dialog.id ?? "new"} {...(dialog.id ? { id: dialog.id } : {})} parentId={dialog.parentId} onClose={close} />;
    case "connection":
      return <ConnectionDialog key={dialog.id ?? "new"} {...(dialog.id ? { id: dialog.id } : {})} folderId={dialog.folderId} onClose={close} />;
  }
}
