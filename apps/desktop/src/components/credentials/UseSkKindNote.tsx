import { isSkMaterial } from "../../lib/credentials.sk";

/**
 * ADR-0024: an `ssh_key` form that holds `sk-*` material, or that Rust refused with
 * `credential.use_sk_kind`. The button opens the security-key form pre-filled with the public
 * values (username, public key, certificate); a key handle is a secret and is never carried over.
 */
export function UseSkKindNote({ values, refused, onSwitch }: {
  values: Record<string, string>;
  refused: boolean;
  onSwitch: (values: Record<string, string>) => void;
}) {
  const pub = values.public_key ?? "";
  const cert = values.certificate ?? "";
  if (!refused && !isSkMaterial(pub) && !isSkMaterial(cert)) return null;
  const carry: Record<string, string> = {};
  if (values.username) carry.username = values.username;
  if (isSkMaterial(pub)) carry.public_key = pub.trim();
  if (isSkMaterial(cert)) carry.certificate = cert.trim();
  return (
    <div className="kind-note flex items-center gap-3" role={refused ? "alert" : "note"}>
      <span className="flex-1">
        This is a security-key key — create a Security key (FIDO2) credential instead.
        {!carry.public_key && " Paste the key's .pub line there; the key handle file is not carried over."}
      </span>
      <button type="button" className="btn btn-primary" onClick={() => { onSwitch(carry); }}>
        Create Security key (FIDO2) credential
      </button>
    </div>
  );
}
