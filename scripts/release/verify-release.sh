#!/usr/bin/env bash
# Download the assets of a Mooring release and verify them.
#
#   scripts/release/verify-release.sh v0.1.0              # yyasar21/Mooring
#   scripts/release/verify-release.sh v0.1.0 owner/fork   # a fork's release
#   DIR=./dl scripts/release/verify-release.sh v0.1.0     # keep the downloads
#   scripts/release/verify-release.sh v0.1.0 --allow-unlisted   # manual: extra files only warn
#
# Checks, in order:
#   1. SHA256SUMS is signed by the release workflow of that repo at the tag ref
#      (cosign keyless: certificate identity release.yml@refs/tags/<tag>, GitHub OIDC issuer,
#      Rekor entry). A signature from refs/heads/main is refused. The signing run (workflow
#      commit, source commit, run URL) is printed from the certificate.
#   2. Every file listed in SHA256SUMS matches its hash.
#   3. No file on the release is left out of SHA256SUMS (unless --allow-unlisted).
#   4. GitHub build-provenance attestation per artifact (when `gh attestation` exists).
#   5. When the release carries latest.json (in-app updater): every platform entry points at
#      this repo and tag, names an artifact of the release, and its embedded signature equals
#      that artifact's `.sig`; with `minisign` installed, each `.sig` is verified against the
#      updater public key compiled into the app (MOORING_UPDATER_PUBKEY overrides it).
#   6. Portable zips (ADR-0021): only `Mooring_<v>_x64_portable.zip` and
#      `Mooring_<v>_universal_portable.zip` are accepted, listed in SHA256SUMS like every
#      asset, never with a `.sig` and never named by latest.json (they are not updater
#      artifacts). Any other `*_portable.zip` or any other `.zip` is refused.
# Fails closed: any missing asset, signature, hash or provenance exits non-zero.
# Needs: gh (authenticated for draft releases), cosign >= 3.0, sha256sum or shasum, python3.
set -euo pipefail

# plugins.updater.pubkey from src-tauri/tauri.release.conf.json (base64 of the minisign public-key
# file). Public material; the matching private key exists only in the owner's secret store.
UPDATER_PUBKEY_DEFAULT='dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDlGNEVEQUM0ODlENEI4NkQKUldSdHVOU0p4TnBPbnhWY3BDdkwxVXZOR1FNcFo3RnJlQWl2cDhiWDA1ZDI3aTg4VlV5NFUyQ3EK'
UPDATER_PUBKEY="${MOORING_UPDATER_PUBKEY:-$UPDATER_PUBKEY_DEFAULT}"

ALLOW_UNLISTED=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --allow-unlisted) ALLOW_UNLISTED=1 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
    -*) echo "error: unknown option $a" >&2; exit 1 ;;
    *) ARGS+=("$a") ;;
  esac
done
((${#ARGS[@]} <= 2)) || { echo "error: too many arguments" >&2; exit 1; }
TAG="${ARGS[0]:-}"
REPO="${ARGS[1]:-yyasar21/Mooring}"
[[ -z "$TAG" ]] && { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "error: tag must look like v1.2.3" >&2; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "error: repo must be owner/name" >&2; exit 1; }

for tool in gh cosign python3; do
  command -v "$tool" >/dev/null || { echo "error: '$tool' is required" >&2; exit 1; }
done
if command -v sha256sum >/dev/null; then SHACHECK=(sha256sum --check --strict);
else SHACHECK=(shasum -a 256 --check --strict); fi

DIR="${DIR:-$(mktemp -d)}"
mkdir -p "$DIR"
echo "==> downloading $REPO@$TAG into $DIR"
gh release download "$TAG" --repo "$REPO" --dir "$DIR" --clobber

cd "$DIR"
for f in SHA256SUMS SHA256SUMS.sigstore.json; do
  [[ -f "$f" ]] || { echo "error: release has no $f" >&2; exit 1; }
done

# The signer must be the release workflow *at the tag ref* (N-58): a push of the tag, or a
# workflow_dispatch started from the tag. `refs/heads/main` is not accepted: anything merged
# to main later could otherwise re-sign an older tag's SHA256SUMS through a re-run.
REPO_RE="${REPO//./\\.}"
TAG_RE="${TAG//./\\.}"
IDENTITY_RE="^https://github\\.com/${REPO_RE}/\\.github/workflows/release\\.yml@refs/tags/${TAG_RE}\$"
ISSUER="https://token.actions.githubusercontent.com"
echo "==> cosign: SHA256SUMS signed by $REPO release.yml at refs/tags/$TAG"
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$ISSUER"

# Show which run signed: the Fulcio certificate's Sigstore extensions (build signer URI and
# digest = workflow file and its commit, source repository digest = the commit that was built,
# run invocation URI). Informational, parsed from the bundle with python -I; cosign above is
# the check. The source commit is compared with the tag's commit when `gh` can resolve it.
SIGNER_INFO=$(python3 -I - SHA256SUMS.sigstore.json <<'PY' 2>/dev/null || true
import base64, json, re, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
vm = doc.get("verificationMaterial") or {}
raw = (vm.get("certificate") or {}).get("rawBytes")
if not raw:
    chain = (vm.get("x509CertificateChain") or {}).get("certificates") or []
    raw = chain[0].get("rawBytes") if chain else None
if not raw:
    sys.exit(0)
der = base64.b64decode(raw)
def ext(n):  # value of extension OID 1.3.6.1.4.1.57264.1.<n> (DER-wrapped UTF8String)
    oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01" + bytes([n])
    i = der.find(oid)
    if i < 0:
        return ""
    i += len(oid)
    if der[i] != 0x04:
        return ""
    i += 2 if der[i + 1] < 0x80 else 2 + (der[i + 1] & 0x7F)
    if der[i] != 0x0C:
        return ""
    ln = der[i + 1]
    if ln < 0x80:
        i += 2
    else:
        k = ln & 0x7F; ln = int.from_bytes(der[i + 2:i + 2 + k], "big"); i += 2 + k
    v = der[i:i + ln].decode("utf-8", "replace")
    return v if re.fullmatch(r"[\x20-\x7e]+", v) else ""
for label, n in (("identity", 9), ("workflow-commit", 10), ("source-commit", 13), ("run", 21)):
    v = ext(n)
    if v:
        print(f"{label} {v}")
PY
)
if [[ -n "$SIGNER_INFO" ]]; then
  while read -r k v; do printf '  %-16s %s\n' "$k:" "$v"; done <<<"$SIGNER_INFO"
  SOURCE_COMMIT=$(awk '$1 == "source-commit" {print $2}' <<<"$SIGNER_INFO")
  TAG_COMMIT=$(gh api "repos/$REPO/commits/$TAG" --jq .sha 2>/dev/null || true)
  if [[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$TAG_COMMIT" =~ ^[0-9a-f]{40}$ && "$SOURCE_COMMIT" != "$TAG_COMMIT" ]]; then
    echo "warning: SHA256SUMS was signed from commit $SOURCE_COMMIT but $TAG now points at $TAG_COMMIT (tag moved?)" >&2
  fi
fi

echo "==> sha256: every listed artifact"
"${SHACHECK[@]}" SHA256SUMS

# Files on the release that SHA256SUMS does not cover (other than the signature itself).
mapfile -t LISTED < <(awk '{sub(/^\*/,"",$2); print $2}' SHA256SUMS)
((${#LISTED[@]})) || { echo "error: SHA256SUMS lists no files" >&2; exit 1; }
UNLISTED=()
for f in *; do
  [[ "$f" == SHA256SUMS || "$f" == SHA256SUMS.sigstore.json ]] && continue
  printf '%s\n' "${LISTED[@]}" | grep -qxF -- "$f" || UNLISTED+=("$f")
done
if ((${#UNLISTED[@]})); then
  if ((ALLOW_UNLISTED)); then
    echo "warning: not covered by SHA256SUMS: ${UNLISTED[*]}" >&2
  else
    echo "error: not covered by SHA256SUMS: ${UNLISTED[*]} (--allow-unlisted to accept)" >&2
    exit 1
  fi
fi

# ADR-0028: release assets carry the release identity only. A dev-identity build (productName
# "Mooring Dev": `Mooring Dev_<v>_*.dmg`, `mooring-dev_<v>_*.deb`, ...) on a release means the
# overlay was not applied.
DEV_RE='mooring[ _.-]dev'
for f in "${LISTED[@]}"; do
  if [[ "${f,,}" =~ $DEV_RE ]]; then
    echo "error: $f is a development build (ADR-0028); release builds use the release overlay" >&2; exit 1
  fi
done

# Portable zips (ADR-0021 §4): exactly the two known names for this version, no updater
# signature next to them (they are not updater artifacts), nothing else that looks like one.
VERSION="${TAG#v}"
PORTABLE=()
for f in *.zip; do
  [[ -e "$f" ]] || continue
  case "$f" in
    "Mooring_${VERSION}_x64_portable.zip"|"Mooring_${VERSION}_universal_portable.zip") PORTABLE+=("$f") ;;
    *) echo "error: unexpected zip on the release: $f (portable builds are Mooring_${VERSION}_{x64,universal}_portable.zip)" >&2; exit 1 ;;
  esac
done
for f in "${PORTABLE[@]}"; do
  [[ ! -e "$f.sig" ]] || { echo "error: $f has an updater signature; portable builds are never updater artifacts" >&2; exit 1; }
  printf '%s\n' "${LISTED[@]}" | grep -qxF -- "$f.sig" && { echo "error: SHA256SUMS lists $f.sig" >&2; exit 1; }
  printf '%s\n' "${LISTED[@]}" | grep -qxF -- "$f" || { echo "error: $f is not in SHA256SUMS" >&2; exit 1; }
done
for f in *.sig; do
  [[ -e "$f" && "$f" == *.zip.sig ]] || continue
  echo "error: $f: a zip must never carry an updater signature" >&2; exit 1
done
((${#PORTABLE[@]} == 0)) || echo "==> portable builds (not updater artifacts): ${PORTABLE[*]}"

if gh attestation --help >/dev/null 2>&1; then
  echo "==> gh attestation: build provenance"
  ok=0; failed=0
  for f in "${LISTED[@]}"; do
    if gh attestation verify "$f" --repo "$REPO" >/dev/null 2>&1; then ok=$((ok + 1));
    else failed=$((failed + 1)); echo "  no valid provenance: $f" >&2; fi
  done
  echo "  provenance verified for $ok file(s), $failed without"
  ((failed == 0)) || { echo "error: $failed file(s) without valid build provenance" >&2; exit 1; }
else
  echo "warning: this gh has no 'attestation' command; build provenance not checked" >&2
fi

if [[ -f latest.json ]]; then
  echo "==> updater manifest: latest.json"
  # python -I: untrusted JSON parsed with no site packages or env hooks. Prints "<key> <asset>".
  ENTRIES_TEXT=$(python3 -I - "$REPO" "$TAG" <<'PY'
import json, re, sys
repo, tag = sys.argv[1:]
doc = json.load(open("latest.json", encoding="utf-8"))
if doc.get("version") != tag[1:]:
    sys.exit(f"error: latest.json version {doc.get('version')!r} is not {tag[1:]!r}")
platforms = doc.get("platforms") or {}
if not platforms:
    sys.exit("error: latest.json has no platforms")
prefix = f"https://github.com/{repo}/releases/download/{tag}/"
for key, entry in sorted(platforms.items()):
    if not re.fullmatch(r"(darwin|windows|linux)-(x86_64|aarch64)", key):
        sys.exit(f"error: unexpected platform key {key!r}")
    url, sig = entry.get("url", ""), entry.get("signature", "")
    if not url.startswith(prefix):
        sys.exit(f"error: {key} url {url!r} is not under {prefix}")
    asset = url[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", asset):
        sys.exit(f"error: {key} asset name {asset!r}")
    if asset.endswith(".zip"):  # ADR-0021: portable builds are never offered to the updater
        sys.exit(f"error: {key}: latest.json names the portable build {asset}")
    try:
        on_disk = open(asset + ".sig", encoding="ascii").read().strip()
    except OSError:
        sys.exit(f"error: {key}: {asset}.sig is not on the release")
    if sig != on_disk:
        sys.exit(f"error: {key}: signature in latest.json differs from {asset}.sig")
    print(key, asset)
PY
  ) || exit 1 # python reported the broken entry
  mapfile -t ENTRIES <<<"$ENTRIES_TEXT"
  for e in "${ENTRIES[@]}"; do
    read -r key asset <<<"$e"
    [[ -f "$asset" ]] || { echo "error: $key: $asset is not on the release" >&2; exit 1; }
    printf '%s\n' "${LISTED[@]}" | grep -qxF -- "$asset" || { echo "error: $key: $asset is not in SHA256SUMS" >&2; exit 1; }
    printf '%s\n' "${LISTED[@]}" | grep -qxF -- "$asset.sig" || { echo "error: $key: $asset.sig is not in SHA256SUMS" >&2; exit 1; }
  done
  if command -v minisign >/dev/null; then
    # The updater key is a minisign key; the `.sig` holds the base64 of a minisign signature
    # file and the configured pubkey is the base64 of a minisign public-key file.
    pub=$(printf '%s' "$UPDATER_PUBKEY" | base64 --decode | sed -n '2p')
    [[ "$pub" =~ ^[A-Za-z0-9+/=]{56}$ ]] || { echo "error: updater public key is not a minisign key" >&2; exit 1; }
    for e in "${ENTRIES[@]}"; do
      read -r key asset <<<"$e"
      base64 --decode "$asset.sig" > "$asset.minisig"
      minisign -Vq -P "$pub" -x "$asset.minisig" -m "$asset" || { echo "error: $key: $asset is not signed by the updater key" >&2; exit 1; }
      rm -f "$asset.minisig"
    done
    echo "  updater signatures verified for ${#ENTRIES[@]} platform(s)"
  else
    echo "warning: 'minisign' not installed; updater signatures not checked against the app's public key" >&2
  fi
fi

echo
echo "verified $REPO $TAG:"
cat SHA256SUMS
