#!/usr/bin/env bash
# Download the assets of a Mooring release and verify them.
#
#   scripts/release/verify-release.sh v0.1.0              # yyasar21/Mooring
#   scripts/release/verify-release.sh v0.1.0 owner/fork   # a fork's release
#   DIR=./dl scripts/release/verify-release.sh v0.1.0     # keep the downloads
#   scripts/release/verify-release.sh v0.1.0 --allow-unlisted   # manual: extra files only warn
#
# Checks, in order:
#   1. SHA256SUMS is signed by the release workflow of that repo at that tag
#      (cosign keyless: Sigstore certificate identity + GitHub OIDC issuer, Rekor entry).
#   2. Every file listed in SHA256SUMS matches its hash.
#   3. No file on the release is left out of SHA256SUMS (unless --allow-unlisted).
#   4. GitHub build-provenance attestation per artifact (when `gh attestation` exists).
# Fails closed: any missing asset, signature, hash or provenance exits non-zero.
# Needs: gh (authenticated for draft releases), cosign >= 3.0, sha256sum or shasum.
set -euo pipefail

ALLOW_UNLISTED=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --allow-unlisted) ALLOW_UNLISTED=1 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
    -*) echo "error: unknown option $a" >&2; exit 1 ;;
    *) ARGS+=("$a") ;;
  esac
done
((${#ARGS[@]} <= 2)) || { echo "error: too many arguments" >&2; exit 1; }
TAG="${ARGS[0]:-}"
REPO="${ARGS[1]:-yyasar21/Mooring}"
[[ -z "$TAG" ]] && { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "error: tag must look like v1.2.3" >&2; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "error: repo must be owner/name" >&2; exit 1; }

for tool in gh cosign; do
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

# Tag pushes sign as ...release.yml@refs/tags/<tag>; a manual re-run (workflow_dispatch) signs
# as ...release.yml@refs/heads/main. Accept exactly those two, nothing else.
REPO_RE="${REPO//./\\.}"
TAG_RE="${TAG//./\\.}"
IDENTITY_RE="^https://github\\.com/${REPO_RE}/\\.github/workflows/release\\.yml@refs/(tags/${TAG_RE}|heads/main)\$"
ISSUER="https://token.actions.githubusercontent.com"
echo "==> cosign: SHA256SUMS signed by $REPO release.yml for $TAG"
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$ISSUER"

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

echo
echo "verified $REPO $TAG:"
cat SHA256SUMS
