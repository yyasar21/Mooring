#!/usr/bin/env bash
# Tests for verify-release.sh with stub `gh`, `cosign` and `minisign` (no network). Each case
# builds a fake release directory and checks the exit status.
# Run: scripts/release/tests/verify-release.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../verify-release.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
REPO_URL="https://github.com/yyasar21/Mooring"

# stub tools: `gh release download` copies $FAKE_RELEASE/*; attestation obeys $ATTEST_FAIL
mkdir -p "$WORK/bin"
cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
  "release download") dir=""; while (($#)); do [[ "$1" == --dir ]] && dir="$2"; shift; done
                      cp "$FAKE_RELEASE"/* "$dir"/ ;;
  "attestation --help") exit 0 ;;
  "attestation verify") [[ " ${ATTEST_FAIL:-} " == *" $3 "* ]] && exit 1; exit 0 ;;
  *) exit 2 ;;
esac
EOF
cat >"$WORK/bin/cosign" <<'EOF'
#!/usr/bin/env bash
[[ "${COSIGN_FAIL:-}" == 1 ]] && exit 1; exit 0
EOF
# stub minisign: obeys $MINISIGN_FAIL (space-separated names of the files to reject)
cat >"$WORK/bin/minisign" <<'EOF'
#!/usr/bin/env bash
m=""; while (($#)); do [[ "$1" == -m ]] && m="$2"; shift; done
[[ " ${MINISIGN_FAIL:-} " == *" $m "* ]] && exit 1; exit 0
EOF
chmod +x "$WORK/bin/gh" "$WORK/bin/cosign" "$WORK/bin/minisign"

release() { # release <name> <files...>: a release dir with SHA256SUMS over the given files
  local d="$WORK/$1"; shift
  mkdir -p "$d"
  for f in "$@"; do echo "content of $f" >"$d/$f"; done
  (cd "$d" && if (($#)); then sha256sum "$@" >SHA256SUMS; else : >SHA256SUMS; fi)
  echo '{}' >"$d/SHA256SUMS.sigstore.json"
  echo "$d"
}
rehash() { # rehash <dir>: SHA256SUMS over every file except the sums and their signature
  (cd "$1" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum -- >SHA256SUMS)
}
SIG64="$(printf 'untrusted comment: signature\n%s\n' "$(head -c 60 /dev/zero | base64 -w0)" | base64 -w0)"
with_updater() { # with_updater <dir> <asset> <platform>: signed artifact + latest.json entry, re-hash
  local d="$1" asset="$2" platform="$3"
  echo "content of $asset" >"$d/$asset"
  printf '%s\n' "$SIG64" >"$d/$asset.sig"
  python3 -I - "$d/latest.json" "$platform" "$asset" "$SIG64" "$REPO_URL" <<'PY'
import json, sys
out, platform, asset, sig, repo = sys.argv[1:]
try:
    doc = json.load(open(out))
except FileNotFoundError:
    doc = {"version": "1.2.3", "notes": "", "pub_date": "2026-01-01T00:00:00Z", "platforms": {}}
doc["platforms"][platform] = {"signature": sig, "url": f"{repo}/releases/download/v1.2.3/{asset}"}
json.dump(doc, open(out, "w"), indent=2)
PY
  rehash "$d"
}

expect() { # expect <0|nonzero> <label> <env...> -- <args...>
  local want="$1" label="$2"; shift 2
  local envs=(); while [[ "$1" != -- ]]; do envs+=("$1"); shift; done; shift
  local rc=0
  env PATH="$WORK/bin:$PATH" DIR="$(mktemp -d -p "$WORK")" "${envs[@]}" \
    bash "$SCRIPT" "$@" >"$WORK/out" 2>&1 || rc=$?
  if { [[ "$want" == 0 ]] && ((rc == 0)); } || { [[ "$want" != 0 ]] && ((rc != 0)); }; then
    pass=$((pass + 1)); echo "ok   $label (exit $rc)"
  else
    fail=$((fail + 1)); echo "FAIL $label (exit $rc, wanted $want)"; sed 's/^/     /' "$WORK/out"
  fi
}

good=$(release good a.dmg b.msi)
expect 0 "all assets listed, signed and attested" FAKE_RELEASE="$good" -- v1.2.3

extra=$(release extra a.dmg); echo x >"$extra/unlisted.exe"
expect nonzero "an asset not covered by SHA256SUMS" FAKE_RELEASE="$extra" -- v1.2.3
expect 0 "--allow-unlisted accepts it" FAKE_RELEASE="$extra" -- v1.2.3 --allow-unlisted

expect nonzero "a listed asset without provenance" FAKE_RELEASE="$good" ATTEST_FAIL=b.msi -- v1.2.3

missing=$(release missing a.dmg b.msi); rm "$missing/b.msi"
expect nonzero "a listed asset missing" FAKE_RELEASE="$missing" -- v1.2.3

tampered=$(release tampered a.dmg); echo evil >>"$tampered/a.dmg"
expect nonzero "a hash mismatch" FAKE_RELEASE="$tampered" -- v1.2.3

nosig=$(release nosig a.dmg); rm "$nosig/SHA256SUMS.sigstore.json"
expect nonzero "no signature bundle" FAKE_RELEASE="$nosig" -- v1.2.3
expect nonzero "a bad signature" FAKE_RELEASE="$good" COSIGN_FAIL=1 -- v1.2.3

empty=$(release empty)
expect nonzero "an empty SHA256SUMS" FAKE_RELEASE="$empty" -- v1.2.3

expect nonzero "an unknown option" FAKE_RELEASE="$good" -- v1.2.3 --yolo

# --- updater manifest (latest.json) ---
APPIMAGE=Mooring_1.2.3_amd64.AppImage
upd=$(release upd a.dmg); with_updater "$upd" "$APPIMAGE" linux-x86_64
with_updater "$upd" Mooring_universal.app.tar.gz darwin-aarch64
expect 0 "latest.json consistent with the .sig files, updater signatures ok" FAKE_RELEASE="$upd" -- v1.2.3
expect nonzero "minisign rejects an updater artifact" FAKE_RELEASE="$upd" MINISIGN_FAIL="$APPIMAGE" -- v1.2.3

wrongsig=$(release wrongsig a.dmg); with_updater "$wrongsig" "$APPIMAGE" linux-x86_64
sed -i 's/"signature": "[^"]*"/"signature": "QUFBQQ=="/' "$wrongsig/latest.json"; rehash "$wrongsig"
expect nonzero "latest.json signature differs from the .sig" FAKE_RELEASE="$wrongsig" -- v1.2.3

foreign=$(release foreign a.dmg); with_updater "$foreign" "$APPIMAGE" linux-x86_64
sed -i 's#yyasar21/Mooring/releases#evil/Mooring/releases#' "$foreign/latest.json"; rehash "$foreign"
expect nonzero "latest.json points outside this repo" FAKE_RELEASE="$foreign" -- v1.2.3

badver=$(release badver a.dmg); with_updater "$badver" "$APPIMAGE" linux-x86_64
sed -i 's/"version": "1.2.3"/"version": "9.9.9"/' "$badver/latest.json"; rehash "$badver"
expect nonzero "latest.json version differs from the tag" FAKE_RELEASE="$badver" -- v1.2.3

nosigfile=$(release nosigfile a.dmg); with_updater "$nosigfile" "$APPIMAGE" linux-x86_64
rm "$nosigfile/$APPIMAGE.sig"; rehash "$nosigfile"
expect nonzero "latest.json names an artifact whose .sig is missing" FAKE_RELEASE="$nosigfile" -- v1.2.3

echo "$pass passed, $fail failed"
((fail == 0))
