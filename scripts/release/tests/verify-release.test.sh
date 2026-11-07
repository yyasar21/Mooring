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
# stub cosign: records its arguments in $COSIGN_ARGS (one per line) and obeys $COSIGN_FAIL
cat >"$WORK/bin/cosign" <<'EOF'
#!/usr/bin/env bash
[[ -n "${COSIGN_ARGS:-}" ]] && printf '%s\n' "$@" >"$COSIGN_ARGS"
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

# --- cosign identity (N-58): the release workflow at the tag ref, never a branch ---
expect 0 "identity recorded" FAKE_RELEASE="$good" COSIGN_ARGS="$WORK/cosign.args" -- v1.2.3
identity=$(awk 'p {print; exit} /^--certificate-identity-regexp$/ {p=1}' "$WORK/cosign.args")
if [[ "$identity" == '^https://github\.com/yyasar21/Mooring/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$' ]]; then
  pass=$((pass + 1)); echo "ok   cosign identity is release.yml at refs/tags/<tag> only"
else
  fail=$((fail + 1)); echo "FAIL cosign identity regexp: $identity"
fi
if grep -q 'heads/main' "$WORK/cosign.args"; then
  fail=$((fail + 1)); echo "FAIL cosign identity still accepts refs/heads/main"
else
  pass=$((pass + 1)); echo "ok   refs/heads/main is not an accepted identity"
fi
if grep -qx -- '--certificate-oidc-issuer' "$WORK/cosign.args" && grep -qx 'https://token.actions.githubusercontent.com' "$WORK/cosign.args"; then
  pass=$((pass + 1)); echo "ok   GitHub OIDC issuer pinned"
else
  fail=$((fail + 1)); echo "FAIL GitHub OIDC issuer not pinned"
fi

# The signer summary comes from the Fulcio extensions of the bundle's certificate. A synthetic
# DER fragment with the four extensions is enough for the parser (it searches by OID bytes).
certinfo=$(release certinfo a.dmg)
python3 -I - "$certinfo/SHA256SUMS.sigstore.json" <<'PY'
import base64, json, sys
def ext(n, value):
    v = value.encode()
    return (b"\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01" + bytes([n])
            + b"\x04" + bytes([len(v) + 2]) + b"\x0c" + bytes([len(v)]) + v)
der = (b"\x30\x82\x01\x00"
       + ext(9, "https://github.com/yyasar21/Mooring/.github/workflows/release.yml@refs/tags/v1.2.3")
       + ext(10, "a" * 40) + ext(13, "b" * 40)
       + ext(21, "https://github.com/yyasar21/Mooring/actions/runs/1/attempts/1"))
json.dump({"verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(der).decode()}}},
          open(sys.argv[1], "w"))
PY
rehash "$certinfo"
expect 0 "a bundle with Fulcio extensions" FAKE_RELEASE="$certinfo" -- v1.2.3
if grep -q 'identity: *https://github.com/yyasar21/Mooring/.github/workflows/release.yml@refs/tags/v1.2.3' "$WORK/out" \
   && grep -q "workflow-commit: *$(printf 'a%.0s' {1..40})" "$WORK/out" \
   && grep -q "source-commit: *$(printf 'b%.0s' {1..40})" "$WORK/out"; then
  pass=$((pass + 1)); echo "ok   signer summary printed from the certificate"
else
  fail=$((fail + 1)); echo "FAIL signer summary missing"; sed 's/^/     /' "$WORK/out"
fi

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

# --- portable zips (ADR-0021): regular assets, never updater artifacts ---
WINZIP=Mooring_1.2.3_x64_portable.zip; MACZIP=Mooring_1.2.3_universal_portable.zip
port=$(release port a.dmg "$WINZIP" "$MACZIP"); with_updater "$port" "$APPIMAGE" linux-x86_64
expect 0 "both portable zips listed in SHA256SUMS, absent from latest.json" FAKE_RELEASE="$port" -- v1.2.3
if grep -q "portable builds (not updater artifacts): $MACZIP $WINZIP" "$WORK/out"; then
  pass=$((pass + 1)); echo "ok   portable zips reported"
else
  fail=$((fail + 1)); echo "FAIL portable zips not reported"; sed 's/^/     /' "$WORK/out"
fi

inmanifest=$(release inmanifest a.dmg "$WINZIP"); with_updater "$inmanifest" "$APPIMAGE" linux-x86_64
with_updater "$inmanifest" "$WINZIP" windows-x86_64 # adds a .sig and a manifest entry for the zip
expect nonzero "a portable zip listed in latest.json" FAKE_RELEASE="$inmanifest" -- v1.2.3

zipsig=$(release zipsig a.dmg "$WINZIP"); printf '%s\n' "$SIG64" >"$zipsig/$WINZIP.sig"; rehash "$zipsig"
expect nonzero "a portable zip with a .sig (not in latest.json)" FAKE_RELEASE="$zipsig" -- v1.2.3

wrongv=$(release wrongv a.dmg Mooring_9.9.9_x64_portable.zip)
expect nonzero "a portable zip of another version" FAKE_RELEASE="$wrongv" -- v1.2.3

oddzip=$(release oddzip a.dmg Mooring_1.2.3_arm64_portable.zip)
expect nonzero "a portable zip with an unknown arch" FAKE_RELEASE="$oddzip" -- v1.2.3

strayzip=$(release strayzip a.dmg something.zip)
expect nonzero "any other zip on the release" FAKE_RELEASE="$strayzip" -- v1.2.3

unlistedzip=$(release unlistedzip a.dmg); echo x >"$unlistedzip/$WINZIP"
expect nonzero "a portable zip not covered by SHA256SUMS" FAKE_RELEASE="$unlistedzip" -- v1.2.3

# A4.1 Q1: SHA256SUMS itself names a `.zip.sig` (listed but not on disk → the sums check
# fails; on disk → the portable check fails): either way the release is refused.
sumsig=$(release sumsig a.dmg "$WINZIP"); with_updater "$sumsig" "$APPIMAGE" linux-x86_64
(cd "$sumsig" && printf '%s  %s\n' "$(sha256sum <<<"x" | cut -d' ' -f1)" "$WINZIP.sig" >>SHA256SUMS)
expect nonzero "SHA256SUMS lists Mooring_<v>_x64_portable.zip.sig (not on disk)" FAKE_RELEASE="$sumsig" -- v1.2.3
sumsig2=$(release sumsig2 a.dmg "$WINZIP" "$MACZIP"); with_updater "$sumsig2" "$APPIMAGE" linux-x86_64
printf '%s\n' "$SIG64" >"$sumsig2/$MACZIP.sig"; rehash "$sumsig2" # listed and on disk
expect nonzero "SHA256SUMS lists Mooring_<v>_universal_portable.zip.sig (on disk)" FAKE_RELEASE="$sumsig2" -- v1.2.3
if grep -q "updater signature\|zip.sig\|SHA256SUMS lists" "$WORK/out"; then
  pass=$((pass + 1)); echo "ok   the .zip.sig is named as the reason"
else
  fail=$((fail + 1)); echo "FAIL the .zip.sig refusal names another reason"; sed 's/^/     /' "$WORK/out"
fi
# A zip-named signature with no zip beside it is still refused (the `*.sig` sweep).
lonesig=$(release lonesig a.dmg); with_updater "$lonesig" "$APPIMAGE" linux-x86_64
printf '%s\n' "$SIG64" >"$lonesig/$WINZIP.sig"; rehash "$lonesig"
expect nonzero "a lone Mooring_<v>_x64_portable.zip.sig without its zip" FAKE_RELEASE="$lonesig" -- v1.2.3

echo "$pass passed, $fail failed"
((fail == 0))
