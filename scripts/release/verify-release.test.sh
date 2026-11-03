#!/usr/bin/env bash
# Tests for verify-release.sh with stub `gh` and `cosign` (no network). Each case builds a fake
# release directory and checks the exit status. Run: scripts/release/verify-release.test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/verify-release.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

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
chmod +x "$WORK/bin/gh" "$WORK/bin/cosign"

release() { # release <name> <files...>: a release dir with SHA256SUMS over the given files
  local d="$WORK/$1"; shift
  mkdir -p "$d"
  for f in "$@"; do echo "content of $f" >"$d/$f"; done
  (cd "$d" && if (($#)); then sha256sum "$@" >SHA256SUMS; else : >SHA256SUMS; fi)
  echo '{}' >"$d/SHA256SUMS.sigstore.json"
  echo "$d"
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

echo "$pass passed, $fail failed"
((fail == 0))
