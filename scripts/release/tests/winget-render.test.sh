#!/usr/bin/env bash
# Dry run of the winget manifest generator (ADR-0018 A2): the templates in packaging/winget
# render byte-for-byte to the fixture in tests/fixtures/winget/ (fixed version, date, hashes,
# product code), the result passes validate.py, and the refusals hold (pre-release, missing
# hash, bad product code, leftover placeholder, tampered manifests). No network, no Windows.
# Run: scripts/release/tests/winget-render.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/../../.."
RENDER="$HERE/../winget/render.py"
VALIDATE="$HERE/../winget/validate.py"
FIXTURE="$HERE/fixtures/winget"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() { # check <label> <test command...>
  local label="$1"; shift
  if "$@" >"$WORK/out" 2>&1; then pass=$((pass + 1)); echo "ok   $label"
  else fail=$((fail + 1)); echo "FAIL $label"; sed 's/^/     /' "$WORK/out"; fi
}
refuses() { ! "$@"; }
hex() { printf "$1%.0s" $(seq 64); }
CODE='{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}'
sums="$WORK/SHA256SUMS"
{ echo "$(hex a)  Mooring_1.2.3_x64-setup.exe"; echo "$(hex b) *Mooring_1.2.3_x64_en-US.msi"
  echo "$(hex c)  Mooring_1.2.3_x64_portable.zip"; } >"$sums"
render() { # render <out> [extra args...]
  local out="$1"; shift
  python3 -I "$RENDER" --templates "$ROOT/packaging/winget" --sums "$sums" --version 1.2.3 \
    --release-date 2026-11-08 --out "$out" "$@"
}
DIR=manifests/y/yyasar21/Mooring/1.2.3

check "render with a product code" render "$WORK/a" --msi-product-code "$CODE"
check "output equals the fixture byte for byte" diff -r "$FIXTURE" "$WORK/a/$DIR"
check "exactly the three manifest files" test "$(ls "$WORK/a/$DIR" | wc -l)" -eq 3
check "no placeholder left" refuses grep -rn '@[A-Z0-9_]*@' "$WORK/a/$DIR"
check "template notes dropped, schema hint kept" bash -c "! grep -q '^# Template' '$WORK/a/$DIR'/*.yaml && grep -q 'yaml-language-server' '$WORK/a/$DIR/yyasar21.Mooring.installer.yaml'"
check "two runs are identical" bash -c "$(declare -f render); sums='$sums' RENDER='$RENDER' ROOT='$ROOT'; render '$WORK/b' --msi-product-code '$CODE' >/dev/null && diff -r '$WORK/a' '$WORK/b'"

check "render without a product code" render "$WORK/c"
check "  ProductCode line dropped" refuses grep -q ProductCode "$WORK/c/$DIR/yyasar21.Mooring.installer.yaml"
check "refuses a pre-release version" refuses python3 -I "$RENDER" --templates "$ROOT/packaging/winget" --sums "$sums" --version 1.2.3-rc.1 --release-date 2026-11-08 --out "$WORK/d"
check "refuses a bad release date" refuses render "$WORK/d" --release-date 2026-13-01
check "refuses a malformed product code" refuses render "$WORK/d" --msi-product-code 'not-a-guid'
grep -v en-US.msi "$sums" >"$WORK/nomsi"
check "refuses SHA256SUMS without the .msi" refuses python3 -I "$RENDER" --templates "$ROOT/packaging/winget" --sums "$WORK/nomsi" --version 1.2.3 --release-date 2026-11-08 --out "$WORK/d"
echo "zz  Mooring_1.2.3_x64-setup.exe" >"$WORK/badsums"
check "refuses a malformed SHA256SUMS" refuses python3 -I "$RENDER" --templates "$ROOT/packaging/winget" --sums "$WORK/badsums" --version 1.2.3 --release-date 2026-11-08 --out "$WORK/d"
cp -r "$ROOT/packaging/winget" "$WORK/tpl"; sed -i 's/^Moniker: mooring/Moniker: @MONIKER@/' "$WORK/tpl/yyasar21.Mooring.locale.en-US.yaml"
check "refuses a template with an unknown placeholder" refuses python3 -I "$RENDER" --templates "$WORK/tpl" --sums "$sums" --version 1.2.3 --release-date 2026-11-08 --out "$WORK/d"

if python3 -I -c 'import yaml' 2>/dev/null; then
  check "validate: the fixture" python3 -I "$VALIDATE" "$WORK/a/$DIR"
  check "validate: without a product code" python3 -I "$VALIDATE" "$WORK/c/$DIR"
  tamper() { # tamper <label> <file> <sed expression>
    local label="$1" file="$2" expr="$3" t
    t="$WORK/t$((pass + fail))/$DIR"; mkdir -p "$t"; cp "$WORK/a/$DIR"/*.yaml "$t/"
    sed -i "$expr" "$t/$file"
    check "validate refuses: $label" refuses python3 -I "$VALIDATE" "$t"
  }
  tamper "a short hash" yyasar21.Mooring.installer.yaml 's/"A\{64\}"/"ABC"/'
  tamper "a version mismatch" yyasar21.Mooring.yaml 's/PackageVersion: "1.2.3"/PackageVersion: "1.2.4"/'
  tamper "another schema version" yyasar21.Mooring.locale.en-US.yaml 's/^ManifestVersion: 1.10.0/ManifestVersion: 1.9.0/'
  tamper "an unknown key (typo)" yyasar21.Mooring.locale.en-US.yaml 's/^License: MIT/Licence: MIT/'
  tamper "an http installer URL" yyasar21.Mooring.installer.yaml '0,/InstallerUrl: https/s//InstallerUrl: http/'
  tamper "an unknown installer type" yyasar21.Mooring.installer.yaml 's/InstallerType: nullsoft/InstallerType: nsis/'
  tamper "a URL for another tag" yyasar21.Mooring.installer.yaml '0,/download\/v1.2.3\//s//download\/v1.2.2\//'
  tamper "a tag with a space" yyasar21.Mooring.locale.en-US.yaml 's/  - remote-access/  - remote access/'
else
  echo "skip validate.py checks (PyYAML not installed)"
fi

echo "$pass passed, $fail failed"
((fail == 0))
