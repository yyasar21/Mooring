#!/usr/bin/env bash
# Tests for lint-workflows.sh: the real workflows pass; synthetic ones with the updater key in
# the wrong job, a second workflow naming it, or a toolchain drift fail.
# Run: scripts/release/tests/lint-workflows.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../lint-workflows.sh"
REAL="$HERE/../../../.github/workflows"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

expect() { # expect <0|nonzero> <label> <dir>
  local want="$1" label="$2" dir="$3" rc=0
  bash "$SCRIPT" "$dir" >"$WORK/out" 2>&1 || rc=$?
  if { [[ "$want" == 0 ]] && ((rc == 0)); } || { [[ "$want" != 0 ]] && ((rc != 0)); }; then
    pass=$((pass + 1)); echo "ok   $label (exit $rc)"
  else
    fail=$((fail + 1)); echo "FAIL $label (exit $rc, wanted $want)"; sed 's/^/     /' "$WORK/out"
  fi
}

# A minimal, valid pair of workflows.
fixture() { # fixture <name> -> dir
  local d="$WORK/$1"; mkdir -p "$d"
  cat >"$d/release.yml" <<'EOF'
name: release
env:
  RUST_TOOLCHAIN: "1.97.0"
jobs:
  build:
    steps:
      - uses: dtolnay/rust-toolchain@sha
        with:
          toolchain: ${{ env.RUST_TOOLCHAIN }}
      - env:
          S_APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}
  sign-updater:
    environment: release
    steps:
      - env:
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
  finalize:
    needs: [sign-updater]
EOF
  cat >"$d/release-repro.yml" <<'EOF'
name: release-repro
env:
  RUST_TOOLCHAIN: "1.97.0"
jobs:
  repro:
    steps: []
EOF
  echo "$d"
}

expect 0 "the repository's own workflows" "$REAL"

good=$(fixture good)
expect 0 "minimal valid pair" "$good"

wrongjob=$(fixture wrongjob)
sed -i 's/S_APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}/S_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}/' "$wrongjob/release.yml"
expect nonzero "updater key referenced by the build job" "$wrongjob"

otherfile=$(fixture otherfile)
printf 'name: ci\njobs:\n  x:\n    steps:\n      - env: { K: "${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}" }\n' >"$otherfile/ci.yml"
expect nonzero "updater key referenced by another workflow" "$otherfile"

nojob=$(fixture nojob)
sed -i 's/^  sign-updater:/  sign-things:/' "$nojob/release.yml"
expect nonzero "no sign-updater job" "$nojob"

drift=$(fixture drift)
sed -i 's/1.97.0/1.96.0/' "$drift/release-repro.yml"
expect nonzero "RUST_TOOLCHAIN differs between the workflows" "$drift"

stable=$(fixture stable)
sed -i 's/toolchain: ${{ env.RUST_TOOLCHAIN }}/toolchain: stable/' "$stable/release.yml"
expect nonzero "toolchain: stable in release.yml" "$stable"

nopin=$(fixture nopin)
sed -i '/RUST_TOOLCHAIN/d' "$nopin/release.yml"
expect nonzero "release.yml without RUST_TOOLCHAIN" "$nopin"

echo "$pass passed, $fail failed"
((fail == 0))
