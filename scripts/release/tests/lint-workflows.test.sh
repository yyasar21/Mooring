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
          S_TAURI_SIGNING_RPM_KEY: ${{ secrets.TAURI_SIGNING_RPM_KEY }}
      - name: Build with tauri-action
        id: tauri
        uses: tauri-apps/tauri-action@1deb371b0cd8bd54025b384f1cd735e725c4060f # v1.0.0
        env:
          MOORING_RELEASE_BUILD: "1"
        with:
          args: --target x --config src-tauri/tauri.release.conf.json --config ${{ steps.cfg.outputs.path }}
          retryAttempts: 1
      - name: next step
        run: echo done
  sign-updater:
    environment: release
    steps:
      - env:
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
        run: |
          mapfile -t targets < <(find artifacts -maxdepth 1 -type f ! -name '*_portable.zip' \
            \( -name '*.app.tar.gz' -o -name '*-setup.exe' -o -name '*.AppImage' \) | LC_ALL=C sort)
  sign-macos:
    environment: release
    steps:
      - env:
          APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}
  sign-windows:
    environment: release
    steps:
      - env:
          HAS_AZURE: ${{ secrets.AZURE_CLIENT_ID != '' && secrets.AZURE_TENANT_ID != '' }}
          WINDOWS_CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE }}
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
sed -i 's/S_TAURI_SIGNING_RPM_KEY: ${{ secrets.TAURI_SIGNING_RPM_KEY }}/S_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}/' "$wrongjob/release.yml"
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

# --- ADR-0021 §2: the portable zips never reach the updater signer ---
noexcl=$(fixture noexcl)
sed -i "s/ ! -name '\*_portable.zip'//" "$noexcl/release.yml"
if grep -q '_portable' "$noexcl/release.yml"; then fail=$((fail + 1)); echo "FAIL fixture edit (noexcl)"; fi
expect nonzero "sign-updater find without the *_portable.zip exclusion" "$noexcl"

zipsel=$(fixture zipsel)
sed -i "s/-name '\*.AppImage'/-name '*.AppImage' -o -name '*.zip'/" "$zipsel/release.yml"
expect nonzero "sign-updater find selecting *.zip" "$zipsel"

portsel=$(fixture portsel)
sed -i "s/-name '\*.AppImage'/-name '*.AppImage' -o -name '*_portable.zip'/" "$portsel/release.yml"
expect nonzero "sign-updater find selecting *_portable.zip despite the exclusion" "$portsel"

# N-70: the quoting style of the `-name` pattern does not matter.
dqzip=$(fixture dqzip)
sed -i "s/-name '\*.AppImage'/-name '*.AppImage' -o -name \"*.zip\"/" "$dqzip/release.yml"
grep -q -- '-name "\*.zip"' "$dqzip/release.yml" || { fail=$((fail + 1)); echo "FAIL fixture edit (dqzip)"; }
expect nonzero "sign-updater find selecting a double-quoted *.zip" "$dqzip"

barezip=$(fixture barezip)
sed -i "s/-name '\*.AppImage'/-name '*.AppImage' -o -name Mooring_portable.zip/" "$barezip/release.yml"
expect nonzero "sign-updater find selecting a bare zip name" "$barezip"

dqok=$(fixture dqok)
sed -i "s/-name '\*.AppImage'/-name \"*.AppImage\"/" "$dqok/release.yml"
expect 0 "double-quoted non-zip patterns still pass" "$dqok"

nofind=$(fixture nofind)
sed -i '/find artifacts/,/LC_ALL=C sort)/d' "$nofind/release.yml"
expect nonzero "sign-updater without an artifact selector" "$nofind"

# --- ADR-0028 rule 4: the release overlay on every tauri build ---
nooverlay=$(fixture nooverlay)
sed -i 's# --config src-tauri/tauri.release.conf.json##' "$nooverlay/release.yml"
expect nonzero "tauri-action without the release overlay" "$nooverlay"

overlaylast=$(fixture overlaylast)
sed -i 's#--config src-tauri/tauri.release.conf.json --config ${{ steps.cfg.outputs.path }}#--config ${{ steps.cfg.outputs.path }} --config src-tauri/tauri.release.conf.json#' "$overlaylast/release.yml"
grep -q 'path }} --config src-tauri' "$overlaylast/release.yml" || { fail=$((fail + 1)); echo "FAIL fixture edit (overlaylast)"; }
expect nonzero "release overlay after the CI config (CI keys must win)" "$overlaylast"

noargs=$(fixture noargs)
sed -i '/^          args: --target x/d' "$noargs/release.yml"
expect nonzero "tauri-action without args" "$noargs"

foldargs=$(fixture foldargs)
sed -i 's#^          args: --target x #          args: >-\n            --target x\n            #' "$foldargs/release.yml"
grep -q '^            --config src-tauri/tauri.release.conf.json' "$foldargs/release.yml" || { fail=$((fail + 1)); echo "FAIL fixture edit (foldargs)"; }
expect 0 "folded multi-line args with the overlay first" "$foldargs"

nobuild=$(fixture nobuild)
sed -i '/uses: tauri-apps\/tauri-action/d' "$nobuild/release.yml"
expect nonzero "release.yml without any tauri build" "$nobuild"

clibuild=$(fixture clibuild)
sed -i 's#        run: echo done#        run: pnpm tauri build --bundles app --no-sign#' "$clibuild/release.yml"
expect nonzero "a CLI tauri build without the overlay" "$clibuild"

cliok=$(fixture cliok)
sed -i 's#        run: echo done#        run: |\n          cargo tauri build --bundles app \\\n            --config src-tauri/tauri.release.conf.json --config ci.json#' "$cliok/release.yml"
grep -q 'cargo tauri build --bundles app' "$cliok/release.yml" || { fail=$((fail + 1)); echo "FAIL fixture edit (cliok)"; }
expect 0 "a CLI tauri build with the overlay on a continuation line" "$cliok"

otherrel=$(fixture otherrel)
printf 'name: release-x\njobs:\n  b:\n    steps:\n      - run: npx tauri bundle --bundles dmg\n' >"$otherrel/release-extra.yml"
expect nonzero "another release*.yml bundles without the overlay" "$otherrel"

ciyml=$(fixture ciyml)
printf 'name: ci\njobs:\n  b:\n    steps:\n      - run: pnpm tauri build --debug --bundles app --no-sign\n' >"$ciyml/ci.yml"
expect 0 "ci.yml builds the dev identity without the overlay" "$ciyml"

# --- ADR-0028 rule 5: MOORING_RELEASE_BUILD only in release.yml's build job ---
relci=$(fixture relci)
printf 'name: ci\njobs:\n  b:\n    env:\n      MOORING_RELEASE_BUILD: "1"\n    steps: []\n' >"$relci/ci.yml"
expect nonzero "MOORING_RELEASE_BUILD set in ci.yml" "$relci"

relrun=$(fixture relrun)
printf 'name: e2e\njobs:\n  b:\n    steps:\n      - run: MOORING_RELEASE_BUILD=1 cargo build\n' >"$relrun/e2e.yml"
expect nonzero "MOORING_RELEASE_BUILD assigned in a run line elsewhere" "$relrun"

reljob=$(fixture reljob)
sed -i 's#^  finalize:#  finalize:\n    env:\n      MOORING_RELEASE_BUILD: "1"#' "$reljob/release.yml"
expect nonzero "MOORING_RELEASE_BUILD in another release.yml job" "$reljob"

relzero=$(fixture relzero)
sed -i 's#MOORING_RELEASE_BUILD: "1"#MOORING_RELEASE_BUILD: "0"#' "$relzero/release.yml"
expect nonzero "MOORING_RELEASE_BUILD set to something other than 1" "$relzero"

relcomment=$(fixture relcomment)
printf 'name: ci\n# MOORING_RELEASE_BUILD is release-only (ADR-0028)\njobs:\n  b:\n    steps: []\n' >"$relcomment/ci.yml"
expect 0 "a comment naming MOORING_RELEASE_BUILD elsewhere" "$relcomment"

# --- ADR-0018 A1-A2 rules 6/7: signing secrets and the winget token stay in their job ---
applebuild=$(fixture applebuild)
sed -i 's/S_TAURI_SIGNING_RPM_KEY: ${{ secrets.TAURI_SIGNING_RPM_KEY }}/S_APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}/' "$applebuild/release.yml"
expect nonzero "an Apple signing secret in the build job" "$applebuild"

azuremac=$(fixture azuremac)
sed -i 's/          APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}/          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}/' "$azuremac/release.yml"
expect nonzero "an Azure secret in sign-macos" "$azuremac"

noenv=$(fixture noenv)
sed -i '/^  sign-windows:$/{n;d;}' "$noenv/release.yml"
grep -A1 '^  sign-windows:' "$noenv/release.yml" | grep -q 'environment' && { fail=$((fail + 1)); echo "FAIL fixture edit (noenv)"; }
expect nonzero "sign-windows without environment: release" "$noenv"

othersign=$(fixture othersign)
printf 'name: ci\njobs:\n  b:\n    steps:\n      - env:\n          K: ${{ secrets.APPLE_API_KEY_P8 }}\n' >"$othersign/ci.yml"
expect nonzero "an Apple secret in another workflow" "$othersign"

wingetok=$(fixture wingetok)
printf 'name: release-winget\njobs:\n  manifests:\n    steps: []\n  submit:\n    steps:\n      - env:\n          HAS: ${{ secrets.WINGET_TOKEN != %s }}\n' "''" >"$wingetok/release-winget.yml"
expect 0 "WINGET_TOKEN in release-winget.yml submit" "$wingetok"

wingetbad=$(fixture wingetbad)
printf 'name: release-winget\njobs:\n  manifests:\n    steps:\n      - env:\n          T: ${{ secrets.WINGET_TOKEN }}\n' >"$wingetbad/release-winget.yml"
expect nonzero "WINGET_TOKEN in the manifests job" "$wingetbad"

echo "$pass passed, $fail failed"
((fail == 0))
