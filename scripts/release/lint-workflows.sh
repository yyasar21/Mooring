#!/usr/bin/env bash
# Lint the release workflows for the two invariants that CI cannot express (security review 7):
#
#   scripts/release/lint-workflows.sh [.github/workflows]
#
#   1. M-17: `secrets.TAURI_SIGNING_PRIVATE_KEY*` is referenced by the `sign-updater` job of
#      release.yml only. Every other job (build scripts, tauri-action, cargo, npm) and every
#      other workflow file must not name it, so the updater key never reaches their environment.
#   2. N-57: release.yml and release-repro.yml declare the same `RUST_TOOLCHAIN`, so the
#      reproducibility check compiles with the compiler that ships.
# Pure bash + python3 -I (line-based, no YAML library). Exit 1 with one `error:` per finding.
set -euo pipefail

DIR="${1:-.github/workflows}"
[[ -d "$DIR" ]] || { echo "error: '$DIR' is not a directory" >&2; exit 1; }
[[ -f "$DIR/release.yml" ]] || { echo "error: $DIR/release.yml not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 1; }

rc=0

# 1. Key scope. A job starts at a two-space-indented key under `jobs:`; a line that references
#    the secret belongs to the job that encloses it.
mapfile -t findings < <(python3 -I - "$DIR" <<'PY'
import os, re, sys
d = sys.argv[1]
ref = re.compile(r"secrets\.TAURI_SIGNING_PRIVATE_KEY")
for name in sorted(os.listdir(d)):
    if not (name.endswith(".yml") or name.endswith(".yaml")):
        continue
    job, in_jobs = None, False
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if re.match(r"^jobs:\s*$", line):
                in_jobs, job = True, None
            elif re.match(r"^\S", line):
                in_jobs = False
            elif in_jobs:
                m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
                if m:
                    job = m.group(1)
            if ref.search(line) and not (name == "release.yml" and job == "sign-updater"):
                print(f"{name}:{n}: TAURI_SIGNING_PRIVATE_KEY referenced in job {job or '<none>'}")
PY
)
for f in "${findings[@]}"; do
  [[ -n "$f" ]] || continue
  echo "error: $f (only release.yml job sign-updater may use the updater key, M-17)" >&2; rc=1
done
grep -q '^  sign-updater:' "$DIR/release.yml" || { echo "error: release.yml has no sign-updater job" >&2; rc=1; }

# 2. One toolchain for the release and its reproducibility check.
if [[ -f "$DIR/release-repro.yml" ]]; then
  pin() { sed -n 's/^  RUST_TOOLCHAIN: *"\{0,1\}\([0-9][0-9.]*\)"\{0,1\} *$/\1/p' "$1" | head -1; }
  a=$(pin "$DIR/release.yml"); b=$(pin "$DIR/release-repro.yml")
  [[ -n "$a" ]] || { echo "error: release.yml declares no top-level RUST_TOOLCHAIN" >&2; rc=1; }
  [[ -n "$b" ]] || { echo "error: release-repro.yml declares no top-level RUST_TOOLCHAIN" >&2; rc=1; }
  if [[ -n "$a" && -n "$b" && "$a" != "$b" ]]; then
    echo "error: RUST_TOOLCHAIN differs: release.yml $a, release-repro.yml $b (N-57)" >&2; rc=1
  fi
  if grep -nE '^\s+toolchain: *stable\s*$' "$DIR/release.yml" >/dev/null; then
    echo "error: release.yml uses 'toolchain: stable'; use \${{ env.RUST_TOOLCHAIN }} (N-57)" >&2; rc=1
  fi
fi

((rc == 0)) && echo "lint-workflows: ok ($DIR)"
exit "$rc"
