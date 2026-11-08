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
#   3. ADR-0021 §2: every `find` in `sign-updater` that selects updater artifacts carries
#      `! -name '*_portable.zip'` and no positive `-name '*.zip'`-like pattern, so the portable
#      zips can never be signed with the updater key, whatever the other patterns become.
#   4. ADR-0028: every tauri build in release*.yml passes the release overlay
#      (`--config src-tauri/tauri.release.conf.json`) first; release.yml has such a build.
#   5. ADR-0028: `MOORING_RELEASE_BUILD` is set ("1") only in release.yml's build job.
#   6. ADR-0018 A1: platform signing secrets only in sign-macos / sign-windows (`release` env).
#   7. ADR-0018 A2: WINGET_TOKEN only in release-winget.yml's submit job.
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

# 3. Portable zips never reach the updater signer. Lines of the sign-updater job with their
#    `\` continuations joined; every `find` that uses `-name` is an artifact selector.
mapfile -t findings < <(python3 -I - "$DIR/release.yml" <<'PY'
import re, sys
lines, job, in_jobs, buf = [], None, False, []
with open(sys.argv[1], encoding="utf-8") as fh:
    for n, raw in enumerate(fh, 1):
        line = raw.rstrip("\n")
        if re.match(r"^jobs:\s*$", line):
            in_jobs, job = True, None
        elif re.match(r"^\S", line):
            in_jobs = False
        elif in_jobs:
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
        if job != "sign-updater":
            continue
        if buf:
            buf[1] += " " + line.strip()
        else:
            buf = [n, line.strip()]
        if buf[1].endswith("\\"):
            buf[1] = buf[1][:-1]
            continue
        lines.append(tuple(buf)); buf = []
selectors = [(n, l) for n, l in lines if re.search(r"\bfind\b", l) and "-name" in l]
if not selectors:
    print("release.yml: sign-updater has no `find ... -name` artifact selector")
for n, l in selectors:
    if "! -name '*_portable.zip'" not in l:
        print(f"release.yml:{n}: sign-updater find without `! -name '*_portable.zip'`")
    # N-70: single-quoted, double-quoted and bare `-name` patterns alike.
    for m in re.finditer(r"""(!\s*)?-i?name\s+(?:'([^']*)'|"([^"]*)"|([^\s'"()]+))""", l):
        pat = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if not m.group(1) and pat.lower().endswith("zip"):
            print(f"release.yml:{n}: sign-updater find selects zip files ({pat})")
PY
)
for f in "${findings[@]}"; do
  [[ -n "$f" ]] || continue
  echo "error: $f (portable zips are never updater artifacts, ADR-0021 §2)" >&2; rc=1
done

# 4./5. ADR-0028 build identity. tauri.conf.json is the dev identity; the release identity is
#    the overlay src-tauri/tauri.release.conf.json, applied by release workflows only:
#   4. every tauri build in release*.yml (a tauri-action step, or a `tauri build|bundle`
#      command line) passes `--config src-tauri/tauri.release.conf.json` as its FIRST
#      --config (CI-only keys may follow and win); release.yml has at least one such build.
#   5. `MOORING_RELEASE_BUILD` (read by src-tauri/build.rs) appears in no workflow but
#      release.yml, and there only in the build job, set to "1".
mapfile -t findings < <(python3 -I - "$DIR" <<'PY'
import os, re, sys
d = sys.argv[1]
OVERLAY = "src-tauri/tauri.release.conf.json"
CMD = re.compile(r"\btauri(?:\.js)?\s+(?:build|bundle)\b")

def indent(s):
    return len(s) - len(s.lstrip(" "))

def first_config(text):
    m = re.search(r"(?:--config|-c)(?:\s+|=)(\S+)", text)
    return m.group(1).strip("'\"") if m else None

builds = 0
for name in sorted(os.listdir(d)):
    if not (name.endswith(".yml") or name.endswith(".yaml")):
        continue
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        lines = [l.rstrip("\n") for l in fh]
    release_file = name.startswith("release")
    job, in_jobs = None, False
    for n, line in enumerate(lines, 1):
        if re.match(r"^jobs:\s*$", line):
            in_jobs, job = True, None
        elif re.match(r"^\S", line):
            in_jobs = False
        elif in_jobs:
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
        # rule 5
        if "MOORING_RELEASE_BUILD" in line and not line.lstrip().startswith("#"):
            if name != "release.yml":
                print(f"{name}:{n}: MOORING_RELEASE_BUILD outside release.yml (rule 5)")
            elif job != "build" or not re.match(r'^\s+MOORING_RELEASE_BUILD:\s*"?1"?\s*$', line):
                print(f"{name}:{n}: MOORING_RELEASE_BUILD must be set to \"1\" in the build job only (rule 5)")
        if not release_file or line.lstrip().startswith("#"):
            continue
        # rule 4a: tauri-action steps; the step runs to the next item at the dash's indent.
        if re.match(r"^\s*(?:-\s+)?uses:\s*tauri-apps/tauri-action@", line):
            start = n - 1
            while start >= 0 and not re.match(r"^\s*-\s", lines[start]):
                start -= 1
            dash = indent(lines[start]) if start >= 0 else 0
            end = n
            while end < len(lines) and not (lines[end].strip() and indent(lines[end]) <= dash):
                end += 1
            args, i = None, start + 1
            while i < end:
                m = re.match(r"^(\s*)args:\s*(.*)$", lines[i])
                if m:
                    parts, j = [m.group(2)], i + 1
                    while j < end and (not lines[j].strip() or indent(lines[j]) > len(m.group(1))):
                        parts.append(lines[j].strip()); j += 1
                    args = " ".join(p for p in parts if p not in (">", ">-", "|", "|-"))
                    break
                i += 1
            builds += name == "release.yml"
            if args is None or first_config(args) != OVERLAY:
                print(f"{name}:{n}: tauri-action without `--config {OVERLAY}` as its first --config (rule 4)")
        # rule 4b: tauri CLI build/bundle command lines (`\` continuations joined).
        elif CMD.search(line) and "signer" not in line:
            text, j = line, n
            while text.rstrip().endswith("\\") and j < len(lines):
                text = text.rstrip()[:-1] + " " + lines[j].strip(); j += 1
            builds += name == "release.yml"
            if first_config(text) != OVERLAY:
                print(f"{name}:{n}: tauri build without `--config {OVERLAY}` as its first --config (rule 4)")
if builds == 0:
    print("release.yml: no tauri build step found (rule 4)")
if not os.path.isfile(os.path.join(d, "..", "..", OVERLAY)) and os.path.isdir(os.path.join(d, "..", "..", "src-tauri")):
    print(f"{OVERLAY} is missing (rule 4)")
PY
)
for f in "${findings[@]}"; do
  [[ -n "$f" ]] || continue
  echo "error: $f (release identity only via the overlay, ADR-0028)" >&2; rc=1
done

# 6./7. ADR-0018 A1–A2 secret scope.
#   6. platform signing secrets (`secrets.APPLE_*`, `secrets.AZURE_CLIENT_*`/`AZURE_TENANT_ID`,
#      `secrets.WINDOWS_CERTIFICATE*`) appear in release.yml only: APPLE_* in job sign-macos,
#      the Windows ones in job sign-windows, and both jobs declare `environment: release`.
#      In particular the build job (npm + cargo build scripts) never names one.
#   7. `secrets.WINGET_TOKEN` appears in release-winget.yml's `submit` job only.
mapfile -t findings < <(python3 -I - "$DIR" <<'PY'
import os, re, sys
d = sys.argv[1]
rules = [
    (re.compile(r"secrets\.APPLE_[A-Z0-9_]+"), "release.yml", "sign-macos", True),
    (re.compile(r"secrets\.(?:AZURE_CLIENT_[A-Z_]+|AZURE_TENANT_ID|WINDOWS_CERTIFICATE[A-Z_]*)\b"), "release.yml", "sign-windows", True),
    (re.compile(r"secrets\.WINGET_TOKEN\b"), "release-winget.yml", "submit", False),
]
for name in sorted(os.listdir(d)):
    if not (name.endswith(".yml") or name.endswith(".yaml")):
        continue
    job, in_jobs, env = None, False, {}
    used = set()
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
                if job and re.match(r"^    environment:\s*release\s*$", line):
                    env[job] = True
            if line.lstrip().startswith("#"):
                continue
            for ref, file, want, _ in rules:
                for m in ref.finditer(line):
                    if name != file or job != want:
                        print(f"{name}:{n}: {m.group(0)} referenced in job {job or '<none>'} (only {file} job {want})")
                    else:
                        used.add(want)
    for _, file, want, needs_env in rules:
        if name == file and want in used and needs_env and not env.get(want):
            print(f"{name}: job {want} uses platform signing secrets without `environment: release`")
PY
)
for f in "${findings[@]}"; do
  [[ -n "$f" ]] || continue
  echo "error: $f (signing secrets stay in their signing job, ADR-0018 A1-A2)" >&2; rc=1
done

((rc == 0)) && echo "lint-workflows: ok ($DIR)"
exit "$rc"
