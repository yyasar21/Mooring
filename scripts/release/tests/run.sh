#!/usr/bin/env bash
# Run every release-script test (bash only, no network): scripts/release/tests/run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
rc=0
for t in "$HERE"/*.test.sh; do
  echo "### $(basename "$t")"
  bash "$t" || rc=1
done
exit "$rc"
