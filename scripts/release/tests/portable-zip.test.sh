#!/usr/bin/env bash
# Tests for portable-zip.py: byte-identical output from two runs, LC_ALL=C entry order, the
# 1980 mtime floor, Unix mode + symlink round trip, a macOS `_CodeSignature` tree untouched.
# Run: scripts/release/tests/portable-zip.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../portable-zip.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() { # check <label> <test command...>
  local label="$1"; shift
  if "$@"; then pass=$((pass + 1)); echo "ok   $label"
  else fail=$((fail + 1)); echo "FAIL $label"; sed 's/^/     /' "$WORK/out" 2>/dev/null || true; fi
}
zipit() { python3 -I "$SCRIPT" "$@" >"$WORK/out" 2>&1; }
zipfails() { ! zipit "$@"; }
# names <zip>: archive entries in stored order
names() { python3 -I -c 'import sys,zipfile;[print(i.filename) for i in zipfile.ZipFile(sys.argv[1]).infolist()]' "$1"; }
# attr <zip> <entry> -> "<octal mode> <date_time> <compress_type> <extra-len>"
attr() {
  python3 -I -c '
import sys, zipfile
zi = zipfile.ZipFile(sys.argv[1]).getinfo(sys.argv[2])
print(oct(zi.external_attr >> 16), "%04d-%02d-%02dT%02d:%02d:%02d" % zi.date_time, zi.compress_type, len(zi.extra))' "$1" "$2"
}

# A fake .app bundle: a nested tree, an executable, a symlink inside Contents/Frameworks (as
# real framework bundles have), a _CodeSignature directory, an empty directory, a file whose
# name sorts differently in C and in a locale collation ("B" < "a" in C).
src="$WORK/src"; app="$src/Mooring.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/_CodeSignature" "$app/Contents/Frameworks/X.framework/Versions/A" "$app/Contents/Resources/empty"
chmod 755 "$app/Contents" # explicit: the expected mode must not depend on the umask
printf '\x7fELF-ish' >"$app/Contents/MacOS/Mooring"; chmod 755 "$app/Contents/MacOS/Mooring"
echo '<plist/>' >"$app/Contents/Info.plist"; chmod 644 "$app/Contents/Info.plist"
echo 'signature blob' >"$app/Contents/_CodeSignature/CodeResources"
echo 'lib' >"$app/Contents/Frameworks/X.framework/Versions/A/X"
ln -s Versions/A/X "$app/Contents/Frameworks/X.framework/X"
ln -s A "$app/Contents/Frameworks/X.framework/Versions/Current"
echo a >"$src/a.txt"; echo B >"$src/B.txt"; echo b >"$src/b.txt"
: >"$src/portable"
# a dangling symlink must be stored as a symlink, not fail (never dereferenced)
ln -s nowhere "$app/Contents/Resources/dangling"

EPOCH=1800000000 # 2027-01-15T08:00:00Z
check "zip from --root" zipit --out "$WORK/one.zip" --epoch "$EPOCH" --root "$src"
touch -d '2001-01-01' "$src/a.txt" # filesystem mtimes must not matter
check "second run (other fs mtimes)" zipit --out "$WORK/two.zip" --epoch "$EPOCH" --root "$src"
check "two runs are byte-identical" cmp -s "$WORK/one.zip" "$WORK/two.zip"
check "  (sha256 agrees)" [ "$(sha256sum <"$WORK/one.zip")" = "$(sha256sum <"$WORK/two.zip")" ]

# entry order: LC_ALL=C over the archive path, parents before children
names "$WORK/one.zip" >"$WORK/names"
check "entry order is LC_ALL=C (B.txt before a.txt, parents first)" \
  bash -c 'diff <(LC_ALL=C sort "$1") "$1" >/dev/null && head -1 "$1" | grep -qx "B.txt"' _ "$WORK/names"
check "explicit directory entries present" grep -qx 'Mooring.app/Contents/Resources/empty/' "$WORK/names"
check "a zip of this tree has the expected entry count" [ "$(wc -l <"$WORK/names")" = 21 ]

# modes, symlinks, mtimes, no extra fields
check "executable keeps 0755" [ "$(attr "$WORK/one.zip" Mooring.app/Contents/MacOS/Mooring)" = "0o100755 2027-01-15T08:00:00 8 0" ]
check "plain file keeps 0644 + deflate" [ "$(attr "$WORK/one.zip" Mooring.app/Contents/Info.plist)" = "0o100644 2027-01-15T08:00:00 8 0" ]
check "symlink stored as S_IFLNK, uncompressed" [ "$(attr "$WORK/one.zip" Mooring.app/Contents/Frameworks/X.framework/X)" = "0o120777 2027-01-15T08:00:00 0 0" ]
check "symlink data is the link target (not dereferenced)" \
  [ "$(python3 -I -c 'import sys,zipfile;print(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode())' "$WORK/one.zip" Mooring.app/Contents/Frameworks/X.framework/Versions/Current)" = A ]
check "dangling symlink kept" [ "$(python3 -I -c 'import sys,zipfile;print(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode())' "$WORK/one.zip" Mooring.app/Contents/Resources/dangling)" = nowhere ]
check "directory entry has S_IFDIR and the DOS dir bit" \
  [ "$(python3 -I -c 'import sys,zipfile;zi=zipfile.ZipFile(sys.argv[1]).getinfo(sys.argv[2]);print(oct(zi.external_attr>>16), zi.external_attr & 0x10)' "$WORK/one.zip" Mooring.app/Contents/)" = "0o40755 16" ]
check "_CodeSignature/CodeResources byte-identical" \
  [ "$(python3 -I -c 'import sys,zipfile;sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode())' "$WORK/one.zip" Mooring.app/Contents/_CodeSignature/CodeResources)" = "signature blob" ]
check "empty marker file is an entry" grep -qx 'portable' "$WORK/names"

# zipinfo (Info-ZIP) reads the Unix attributes back: executable, symlink, directory
if command -v zipinfo >/dev/null; then
  zipinfo "$WORK/one.zip" >"$WORK/zi" 2>&1 || true
  check "zipinfo shows -rwxr-xr-x for the executable" grep -qE '^-rwxr-xr-x .* Mooring\.app/Contents/MacOS/Mooring$' "$WORK/zi"
  check "zipinfo shows lrwxrwxrwx for the symlink" grep -qE '^lrwxrwxrwx .* Mooring\.app/Contents/Frameworks/X\.framework/X$' "$WORK/zi"
  check "zipinfo shows drwxr-xr-x for a directory" grep -qE '^drwxr-xr-x .* Mooring\.app/Contents/$' "$WORK/zi"
fi
# unzip round trip: the symlink is a symlink again and the executable bit survives
if command -v unzip >/dev/null; then
  mkdir "$WORK/x" && (cd "$WORK/x" && unzip -q "$WORK/one.zip")
  check "unzip restores the symlink" [ "$(readlink "$WORK/x/Mooring.app/Contents/Frameworks/X.framework/X")" = Versions/A/X ]
  check "unzip restores the executable bit" [ -x "$WORK/x/Mooring.app/Contents/MacOS/Mooring" ]
  check "unzip restores the file content" cmp -s "$WORK/x/Mooring.app/Contents/_CodeSignature/CodeResources" "$app/Contents/_CodeSignature/CodeResources"
  check "unzip restores the empty directory" [ -d "$WORK/x/Mooring.app/Contents/Resources/empty" ]
fi

# 1980 floor: epoch 0 and the limit itself both give 1980-01-01T00:00:00
check "epoch 0 → 1980-01-01" zipit --out "$WORK/old.zip" --epoch 0 --root "$src"
check "  mtime floored" [ "$(attr "$WORK/old.zip" a.txt | cut -d' ' -f2)" = 1980-01-01T00:00:00 ]
check "  floor is deterministic too" bash -c 'python3 -I "$1" --out "$2/old2.zip" --epoch 7 --root "$3" >/dev/null && cmp -s "$2/old.zip" "$2/old2.zip"' _ "$SCRIPT" "$WORK" "$src"

# explicit NAME=PATH entries (the workflow's form): a bundle, the marker and a README
: >"$WORK/portable"; echo 'readme' >"$WORK/README.txt"
check "explicit entries" zipit --out "$WORK/ex.zip" --epoch "$EPOCH" "Mooring.app=$app" "portable=$WORK/portable" "README.txt=$WORK/README.txt"
check "  top level is exactly the three names" \
  [ "$(names "$WORK/ex.zip" | awk -F/ '{print $1}' | LC_ALL=C sort -u | tr '\n' ' ')" = "Mooring.app README.txt portable " ]
check "  --root and entries combine" bash -c 'python3 -I "$1" --out "$2/mix.zip" --epoch 1 --root "$3" "extra/README.txt=$2/README.txt" >/dev/null' _ "$SCRIPT" "$WORK" "$src"

# refusals
check "duplicate name fails" zipfails --out "$WORK/d.zip" --epoch 1 "portable=$WORK/portable" "portable=$WORK/README.txt"
check "name with .. fails" zipfails --out "$WORK/d.zip" --epoch 1 "../x=$WORK/portable"
check "absolute name fails" zipfails --out "$WORK/d.zip" --epoch 1 "/x=$WORK/portable"
check "backslash in name fails" zipfails --out "$WORK/d.zip" --epoch 1 "a\\b=$WORK/portable"
check "missing path fails" zipfails --out "$WORK/d.zip" --epoch 1 "x=$WORK/nope"
check "no entries fails" zipfails --out "$WORK/d.zip" --epoch 1
check "negative epoch fails" zipfails --out "$WORK/d.zip" --epoch -1 --root "$src"
check "a fifo fails" bash -c 'mkfifo "$2/fifo" && ! python3 -I "$1" --out "$2/d.zip" --epoch 1 "f=$2/fifo" >/dev/null 2>&1' _ "$SCRIPT" "$WORK"
check "nothing left behind on failure" [ ! -e "$WORK/d.zip" ]

echo "$pass passed, $fail failed"
((fail == 0))
