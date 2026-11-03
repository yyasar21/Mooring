#!/usr/bin/env python3
"""Verify the nexus-vault test vectors with the reference `age` CLI, independently of Rust.

Run from the repository root (needs `age` on PATH):

    python3 tests/vectors/verify_age_export.py

Checks (ADR-0006):
  1. `age --decrypt` of export.age (via age_decrypt.py) exits 0 and yields JSON.
  2. Its `header` equals header.json.
  3. Every sealed.json vector appears exactly once in `credentials[].fields`, byte-identical,
     and the export holds no field that is not a vector.
  4. A tampered copy of export.age is rejected by the CLI (non-zero exit).
"""

import json
import os
import subprocess
import sys
import tempfile

VEC = os.path.join("crates", "nexus-vault", "tests", "vectors")
DECRYPT = os.path.join(VEC, "age_decrypt.py")


def decrypt(path):
    return subprocess.run(
        [sys.executable, DECRYPT, path], capture_output=True, timeout=120, check=False
    )


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1


def main():
    res = decrypt(os.path.join(VEC, "export.age"))
    if res.returncode != 0:
        return fail(f"age --decrypt exited {res.returncode}")
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        return fail("decrypted payload is not JSON")

    with open(os.path.join(VEC, "header.json"), encoding="utf-8") as f:
        header = json.load(f)
    if doc.get("header") != header:
        return fail("export header differs from header.json")

    with open(os.path.join(VEC, "sealed.json"), encoding="utf-8") as f:
        sealed = json.load(f)
    want = {(v["record_id"], v["field"]): v["sealed"] for v in sealed}
    got = {}
    for rec in doc.get("credentials", []):
        for field, value in rec.get("fields", {}).items():
            key = (rec["record_id"], field)
            if key in got:
                return fail(f"duplicate field {key}")
            got[key] = value
    if got != want:
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        return fail(f"sealed fields differ: missing={missing} extra={extra}")

    # Negative control: flip one base64 character in the armored body.
    with open(os.path.join(VEC, "export.age"), "rb") as f:
        lines = f.read().split(b"\n")
    mid = len(lines) // 2
    body = bytearray(lines[mid])
    body[len(body) // 2] = ord("A") if body[len(body) // 2] != ord("A") else ord("B")
    lines[mid] = bytes(body)
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "tampered.age")
        with open(bad, "wb") as f:
            f.write(b"\n".join(lines))
        if decrypt(bad).returncode == 0:
            return fail("age accepted a tampered export.age")

    print(f"OK: header + {len(want)} sealed vectors verified with the age CLI; tamper rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
