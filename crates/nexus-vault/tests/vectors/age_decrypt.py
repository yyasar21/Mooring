#!/usr/bin/env python3
"""Decrypt export.age with the reference `age` CLI and print the JSON document.

The `age` CLI only reads passphrases from a terminal, so this script runs it under a
pseudo-terminal. Usage (from the repository root):

    python3 crates/nexus-vault/tests/vectors/age_decrypt.py \
        crates/nexus-vault/tests/vectors/export.age > /tmp/export.json

The passphrase is the fixed, public test passphrase documented in README.md.
"""

import os
import pty
import sys

PASSPHRASE = b"nexus-export-vector-passphrase\n"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: age_decrypt.py <export.age>", file=sys.stderr)
        return 2
    out_r, out_w = os.pipe()
    pid, tty = pty.fork()
    if pid == 0:
        os.dup2(out_w, 1)
        os.execvp("age", ["age", "--decrypt", sys.argv[1]])
    os.close(out_w)
    prompt = b""
    while b"passphrase" not in prompt.lower():
        chunk = os.read(tty, 1024)
        if not chunk:
            break
        prompt += chunk
    os.write(tty, PASSPHRASE)
    data = b""
    while True:
        chunk = os.read(out_r, 65536)
        if not chunk:
            break
        data += chunk
    _, status = os.waitpid(pid, 0)
    sys.stdout.buffer.write(data)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
