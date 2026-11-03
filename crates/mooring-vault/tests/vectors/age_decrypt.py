#!/usr/bin/env python3
"""Decrypt export.age with the reference `age` CLI and print the JSON document.

The `age` CLI only reads passphrases from a terminal, so this script runs it under a
pseudo-terminal. Usage (from the repository root):

    python3 crates/mooring-vault/tests/vectors/age_decrypt.py \
        crates/mooring-vault/tests/vectors/export.age > /tmp/export.json

The passphrase is the fixed, public test passphrase documented in README.md.

Portability notes: the terminal is drained in a background thread so the child can never
block on a full pty buffer; the passphrase is written only after the prompt has appeared and
the child has had time to switch the terminal into password mode (macOS flushes pending
input when the line discipline changes); a hard timeout turns a hang into a diagnostic.
"""

import os
import pty
import select
import signal
import sys
import threading
import time

PASSPHRASE = b"nexus-export-vector-passphrase"
TIMEOUT_S = 60.0


def drain(fd, sink, stop):
    """Read everything the child prints on the terminal until it closes."""
    while not stop.is_set():
        try:
            ready, _, _ = select.select([fd], [], [], 0.1)
        except (OSError, ValueError):
            return
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return
        if not chunk:
            return
        sink.append(chunk)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: age_decrypt.py <export.age>", file=sys.stderr)
        return 2
    out_r, out_w = os.pipe()
    pid, tty = pty.fork()
    if pid == 0:  # child: stdout -> pipe, stdin/stderr stay on the pty
        os.dup2(out_w, 1)
        os.close(out_r)
        os.close(out_w)
        os.execvp("age", ["age", "--decrypt", sys.argv[1]])
    os.close(out_w)

    tty_log: list[bytes] = []
    stop = threading.Event()
    reader = threading.Thread(target=drain, args=(tty, tty_log, stop), daemon=True)
    reader.start()

    deadline = time.monotonic() + TIMEOUT_S
    sent = False
    data = b""
    out_open = True
    while time.monotonic() < deadline:
        if not sent and b"passphrase" in b"".join(tty_log).lower():
            time.sleep(0.3)  # let age finish switching the pty to no-echo mode
            os.write(tty, PASSPHRASE + b"\r")
            sent = True
        if out_open:
            ready, _, _ = select.select([out_r], [], [], 0.1)
            if ready:
                chunk = os.read(out_r, 65536)
                if chunk:
                    data += chunk
                else:
                    out_open = False
        else:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            time.sleep(0.05)
    else:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        stop.set()
        shown = b"".join(tty_log).decode("utf-8", "replace")
        print(
            f"age_decrypt: timed out after {TIMEOUT_S:.0f}s "
            f"(passphrase sent: {sent}); terminal output was:\n{shown}",
            file=sys.stderr,
        )
        return 124

    stop.set()
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        sys.stderr.write(b"".join(tty_log).decode("utf-8", "replace"))
    sys.stdout.buffer.write(data)
    return code


if __name__ == "__main__":
    sys.exit(main())
