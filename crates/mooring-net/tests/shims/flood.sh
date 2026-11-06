#!/bin/sh
# Test shim that prints far more than the 64 KiB output cap, then hangs: the runner must cut
# the output and kill it.
i=0
while [ "$i" -lt 4000 ]; do
  printf '64 bytes from 192.0.2.1: icmp_seq=%d ttl=64 time=0.1 ms\n' "$i"
  i=$((i + 1))
done
exec /bin/sleep 60
