#!/bin/sh
# Test shim that prints one line and then hangs (the runner's deadline must kill it).
printf '64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1 ms\n'
exec /bin/sleep 60
