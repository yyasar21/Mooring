#!/bin/sh
# Test shim standing in for iputils ping (never installed, never on PATH). Records its argv next
# to itself and prints a canned run with one lost packet; exits 1 like ping does on loss.
printf '%s\n' "$@" > "$0.argv"
printf 'PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.\n'
printf '64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.045 ms\n'
printf '64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=0.050 ms\n'
printf '64 bytes from 192.0.2.1: icmp_seq=3 ttl=64 time=0.040 ms\n'
printf '\n--- 192.0.2.1 ping statistics ---\n'
printf '4 packets transmitted, 3 received, 25%% packet loss, time 3004ms\n'
printf 'rtt min/avg/max/mdev = 0.040/0.045/0.050/0.004 ms\n'
printf 'LC_ALL=%s HOME=%s\n' "${LC_ALL-unset}" "${HOME-unset}" 1>&2
exit 1
