#!/bin/sh
# Test shim standing in for traceroute. Records its argv next to itself.
printf '%s\n' "$@" > "$0.argv"
printf 'traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 60 byte packets\n'
printf ' 1  192.0.2.254  0.321 ms\n'
printf ' 2  *\n'
printf ' 3  192.0.2.1  13.001 ms\n'
exit 0
