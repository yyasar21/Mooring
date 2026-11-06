#!/bin/sh
# Test shim standing in for iputils tracepath. Records its argv next to itself.
printf '%s\n' "$@" > "$0.argv"
printf ' 1?: [LOCALHOST]                      pmtu 1500\n'
printf ' 1:  192.0.2.254                                           0.321ms\n'
printf ' 2:  192.0.2.1                                            12.345ms reached\n'
printf '     Resume: pmtu 1500 hops 2 back 2\n'
exit 0
