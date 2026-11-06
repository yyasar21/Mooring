#!/bin/sh
# Test shim standing in for wg. `wg1` answers like a non-root run. Keys are throwaway test
# strings, not key material.
printf '%s\n' "$@" >> "$0.argv"
KEY_A='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
KEY_B='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb='
case "$1 $2 $3" in
  "show interfaces ") printf 'wg0 wg1\n' ;;
  "show wg0 listen-port") printf '51820\n' ;;
  "show wg0 endpoints") printf '%s\t192.0.2.7:51820\n%s\t(none)\n' "$KEY_A" "$KEY_B" ;;
  "show wg0 latest-handshakes") printf '%s\t1700000000\n%s\t0\n' "$KEY_A" "$KEY_B" ;;
  "show wg0 transfer") printf '%s\t1024\t2048\n%s\t0\t0\n' "$KEY_A" "$KEY_B" ;;
  "show wg1 "*) printf 'Unable to access interface: Operation not permitted\n' 1>&2; exit 1 ;;
  *) printf 'Invalid subcommand\n' 1>&2; exit 1 ;;
esac
exit 0
