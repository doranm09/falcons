#!/bin/sh
set -eu

if [ -n "${STATIC_ROUTES:-}" ]; then
  old_ifs=$IFS
  IFS=';'
  for route in $STATIC_ROUTES; do
    [ -n "$route" ] || continue
    IFS=$old_ifs
    ip route replace $route
    IFS=';'
    echo "route installed: $route"
  done
  IFS=$old_ifs
fi

exec "$@"
