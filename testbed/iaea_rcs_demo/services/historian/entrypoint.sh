#!/bin/sh
set -eu

if [ -n "${STATIC_ROUTES:-}" ]; then
  old_ifs=$IFS
  IFS=';'
  for route in $STATIC_ROUTES; do
    [ -n "$route" ] || continue
    IFS=$old_ifs
    if ! ip route replace $route; then
      echo "route install failed: $route"
    fi
    IFS=';'
    echo "route installed: $route"
  done
  IFS=$old_ifs
fi

exec "$@"
