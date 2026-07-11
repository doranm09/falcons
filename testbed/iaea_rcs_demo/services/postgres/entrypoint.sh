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

if [ -f /usr/local/bin/start_host_agent.sh ]; then
  . /usr/local/bin/start_host_agent.sh
  start_host_agent
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
