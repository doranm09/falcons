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

cleanup() {
  if [ -n "${HOST_AGENT_PID:-}" ]; then
    kill "${HOST_AGENT_PID}" 2>/dev/null || true
    wait "${HOST_AGENT_PID}" 2>/dev/null || true
  fi
  for sniff_pid in ${HOST_AGENT_SNIFF_PIDS:-}; do
    kill "${sniff_pid}" 2>/dev/null || true
    wait "${sniff_pid}" 2>/dev/null || true
  done
}

trap cleanup INT TERM

exec "$@"
