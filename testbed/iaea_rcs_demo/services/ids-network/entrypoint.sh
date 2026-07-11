#!/bin/sh
set -eu

require_net_admin="${IDS_REQUIRE_NET_ADMIN:-0}"
enable_promisc="${IDS_ENABLE_PROMISC:-0}"
capture_iface="${IDS_IFACE:-eth0}"

warn_or_exit() {
  message="$1"
  echo "$message" >&2
  if [ "$require_net_admin" = "1" ]; then
    exit 1
  fi
}

if [ "$enable_promisc" = "1" ]; then
  if ip link show dev "$capture_iface" >/dev/null 2>&1; then
    if ip link set dev "$capture_iface" promisc on >/dev/null 2>&1; then
      echo "enabled promiscuous mode on $capture_iface"
    else
      warn_or_exit "warning: unable to enable promiscuous mode on $capture_iface"
    fi
  else
    warn_or_exit "warning: capture interface $capture_iface does not exist"
  fi
fi

if [ -n "${STATIC_ROUTES:-}" ]; then
  old_ifs=$IFS
  IFS=';'
  for route in $STATIC_ROUTES; do
    [ -n "$route" ] || continue
    IFS=$old_ifs
    if ip route replace $route >/dev/null 2>&1; then
      echo "route installed: $route"
    else
      warn_or_exit "warning: unable to install static route: $route"
    fi
    IFS=';'
  done
  IFS=$old_ifs
fi

exec "$@"
