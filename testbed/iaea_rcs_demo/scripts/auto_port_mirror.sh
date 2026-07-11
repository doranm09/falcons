#!/bin/sh
set -eu

from_iface="${MIRROR_FROM_IFACE:-br_rcs_l1m}"
target_container="${MIRROR_TARGET_CONTAINER:-ids-network}"
reapply_seconds="${MIRROR_REAPPLY_SECONDS:-5}"

last_state=""

log_state() {
  state="$1"
  msg="$2"
  if [ "$state" != "$last_state" ]; then
    echo "$msg"
    last_state="$state"
  fi
}

while true; do
  if ! ip link show dev "$from_iface" >/dev/null 2>&1; then
    log_state "missing-iface" "[ids-mirror] waiting for interface $from_iface"
    sleep "$reapply_seconds"
    continue
  fi

  ip link set dev "$from_iface" promisc on >/dev/null 2>&1 || true

  if python3 /scripts/setup_port_mirror.py "$from_iface" "$target_container" >/tmp/port-mirror.log 2>&1; then
    log_state "mirroring" "[ids-mirror] mirroring active: $from_iface -> $target_container"
  else
    echo "[ids-mirror] mirror setup not ready yet"
    cat /tmp/port-mirror.log
    last_state=""
  fi

  sleep "$reapply_seconds"
done
