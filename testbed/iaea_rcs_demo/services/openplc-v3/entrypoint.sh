#!/usr/bin/env bash
set -euo pipefail

cd /workdir

bootstrap_persistent() {
  if [ -d "/docker_persistent" ]; then
    mkdir -p /docker_persistent/st_files
    cp -n /workdir/webserver/dnp3_default.cfg /docker_persistent/dnp3.cfg
    cp -n /workdir/webserver/openplc_default.db /docker_persistent/openplc.db
    cp -n /workdir/webserver/active_program_default /docker_persistent/active_program
    cp -n /workdir/webserver/st_files_default/* /docker_persistent/st_files/
    cp -n /dev/null /docker_persistent/persistent.file
    cp -n /dev/null /docker_persistent/mbconfig.cfg
  fi
}

bootstrap_persistent

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

if [ -n "${PLC_PROGRAM_TEMPLATE:-}" ] || [ -n "${PLC_MODBUS_PROFILE:-}" ]; then
  python3 /opt/openplc-lab/seed_lab_profile.py
fi

compat_pid=""
if [ -n "${COMPAT_HTTP_PORT:-}" ]; then
  python3 /opt/openplc-lab/compat_listener.py &
  compat_pid=$!
fi

opc_pid=""
if [ -n "${PLC_OPC_PROFILE:-}" ]; then
  /opt/openplc-lab/venv/bin/python /opt/openplc-lab/opc_bridge.py &
  opc_pid=$!
fi

./start_openplc.sh &
openplc_pid=$!

cleanup() {
  kill "$openplc_pid" 2>/dev/null || true
  if [ -n "$compat_pid" ]; then
    kill "$compat_pid" 2>/dev/null || true
  fi
  if [ -n "$opc_pid" ]; then
    kill "$opc_pid" 2>/dev/null || true
  fi
  wait "$openplc_pid" 2>/dev/null || true
  if [ -n "$compat_pid" ]; then
    wait "$compat_pid" 2>/dev/null || true
  fi
  if [ -n "$opc_pid" ]; then
    wait "$opc_pid" 2>/dev/null || true
  fi
}

trap cleanup INT TERM

wait -n "$openplc_pid" ${compat_pid:+"$compat_pid"} ${opc_pid:+"$opc_pid"}
status=$?
cleanup
exit "$status"
