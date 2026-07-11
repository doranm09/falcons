#!/bin/sh
set -eu

RUNTIME_DIR="${SIEM_RUNTIME_DIR:-/var/lib/siem/runtime}"
LOG_DIR="${SIEM_SURICATA_DIR:-/var/lib/siem/suricata}"
SENSOR_ID="${SIEM_SENSOR_ID:-suricata-sensor}"
HOSTNAME_VALUE="${SIEM_SENSOR_HOSTNAME:-$SENSOR_ID}"
INTERFACES="${SIEM_SENSOR_INTERFACES:-eth0,eth1}"
PIDFILE="/var/run/suricata.pid"

mkdir -p "$RUNTIME_DIR" "$LOG_DIR"

if [ -f "$PIDFILE" ]; then
  STALE_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [ -n "$STALE_PID" ] && kill -0 "$STALE_PID" 2>/dev/null; then
    echo "Suricata already running with pid $STALE_PID" >&2
    exit 1
  fi
  rm -f "$PIDFILE"
fi

INTERFACE_JSON=$(printf '%s' "$INTERFACES" | awk -F',' '
BEGIN { printf("[") }
{
  for (i = 1; i <= NF; i++) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i)
    if ($i != "") {
      if (count > 0) printf(",")
      printf("\"%s\"", $i)
      count++
    }
  }
}
END { printf("]") }')

cat > "$RUNTIME_DIR/$SENSOR_ID.json" <<EOF
{"sensor_id":"$SENSOR_ID","hostname":"$HOSTNAME_VALUE","interfaces":$INTERFACE_JSON,"capture_mode":"passive","testbed":"iaea_rcs_demo"}
EOF

set -- suricata -l "$LOG_DIR" -D
OLD_IFS="$IFS"
IFS=','
for iface in $INTERFACES; do
  iface=$(printf '%s' "$iface" | xargs)
  if [ -n "$iface" ]; then
    set -- "$@" -i "$iface"
  fi
done
IFS="$OLD_IFS"

"$@"

tail -F "$LOG_DIR"/eve.json
