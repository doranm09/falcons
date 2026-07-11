#!/bin/sh
set -eu

if command -v zeek-config >/dev/null 2>&1; then
  PREFIX="$(zeek-config --prefix)"
elif [ -d /usr/local/zeek ]; then
  PREFIX="/usr/local/zeek"
else
  echo "Unable to determine Zeek installation prefix" >&2
  exit 1
fi

PATH="$PREFIX/bin:$PATH"
export PATH

ETC_DIR="$PREFIX/etc"
SITE_DIR="$PREFIX/share/zeek/site"
RUNTIME_DIR="${SIEM_RUNTIME_DIR:-/var/lib/siem/runtime}"
LOG_DIR="${SIEM_ZEEK_DIR:-/var/lib/siem/zeek}"
SPOOL_DIR="$LOG_DIR/spool"
SENSOR_ID="${SIEM_SENSOR_ID:-zeek-sensor}"
HOSTNAME_VALUE="${SIEM_SENSOR_HOSTNAME:-$SENSOR_ID}"
INTERFACES="${SIEM_SENSOR_INTERFACES:-eth0,eth1}"

mkdir -p "$RUNTIME_DIR" "$LOG_DIR" "$SPOOL_DIR" "$SITE_DIR"

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

cat > "$ETC_DIR/networks.cfg" <<'EOF'
10.1.1.0/24 ControlNetA
10.1.2.0/24 ControlNetB
EOF

cat > "$ETC_DIR/node.cfg" <<'EOF'
[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost

[proxy]
type=proxy
host=localhost

[worker-1]
type=worker
host=localhost
interface=eth0

[worker-2]
type=worker
host=localhost
interface=eth1
EOF

cat > "$SITE_DIR/iaea-json-logs.zeek" <<'EOF'
redef LogAscii::use_json = T;
EOF

if ! grep -q "iaea-json-logs" "$SITE_DIR/local.zeek" 2>/dev/null; then
  printf '\n@load ./iaea-json-logs.zeek\n' >> "$SITE_DIR/local.zeek"
fi

if grep -q "^LogDir" "$ETC_DIR/zeekctl.cfg" 2>/dev/null; then
  sed -i "s|^LogDir = .*|LogDir = $LOG_DIR|" "$ETC_DIR/zeekctl.cfg"
else
  printf '\nLogDir = %s\n' "$LOG_DIR" >> "$ETC_DIR/zeekctl.cfg"
fi

if grep -q "^SpoolDir" "$ETC_DIR/zeekctl.cfg" 2>/dev/null; then
  sed -i "s|^SpoolDir = .*|SpoolDir = $SPOOL_DIR|" "$ETC_DIR/zeekctl.cfg"
else
  printf '\nSpoolDir = %s\n' "$SPOOL_DIR" >> "$ETC_DIR/zeekctl.cfg"
fi

zeekctl deploy

tail -F "$LOG_DIR"/current/*.log
