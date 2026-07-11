#!/usr/bin/env bash
set -euo pipefail

ENGINEER_HOME="${HOME:-/home/engineer}"

mkdir -p "${ENGINEER_HOME}/.config/openbox" "${ENGINEER_HOME}/Desktop"

cat > "${ENGINEER_HOME}/.config/openbox/autostart" <<EOF
xterm -geometry 120x30+20+20 -fa Monospace -fs 11 -title "Layer 2 Shell" -e bash -lc 'printf "Layer 2 engineering workstation\\nUse opc-read and tcpdump for PLC path verification.\\n"; exec bash' &
EOF

exec dbus-launch --exit-with-session openbox-session
