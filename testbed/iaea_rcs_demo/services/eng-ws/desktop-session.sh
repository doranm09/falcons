#!/usr/bin/env bash
set -euo pipefail

ENGINEER_HOME="${HOME:-/home/engineer}"
GATEWAY_URL="${IGNITION_GATEWAY_URL:-http://ignition:8088}"
LAUNCHER_DIR=/opt/eng-ws/designerlauncher

mkdir -p "${ENGINEER_HOME}/.config/openbox" "${ENGINEER_HOME}/Desktop"

cat > "${ENGINEER_HOME}/.config/openbox/autostart" <<EOF
xterm -geometry 120x30+20+20 -fa Monospace -fs 11 -title "Layer 2 Shell" -e bash -lc 'printf "Layer 2 engineering workstation\\nGateway: ${GATEWAY_URL}\\nDesigner Launcher is starting...\\n"; exec bash' &
sleep 2
"${LAUNCHER_DIR}/designerlauncher.sh" &
EOF

cat > "${ENGINEER_HOME}/Desktop/Designer Launcher.desktop" <<EOF
[Desktop Entry]
Name=Designer Launcher
Exec=${LAUNCHER_DIR}/designerlauncher.sh
Icon=${LAUNCHER_DIR}/app/launcher.png
Terminal=false
Type=Application
Categories=Development;Network;
EOF

chmod +x "${ENGINEER_HOME}/Desktop/Designer Launcher.desktop"

exec dbus-launch --exit-with-session openbox-session
