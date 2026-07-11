#!/usr/bin/env bash
set -euo pipefail

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

ENGINEER_HOME=/home/engineer
DISPLAY_NUMBER="${ENGINEER_WS_DISPLAY_NUMBER:-0}"
DISPLAY=":${DISPLAY_NUMBER}"
VNC_PORT="${ENGINEER_WS_VNC_PORT:-5900}"
NOVNC_PORT="${ENGINEER_WS_NOVNC_PORT:-6080}"
VNC_PASSWORD="${ENGINEER_WS_VNC_PASSWORD:-engwsdemo}"
DESKTOP_GEOMETRY="${ENGINEER_WS_DESKTOP_GEOMETRY:-1440x900}"
RUNTIME_LOG_DIR=/tmp/eng-ws
XVFB_LOG="${RUNTIME_LOG_DIR}/xvfb.log"
X11VNC_LOG="${RUNTIME_LOG_DIR}/x11vnc.log"
WEBSOCKIFY_LOG="${RUNTIME_LOG_DIR}/websockify.log"
HOST_AGENT_LOG="${RUNTIME_LOG_DIR}/host-agent.log"

prepare_home() {
  mkdir -p \
    "${RUNTIME_LOG_DIR}" \
    "${ENGINEER_HOME}/.config/openbox" \
    "${ENGINEER_HOME}/.vnc" \
    "${ENGINEER_HOME}/Desktop"
  chown -R engineer:engineer "${ENGINEER_HOME}"
}

wait_for_x_socket() {
  local socket="/tmp/.X11-unix/X${DISPLAY_NUMBER}"
  for _ in $(seq 1 100); do
    [ -S "${socket}" ] && return 0
    sleep 0.1
  done
  echo "Xvfb socket ${socket} did not appear" >&2
  if [ -f "${XVFB_LOG}" ]; then
    tail -n 40 "${XVFB_LOG}" >&2 || true
  fi
  return 1
}

prepare_home

if [ -f /usr/local/bin/start_host_agent.sh ]; then
  . /usr/local/bin/start_host_agent.sh
  start_host_agent
fi

Xvfb "${DISPLAY}" -screen 0 "${DESKTOP_GEOMETRY}x24" -nolisten tcp >>"${XVFB_LOG}" 2>&1 &
xvfb_pid=$!
wait_for_x_socket

su -s /bin/bash engineer -c "HOME=${ENGINEER_HOME} DISPLAY=${DISPLAY} /opt/eng-ws/desktop-session.sh" &
desktop_pid=$!

x11vnc -storepasswd "${VNC_PASSWORD}" "${ENGINEER_HOME}/.vnc/passwd" >/dev/null 2>&1
chown engineer:engineer "${ENGINEER_HOME}/.vnc/passwd"

x11vnc \
  -display "${DISPLAY}" \
  -rfbport "${VNC_PORT}" \
  -rfbauth "${ENGINEER_HOME}/.vnc/passwd" \
  -forever \
  -shared \
  -quiet \
  -xkb \
  -no6 \
  -noipv6 \
  -nowireframe \
  -noscrollcopyrect \
  -nodpms \
  -noxrecord \
  -noxfixes \
  -noxdamage >>"${X11VNC_LOG}" 2>&1 &
vnc_pid=$!

websockify --web=/usr/share/novnc/ "${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" >>"${WEBSOCKIFY_LOG}" 2>&1 &
novnc_pid=$!

"$@" &
main_pid=$!

cleanup() {
  kill "${main_pid}" 2>/dev/null || true
  kill "${novnc_pid}" 2>/dev/null || true
  kill "${vnc_pid}" 2>/dev/null || true
  kill "${desktop_pid}" 2>/dev/null || true
  kill "${xvfb_pid}" 2>/dev/null || true
  if [ -n "${HOST_AGENT_PID:-}" ]; then
    kill "${HOST_AGENT_PID}" 2>/dev/null || true
  fi
  wait "${main_pid}" 2>/dev/null || true
  wait "${novnc_pid}" 2>/dev/null || true
  wait "${vnc_pid}" 2>/dev/null || true
  wait "${desktop_pid}" 2>/dev/null || true
  wait "${xvfb_pid}" 2>/dev/null || true
  if [ -n "${HOST_AGENT_PID:-}" ]; then
    wait "${HOST_AGENT_PID}" 2>/dev/null || true
  fi
}

trap cleanup INT TERM

wait -n "${main_pid}" "${novnc_pid}" "${vnc_pid}" "${desktop_pid}" "${xvfb_pid}"
status=$?
cleanup
exit "${status}"
