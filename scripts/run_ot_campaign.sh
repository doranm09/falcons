#!/usr/bin/env bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

BASE_URL="${BASE_URL:-http://localhost:8000}"
CIDR="${1:-${CIDR:-172.30.2.0/24}}"
SCAN_METHOD="${SCAN_METHOD:-nmap}"
AGENT_ID="${AGENT_ID:-}"
RUN_OPENVAS="${RUN_OPENVAS:-1}"
GVMD_CONFIG="${GVMD_CONFIG:-full_and_fast}"
SLIVER_SESSION_ID="${SLIVER_SESSION_ID:-}"
SLIVER_COMMAND="${SLIVER_COMMAND:-whoami}"
COLLECT_LOOT="${COLLECT_LOOT:-1}"

echo "Starting OT campaign: cidr=${CIDR} method=${SCAN_METHOD} openvas=${RUN_OPENVAS} agent=${AGENT_ID:-none}"

START_JSON="$(
  curl -fsS -X POST "${BASE_URL}/scan/campaign/start/" \
    -F "cidr=${CIDR}" \
    -F "scan_method=${SCAN_METHOD}" \
    -F "agent_id=${AGENT_ID}" \
    -F "run_openvas=${RUN_OPENVAS}" \
    -F "gvmd_config=${GVMD_CONFIG}" \
    -F "sliver_session_id=${SLIVER_SESSION_ID}" \
    -F "sliver_command=${SLIVER_COMMAND}" \
    -F "collect_loot=${COLLECT_LOOT}"
)"

TASK_ID="$(echo "${START_JSON}" | jq -r '.task_id // empty')"
if [[ -z "${TASK_ID}" ]]; then
  echo "Failed to start campaign: ${START_JSON}" >&2
  exit 1
fi

echo "Task queued: ${TASK_ID}"

while true; do
  STATUS_JSON="$(curl -fsS "${BASE_URL}/scan/campaign/status/${TASK_ID}/")"
  STATE="$(echo "${STATUS_JSON}" | jq -r '.state')"
  STEP="$(echo "${STATUS_JSON}" | jq -r '.step // empty')"
  MESSAGE="$(echo "${STATUS_JSON}" | jq -r '.message // empty')"

  if [[ "${STATE}" == "PROGRESS" ]]; then
    if [[ -n "${STEP}" || -n "${MESSAGE}" ]]; then
      echo "[${STATE}] ${STEP} ${MESSAGE}"
    else
      echo "[${STATE}] running..."
    fi
    sleep 3
    continue
  fi

  echo "Final state: ${STATE}"
  echo "${STATUS_JSON}" | jq '.result // .'
  break
done
