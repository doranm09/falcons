start_host_agent() {
  if [ -z "${AGENT_SERVER_URL:-}" ]; then
    if getent hosts host.docker.internal >/dev/null 2>&1; then
      AGENT_SERVER_URL="http://host.docker.internal:8000"
    else
      gateway_ip="$(ip route show default 2>/dev/null | awk 'NR==1 {print $3}')"
      if [ -n "${gateway_ip:-}" ]; then
        AGENT_SERVER_URL="http://${gateway_ip}:8000"
      fi
    fi
    if [ -n "${AGENT_SERVER_URL:-}" ]; then
      export AGENT_SERVER_URL
    fi
  fi

  if [ -z "${AGENT_SERVER_URL:-}" ]; then
    echo "host agent disabled: AGENT_SERVER_URL not set and no default gateway found"
    return 0
  fi

  if [ -z "${AGENT_API_TOKEN:-}" ]; then
    AGENT_API_TOKEN="iaea-demo-agent-token"
    export AGENT_API_TOKEN
  fi

  if [ -z "${AGENT_ID:-}" ]; then
    AGENT_ID="$(hostname)"
    export AGENT_ID
  fi

  HOST_AGENT_DIR="${HOST_AGENT_DIR:-/opt/host_agent}"
  HOST_AGENT_LOG_DIR="${HOST_AGENT_LOG_DIR:-/tmp/host-agent}"
  HOST_AGENT_PYTHON="${HOST_AGENT_PYTHON:-python3}"

  mkdir -p "${HOST_AGENT_LOG_DIR}"

  "${HOST_AGENT_PYTHON}" "${HOST_AGENT_DIR}/agent.py" --url "${AGENT_SERVER_URL}" run \
    >"${HOST_AGENT_LOG_DIR}/agent.log" 2>&1 &
  HOST_AGENT_PID=$!
  export HOST_AGENT_PID

  HOST_AGENT_SNIFF_PIDS=""
  if [ -n "${HOST_AGENT_SNIFF_INTERFACES:-}" ]; then
    old_ifs=$IFS
    IFS=','
    for iface in ${HOST_AGENT_SNIFF_INTERFACES}; do
      iface="$(printf '%s' "${iface}" | xargs)"
      [ -n "${iface}" ] || continue
      "${HOST_AGENT_PYTHON}" "${HOST_AGENT_DIR}/agent.py" --url "${AGENT_SERVER_URL}" sniff --interface "${iface}" \
        >"${HOST_AGENT_LOG_DIR}/sniff-${iface}.log" 2>&1 &
      sniff_pid=$!
      if [ -z "${HOST_AGENT_SNIFF_PIDS}" ]; then
        HOST_AGENT_SNIFF_PIDS="${sniff_pid}"
      else
        HOST_AGENT_SNIFF_PIDS="${HOST_AGENT_SNIFF_PIDS} ${sniff_pid}"
      fi
      echo "host agent sniff started: pid=${sniff_pid} iface=${iface}"
    done
    IFS=$old_ifs
    export HOST_AGENT_SNIFF_PIDS
  fi

  echo "host agent started: pid=${HOST_AGENT_PID} url=${AGENT_SERVER_URL}"
}
