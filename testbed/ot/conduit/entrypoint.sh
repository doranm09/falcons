#!/bin/sh
set -e

ALLOWED_PORTS="${ALLOWED_PORTS:-}"
DEFAULT_POLICY="${DEFAULT_POLICY:-DROP}"

iptables -P INPUT ${DEFAULT_POLICY}
iptables -P FORWARD ${DEFAULT_POLICY}
iptables -P OUTPUT ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

if [ -n "$ALLOWED_PORTS" ]; then
  for port in $(echo "$ALLOWED_PORTS" | tr ',' ' '); do
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done
fi

exec python3 /app/conduit.py
