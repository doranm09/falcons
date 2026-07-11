#!/usr/bin/env bash
set -euo pipefail

iptables -F
iptables -t nat -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

add_tcp_rule() {
  local src="$1"
  local dst="$2"
  local ports_csv="$3"
  local old_ifs=$IFS
  IFS=','
  for port in $ports_csv; do
    [ -n "$port" ] || continue
    iptables -A FORWARD -s "$src" -d "$dst" -p tcp --dport "$port" -j ACCEPT
  done
  IFS=$old_ifs
}

load_rule_specs() {
  local mode="$1"
  local specs="$2"
  local old_ifs=$IFS
  IFS=';'
  for spec in $specs; do
    [ -n "$spec" ] || continue
    IFS=$old_ifs
    spec=${spec//|/ }
    read -r src dst ports <<<"$spec"
    if [ -z "${src:-}" ] || [ -z "${dst:-}" ] || [ -z "${ports:-}" ]; then
      echo "invalid ${mode} rule spec: $spec" >&2
      exit 1
    fi
    add_tcp_rule "$src" "$dst" "$ports"
    if [ "$mode" = "bidir" ]; then
      add_tcp_rule "$dst" "$src" "$ports"
    fi
    IFS=';'
  done
  IFS=$old_ifs
}

if [ -n "${STATIC_ROUTES:-}" ]; then
  old_ifs=$IFS
  IFS=';'
  for route in $STATIC_ROUTES; do
    [ -n "$route" ] || continue
    IFS=$old_ifs
    ip route replace $route
    IFS=';'
    echo "${FIREWALL_NAME:-firewall} route installed: $route"
  done
  IFS=$old_ifs
fi

case "${RULESET:-default}" in
  l2_l3)
    ALLOW_TCP=${ALLOW_TCP:-"10.2.50.10|10.3.50.10|443,4840;10.2.50.20|10.3.50.10|443,4840"}
    ;;
  l3_l4)
    ALLOW_TCP=${ALLOW_TCP:-"10.4.50.10|10.3.50.10|443,4840;10.4.50.10|10.4.50.20|5432"}
    ;;
  *)
    ;;
esac

if [ -n "${ALLOW_TCP:-}" ]; then
  load_rule_specs unidir "${ALLOW_TCP}"
fi

if [ -n "${ALLOW_BIDIR_TCP:-}" ]; then
  load_rule_specs bidir "${ALLOW_BIDIR_TCP}"
fi

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "${FIREWALL_NAME:-firewall} rules loaded"
exec sh -c 'while true; do sleep 3600; done'
