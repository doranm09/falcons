#!/bin/sh
set -eu

source_ip="${DIODE_SOURCE_IP:?DIODE_SOURCE_IP is required}"
destination_ip="${DIODE_DESTINATION_IP:?DIODE_DESTINATION_IP is required}"
destination_port="${DIODE_DESTINATION_PORT:?DIODE_DESTINATION_PORT is required}"
protocol="${DIODE_PROTOCOL:-udp}"

case "${protocol}" in
  udp|tcp) ;;
  *)
    echo "unsupported DIODE_PROTOCOL: ${protocol}" >&2
    exit 2
    ;;
esac

iptables -F
iptables -t nat -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

# Deliberately one-way. Do not add a reverse rule and do not add a general
# ESTABLISHED,RELATED rule to FORWARD. UDP is used because TCP acknowledgements
# would require a reverse path and would no longer model the manuscript diode.
iptables -A FORWARD \
  -s "${source_ip}" \
  -d "${destination_ip}" \
  -p "${protocol}" \
  --dport "${destination_port}" \
  -j ACCEPT

# Make the intended publication policy visible in container logs and validation.
echo "data-diode policy loaded: ${source_ip} -> ${destination_ip}:${destination_port}/${protocol}"
echo "reverse forwarding remains DROP"
iptables -S FORWARD

exec sh -c 'while true; do sleep 3600; done'
