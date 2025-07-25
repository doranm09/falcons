mkdir -p ~/network_debug
(
  echo "=== OVS ==="
  sudo ovs-vsctl show
  echo -e "\n=== Interface IPs ==="
  ip addr show
  echo -e "\n=== Routes ==="
  ip route show
  echo -e "\n=== ARP ==="
  ip neigh show
  echo -e "\n=== Firewall ==="
  sudo iptables -L -n -v
  echo -e "\n=== RP Filter ==="
  sysctl net.ipv4.conf.veth-host.rp_filter
  sysctl net.ipv4.conf.all.rp_filter
) > ~/network_debug/mega_bridge_config.txt
