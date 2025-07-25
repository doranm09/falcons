# Define a Shared VLAN Network
```
net add experiment
net forward experiment none  # No external NAT/DHCP
```

or simply

```
vm config net 100  # Uses vlan 100 (auto-bridged)
```

# Configure and Launch VMs

```
vm config memory 2048
vm config net 100
vm config disk /var/lib/minimega/images/vm01.qcow2
vm launch kvm vm01

vm config disk /var/lib/minimega/images/vm02.qcow2
vm launch kvm vm02

```

# Assign static IP in each VM
```
sudo ip addr add 192.168.100.11/24 dev enp1s1
sudo ip link set enp1s1 up

```

# Bridge Host to VM Network

```
sudo ovs-vsctl add-port mega_bridge eth1  # Replace eth1 with the correct NIC

```

# Setup veth-pair
```
sudo ip link add veth-host type veth peer name veth-br
sudo ip addr add 192.168.100.1/24 dev veth-host
sudo ip link set veth-host up
ip link show veth-host
ip addr show veth-host

```

# Settings
```
sudo ovs-vsctl show

a8f69c7a-6bc9-407f-b0a2-725837c5156f
    Bridge mega_bridge
        Port mega_tap0
            tag: 100
            Interface mega_tap0
        Port mega_tap1
            tag: 100
            Interface mega_tap1
        Port mega_bridge
            Interface mega_bridge
                type: internal
        Port veth-br
            tag: 100
            Interface veth-br
    ovs_version: "3.3.0"


```

```
ip addr show mega_bridge
ip addr show veth-host
ip addr show veth-br
ip addr show mega_tap0
ip addr show mega_tap1


25: mega_bridge: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether 6e:6b:67:16:82:4d brd ff:ff:ff:ff:ff:ff
29: veth-host@veth-br: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 32:3c:40:4f:bf:01 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.1/24 scope global veth-host
       valid_lft forever preferred_lft forever
28: veth-br@veth-host: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc noqueue master ovs-system state UP group default qlen 1000
    link/ether 7e:9d:83:c9:d7:45 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::7c9d:83ff:fec9:d745/64 scope link 
       valid_lft forever preferred_lft forever
26: mega_tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master ovs-system state UP group default qlen 1000
    link/ether 56:28:4d:ac:7b:50 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::5428:4dff:feac:7b50/64 scope link 
       valid_lft forever preferred_lft forever
27: mega_tap1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master ovs-system state UP group default qlen 1000
    link/ether be:ff:d8:f4:63:71 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::bcff:d8ff:fef4:6371/64 scope link 
       valid_lft forever preferred_lft forever

```

# Routing Table

```

ip route show

```

# ARP Tables (MAC/IP Pairings)

```
ip neigh show dev veth-host
ip neigh show dev mega_bridge

```