# Add (or re-add) the NIC as a trunk port
sudo ovs-vsctl --may-exist add-br mega_bridge
sudo ovs-vsctl --may-exist add-port mega_bridge eno1
sudo ovs-vsctl set port eno1 trunks=1,2,3,4,10

# OOB host interface (VLAN 10) -> oob0
sudo ovs-vsctl --may-exist add-port mega_bridge oob0 -- set interface oob0 type=internal
sudo ovs-vsctl set port oob0 vlan_mode=native-untagged tag=10
sudo ip addr add 10.1.13.254/24 dev oob0
sudo ip link set oob0 up

# Control nets host interfaces (optional)
sudo ovs-vsctl --may-exist add-port mega_bridge ctrl3 -- set interface ctrl3 type=internal
sudo ovs-vsctl set port ctrl3 vlan_mode=native-untagged tag=3
sudo ip addr add 10.3.13.254/24 dev ctrl3
sudo ip link set ctrl3 up

sudo ovs-vsctl --may-exist add-port mega_bridge ctrl4 -- set interface ctrl4 type=internal
sudo ovs-vsctl set port ctrl4 vlan_mode=native-untagged tag=4
sudo ip addr add 10.4.13.254/24 dev ctrl4
sudo ip link set ctrl4 up

vm config memory 2048
vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm config snapshot true

# --- OOB relay/collector: NICs on VLAN 10, 3, 4 ---
vm config net 10
vm config networks mega_bridge
vm config net 3
vm config networks mega_bridge
vm config net 4
vm config networks mega_bridge
vm launch kvm oob-collector

# --- PT-455 on primary I/O (VLAN 1) ---
vm config net 1
vm config networks mega_bridge
vm launch kvm pt-455

# --- PT-456 dual-homed (VLAN 1 and 2) ---
vm config net 1
vm config networks mega_bridge
vm config net 2
vm config networks mega_bridge
vm launch kvm pt-456

# --- PT-457 dual-homed (VLAN 1 and 2) ---
vm config net 1
vm config networks mega_bridge
vm config net 2
vm config networks mega_bridge
vm launch kvm pt-457

# --- PT-458 backup I/O only (VLAN 2) ---
vm config net 2
vm config networks mega_bridge
vm launch kvm pt-458

# --- PLC-Main (VLAN 1 + VLAN 3) ---
vm config net 1
vm config networks mega_bridge
vm config net 3
vm config networks mega_bridge
vm launch kvm plc-main

# --- PLC-Backup (VLAN 2 + VLAN 4) ---
vm config net 2
vm config networks mega_bridge
vm config net 4
vm config networks mega_bridge
vm launch kvm plc-backup

# --- Valve controllers on control nets (VLAN 3 + VLAN 4) ---
vm config net 3
vm config networks mega_bridge
vm config net 4
vm config networks mega_bridge
vm launch kvm vc-pv455a
vm launch kvm vc-pv455b
vm launch kvm vc-pv455c

# --- Heat Controller (VLAN 3 + VLAN 4) ---
vm config net 3
vm config networks mega_bridge
vm config net 4
vm config networks mega_bridge
vm launch kvm heat-ctrl

vm start all

A) Pull model (preferred) — no forwarding required

Run collectors on oob-collector (e.g., Telegraf/Prometheus/Fluent Bit/Zeek) that initiate connections from OOB → VLAN3/4.
No firewall rules or routes needed on PLCs/VCs, and no cross-VLAN chatter other than the specific sessions you initiate.