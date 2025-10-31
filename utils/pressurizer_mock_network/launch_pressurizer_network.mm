# === Defaults ===
vm config memory 2048
vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm config snapshot true

# ------------------------------------------------------------
# OOB management: VLAN 10 on bridge br_oob_10
# Control nets:   VLAN 3  on bridge br_10_3_13
#                 VLAN 4  on bridge br_10_4_13
# I/O nets:       VLAN 1  on bridge br_10_1_13
#                 VLAN 2  on bridge br_10_2_13
# ------------------------------------------------------------

# === OOB Collector / Relay (multi-homed: OOB + control nets) ===
vm config networks br_oob_10,10 br_10_3_13,3 br_10_4_13,4
vm launch kvm oob-collector

# === Primary Pressure Transmitter 455 (I/O VLAN 1 only) ===
vm config networks br_10_1_13,1
vm launch kvm pt-455

# === Redundant Pressure Transmitters 456, 457 (I/O VLAN 1 + VLAN 2) ===
vm config networks br_10_1_13,1 br_10_2_13,2
vm launch kvm pt-456
vm launch kvm pt-457

# === Secondary Pressure Transmitter 458 (I/O VLAN 2 only) ===
vm config networks br_10_2_13,2
vm launch kvm pt-458

# === PLC-Main (I/O VLAN 1 + Control VLAN 3) ===
vm config networks br_10_1_13,1 br_10_3_13,3
vm launch kvm plc-main

# === PLC-Backup (I/O VLAN 2 + Control VLAN 4) ===
vm config networks br_10_2_13,2 br_10_4_13,4
vm launch kvm plc-backup

# === Valve controllers (Control VLAN 3 + VLAN 4) ===
vm config networks br_10_3_13,3 br_10_4_13,4
vm launch kvm vc-pv455a
vm launch kvm vc-pv455b
vm launch kvm vc-pv455c

# === Heat Controller (Control VLAN 3 + VLAN 4) ===
vm config networks br_10_3_13,3 br_10_4_13,4
vm launch kvm heat-ctlr


# Start all
vm start all
