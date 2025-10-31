vm config memory 2048
vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2

# === Primary Pressure Transmitter 455 === 
vm config networks br_10_1_13,1
vm launch kvm pt-455

# === Redundnant Pressure Transmitter 456, 457 ===
vm config networks br_10_1_13,1 br_10_2_13,2
vm launch kvm pt-456
vm launch kvm pt-457

# === Secondary Pressure Transmitter 458 ===
vm config networks br_10_2_13,2
vm launch kvm pt-458

# === PLC-Main ===
vm config networks br_10_1_13,1 br_10_3_13,3
vm launch kvm plc-main

# === PLC-Backup ===
vm config networks br_10_2_13,1 br_10_4_13,4
vm launch kvm plc-backup

# === Valve controllers ===
vm config networks br_10_3_13,3 br_10_4_13,4
vm launch kvm vc-pv455a
vm launch kvm vc-pv455b
vm launch kvm vc-pv455c

# === Heat Controller ===
vm launch kvm heat-ctlr

vm start all