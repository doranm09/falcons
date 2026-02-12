# === Defaults ===
vm config memory 2048
vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm config snapshot true

# ------------------------------------------------------------
# Segmentation using existing OVS bridges:
#
#   Level 1 (Primary Control):         br_10_1_13, VLAN 1
#   Level 1R (Redundant Control):      br_10_4_13, VLAN 4
#   Level 2 (Supervisory / Hosts):     br_10_2_13, VLAN 2
#   Level 3 (Plant Information):       br_10_3_13, VLAN 3
#   OOB Management Network:            br_oob_10,  VLAN 10
#
# Inter-layer connectivity is provided *only* via dedicated
# gateway VMs between L1↔L2 and L2↔L3.
# ------------------------------------------------------------


# ============================================================
# Inter-Layer Gateways (bridges between segments)
# ============================================================

# Gateway between Level 1 (control) and Level 2 (supervisory)
# Acts as firewall/router/L3 bridge in a real deployment.
vm config networks br_10_1_13,1 br_10_2_13,2 br_oob_10,10
vm launch kvm gw-l1-l2

# Gateway between Level 2 (supervisory) and Level 3 (plant info)
vm config networks br_10_2_13,2 br_10_3_13,3 br_oob_10,10
vm launch kvm gw-l2-l3


# ============================================================
# Level 1 — Controller Network (Primary + Redundant)
# ============================================================

# vPLC1
vm config networks br_10_1_13,1 br_10_4_13,4 br_oob_10,10
vm launch kvm vplc1

# vPLC2
vm config networks br_10_1_13,1 br_10_4_13,4 br_oob_10,10
vm launch kvm vplc2

# Allen-Bradley PLC
vm config networks br_10_1_13,1 br_10_4_13,4 br_oob_10,10
vm launch kvm ab-plc


# ============================================================
# Level 2 — Supervisory Layer (Engineering Workstation, Pentest)
# ============================================================

# Engineering Host Machine
vm config networks br_10_2_13,2 br_oob_10,10
vm launch kvm host-machine

# Pentest Host
vm config networks br_10_2_13,2 br_oob_10,10
vm launch kvm pentest-host


# ============================================================
# Level 3 — Plant Information Layer (Historian)
# ============================================================

# Data Historian
vm config networks br_10_3_13,3 br_oob_10,10
vm launch kvm historian


# ============================================================
# Start all
# ============================================================
vm start all
