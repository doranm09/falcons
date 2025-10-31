# Make each bridge's internal port native-untagged to the VM's tag
```
# Set the bridge's internal port to native-untagged VLAN 2
sudo ovs-vsctl set port br_10_3_13 vlan_mode=native-untagged tag=2
sudo ovs-vsctl set port br_10_2_13 vlan_mode=native-untagged tag=1

```

# Sanity check

```
# Show the whole picture
sudo ovs-vsctl show
```

You should see something like this:

```

Bridge br_10_2_13
        Port br_10_2_13
            tag: 1
            Interface br_10_2_13
                type: internal
        Port mega_tap0
            tag: 1
            Interface mega_tap0
    Bridge br_10_3_13
        Port mega_tap1
            tag: 2
            Interface mega_tap1
        Port br_10_3_13
            tag: 2
            Interface br_10_3_13
                type: internal
    ovs_version: "3.3.0"

```

# Pressurizer setup

| Device                  | Interface 1 (Primary)           | Interface 2 (Secondary)        | Description / Function                                  |
| ----------------------- | ------------------------------- | ------------------------------ | ------------------------------------------------------- |
| **PT-455**              | `br_10_1_13` → `10.1.13.1/24`   | —                              | Pressure Transmitter #1 on primary I/O subnet           |
| **PT-456**              | `br_10_1_13` → `10.1.13.2/24`   | `br_10_2_13` → `10.2.23.2/24`  | Pressure Transmitter #2 with redundant I/O path         |
| **PT-457**              | `br_10_1_13` → `10.1.13.3/24`   | `br_10_2_13` → `10.2.13.3/24`  | Pressure Transmitter #3 on primary I/O subnet           |
| **PT-458**              | `br_10_2_13` → `10.2.13.3/24`   | -                              | Pressure Transmitter #4 on redundant I/O subnet         |
| **PLC-Main**            | `br_10_1_13` → `10.1.13.10/24`  | `br_10_3_13` → `10.3.13.10/24` | Primary PLC controller bridging I/O and control domains |
| **PLC-Backup**          | `br_10_2_13` → `10.2.23.10/24`  | `br_10_4_23` → `10.4.23.10/24` | Backup PLC controller                                   |
| **VC-PV455A**           | `br_10_3_13` → `10.3.13.1/24`   | `br_10_4_13` → `10.4.13.1/24`  | Valve Controller A, dual-connected                      |
| **VC-PV455B**           | `br_10_3_13` → `10.3.13.2/24`   | `br_10_4_13` → `10.4.13.2/24`  | Valve Controller B, dual-connected                      |
| **VC-PV455C**           | `br_10_3_13` → `10.3.13.3/24`   | `br_10_4_13` → `10.4.13.3/24`  | Valve Controller C, dual-connected                      |
| **Heat-Ctrl**           | `br_10_3_13` → `10.3.13.5/24`   | `br_10_4_23` → `10.4.23.5/24`  | Heating controller with dual connectivity               |

| Bridge (OVS Name) | Subnet         | Connected Devices                  | Typical Role                   | OVS VLAN Tag (example) |
| ----------------- | -------------- | ---------------------------------- | ------------------------------ | ---------------------- |
| `br_10_2_13`      | `10.2.13.0/24` | PT-455, PT-456, PLC-Main           | Primary I/O (sensor data)      | 1                      |
| `br_10_2_23`      | `10.2.23.0/24` | PT-456, PLC-Backup                 | Backup I/O network             | 3                      |
| `br_10_3_13`      | `10.3.13.0/24` | PLC-Main, VC-PV455A/B/C, Heat-Ctrl | Main control/actuation network | 2                      |
| `br_10_4_13`      | `10.4.13.0/24` | VC-PV455A/B/C                      | Backup control network         | 4                      |
| `br_10_4_23`      | `10.4.23.0/24` | PLC-Backup, Heat-Ctrl              | Backup control + heating path  | 5                      |


# Set VM ip address

```
vm shell plc-main
# inside the guest
ip addr add 10.2.13.10/24 dev eth0
ip addr add 10.3.13.10/24 dev eth1
ip link set eth0 up
ip link set eth1 up
exit


```

# Commands for ovs bridges

```
# Example: test the 10.3.13.x network from host
sudo ip addr add 10.3.13.254/24 dev br_10_3_13
sudo ip link set br_10_3_13 up

sudo ip addr add 10.2.13.254/24 dev br_10_2_13
sudo ip link set br_10_2_13 up

# Ping a VM on that subnet
ping -c2 10.3.13.10     # plc-main

```