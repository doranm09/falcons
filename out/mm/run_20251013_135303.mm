clear

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-00

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-01

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-02

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-03

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-04

vm config memory 4096
vm config vcpus 2
vm config bridge br-int
vm config vlan 200
vm config virtio-ports miniccc=ch0
vm config virtio-ports telemetry=ch1
vm config disk /var/lib/minimega/snapshots/ubuntu-server-snap.qcow2
vm launch kvm scan-provision-ubuntu-server-05

vm start all
