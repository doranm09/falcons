clear vm config
vm config memory 2048
vm config net 200
vm config virtio-ports cc

vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm launch kvm vm01

vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm launch kvm vm02

vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm launch kvm vm03

vm start all