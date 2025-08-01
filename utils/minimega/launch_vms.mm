clear vm config
vm config memory 2048
vm config net 100

vm config disk /var/lib/minimega/images/standalone-vm01.qcow2
vm launch kvm vm01

vm config disk /var/lib/minimega/images/standalone-vm01.qcow2
vm launch kvm vm02

vm config disk /var/lib/minimega/images/standalone-vm01.qcow2
vm launch kvm vm03

vm start all