# Enabling Virtio-Serial Support for MiniMega with miniccc

This guide explains how to enable `virtio-ports` support in MiniMega VM configurations using `miniccc` over virtio-serial. If you're encountering errors like:

```
ERROR vm.go:914: vm 0: unable to connect to qmp socket: qmp timeout
```


you are likely missing the required `virtio_console` kernel module.

---

## System Requirements

- Ubuntu 20.04 or newer
- MiniMega installed and functioning
- Kernel version with full module support
- `virtio_console` module present and loadable

---

## Check for virtio support

Check which virtio-related kernel modules are present:

```bash
find /lib/modules/$(uname -r) -type f -name '*virtio*'

sudo apt update
sudo apt install linux-modules-extra-$(uname -r)

sudo modprobe virtio_console

lsmod | grep virtio

sudo minimega

clear vm config
vm config memory 2048
vm config net 200
vm config virtio-ports cc
vm config disk /var/lib/minimega/images/base-with-miniccc.qcow2
vm launch kvm vm01
vm start vm01

echo virtio_console | sudo tee -a /etc/modules
