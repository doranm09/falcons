# Snapshot a qcow

```
sudo qemu-img create -f qcow2 -b /var/lib/libvirt/images/ifan-ubuntu24.04.qcow2 -F qcow2 /var/lib/minimega/images/vm01.qcow2
```

# Convert the Modified Snapshot into a New Base Image

```
qemu-img convert -f qcow2 -O qcow2 /path/to/modified-vm.qcow2 /var/lib/minimega/images/base-with-miniccc.qcow2


```