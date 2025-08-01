# MiniMega VM Script Generator

This Python utility dynamically generates MiniMega-compatible `.mm` scripts to automate the deployment of multiple Linux virtual machines (VMs). You can specify the number of VMs, VLAN assignment, and disk image path.

---

## 🧩 Features

- Configurable number of VMs
- Shared or custom disk image (.qcow2)
- Custom VLAN / virtual network ID
- Outputs a MiniMega launch script (`.mm` file)

---

## 🚀 Usage

### 1. Run from the command line:

```bash
python generate_minimega_script.py \
  --count 3 \
  --vlan 200 \
  --disk /var/lib/minimega/images/debian.qcow2 \
  --output launch_vms.mm
