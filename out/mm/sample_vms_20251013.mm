# Sample MiniMega VM script
# Launch two Ubuntu VMs with networking

vm launch ubuntu ubuntu-1
vm launch ubuntu ubuntu-2

# Configure networking
vm net ubuntu-1 0
vm net ubuntu-2 0

# Start VMs
vm start ubuntu-1
vm start ubuntu-2
