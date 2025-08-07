# Create a host directory to hold the gvmd socket

```bash

sudo mkdir -p /opt/gvm-run
sudo chmod 777 /opt/gvm-run  # dev-only perms; restrict later

```

# Start OpenVAS

```bash
docker compose down
docker compose up -d

```