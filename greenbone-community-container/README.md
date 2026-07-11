# Start Greenbone

From the repo root:

```bash
docker compose \
  -f greenbone-community-container/compose.yaml \
  -f greenbone-community-container/docker-compose.iaea-networks.yml \
  up -d
```

This override attaches `ospd-openvas` directly to the validated IAEA hybrid
topology networks:

- `iaea_rcs_demo_l4_net` at `10.4.50.250`
- `iaea_rcs_demo_l3_net` at `10.3.50.250`
- `iaea_rcs_demo_l2_net` at `10.2.50.250`
- `iaea_rcs_demo_net_10_1_1` at `10.1.1.249`
- `iaea_rcs_demo_net_10_1_2` at `10.1.2.249`
- `iaea_rcs_demo_oob_mgmt` at `172.31.250.249`

The Level 1 addresses intentionally use `.249` because `.250` is already
assigned to `span-l1a` and `span-l1b` in the hybrid compose stack.

# Default Manager Credentials

The bundled `start-gvmd` entrypoint defaults to:

- username: `admin`
- password: `admin`

# Stop Greenbone

```bash
docker compose \
  -f greenbone-community-container/compose.yaml \
  -f greenbone-community-container/docker-compose.iaea-networks.yml \
  down
```
