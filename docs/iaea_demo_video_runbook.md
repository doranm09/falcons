# IAEA Demo Video Runbook

This is the current operator path for recording the validated IAEA hybrid demo on April 28, 2026.

## Scope

- Django dashboard and SIEM at `http://127.0.0.1:8000/dashboard/`
- Hybrid Purdue testbed from `testbed/iaea_rcs_demo/docker-compose-hybrid.yml`
- Current validated topology:
  - Layer 4: `metasploit 10.4.50.10`, `postgres 10.4.50.20`
  - Layer 3: `historian 10.3.50.10`
  - Layer 2: `hmi 10.2.50.10`, `engineer-ws 10.2.50.20`
  - Layer 1: `plc-main 10.1.1.14 / 10.1.2.14`, `plc-backup 10.1.1.15 / 10.1.2.15`, `channel-a` through `channel-d`
  - OOB telemetry: `172.31.250.0/24`

Important:

- `pt-457` and `pt-458` are analog-only Level 0 signals. Do not describe them as IP-addressable hosts in the demo.
- `historian-db`, `ignition`, `l2-jump`, and `database` are not part of the current hybrid demo compose, even though historical artifacts remain in the repo.
- Historian persistence to Influx is optional in the current demo path. The default validated flow leaves `HISTORIAN_INFLUX_URL` empty.

## Startup

From the repo root:

```bash
docker compose up -d --build
docker compose -f testbed/iaea_rcs_demo/docker-compose-hybrid.yml up -d --build --remove-orphans
```

The hybrid bring-up above includes `kali-attacker`, which serves the IDS pentest helper API on `http://127.0.0.1:5001/`.

Optional:

- Start Greenbone only if the recording needs vulnerability scanning views:

```bash
docker compose -f greenbone-community-container/compose.yaml up -d
```

## Pre-Record Gate

Run these before recording:

```bash
python3 testbed/iaea_rcs_demo/scripts/verify_hybrid_runtime.py --timeout-sec 60 --traffic-iterations 2
python3 testbed/iaea_rcs_demo/scripts/verify_siem_sensors.py --timeout-sec 60
curl -s http://127.0.0.1:4840/
```

Expected results:

- `verify_hybrid_runtime.py` prints `Hybrid runtime verification passed`
- `verify_siem_sensors.py` prints `SIEM sensor verification passed`
- `curl -s http://127.0.0.1:4840/` returns JSON with `"status": "ok"` and both PLC profiles connected

## Recording Sequence

Recommended page order:

1. `http://127.0.0.1:8000/dashboard/network/monitoring/`
2. `http://127.0.0.1:8000/dashboard/siem/overview/`
3. `http://127.0.0.1:8000/dashboard/siem/events/explorer/`
4. `http://127.0.0.1:8000/dashboard/risk-assessment/`

Recommended story:

1. Show the Purdue layout and call out the validated Layer 4 through Layer 0 segmentation.
2. Show the passive sensor plane and SIEM health.
3. Pivot into recent SIEM events or flow telemetry.
4. Finish on the risk assessment page and ICS visuals if the sibling `ics-risk-assessment` repo is mounted.

## Useful Host Endpoints

- Dashboard: `http://127.0.0.1:8000/dashboard/`
- HMI: `http://127.0.0.1:8081/`
- Engineering workstation status: `http://127.0.0.1:8082/`
- Engineering workstation noVNC: `http://127.0.0.1:6080/`
- Historian status: `http://127.0.0.1:4840/`
- Postgres: `127.0.0.1:25432`
- Metasploit RPC: `127.0.0.1:4444`
- PLC main UI: `http://127.0.0.1:18080/`
- PLC backup UI: `http://127.0.0.1:18081/`

## Known Caveats

- The topology board is agent-driven. Offline modeled-only assets are intentionally not surfaced by default.
- Because `pt-457` and `pt-458` are analog-only, they should not appear as standalone IP nodes on the topology board.
- OOB management addresses under `172.31.250.0/24` are for telemetry backhaul. The Purdue identity of PLCs and channels should still resolve to the `10.1.1.x` and `10.1.2.x` control networks.
- If Python changes do not appear in the dashboard, restart the app stack:

```bash
docker compose up -d --build
```

## Teardown

```bash
docker compose -f testbed/iaea_rcs_demo/docker-compose-hybrid.yml down
docker compose down
```
