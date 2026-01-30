# OT Testbed (Purdue-style)

This sandbox mirrors the multi-zone OT layout from `oscal-pbnc` and is designed to functionally test
Cyber Pen Test network scan features (ping, nmap, agent-based).

## Bring Up
From the repo root:
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml up -d --build
```

## Tear Down
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml down -v
```

## How It Maps
- Zones: L0/1, L2, L3, L3.5, L4, L5 (Docker networks with static IPs)
- Services: simple HTTP responders per zone
- Conduits: proxy containers that allow narrow port access between zones
- Zone agents: `agent-l01`, `agent-l2`, ... attached to both their zone and the app network

## Functional Scan Tests
- **Ping/Nmap discovery** (from dashboard):
  - Use CIDR `172.30.2.0/24` (L3 zone, directly attached to web/celery)
- **Agent scan**:
  - Pick the agent matching the zone (e.g., `agent-l35`) and scan CIDR `172.30.3.0/24`

## Notes
- Networks are marked `internal: true` to mimic zone isolation.
- Agents bridge their zone to the app network for command/telemetry.
- Conduits are optional for scan coverage; they primarily emulate OT traffic flows.
