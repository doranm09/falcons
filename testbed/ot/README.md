# OT Testbed (Purdue-style)

This sandbox mirrors the multi-zone OT layout from `oscal-pbnc` and is designed to functionally test
Cyber Pen Test network scan features (ping, nmap, agent-based).

## Bring Up
From the repo root:
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml up -d --build
```

### OpenVAS Bridge to OT Zones
To let OpenVAS scan all OT zones, start Greenbone with the OT network override:
```bash
docker compose \
  -f greenbone-community-container/docker-compose.yml \
  -f greenbone-community-container/docker-compose.ot-networks.yml \
  up -d
```

### Bring Up With Kali Attacker
Kali is optional and runs behind a compose profile so normal testbed startup remains fast.
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml --profile kali up -d --build
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
  - Single zone: `172.30.2.0/24`
  - Full OT testbed: `172.30.0.0/16`
- **Agent scan**:
  - Pick the agent matching the zone (e.g., `agent-l35`) and scan CIDR `172.30.3.0/24`

## Kali Scan Examples
Once the profile is running, use Kali as an attacker vantage point in L3 and L3.5:
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml exec kali-attacker \
  nmap -sV 172.30.2.0/24

docker compose -f docker-compose.yml -f docker-compose.testbed.yml exec kali-attacker \
  nmap -sV --script vuln 172.30.3.0/24
```

You can then pivot to Sliver deployment workflows in the dashboard:
1. Create Teamserver + Engagement under `/sliver/`.
2. Generate/deploy implant to a zone agent (e.g., `agent-l3`).
3. Verify execution and audit events in `/sliver/jobs/` and `/dashboard/agent/monitoring/`.

## One-Click OT Campaign
The `Network Scans` page includes a **One-Click OT Campaign** section that chains:
- discovery,
- optional OpenVAS,
- optional agent scan queue,
- optional Sliver command + loot collection.

For non-UI runs, use:
```bash
./scripts/run_ot_campaign.sh 172.30.2.0/24
```

## Notes
- Networks are marked `internal: true` to mimic zone isolation.
- Agents bridge their zone to the app network for command/telemetry.
- Conduits are optional for scan coverage; they primarily emulate OT traffic flows.
