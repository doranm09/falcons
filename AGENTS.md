# AGENTS Notes

## Environment first

Use the project virtualenv for Python and Django commands in this repository.

- Virtualenv path: `/home/michaeldoran/git/cyber_pen_test/venv`
- Preferred interpreter: `/home/michaeldoran/git/cyber_pen_test/venv/bin/python`
- Django project root: `/home/michaeldoran/git/cyber_pen_test/cyber_pen_test`
- Example test command:

```bash
/home/michaeldoran/git/cyber_pen_test/venv/bin/python manage.py test dashboard.tests.NetworkTopologyTests
```

- Example management command pattern:

```bash
cd /home/michaeldoran/git/cyber_pen_test/cyber_pen_test
/home/michaeldoran/git/cyber_pen_test/venv/bin/python manage.py <command>
```

Do not assume `python3` in the default shell has Django installed.

## SIEM auth and OpenSearch invariants

Date: 2026-04-17
Working area: `dashboard/views.py`, `cyber_pen_test/settings.py`, `dashboard/opensearch_client.py`, `configs/opensearch/*`

- If `SIEM_INGEST_TOKEN_REQUIRED=1`, SIEM ingest fails closed unless at least one SIEM token is configured.
- Preferred SIEM secret:
  - `SIEM_INGEST_TOKEN`
- Compatibility alias accepted by the server and sensor forwarder:
  - `SIEM_SENSOR_TOKEN`
- If both SIEM token variables are set, keep them identical unless intentionally running a staged migration.
- OpenSearch bootstrap now renders the ISM policy and index template from `OPENSEARCH_INDEX_PREFIX` at container startup.
- OpenSearch documents keep producer identity in `event_source` and reserve ECS-style `source.*` / `destination.*` objects for endpoint fields.

## IDS PR integration

Date: 2026-04-17
Working area: `testbed/iaea_rcs_demo/services/ids`, `testbed/iaea_rcs_demo/scripts/capture_interface_pcap.py`, compose files

- Remote branch identified for the IDS work:
  - `origin/iaea_demo_testbed_ids`
  - merge ref: `origin/pr/13`
- The IDS branch was based far behind the validated hybrid topology and could not be merged cleanly.
- The current integration model ports the IDS code manually into the current repo state.
- Integrated assets:
  - offline anomaly IDS service under `testbed/iaea_rcs_demo/services/ids`
  - host-side capture helper `testbed/iaea_rcs_demo/scripts/capture_interface_pcap.py`
  - `ids` service in both `docker-compose.yml` and `docker-compose-hybrid.yml`
- Current intended workflow:
  - capture `.pcap` files into `testbed/iaea_rcs_demo/data/network`
  - train models into `testbed/iaea_rcs_demo/models`
  - emit score plots into `testbed/iaea_rcs_demo/plots`
  - run the analysis inside the `ids` container with `docker compose exec ids python /app/ids.py ...`
- Important limitation:
  - this integration is currently offline/manual pcap analysis
  - it is not yet wired to a live SPAN/pcap feed from `suricata-sensor`, `zeek-sensor`, `span-l1a`, or `span-l1b`
  - the `ids` container should start unprivileged by default for offline analysis; live interface capture now requires explicit opt-in such as `IDS_ENABLE_PROMISC=1` and the necessary container capabilities

## IAEA RCS hybrid topology alignment

Date: 2026-04-16
Working area: `testbed/iaea_rcs_demo`

The hybrid compose file was refactored to match the current Purdue-style topology used in `README.md` and validated at runtime.

### Target topology

- Layer 4 / Enterprise: `metasploit` at `10.4.50.10`, `postgres` at `10.4.50.20`
- Layer 3 / Operations: `historian` at `10.3.50.10`
- Layer 2 / Supervisory: `engineer-ws` at `10.2.50.20`, `hmi` at `10.2.50.10`
- Layer 1 / Control: `plc-main` at `10.1.1.14 / 10.1.2.14`, `plc-backup` at `10.1.1.15 / 10.1.2.15`, channels A-D at `.10-.13`
- Field: `pt-455`, `pt-456`, analog signal paths for PT-457/PT-458, heat controller, valve controllers, spray / pressure relief outputs

### Removed from `docker-compose-hybrid.yml`

- `ignition`
- `database`
- `historian-db`
- `l2-jump`

These did not belong in the new hybrid topology and were removed from the compose file and volume declarations.

### Compose and service changes

- Moved `postgres` from `10.4.50.41` to `10.4.50.20`
- Updated `firewall-2` rules to allow:
  - `10.4.50.10 -> 10.3.50.10` on `443,4840`
  - `10.4.50.10 -> 10.4.50.20` on `5432`
  - `10.3.50.10 -> 10.4.50.20` on `5432`
- Added `STATIC_ROUTES` to `postgres` for `10.3.50.0/24` and `10.2.50.0/24` via `10.4.50.254`
- Added `NET_ADMIN` to `postgres` so its entrypoint can install routes
- Added `STATIC_ROUTES` to `firewall-0` for:
  - `10.3.50.0/24 via 10.2.50.254`
  - `10.4.50.0/24 via 10.2.50.254`
- Removed `aux_addresses` reservations for `span-l1a` / `span-l1b` because Docker would not assign container IPs that were already reserved in IPAM

### Historian change

File: `testbed/iaea_rcs_demo/services/historian/collector.py`

- Made Influx persistence optional
- Default `INFLUX_URL` is now empty
- Historian can still poll PLC OPC endpoints and expose status without `historian-db`

Important: after editing historian code, the service must be rebuilt:

```bash
docker compose -f docker-compose-hybrid.yml up -d --build historian
```

### Runtime issues found and fixed

1. `postgres` could not start at `10.4.50.20` because orphaned removed services still existed.
   Fix: `docker compose -f docker-compose-hybrid.yml up -d --remove-orphans`

2. `span-l1a` and `span-l1b` could not start because their IPs were duplicated by `aux_addresses`.
   Fix: remove the `aux_addresses` entries and recreate the stack networks.

3. `historian -> postgres:5432` timed out even though firewall rules existed.
   Root cause: `postgres` had no return routes through `firewall-2`.
   Fix: add Layer 3 / Layer 2 static routes plus `NET_ADMIN` on `postgres`.

4. `historian -> plc-main/plc-backup:4840` timed out.
   Root cause: `firewall-0` allowed the traffic but had no return route for `10.3.50.0/24`.
   Fix: add `STATIC_ROUTES` on `firewall-0`.

### Validation performed

Compose status:

```bash
docker compose -f docker-compose-hybrid.yml ps
```

Successful path checks:

- `metasploit -> postgres:5432`
- `metasploit -> historian:443`
- `metasploit -> historian:4840`
- `historian -> postgres:5432`
- `historian -> plc-main:4840`
- `historian -> plc-backup:4840`
- `engineer-ws -> historian:443`
- `engineer-ws -> historian:4840`
- `engineer-ws -> plc-main:44818`
- `engineer-ws -> plc-backup:44818`
- `hmi -> plc-main:502`
- `hmi -> plc-backup:502`
- `plc-main -> channel-a/b/c/d:502`
- `channel-a -> pt-455:502`
- `channel-b -> pt-456:502`

Historian steady-state check:

```bash
curl -s http://127.0.0.1:4840/
```

Expected result:

- `"status": "ok"`
- both `"main"` and `"backup"` profiles show `"connected": true`
- `"influx_url": ""`

## Next work

The next requested task is to refactor the Purdue topology shown on the `cyber_pen_test` web dashboard so it reflects the validated hybrid topology above instead of the older layout.

## Dashboard Purdue refactor

Date: 2026-04-16
Working area: `dashboard/views.py`, `dashboard/tests.py`, `dashboard/templates/dashboard/network_monitoring.html`

### Current findings

The dashboard topology is driven primarily by:

- `dashboard/views.py`
  - `PURDUE_TOPOLOGY_LAYERS`
  - `IAEA_TESTBED_STATIC_TOPOLOGY`
  - `_infer_topology_role()`
  - `_infer_purdue_layer()`
  - `_topology_segment_label()`
  - `_is_iaea_testbed_active()`
  - `network_topology_api()`
- `dashboard/templates/dashboard/network_monitoring.html`
  - renders the Purdue board from `network_topology_api()`
- `dashboard/tests.py`
  - `NetworkTopologyTests`

The old dashboard model was still using the retired IAEA layout:

- `database`
- `historian-db`
- `ignition`
- `l2-jump`
- old ranges like `10.1.13.x`, `10.2.23.x`, `10.3.13.x`, `10.4.23.x`
- old historian IP `10.2.50.31`
- old postgres IP `10.4.50.41`

### In-progress changes

`dashboard/views.py` has been updated in the working tree to move toward the validated hybrid topology:

- removed old static nodes:
  - `database`
  - `historian-db`
  - `ignition`
  - `l2-jump`
- updated static nodes:
  - `postgres` -> `10.4.50.20`
  - `historian` -> `10.3.50.10`
  - added `plc-main`
  - added `channel-a` / `channel-b` / `channel-c` / `channel-d`
  - updated `firewall-0` to `10.2.50.253`
- updated range detection:
  - `10.1.1.x`
  - `10.1.2.x`
- updated segment labeling to use the redundant control network naming
- updated L1/L0 labels for control and field wording

Note: these view changes are not fully validated yet. Tests still need to be updated and run after the user-approved design direction is settled.

Important correction from user:

- `pt-457` and `pt-458` are analog sensors
- they should remain modeled as Level 0 analog sensors
- they should not be treated as IP-addressable network nodes or merged by channel IP
- the dashboard static topology has been adjusted so they have no network IPs and use the role label `Analog Sensor`

## Intelligent topology population with agents

The user asked whether the dashboard topology can be populated intelligently from agents. The answer is yes.

### Recommended model

Use a hybrid topology builder with these inputs:

1. Expected topology model
   - the validated IAEA RCS topology acts as the baseline asset inventory and expected placement

2. Agent identity
   - `AgentStatus.hostname`
   - `AgentStatus.ip_address`
   - hostnames / labels from `Node`
   - interface inventory from network metadata

3. Agent-observed network evidence
   - `NetworkConnection`
   - service listeners / local ports
   - interface subnets
   - process / service fingerprints when available

### Matching strategy

For each observed asset:

- match by exact IP first
- then exact hostname
- then normalized hostname / label aliases
- then subnet + role heuristics

For dual-homed devices like PLCs and channels:

- support multiple IP aliases per logical node instead of assuming one IP per node
- collapse `10.1.1.x` and `10.1.2.x` identities into a single logical asset where appropriate

### What to implement next

1. Extend static topology entries to support:
   - `ip_addresses: []`
   - optional aliases for hostname / label matching

2. Update `network_topology_api()` to:
   - merge multiple observed IPs into one logical node
   - enrich static nodes with live agent status and observed flows
   - show modeled nodes even when offline

3. Use agent flow evidence to:
   - confirm expected edges
   - highlight unexpected cross-layer paths
   - distinguish modeled paths from observed traffic

4. Keep `AGENTS.md` updated as these changes land

### Implemented in this pass

Files changed:

- `dashboard/views.py`
- `dashboard/urls.py`
- `dashboard/tests.py`

What was implemented:

1. Static topology logical identity support
   - static IAEA topology entries now support:
     - `ip_addresses`
     - `aliases`
   - dual-homed assets are represented as one logical asset with multiple IPs
   - examples:
     - `plc-main` -> `10.1.1.14`, `10.1.2.14`
     - `plc-backup` -> `10.1.1.15`, `10.1.2.15`
     - `channel-a`..`channel-d` -> paired `10.1.1.x` / `10.1.2.x`
     - `firewall-0` / `firewall-1` / `firewall-2` -> multi-interface logical assets

2. Analog sensor correction
   - `pt-457` and `pt-458` remain Level 0 analog sensors
   - they have no network IPs in the static topology
   - they are intentionally not merged by channel IP

3. Agent-aware topology resolution
   - topology builder now uses:
     - `Node.ip_address`
     - `NodeInterface.ip`
     - `AgentStatus.interfaces[*].ip`
   - IAEA override resolution now checks all observed IPs for a node/agent, not just the primary IP
   - logical topology nodes are merged via:
     - static hostname
     - aliases
     - any matching IP in `ip_addresses`
   - important: IAEA static definitions are now used only for identity matching and Purdue classification
   - they are no longer appended as modeled fallback nodes

4. Agent flow integration
   - observed `NetworkConnection` flows are resolved to logical topology node IDs
   - source node uses the merged logical agent/node identity
   - target node is resolved from parsed remote IP
   - edges no longer rely only on raw `agent_id -> "ip:port"` strings

5. Agent network metadata endpoint completion
   - added missing URL route:
     - `dashboard:agent_network_metadata`
     - path: `/agent/network_metadata/`
   - endpoint now parses:
     - `local_address` into `local_address` + `local_port`
     - `remote_address` into `remote_address` + `remote_port`
   - `process_cmdline` now safely defaults to `""`

### Validation completed

Focused Django tests passed with the project virtualenv and test settings:

```bash
cd /home/michaeldoran/git/cyber_pen_test
PYTHONPATH=/home/michaeldoran/git/cyber_pen_test \
/home/michaeldoran/git/cyber_pen_test/venv/bin/python \
cyber_pen_test/manage.py test \
  dashboard.tests.NetworkTopologyTests \
  dashboard.tests.AgentNetworkMetadataTests \
  --settings=cyber_pen_test.test_settings
```

Passing behaviors covered:

- topology only shows observed assets
- stale modeled-only nodes like `ignition` and `l2-jump` are excluded
- dual-homed logical assets are merged
- observed flows resolve to logical topology nodes
- agent network metadata endpoint accepts POSTs
- endpoint strings are parsed into address + port fields

Current implication:

- the topology board is now effectively agent-driven / observation-driven
- non-IP analog assets like `pt-457` / `pt-458` will not appear unless a separate telemetry-driven representation is implemented for them

## Hybrid SIEM sensor smoke validation

Date: 2026-04-16
Working area: `testbed/iaea_rcs_demo/scripts/verify_siem_sensors.py`, `testbed/iaea_rcs_demo/services/zeek/Dockerfile`

### Implemented

1. Added a focused smoke script for the passive network sensor path
   - script: `testbed/iaea_rcs_demo/scripts/verify_siem_sensors.py`
   - waits for:
     - `zeek-sensor`
     - `suricata-sensor`
     - `siem-forwarder`
   - validates:
     - dashboard sensor health endpoint returns both sensors online
     - `zeek-sensor` reports a positive `event_count`
     - Zeek log files exist under `/var/lib/siem/zeek`
     - forwarder offsets include Zeek spool consumption such as `spool/logger/conn.log`

2. Pinned the Zeek base image after runtime validation
   - file: `testbed/iaea_rcs_demo/services/zeek/Dockerfile`
   - pinned to the validated upstream digest instead of `zeek/zeek:latest`

### Validation completed

Validated against the running hybrid stack with:

```bash
python3 testbed/iaea_rcs_demo/scripts/verify_siem_sensors.py
```

Observed result:

- SIEM sensor verification passed
- dashboard health endpoint reported:
  - `suricata-sensor` online
  - `zeek-sensor` online
- forwarder offsets contained Zeek spool paths
- Zeek event flow was visible end to end through the dashboard sensor health API

## Hybrid runtime verifier refresh

Date: 2026-04-16
Working area: `testbed/iaea_rcs_demo/scripts/verify_hybrid_runtime.py`

### Problem found

The hybrid runtime verifier had drifted behind the validated topology and live service model:

- it still expected retired checks such as:
  - historian to InfluxDB
  - historian to old postgres IP `10.4.50.41`
  - `l2-jump`
- it assumed direct OPC payloads still exposed per-channel keys like:
  - `channel_a_pv`
  - `channel_b_pv`
- the current runtime instead exposes:
  - direct OPC summary fields like `average_pressure`
  - HMI per-PT values like `pt455_pv`, `pt456_pv`, `pt457_pv`, `pt458_pv`

### Implemented

1. Refreshed field-path verification
   - uses current main and backup field addresses:
     - `10.1.1.9`, `10.1.1.8`, `10.1.1.12`
     - `10.1.2.8`, `10.1.2.12`, `10.1.2.13`
   - verifies direct Modbus reads return status `1`
   - verifies direct OPC `average_pressure` matches the live field-value average

2. Refreshed HMI checks
   - verifies HMI remains connected to both PLCs
   - verifies current HMI PT keys are present:
     - `plc-main` -> `pt455_pv`, `pt456_pv`, `pt457_pv`
     - `plc-backup` -> `pt456_pv`, `pt457_pv`, `pt458_pv`
   - verifies HMI `average_pressure` matches the visible PT values

3. Refreshed policy checks
   - removed retired checks for:
     - InfluxDB
     - old postgres IP
     - `l2-jump`
   - current allow list includes historian to `postgres` at `10.4.50.20:5432`

### Validation completed

Validated against the live hybrid stack with:

```bash
python3 testbed/iaea_rcs_demo/scripts/verify_hybrid_runtime.py --timeout-sec 60
```

Observed result:

- `Hybrid runtime verification passed`
- services running: `25`
- main and backup OPC bridge checks passed
- HMI and historian checks passed
- allow / block policy probes matched the validated hybrid topology

## Hybrid layer traffic smoke gate

Date: 2026-04-17
Working area: `testbed/iaea_rcs_demo/scripts/verify_hybrid_runtime.py`, `testbed/iaea_rcs_demo/services/suricata/entrypoint.sh`

### Problem found

Before moving to the next SOC/SIEM integration step, the repo needed a clearer gate that actively drives traffic through the hybrid Purdue layers rather than only checking steady-state status.

Also found during live validation:

- `suricata-sensor` could get stuck in a restart loop because `/var/run/suricata.pid` was left behind after an earlier daemon run
- when that happened, passive-sensor validation could fail even if the core hybrid traffic paths were otherwise healthy

### Implemented

1. Hybrid runtime verification now drives traffic intentionally before validating state
   - `verify_hybrid_runtime.py` now exercises:
     - Layer 4 to Layer 3 and Layer 4 to enterprise database paths
     - Layer 3 to Layer 4 and Layer 3 to Layer 1 OPC paths
     - Layer 2 to Layer 3 historian paths
     - Layer 2 to Layer 1 PLC paths
     - Layer 1 PLC to channel paths
     - Layer 0 channel to digital transmitter paths
   - new flag:
     - `--traffic-iterations`
   - verifier output now includes `layer_traffic` counts so the smoke run shows that each layer was actually exercised

2. Hybrid runtime preflight now waits on core traffic-producing services
   - it no longer blocks on passive SIEM sensor containers before verifying core process traffic
   - this keeps the traffic smoke gate focused on the actual cross-layer plant/runtime behavior

3. Suricata restart robustness improved
   - `services/suricata/entrypoint.sh` now removes a stale `/var/run/suricata.pid` before starting
   - this fixes the observed restart loop:
     - `pid file '/var/run/suricata.pid' exists but appears stale`

### Intended validation flow

1. Drive and verify cross-layer traffic:

```bash
python3 testbed/iaea_rcs_demo/scripts/verify_hybrid_runtime.py --timeout-sec 60 --traffic-iterations 2
```

2. Then verify passive SIEM sensor ingestion:

```bash
python3 testbed/iaea_rcs_demo/scripts/verify_siem_sensors.py --timeout-sec 60
```

This is the preferred gate before continuing with the next SOC/SIEM build-out step.

## Agent-driven topology enumeration continuation

Date: 2026-04-16
Working area: `dashboard/views.py`, `dashboard/tests.py`

### Additional changes implemented

1. Network metadata now updates topology identity state
   - `agent_network_metadata()` now updates `AgentStatus` with:
     - refreshed `interfaces`
     - refreshed `active_ports`
     - `status = "online"`
     - primary IP chosen from reported non-loopback interfaces
   - the same endpoint now also upserts the corresponding `Node`
   - reported interfaces are mirrored into `NodeInterface` rows when provided
   - this closes the earlier gap where topology enumeration could ignore interface inventory that was only present in `NetworkMetadata`

2. Topology enumeration now uses agent metadata evidence directly
   - `network_topology_api()` now reads recent `NetworkMetadata` records and uses their interface inventory during logical node assembly
   - enumeration no longer depends on `AgentStatus.interfaces` being populated by `agent_report()` first
   - agents with current metadata but limited heartbeat inventory can still resolve into the expected Purdue node identity

3. Observed remote peers now become inferred topology nodes
   - if a recent `NetworkConnection` targets a remote IP that does not yet map to a persisted `Node` or `AgentStatus`, the topology builder now creates an inferred logical node for that peer
   - if the remote IP matches the IAEA hybrid model, the inferred node is resolved to the expected logical asset, for example:
     - `10.3.50.10` -> `static:historian`
   - if there is no static match, the node is still surfaced with inferred Purdue placement from IP / port heuristics

4. Flow resolution improved
   - source edges now prefer `local_address` IP matching before falling back to `agent_id`
   - target edges use parsed `remote_address` and `remote_port`
   - grouped flows now preserve endpoint context needed for inferred-node resolution

### Validation completed

Focused Django tests passed with the project virtualenv and test settings:

```bash
cd /home/michaeldoran/git/cyber_pen_test
PYTHONPATH=/home/michaeldoran/git/cyber_pen_test \
/home/michaeldoran/git/cyber_pen_test/venv/bin/python \
cyber_pen_test/manage.py test \
  dashboard.tests.NetworkTopologyTests \
  dashboard.tests.AgentNetworkMetadataTests \
  --settings=cyber_pen_test.test_settings
```

New passing behaviors covered:

- remote peers observed only in connection telemetry appear in the topology
- static IAEA logical identities are recovered from flow evidence alone
- metadata ingestion refreshes agent and node interface inventory for topology rendering
- a metadata-only dual-homed PLC identity resolves as one logical Purdue node

## L1 out-of-band management path

Date: 2026-04-16
Working area: `testbed/iaea_rcs_demo/docker-compose-hybrid.yml`, `dashboard/views.py`

### Implemented

1. Added an out-of-band management network for hybrid Layer 1 reporting
   - new Docker network:
     - `oob_mgmt`
     - subnet: `172.31.250.0/24`
   - attached hybrid L1 reporting assets to the OOB network:
     - `channel-a` -> `172.31.250.10`
     - `channel-b` -> `172.31.250.11`
     - `channel-c` -> `172.31.250.12`
     - `channel-d` -> `172.31.250.13`
     - `plc-main` -> `172.31.250.14`
     - `plc-backup` -> `172.31.250.15`
     - `span-l1a` -> `172.31.250.250`
     - `span-l1b` -> `172.31.250.251`

2. Preserved Purdue asset identity in dashboard ingestion
   - dashboard primary-IP selection now prefers the Purdue / process-facing `10.x` interfaces over the OOB management subnet
   - this prevents the OOB address from replacing the logical control-network identity for PLCs and channels

### Expected result

- L1 agents now have a non-internal path back to `host.docker.internal:8000`
- the dashboard should be able to receive heartbeats and metadata from channels, PLCs, and L1 passive sensors without relying only on in-band control traffic
- topology identity should still map those assets to:
  - `10.1.1.x`
  - `10.1.2.x`
  rather than the `172.31.250.x` management subnet

### Browser checkpoint

After the web process reloads, the updated Purdue topology should be viewable in:

- `Dashboard -> Network Monitoring`
- route name: `dashboard:network_monitoring`
- URL path: `/dashboard/network/monitoring/` if mounted under the dashboard prefix

If the running web container does not auto-reload Python changes, restart the Django web service before browser verification.

## Security Onion SIEM expansion plan

Date: 2026-04-16
Scope: phased build-out of a Security Onion-style SOC platform on top of the current repo

### Current repo baseline

This repository already has a substantial SIEM foundation and should not be treated as greenfield:

- OpenSearch + OpenSearch Dashboards are already present in `docker-compose.yml`
- Django already provides SIEM ingest, event search, alerting, case management, hunts, RBAC, audit, exports, and threat-intel enrichment
- the host agent already supports:
  - osquery result forwarding
  - file integrity monitoring
  - syslog / Windows-style event forwarding paths
  - network metadata and connection reporting
- the existing dashboard already has:
  - Event Explorer
  - alert queue
  - cases
  - hunts
  - network monitoring and topology views

Important implementation default:

- keep OpenSearch as the backend
- do not plan or perform an Elastic migration as part of this roadmap

### Product target

Target a Security Onion-style system optimized for:

- phased parity, not a monolithic rewrite
- single-node lab deployment first
- containerized network sensors first
- current Django SIEM as the control plane and analyst workflow layer

The first major build-out after the existing SIEM base is the network sensor plane:

- Zeek
- Suricata
- packet capture / mirrored interface attachment
- normalized network event pipelines
- sensor health and operator workflows

### Canonical architecture

Build the platform in four layers:

1. Sensor plane
- `suricata-sensor`
- `zeek-sensor`
- optional later sensor-side packet capture helpers

2. Collection / forwarding plane
- repo-owned `siem-forwarder` service
- shared volumes from sensors into forwarder
- batched POST into Django SIEM endpoints

3. Control plane
- Django views, normalization, detections, cases, hunts, dashboards, and health views

4. Search / storage plane
- OpenSearch indices for normalized events
- OpenSearch Dashboards for raw analyst search and dashboards

Implementation default:

- sensors do not write directly to OpenSearch in the first implementation
- all sensor data flows through repo-managed ingest endpoints

### Canonical event conventions

All normalized events must include:

- `@timestamp`
- `event.module`
- `event.dataset`
- `observer.*` for sensor identity
- normalized `source.*`, `destination.*`, and `network.*` fields
- raw payload retention for analyst inspection

Use these module / dataset defaults:

- `event.module=suricata`
- `event.dataset=suricata.eve`
- `event.module=zeek`
- `event.dataset=zeek.conn`
- `event.dataset=zeek.dns`
- `event.dataset=zeek.http`
- `event.dataset=zeek.ssl`
- `event.dataset=zeek.notice`
- `event.dataset=zeek.files`
- existing endpoint telemetry keeps current datasets such as `osquery`, `fim`, `syslog`, and `windows`

Required schema extensions for the network phase:

- `network.community_id`
- `related.ip`
- `related.hosts`
- `rule.*`
- `suricata.*`
- `zeek.*`

### Required new interfaces

New sensor ingest endpoints:

- `POST /dashboard/siem/sensors/suricata/eve/`
- `POST /dashboard/siem/sensors/zeek/logs/`
- `GET /dashboard/siem/sensors/health/`

These endpoints should use the current SIEM normalization path internally instead of bypassing it.

Required config/env surface:

- `SURICATA_ENABLED`
- `ZEEK_ENABLED`
- `SIEM_SENSOR_TOKEN`
- `SIEM_SENSOR_BATCH_SIZE`
- `SIEM_SENSOR_HEALTH_LOOKBACK_SEC`
- explicit sensor interface / mirrored-network attachment configuration in compose

### Implementation phases

#### Phase 1: foundation hardening

Goal:

- document and stabilize the current SIEM baseline before adding sensors

Required work:

- inventory the current SIEM features already shipped in the repo
- create a concise Security Onion-style architecture doc in repo docs and reference it from `README.md`
- define the normalized network event contract and required fields
- define OpenSearch index template updates needed for Zeek and Suricata data
- ensure the current event explorer can filter reliably by `event.module` and `event.dataset`

Acceptance criteria:

- repo docs clearly distinguish existing SIEM capabilities from missing sensor-plane work
- a developer can identify where new Zeek and Suricata events enter, normalize, index, and surface in the UI

#### Phase 2: containerized network sensors

Goal:

- collect network telemetry from the lab using containerized sensors

Required work:

- add `suricata-sensor` service to compose
- add `zeek-sensor` service to compose
- add `siem-forwarder` service to compose
- mount sensor output directories into the forwarder
- attach sensors to mirrored / SPAN-style lab networks first, especially the IAEA hybrid testbed
- add health checks for sensor liveness and forwarder backlog

Acceptance criteria:

- the stack boots with web, OpenSearch, Dashboards, Suricata, Zeek, and the forwarder
- both sensors produce logs into shared volumes
- the forwarder can report health and backlog state

#### Phase 3: ingest and normalization

Goal:

- normalize Zeek and Suricata telemetry into the existing SIEM store

Required work:

- add Suricata EVE endpoint and parser
- add Zeek log endpoint and parser
- implement mappings for:
  - Suricata alert, flow, DNS, HTTP, TLS, file records
  - Zeek `conn`, `dns`, `http`, `ssl`, `notice`, `files`
- extend index template / mappings to support network-specific fields
- ensure raw payload stays available for analysts

Acceptance criteria:

- sample Zeek and Suricata fixtures ingest successfully end to end
- normalized events are searchable in the current event explorer
- OpenSearch documents contain module/dataset and observer identity consistently

#### Phase 4: analyst workflows

Goal:

- make the current UI feel like a SOC console rather than just an event backend

Required work:

- add a SOC landing area summarizing:
  - sensor health
  - alert volume
  - top talkers
  - top detections
  - recent DNS / HTTP / flow activity
- extend pivots in the Event Explorer to support:
  - source IP
  - destination IP
  - hostname
  - community ID
  - Suricata signature
  - Zeek UID / session
- add saved searches or overview widgets for common workflows:
  - network alerts
  - DNS hunting
  - HTTP/TLS investigations
  - lateral movement flow review

Acceptance criteria:

- analysts can pivot from network alert to related events, host context, and case creation without leaving the dashboard
- the SOC landing page surfaces sensor problems and high-volume detections clearly

#### Phase 5: detections and operations

Goal:

- make the platform operationally useful and maintainable

Required work:

- add lab-focused Suricata rule-pack management
- add Sigma-style detections over normalized Zeek and Suricata data using the existing alert framework
- add metrics for:
  - sensor liveness
  - ingest lag
  - event throughput
  - parser failures
- add retention and operational docs for day-2 use
- document the follow-on path for manager plus remote sensors after the single-node lab is stable

Acceptance criteria:

- detections can trigger from normalized network events and enter the existing alert queue
- operators can tell if sensors are stale, broken, or backlogged

### Agent work packages

Use these disjoint workstreams for Codex agents.

#### Workstream A: sensor runtime and compose

Ownership:

- compose services
- sensor container definitions
- mounted volumes
- network attachments
- sensor and forwarder health checks

Primary files:

- `docker-compose.yml`
- sensor Dockerfiles / entrypoints under a new sensor service area
- testbed compose overrides

Acceptance criteria:

- services boot consistently
- sensors attach to intended mirrored networks
- health endpoints reflect container and capture state

Non-goals:

- alert correlation logic
- analyst dashboard implementation

#### Workstream B: ingest and schema

Ownership:

- new sensor endpoints
- parsers
- normalization
- OpenSearch mapping updates

Primary files:

- `dashboard/views.py`
- `dashboard/siem_pipeline.py`
- new `dashboard/siem_suricata.py`
- new `dashboard/siem_zeek.py`
- `configs/opensearch/*`

Acceptance criteria:

- fixtures normalize deterministically
- documents index cleanly
- event explorer can filter by new module/dataset values

Non-goals:

- compose sensor runtime
- analyst dashboard widgets

#### Workstream C: analyst UI

Ownership:

- SOC landing pages
- sensor status views
- Event Explorer pivots
- saved workflow dashboards

Primary files:

- `dashboard/templates/dashboard/*`
- related dashboard view/controller code

Acceptance criteria:

- UI exposes sensor health, top detections, and network pivots
- analysts can traverse from alert to events to case context

Non-goals:

- parser implementation
- container capture setup

#### Workstream D: detections and operations

Ownership:

- Suricata rule management
- network detection rules
- throughput/health metrics
- operational docs

Primary files:

- alerting modules
- rule/config directories
- docs under `docs/`

Acceptance criteria:

- network-derived alerts appear in the current queue
- operator docs cover startup, rule reload, and troubleshooting

Non-goals:

- raw sensor container build logic
- event explorer UI detail work

#### Workstream E: fixtures and validation

Ownership:

- sample Zeek and Suricata fixtures
- integration validation scripts
- regression coverage

Primary files:

- tests for SIEM ingest and search
- sample log fixture directories

Acceptance criteria:

- fixtures cover the canonical sensor record types
- end-to-end tests prove indexing and UI visibility

Non-goals:

- production compose changes
- analyst UX design

### Required tests

Before any phase is marked complete, run the appropriate focused tests from the project virtualenv.

Unit tests required:

- Suricata EVE normalization:
  - alerts
  - flows
  - DNS
  - HTTP
  - TLS
- Zeek normalization:
  - `conn`
  - `dns`
  - `http`
  - `ssl`
  - `notice`
- alert generation over normalized network events

API tests required:

- sensor ingest endpoints accept valid batched payloads
- malformed payloads are rejected with clear errors
- sensor health endpoint marks live versus stale sensors correctly

UI tests required:

- SOC overview renders sensor counts and event summaries
- Event Explorer filters and pivots by `event.module` and `event.dataset`

Integration tests required:

- Suricata fixture logs flow from forwarder to Django to OpenSearch to dashboard search
- Zeek fixture logs flow from forwarder to Django to OpenSearch to dashboard search
- normalized network events can promote alerts, cases, and hunts through the current workflow model

Compose smoke tests required:

- single-node stack boots with:
  - web
  - OpenSearch
  - OpenSearch Dashboards
  - Suricata
  - Zeek
  - forwarder
- known traffic replay produces both Zeek and Suricata events visible in the UI

### Explicit defaults and non-decisions

These defaults are chosen so implementers do not need to make architecture decisions during implementation:

- backend remains OpenSearch
- first deployment target is single-node lab
- first sensor model is containerized sensors
- first monitored environment is the existing lab / testbed networks, especially the IAEA hybrid topology
- Django remains the primary control plane and analyst workflow layer
- initial storage stays in the existing SIEM event store pattern; distinguish sources by module/dataset before introducing separate stores
- direct Elastic migration is out of scope
- multi-sensor distributed manager/sensor separation is a later phase after the single-node lab is stable
