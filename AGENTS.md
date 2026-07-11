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
