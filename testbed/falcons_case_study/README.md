# FALCONS publication case-study testbed

This directory defines the publication-specific emulated network testbed for the
FALCONS manuscript. It is intentionally separate from
`testbed/iaea_rcs_demo` so that the topology, assumptions, addresses, and
experiment evidence can be frozen for the paper without changing the existing
demonstration environment.

The initial configuration addresses publication blocker 1 by matching the
representative architecture shown in Figure 3 of the manuscript:

- Enterprise layer with two plant-information workstations.
- Operations layer containing the historian.
- A one-way data-diode boundary from Operations to Enterprise.
- Supervisory layer containing an operator workstation and HMI.
- `Gateway-0` as the only routed path between Supervisory and Control.
- Redundant control networks with main and backup PLCs.
- Independent Channels A-D.
- Smart networked pressure transmitters PT-455 and PT-456.
- Analog-only PT-457/PT-458 and controller/actuator elements represented as
  non-network-addressable physical elements.

## Publication status

This is the **network-topology and policy foundation** for the case study. It is
not yet a declaration that final publication experiments are ready. Before a
suite can be promoted for manuscript results, the GPWR process interface must
be connected and its provenance must show that the process source is the live
or approved recorded GPWR dataset used by the study. The temporary Channel C/D
process behavior currently reuses the existing deterministic pressurizer trace
for integration testing only.

## Files

- `docker-compose.yml` — executable segmented topology.
- `allowed_communications.json` — service-aware policy baseline used to define
  allowed reachability.
- `sim_system.json` — sectioned cyber-physical model supplied to the risk
  assessment pipeline.
- `scripts/validate.py` — static and optional runtime validation.

The policy file and model are intentionally committed alongside the Compose
file. A publication run should hash and archive all three so the NDT/testbed and
DBN cannot silently describe different systems.

## Address plan

| Layer | Network | Principal assets |
|---|---|---|
| Enterprise | `10.4.50.0/24` | `enterprise-ws-1` `.10`, `enterprise-ws-2` `.20`, data-diode `.254` |
| Operations | `10.3.50.0/24` | historian `.10`, data-diode `.254` |
| Supervisory | `10.2.50.0/24` | HMI `.10`, workstation `.20`, historian `.30`, Gateway-0 `.253` |
| Control A | `10.1.1.0/24` | PT-456 `.8`, PT-455 `.9`, Channels A-D `.10-.13`, PLC main `.14`, PLC backup `.15`, Gateway-0 `.253` |
| Control B | `10.1.2.0/24` | redundant addresses using the same host octets |
| Out-of-band collection | `172.31.251.0/24` | agent and monitoring traffic only |

## Boundary assumptions

1. The data diode forwards only historian-originated UDP export traffic from
   `10.3.50.10` to the Enterprise subnet on the configured export port. It
   installs no Enterprise-to-Operations forwarding rule.
2. `Gateway-0` is the only service attached to both the Supervisory and Control
   networks.
3. Gateway rules permit only the documented HMI, workstation, and historian
   services to the two PLCs.
4. Communication absent from `allowed_communications.json` is treated as
   unreachable for publication scenarios unless a scenario explicitly changes
   the configuration.
5. PT-457, PT-458, heat/valve controllers, sprays, and relief valves are
   physical/analog elements and are not included as IP attack-surface nodes.

## Start

From the repository root:

```bash
cd testbed/falcons_case_study
python3 scripts/validate.py
docker compose up -d --build
```

The FALCONS dashboard and risk service are expected to run from the normal
repository Compose project. Testbed agents report to
`http://host.docker.internal:8000` by default.

## Validate

Static validation does not start containers:

```bash
python3 scripts/validate.py
```

Runtime validation also asks Docker Compose to normalize the file and inspects
the running boundary rules:

```bash
python3 scripts/validate.py --runtime
```

## Stop

```bash
docker compose down
```

Use `docker compose down -v` only when experiment state and PLC persistent
volumes should be deliberately destroyed.

## Remaining publication hardening

The next work items after this topology lands are:

1. Bind Channels A-D and process evidence to the approved GPWR interface.
2. Add a historian export producer and enterprise receiver to exercise the
   one-way path with a recorded artifact.
3. Attach passive sensors to the Supervisory and redundant Control bridges.
4. Make the FALCONS experiment preflight verify this exact model, policy, and
   Compose digest before accepting a publication run.
5. Add end-to-end assertions for S1 reachable and S2 unreachable assets.
