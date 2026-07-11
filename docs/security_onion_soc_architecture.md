# Security Onion-Style SOC Architecture

This repository is not starting from zero. It already contains a functioning SIEM control plane, partial sensor-plane support, and analyst workflows that can be extended toward a Security Onion-style lab deployment.

## Current Baseline

- Django is the control plane for ingest, normalization, detections, cases, hunts, audit, exports, and dashboards.
- OpenSearch remains the search and storage backend. OpenSearch Dashboards is the raw analyst search surface.
- Host agents already provide heartbeat, process, interface, connection, osquery, FIM, syslog, and Windows-event style telemetry.
- The IAEA hybrid testbed already includes validated `suricata-sensor`, `zeek-sensor`, and `siem-forwarder` runtime paths.

## Architecture Layers

1. Sensor plane
- `suricata-sensor`
- `zeek-sensor`
- mirrored/SPAN-style attachment in the lab testbed

2. Collection and forwarding plane
- `siem-forwarder`
- sensor output directories mounted into the forwarder
- batched POST into Django ingest endpoints

3. Control plane
- SIEM ingest and normalization in `dashboard/views.py`, `dashboard/siem.py`, `dashboard/siem_suricata.py`, and `dashboard/siem_zeek.py`
- search and explorer in `dashboard/siem_query.py` and `dashboard/templates/dashboard/siem_events.html`
- SOC overview and sensor health in `dashboard/templates/dashboard/siem_overview.html`

4. Search and storage plane
- local `SiemEvent` persistence in `dashboard/models.py`
- OpenSearch bulk indexing in `dashboard/opensearch_client.py`
- index template in `configs/opensearch/siem_index_template.json`

## Implemented Data Paths

- Generic SIEM ingest:
  - `POST /dashboard/siem/ingest/`
  - `POST /dashboard/siem/pipeline/ingest/`
- Sensor ingest:
  - `POST /dashboard/siem/sensors/suricata/eve/`
  - `POST /dashboard/siem/sensors/zeek/logs/`
  - `GET /dashboard/siem/sensors/health/`
- Agent-derived network telemetry:
  - `POST /agent/network_metadata/`
  - connection metadata can be normalized into `agent.network_connection` SIEM events

## Canonical Event Shape In Use

The current normalized event path reliably stores:

- `@timestamp`
- `event_type`
- `source`
- `event_module`
- `event_dataset`
- `observer_name`
- `asset_id`
- `asset_ip`
- `source_ip`
- `source_port`
- `destination_ip`
- `destination_port`
- `network_community_id`
- `summary`
- `raw`

This is the minimum viable contract that lets the Event Explorer and SOC overview pivot on network telemetry in a Security Onion-style workflow.

## Analyst Workflow State

Already implemented:

- SOC overview for sensor health, alerts, top datasets, top talkers, and recent events
- Event Explorer filters for module, dataset, observer, IPs, ports, community ID, and summary
- workflow presets for common OT traffic views such as Modbus, OPC, engineering workstation to PLC, and channel-to-field traffic
- alert queue, case promotion, hunts, audit, and export flows

Still thin or pending:

- dedicated dashboards for DNS/HTTP/TLS investigations
- richer flow correlation based on session identifiers beyond `network_community_id`
- stronger protocol-aware summaries for non-connection datasets
- broader end-to-end tests that prove Zeek and Suricata fixtures land in both OpenSearch and the Django analyst views

## Recommended Next Work

1. Expand parser coverage and tests for additional Suricata and Zeek datasets.
2. Add dedicated saved searches or widgets for DNS, HTTP, TLS, and lateral-movement review.
3. Add more protocol- and testbed-aware event summaries so OT workflows read clearly without opening raw payloads.
4. Keep AGENTS notes aligned with any accepted schema, UI, or compose changes.
