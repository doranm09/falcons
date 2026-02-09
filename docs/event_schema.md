# SIEM Event Schema (Phase 1)

This project accepts a minimal ECS-inspired event shape to normalize Security Onion, Zeek, Suricata, host agent, and scan events.

**Required Fields**
- `event_type`: The event category or type, such as `suricata.alert`, `zeek.conn`, `agent.heartbeat`.
- `timestamp`: ISO 8601 datetime string. Defaults to ingestion time if omitted.

**Optional Fields**
- `source`: The emitting system, such as `suricata`, `zeek`, `agent`, `sniffer`.
- `severity`: Integer severity (0-10).
- `asset_id`: Host identifier (agent id, hostname, or UUID).
- `asset_ip`: IP address for the asset.
- `message` or `summary`: Short human-readable description.
- `raw`: Full event payload is preserved on ingest.

**ECS-Inspired Fields Used**
- `@timestamp`: Primary event timestamp.
- `event.kind`: Always `event`.
- `event.category`: High-level domain such as `host`, `scan`, `vulnerability`, `package`, `network`.
- `event.type`: Activity type such as `info`, `start`, `end`, `alert`.
- `event.action`: Verb such as `heartbeat`, `detected`, `sbom_report`.
- `event.outcome`: `success`, `failure`, or `unknown`.
- `event.severity`: Integer severity (0-10).
- `host.hostname`, `host.ip`, `host.id`.
- `agent.id`, `agent.name`, `agent.version`.
- `rule.id`, `rule.name`, `rule.reference` (for CVEs / detections).
- `labels`: Small key/value context (scan ID, CIDR, SBOM format, etc).

**Event Normalization Rules**
- `@timestamp` or `event.created` is accepted if `timestamp` is absent.
- `event.type` or `event.category` is accepted if `event_type` is absent.
- `host.ip` is accepted if `asset_ip` is absent.
- `event.severity` is accepted if `severity` is absent.

**Adapter Output Mapping**
The adapter helpers emit ECS-inspired JSON for core sources. These are available from `/dashboard/siem/adapters/...` endpoints.

- `agent.heartbeat`: `event.category=host`, `event.type=info`, `event.action=heartbeat`, `host.*`, `agent.*`
- `scan.run`: `event.category=scan`, `event.type=start|end`, `event.action=<scan_type>`, `labels.cidr`, `labels.scan_id`
- `vulnerability.detected`: `event.category=vulnerability`, `event.type=info`, `rule.id=<CVE>`, `vulnerability.*`, `host.*` (optional)
- `sbom.report`: `event.category=package`, `event.type=info`, `event.action=sbom_report`, `labels.*`

**Pipeline Mapping**
Pipeline ingest maps raw payloads to this schema automatically before normalization:
- Suricata-like payloads (`alert` field) -> `suricata.alert`
- Zeek-like payloads (`id_orig_h` or `uid`) -> `zeek.conn` or `zeek.event`
- Agent-like payloads (`agent_id` or `hostname`) -> `agent.telemetry`
- Scan-like payloads (`scan_type` or `cidr`) -> `scan.run`

**Example**
```json
{
  "event_type": "suricata.alert",
  "source": "suricata",
  "timestamp": "2026-02-06T12:00:00Z",
  "severity": 4,
  "asset_ip": "10.10.0.15",
  "message": "ET MALWARE Example"
}
```
