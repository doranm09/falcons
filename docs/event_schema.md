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

**Event Normalization Rules**
- `@timestamp` or `event.created` is accepted if `timestamp` is absent.
- `event.type` or `event.category` is accepted if `event_type` is absent.
- `host.ip` is accepted if `asset_ip` is absent.
- `event.severity` is accepted if `severity` is absent.

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
