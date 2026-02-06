# SIEM Event Ingest and Search

This feature provides a minimal SIEM event store with ingestion and search APIs. It is the foundation for Security Onion and SIEM integrations (Zeek, Suricata, host agent, and scan outputs).

**Endpoints**
- `POST /dashboard/siem/ingest/` Ingest one event or a list of events.
- `POST /dashboard/siem/pipeline/ingest/` Ingest raw pipeline events (auto-mapped to ECS subset).
- `GET /dashboard/siem/events/` Search events by time range and filters.
- `GET /dashboard/siem/events/explorer/` UI for searching and pivoting on events.
- `GET /dashboard/siem/adapters/agent/<agent_id>/` Adapter preview for agent heartbeat events.
- `GET /dashboard/siem/adapters/scan/<scan_id>/` Adapter preview for scan events.
- `GET /dashboard/siem/adapters/vuln/<vuln_id>/` Adapter preview for vulnerability events.
- `GET /dashboard/siem/adapters/sbom/<sbom_id>/` Adapter preview for SBOM events.
- `GET /dashboard/siem/pivot/?asset_ip=<ip>&asset_id=<id>` Resolve events to nodes and scans.

**Authentication**
- If `SIEM_INGEST_TOKEN` is set, requests must include `X-SIEM-Token: <token>` or `Authorization: Bearer <token>`.
- `SIEM_MAX_INGEST_BATCH` controls the maximum number of events per request (default 500).

**Ingest Example**
```bash
curl -X POST http://localhost:8000/dashboard/siem/ingest/ \
  -H "Content-Type: application/json" \
  -H "X-SIEM-Token: your-token" \
  -d '{
    "event_type": "zeek.conn",
    "source": "zeek",
    "timestamp": "2026-02-06T12:00:00Z",
    "message": "connection",
    "severity": 2,
    "asset_ip": "10.0.0.5"
  }'
```

**Batch Ingest**
```bash
curl -X POST http://localhost:8000/dashboard/siem/ingest/ \
  -H "Content-Type: application/json" \
  -d '[
    {"event_type": "suricata.alert", "source": "suricata", "timestamp": "2026-02-06T12:01:00Z"},
    {"event_type": "agent.heartbeat", "source": "agent", "timestamp": "2026-02-06T12:02:00Z"}
  ]'
```

**Pipeline Ingest Example (Suricata-like)**
```bash
curl -X POST http://localhost:8000/dashboard/siem/pipeline/ingest/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {"signature": "ET MALWARE Example", "severity": 2},
    "src_ip": "10.10.0.20",
    "timestamp": "2026-02-06T12:05:00Z"
  }'
```

**Pipeline Mapping**
- Suricata-like payloads with `alert` map to `suricata.alert`.
- Zeek-like payloads with `id_orig_h` or `uid` map to `zeek.conn` or `zeek.event`.
- Agent-like payloads with `agent_id` map to `agent.telemetry`.
- Scan-like payloads with `scan_type` or `cidr` map to `scan.run`.

**OpenSearch Forwarding**
When `OPENSEARCH_ENABLED=1`, ingested events are also indexed into OpenSearch using the `_bulk` API.
See `docs/opensearch.md` for setup and dashboards instructions.

**Search Example**
```bash
curl "http://localhost:8000/dashboard/siem/events/?event_type=suricata.alert&start=2026-02-06T12:00:00Z&end=2026-02-06T13:00:00Z"
```

**Aggregation Example**
```bash
curl "http://localhost:8000/dashboard/siem/events/?agg=source,event_type&agg_size=10"
```

**Multi-Value Filters**
- `event_type_in=suricata.alert,zeek.conn`
- `source_in=suricata,zeek`

**UI Usage**
- Navigate to `SIEM > Event Explorer` in the sidebar.
- Use filters and quick ranges to search events.
- Click `View` to inspect the raw payload.
- Click `Pivot` to jump to the related node and scan details (if found).

**Adapter Preview Example**
```bash
curl \"http://localhost:8000/dashboard/siem/adapters/agent/agent-01/\"\n```

**Response Format**
- `count`: Total matching events.
- `results`: List of event records with normalized fields and `raw` payload.
