# SIEM Event Ingest and Search

This feature provides a minimal SIEM event store with ingestion and search APIs. It is the foundation for Security Onion and SIEM integrations (Zeek, Suricata, host agent, and scan outputs).

**Endpoints**
- `POST /dashboard/siem/ingest/` Ingest one event or a list of events.
- `GET /dashboard/siem/events/` Search events by time range and filters.
- `GET /dashboard/siem/events/explorer/` UI for searching and pivoting on events.
- `GET /dashboard/siem/adapters/agent/<agent_id>/` Adapter preview for agent heartbeat events.
- `GET /dashboard/siem/adapters/scan/<scan_id>/` Adapter preview for scan events.
- `GET /dashboard/siem/adapters/vuln/<vuln_id>/` Adapter preview for vulnerability events.
- `GET /dashboard/siem/adapters/sbom/<sbom_id>/` Adapter preview for SBOM events.

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

**Search Example**
```bash
curl "http://localhost:8000/dashboard/siem/events/?event_type=suricata.alert&start=2026-02-06T12:00:00Z&end=2026-02-06T13:00:00Z"
```

**UI Usage**
- Navigate to `SIEM > Event Explorer` in the sidebar.
- Use filters and quick ranges to search events.
- Click `View` to inspect the raw payload.

**Adapter Preview Example**
```bash
curl \"http://localhost:8000/dashboard/siem/adapters/agent/agent-01/\"\n```

**Response Format**
- `count`: Total matching events.
- `results`: List of event records with normalized fields and `raw` payload.
