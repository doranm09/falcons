# Threat Intel Ingestion and Enrichment

This feature ingests threat intel indicators and enriches SIEM events during ingest. Matching events are tagged and surfaced in alerts.

## Enablement
Set `THREAT_INTEL_ENABLED=1` in `.env`.

## Ingest Indicators
### Generic Payload
```json
{
  "indicators": [
    {"indicator_type": "ip", "value": "10.10.0.10", "source": "misp", "description": "Known C2"},
    {"indicator_type": "domain", "value": "evil.example", "source": "misp"}
  ]
}
```

### MISP-like Payload
You can POST a MISP event payload with `Event.Attribute` or a flat payload with `Attribute`.

### Endpoint
`POST /dashboard/siem/threat-intel/ingest/`

## List Indicators
`GET /dashboard/siem/threat-intel/?type=ip&active=1`

## Matching Rules
- `ip` indicators match `asset_ip` or any raw payload text.
- `domain`, `url`, and `hash` indicators match raw payload text.

## Alert Enrichment
When a match occurs, alerts will include `[IOC: <value>]` in the summary and the raw sample will include an `ioc_matches` array.

## Notes
- Indicators are stored as unique `(indicator_type, value)`.
- Ingesting an existing indicator updates its metadata.
