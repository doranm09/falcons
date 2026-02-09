# SIEM Research Export

This feature exports SIEM events for reproducible research runs.

## Endpoint
`GET /dashboard/siem/export/`

Requires an authenticated session with `admin` or `analyst` role.

Query params:
- `start`: ISO8601 timestamp (optional)
- `end`: ISO8601 timestamp (optional)
- `format`: `ndjson` (default) or `parquet`
- `schema_version`: override schema version (default `1.0`)

## NDJSON Example
```bash
curl -G http://localhost:8000/dashboard/siem/export/ \
  --data-urlencode "start=2026-02-06T00:00:00Z" \
  --data-urlencode "end=2026-02-06T23:59:59Z" \
  --data-urlencode "format=ndjson" \
  --output siem_export.ndjson
```

## Parquet Example
Parquet export requires `pyarrow` in the Django environment.
```bash
curl -G http://localhost:8000/dashboard/siem/export/ \
  --data-urlencode "format=parquet" \
  --output siem_export.parquet
```

## Schema Versioning
Each exported record includes a `schema_version` field. Use this value to track downstream transformations and reproducibility.
