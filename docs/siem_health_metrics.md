# SIEM Health Checks + Metrics

## Health Check
- `GET /dashboard/healthz/`

Response includes overall status and component checks:
```json
{
  "status": "ok",
  "timestamp": "2026-02-06T13:00:00Z",
  "checks": {
    "database": {"status": "ok"},
    "opensearch": {"status": "disabled"}
  }
}
```

If any component is unhealthy, the endpoint returns HTTP 503.

## Metrics
- `GET /dashboard/metrics/`

Prometheus-style metrics are exposed, including:
- `cybertwin_service_up{service="database"}`
- `cybertwin_service_up{service="opensearch"}`
- `cybertwin_siem_events_total`
- `cybertwin_siem_alerts_open`
- `cybertwin_siem_cases_open`
- `cybertwin_siem_hunts_open`

## Dashboard Status
The SIEM Event Explorer UI shows service status badges based on the latest health snapshot.
