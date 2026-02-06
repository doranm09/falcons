# SIEM Feature Overview

This document walks through each SIEM capability that has been implemented, how it works, and where to find related UI/endpoint documentation. It complements the task-specific docs by forming a single go-to reference for researchers and operators.

## Event Ingestion & Normalization
- `POST /dashboard/siem/ingest/` and `/dashboard/siem/pipeline/ingest/` accept JSON (batch or single) from agents, syslog, scans, or custom sources. The ingestion pipeline (see `dashboard/siem_pipeline.py`) normalizes timestamps, infers sources (`suricata`, `zeek`, `agent`, `scan`, `custom`), and tags assets via ECS-inspired fields. Normalized events flow into the local `SiemEvent` store and optionally OpenSearch via `dashboard/opensearch_client.py`.
- Indicators are matched during ingestion; matching IOC metadata is stored in `ThreatIntelMatch` and appended to alert summaries (`dashboard/siem_threat_intel.py`). Docs: `docs/siem_events.md`, `docs/event_schema.md`, `docs/opensearch.md`, `docs/threat_intel.md`.

## Search & Explorer
- `GET /dashboard/siem/events/` (via `dashboard/siem_query`) exposes time-range filtering, multi-value filters (`event_type_in`, `source_in`), pagination, and aggregation buckets. The explorer UI (`dashboard/siem_events.html`) renders search controls, timeline, top sources/types, and current health snapshot events for quick triage.
- Health data is produced by `dashboard/health.py` and surfaced both in `/dashboard/healthz/` and within the explorer UI, providing database/OpenSearch status plus Prometheus gauges (`/dashboard/metrics/`). Docs: `docs/siem_events.md`, `docs/siem_health_metrics.md`.

## Alerting & Cases
- Alert rules (`AlertRule`) support SIGMA/Suricata, deduplication, suppression, and summary filtering. Alerts are stored in `Alert` with IOC/context enrichment via `dashboard/siem_alerting.py` and `dashboard/siem_correlation.py` (scan/CVE counts appended). Rules can be toggled in the alert queue UI (`siem_alerts.html`).
- Cases (`Case`, `CaseNote`, `CaseEvidence`) are first-class objects that can be created directly or promoted from alerts. The Case UI exposes creation forms, notes, evidence, and exports. Docs: `docs/siem_alerts.md`, `docs/siem_cases.md`.

## Threat Hunting & Correlation
- Hunt workflow (Task 13) introduces `Hunt`, tags, saved searches, and notebooks. Saved searches reuse the SIEM query parser and can replay results via `/dashboard/siem/hunts/<id>/replay/<search_id>/`. Hunts and tags are managed through `dashboard/siem_hunts.py` and UI pages.
- Correlation context (`dashboard/siem_correlation.py`) resolves nodes by asset IP/agent ID, counts scan-specific vulnerabilities (`ScanVulnerability`) and global CVEs (`Vulnerability.nodes`), and appends `[scan_vulns:x] [node_cves:y]` to alert summaries.

## Observability & Security
- RBAC (`SiemUserRole`) grants `admin`, `analyst`, `viewer` scopes. Audit logging (`SiemAuditLog`) records every protected action, with a dedicated UI/JSON at `/dashboard/siem/audit/`. Token-based protection secures SIEM ingest and agent APIs; secret files (`_FILE`) are supported by `read_secret`. The host agent automatically sends both tokens when configured.
- Production-ready security guidance is captured in `docs/siem_production_security.md`, covering token rotation, TLS flags, and recommended headers.

## Export & Research
- `/dashboard/siem/export/` streams normalized events as NDJSON or (with `pyarrow`) Parquet. Each record includes a `schema_version` field for downstream reproducibility. Audit entries track export requests; analytics include metadata on format and schema.
- Research profiles (`ResearchProfile`) provide versioned pipeline/ruleset metadata plus ingest batch caps. Activating a profile marks it as current, overrides `SIEM_MAX_INGEST_BATCH`, and is surfaced via `/dashboard/siem/research/`. Profiles document retention, max batch, and version strings used in experiments (see `docs/siem_research_profile.md`).

## Supporting Infrastructure
- OpenSearch forwarding is optional; the client (`dashboard/opensearch_client.py`) builds NDJSON bulk payloads with index names like `siem-events-YYYY.MM.DD` and honors TLS/auth.
- Token guarding is enforced in `dashboard/views.py` via `_check_siem_token` and `_check_agent_token`, with defaults to allow disabling during dev loops.
- Health/metrics endpoints use Prometheus-style counters for SIEM event/alert/case/hunt totals, which makes it easy to monitor stability.

## Next Steps
- Adjust ingestion tokens/perms via environment or secret files documented in `docs/siem_production_security.md`.
- Use research export + profile metadata to anchor CVEs/events to reproducible research runs, then archive the NDJSON/Parquet snapshots.

Let me know if you’d like this content merged into the README or exported elsewhere. EOF
