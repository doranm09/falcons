# OpenSearch Log Store (SIEM)

This project can forward SIEM events to an OpenSearch single-node stack for indexing and dashboards.

## Services
- OpenSearch: `http://localhost:9200`
- OpenSearch Dashboards: `http://localhost:5601`

Both are defined in `docker-compose.yml` and `docker-compose.prod.yml`.

## Configuration
Set these values in `.env`:
- `OPENSEARCH_ENABLED=1` to enable forwarding
- `OPENSEARCH_URL=http://opensearch:9200`
- `OPENSEARCH_INDEX_PREFIX=siem-events`
- `OPENSEARCH_USER` / `OPENSEARCH_PASS` if security is enabled
- `OPENSEARCH_VERIFY_TLS=0` for local dev (self-signed or HTTP)

## Index Template and Retention Policy
The bootstrap container applies:
- ISM policy: `configs/opensearch/siem_ism_policy.json` (deletes indices older than 30 days)
- Index template: `configs/opensearch/siem_index_template.json`

These are applied automatically by the `opensearch-init` service on startup.

## Quick Start
1. `docker-compose up --build`
2. Confirm OpenSearch health:
   ```bash
   curl http://localhost:9200/_cluster/health
   ```
3. Ingest an event via `/dashboard/siem/ingest/` or `/dashboard/siem/pipeline/ingest/`.
4. View indices:
   ```bash
   curl http://localhost:9200/_cat/indices?v
   ```
5. Open dashboards at `http://localhost:5601` and create an index pattern for `siem-events-*`.

## Notes
- Security is disabled by default for local development. Enable OpenSearch security before production use.
- Index names follow `siem-events-YYYY.MM.DD`.
