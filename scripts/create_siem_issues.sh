#!/usr/bin/env bash
set -euo pipefail

HOST=${GH_HOST:-github.gatech.edu}
REPO=${REPO:-""}

if [[ -z "$REPO" ]]; then
  if ! REPO=$(gh --host "$HOST" repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null); then
    echo "Unable to resolve repo. Set REPO=owner/name or login: gh auth login -h $HOST" >&2
    exit 1
  fi
fi

create_issue() {
  local title="$1"
  local body="$2"
  gh --host "$HOST" issue create --repo "$REPO" --title "$title" --body "$body"
}

create_issue "SO-SIEM-01: Sensor stack (Zeek + Suricata)" "Add Zeek + Suricata services to docker-compose for dev and prod.\n\nAcceptance Criteria:\n- Zeek and Suricata services start with docker compose.\n- PCAP retention and log output paths are configurable via env.\n- Events flow into the ingest pipeline.\n\nTesting:\n- Unit test: config parsing for paths and env.\n- Functional test: container healthcheck endpoints return healthy.\n- Integration test: sample PCAP triggers an alert and event ingestion." 

create_issue "SO-SIEM-02: Event schema (ECS subset)" "Define an ECS-inspired event schema and mapping guidance.\n\nAcceptance Criteria:\n- docs/event_schema.md updated with required and optional fields.\n- Adapters output ECS-compliant JSON for core sources.\n\nTesting:\n- Unit test: normalization mapping helper.\n- Functional test: API accepts schema-compliant payload.\n- Integration test: schema-compliant events persist and are queryable." 

create_issue "SO-SIEM-03: Ingestion pipeline" "Implement ingestion pipeline that normalizes events and writes to log store.\n\nAcceptance Criteria:\n- Pipeline service (Fluent Bit or Logstash) included in compose.\n- Inputs mapped to ECS.\n- Output to OpenSearch/Elastic.\n\nTesting:\n- Unit test: pipeline config renders expected outputs.\n- Functional test: send event to pipeline and confirm delivery.\n- Integration test: end-to-end ingest from sensor to index." 

create_issue "SO-SIEM-04: OpenSearch/Elastic stack" "Add OpenSearch/Elastic single-node stack with index templates and ILM.\n\nAcceptance Criteria:\n- Stack starts in dev/prod compose.\n- Index templates and ILM applied.\n- Dashboards can query last 24h of events.\n\nTesting:\n- Unit test: template JSON validation.\n- Functional test: index creation and write/read.\n- Integration test: pipeline writes events and dashboards query them." 

create_issue "SO-SIEM-05: Event search APIs" "Add SIEM event search APIs with time range, filters, and pagination.\n\nAcceptance Criteria:\n- /dashboard/siem/events endpoint supports filters and pagination.\n- Searches return normalized event fields.\n\nTesting:\n- Unit test: query parsing and validation.\n- Functional test: search endpoint returns expected results.\n- Integration test: ingest then search across multiple filters." 

create_issue "SO-SIEM-06: Event Explorer UI" "Create SIEM Event Explorer UI with search, timeline, and pivot to asset/CVE.\n\nAcceptance Criteria:\n- UI renders event table with filters.\n- Pivot from event to asset and CVE.\n\nTesting:\n- Unit test: frontend filtering logic.\n- Functional test: UI loads and displays events.\n- Integration test: search -> pivot flow works end-to-end." 

create_issue "SO-SIEM-07: Alerting (Sigma + Suricata)" "Implement alerting pipeline with Sigma and Suricata detections, dedup, and suppression.\n\nAcceptance Criteria:\n- Alert rules can be enabled/disabled.\n- Alert queue shows latest detections.\n\nTesting:\n- Unit test: rule parsing and dedup logic.\n- Functional test: detection triggers alert.\n- Integration test: event -> detection -> alert lifecycle." 

create_issue "SO-SIEM-08: Case management" "Add case management for alerts with notes, evidence, and status.\n\nAcceptance Criteria:\n- Alerts can be promoted to cases.\n- Cases can be updated and exported.\n\nTesting:\n- Unit test: case lifecycle transitions.\n- Functional test: create/update case via UI.\n- Integration test: alert -> case workflow." 

create_issue "SO-SIEM-09: Threat intel ingestion" "Add threat intel ingestion (MISP or TAXII) and enrichment.\n\nAcceptance Criteria:\n- IOCs ingested and stored.\n- Matching events are tagged and surfaced.\n\nTesting:\n- Unit test: IOC normalization.\n- Functional test: IOC import and tagging.\n- Integration test: incoming event matches IOC and alerts." 

create_issue "SO-SIEM-10: Host telemetry (osquery + FIM)" "Extend host agent to support osquery and file integrity monitoring.\n\nAcceptance Criteria:\n- Host events stream into SIEM with ECS mapping.\n\nTesting:\n- Unit test: osquery result mapping.\n- Functional test: agent generates events.\n- Integration test: agent -> ingest -> search." 

create_issue "SO-SIEM-11: Syslog + Windows event ingestion" "Add syslog and Windows Event Log ingestion endpoints.\n\nAcceptance Criteria:\n- Syslog endpoint accepts RFC5424 messages.\n- Windows Event Logs ingested and normalized.\n\nTesting:\n- Unit test: parser coverage.\n- Functional test: sample logs ingest.\n- Integration test: logs visible in search." 

create_issue "SO-SIEM-12: Correlation engine" "Build correlation engine linking events to assets, scans, and vulnerabilities.\n\nAcceptance Criteria:\n- Alerts show affected node and CVE context.\n- Correlation rules documented.\n\nTesting:\n- Unit test: correlation rule evaluation.\n- Functional test: correlated alert displays context.\n- Integration test: end-to-end correlation on sample data." 

create_issue "SO-SIEM-13: Hunt workflow" "Implement hunt workflow with saved searches, tagging, and notebooks.\n\nAcceptance Criteria:\n- Saved searches can be created and replayed.\n- Notes and tags stored per hunt.\n\nTesting:\n- Unit test: hunt persistence.\n- Functional test: create/save/replay.\n- Integration test: hunt uses events from ingest." 

create_issue "SO-SIEM-14: RBAC + audit logging" "Implement RBAC for admin/analyst/viewer and audit logging.\n\nAcceptance Criteria:\n- Roles enforced on SIEM endpoints.\n- Audit log is queryable.\n\nTesting:\n- Unit test: permission checks.\n- Functional test: role-based access to UI.\n- Integration test: audit events generated per action." 

create_issue "SO-SIEM-15: Production security" "Add TLS, API tokens, and secure secrets handling for production.\n\nAcceptance Criteria:\n- Tokens required for agent and ingest endpoints.\n- Secrets handled via env or vault.\n\nTesting:\n- Unit test: token validator.\n- Functional test: unauthorized requests rejected.\n- Integration test: secure pipeline end-to-end." 

create_issue "SO-SIEM-16: Health checks + metrics" "Add health checks and metrics for all services.\n\nAcceptance Criteria:\n- /healthz and /metrics available.\n- Dashboards show service status.\n\nTesting:\n- Unit test: health evaluator.\n- Functional test: endpoints return OK.\n- Integration test: stack health across services." 

create_issue "SO-SIEM-17: Research export" "Add data export for research reproducibility (NDJSON/Parquet).\n\nAcceptance Criteria:\n- Snapshots export by time range.\n- Schema versioning included.\n\nTesting:\n- Unit test: export serializer.\n- Functional test: export endpoint returns file.\n- Integration test: export re-import validates." 

create_issue "SO-SIEM-18: Research mode profile" "Create a Research Mode profile for deterministic runs.\n\nAcceptance Criteria:\n- Pipeline/ruleset/retention pinned and versioned.\n- Profile documented and selectable.\n\nTesting:\n- Unit test: profile parser.\n- Functional test: profile activates configuration.\n- Integration test: repeatable results across runs." 

printf '\nAll SIEM issues created in %s\n' "$REPO"
