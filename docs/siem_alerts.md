# SIEM Alerting

This feature provides Sigma/Suricata-style alerting with deduplication and suppression.

## How It Works
- Ingested SIEM events are evaluated against enabled alert rules.
- Matching rules create alerts in the queue.
- Alerts are deduplicated using rule + event type + asset identifiers.
- Suppression windows prevent duplicate alerts for the same dedup key.

## Default Rules
A default Suricata rule is created via migration:
- `Suricata Alerts` (type `suricata`)
- Matches `event_type=suricata.alert`
- Suppression window: 5 minutes

## Rule Fields
- `rule_type`: `sigma` or `suricata`
- `match_event_type`: exact match on event type
- `match_source`: exact match on source
- `match_contains`: case-insensitive substring search in summary or raw payload
- `severity`: override severity for alerts
- `suppression_minutes`: suppression window for dedup

## Alert Queue
Navigate to `/dashboard/siem/alerts/` or use the sidebar link:
- Filter by `open` or `closed` status
- View latest detections and counts
- Toggle rules on/off

## API Usage
Alerts are created automatically on ingest. The following endpoints are available:
- `POST /dashboard/siem/ingest/`
- `POST /dashboard/siem/pipeline/ingest/`

## Deduplication
Alerts are grouped by:
- `rule_id`
- `event_type`
- `asset_ip`
- `asset_id`

If a matching alert is found within the suppression window, the alert count increments and `last_seen` updates.
