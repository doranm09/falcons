# Syslog and Windows Event Log Ingestion

## Syslog
Send syslog lines (RFC3164 or RFC5424) to:

`POST /dashboard/siem/syslog/`

### Example
```bash
printf '<34>Oct 11 22:14:15 web01 sshd[123]: Failed password for root\n' | \
  curl -X POST http://localhost:8000/dashboard/siem/syslog/ \
  -H "Content-Type: text/plain" \
  --data-binary @-
```

This maps to SIEM events with:
- `event_type`: `syslog.message`
- `source`: `syslog`
- `asset_id`: hostname from the syslog header
- `summary`: syslog message

## Windows Event Logs
Send JSON payloads to:

`POST /dashboard/siem/windows/`

### Example
```json
{
  "system": {"event_id": 4625, "computer": "WIN-HOST"},
  "provider": {"name": "Microsoft-Windows-Security-Auditing"},
  "timestamp": "2026-02-06T12:55:00Z",
  "message": "An account failed to log on"
}
```

This maps to SIEM events with:
- `event_type`: `windows.event`
- `source`: `windows`
- `asset_id`: computer name
- `labels.provider`: provider name
- `labels.event_id`: Windows Event ID
