# Host Agent: Osquery + File Integrity Monitoring

## Osquery
The agent can run osquery queries locally (requires `osqueryi` in PATH) and forward results to the SIEM pipeline ingest endpoint.

### CLI
```bash
python agent.py osquery --query "select * from processes limit 5;"
```

### Remote Command
Send an agent command with action `osquery` and parameter `query`:
```json
{
  "action": "osquery",
  "parameters": {"query": "select * from processes limit 5;"}
}
```

## File Integrity Monitoring (FIM)
FIM captures a baseline of file hashes and compares for changes.

### CLI
Create a baseline:
```bash
python agent.py fim-baseline --paths "/etc,/usr/bin"
```

Scan for changes:
```bash
python agent.py fim-scan --paths "/etc,/usr/bin"
```

### Remote Commands
- `fim_baseline` with `paths` and optional `baseline_path`
- `fim_scan` with `paths` and optional `baseline_path`

Example payload:
```json
{
  "action": "fim_scan",
  "parameters": {"paths": ["/etc", "/usr/bin"], "baseline_path": "/tmp/fim_baseline.json"}
}
```

## SIEM Events
Events are sent to `/dashboard/siem/pipeline/ingest/` with:
- `event_type`: `osquery.result` or `fim.change`
- `source`: `osquery` or `fim`
- `raw`: query results or change details

## Authentication
Set the following environment variables on the agent so requests are authorized:
```
export SIEM_INGEST_TOKEN=your-siem-token
export AGENT_API_TOKEN=your-agent-token
```

The agent includes these headers automatically:
- `X-SIEM-Token` for SIEM ingest endpoints
- `X-Agent-Token` for agent API endpoints
