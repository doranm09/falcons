# Agent Guide

This project includes a Python host agent for system telemetry, SBOM collection, and SIEM pipeline enrichment. This file is a concise runbook; see `host_agent/README.md` and `host_agent/README_OSQUERY_FIM.md` for deeper details.

## What The Agent Does
- Sends heartbeat telemetry to `/agent/report/` and optional cyber template data to `/agent/cyber_report/`.
- Polls `/agent/commands/` and posts results to `/agent/command_result/`.
- Collects SBOMs and posts them to `/sbom`.
- Generates SIEM events for osquery and file integrity monitoring (FIM) via `/dashboard/siem/pipeline/ingest/`.

## Install
```bash
python3 -m venv host_agent/venv
source host_agent/venv/bin/activate
pip install -r host_agent/requirements.txt
```

## Configure
Required environment variables:
- `AGENT_SERVER_URL` (e.g., `http://server:8000`)
- `AGENT_API_TOKEN` (for agent API endpoints)
- `SIEM_INGEST_TOKEN` (for SIEM pipeline ingest)

Optional:
- `AGENT_API_TOKEN_FILE` and `SIEM_INGEST_TOKEN_FILE` for file-based secrets

Example:
```bash
export AGENT_SERVER_URL=http://server:8000
export AGENT_API_TOKEN=your-agent-token
export SIEM_INGEST_TOKEN=your-siem-token
```

## Quick Start
```bash
python host_agent/agent.py --url http://server:8000 run
```

Common one-shot actions:
```bash
python host_agent/agent.py --url http://server:8000 heartbeat
python host_agent/agent.py --url http://server:8000 poll
python host_agent/agent.py --url http://server:8000 info
```

## SBOM Collection
```bash
python host_agent/agent.py sbom --format cyclonedx --output sbom.json
```
Optional vulnerabilities:
```bash
python host_agent/agent.py sbom --format cyclonedx --vuln-file grype.json
```

## SIEM Telemetry
Osquery:
```bash
python host_agent/agent.py osquery --query "select * from processes limit 5;"
```
FIM baseline + scan:
```bash
python host_agent/agent.py fim-baseline --paths "/etc,/usr/bin"
python host_agent/agent.py fim-scan --paths "/etc,/usr/bin"
```

Events map to SIEM types:
- `osquery.result`
- `fim.change`

## Security Notes
- Agent endpoints require `X-Agent-Token` and SIEM ingest requires `X-SIEM-Token` when tokens are enabled.
- See `docs/siem_production_security.md` for token and TLS guidance.

## Troubleshooting
- `401 Unauthorized`: verify `AGENT_API_TOKEN` or `SIEM_INGEST_TOKEN`.
- `Connection refused`: verify `AGENT_SERVER_URL` and server reachability.
- Missing events: confirm SIEM ingest token is set and server is reachable.

## References
- `host_agent/README.md`
- `host_agent/README_OSQUERY_FIM.md`
- `docs/siem_production_security.md`
