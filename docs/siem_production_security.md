# SIEM Production Security

This project supports production-hardening with token-based ingest, agent API tokens, and secret file support.

## Required Tokens
- SIEM ingest endpoints (`/dashboard/siem/ingest/`, `/dashboard/siem/pipeline/ingest/`, `/dashboard/siem/syslog/`, `/dashboard/siem/windows/`)
  - Header: `X-SIEM-Token: <token>` or `Authorization: Bearer <token>`
- Agent endpoints (`/agent/report/`, `/agent/cyber_report/`, `/sbom`, `/agent/commands/`, `/agent/command_result/`, `/agent/scan_results/`, `/agent/network_metadata/`)
  - Header: `X-Agent-Token: <token>` or `Authorization: Bearer <token>`

Environment variables:
- `SIEM_INGEST_TOKEN` (or `SIEM_INGEST_TOKEN_FILE`)
- `AGENT_API_TOKEN` (or `AGENT_API_TOKEN_FILE`)
- `SIEM_INGEST_TOKEN_REQUIRED=1` (default)
- `AGENT_API_TOKEN_REQUIRED=1` (default)

## Secret Files
You can load secrets from files to integrate with Docker secrets or a vault sidecar:
- `SIEM_INGEST_TOKEN_FILE=/run/secrets/siem_ingest_token`
- `AGENT_API_TOKEN_FILE=/run/secrets/agent_api_token`
- `DJANGO_SECRET_KEY_FILE=/run/secrets/django_secret_key`
- `OPENSEARCH_PASS_FILE=/run/secrets/opensearch_pass`

## TLS
Terminate TLS in front of the Django service:
- Use Nginx/Traefik/Caddy with a valid certificate.
- Set `SECURE_PROXY_SSL_HEADER` and `CSRF_TRUSTED_ORIGINS` as needed for your deployment.

Optional Django flags (env-driven):
- `DJANGO_SECURE_SSL_REDIRECT=1`
- `DJANGO_SESSION_COOKIE_SECURE=1`
- `DJANGO_CSRF_COOKIE_SECURE=1`
- `DJANGO_SECURE_PROXY_SSL=1`

## Host Agent Configuration
Set the tokens in the host agent environment:
```
export AGENT_API_TOKEN=your-agent-token
export SIEM_INGEST_TOKEN=your-siem-token
```

The host agent will include these headers automatically when posting to the server.
