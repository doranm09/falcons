# Cyber Pen Test Platform

This repository is a Django-based security operations and ICS lab platform. The
current deployment model is built around two Docker Compose projects that run
together:

1. The application stack in `docker-compose.yml`
2. The standalone Greenbone / OpenVAS stack in `greenbone-community-container/compose.yaml`

The dashboard, worker, SIEM, risk service, and Greenbone scanner are integrated,
but Greenbone is still operated as its own stack.

## What This Stack Does

- Django dashboard for topology, scans, SIEM workflows, cases, hunts, and risk views
- Celery worker for background jobs
- OpenSearch and OpenSearch Dashboards for event storage and analyst search
- FastAPI-based ICS risk assessment service from the sibling `ics-risk-assessment` repo
- Greenbone / OpenVAS for vulnerability scanning
- Optional OT / IAEA hybrid testbed overlays

## Architecture

### Application stack

Started from `docker-compose.yml`, this brings up:

- `web`
- `celery`
- `db`
- `redis`
- `sniffer`
- `risk-assessment`
- `opensearch`
- `opensearch-dashboards`
- `opensearch-init`

### Greenbone stack

Started from `greenbone-community-container/compose.yaml`, this brings up:

- `gvmd`
- `gsad`
- `ospd-openvas`
- `openvasd`
- `pg-gvm`
- `nginx`
- feed / data containers

### How the two stacks connect

The integration is through shared Docker resources and Unix sockets:

- Shared Docker network: `cyber_pen_test_greenbone_shared`
- Shared gvmd GMP socket on the host: `/opt/gvm-run/gvmd.sock`
- Shared gvmd PostgreSQL socket volume: `cyber_pen_test_gvmd_psql_socket`

The Django `web` and `celery` containers talk to Greenbone over those shared
resources. They do not embed the scanner inside the main app stack.

Important:

- Use `greenbone-community-container/compose.yaml` as the canonical way to run Greenbone.
- Do not run both `docker-compose.greenbone.yml` and `greenbone-community-container/compose.yaml` at the same time.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2
- The sibling repo `../ics-risk-assessment` present on disk
- A writable host directory at `/opt/gvm-run`
- Optional: local Python virtualenv for direct Django test runs

## First-Time Setup

1. Create the environment file if needed:

```bash
cp .env.example .env
```

2. Ensure the sibling risk repo exists at:

```text
../ics-risk-assessment
```

3. Create the shared Greenbone socket directory on the host:

```bash
sudo mkdir -p /opt/gvm-run
sudo chmod 777 /opt/gvm-run
```

4. If your host user is not UID/GID `1000`, export your IDs before starting the
dev stack to avoid bind-mount permission problems:

```bash
export LOCAL_UID=$(id -u)
export LOCAL_GID=$(id -g)
```

5. Review `.env` and change any tokens or passwords you do not want to keep at
their development defaults.

## Repeatable Startup Sequence

### Standard startup

From the repo root:

1. Start Greenbone first:

```bash
docker compose -f greenbone-community-container/compose.yaml up -d
```

2. Start the application stack:

```bash
docker compose up -d --build
```

3. Confirm both stacks are healthy:

```bash
docker compose ps
docker compose -f greenbone-community-container/compose.yaml ps
```

4. Create a Django admin user if this is a fresh environment:

```bash
docker compose exec web python cyber_pen_test/manage.py createsuperuser
```

Notes:

- The `web` entrypoint already runs `migrate`, `setup_sliver.py`, and `collectstatic`.
- You do not need to run `manage.py migrate` manually on every startup.

### Optional: attach OpenVAS to the IAEA hybrid lab networks

If you want the scanner attached to the validated IAEA hybrid networks, start
Greenbone with the network override:

```bash
docker compose \
  -f greenbone-community-container/compose.yaml \
  -f greenbone-community-container/docker-compose.iaea-networks.yml \
  up -d
```

See `greenbone-community-container/README.md` for the scanner IP assignments used
on those lab networks.

## Service Endpoints

| Service | URL | Notes |
| --- | --- | --- |
| Django dashboard | `http://127.0.0.1:8000` | Main UI |
| Django admin | `http://127.0.0.1:8000/admin` | Create via `createsuperuser` |
| Sniffer API | `http://127.0.0.1:5050` | Passive capture helper |
| Risk assessment API | `http://127.0.0.1:7890/status` | FastAPI health endpoint |
| OpenSearch | `http://127.0.0.1:9200` | Raw event store |
| OpenSearch Dashboards | `http://127.0.0.1:5601` | Analyst search UI |
| OpenVAS UI | `http://127.0.0.1:9392/` | Redirects to `https://127.0.0.1/` |

OpenVAS UI note:

- The Greenbone nginx front end uses a local test certificate.
- Expect a browser TLS warning unless you trust that local CA.
- If you want the UI directly, `https://127.0.0.1/` is the end state after the redirect.

Default Greenbone manager credentials:

- username: `admin`
- password: `admin`

## Health Checks and Verification

### Verify the app stack

```bash
docker compose ps
```

### Verify the Greenbone stack

```bash
docker compose -f greenbone-community-container/compose.yaml ps
```

### Verify Django can reach gvmd

```bash
docker compose exec -T web python cyber_pen_test/manage.py shell -c \
  "from dashboard.openvas_client import openvas_session; gmp = openvas_session(); print(gmp.get_version())"
```

### Verify Django can query the gvmd database socket

```bash
docker compose exec -T web python cyber_pen_test/manage.py shell -c \
  "from django.db import connections; c = connections['gvmd']; cur = c.cursor(); cur.execute('select 1'); print(cur.fetchone())"
```

## Common Day-to-Day Commands

### Restart only the application stack

```bash
docker compose up -d --build
```

### Restart only Greenbone

```bash
docker compose -f greenbone-community-container/compose.yaml up -d
```

### Stop the application stack

```bash
docker compose down
```

### Stop Greenbone

```bash
docker compose -f greenbone-community-container/compose.yaml down
```

### Clean restart without deleting named volumes

```bash
docker compose down
docker compose -f greenbone-community-container/compose.yaml down
docker compose -f greenbone-community-container/compose.yaml up -d
docker compose up -d --build
```

### Remove stale application-side scanner orphans

Use this if you previously ran an older combined scanner definition and Compose
is still warning about orphaned `cyber_pen_test-*` Greenbone containers:

```bash
docker compose up -d --remove-orphans web celery
```

## Development Modes

### Live-reload Django

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

### Debug Django with `debugpy`

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.local.yml \
  -f docker-compose.debug.yml \
  up -d --build
```

Debugger port:

- `127.0.0.1:5678`

### Optional OT / testbed overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml up -d --build
```

Optional Kali attacker profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml --profile kali up -d --build
```

## Optional Host Agent

To run the host agent outside the containers:

```bash
cd host_agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python agent.py
```

## Troubleshooting

### OpenVAS UI looks down

Check both of these first:

```bash
docker compose -f greenbone-community-container/compose.yaml ps
curl -vL http://127.0.0.1:9392/
```

If the redirect works but the browser still blocks the page, the issue is
usually the local TLS certificate warning, not scanner availability.

### Django cannot reach Greenbone

Make sure:

- Greenbone was started from `greenbone-community-container/compose.yaml`
- `/opt/gvm-run/gvmd.sock` exists on the host
- `web` and `celery` were recreated after any Greenbone network or socket changes

### Bind-mount permission errors

If Django fails writing `staticfiles` or other mounted paths, export your host
UID and GID before starting the stack:

```bash
export LOCAL_UID=$(id -u)
export LOCAL_GID=$(id -g)
```

## Related Docs

- `docs/security_onion_soc_architecture.md`
- `docs/siem_feature_overview.md`
- `docs/event_schema.md`
- `docs/opensearch.md`
- `docs/sliver_c2_dashboard.md`
- `greenbone-community-container/README.md`
- `host_agent/README.md`
