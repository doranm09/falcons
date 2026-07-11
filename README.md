# Cybersecurity Digital Twin for Advanced Networked Systems

This project is a full-stack Django platform that simulates and secures networked environments (e.g., advanced reactors or industrial control systems). It integrates passive monitoring, active scanning, vulnerability assessment, and remote agent coordination into a cohesive digital twin.

---

## Project Architecture

- **Django + Celery Backend** — Topology modeling, scans, CVE storage
- **Cytoscape.js Frontend** — Visual graph of nodes and link latencies
- **Passive Sniffer API (Flask)** — Starts/stops sniffing via exposed interfaces
- **Host Agent (Python)** — Pushes system info and responds to remote commands
- **ICS Risk Assessment Service (FastAPI)** — Dynamic Bayesian risk probabilities for ICS nodes
- **Dockerized Infrastructure** — PostgreSQL, Redis, Flask sniffer, Celery worker

---

## Key Features

### 1. Network Mapping & Node Discovery
- Passive sniffer interface management via dashboard
- IP discovery and latency-weighted graph generation
- Dijkstra-based shortest path calculation
- Versioned scans with historical view
- Ping sweep, Nmap discovery, and agent-based scanning (dedicated Network Scans view)

### 2. Vulnerability Assessment
- CVE ingestion from NVD (via keyword or CPE)
- Severity scoring and association with nodes
- Admin integration for search, filter, and review

### 3. Persistent Host Agent
- Periodic system info push (CPU, interfaces, processes)
- Command polling (e.g., test ping, scans)
- Remote execution with output POST-back
- SBOM collection and upload (CycloneDX supported)

### 4. Real-Time Visualization
- Dynamic network graph with Cytoscape.js
- Node color/size/styling mapped to attributes
- Interactive shortest path UI

### 5. SIEM Event Ingestion (Phase 1)
- ECS-inspired event schema and normalization
- `/dashboard/siem/ingest/` endpoint for batch or single-event ingest
- `/dashboard/siem/events/` search with time range and filters
- Token-based ingest protection via `SIEM_INGEST_TOKEN`
- Event Explorer UI with filters and raw payload inspection
- Event Explorer pivot to related node and scan details
- Adapter preview endpoints for agent, scan, vulnerability, and SBOM events
- Pipeline ingest endpoint that maps raw sensor payloads to ECS subset
- OpenSearch log store + Dashboards for indexed SIEM events
- Alert queue with deduplication and rule toggles (Sigma + Suricata)
- Case management with notes, evidence, and exports
- Threat intel ingestion (MISP-like) and IOC enrichment in alerts
- Host agent telemetry with osquery + file integrity monitoring (FIM)
- Syslog and Windows Event Log ingestion endpoints

### 6. Digital Twin Generation (MiniMega)
- Generate MiniMega launch scripts and manifests from scans
- Optional server-side execution with safety gates
- Download script + manifest bundles

### 7. Sliver C2 Operations
- Sliver teamserver management with UI-based create/edit/delete
- Engagement tracking, sessions, and job queue with live updates
- Job retry + CSV export, and downloadable loot artifacts
- Implant generation + deployment workflows

### 8. ICS Risk Assessment
- Integrated Risk Assessment UI (Overview, Nodes, Probability)
- Network risk overlay computed from cyber scan data
- Proxy endpoints to the ICS risk assessment API
- Dockerized FastAPI service started alongside web/worker

#### Risk Assessment Views
- **Overview**: Health/status of the risk assessment service.
- **Nodes**: List of DBN nodes and their state definitions from the risk service.
- **Mappings**: Link risk model node IDs to discovered IPs/nodes and manage labels/notes.
- **Probability**: Run probability queries with optional evidence + cyber data payloads.
- **Network View**: Graph + table that overlays per-node risk on the live topology.

#### What It Does
The risk assessment service provides Bayesian probability outputs for ICS nodes. The
dashboard fetches available risk nodes, maps them to discovered network nodes (by
name or IP), generates a cyber vulnerability payload, and computes risk scores.
Results are shown in the Network View graph (color-coded) and in a sortable table.

#### How To Use
1. Start the stack with Docker Compose (the `risk-assessment` service must be running).
2. Go to `Risk Analysis -> Risk Assessment`.
3. Use:
   - **Overview** to confirm service health.
   - **Nodes** to see available DBN nodes.
   - **Network View** to load the graph and compute risk overlay.
   - **Probability** for manual queries (optional evidence/cyber payloads).

#### Mapping Risk Nodes
To align your discovered nodes with the risk model, manage mappings in the Risk Assessment UI:
1. Go to `Risk Analysis -> Risk Assessment` and open the **Mappings** tab.
2. For each risk node ID, select a **Node** or enter an **IP address**.
3. Optionally add a label/notes and keep the mapping **Active**.

You can also manage mappings via `/admin/` → **Risk Node Mappings** if needed.

The Mappings tab supports:
- **Save All** to persist the entire table at once.
- **Import CSV** to pre-fill rows using a file with `risk_node_id`, plus optional `node_id`,
  `node_name`, `ip_address`, `label`, `notes`, and `active` columns.
- **Node Metadata** to help match assets (OS, platform, ports, MACs, last heartbeat).

#### Risk Schema Testbed
To create a synthetic network that matches the risk model schema (and feed it into the
risk assessment service):
1. Go to `Risk Analysis -> Risk Assessment` and open the **Testbed** tab.
2. Provide a CIDR (default `192.168.236.0/24`) and a CVE list (comma or newline separated).
3. Click **Generate Testbed** to create nodes, mappings, and vulnerabilities.
4. Go to **Network View** and click **Compute Risk** to see the overlay.

The testbed generator also creates a Purdue-style connected topology (tiered rings with
north-south links), and the Risk Assessment graph filters to the generated scan run so
older nodes are hidden.

Mappings are used to attach vulnerability data to the correct risk model nodes so
the risk engine can compute non‑`unknown` scores.

---

## Getting Started

### Prerequisites
- Docker & Docker Compose
- Python 3.10+ (for host agent)

### 0. Openvas Log File
```bash
mkdir -p ./data/gvm-logs

# on your host, NOT inside the container
sudo chown -R 1000:1000 ./data/gvm-logs
sudo chmod -R u+rwX,go-rwx ./data/gvm-logs

```

### 1. Build & Run the Platform

```bash
cp .env.example .env
docker-compose up --build
```

> Note (Linux bind-mount permissions): the dev compose file mounts `.:/code`. If you hit a Django `collectstatic` error like `Permission denied: '/code/staticfiles/...'`, run with your host UID/GID so the container can write to the mounted files:
```bash
LOCAL_UID=$(id -u) LOCAL_GID=$(id -g) docker-compose up --build
```

- Web app: http://localhost:8000
- Sniffer API: http://localhost:5050 or http://sniffer:5000 internally
- Risk Assessment API: http://localhost:7890

> Note: `docker-compose` expects the risk assessment repo to be available at `../ics-risk-assessment` relative to this project root. If you keep it elsewhere, update the `risk-assessment` build context in `docker-compose.yml`.

If you previously ran containers, rebuild to pick up dependency changes:
```bash
docker-compose up --build --force-recreate
```

### Production Compose
For a production-like deployment (no bind mounts), use:
```bash
docker-compose -f docker-compose.prod.yml up --build -d
```

> Note: `LOCAL_UID`/`LOCAL_GID` is only needed for the dev compose bind mount. The production compose file should run with the image's default non-root user.

---

### 2. Create Superuser

```bash
docker-compose exec web python manage.py createsuperuser
```

Then access the admin panel at: http://localhost:8000/admin

---

### 3. Run Host Agent (on external system or host)

```bash
cd host_agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python agent.py
```

- Agent sends system heartbeat to `/agent/report/`
- Polls for commands via `/agent/commands/`
- Returns results via `/agent/command_result/`
- Posts SBOMs to `/sbom/` (manual or via command)

---

## SBOM Collection & Diff

You can trigger SBOM collection from the **Agent Monitor** page or directly on the agent:

```bash
python agent.py sbom --format cyclonedx
```

### SBOM Export
- Latest JSON: `/agent/<agent_id>/sbom/`
- CSV export: `/agent/<agent_id>/sbom/?format=csv`
- Bundle (latest SBOM + diff): `/agent/<agent_id>/sbom/bundle/`

### SBOM Diff
Compare the last two SBOMs for an agent:
```
/agent/<agent_id>/sbom/diff/
```

---

## SIEM Event Ingestion (Phase 1)
Documentation:
- `docs/event_schema.md`
- `docs/siem_events.md`
- `docs/opensearch.md`
- `docs/siem_alerts.md`
- `docs/siem_cases.md`
- `docs/siem_hunts.md`
- `docs/siem_rbac_audit.md`
- `docs/siem_production_security.md`
- `docs/siem_health_metrics.md`
- `docs/siem_export.md`
- `docs/siem_research_profile.md`
- `docs/threat_intel.md`
- `docs/siem_feature_overview.md`
- `docs/siem_syslog_windows.md`
- `docs/pid_drawio_pipeline.md`

---

## Digital Twin + MiniMega

Go to **Tools & Configuration → Digital Twin** to generate a MiniMega script and manifest from a scan.

### Generate a Script + Manifest
- Select a scan
- Provide a base disk image path (qcow2)
- Download a bundle ZIP or copy the script directly

### Optional: Server-Side Execution
To enable execution from the dashboard, set:
```
MINIMEGA_EXECUTION_ENABLED=1
```

The UI requires a confirm token `RUN_MINIMEGA` before execution.  
Scripts are written to:
```
/tmp/cybertwin_minimega
```
You can override this with:
```
MINIMEGA_SCRIPT_DIR=/path/to/scripts
```

Execution events are logged in the admin under **MiniMega Execution Logs**.
You can also view logs in the UI at `/digital-twin/logs/` (staff only).

### Safe Reset / Kill (Staff Only)
These controls are staff-gated and require explicit confirmation tokens:
```
MINIMEGA_ALLOW_RESET=1
MINIMEGA_ALLOW_KILL=1
```

Defaults can be overridden:
```
MINIMEGA_RESET_COMMAND="clear vm"
MINIMEGA_KILL_COMMAND="quit"
```

Confirmation tokens required by the UI:
- Reset: `RESET_MINIMEGA`
- Kill: `KILL_MINIMEGA`

You must be logged in as a staff user to use the reset/kill controls.

---

## Network Scans

All scan workflows live under **Vulnerability Assessment → Network Scans**:
- **Ping Sweep** (fast discovery)
- **Nmap Discovery** (more accurate host discovery)
- **Agent Scan** (distributed discovery from a selected host agent)

### Agent Scan Flow
1. Select agent + CIDR in the Network Scans view.
2. The dashboard issues a command to that agent.
3. The agent performs a ping sweep and posts results back to `/agent/scan_results/`.

### Nmap Requirements
Nmap runs inside the web/celery containers. If you pull a fresh build, it’s already included.  
If you modify Dockerfiles, rebuild the images:
```bash
docker-compose up --build --force-recreate
```

---

## OpenVAS / GVM Integration

The repo includes a Greenbone Community Edition stack at:
```
greenbone-community-container/
```

### Quick Start (OpenVAS)
```bash
sudo mkdir -p /opt/gvm-run
sudo chmod 777 /opt/gvm-run
docker compose -f greenbone-community-container/docker-compose.yml up -d
```

### OpenVAS OT Network Bridge (for full testbed scans)
When scanning the OT sandbox from OpenVAS, attach the scanner to OT zone networks:
```bash
docker compose \
  -f greenbone-community-container/docker-compose.yml \
  -f greenbone-community-container/docker-compose.ot-networks.yml \
  up -d
```
This makes OpenVAS reach L0/1, L2, L3, L3.5, L4, and L5 (`172.30.0.0/16`).

For the IAEA RCS demo, use the matching override instead:
```bash
docker compose \
  -f greenbone-community-container/compose.yaml \
  -f greenbone-community-container/docker-compose.iaea-networks.yml \
  up -d
```
This gives the scanner containers direct access to the `iaea_rcs_demo` subnets so you can scan every layer in the lab.

### Configure the Dashboard
Set these in `.env` (defaults are shown):
```
GVM_SOCKET_PATH=/opt/gvm-run/gvmd.sock
GVM_USER=admin
GVM_PASS=admin
GVM_HOST=openvas
GVM_PORT=9390
```

The web and celery containers mount `/opt/gvm-run` so GMP over Unix socket works out of the box once GVM is running.
If you use TLS instead, unset `GVM_SOCKET_PATH` and set `GVM_HOST` + `GVM_PORT`.

### Sync the web container with local code
When the stack is running in the testbed or production profile and you need local Django code changes to show up immediately, add `docker-compose.local.yml` to your compose command. It appends a bind mount (`.:/code`) for both `web` and `celery` without disturbing the existing `/opt/gvm-run` volume:
```
docker compose -f docker-compose.yml -f docker-compose.testbed.yml -f docker-compose.local.yml up -d --build
```
Or if you are orchestrating the production configuration directly:
```
docker compose -f docker-compose.prod.yml -f docker-compose.testbed.yml -f docker-compose.local.yml up -d --build
```
The extra override layer ensures the container sees the repository files so Django reloads while you iterate locally.

---

## OT Testbed Sandbox (Purdue-Style)

This repo includes a multi-zone OT sandbox modeled after the `oscal-pbnc` layout. It creates L0/1–L5 networks,
explicit conduits, and simple HTTP services with static IPs. It’s intended for functional testing of
network scans and agent-based discovery.

### Bring Up
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml up -d --build
```

### Bring Up With Kali (Optional)
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml --profile kali up -d --build
```

### Tear Down
```bash
docker compose -f docker-compose.yml -f docker-compose.testbed.yml down -v
```

### Example Scan Targets
- **Ping/Nmap discovery (single zone)**: `172.30.2.0/24`
- **Ping/Nmap discovery (full OT testbed)**: `172.30.0.0/16`
- **Agent scan**: choose the zone agent (e.g., `agent-l35`) and scan `172.30.3.0/24`
- **Kali-driven enumeration** (optional):
  - `docker compose -f docker-compose.yml -f docker-compose.testbed.yml exec kali-attacker nmap -sV 172.30.2.0/24`
  - `docker compose -f docker-compose.yml -f docker-compose.testbed.yml exec kali-attacker nmap -sV --script vuln 172.30.3.0/24`

### One-Click OT Campaign (UI)
Open `Network Scans` and use **One-Click OT Campaign** to orchestrate:
1. Discovery scan (ping or nmap)
2. Optional agent scan queue
3. Optional OpenVAS vulnerability stage
4. Optional Sliver command + loot collection

### OT Campaign Runner Script
For headless labs:
```bash
./scripts/run_ot_campaign.sh 172.30.2.0/24
```
Environment overrides:
- `BASE_URL` (default `http://localhost:8000`)
- `SCAN_METHOD` (`nmap` or `ping`)
- `AGENT_ID` (optional)
- `RUN_OPENVAS` (`1`/`0`)
- `GVMD_CONFIG` (e.g. `full_and_fast`)
- `SLIVER_SESSION_ID` (optional)
- `SLIVER_COMMAND` (default `whoami`)
- `COLLECT_LOOT` (`1`/`0`)

Details: `testbed/ot/README.md`

---

## Running the Test Suite

The project includes a comprehensive unit test suite covering all major features of the cybersecurity dashboard. The test suite consists of 60+ tests with ~83% pass rate, covering models, views, APIs, utilities, and background tasks.

### Prerequisites for Testing
- Python 3.10+
- All Django dependencies installed (see requirements.txt)
- SQLite (automatically used for tests instead of PostgreSQL)

### Running All Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Navigate to project root
cd cyber_pen_test

# Run all tests with test settings
python manage.py test dashboard --settings=cyber_pen_test.test_settings --verbosity=2
```

### Risk Assessment Integration Test
Requires the `risk-assessment` service running (see Docker Compose instructions).

```bash
pytest tests/integration/test_risk_assessment_integration.py
```

### Running Specific Test Categories

```bash
# Run only model tests
python manage.py test dashboard.tests -k "ModelTest" --settings=cyber_pen_test.test_settings

# Run only view tests
python manage.py test dashboard.tests -k "ViewTests" --settings=cyber_pen_test.test_settings

# Run only utility tests
python manage.py test dashboard.tests.UtilsTestCase --settings=cyber_pen_test.test_settings
```

### Test Coverage Summary

The test suite covers:

- **Model Tests (9 classes)**
  - ScanRun, Node, Link models and their methods
  - AgentStatus and heartbeat handling
  - Vulnerability and AgentCommand models
  - NetworkMetadata and Connection models

- **View Tests (8 classes)**
  - Dashboard home and graph visualization
  - Agent monitoring and command sending
  - Network monitoring and topology APIs
  - History, download, and analysis views

- **API Endpoint Tests (3 classes)**
  - Agent report, cyber data, and command result handling
  - Network metadata upload and retrieval
  - Real-time agent status APIs

- **Utility Tests (1 class)**
  - Dijkstra shortest path algorithm
  - Network interface detection

- **Task Tests (1 class)**
  - Celery background tasks for scanning
  - OpenVAS integration and vulnerability processing

### Troubleshooting Tests

If tests fail with database connection errors:
```bash
# Ensure PostgreSQL is running or use test settings
export POSTGRES_NAME=test
export POSTGRES_USER=user
export POSTGRES_PASSWORD=pass
```

For template rendering issues during tests, verify all dashboard templates exist in `dashboard/templates/dashboard/`.

## Running the Comprehensive Test Suite

The project now includes a comprehensive test suite covering server-side functional tests and browser-based E2E tests. The test suite includes deterministic mocks for outbound HTTP, comprehensive fixtures, and factory boys for test data.

### Test Structure

```
tests/
├── conftest.py                    # Common fixtures and settings
├── factories/                     # Factory Boy factories
│   ├── __init__.py
│   └── user_factory.py           # User factory with faker
├── server/                        # Server-side functional tests
│   ├── test_download_view.py      # Download view tests (API, fallback, cache, security)
│   ├── test_auth_and_redirects.py # Auth/permission tests
│   └── test_crud_examples.py      # CRUD operations tests
└── e2e/                          # Browser E2E tests with Playwright
    ├── test_download_e2e.py       # Download flow E2E tests
    └── test_auth_flow_e2e.py      # Auth flow E2E tests
```

### Prerequisites for Testing
- Python 3.10+
- Docker & Docker Compose (for CI)
- All dependencies installed: `pip install -r requirements.txt && pip install -r requirements-dev.txt`
- Playwright browsers: `python -m playwright install --with-deps chromium`

### Running Tests Locally

#### Using pytest directly:

```bash
# Run all tests
pytest -q --settings=cyber_pen_test.test_settings

# Run server tests only
pytest tests/server -q --settings=cyber_pen_test.test_settings

# Run E2E tests only
pytest tests/e2e -q --settings=cyber_pen_test.test_settings

# Run with verbose output
pytest --settings=cyber_pen_test.test_settings -v
```

#### Using Makefile (preferred):

```bash
# Install development dependencies
make install-deps

# Run all tests
make test

# Run server tests only
make test-server

# Run E2E tests only
make test-e2e

# Run migrations first (if needed)
make migrate

# Clean test artifacts
make clean
```

### CI/CD Testing

Tests run automatically on GitHub Actions for pushes and pull requests to `main` and `develop` branches. The CI:

- Sets up PostgreSQL and Redis services
- Installs all dependencies and Playwright browsers
- Runs migrations
- Executes server tests, E2E tests, and full test suite
- Uploads Playwright traces on failure

### Test Coverage

The test suite covers:

**Server Tests:**
- **Download View**: GitHub API success/fallback, caching (<1h), security (no path traversal)
- **Authentication**: Public access verification (no global auth middleware)
- **CRUD Operations**: Node model create/list/detail/update/delete with form validation
- **Permission Checks**: Admin/staff-only routes and API endpoints

**E2E Tests:**
- **Download Flow**: Navigate to `/agent/download/`, click `[data-testid="download-agent"]`, verify ZIP download
- **Auth Flow**: Verify public pages accessible without login
- **UI Interactions**: Dropdown menus, navigation, and interactive elements

**Key Features:**
- ✅ Deterministic mocks (responses library for GitHub API)
- ✅ Isolated test database (SQLite for fast tests)
- ✅ Factory Boy + Faker for realistic test data
- ✅ Playwright for browser automation
- ✅ Comprehensive fixtures (user, admin_user, client variants)
- ✅ Stable selectors (`data-testid="download-agent"`)
- ✅ No external network dependencies during tests
- ✅ ZIP file validation using `zipfile.ZipFile`

### Test Configuration

- **pytest.ini**: Settings for Django tests with `cyber_pen_test.test_settings`
- **conftest.py**: Autouse media root isolation, user factories, client fixtures
- **requirements-dev.txt**: Test dependencies (pytest, playwright, factory-boy, faker, responses)

### Troubleshooting Tests

**Database Issues:**
```bash
# For local testing, ensure migrations are run
python manage.py migrate --settings=cyber_pen_test.test_settings
```

**E2E Test Failures:**
```bash
# Reinstall Playwright browsers
playwright install --with-deps chromium

# Run with visible browser for debugging
pytest tests/e2e::TestDownloadE2E::test_download_agent_zip_e2e --headed
```

**Permission Issues:**
```bash
# Ensure proper permissions for test files
chmod -R 755 host_agent/
```

---

## Running the Test Suite

The project includes a comprehensive unit test suite covering all major features of the cybersecurity dashboard. The test suite consists of 60+ tests with ~83% pass rate, covering models, views, APIs, utilities, and background tasks.

### Prerequisites for Testing
- Python 3.10+
- All Django dependencies installed (see requirements.txt)
- SQLite (automatically used for tests instead of PostgreSQL)

### Running All Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Navigate to project root
cd cyber_pen_test

# Run all tests with test settings
python manage.py test dashboard --settings=cyber_pen_test.test_settings --verbosity=2
```

### Running Specific Test Categories

```bash
# Run only model tests
python manage.py test dashboard.tests -k "ModelTest" --settings=cyber_pen_test.test_settings

# Run only view tests
python manage.py test dashboard.tests -k "ViewTests" --settings=cyber_pen_test.test_settings

# Run only utility tests
python manage.py test dashboard.tests.UtilsTestCase --settings=cyber_pen_test.test_settings
```

### Test Coverage Summary

The test suite covers:

- **Model Tests (9 classes)**
  - ScanRun, Node, Link models and their methods
  - AgentStatus and heartbeat handling
  - Vulnerability and AgentCommand models
  - NetworkMetadata and Connection models

- **View Tests (8 classes)**
  - Dashboard home and graph visualization
  - Agent monitoring and command sending
  - Network monitoring and topology APIs
  - History, download, and analysis views

- **API Endpoint Tests (3 classes)**
  - Agent report, cyber data, and command result handling
  - Network metadata upload and retrieval
  - Real-time agent status APIs

- **Utility Tests (1 class)**
  - Dijkstra shortest path algorithm
  - Network interface detection

- **Task Tests (1 class)**
  - Celery background tasks for scanning
  - OpenVAS integration and vulnerability processing

### Troubleshooting Tests

If tests fail with database connection errors:
```bash
# Ensure PostgreSQL is running or use test settings
export POSTGRES_NAME=test
export POSTGRES_USER=user
export POSTGRES_PASSWORD=pass
```

For template rendering issues during tests, verify all dashboard templates exist in `dashboard/templates/dashboard/`.

## Running the Comprehensive Test Suite

The project now includes a comprehensive test suite covering server-side functional tests and browser-based E2E tests. The test suite includes deterministic mocks for outbound HTTP, comprehensive fixtures, and factory boys for test data.

### Test Structure

```
tests/
├── conftest.py                    # Common fixtures and settings
├── factories/                     # Factory Boy factories
│   ├── __init__.py
│   └── user_factory.py           # User factory with faker
├── server/                        # Server-side functional tests
│   ├── test_download_view.py      # Download view tests (API, fallback, cache, security)
│   ├── test_auth_and_redirects.py # Auth/permission tests
│   └── test_crud_examples.py      # CRUD operations tests
└── e2e/                          # Browser E2E tests with Playwright
    ├── test_download_e2e.py       # Download flow E2E tests
    └── test_auth_flow_e2e.py      # Auth flow E2E tests
```

### Prerequisites for Testing
- Python 3.10+
- Docker & Docker Compose (for CI)
- All dependencies installed: `pip install -r requirements.txt && pip install -r requirements-dev.txt`
- Playwright browsers: `python -m playwright install --with-deps chromium`

### Running Tests Locally

#### Using pytest directly:

```bash
# Run all tests
pytest -q --settings=cyber_pen_test.test_settings

# Run server tests only
pytest tests/server -q --settings=cyber_pen_test.test_settings

# Run E2E tests only
pytest tests/e2e -q --settings=cyber_pen_test.test_settings

# Run with verbose output
pytest --settings=cyber_pen_test.test_settings -v
```

#### Using Makefile (preferred):

```bash
# Install development dependencies
make install-deps

# Run all tests
make test

# Run server tests only
make test-server

# Run E2E tests only
make test-e2e

# Run migrations first (if needed)
make migrate

# Clean test artifacts
make clean
```

### CI/CD Testing

Tests run automatically on GitHub Actions for pushes and pull requests to `main` and `develop` branches. The CI:

- Sets up PostgreSQL and Redis services
- Installs all dependencies and Playwright browsers
- Runs migrations
- Executes server tests, E2E tests, and full test suite
- Uploads Playwright traces on failure

### Test Coverage

The test suite covers:

**Server Tests:**
- **Download View**: GitHub API success/fallback, caching (<1h), security (no path traversal)
- **Authentication**: Public access verification (no global auth middleware)
- **CRUD Operations**: Node model create/list/detail/update/delete with form validation
- **Permission Checks**: Admin/staff-only routes and API endpoints

**E2E Tests:**
- **Download Flow**: Navigate to `/agent/download/`, click `[data-testid="download-agent"]`, verify ZIP download
- **Auth Flow**: Verify public pages accessible without login
- **UI Interactions**: Dropdown menus, navigation, and interactive elements

**Key Features:**
- ✅ Deterministic mocks (responses library for GitHub API)
- ✅ Isolated test database (SQLite for fast tests)
- ✅ Factory Boy + Faker for realistic test data
- ✅ Playwright for browser automation
- ✅ Comprehensive fixtures (user, admin_user, client variants)
- ✅ Stable selectors (`data-testid="download-agent"`)
- ✅ No external network dependencies during tests
- ✅ ZIP file validation using `zipfile.ZipFile`

### Test Configuration

- **pytest.ini**: Settings for Django tests with `cyber_pen_test.test_settings`
- **conftest.py**: Autouse media root isolation, user factories, client fixtures
- **requirements-dev.txt**: Test dependencies (pytest, playwright, factory-boy, faker, responses)

### Troubleshooting Tests

**Database Issues:**
```bash
# For local testing, ensure migrations are run
python manage.py migrate --settings=cyber_pen_test.test_settings
```

**E2E Test Failures:**
```bash
# Reinstall Playwright browsers
playwright install --with-deps chromium

# Run with visible browser for debugging
pytest tests/e2e::TestDownloadE2E::test_download_agent_zip_e2e --headed
```

**Permission Issues:**
```bash
# Ensure proper permissions for test files
chmod -R 755 host_agent/
```

---

## Testing Agent Commands

From the Django Admin:
1. Go to **AgentCommand**
2. Create a new entry:
   - `agent_id`: (matches your MAC or UUID)
   - `action`: e.g., `ping` or `scan`
3. Agent will pull command and respond

---

## API Endpoints (Simplified)

| Endpoint                | Method | Purpose                      |
|-------------------------|--------|------------------------------|
| `/agent/report/`        | POST   | Receive system info from agent |
| `/agent/commands/`      | GET    | Agent polls for commands     |
| `/agent/command_result/`| POST   | Agent returns command output |
| `/sbom/`                | POST   | Receive SBOM payload         |
| `/agent/<id>/sbom/`     | GET    | Download latest SBOM (JSON/CSV) |
| `/agent/<id>/sbom/diff/`| GET    | Diff latest two SBOMs        |
| `/agent/<id>/sbom/bundle/`| GET  | Download latest SBOM + diff bundle |
| `/digital-twin/`        | GET    | Digital twin generator UI    |
| `/digital-twin/generate/`| POST  | Generate script + manifest   |
| `/digital-twin/export/` | POST   | Download bundle ZIP          |
| `/digital-twin/execute/`| POST   | Execute MiniMega (optional)  |
| `/digital-twin/reset/`  | POST   | Reset MiniMega (staff only)  |
| `/digital-twin/kill/`   | POST   | Kill MiniMega (staff only)   |
| `/digital-twin/logs/`   | GET    | MiniMega execution logs (staff only) |
| `/sniffer/interfaces/`  | GET    | List interfaces (Flask)      |
| `/sniffer/start/`       | POST   | Start sniffing on interface  |
| `/sniffer/stop/`        | POST   | Stop packet capture          |

---

## Tech Stack

- Python 3.10
- Django 3.2+
- Celery + Redis
- PostgreSQL 15+
- Cytoscape.js (frontend graph)
- Flask (sniffer API)
- psutil / platform / requests (host agent)

---

## Directory Structure

```
cyber_pen_test/
├── dashboard/           # Django app: views, models, tasks
├── host_agent/          # Lightweight remote Python agent
├── sniffer/             # Flask-based capture interface
├── static/              # JavaScript (scan.js) & CSS
├── templates/           # Dashboard HTML templates
├── docker-compose.yml
├── Dockerfile, Dockerfile.sniffer
```

---

## License

© 2025 Michael Doran — for academic and federal cybersecurity research. Not intended for offensive use without explicit authorization.

---

## Roadmap
### Current Functionality
- [x] Task 1.1: Passive Listener to capture real-time traffic
- [x] Task 1.2: Extended Node model with protocols, banners, status
- [x] Task 1.3: Visualize topology as weighted graph (Cytoscape)
- [x] Task 1.4: Versioned rescan support
- [x] Task 2.1: Backend vulnerability scan module stub
- [x] Task 2.3: Node color gradient based on CVE severity

---

### In Progress / Research-Driven Tasks
#### 3. Asset Importance via Causal Learning
- [ ] Task 3.1: Integrate DoWhy / PyWhy causal backends
- [ ] Task 3.2: Compute `causal_score` per node
- [ ] Task 3.3: Encode causal score visually (e.g., node size or border thickness)
- [ ] Task 3.4: Generate causal impact heatmap for graph

#### 4. CDA Tier Classification Engine
- [ ] Task 4.1: Fuse `causal_score` and `vuln_score` into tier level (I, II, III)
- [ ] Task 4.2: Admin-adjustable thresholds for tiers
- [ ] Task 4.3: Filter/Highlight nodes by tier level
- [ ] Task 4.4: Export tiered CDA report with justification

#### 5. Time-Based Monitoring
- [ ] Task 5.1: Track network snapshots by scan timestamp
- [ ] Task 5.2: Plot time series of CVEs and tier changes
- [ ] Task 5.3: Visual diff for graph deltas

#### 6. Digital Twin + HIL Integration
- [ ] Task 6.1: Mock digital twin API for reactor operational data
- [ ] Task 6.2: Sync state between ops model and cyber twin
- [ ] Task 6.3: Display live reactor variables (e.g. core pressure, flow) on graph nodes
- [ ] Task 6.4: Enable HIL mode with external testbed (e.g., Georgia Tech)

#### 7. Real-time Packet Analytics
- [ ] Task 7.1: Extract protocol + banner info from PyShark captures
- [ ] Task 7.2: Enrich node metadata with passive scan results
- [ ] Task 7.3: Flag packets matching CVE fingerprints in real-time
- [ ] Task 7.4: Map protocol activity to live heatmap overlays

---

---

## 🙋‍♂️ Questions?

Open an issue or contact via GitHub or LinkedIn. This work is under development as part of a doctoral research effort into cyber-informed engineering and digital twin resilience.

## 📄 Research Abstract
**Title**: Causal-Aware Cybersecurity Digital Twins for Networked Nuclear Systems

**Abstract**:
This work presents a novel cybersecurity digital twin architecture for advanced nuclear reactors, integrating causal inference, vulnerability awareness, and real-time network telemetry. Unlike conventional vulnerability scanners, our system overlays cyber-physical impact models atop live network scans, enabling proactive risk prioritization based on operational criticality. The backend includes passive and active probing components, a shortest-path engine, and CVE classification logic. We extend this with a causal learning module that quantifies the system-wide effect of node compromise, and a tiered classification engine for Critical Digital Assets (CDAs). Through synchronized physical twin data (e.g., flow rate, control rod position), the framework simulates cyber-physical state evolution under fault scenarios. The platform supports time-based graph diffs, regulatory overlays, and simulated penetration testing to assess resilience. Our contributions lie in the integration of causal reasoning, digital twin synchronization, and a security-by-design interface for the nuclear cyber-physical domain.

---
