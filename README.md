# Cybersecurity Digital Twin for Advanced Networked Systems

This project is a full-stack Django platform that simulates and secures networked environments (e.g., advanced reactors or industrial control systems). It integrates passive monitoring, active scanning, vulnerability assessment, and remote agent coordination into a cohesive digital twin.

---

## Project Architecture

- **Django + Celery Backend** — Topology modeling, scans, CVE storage
- **Cytoscape.js Frontend** — Visual graph of nodes and link latencies
- **Passive Sniffer API (Flask)** — Starts/stops sniffing via exposed interfaces
- **Host Agent (Python)** — Pushes system info and responds to remote commands
- **Dockerized Infrastructure** — PostgreSQL, Redis, Flask sniffer, Celery worker

---

## Key Features

### 1. Network Mapping & Node Discovery
- Passive sniffer interface management via dashboard
- IP discovery and latency-weighted graph generation
- Dijkstra-based shortest path calculation
- Versioned scans with historical view

### 2. Vulnerability Assessment
- CVE ingestion from NVD (via keyword or CPE)
- Severity scoring and association with nodes
- Admin integration for search, filter, and review

### 3. Persistent Host Agent
- Periodic system info push (CPU, interfaces, processes)
- Command polling (e.g., test ping, scans)
- Remote execution with output POST-back

### 4. Real-Time Visualization
- Dynamic network graph with Cytoscape.js
- Node color/size/styling mapped to attributes
- Interactive shortest path UI

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
docker-compose up --build
```

- Web app: http://localhost:8000
- Sniffer API: http://localhost:5050 or http://sniffer:5000 internally

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
